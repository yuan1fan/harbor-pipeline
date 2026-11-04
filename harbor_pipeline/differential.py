"""Render and run the T01-T12 differential experiment matrix.

The matrix is a ladder: every step is its own Harbor job, and a blocking step
that misses an expectation stops the remaining steps. Results are mapped back
to experiments by resolved task path, never by task name.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import SCHEMA_VERSION
from .contracts import Experiment, load_experiments
from .errors import TaskError
from .generator import GeneratedTask, render_task
from .harbor_adapter import HarborAdapter, JobOutcome
from .trials import Expectation, build_trial_record, evaluate_expectation
from .util import PipelineError, digest

# Probes that are realised by a different mechanism than a PoC payload.
_SPECIAL_PROBES = {"seed", "control", "fault"}

NEGATIVE_EXPERIMENTS = ("T05", "T06", "T07", "T10")


@dataclass
class MatrixCase:
    experiment: Experiment
    task: GeneratedTask
    task_dir: Path

    @property
    def id(self) -> str:
        return self.experiment.id


@dataclass(frozen=True)
class MatrixStep:
    """One fail-fast rung of the differential ladder.

    Each step is a separate Harbor job. A blocking step that misses an
    expectation stops the ladder before the next job starts, which is the
    whole point: a candidate that cannot pass T03 never pays for T04, the
    negative probes, or the repeats.
    """

    key: str
    experiment_ids: tuple[str, ...]
    repeats: int = 1
    blocking: bool = True


def plan_matrix_steps(*, repeats: int, include_optional: bool = True) -> list[MatrixStep]:
    """Order the matrix cheapest-and-most-decisive first.

    The first T03 decides most candidates in one trial, then the first T04
    proves the differential. Repeats are confirmation, so they run after every
    distinct check has passed; T11/T12 are advisory (they lower the quality
    score but do not block release) and run last.

    T01/T02 are deliberately absent: their health/business check runs inside
    every T03/T04 verifier invocation, so the verdict is derived from those
    records instead of starting two extra targets (see
    ``CvePipeline._derive_health_verdicts``). T05/T06/T07/T10 are absent
    because their payloads are framework constants and run once per verifier
    template in ``verifier_check.verifier_regression_checks``.
    """
    if repeats < 1:
        raise PipelineError("repeats must be positive")
    steps = [
        MatrixStep("t03-first", ("T03",), 1, True),
        MatrixStep("t04-first", ("T04",), 1, True),
    ]
    if repeats > 1:
        steps.append(MatrixStep("confirm", ("T03", "T04"), repeats - 1, True))
    if include_optional:
        steps.extend([
            MatrixStep("t11", ("T11",), 1, False),
            MatrixStep("t12", ("T12",), 1, False),
        ])
    return steps


@dataclass
class MatrixResult:
    job: JobOutcome | None = None
    records: list[dict] = field(default_factory=list)
    expectations: dict[str, Expectation] = field(default_factory=dict)
    verdicts: list[Expectation] = field(default_factory=list)
    cases: dict[str, MatrixCase] = field(default_factory=dict)
    all_cases: list[MatrixCase] = field(default_factory=list)
    jobs: list[JobOutcome] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    aborted_at: str | None = None
    aborted_detail: str = ""
    aborted_category: str | None = None
    matrix_repeats: int | None = None
    framework_checks: dict[str, dict] = field(default_factory=dict)
    derived_records: list[dict] = field(default_factory=list)

    def record_for(self, experiment_id: str) -> dict | None:
        for record in self.records:
            if record["experiment_id"] == experiment_id:
                return record
        return None

    def expectation(self, experiment_id: str) -> Expectation | None:
        return self.expectations.get(experiment_id)

    def all_met(self) -> bool:
        return bool(self.verdicts) and all(e.met for e in self.verdicts)

    @property
    def stopped_before_negatives(self) -> bool:
        """True when the ladder stopped before any negative probe ran.

        The repair classifier uses this: an unrun negative is not evidence
        that the grader is too loose, only that there was no reason to ask.
        """
        return self.aborted_at in {"t01", "t02", "t03-first", "t04-first"}

    def merge(self, other: "MatrixResult") -> None:
        """Fold one step's job into the ladder result."""
        self.records.extend(other.records)
        self.expectations.update(other.expectations)
        self.verdicts.extend(other.verdicts)
        self.cases.update(other.cases)
        self.all_cases.extend(other.all_cases)
        self.errors.extend(other.errors)
        if other.job is not None:
            self.jobs.append(other.job)
            self.job = other.job

    def unmet(self) -> list[Expectation]:
        return [verdict for verdict in self.verdicts if not verdict.met]

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "job_name": self.job.job_name if self.job else None,
            "job_dir": str(self.job.job_dir) if self.job else None,
            "jobs": [
                {"job_name": job.job_name, "job_dir": str(job.job_dir)}
                for job in self.jobs
            ],
            "aborted_at": self.aborted_at,
            "aborted_detail": self.aborted_detail,
            "matrix_repeats": self.matrix_repeats,
            "framework_checks": self.framework_checks,
            "records": self.records,
            "derived_records": self.derived_records,
            "expectations": [e.to_json() for e in self.verdicts],
            "errors": list(self.errors),
        }


def run_ladder(steps: list[MatrixStep], run_step) -> MatrixResult:
    """Execute steps in order and stop at the first blocking failure.

    `run_step(step)` returns that step's MatrixResult. Keeping the loop here,
    separate from Harbor and the ledger, makes the fail-fast rule testable
    without Docker.
    """
    ladder = MatrixResult()
    for step in steps:
        result = run_step(step)
        ladder.merge(result)
        if result.errors:
            # No trial was mapped back for at least one case. That is a
            # plumbing failure, never a verdict about the task.
            failure = "; ".join(result.errors[:4])
            category = "infra_error"
        else:
            unmet = result.unmet()
            failure = "; ".join(
                f"{verdict.experiment_id}: {verdict.detail}" for verdict in unmet[:4]
            )
            categories = {
                verdict.error_category
                for verdict in result.verdicts
                if verdict.error_category
            }
            # An unstarted target or a failed build is infrastructure, not a
            # task defect; the caller must retry or repair instead of treating
            # the candidate as a bad task.
            category = next(
                (
                    name for name in ("infra_error", "build_error", "oracle_failure")
                    if name in categories
                ),
                None,
            )
        if failure and step.blocking:
            ladder.aborted_at = step.key
            ladder.aborted_detail = failure
            ladder.aborted_category = category
            break
    return ladder


def _render_case(
    experiment: Experiment,
    *,
    spec: dict,
    scenario_name: str,
    root: Path,
    name: str,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    overrides: dict[str, str] | None = None,
    synthesis=None,
    revision: int = 1,
    prebuilt: bool = False,
) -> MatrixCase:
    variant = experiment.variant if experiment.variant in {"vulnerable", "fixed"} else "vulnerable"
    controlled = experiment.id == "T08"
    fault = experiment.id == "T12"
    probe = experiment.probe
    if probe in _SPECIAL_PROBES:
        probe = "health" if fault else "reference"
    task = render_task(
        spec,
        scenario_name=scenario_name,
        variant=variant,
        probe=probe,
        network_mode=network_mode,
        allowed_hosts=allowed_hosts,
        controlled=controlled,
        fault=fault,
        overrides=overrides,
        synthesis=synthesis,
        revision=revision,
        prebuilt=prebuilt,
    )
    task_dir = task.write(root / name)
    return MatrixCase(experiment=experiment, task=task, task_dir=task_dir)


def _selected_experiments(
    experiment_ids: tuple[str, ...],
    *,
    include_optional: bool = True,
    synthesis=None,
) -> tuple[Experiment, ...]:
    selected = []
    for experiment in load_experiments():
        if experiment.id not in experiment_ids:
            continue
        if experiment.probe == "seed":
            continue
        if not include_optional and not experiment.mandatory_for_release:
            continue
        # A synthesized target has no framework-owned controlled variant: the
        # application code comes from the model, so there is no deterministic
        # way to remove a single precondition. Rendering T08 would run the
        # vulnerable build under fixed-variant expectations and report a leak
        # that the control was supposed to prevent. The experiment is optional
        # for release, so record it as not applicable instead of mis-scoring it.
        if synthesis is not None and experiment.probe == "control":
            continue
        selected.append(experiment)
    return tuple(selected)


def build_step_cases(
    spec: dict,
    *,
    step: MatrixStep,
    scenario_name: str,
    root: Path,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    overrides: dict[str, str] | None = None,
    synthesis=None,
    revision: int = 1,
) -> list[MatrixCase]:
    """Render one ladder step against the candidate's prebuilt images.

    Probe tasks are never released, so they can reference the local image tags
    and skip Harbor's per-trial ``docker compose build`` entirely.
    """
    root.mkdir(parents=True, exist_ok=True)
    experiments = _selected_experiments(step.experiment_ids, synthesis=synthesis)
    if not experiments:
        raise PipelineError(f"No experiments selected for step {step.key}")
    cases: list[MatrixCase] = []
    for experiment in experiments:
        for index in range(1, step.repeats + 1):
            cases.append(_render_case(
                experiment,
                spec=spec,
                scenario_name=scenario_name,
                root=root,
                name=f"{step.key}-{experiment.id.lower()}-{index:02d}",
                network_mode=network_mode,
                allowed_hosts=allowed_hosts,
                overrides=overrides,
                synthesis=synthesis,
                revision=revision,
                prebuilt=True,
            ))
    return cases


def build_matrix(
    spec: dict,
    *,
    scenario_name: str,
    root: Path,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    include_optional: bool = True,
    experiments: tuple[Experiment, ...] | None = None,
    overrides: dict[str, str] | None = None,
    synthesis=None,
) -> list[MatrixCase]:
    """Render every selected experiment once (kept for callers that need all)."""
    if root.exists():
        shutil.rmtree(root)
    selected = _selected_experiments(
        tuple(e.id for e in (experiments or load_experiments())),
        include_optional=include_optional,
        synthesis=synthesis,
    )
    cases: list[MatrixCase] = [
        _render_case(
            experiment,
            spec=spec,
            scenario_name=scenario_name,
            root=root,
            name=f"{experiment.id.lower()}-{experiment.name}",
            network_mode=network_mode,
            allowed_hosts=allowed_hosts,
            overrides=overrides,
            synthesis=synthesis,
        )
        for experiment in selected
    ]
    if not cases:
        raise PipelineError("No experiments selected for the matrix")
    return cases


def run_cases(
    adapter: HarborAdapter,
    cases: list[MatrixCase],
    *,
    run_id: str,
    cve_id: str,
    candidate_revision: int,
    artifact_digest: str,
    agent: str = "oracle",
    n_concurrent: int = 2,
    timeout_sec: int | None = None,
    seed: int = 0,
) -> MatrixResult:
    job = adapter.run(
        [case.task_dir for case in cases],
        agent=agent,
        job_name=f"{cve_id.lower()}-matrix",
        n_concurrent=n_concurrent,
        timeout_sec=timeout_sec,
    )
    return collate(
        job,
        cases,
        run_id=run_id,
        cve_id=cve_id,
        candidate_revision=candidate_revision,
        artifact_digest=artifact_digest,
        seed=seed,
    )


def collate(
    job: JobOutcome,
    cases: list[MatrixCase],
    *,
    run_id: str,
    cve_id: str,
    candidate_revision: int,
    artifact_digest: str,
    seed: int = 0,
) -> MatrixResult:
    by_path = job.by_task_path()
    result = MatrixResult(job=job)
    for case in cases:
        trial = by_path.get(str(case.task_dir.resolve()).casefold())
        if trial is None:
            result.errors.append(f"{case.id}: no trial found for {case.task_dir}")
            continue
        expectation = evaluate_expectation(case.experiment, trial)
        record = build_trial_record(
            experiment=case.experiment,
            trial=trial,
            run_id=run_id,
            cve_id=cve_id,
            candidate_revision=candidate_revision,
            artifact_digest=artifact_digest,
            seed=seed,
            poc_path=case.task_dir / "solution" / "solve.sh",
            started_at=job.result.get("started_at", ""),
        )
        record["_audit"] = {
            "trial_name": trial.trial_name,
            "trial_dir": str(trial.trial_dir),
            "task_path": str(case.task_dir),
            "task_digest": case.task.task_digest,
            "evidence": str(trial.trial_dir / "verifier" / "evidence.json"),
        }
        result.records.append(record)
        result.expectations[case.id] = expectation
        result.verdicts.append(expectation)
        result.cases[case.id] = case
        result.all_cases.append(case)
    return result


def replicate_matrix(
    spec: dict,
    *,
    scenario_name: str,
    root: Path,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    experiments: tuple[Experiment, ...],
    repeats: int,
    overrides: dict[str, str] | None = None,
    synthesis=None,
    name_prefix: str = "",
) -> list[MatrixCase]:
    """Create `repeats` independent copies of each case for paired sampling."""
    if repeats < 1:
        raise PipelineError("repeats must be positive")
    root.mkdir(parents=True, exist_ok=True)
    cases: list[MatrixCase] = []
    for experiment in experiments:
        for index in range(1, repeats + 1):
            cases.append(_render_case(
                experiment,
                spec=spec,
                scenario_name=scenario_name,
                root=root,
                name=f"{name_prefix}{experiment.id.lower()}-{index:02d}",
                network_mode=network_mode,
                allowed_hosts=allowed_hosts,
                overrides=overrides,
                synthesis=synthesis,
            ))
    return cases


def run_seed_repeats(
    adapter: HarborAdapter,
    spec: dict,
    *,
    scenario_name: str,
    root: Path,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    run_id: str,
    candidate_revision: int,
    artifact_digest: str,
    repeats: int = 3,
    n_concurrent: int = 2,
    overrides: dict[str, str] | None = None,
    synthesis=None,
    fail_fast: bool = True,
) -> tuple[list[dict], list[str]]:
    """T09: rebuild the same reference task across independent jobs.

    With ``fail_fast`` the first seed that does not reach the goal stops the
    loop: the stability condition already fails, and the remaining rebuilds
    cannot change that verdict.
    """
    records: list[dict] = []
    statuses: list[str] = []
    for seed in range(repeats):
        task = render_task(
            spec,
            scenario_name=scenario_name,
            variant="vulnerable",
            probe="reference",
            network_mode=network_mode,
            allowed_hosts=allowed_hosts,
            overrides=overrides,
            synthesis=synthesis,
            revision=candidate_revision,
            prebuilt=True,
        )
        task_dir = task.write(root / f"seed-{seed + 1}")
        outcome = adapter.run(
            [task_dir],
            agent="oracle",
            job_name=f"{spec['cve_id'].lower()}-seed-{seed + 1}",
            n_concurrent=1,
        )
        if not outcome.trials:
            raise TaskError("infra_error", f"Seed trial {seed + 1} produced no result")
        trial = outcome.trials[0]
        statuses.append(trial.evidence_status)
        experiment = _seed_experiment()
        record = build_trial_record(
            experiment=experiment,
            trial=trial,
            run_id=run_id,
            cve_id=spec["cve_id"],
            candidate_revision=candidate_revision,
            artifact_digest=artifact_digest,
            seed=seed,
            poc_path=task_dir / "solution" / "solve.sh",
            started_at=outcome.result.get("started_at", ""),
        )
        record["_audit"] = {
            "trial_name": trial.trial_name,
            "trial_dir": str(trial.trial_dir),
            "task_path": str(task_dir),
        }
        records.append(record)
        if fail_fast and trial.evidence_status != "goal_passed":
            break
    consistent = all(s == "goal_passed" for s in statuses)
    errors = [] if consistent else [f"T09 statuses differ across seeds: {statuses}"]
    return records, errors


def _seed_experiment() -> Experiment:
    for experiment in load_experiments():
        if experiment.id == "T09":
            return experiment
    raise PipelineError("T09 is missing from the experiment policy")


def case_manifest(cases: list[MatrixCase]) -> dict:
    """Digest of every rendered probe; used to bind matrix results to inputs."""
    return {
        "cases": [
            {
                "id": case.id,
                "name": case.experiment.name,
                "expect": case.experiment.expect,
                "task_digest": case.task.task_digest,
                "path": str(case.task_dir),
            }
            for case in cases
        ],
        "digest": digest({case.id: case.task.task_digest for case in cases}),
    }
