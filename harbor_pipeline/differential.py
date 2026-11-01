"""Render and run the T01-T12 differential experiment matrix.

A matrix run is one Harbor job: every probe is a separate task directory, all
executed with the same agent and the same frozen candidate. Results are mapped
back to experiments by resolved task path, never by task name.
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


@dataclass
class MatrixResult:
    job: JobOutcome
    records: list[dict] = field(default_factory=list)
    expectations: dict[str, Expectation] = field(default_factory=dict)
    cases: dict[str, MatrixCase] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def record_for(self, experiment_id: str) -> dict | None:
        for record in self.records:
            if record["experiment_id"] == experiment_id:
                return record
        return None

    def expectation(self, experiment_id: str) -> Expectation | None:
        return self.expectations.get(experiment_id)

    def all_met(self) -> bool:
        return bool(self.expectations) and all(e.met for e in self.expectations.values())

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "job_name": self.job.job_name,
            "job_dir": str(self.job.job_dir),
            "records": self.records,
            "expectations": [e.to_json() for e in self.expectations.values()],
            "errors": list(self.errors),
        }


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
) -> list[MatrixCase]:
    if root.exists():
        shutil.rmtree(root)
    cases: list[MatrixCase] = []
    for experiment in experiments or load_experiments():
        if experiment.probe == "seed":
            continue
        if not include_optional and not experiment.mandatory_for_release:
            continue
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
        )
        task_dir = task.write(root / f"{experiment.id.lower()}-{experiment.name}")
        cases.append(MatrixCase(experiment=experiment, task=task, task_dir=task_dir))
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
        result.cases[case.id] = case
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
) -> list[MatrixCase]:
    """Create `repeats` independent copies of each case for paired sampling."""
    if repeats < 1:
        raise PipelineError("repeats must be positive")
    cases: list[MatrixCase] = []
    for experiment in experiments:
        variant = experiment.variant if experiment.variant in {"vulnerable", "fixed"} else "vulnerable"
        probe = "health" if experiment.probe in {"health"} else "reference"
        for index in range(1, repeats + 1):
            task = render_task(
                spec,
                scenario_name=scenario_name,
                variant=variant,
                probe=probe,
                network_mode=network_mode,
                allowed_hosts=allowed_hosts,
                overrides=overrides,
            )
            task_dir = task.write(root / f"{experiment.id.lower()}-{index:02d}")
            cases.append(MatrixCase(experiment=experiment, task=task, task_dir=task_dir))
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
) -> tuple[list[dict], list[str]]:
    """T09: rebuild the same reference task across independent jobs."""
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
    consistent = len(set(statuses)) == 1 and all(s == "goal_passed" for s in statuses)
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
