"""End-to-end per-CVE orchestration with resumable state and budget accounting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import SCHEMA_VERSION
from .backend import build_task_images
from .config import Config
from .contracts import load_experiments, load_policy, validate
from .cves import artifact_identity_from_evidence, get as get_builtin, raw_spec, source_plan
from .differential import (
    MatrixCase,
    MatrixResult,
    build_matrix,
    case_manifest,
    collate,
    replicate_matrix,
    run_seed_repeats,
)
from .errors import TaskError
from .evaluator import EvaluationOutcome, evaluate
from .generator import GeneratedTask, inspect_task, render_task
from .harbor_adapter import Capabilities, HarborAdapter
from .release import build_release, recheck_from_release, verify_release
from .repair import RepairEngine, repair_log_entry
from .sources import EvidenceCollector
from .spec import check_evidence_links, check_spec_consistency, freeze
from .state import JobStore, new_run_id
from .util import PipelineError, digest

STAGE_ORDER = (
    "DISCOVERED",
    "EVIDENCE_READY",
    "SPEC_FROZEN",
    "GENERATED",
    "BUILT",
    "VALIDATING",
    "VALIDATED",
    "RELEASED",
)


@dataclass
class PipelineReport:
    cve_id: str
    run_id: str
    state: str
    task_digest: str | None
    image_digest: str | None
    quality_score: float | None
    admission_status: str | None
    release: dict | None
    evaluation: dict | None
    trials: list[dict]
    error: dict | None
    budget: dict

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "cve_id": self.cve_id,
            "run_id": self.run_id,
            "state": self.state,
            "task_digest": self.task_digest,
            "image_digest": self.image_digest,
            "quality_score": self.quality_score,
            "admission_status": self.admission_status,
            "release": self.release,
            "evaluation": self.evaluation,
            "trials": self.trials,
            "error": self.error,
            "budget": self.budget,
        }


class CvePipeline:
    def __init__(
        self,
        *,
        config: Config,
        cve_id: str,
        run_id: str | None = None,
        adapter: HarborAdapter | None = None,
        profile: str = "smoke",
        scenario: str | None = None,
        workers: int = 1,
        ledger=None,
        output_root: Path | None = None,
    ):
        self.config = config
        self.cve = get_builtin(cve_id)
        self.run_id = run_id or new_run_id("run")
        base = Path(output_root) if output_root else Path(config.pipeline.output_dir)
        self.root = base.resolve() / self.run_id
        self.store = JobStore(base, self.run_id, cve_id)
        self.adapter = adapter or HarborAdapter(
            jobs_dir=self.root / "jobs",
            run_root=self.root,
            timeout_sec=config.pipeline.command_timeout_sec,
        )
        self.profile = load_policy().profile(profile)
        self.policy = load_policy()
        self.scenario = scenario or self.cve.template
        self.workers = max(1, workers)
        self._capabilities: Capabilities | None = None
        self._ledger_obj = ledger
        self._repair = None
        self._repair_error: str | None = None

    # -- facility ----------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        if self._capabilities is None:
            self._capabilities = self.adapter.capabilities()
        return self._capabilities

    @property
    def network_mode(self) -> str:
        return self.capabilities.network_mode

    def _ledger(self):
        from .budget import Ledger

        if self._ledger_obj is not None:
            return self._ledger_obj
        limits = {
            "trials": max(60, self.profile.trials * 4 + 20),
            "builds": 10,
            "wall_sec": 7200.0,
        }
        return Ledger.load_or_create(self.root / "budget.json", limits=limits)

    # -- stages ------------------------------------------------------------

    def collect(self, job=None) -> dict:
        job = job or self.store.create()
        if self.store.state_path.exists():
            try:
                existing = self.store.read_artifact("evidence-index.json")
            except PipelineError:
                existing = None
            complete = existing and all(
                source.get("status") == "ok"
                for source in existing.get("sources", [])
            )
            if existing and existing.get("cve_id") == self.cve.cve_id and complete:
                if job.state == "DISCOVERED":
                    self.store.transition(job, "EVIDENCE_READY", "evidence loaded from checkpoint")
                return existing
        collector = EvidenceCollector(self.config.sources, self.store.root)
        evidence = collector.collect(self.cve.cve_id, source_plan(self.cve))
        validate("evidence-index", evidence)
        self.store.write_artifact("evidence-index.json", evidence)
        failed = [
            source["id"] for source in evidence.get("sources", [])
            if source.get("status") != "ok"
        ]
        if failed:
            raise TaskError(
                "source_error",
                "Source fetch failed for " + ", ".join(failed),
                detail={"failed_sources": failed},
            )
        job = self.store.load()
        if job.state == "DISCOVERED":
            self.store.transition(job, "EVIDENCE_READY", "sources fetched")
        return evidence

    def freeze(self, evidence: dict, job=None) -> dict:
        job = job or self.store.load()
        try:
            existing = self.store.read_artifact("cve-spec.json")
        except PipelineError:
            existing = None
        if existing and existing.get("frozen_digest"):
            job = self.store.load()
            if job.state == "EVIDENCE_READY":
                self.store.transition(job, "SPEC_FROZEN", "frozen spec resumed")
            return existing
        identity = artifact_identity_from_evidence(self.cve, evidence, self.store.root)
        spec = freeze(raw_spec(self.cve, evidence, identity), self.policy.policy_version)
        issues = check_evidence_links(spec, evidence) + check_spec_consistency(spec)
        if issues:
            raise TaskError("evidence_insufficient", "; ".join(issues), detail={"issues": issues})
        self.store.write_artifact("cve-spec.json", spec)
        job = self.store.load()
        if job.state == "EVIDENCE_READY":
            self.store.transition(job, "SPEC_FROZEN", "facts frozen")
        return spec

    def generate(self, spec: dict, job=None) -> tuple[GeneratedTask, Path]:
        job = job or self.store.load()
        task_dir = self.store.path("task")
        if job.state == "GENERATED" or (job.state in {"BUILT", "VALIDATING", "VALIDATED", "RELEASED"}):
            manifest = self.store.read_artifact("task-manifest.json")
            if task_dir.is_dir() and _tree_digest(task_dir) == manifest.get("tree_digest"):
                task = render_task(
                    spec,
                    scenario_name=self.scenario,
                    variant="vulnerable",
                    probe="reference",
                    network_mode=self.network_mode,
                    overrides=self._overlay(),
                )
                if task.task_digest == manifest.get("task_digest"):
                    return task, task_dir
                raise TaskError(
                    "generation_error",
                    "Frozen spec no longer renders the recorded task; invalidate the candidate",
                )
        task = render_task(
            spec,
            scenario_name=self.scenario,
            variant="vulnerable",
            probe="reference",
            network_mode=self.network_mode,
            overrides=self._overlay(),
        )
        task.write(self.store.root)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "cve_id": spec["cve_id"],
            "task_digest": task.task_digest,
            "spec_digest": spec["frozen_digest"],
            "scenario": self.scenario,
            "tree_digest": _tree_digest(task_dir),
            "files": sorted(task.files),
        }
        self.store.write_artifact("task-manifest.json", manifest)
        job = self.store.load()
        if job.state in {"SPEC_FROZEN", "REPAIRING"}:
            self.store.transition(job, "GENERATED", "task rendered")
        return task, task_dir

    def build(self, spec: dict, task: GeneratedTask, job=None) -> dict:
        job = job or self.store.load()
        if job.state in {"BUILT", "VALIDATING", "VALIDATED", "RELEASED"}:
            try:
                image_set = self.store.read_artifact("image-set.json")
                if image_set.get("target_digest"):
                    return image_set
            except PipelineError:
                pass
        ledger = self._ledger()
        try:
            ledger.reserve(
                f"{self.cve.cve_id}-build-{job.revision}", {"builds": 3}, reuse=True
            )
        except PipelineError as exc:
            raise TaskError("budget_exhausted", str(exc)) from exc
        try:
            image_set = build_task_images(
                task_dir=self.store.path("task"),
                variant="vulnerable",
                revision=job.revision,
                log_dir=self.store.path("build-logs"),
                timeout_sec=self.config.pipeline.command_timeout_sec,
                harbor_version=self.capabilities.harbor_version,
            )
        except Exception:
            ledger.refund(f"{self.cve.cve_id}-build-{job.revision}")
            raise
        ledger.commit(f"{self.cve.cve_id}-build-{job.revision}", {"builds": 3})
        self.store.write_artifact("image-set.json", image_set)
        job = self.store.load()
        if job.state == "GENERATED":
            self.store.transition(job, "BUILT", "images built")
        return image_set

    def validate(
        self,
        spec: dict,
        evidence: dict,
        task: GeneratedTask,
        image_set: dict,
        job=None,
    ) -> tuple[MatrixResult, EvaluationOutcome]:
        job = job or self.store.load()
        if job.state in {"VALIDATING", "VALIDATED", "RELEASED"}:
            try:
                evaluation = self.store.read_artifact("evaluation.json")
                trials = self.store.read_artifact("trials.json")
                outcome = _reload_evaluation(evaluation)
                return _ReloadedMatrix(trials), outcome  # type: ignore[return-value]
            except PipelineError:
                pass
        job = self.store.load()
        if job.state == "BUILT":
            job = self.store.transition(job, "VALIDATING", "differential matrix started")
        artifact_digest = image_set["target_digest"]
        experiments = load_experiments()
        mandatory = tuple(e for e in experiments if e.id not in {"T03", "T04", "T09"})
        base_cases = build_matrix(
            spec,
            scenario_name=self.scenario,
            root=self.store.path("matrix"),
            network_mode=self.network_mode,
            allowed_hosts=("target",),
            experiments=mandatory,
            overrides=self._overlay(),
        )
        sample_experiments = tuple(e for e in experiments if e.id in {"T03", "T04"})
        sample_cases = replicate_matrix(
            spec,
            scenario_name=self.scenario,
            root=self.store.path("matrix"),
            network_mode=self.network_mode,
            allowed_hosts=("target",),
            experiments=sample_experiments,
            repeats=self.profile.trials,
            overrides=self._overlay(),
        )
        cases: list[MatrixCase] = base_cases + sample_cases
        ledger = self._ledger()
        reservation = f"{self.cve.cve_id}-trials-{job.revision}"
        try:
            ledger.reserve(reservation, {"trials": len(cases) + 3}, reuse=True)
        except PipelineError as exc:
            raise TaskError("budget_exhausted", str(exc)) from exc
        job_outcome = self.adapter.run(
            [case.task_dir for case in cases],
            agent="oracle",
            job_name=f"{spec['cve_id'].lower()}-matrix",
            n_concurrent=self.workers,
            timeout_sec=max(3600, self.config.pipeline.command_timeout_sec * 8),
        )
        matrix = collate(
            job_outcome,
            cases,
            run_id=self.run_id,
            cve_id=spec["cve_id"],
            candidate_revision=job.revision,
            artifact_digest=artifact_digest,
        )
        seed_records, seed_errors = run_seed_repeats(
            self.adapter,
            spec,
            scenario_name=self.scenario,
            root=self.store.path("matrix"),
            network_mode=self.network_mode,
            allowed_hosts=("target",),
            run_id=self.run_id,
            candidate_revision=job.revision,
            artifact_digest=artifact_digest,
            repeats=3,
            n_concurrent=min(3, self.workers),
            overrides=self._overlay(),
        )
        matrix.records.extend(seed_records)
        ledger.commit(reservation, {"trials": len(job_outcome.trials) + len(seed_records)})

        outcome = evaluate(
            spec=spec,
            evidence=evidence,
            matrix=matrix,
            image_set=image_set,
            policy=self.policy,
            profile_name=self.profile.name,
            package_issues=inspect_task(task.files, spec),
            network_isolation=self.network_mode,
            extra_seed_errors=seed_errors,
        )
        matrix_json = matrix.to_json()
        matrix_json["cases"] = case_manifest(cases)
        self.store.write_artifact("trials.json", matrix_json)
        self.store.write_artifact("evaluation.json", outcome.evaluation)
        job = self.store.load()
        if job.state == "VALIDATING":
            admission = outcome.evaluation["admission_status"]
            target_state = "QUARANTINED" if admission == "quarantined" else "VALIDATED"
            self.store.transition(
                job,
                target_state,
                f"quality={outcome.evaluation['quality_score']} admission={admission}",
            )
        return matrix, outcome

    def release(
        self,
        spec: dict,
        evidence: dict,
        task: GeneratedTask,
        image_set: dict,
        matrix: MatrixResult,
        outcome: EvaluationOutcome,
        job=None,
    ) -> dict:
        job = job or self.store.load()
        if job.state == "RELEASED":
            try:
                return self.store.read_artifact("release.json")
            except PipelineError:
                pass
        if outcome.evaluation["admission_status"] != "released":
            raise TaskError(
                "attribution_failure",
                "Release refused: " + "; ".join(outcome.evaluation["failure_reasons"][:5]),
                detail={"evaluation": outcome.evaluation},
            )
        result = build_release(
            spec=spec,
            evidence=evidence,
            evaluation=outcome.evaluation,
            matrix_result=matrix.to_json() if hasattr(matrix, "to_json") else matrix,
            task=task,
            task_dir=self.store.path("task"),
            image_set=image_set,
            run_dir=self.store.root,
            revision=job.revision,
            harbor_version=self.capabilities.harbor_version,
        )
        issues = verify_release(result.root, expected_digest=image_set["target_digest"])
        if issues:
            raise TaskError("grader_failure", "Release package failed recheck: " + "; ".join(issues))
        recheck = recheck_from_release(self.adapter, result.root, n_concurrent=self.workers)
        if recheck.get("reward") != 1.0:
            raise TaskError(
                "oracle_failure",
                f"Release recheck did not reproduce the goal: {recheck}",
                detail=recheck,
            )
        record = {**result.to_json(), "recheck": recheck}
        self.store.write_artifact("release.json", record)
        job = self.store.load()
        if job.state == "VALIDATED":
            self.store.transition(job, "RELEASED", "release package verified")
        return record

    # -- driver ------------------------------------------------------------

    def run(self, until: str = "release") -> PipelineReport:
        """Advance the candidate up to `until`; safe to call again to resume."""
        if until not in {"collect", "freeze", "generate", "build", "validate", "release"}:
            raise PipelineError(f"Unknown stage {until!r}")
        self.store.create()
        with self.store.lease:
            return self._run(until)

    def _run(self, until: str) -> PipelineReport:
        job = self.store.load()
        try:
            job = self._prepare_retry(job)
            if job.state in {"QUARANTINED", "UNSUPPORTED", "RELEASED"}:
                return self._stored_report(job)
            while True:
                try:
                    return self._advance(until)
                except TaskError as exc:
                    if not self._attempt_repair(exc):
                        raise
        except TaskError as exc:
            job = self.store.load()
            self.store.fail(job, exc)
            return self._stored_report(self.store.load())
        except PipelineError as exc:
            job = self.store.load()
            wrapped = TaskError("infra_error", str(exc))
            self.store.fail(job, wrapped)
            return self._stored_report(self.store.load())
        except Exception as exc:  # unexpected faults are infrastructure failures
            job = self.store.load()
            wrapped = TaskError("infra_error", f"{type(exc).__name__}: {exc}")
            self.store.fail(job, wrapped)
            return self._stored_report(self.store.load())

    def _advance(self, until: str) -> PipelineReport:
        job = self.store.load()
        evidence = self.collect(job)
        if until == "collect":
            return self._report(self.store.load(), None, None, None, None, None)
        job = self.store.load()
        spec = self.freeze(evidence, job)
        if until == "freeze":
            return self._report(self.store.load(), None, None, None, None, None)
        job = self.store.load()
        task, _ = self.generate(spec, job)
        if until == "generate":
            return self._report(self.store.load(), task, None, None, None, None)
        job = self.store.load()
        image_set = self.build(spec, task, job)
        if until == "build":
            return self._report(self.store.load(), task, image_set, None, None, None)
        job = self.store.load()
        matrix, outcome = self.validate(spec, evidence, task, image_set, job)
        if until == "validate":
            return self._report(
                self.store.load(), task, image_set, outcome, None, matrix
            )
        job = self.store.load()
        release = None
        if outcome.evaluation["admission_status"] == "released":
            release = self.release(spec, evidence, task, image_set, matrix, outcome, job)
            if until != "release":
                return self._report(
                    self.store.load(), task, image_set, outcome, release, matrix
                )
        job = self.store.load()
        return self._report(job, task, image_set, outcome, release, matrix)

    # -- bounded model repair ---------------------------------------------

    def _overlay(self) -> dict[str, str]:
        try:
            overlay = self.store.read_artifact("repair-overlay.json")
        except PipelineError:
            return {}
        if not isinstance(overlay, dict):
            raise PipelineError("repair-overlay.json is not an object")
        for name, body in overlay.items():
            if not isinstance(name, str) or not isinstance(body, str):
                raise PipelineError("repair overlay must map paths to text")
        return dict(overlay)

    def _repair_engine(self):
        if self._repair is None:
            try:
                self._repair = RepairEngine(self.config, self._ledger(), role="repairer")
            except Exception as exc:  # noqa: BLE001 - repair is optional
                self._repair = False
                self._repair_error = str(exc)
        return self._repair or None

    def _task_files(self) -> dict[str, str]:
        root = self.store.path("task")
        if not root.is_dir():
            return {}
        files: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            if name.startswith("environment/"):
                files[name] = path.read_text(encoding="utf-8")
        return files

    def _repair_log(self) -> list[dict]:
        try:
            log = self.store.read_artifact("repair-log.json")
        except PipelineError:
            return []
        return list(log) if isinstance(log, list) else []

    def _attempt_repair(self, error: TaskError) -> bool:
        """Try one bounded repair; return True when the pipeline may resume."""
        if error.category.code not in {"build_error", "generation_error"}:
            return False
        job = self.store.load()
        used = int(job.attempts.get("repair", 0))
        if used >= self.config.pipeline.max_repairs:
            return False
        if not self.store.path("task").is_dir():
            return False
        try:
            self.store.read_artifact("cve-spec.json")
        except PipelineError:
            return False
        engine = self._repair_engine()
        if engine is None:
            return False
        files = self._task_files()
        overlay = self._overlay()
        self.store.fail(job, error)
        job = self.store.transition(
            self.store.load(), "REPAIRING", f"model repair {used + 1}"
        )
        job.revision += 1
        job.attempts["repair"] = used + 1
        self.store.save(job)
        try:
            result = engine.repair(
                cve_id=self.cve.cve_id,
                revision=job.revision,
                error=error,
                files=files,
                previous=overlay,
            )
        except TaskError as exc:
            self._append_repair_log(used + 1, error, files, model="unavailable", failure=str(exc))
            self.store.fail(self.store.load(), error)
            return False
        self._append_repair_log(used + 1, error, files, result=result)
        if not result.files:
            self.store.fail(self.store.load(), error)
            return False
        overlay.update(result.files)
        self.store.write_artifact("repair-overlay.json", overlay)
        return True

    def _append_repair_log(self, attempt, error, files, *, result=None, model="", failure=None) -> None:
        from .repair import RepairResult

        entry = repair_log_entry(
            attempt=attempt,
            result=result or RepairResult({}, "", model or "unavailable", {}, failure),
            error=error,
            files_before=files,
        )
        log = self._repair_log()
        log.append(entry)
        self.store.write_artifact("repair-log.json", log)

    def _prepare_retry(self, job):
        """QUARANTINED jobs may only leave through REPAIRING, and only if retryable."""
        if job.state != "QUARANTINED":
            return job
        error = job.error or {}
        if not error.get("retryable"):
            return job
        used = int(job.attempts.get("retry", 0))
        if used >= self.config.pipeline.max_repairs:
            return job
        job.attempts["retry"] = used + 1
        self.store.save(job)
        return self.store.transition(
            job, "REPAIRING", f"retry {used + 1} after {error.get('category')}"
        )

    def _report(self, job, task, image_set, outcome, release, matrix) -> PipelineReport:
        evaluation = outcome.evaluation if outcome else None
        return PipelineReport(
            cve_id=self.cve.cve_id,
            run_id=self.run_id,
            state=job.state,
            task_digest=task.task_digest if task else job.artifacts.get("task-manifest.json"),
            image_digest=(image_set or {}).get("target_digest"),
            quality_score=evaluation["quality_score"] if evaluation else None,
            admission_status=evaluation["admission_status"] if evaluation else None,
            release=release,
            evaluation=evaluation,
            trials=(matrix.records if matrix is not None and hasattr(matrix, "records") else []),
            error=job.error,
            budget=self._ledger().snapshot(),
        )

    def _stored_report(self, job) -> PipelineReport:
        """Report the best evidence available on disk without re-running stages."""

        def artifact(name: str):
            try:
                return self.store.read_artifact(name)
            except PipelineError:
                return None

        evaluation = artifact("evaluation.json")
        trials = artifact("trials.json") or {}
        manifest = artifact("task-manifest.json") or {}
        image_set = artifact("image-set.json") or {}
        release = artifact("release.json")
        return PipelineReport(
            cve_id=self.cve.cve_id,
            run_id=self.run_id,
            state=job.state,
            task_digest=manifest.get("task_digest"),
            image_digest=image_set.get("target_digest"),
            quality_score=evaluation["quality_score"] if evaluation else None,
            admission_status=evaluation["admission_status"] if evaluation else None,
            release=release,
            evaluation=evaluation,
            trials=trials.get("records", []),
            error=None if job.state in {"VALIDATED", "RELEASED"} else job.error,
            budget=self._ledger().snapshot(),
        )


class _ReloadedMatrix:
    """Minimal MatrixResult stand-in when validation is resumed from disk."""

    def __init__(self, data: dict):
        self.payload = data
        self.records = data.get("records", [])

    def to_json(self) -> dict:
        return dict(self.payload)


def _reload_evaluation(data: dict) -> EvaluationOutcome:
    return EvaluationOutcome(evaluation=data, dimensions={}, hard_conditions=data.get("hard_conditions", []))


def _tree_digest(root: Path) -> str:
    from .util import tree_hashes

    return digest(tree_hashes(root))
