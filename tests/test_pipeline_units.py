"""Unit tests for budgets, batch planning, worker isolation and retries."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from harbor_pipeline.batch import Candidate, load_candidates, plan_batch
from harbor_pipeline.budget import Ledger
from harbor_pipeline.config import Config, Settings
from harbor_pipeline.errors import TaskError
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.release import dataset_split, root_cause_group
from harbor_pipeline.state import JobStore
from harbor_pipeline.util import PipelineError
from harbor_pipeline.worker import CandidateJob, run_candidate


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def test_concurrent_reservations_are_atomic(tmp_path: Path):
    ledger = Ledger.load_or_create(tmp_path / "budget.json", limits={"trials": 100})

    def work(index: int) -> None:
        rid = f"worker-{index}"
        ledger.reserve(rid, {"trials": 10})
        ledger.commit(rid, {"trials": 10})

    threads = [threading.Thread(target=work, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    snapshot = ledger.snapshot()
    assert snapshot["used"]["trials"] == 100
    assert snapshot["remaining"]["trials"] == 0

    with pytest.raises(PipelineError, match="Budget exhausted"):
        ledger.reserve("overflow", {"trials": 1})


def test_reservation_reuse_and_conflict(tmp_path: Path):
    ledger = Ledger.load_or_create(tmp_path / "budget.json", limits={"trials": 10})
    ledger.reserve("job", {"trials": 4}, reuse=True)
    ledger.reserve("job", {"trials": 4}, reuse=True)
    with pytest.raises(PipelineError, match="different amounts"):
        ledger.reserve("job", {"trials": 5}, reuse=True)
    with pytest.raises(PipelineError, match="Duplicate reservation"):
        ledger.reserve("job", {"trials": 4})
    ledger.commit("job", {"trials": 3})
    assert ledger.snapshot()["used"]["trials"] == 3


def test_two_ledger_objects_share_one_file(tmp_path: Path):
    path = tmp_path / "budget.json"
    first = Ledger.load_or_create(path, limits={"trials": 10})
    second = Ledger.load_or_create(path, limits={"trials": 10})
    first.reserve("a", {"trials": 6})
    with pytest.raises(PipelineError, match="Budget exhausted"):
        second.reserve("b", {"trials": 6})
    second.reserve("b", {"trials": 4})
    assert first.snapshot()["reserved"]["trials"] == 10


# ---------------------------------------------------------------------------
# Batch planning
# ---------------------------------------------------------------------------


def test_load_candidates_formats(tmp_path: Path):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps({"candidates": [
        {"cve_id": "cve-2024-23334", "priority": 5},
        "CVE-2024-99999",
        "nonsense",
    ]}), encoding="utf-8")
    candidates, rejected = load_candidates(path)
    assert [c.cve_id for c in candidates] == ["CVE-2024-23334", "CVE-2024-99999"]
    assert len(rejected) == 1

    comma, _ = load_candidates("CVE-2024-23334, CVE-2024-23334")
    assert len(comma) == 2


def test_plan_batch_deduplicates_and_classifies(tmp_path: Path):
    plan = plan_batch(
        [
            Candidate("CVE-2024-23334", priority=1),
            Candidate("cve-2024-23334"),
            Candidate("CVE-2099-0001"),
        ],
        run_id="batch-test",
        profile="smoke",
        workers=2,
        output_root=tmp_path,
        max_repairs=2,
    )
    assert [c.cve_id for c in plan.candidates] == ["CVE-2024-23334"]
    assert plan.duplicates == [
        {"cve_id": "CVE-2024-23334", "duplicate_of": "CVE-2024-23334"}
    ]
    assert [u["cve_id"] for u in plan.unsupported] == ["CVE-2099-0001"]
    assert plan.limits["trials"] > 0
    assert plan.limits["builds"] >= 9
    assert plan.root == tmp_path / "batch-test"


def test_plan_batch_limit_is_terminal(tmp_path: Path):
    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-limit",
        profile="smoke",
        workers=1,
        limit=0,
        output_root=tmp_path,
    )
    assert plan.candidates == []
    assert any("limit" in item["reason"] for item in plan.unsupported)


# ---------------------------------------------------------------------------
# Worker isolation
# ---------------------------------------------------------------------------


def _job(tmp_path: Path, cve_id: str) -> CandidateJob:
    return CandidateJob(
        cve_id=cve_id,
        run_id="worker-test",
        profile="smoke",
        scenario=None,
        output_root=tmp_path,
        ledger=Ledger.load_or_create(
            tmp_path / "budget.json", limits={"trials": 10, "builds": 10}
        ),
    )


def test_worker_reports_unknown_cve_instead_of_raising(tmp_path: Path):
    payload = run_candidate(_job(tmp_path, "CVE-2099-0003"), Config())
    assert payload["state"] == "UNSUPPORTED"
    assert payload["error"]["category"] == "unsupported"


# ---------------------------------------------------------------------------
# Retry and release grouping
# ---------------------------------------------------------------------------


def test_quarantined_retryable_job_moves_to_repairing(tmp_path: Path):
    config = Config(pipeline=Settings(output_dir=str(tmp_path), max_repairs=2))
    pipeline = CvePipeline(config=config, cve_id="CVE-2024-23334", run_id="retry-test")
    store = JobStore(tmp_path, "retry-test", "CVE-2024-23334")
    job = store.create()
    store.fail(job, TaskError("infra_error", "docker went away"))

    job = pipeline._prepare_retry(store.load())
    assert job.state == "REPAIRING"
    assert job.attempts["retry"] == 1

    job = store.transition(store.load(), "GENERATED", "rebuilt")
    store.fail(job, TaskError("infra_error", "docker went away again"))
    pipeline._prepare_retry(store.load())
    store.fail(store.load(), TaskError("infra_error", "third"))
    job = pipeline._prepare_retry(store.load())
    assert job.state == "QUARANTINED"
    assert job.attempts["retry"] == 2


def test_quarantined_non_retryable_stays_terminal(tmp_path: Path):
    config = Config(pipeline=Settings(output_dir=str(tmp_path)))
    pipeline = CvePipeline(config=config, cve_id="CVE-2024-23334", run_id="retry-test-2")
    store = JobStore(tmp_path, "retry-test-2", "CVE-2024-23334")
    job = store.create()
    store.fail(job, TaskError("build_error", "bad image"))
    assert pipeline._prepare_retry(store.load()).state == "QUARANTINED"


def test_repair_overrides_are_restricted_and_change_the_digest(tmp_path: Path):
    from harbor_pipeline import fixtures
    from harbor_pipeline.generator import render_task

    spec = fixtures.cve_spec()
    base = render_task(spec, scenario_name="aiohttp_static_traversal", variant="vulnerable")
    changed = render_task(
        spec,
        scenario_name="aiohttp_static_traversal",
        variant="vulnerable",
        overrides={"environment/Dockerfile": base.files["environment/Dockerfile"] + "\n# x\n"},
    )
    assert changed.task_digest != base.task_digest
    assert "# x" in changed.files["environment/Dockerfile"]
    with pytest.raises(PipelineError, match="may not modify"):
        render_task(
            spec,
            scenario_name="aiohttp_static_traversal",
            variant="vulnerable",
            overrides={"tests/test.sh": "exit 0"},
        )


def test_repair_validator_rejects_escapes():
    from harbor_pipeline.repair import _validate

    files = {"environment/Dockerfile": "FROM python:3.12\n"}
    assert _validate({"files": [], "reason": "none"}, files, {}) == {}
    applied = _validate(
        {"files": [{"path": "environment/Dockerfile", "content": "FROM python:3.12\n# fix\n"}],
         "reason": "pin"},
        files,
        {},
    )
    assert applied == {"environment/Dockerfile": "FROM python:3.12\n# fix\n"}
    for bad in ("tests/test.sh", "environment/../tests/test.sh", "environment/new.sh"):
        with pytest.raises(PipelineError):
            _validate(
                {"files": [{"path": bad, "content": "x"}], "reason": "bad"},
                files,
                {},
            )


def test_fixture_repairer_is_a_noop(tmp_path: Path):
    from harbor_pipeline.config import ModelSettings
    from harbor_pipeline.repair import RepairEngine

    config = Config(models={"default": ModelSettings(provider="fixture")})
    ledger = Ledger.load_or_create(
        tmp_path / "budget.json", limits={"calls": 5, "tokens": 100000, "usd": 1.0}
    )
    engine = RepairEngine(config, ledger)
    result = engine.repair(
        cve_id="CVE-2024-23334",
        revision=2,
        error=TaskError("build_error", "docker build failed"),
        files={"environment/Dockerfile": "FROM python:3.12-slim\n"},
    )
    assert result.files == {}
    assert result.error is None
    assert ledger.snapshot()["used"]["calls"] == 1


def test_dataset_split_is_group_stable():
    group = root_cause_group({"root_cause": {"summary": "path traversal in static handler"}})
    assert group == "path-traversal"
    splits = {
        dataset_split(cve, "aiohttp", group)
        for cve in ("CVE-2024-23334", "CVE-2024-23335", "CVE-2024-23336")
    }
    assert len(splits) == 1


# ---------------------------------------------------------------------------
# Batch execution and reporting
# ---------------------------------------------------------------------------


def _released_payload(cve_id: str, run_id: str) -> dict:
    entry = {
        "cve_id": cve_id,
        "task_version": "1.0.0",
        "artifact_digest": "sha256:" + "a" * 64,
        "project": "aiohttp",
        "root_cause_group": "path-traversal",
        "patch_group": "1c335944d6a8",
        "split": "train",
        "location": "runs/x/task",
    }
    return {
        "schema_version": "1.0",
        "cve_id": cve_id,
        "run_id": run_id,
        "state": "RELEASED",
        "task_digest": "t",
        "image_digest": entry["artifact_digest"],
        "quality_score": 100.0,
        "admission_status": "released",
        "release": {"dataset_entry": entry},
        "evaluation": {},
        "trials": [
            {"experiment_id": "T03", "goal_result": "passed", "duration_sec": 12.0},
            {"experiment_id": "T09", "goal_result": "passed", "duration_sec": 10.0},
        ],
        "error": None,
        "budget": {},
        "attempts": 1,
    }


def test_run_batch_aggregates_reports_and_dataset(tmp_path: Path, monkeypatch):
    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-run",
        profile="qualification",
        workers=1,
        output_root=tmp_path,
    )
    monkeypatch.setattr(
        batch_module,
        "run_candidate",
        lambda job, config: _released_payload(job.cve_id, job.run_id),
    )
    summary = run_batch(plan, Config(), output_root=tmp_path)
    root = tmp_path / "batch-run"
    assert summary["counts"]["RELEASED"] == 1
    assert summary["dataset"]["split_audit"]["ok"] is True
    assert (root / "batch-report.json").is_file()
    assert (root / "dataset-manifest.json").is_file()
    assert (root / "reports" / "CVE-2024-23334.json").is_file()
    assert summary["difficulty_baseline"]["oracle_success_rate"] == 1.0


def test_run_batch_worker_exception_is_terminal(tmp_path: Path, monkeypatch):
    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-fault",
        profile="smoke",
        workers=1,
        output_root=tmp_path,
    )

    def explode(job, config):
        raise RuntimeError("worker died")

    monkeypatch.setattr(batch_module, "run_candidate", explode)
    summary = run_batch(plan, Config(), output_root=tmp_path)
    entries = [item for item in summary["candidates"] if item["cve_id"] == "CVE-2024-23334"]
    assert entries and entries[0]["state"] == "QUARANTINED"
    assert "worker died" in entries[0]["error_message"]


def test_run_batch_records_unsupported_input(tmp_path: Path):
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2099-0004")],
        run_id="batch-unsupported",
        profile="smoke",
        workers=1,
        output_root=tmp_path,
    )
    summary = run_batch(plan, Config(), output_root=tmp_path)
    assert summary["counts"]["UNSUPPORTED"] == 1
    assert summary["dataset"]["entries"] == []


def test_run_batch_workers_resume_the_plan_run_directory(tmp_path: Path, monkeypatch):
    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-root",
        profile="smoke",
        workers=1,
        output_root=tmp_path,
    )
    seen: list[Path] = []

    def capture(job, config):
        seen.append(job.output_root)
        return _released_payload(job.cve_id, job.run_id)

    monkeypatch.setattr(batch_module, "run_candidate", capture)
    run_batch(plan, Config(), output_root=tmp_path)
    assert seen == [plan.root.parent]


def test_audit_bundle_keeps_same_experiment_trials_separate(tmp_path: Path):
    import zipfile

    from harbor_pipeline.release import _write_audit

    run_dir = tmp_path / "run"
    release_dir = run_dir / "release"
    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "source.json").write_text("{}", encoding="utf-8")
    release_dir.mkdir()
    records = []
    for name in ("trial-a", "trial-b"):
        trial_dir = run_dir / "jobs" / name
        trial_dir.mkdir(parents=True)
        evidence = trial_dir / "evidence.json"
        evidence.write_text(json.dumps({"trial": name}), encoding="utf-8")
        records.append({
            "experiment_id": "T03",
            "_audit": {"trial_name": name, "evidence": str(evidence)},
        })
    _write_audit(
        release_dir / "audit.zip",
        {"cve_id": "CVE-2024-23334"},
        {"sources": []},
        {"quality_score": 100.0},
        {"image_digest": "x"},
        {"records": records},
        release_dir,
    )
    with zipfile.ZipFile(release_dir / "audit.zip") as archive:
        names = archive.namelist()
    assert len(names) == len(set(names))
    assert "trials/T03/trial-a/evidence.json" in names
    assert "trials/T03/trial-b/evidence.json" in names


def test_model_baseline_records_success_latency_and_usage(tmp_path: Path):
    from harbor_pipeline.benchmark import measure_model_baseline
    from harbor_pipeline.harbor_adapter import JobOutcome, TrialOutcome

    task_dir = tmp_path / "release" / "task"
    task_dir.mkdir(parents=True)
    (task_dir / "task.toml").write_text('schema_version = "1.4"\n', encoding="utf-8")
    (task_dir / "instruction.md").write_text("read the token\n", encoding="utf-8")
    (task_dir.parent / "build-manifest.json").write_text(
        json.dumps({"task_digest": "digest-1"}), encoding="utf-8"
    )
    trials = []
    for index, reward in enumerate((1.0, 0.0)):
        trial_dir = tmp_path / "jobs" / f"task__{index}"
        trial_dir.mkdir(parents=True)
        (trial_dir / "result.json").write_text(json.dumps({
            "agent_info": {"name": "claude-code", "version": "1", "model_info": {"model": "m"}},
            "agent_result": {"n_input_tokens": 10, "n_output_tokens": 2, "cost_usd": 0.5},
        }), encoding="utf-8")
        trials.append(TrialOutcome(
            trial_name=trial_dir.name,
            task_path=str(task_dir),
            task_name="task",
            trial_dir=trial_dir,
            reward=reward,
            exception=None,
            evidence={"status": "healthy" if reward else "goal_failed"},
            started_at=None,
            finished_at=None,
            duration_sec=10.0 + index,
        ))

    class FakeAdapter:
        def run(self, *args, **kwargs):
            assert kwargs["n_attempts"] == 2
            return JobOutcome(
                job_name="baseline",
                job_dir=tmp_path / "jobs",
                config_path=tmp_path / "config.json",
                stdout_path=tmp_path / "log",
                returncode=0,
                result={},
                trials=trials,
            )

    result = measure_model_baseline(
        FakeAdapter(), task_dir, agent="claude-code", model_name="m", attempts=2
    )
    assert result["successes"] == 1
    assert result["success_rate"] == 0.5
    assert result["median_duration_sec"] == 10.5
    assert result["usage"]["n_input_tokens"] == 20
    assert result["failure_types"] == {"goal_failed": 1}
    assert result["model_identity"]["model_info"] == {"model": "m"}
    assert result["task_digest"] == "digest-1"
    assert result["prompt_sha256"].startswith("sha256:")


def test_batch_reads_model_baseline_file(tmp_path: Path, monkeypatch):
    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-model",
        profile="qualification",
        workers=1,
        output_root=tmp_path,
    )
    plan.root.mkdir(parents=True)
    (plan.root / "model-baseline.json").write_text(json.dumps({
        "agent": "claude-code",
        "model_name": "sonnet",
        "attempts": 3,
        "successes": 2,
        "success_rate": 0.6667,
        "median_duration_sec": 12.0,
    }), encoding="utf-8")
    monkeypatch.setattr(
        batch_module,
        "run_candidate",
        lambda job, config: _released_payload(job.cve_id, job.run_id),
    )
    summary = run_batch(plan, Config(), output_root=tmp_path)
    baseline = summary["difficulty_baseline"]["model_baseline"]
    assert baseline["success_rate"] == 0.6667
    assert baseline["agent"] == "claude-code"
    assert "model-baseline.json" in baseline["path"]


def test_benchmark_forwards_provider_credentials_without_recording_values(
    tmp_path: Path, monkeypatch
):
    from harbor_pipeline.benchmark import measure_model_baseline
    from harbor_pipeline.harbor_adapter import JobOutcome, TrialOutcome

    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "secret-token")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://example.invalid")
    task_dir = tmp_path / "task"
    task_dir.mkdir()
    (task_dir / "task.toml").write_text('schema_version = "1.4"\n', encoding="utf-8")
    trial_dir = tmp_path / "jobs" / "task__one"
    trial_dir.mkdir(parents=True)
    seen = {}

    class FakeAdapter:
        def run(self, *args, **kwargs):
            seen["env"] = kwargs["agent_env"]
            seen["setup_timeout"] = kwargs["agent_setup_timeout_sec"]
            return JobOutcome(
                job_name="baseline",
                job_dir=tmp_path / "jobs",
                config_path=tmp_path / "config.json",
                stdout_path=tmp_path / "log",
                returncode=0,
                result={},
                trials=[TrialOutcome(
                    trial_name="task__one",
                    task_path=str(task_dir),
                    task_name="task",
                    trial_dir=trial_dir,
                    reward=1.0,
                    exception=None,
                    evidence={"status": "healthy"},
                    started_at=None,
                    finished_at=None,
                    duration_sec=1.0,
                )],
            )

    result = measure_model_baseline(
        FakeAdapter(), task_dir, attempts=1, agent_env={"CUSTOM_FLAG": "yes"}
    )
    assert seen["env"]["ANTHROPIC_AUTH_TOKEN"] == "secret-token"
    assert seen["env"]["CUSTOM_FLAG"] == "yes"
    assert seen["setup_timeout"] == 1800
    assert result["fixed_settings"]["agent_env_vars"] == [
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CUSTOM_FLAG",
    ]
    assert result["model_endpoint_host"] == "example.invalid"
    assert "secret-token" not in json.dumps(result)


def test_adapter_templatizes_credentials_in_job_config(monkeypatch):
    from harbor_pipeline.harbor_adapter import _persisted_agent_env
    from harbor_pipeline.util import PipelineError

    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "secret-token")
    persisted = _persisted_agent_env({
        "ANTHROPIC_AUTH_TOKEN": "secret-token",
        "ANTHROPIC_BASE_URL": "https://example.invalid",
    })
    assert persisted["ANTHROPIC_AUTH_TOKEN"] == "${ANTHROPIC_AUTH_TOKEN}"
    assert persisted["ANTHROPIC_BASE_URL"] == "https://example.invalid"

    try:
        _persisted_agent_env({"ANTHROPIC_AUTH_TOKEN": "different"})
    except PipelineError as exc:
        assert "ANTHROPIC_AUTH_TOKEN" in str(exc)
    else:
        raise AssertionError("literal credential must be rejected")


def test_prepare_benchmark_task_changes_only_the_agent_dockerfile(tmp_path: Path):
    from harbor_pipeline.benchmark import prepare_benchmark_task

    source = tmp_path / "release" / "task"
    (source / "environment").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "environment" / "Dockerfile").write_text(
        "FROM python:3.12-slim\n", encoding="utf-8"
    )
    (source / "instruction.md").write_text("find the token\n", encoding="utf-8")
    (source / "tests" / "test.sh").write_text("exit 0\n", encoding="utf-8")
    (source / "task.toml").write_text('schema_version = "1.4"\n', encoding="utf-8")

    dest = prepare_benchmark_task(source, tmp_path / "bench" / "task", "example/agent:1")

    assert "FROM example/agent:1" in (dest / "environment" / "Dockerfile").read_text()
    assert (dest / "instruction.md").read_text() == "find the token\n"
    assert (dest / "tests" / "test.sh").read_text() == "exit 0\n"
    assert (source / "environment" / "Dockerfile").read_text().startswith("FROM python")
