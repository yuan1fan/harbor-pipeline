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
from harbor_pipeline.providers.base import ModelRequest
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
    assert [c.cve_id for c in plan.candidates] == ["CVE-2024-23334", "CVE-2099-0001"]
    assert plan.duplicates == [
        {"cve_id": "CVE-2024-23334", "duplicate_of": "CVE-2024-23334"}
    ]
    assert plan.unsupported == []
    assert plan.limits["trials"] > 0
    assert plan.limits["builds"] >= 9
    # The ledger is shared by the whole batch, so the model ceilings must scale
    # with the candidate count instead of staying at the per-run defaults.
    assert plan.limits["calls"] > 12
    assert plan.limits["tokens"] > 180000
    assert plan.limits["usd"] > 3.0
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


def test_worker_routes_unknown_cve_to_auto_discovery(tmp_path: Path, monkeypatch):
    import harbor_pipeline.pipeline as pipeline_module
    from harbor_pipeline.errors import TaskError

    def no_record(settings, run_dir, cve_id):
        raise TaskError("unsupported", f"no public record for {cve_id}")

    monkeypatch.setattr(pipeline_module.discovery_mod, "collect", no_record)
    payload = run_candidate(_job(tmp_path, "CVE-2099-0003"), Config())
    assert payload["state"] == "UNSUPPORTED"
    assert payload["error"]["category"] == "unsupported"
    assert payload["error"]["retryable"] is False


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


def test_matrix_repeats_defaults_to_the_profile_and_follows_the_author(tmp_path: Path):
    from types import SimpleNamespace

    config = Config(pipeline=Settings(output_dir=str(tmp_path)))
    pipeline = CvePipeline(
        config=config,
        cve_id="CVE-2024-23334",
        run_id="repeats",
        profile="qualification",
    )
    # A deterministic exploit uses the profile floor.
    assert pipeline._matrix_repeats() == 3
    # The author may raise it when the exploit path is nondeterministic.
    pipeline.synthesis = SimpleNamespace(bundle={"matrix_repeats": 8})
    assert pipeline._matrix_repeats() == 8
    # A malformed or oversized request cannot schedule a giant matrix.
    pipeline.synthesis = SimpleNamespace(bundle={"matrix_repeats": 10_000})
    assert pipeline._matrix_repeats() == 20
    pipeline.synthesis = SimpleNamespace(bundle={})
    assert pipeline._matrix_repeats() == 3


def test_replicate_matrix_renders_repeats_of_both_samples(tmp_path: Path, monkeypatch):
    """The repeat count is the only thing that changes between a 3- and a
    20-trial dataset: both T03 and T04 get exactly `repeats` copies."""
    import harbor_pipeline.differential as differential_mod
    from harbor_pipeline.contracts import load_experiments

    class FakeTask:
        task_digest = "digest"

        def write(self, path: Path) -> Path:
            path.mkdir(parents=True, exist_ok=True)
            return path

    monkeypatch.setattr(differential_mod, "render_task", lambda *a, **k: FakeTask())
    experiments = tuple(
        e for e in load_experiments() if e.id in {"T03", "T04"}
    )
    cases = differential_mod.replicate_matrix(
        {"cve_id": "CVE-2024-0001"},
        scenario_name="s",
        root=tmp_path,
        network_mode="none",
        allowed_hosts=(),
        experiments=experiments,
        repeats=3,
    )
    assert [case.task_dir.name for case in cases] == [
        "t03-01",
        "t03-02",
        "t03-03",
        "t04-01",
        "t04-02",
        "t04-03",
    ]


def _verdict(experiment_id: str, *, met: bool, category: str | None = None):
    from harbor_pipeline.trials import Expectation

    return Expectation(
        experiment_id=experiment_id,
        met=met,
        detail=f"{experiment_id} {'ok' if met else 'missed'}",
        observed_status="goal_passed" if met else "goal_failed",
        error_category=category,
    )


def test_trial_classification_separates_infra_from_scored_failures():
    """T12's decision is a pure mapping; only the fault injection needs Docker."""
    from harbor_pipeline.harbor_adapter import TrialOutcome, classify_trial

    def trial(*, reward=None, exception=None, status="missing"):
        return TrialOutcome(
            trial_name="t",
            task_path="",
            task_name="t",
            trial_dir=Path("."),
            reward=reward,
            exception=exception,
            evidence={"status": status},
            started_at=None,
            finished_at=None,
            duration_sec=0.0,
        )

    # A target that never starts is infrastructure, not a model miss.
    assert classify_trial(trial(status="target_unhealthy")) == "infra_error"
    assert classify_trial(trial(status="missing")) == "infra_error"
    assert classify_trial(trial(exception={"type": "DockerBuildError"})) == "build_error"
    assert classify_trial(trial(exception={"type": "ValueError"})) == "infra_error"
    # A trial that produced a reward was scored: it is never an infra error.
    assert classify_trial(trial(reward=0.0, status="goal_failed")) is None
    assert classify_trial(trial(reward=0.0, status="oracle_failure")) is None


def test_resumed_debug_loads_the_cached_synthesis(tmp_path, monkeypatch):
    # A repair resumed from QUARANTINED runs before synthesize(). Without the
    # cached bundle the debug task renders with scenario='synthesized' and no
    # template, which used to abort the second repair.
    from types import SimpleNamespace

    import harbor_pipeline.pipeline as pipeline_mod

    pipeline = object.__new__(CvePipeline)
    pipeline.auto = True
    pipeline.synthesis = None
    pipeline.cve_id = "CVE-2024-0001"
    pipeline.store = SimpleNamespace(root=tmp_path)
    sentinel = object()
    monkeypatch.setattr(
        pipeline_mod.synthesis_mod, "load", lambda _root, _cve: sentinel
    )
    pipeline._ensure_synthesis()
    assert pipeline.synthesis is sentinel

    # A curated scenario has no synthesis bundle and must stay untouched.
    curated = object.__new__(CvePipeline)
    curated.auto = False
    curated.synthesis = None
    curated._ensure_synthesis()
    assert curated.synthesis is None


def test_task_files_keep_the_variant_ref_placeholder(tmp_path: Path):
    from types import SimpleNamespace

    from harbor_pipeline.pipeline import CvePipeline

    task = tmp_path / "task"
    (task / "environment" / "target").mkdir(parents=True)
    (task / "environment" / "target" / "requirements.txt").write_text(
        "foo==1.0.0\n", encoding="utf-8"
    )
    (task / "environment" / "target" / "app.py").write_text(
        "print('app')\n", encoding="utf-8"
    )
    (task / "environment" / "Dockerfile").write_text(
        "FROM python:3.12\n", encoding="utf-8"
    )
    (task / "tests").mkdir()
    (task / "tests" / "reference_poc.py").write_text(
        "print('probe')\n", encoding="utf-8"
    )
    (task / "instruction.md").write_text("# task\n", encoding="utf-8")

    pipeline = object.__new__(CvePipeline)
    pipeline.store = SimpleNamespace(path=lambda *parts: tmp_path.joinpath(*parts))
    pipeline._overlay = lambda: {}
    pipeline._ensure_synthesis = lambda: None
    pipeline.synthesis = SimpleNamespace(
        target={
            "files": {
                "requirements.txt": "foo=={{REF}}\n",
                "app.py": "print('app')\n",
            }
        },
        poc={"reference": "print('probe')\n"},
    )

    files = pipeline._task_files()

    # The author sees the template, not the vulnerable variant's substitution,
    # so an edit cannot silently pin the fixed build to the vulnerable release.
    assert files["environment/target/requirements.txt"] == "foo=={{REF}}\n"
    # Framework-owned files stay as rendered.
    assert files["environment/Dockerfile"] == "FROM python:3.12\n"
    assert files["instruction.md"] == "# task\n"
    assert files["tests/reference_poc.py"] == "print('probe')\n"


def test_debug_overrides_keep_an_earlier_poc_repair():
    from harbor_pipeline.repair import POC_PATH

    pipeline = object.__new__(CvePipeline)
    pipeline._overlay = lambda: {POC_PATH: "repaired"}
    merged = pipeline._debug_overrides({
        "environment/target/server.js": "new",
    })
    assert merged[POC_PATH] == "repaired"
    assert merged["environment/target/server.js"] == "new"


def test_build_prebuilds_both_variants_for_the_probes(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    import harbor_pipeline.pipeline as pipeline_mod
    from harbor_pipeline import fixtures
    from harbor_pipeline.generator import render_task

    config = Config(pipeline=Settings(output_dir=str(tmp_path)))
    pipeline = CvePipeline(
        config=config,
        cve_id="CVE-2024-23334",
        run_id="build-test",
        scenario="fixture",
    )
    pipeline._capabilities = SimpleNamespace(
        harbor_version="0.23.0", network_mode="public"
    )
    spec = fixtures.cve_spec()
    task = render_task(spec, scenario_name="fixture", variant="vulnerable")
    pipeline.store.create()
    task.write(pipeline.store.root)

    calls: list[dict] = []

    def fake_build(**kwargs):
        calls.append(kwargs)
        return {
            "tag_base": kwargs["tag_base"],
            "images": {},
            "target_digest": "sha256:" + "a" * 64,
            "architecture": "x86_64",
            "dependencies": {},
        }

    monkeypatch.setattr(pipeline_mod, "build_task_images", fake_build)
    image_set = pipeline.build(spec, task)

    assert [call["variant"] for call in calls] == ["vulnerable", "fixed"]
    assert calls[0]["tag_base"] == "harbor-pipeline/cve-2024-23334-vulnerable-r1"
    assert calls[1]["tag_base"] == "harbor-pipeline/cve-2024-23334-fixed-r1"
    assert image_set["tag_bases"] == [
        "harbor-pipeline/cve-2024-23334-vulnerable-r1",
        "harbor-pipeline/cve-2024-23334-fixed-r1",
    ]
    assert image_set["variants"]["fixed"]["tag_base"].endswith("fixed-r1")


def test_matrix_ladder_stops_at_the_first_blocking_failure():
    from harbor_pipeline.differential import MatrixResult, MatrixStep, run_ladder

    calls: list[str] = []

    def run_step(step):
        calls.append(step.key)
        result = MatrixResult()
        result.verdicts.append(_verdict("T03", met=step.key != "t03-first"))
        return result

    steps = [
        MatrixStep("t01", ("T01",), 1, True),
        MatrixStep("t02", ("T02",), 1, True),
        MatrixStep("t03-first", ("T03",), 1, True),
        MatrixStep("t04-first", ("T04",), 1, True),
    ]
    ladder = run_ladder(steps, run_step)
    assert calls == ["t01", "t02", "t03-first"]
    assert ladder.aborted_at == "t03-first"
    assert "T03" in ladder.aborted_detail
    assert len(ladder.verdicts) == 3


def test_matrix_ladder_continues_after_an_advisory_failure():
    from harbor_pipeline.differential import MatrixResult, MatrixStep, run_ladder

    calls: list[str] = []

    def run_step(step):
        calls.append(step.key)
        result = MatrixResult()
        if step.key == "t11":
            result.verdicts.append(_verdict("T11", met=False))
        else:
            result.verdicts.append(_verdict("T03", met=True))
        return result

    steps = [
        MatrixStep("t11", ("T11",), 1, False),
        MatrixStep("confirm", ("T03", "T04"), 2, True),
    ]
    ladder = run_ladder(steps, run_step)
    assert calls == ["t11", "confirm"]
    assert ladder.aborted_at is None


def test_matrix_ladder_classifies_an_infra_failure():
    from harbor_pipeline.differential import MatrixResult, MatrixStep, run_ladder

    def run_step(step):
        result = MatrixResult()
        result.verdicts.append(
            _verdict("T01", met=False, category="infra_error")
        )
        return result

    ladder = run_ladder([MatrixStep("t01", ("T01",), 1, True)], run_step)
    assert ladder.aborted_at == "t01"
    assert ladder.aborted_category == "infra_error"


def _derive(matrix, spec, *, revision=1):
    from types import SimpleNamespace

    from harbor_pipeline.pipeline import CvePipeline

    pipeline = object.__new__(CvePipeline)
    pipeline.run_id = "derive"
    pipeline.synthesis = None
    pipeline._derive_health_verdicts(
        matrix, spec, SimpleNamespace(revision=revision), "sha256:" + "a" * 64
    )


def test_health_verdicts_are_derived_from_t03_and_t04():
    from harbor_pipeline import fixtures
    from harbor_pipeline.differential import MatrixResult

    spec = fixtures.cve_spec()
    matrix = MatrixResult(records=[
        fixtures.trial_record("T03", health=True),
        fixtures.trial_record("T04", health=True),
    ])
    _derive(matrix, spec)

    assert matrix.expectation("T01").met is True
    assert matrix.expectation("T02").met is True
    assert [record["experiment_id"] for record in matrix.derived_records] == ["T01", "T02"]
    assert all(
        record["_audit"]["mode"] == "derived"
        for record in matrix.derived_records
    )


def test_derived_health_marks_an_unrun_t04_as_unknown():
    from harbor_pipeline import fixtures
    from harbor_pipeline.differential import MatrixResult

    spec = fixtures.cve_spec()
    matrix = MatrixResult(records=[fixtures.trial_record("T03", health=True)])
    _derive(matrix, spec)

    assert matrix.expectation("T01").met is True
    t02 = matrix.expectation("T02")
    assert t02.met is False
    assert t02.observed_status == "missing"
    # No T04 record means no derived T02 record either.
    assert [record["experiment_id"] for record in matrix.derived_records] == ["T01"]


def test_derived_health_reports_an_unhealthy_vulnerable_build():
    from harbor_pipeline import fixtures
    from harbor_pipeline.differential import MatrixResult

    spec = fixtures.cve_spec()
    matrix = MatrixResult(records=[fixtures.trial_record("T03", health=False)])
    _derive(matrix, spec)

    t01 = matrix.expectation("T01")
    assert t01.met is False
    assert t01.observed_status == "target_unhealthy"
    assert matrix.derived_records[0]["health"]["ok"] is False


def test_plan_matrix_steps_keeps_framework_negatives_out_of_the_ladder():
    from harbor_pipeline.differential import plan_matrix_steps

    steps = plan_matrix_steps(repeats=3)
    experiment_ids = [eid for step in steps for eid in step.experiment_ids]
    # T05/T06/T07/T10 run once per verifier template, not per candidate.
    assert not {"T05", "T06", "T07", "T10"} & set(experiment_ids)
    # T01/T02 are derived from T03/T04 instead of starting their own target.
    assert not {"T01", "T02"} & set(experiment_ids)
    assert [step.key for step in steps if not step.blocking] == ["t11", "t12"]
    assert steps[-1].key == "t12"
    assert any(step.key == "confirm" for step in steps)


def test_quarantined_validation_error_repairs_on_resume(tmp_path: Path, monkeypatch):
    from harbor_pipeline.repair import RepairResult

    config = Config(pipeline=Settings(output_dir=str(tmp_path), max_repairs=2))
    pipeline = CvePipeline(
        config=config, cve_id="CVE-2024-23334", run_id="retry-repair"
    )
    store = JobStore(tmp_path, "retry-repair", "CVE-2024-23334")
    job = store.create()
    environment = store.path("task") / "environment"
    environment.mkdir(parents=True)
    (environment / "app.py").write_text("print('app')\n", encoding="utf-8")
    store.write_artifact("cve-spec.json", {"cve_id": "CVE-2024-23334"})
    store.fail(
        job,
        TaskError("validation_error", "the reference exploit reached no secret"),
    )

    calls: list[dict] = []

    class Engine:
        def repair(self, **kwargs):
            calls.append(kwargs)
            return RepairResult(
                files={"environment/app.py": "print('repaired')\n"},
                reason="keep the reference route",
                model_identity="test",
                usage={},
            )

    monkeypatch.setattr(pipeline, "_repair_engine", lambda: Engine())
    job = pipeline._prepare_retry(store.load())

    assert job.state == "REPAIRING"
    assert job.attempts["repair"] == 1
    assert len(calls) == 1
    assert calls[0]["error"].category.code == "validation_error"
    overlay = store.read_artifact("repair-overlay.json")
    assert overlay["environment/app.py"] == "print('repaired')\n"


def test_resume_does_not_repair_past_the_budget(tmp_path: Path, monkeypatch):
    config = Config(pipeline=Settings(output_dir=str(tmp_path), max_repairs=1))
    pipeline = CvePipeline(
        config=config, cve_id="CVE-2024-23334", run_id="retry-capped"
    )
    store = JobStore(tmp_path, "retry-capped", "CVE-2024-23334")
    job = store.create()
    (store.path("task") / "environment").mkdir(parents=True)
    store.write_artifact("cve-spec.json", {"cve_id": "CVE-2024-23334"})
    job.attempts["repair"] = 1
    store.save(job)
    store.fail(job, TaskError("build_error", "the target image does not start"))

    monkeypatch.setattr(
        pipeline,
        "_repair_engine",
        lambda: pytest.fail("a resume must not repair past max_repairs"),
    )
    assert pipeline._prepare_retry(store.load()).state == "QUARANTINED"


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
        overrides={
            "environment/target/app/server.py":
                base.files["environment/target/app/server.py"] + "\n# x\n"
        },
    )
    assert changed.task_digest != base.task_digest
    assert "# x" in changed.files["environment/target/app/server.py"]
    with pytest.raises(PipelineError, match="may not modify"):
        render_task(
            spec,
            scenario_name="aiohttp_static_traversal",
            variant="vulnerable",
            overrides={"tests/test.sh": "exit 0"},
        )
    with pytest.raises(PipelineError, match="framework-owned"):
        render_task(
            spec,
            scenario_name="aiohttp_static_traversal",
            variant="vulnerable",
            overrides={"environment/target/entrypoint.sh": "exit 1"},
        )


def test_repair_write_paths_are_bounded():
    from harbor_pipeline.repair import _allowed_write

    # The author may rewrite the application, its target Dockerfile, new
    # helper files and the exploit. The verifier, instruction, frozen spec and
    # the framework-owned entrypoint/main compose are unreachable.
    assert _allowed_write("environment/target/Dockerfile")
    assert _allowed_write("environment/target/app.py")
    assert _allowed_write("environment/target/new_helper.py")
    assert _allowed_write("tests/reference_poc.py")
    for bad in (
        "tests/verify.py",
        "tests/test.sh",
        "instruction.md",
        "task.toml",
        "environment/target/entrypoint.sh",
        "environment/Dockerfile",
        "environment/docker-compose.yaml",
        "environment/../tests/test.sh",
        "/etc/passwd",
        "environment",
        "environment/",
    ):
        assert not _allowed_write(bad), bad


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
        files={"environment/target/app.py": "print('app')\n"},
    )
    assert result.files == {}
    assert result.error is None
    assert ledger.snapshot()["used"]["calls"] == 1


def test_repair_retries_a_malformed_reply(tmp_path: Path, monkeypatch):
    """A wrong response shape is a model-output fault, not a bad candidate."""
    from harbor_pipeline.config import ModelSettings
    from harbor_pipeline.providers.base import ModelResponse
    from harbor_pipeline.repair import RepairEngine

    class ScriptedProvider:
        name = "scripted"

        def __init__(self):
            self.prompts: list[str] = []

        def generate(self, request):
            self.prompts.append(request.prompt)
            if len(self.prompts) == 1:
                return ModelResponse(
                    text="not json",
                    structured=None,
                    usage={"input_tokens": 10, "output_tokens": 2, "usd": 0.5},
                    model_identity="scripted",
                )
            body = {"action": "abort", "reason": "nothing to change"}
            return ModelResponse(
                text=json.dumps(body),
                structured=body,
                usage={"input_tokens": 10, "output_tokens": 2, "usd": 0.5},
                model_identity="scripted",
            )

    provider = ScriptedProvider()
    monkeypatch.setattr(
        "harbor_pipeline.repair.build_provider", lambda *_args, **_kwargs: provider
    )
    config = Config(models={"default": ModelSettings(provider="fixture")})
    ledger = Ledger.load_or_create(
        tmp_path / "budget.json", limits={"calls": 5, "tokens": 100000, "usd": 2.0}
    )
    engine = RepairEngine(config, ledger)

    result = engine.repair(
        cve_id="CVE-2024-23334",
        revision=2,
        error=TaskError("validation_error", "reference exploit got HTTP 500"),
        files={"environment/target/app.py": "print('app')\n"},
    )

    assert result.error is None
    assert result.files == {}
    assert len(provider.prompts) == 2
    assert "not structured JSON" in provider.prompts[1]
    assert result.usage == {"input_tokens": 20, "output_tokens": 4, "usd": 1.0}
    assert ledger.snapshot()["used"]["calls"] == 2


def test_dataset_split_is_group_stable():
    group = root_cause_group({"root_cause": {"summary": "path traversal in static handler"}})
    assert group == "path-traversal"
    splits = {
        dataset_split(cve, "aiohttp", group)
        for cve in ("CVE-2024-23334", "CVE-2024-23335", "CVE-2024-23336")
    }
    assert len(splits) == 1


def test_repair_system_prompt_is_runtime_specific():
    from harbor_pipeline.repair import _system

    node = _system({"environment/target/server.mjs": "console.log(1)"})
    assert "node:child_process" in node
    go = _system({"environment/target/main.go": "package main"})
    assert "node:child_process" not in go
    assert "GOTOOLCHAIN=local" in go
    assert "Return JSON only" in go


def test_root_cause_group_ignores_incidental_path_mentions():
    # The word "path" comes from path.resolve(), not from a traversal bug.
    spec = {
        "root_cause": {
            "summary": (
                "The destination is resolved with path.resolve() before being "
                "placed in the argument vector, allowing injected flags."
            )
        }
    }
    assert root_cause_group(spec) == "injection"


def test_root_cause_group_normalises_the_fallback_summary():
    first = root_cause_group({"root_cause": {"summary": "Race in session  store."}})
    second = root_cause_group({"root_cause": {"summary": "Race in session\nstore."}})
    assert first == second
    assert first.startswith("root-cause-")


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
        "quality_score": None,
        "quality_tier": "A",
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


def test_dataset_manifest_keeps_releases_from_earlier_batches(tmp_path: Path, monkeypatch):
    """A run directory outlives a batch: releases from an earlier invocation
    must survive the manifest rewrite that a later batch performs."""
    import json

    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    monkeypatch.setattr(
        batch_module,
        "run_candidate",
        lambda job, config: _released_payload(job.cve_id, job.run_id),
    )
    for cve in ("CVE-2024-23334", "CVE-2024-34069"):
        plan = plan_batch(
            [Candidate(cve)],
            run_id="batch-union",
            profile="qualification",
            workers=1,
            output_root=tmp_path,
        )
        run_batch(plan, Config(), output_root=tmp_path)
    manifest = json.loads((tmp_path / "batch-union" / "dataset-manifest.json").read_text())
    assert [task["cve_id"] for task in manifest["tasks"]] == [
        "CVE-2024-23334",
        "CVE-2024-34069",
    ]


def test_run_batch_prunes_released_candidate_images(tmp_path: Path, monkeypatch):
    import harbor_pipeline.batch as batch_module
    from harbor_pipeline.batch import run_batch

    plan = plan_batch(
        [Candidate("CVE-2024-23334")],
        run_id="batch-prune",
        profile="qualification",
        workers=1,
        output_root=tmp_path,
    )
    root = tmp_path / "batch-prune"
    (root / "CVE-2024-23334").mkdir(parents=True)
    (root / "CVE-2024-23334" / "image-set.json").write_text(
        json.dumps({"tag_base": "harbor-pipeline/cve-2024-23334-vulnerable-r1"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        batch_module,
        "run_candidate",
        lambda job, config: _released_payload(job.cve_id, job.run_id),
    )
    calls: list[str] = []

    def fake_prune(tag_base: str) -> list[str]:
        calls.append(tag_base)
        return [f"{tag_base}-target:latest"]

    monkeypatch.setattr(batch_module, "prune_task_images", fake_prune)
    run_batch(plan, Config(), output_root=tmp_path, prune_images=True)

    assert calls == ["harbor-pipeline/cve-2024-23334-vulnerable-r1"]
    report = json.loads(
        (root / "reports" / "CVE-2024-23334.json").read_text(encoding="utf-8")
    )
    assert report["pruned_images"] == [
        "harbor-pipeline/cve-2024-23334-vulnerable-r1-target:latest"
    ]


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
    # A well-formed but nonexistent CVE is recorded, never silently dropped.
    # Depending on whether the public record answers 404 or the network fails,
    # it is UNSUPPORTED or QUARANTINED with a source error.
    assert summary["counts"]["inputs"] == 1
    assert (
        summary["state_counts"].get("UNSUPPORTED", 0)
        + summary["state_counts"].get("QUARANTINED", 0)
        == 1
    )
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
        "model_name": "deepseek-flash-cyber",
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


def test_shipped_model_configs_use_deepseek_flash_cyber(monkeypatch):
    """Every configurable model entry point uses the requested model."""
    import tomllib
    from harbor_pipeline.config import load_config

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://example.invalid")
    config = load_config(root / "pipeline.toml")
    assert config.model_for("default").model == "deepseek-flash-cyber"
    assert config.model_for("repairer").model == "deepseek-flash-cyber"

    api_config = load_config(root / "pipeline.api.toml")
    assert api_config.model_for("default").model == "deepseek-flash-cyber"
    assert api_config.models["default"].api_base == "https://example.invalid"

    raw = tomllib.loads((root / "pipeline.toml").read_text(encoding="utf-8"))
    # Repair returns whole files as one JSON object, so it cannot use the
    # agentic CLI provider: that model emits tool calls instead of JSON.
    assert raw["models"]["repairer"]["provider"] == "anthropic"
    assert config.model_for("repairer").api_base == "https://example.invalid"


def test_claude_cli_disables_tools_and_keeps_the_system_prompt(monkeypatch):
    import subprocess

    from harbor_pipeline.config import ModelSettings
    from harbor_pipeline.providers import claude_cli

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps({"result": '{"files": [], "reason": "ok"}', "model": "m"}),
            stderr="",
        )

    monkeypatch.setattr(claude_cli.shutil, "which", lambda _name: "claude")
    monkeypatch.setattr(claude_cli.subprocess, "run", fake_run)
    provider = claude_cli.ClaudeCliProvider(
        ModelSettings(provider="claude-cli", model="deepseek-flash-cyber", timeout_sec=10)
    )
    request = ModelRequest(
        role="repairer",
        system="SYSTEM RULES",
        prompt="fix the app",
        schema={"type": "object"},
    )

    provider.generate(request)

    argv = captured["argv"]
    assert argv[argv.index("--tools") + 1] == ""
    # Untrusted evidence-derived code must not reach a host shell.
    assert captured["input"].startswith("SYSTEM RULES")
    assert "fix the app" in captured["input"]
    assert "Return only JSON matching this schema" in captured["input"]


def test_claude_cli_falls_back_when_the_model_alias_is_rejected(monkeypatch):
    import subprocess

    from harbor_pipeline.config import ModelSettings
    from harbor_pipeline.providers import claude_cli

    seen = []

    def fake_run(argv, **_kwargs):
        seen.append(argv)
        if "--model" in argv:
            return subprocess.CompletedProcess(
                argv,
                1,
                stdout="",
                stderr='[claude-code:unrecognized_model] {"model":"alias"}',
            )
        return subprocess.CompletedProcess(
            argv, 0, stdout=json.dumps({"result": "ok"}), stderr=""
        )

    monkeypatch.setattr(claude_cli.shutil, "which", lambda _name: "claude")
    monkeypatch.setattr(claude_cli.subprocess, "run", fake_run)
    provider = claude_cli.ClaudeCliProvider(
        ModelSettings(provider="claude-cli", model="alias", timeout_sec=10)
    )

    response = provider.generate(ModelRequest(role="default", system="", prompt="hi"))

    assert response.text == "ok"
    assert len(seen) == 2
    assert "--model" in seen[0]
    assert "--model" not in seen[1]


# ---------------------------------------------------------------------------
# Validation repair routing
# ---------------------------------------------------------------------------


def _hard_conditions(failed: set[str]) -> list[dict]:
    ids = [
        "t01_vulnerable_health",
        "t02_fixed_health",
        "reference_poc_all_success",
        "zero_fixed_success",
        "negative_T05",
        "negative_T06",
        "negative_T07",
        "negative_T10",
        "infra_error_rate",
        "quality_threshold",
    ]
    return [
        {"id": hc_id, "passed": hc_id not in failed, "detail": f"{hc_id} detail"}
        for hc_id in ids
    ]


def _trial(experiment_id: str, *, goal="failed", status="oracle_failure",
           healthy=True, reward=0.0, evidence: str | None = None) -> dict:
    record = {
        "trial_id": f"{experiment_id}-trial",
        "experiment_id": experiment_id,
        "goal_result": goal,
        "health": {"ok": healthy},
        "trigger_evidence": {"observed": False, "detail": status},
        "reward": reward,
    }
    if evidence:
        record["_audit"] = {"evidence": evidence}
    return record


def _outcome(failed: set[str]):
    from types import SimpleNamespace

    return SimpleNamespace(
        evaluation={"admission_status": "quarantined"},
        hard_conditions=_hard_conditions(failed),
    )


def _classify(records: list[dict], failed: set[str]):
    from types import SimpleNamespace

    pipeline = object.__new__(CvePipeline)
    return CvePipeline._matrix_repair_error(
        pipeline,
        SimpleNamespace(records=records),
        _outcome(failed),
    )


def test_validation_failure_routes_to_app_repair(tmp_path: Path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({
        "status": "oracle_failure",
        "reference_exit": 1,
        "reference_error": "urllib.error.HTTPError: HTTP Error 500: Internal Server Error",
    }), encoding="utf-8")
    error = _classify(
        [_trial("T03", evidence=str(evidence))],
        {"reference_poc_all_success"},
    )

    assert error is not None
    assert error.category.code == "validation_error"
    assert error.category.auto_repairable is True
    assert "HTTP Error 500" in str(error)


def test_validation_repair_allows_negatives_that_only_crashed():
    # A broken app returns HTTP 500 for the negative submissions too, so each
    # ends as oracle_failure with zero reward. That is repairable app logic,
    # not a grader that accepts a negative.
    records = [_trial("T03")] + [
        _trial(experiment) for experiment in ("T05", "T06", "T07", "T10")
    ]
    failed = {
        "reference_poc_all_success",
        "negative_T05", "negative_T06", "negative_T07", "negative_T10",
    }

    error = _classify(records, failed)

    assert error is not None
    assert error.category.code == "validation_error"


def test_validation_repair_allows_a_t03_failure_with_an_unrun_t04():
    # T04 never runs when T03 fails, so the derived T02 is unknown. That must
    # not stop the repairer from fixing the application that failed T03.
    from types import SimpleNamespace

    from harbor_pipeline import fixtures
    from harbor_pipeline.differential import MatrixResult

    spec = fixtures.cve_spec()
    matrix = MatrixResult(records=[fixtures.trial_record("T03")])
    pipeline = object.__new__(CvePipeline)
    pipeline.run_id = "derive"
    pipeline.synthesis = None
    pipeline._derive_health_verdicts(
        matrix, spec, SimpleNamespace(revision=1), "sha256:" + "a" * 64
    )
    error = CvePipeline._matrix_repair_error(
        pipeline,
        matrix,
        _outcome({"reference_poc_all_success", "t02_fixed_health"}),
    )
    assert error is not None
    assert error.category.code == "validation_error"


def test_validation_repair_blocks_an_observed_unhealthy_fixed_build():
    from types import SimpleNamespace

    from harbor_pipeline import fixtures
    from harbor_pipeline.differential import MatrixResult

    spec = fixtures.cve_spec()
    matrix = MatrixResult(records=[
        fixtures.trial_record("T03", health=True),
        fixtures.trial_record("T04", health=False),
    ])
    pipeline = object.__new__(CvePipeline)
    pipeline.run_id = "derive"
    pipeline.synthesis = None
    pipeline._derive_health_verdicts(
        matrix, spec, SimpleNamespace(revision=1), "sha256:" + "a" * 64
    )
    assert CvePipeline._matrix_repair_error(
        pipeline,
        matrix,
        _outcome({"reference_poc_all_success", "t02_fixed_health"}),
    ) is None


def test_validation_repair_allows_unrun_negatives_after_a_fail_fast_stop():
    # The ladder stops at the first failed T03, so T05/T07 never ran. Their
    # absence is not evidence that the grader is too loose.
    error = _classify(
        [_trial("T03")],
        {"reference_poc_all_success", "negative_T05", "negative_T07"},
    )
    assert error is not None
    assert error.category.code == "validation_error"


def test_validation_repair_still_blocks_when_an_observed_negative_was_accepted():
    records = [
        _trial("T03"),
        _trial("T05", goal="passed", status="goal_passed", reward=1.0),
    ]
    assert _classify(
        records,
        {"reference_poc_all_success", "negative_T05", "negative_T07"},
    ) is None


def test_validation_repair_skips_an_accepted_negative():
    # reward 1.0 means the negative reached the goal: the grader is too loose.
    records = [
        _trial("T03"),
        _trial("T05", goal="passed", status="goal_passed", reward=1.0),
    ]

    assert _classify(
        records, {"reference_poc_all_success", "negative_T05"}
    ) is None


def test_validation_repair_skips_verifier_and_health_failures():
    t03 = [_trial("T03")]
    assert _classify(t03, {"negative_T05"}) is None
    assert _classify(t03, {"t01_vulnerable_health"}) is None
    assert _classify(t03, {"quality_threshold"}) is None
    assert _classify(t03, set()) is None


def test_validation_repair_ignores_passing_and_held_trials():
    records = [
        _trial("T03", goal="passed", status="goal_passed", reward=1.0),
        _trial("T04", status="fixed_variant_holds", reward=0.0),
        _trial("T04", status="fixed_variant_leaks", reward=0.0),
    ]
    error = _classify(records, {"zero_fixed_success"})

    assert error is not None
    assert "T03-trial" not in str(error)
    assert str(error).count("T04-trial") == 1
    assert "fixed_variant_leaks" in str(error)


def test_prune_orphan_networks_removes_only_unused_task_networks(monkeypatch):
    from types import SimpleNamespace

    from harbor_pipeline import backend

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["network", "ls"]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "task__a__env_default\n"
                    "task__b__verifier__trial_default\n"
                    "user_project_default\n"
                ),
            )
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(backend.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(backend.subprocess, "run", fake_run)

    removed = backend.prune_orphan_networks()

    assert removed == ["task__a__env_default", "task__b__verifier__trial_default"]
    listings = [c for c in calls if c[1:3] == ["network", "ls"]]
    assert listings[0][3:5] == ["--filter", "dangling=true"]
    removals = [c for c in calls if c[1:3] == ["network", "rm"]]
    assert removals == [
        ["docker", "network", "rm", "task__a__env_default"],
        ["docker", "network", "rm", "task__b__verifier__trial_default"],
    ]


def test_repair_may_rewrite_the_exploit_on_any_failure():
    from harbor_pipeline.repair import POC_PATH, _editable

    # The exploit is an authoring artifact; the paired verifier keeps it
    # honest, not a rule about which error category permits touching it.
    assert _editable(POC_PATH)
    assert _editable("environment/target/app.py")
    assert not _editable("tests/verify.py")
    assert not _editable("instruction.md")


def test_repair_still_cannot_touch_the_verifier():
    from harbor_pipeline.repair import _allowed_write

    assert not _allowed_write("tests/verify.py")
    assert not _allowed_write("tests/test.sh")
    assert not _allowed_write("instruction.md")
    assert not _allowed_write("task.toml")


def test_exploit_override_reaches_the_rendered_task():
    from harbor_pipeline.generator import _apply_overrides

    files = {
        "environment/target/app.py": "print('ok')",
        "tests/reference_poc.py": "print('probe')",
        "tests/verify.py": "print('grade')",
    }

    patched = _apply_overrides(files, {"tests/reference_poc.py": "print('v2')"})
    assert patched["tests/reference_poc.py"] == "print('v2')"

    with pytest.raises(PipelineError):
        _apply_overrides(files, {"tests/verify.py": "print(1.0)"})


def test_repair_override_keeps_the_variant_refs_apart():
    """A shared manifest edit must not pin the fixed build to the vulnerable release."""
    from harbor_pipeline import fixtures
    from harbor_pipeline.generator import render_task
    from harbor_pipeline.synthesis import Synthesis
    from harbor_pipeline.util import digest

    spec = fixtures.cve_spec()
    bundle = {
        "product": {"name": spec["product"]["name"]},
        "versions": spec["versions"],
        "preconditions": spec["preconditions"],
        "root_cause": spec["root_cause"],
        "impact": spec["impact"],
        "task_goal": spec["task_goal"],
        "fix_basis": spec["fix_basis"],
        "assertions": spec["assertions"],
        "target": {
            "port": 8080,
            "start_command": "python app.py",
            "files": {
                "Dockerfile": "FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n",
                "requirements.txt": "foo=={{REF}}\n",
                "app.py": "print('app')\n",
            },
            "fixed_overrides": {"requirements.txt": "fixed=={{REF}}\n"},
        },
        "poc": {"reference": "print('poc')\n", "alternate": "print('alt')\n"},
    }
    synthesis = Synthesis(
        cve_id=spec["cve_id"],
        bundle=bundle,
        model_identity="test",
        usage={},
        prompt_sha256="",
        generated_at="",
        digest=digest(bundle),
    )
    overrides = {
        "environment/target/requirements.txt": "bar=={{REF}}\n# repaired\n",
    }

    vulnerable = render_task(
        spec, scenario_name="fixture", variant="vulnerable",
        synthesis=synthesis, overrides=overrides,
    )
    fixed = render_task(
        spec, scenario_name="fixture", variant="fixed",
        synthesis=synthesis, overrides=overrides,
    )

    assert vulnerable.files["environment/target/requirements.txt"] == (
        f"bar=={spec['versions']['vulnerable_ref']}\n# repaired\n"
    )
    # The bundle's fixed-only pin wins over a vulnerable-side repair.
    assert fixed.files["environment/target/requirements.txt"] == (
        f"fixed=={spec['versions']['fixed_ref']}\n"
    )


def test_authoring_override_adds_files_and_keeps_the_variant_ref_placeholder():
    from harbor_pipeline.generator import _apply_overrides

    files = {
        "environment/target/requirements.txt": "foo=={{REF}}\n",
        "tests/reference_poc.py": "print('probe')",
    }
    patched = _apply_overrides(
        files,
        {
            "environment/target/requirements.txt": "bar=={{REF}}\n# repaired\n",
            "environment/target/helper.py": "VALUE = 1\n",
        },
        version="1.2.3",
    )
    # The placeholder is substituted per variant, so the fixed build keeps its
    # own release even though the repairer rewrote the shared manifest.
    assert patched["environment/target/requirements.txt"] == "bar==1.2.3\n# repaired\n"
    assert patched["environment/target/helper.py"] == "VALUE = 1\n"


