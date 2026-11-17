"""Resume successful trials/seeds while preserving input and provenance checks."""
from types import SimpleNamespace

import pytest

from harbor_pipeline import backend, fixtures, pipeline as pipeline_mod
from harbor_pipeline.config import Config, Settings
from harbor_pipeline.differential import run_seed_repeats
from harbor_pipeline.errors import TaskError
from harbor_pipeline.evaluator import EvaluationOutcome
from harbor_pipeline.execution_progress import ExecutionProgress
from harbor_pipeline.generator import render_task
from harbor_pipeline.harbor_adapter import JobOutcome, TrialOutcome
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.util import digest, read_json
from harbor_pipeline.validation_evidence import execution_signature, validation_signature


def _images(cve_id, revision=1):
    variants = {}
    for variant, digit in (("vulnerable", "a"), ("fixed", "b")):
        base = f"harbor-pipeline/{cve_id.lower()}-{variant}-r{revision}"
        images = {name: {"image_ref": base + "-" + name,
                         "image_digest": "sha256:" + value * 64}
                  for name, value in (("target", digit), ("verifier", "c"), ("agent", "d"))}
        variants[variant] = {"images": images, "target_digest": images["target"]["image_digest"]}
    return {**variants["vulnerable"], "variants": variants}


class Adapter:
    def __init__(self, root):
        self.root, self.calls, self.fail_on = root, [], None

    def run(self, paths, **kwargs):
        import tomllib
        trials = []
        for path in paths:
            self.calls.append(path.parent.name)
            meta = tomllib.loads((path / "task.toml").read_text())["metadata"]
            variant = meta["variant"]
            failed = self.fail_on and self.fail_on in path.parent.name
            negative = any(name in path.parent.name for name in ("t05", "t06", "t07", "t10"))
            status, reward = ("goal_failed", 0.0) if negative else ("goal_passed", 1.0)
            if variant == "fixed":
                status, reward = "fixed_variant_holds", 0.0
            if meta.get("fault_injected"):
                status, reward = "target_unhealthy", 0.0
            if failed:
                status, reward = "missing", None
            trial_dir = self.root / f"trial-{len(self.calls)}"
            trial_dir.mkdir(parents=True)
            trials.append(TrialOutcome(
                trial_name=trial_dir.name, task_path=str(path), task_name="probe", trial_dir=trial_dir,
                reward=reward, exception={"exception_type": "NetworkError"} if failed else None,
                evidence={"status": status, "health_ok": status != "target_unhealthy",
                          "business_ok": status != "target_unhealthy", "submitted_observed": reward == 1.0},
                started_at=fixtures.NOW, finished_at=fixtures.NOW, duration_sec=0.01,
            ))
        return JobOutcome(job_name=kwargs["job_name"], job_dir=self.root,
                          config_path=self.root / "config.json", stdout_path=self.root / "stdout.log",
                          returncode=0, result={"started_at": fixtures.NOW}, trials=trials)


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    adapter = Adapter(tmp_path / "jobs")
    config = Config(pipeline=Settings(solver_review=False, docker_slots=0))
    pipeline = CvePipeline(config=config, cve_id="CVE-2024-23334", run_id="resume",
                           scenario="fixture", output_root=tmp_path, adapter=adapter)
    pipeline._capabilities = SimpleNamespace(network_mode="public", harbor_version="0.23.0")
    pipeline.store.create()
    job = pipeline.store.load()
    job.state = "BUILT"
    pipeline.store.save(job)
    spec = fixtures.cve_spec()
    spec["cve_id"] = pipeline.cve_id
    task = render_task(spec, scenario_name="fixture", variant="vulnerable")
    task.write(pipeline.store.root)
    images = _images(pipeline.cve_id)
    pipeline.store.write_artifact("image-set.json", images)
    monkeypatch.setattr(pipeline, "_matrix_repeats", lambda: 2)
    monkeypatch.setattr(pipeline_mod, "evaluate", lambda **kwargs: EvaluationOutcome(
        fixtures.evaluation("released"), {}, []))
    monkeypatch.setattr(pipeline_mod, "run_seed_repeats", lambda *a, **k: ([], []))
    return SimpleNamespace(pipeline=pipeline, adapter=adapter, spec=spec, task=task, images=images)


def _validate(scenario):
    return scenario.pipeline.validate(scenario.spec, fixtures.evidence_index(), scenario.task, scenario.images)


def test_partial_step_resumes_only_the_failed_case_without_charging_successes(scenario):
    scenario.adapter.fail_on = "confirm-t04"
    with pytest.raises(TaskError) as caught:
        _validate(scenario)
    assert caught.value.category.code == "infra_error"
    assert len(read_json(scenario.pipeline.store.path("matrix/progress.json"))["entries"]) == 3
    calls = list(scenario.adapter.calls)
    assert len(calls) == 4
    scenario.adapter.fail_on = None
    matrix, _ = _validate(scenario)
    new_calls = scenario.adapter.calls[len(calls):]
    assert "confirm-t04-01" in new_calls
    assert "confirm-t03-01" not in new_calls
    assert "t03-first-t03-01" not in new_calls
    assert "t04-first-t04-01" not in new_calls
    assert len({r["trial_id"] for r in matrix.records}) == len(matrix.records)
    assert scenario.pipeline._ledger().snapshot()["used"]["trials"] == len(scenario.adapter.calls)


def test_presentation_repair_reuses_execution_but_keeps_current_validation_binding(scenario):
    _validate(scenario)
    count = len(scenario.adapter.calls)
    original = scenario.pipeline.store.read_artifact("trials.json")["validation_signature"]
    job = scenario.pipeline.store.load()
    job.state, job.revision = "REPAIRING", 2
    scenario.pipeline.store.save(job)
    scenario.pipeline._clear_derived()
    assert scenario.pipeline.store.path("image-set.json").exists()
    assert scenario.pipeline.store.path("matrix/progress.json").exists()
    scenario.task.files["instruction.md"] += "\nClarified the request parameter.\n"
    scenario.images = _images(scenario.pipeline.cve_id, revision=2)
    job.state = "BUILT"
    scenario.pipeline.store.save(job)
    matrix, _ = _validate(scenario)
    assert len(scenario.adapter.calls) == count
    assert all(r["_audit"]["reuse"]["source_revision"] == 1 for r in matrix.records)
    result = scenario.pipeline.store.read_artifact("trials.json")
    assert result["validation_signature"] != original
    assert result["validation_signature"] == validation_signature(scenario.spec, scenario.task, scenario.images)


@pytest.mark.parametrize("change", ["poc", "target", "verifier", "timeout", "image", "network"])
def test_execution_changes_invalidate_progress(scenario, change):
    scenario.adapter.fail_on = "confirm-t04"
    with pytest.raises(TaskError):
        _validate(scenario)
    before = len(scenario.adapter.calls)
    if change in {"poc", "target", "verifier"}:
        path = {"poc": "solution/solve.sh", "target": "environment/target/Dockerfile",
                "verifier": "tests/verify.py"}[change]
        scenario.task.files[path] += "\n# changed\n"
    elif change == "timeout":
        scenario.task.files["task.toml"] = scenario.task.files["task.toml"].replace("timeout_sec = 600.0", "timeout_sec = 601.0")
    elif change == "image":
        scenario.images["variants"]["fixed"]["images"]["target"]["image_digest"] = "sha256:" + "f" * 64
    else:
        scenario.pipeline._capabilities.network_mode = "allowlist"
    with pytest.raises(TaskError):
        _validate(scenario)
    assert scenario.adapter.calls[before] == "t03-first-t03-01"
    assert len(scenario.adapter.calls) == before + 4


def test_missing_trial_artifacts_force_the_affected_case_to_rerun(scenario):
    scenario.adapter.fail_on = "confirm-t04"
    with pytest.raises(TaskError):
        _validate(scenario)
    # Empty test-only artifact directory, not a real Harbor job.
    (scenario.adapter.root / "trial-1").rmdir()
    before = len(scenario.adapter.calls)
    with pytest.raises(TaskError):
        _validate(scenario)
    assert scenario.adapter.calls[before:] == ["t03-first-t03-01", "confirm-t04-01"]


def test_corrupt_checkpoint_is_a_cache_miss(scenario):
    scenario.adapter.fail_on = "confirm-t04"
    with pytest.raises(TaskError):
        _validate(scenario)
    scenario.pipeline.store.path("matrix/progress.json").write_text("{truncated")
    before = len(scenario.adapter.calls)
    with pytest.raises(TaskError):
        _validate(scenario)
    assert len(scenario.adapter.calls) == before + 4


def test_experiment_rule_changes_invalidate_saved_expectations(scenario, monkeypatch):
    from dataclasses import replace
    scenario.adapter.fail_on = "confirm-t04"
    with pytest.raises(TaskError):
        _validate(scenario)
    before = len(scenario.adapter.calls)
    rules = tuple(replace(rule, expect="healthy") if rule.id == "T03" else rule
                  for rule in pipeline_mod.load_experiments())
    monkeypatch.setattr(pipeline_mod, "load_experiments", lambda: rules)
    with pytest.raises(TaskError):
        _validate(scenario)
    assert scenario.adapter.calls[before] == "t03-first-t03-01"
    assert len(scenario.adapter.calls) == before + 4


def test_partial_cold_seeds_resume_without_duplicate_builds_or_missing_seeds(tmp_path, monkeypatch):
    spec = fixtures.cve_spec()
    adapter = Adapter(tmp_path / "jobs")
    built, cleaned = [], []

    def build(**kwargs):
        built.append(kwargs)
        images = _images(spec["cve_id"])["variants"][kwargs["variant"]]
        for name, image in images["images"].items():
            image["image_ref"] = kwargs["tag_base"] + "-" + name
        return images

    monkeypatch.setattr(backend, "build_task_images", build)
    monkeypatch.setattr(backend, "prune_task_images", cleaned.append)
    kwargs = dict(scenario_name="fixture", root=tmp_path / "matrix", network_mode="public",
                  allowed_hosts=("target",), run_id="resume", candidate_revision=1,
                  artifact_digest="sha256:" + "a" * 64, environment_image="shared-agent")
    path = tmp_path / "matrix/progress.json"
    adapter.fail_on = "seed-2-vulnerable"
    records, errors = run_seed_repeats(adapter, spec, **kwargs, progress=ExecutionProgress(path, "same-inputs"))
    assert errors and len(records) == 3
    assert len(read_json(path)["entries"]) == 2
    adapter.fail_on = None
    records, errors = run_seed_repeats(adapter, spec, **kwargs, progress=ExecutionProgress(path, "same-inputs"))
    assert not errors and len(records) == 6
    assert len(built) == len(cleaned) == 7
    assert all(call["no_cache"] is True for call in built)
    assert {(r["seed"], r["variant"]) for r in records} == {
        (seed, variant) for seed in range(3) for variant in ("vulnerable", "fixed")}
    assert len({r["trial_id"] for r in records}) == 6
    assert sum("reuse" in r["_audit"] for r in records) == 2


def test_alternate_poc_changes_execution_signature_even_if_reference_task_is_unchanged(scenario):
    synthesis = SimpleNamespace(target={"files": {}}, poc={"reference": "same", "alternate": "one"})
    before = execution_signature(scenario.spec, scenario.task, scenario.images, synthesis=synthesis)
    synthesis.poc["alternate"] = "two"
    assert execution_signature(scenario.spec, scenario.task, scenario.images, synthesis=synthesis) != before


def test_old_seed_logs_do_not_charge_a_new_build_that_never_started(tmp_path, monkeypatch):
    from harbor_pipeline.budget import Ledger
    spec = fixtures.cve_spec()
    root = tmp_path / "matrix"
    logs = root / "seed-1-vulnerable/build-logs"
    logs.mkdir(parents=True)
    for name in ("target", "verifier"):
        (logs / f"build-{name}.log").write_text("old attempt")

    def unavailable(**kwargs):
        raise TaskError("infra_error", "Docker daemon unavailable before build")

    monkeypatch.setattr(backend, "build_task_images", unavailable)
    monkeypatch.setattr(backend, "prune_task_images", lambda *a: None)
    ledger = Ledger.load_or_create(tmp_path / "budget.json")
    with pytest.raises(TaskError):
        run_seed_repeats(Adapter(tmp_path / "jobs"), spec, scenario_name="fixture", root=root,
                         network_mode="public", allowed_hosts=("target",), run_id="resume",
                         candidate_revision=1, artifact_digest="sha256:" + "a" * 64,
                         environment_image="base", ledger=ledger)
    assert ledger.snapshot()["used"]["builds"] == 0
    assert ledger.snapshot()["used"]["trials"] == 0


def test_instruction_change_reruns_solver_and_reviewer(scenario, monkeypatch):
    pipeline = scenario.pipeline
    pipeline.config.pipeline.solver_review = True
    calls = []
    monkeypatch.setattr(pipeline, "_solver_task", lambda *a: (scenario.task, pipeline.store.path("task")))
    monkeypatch.setattr(pipeline, "_evidence", lambda: {})
    review_module = pipeline_mod.solver_review_mod
    monkeypatch.setattr(review_module, "build_evidence_context", lambda *a: "same evidence")

    def solver(*args, **kwargs):
        calls.append("solver")
        return {"trials": [{"reward": 1.0, "exception": None}]}

    def reviewer(task, solver, *args, **kwargs):
        calls.append("reviewer")
        return {"review_protocol": 2, "solver": solver, "task_digest": task.task_digest,
                "instruction_sha256": digest(task.files["instruction.md"]),
                "review": {"verdict": "release", "score": 100, "fidelity": "supported"}}

    monkeypatch.setattr(review_module, "run_solver", solver)
    monkeypatch.setattr(review_module, "solver_review", reviewer)
    pipeline.solver_review(scenario.spec)
    pipeline.solver_review(scenario.spec)
    assert calls == ["solver", "reviewer"]
    scenario.task.files["instruction.md"] += "\nNew hint.\n"
    pipeline.solver_review(scenario.spec)
    assert calls == ["solver", "reviewer", "solver", "reviewer"]
