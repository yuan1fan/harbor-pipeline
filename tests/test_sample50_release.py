"""Release failures retry their own staged copy, never delete a locked attempt."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from harbor_pipeline import fixtures, pipeline as pipeline_mod, release, retries
from harbor_pipeline.config import Config, Settings
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.errors import TaskError
from harbor_pipeline.evaluator import EvaluationOutcome
from harbor_pipeline.generator import render_task
from harbor_pipeline.harbor_adapter import TrialOutcome
from harbor_pipeline.pipeline import CvePipeline, _tree_digest
from harbor_pipeline.util import digest, read_json
from harbor_pipeline.contracts import freeze_digest
from harbor_pipeline.validation_evidence import validation_signature


@pytest.fixture
def ready(tmp_path, monkeypatch):
    pipeline = CvePipeline(config=Config(pipeline=Settings(solver_review=False, docker_slots=0)),
        cve_id="CVE-2024-23334", run_id="publication", scenario="fixture", output_root=tmp_path)
    pipeline._capabilities = SimpleNamespace(network_mode="public", harbor_version="0.23.0")
    pipeline.store.create()
    job = pipeline.store.load()
    job.state = "VALIDATED"
    pipeline.store.save(job)
    spec, evidence = fixtures.cve_spec(), fixtures.evidence_index()
    spec["cve_id"] = evidence["cve_id"] = pipeline.cve_id
    spec["frozen_digest"] = freeze_digest(spec)
    for source in evidence["sources"]:
        path = pipeline.store.path(source["local_path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        body = source["id"].encode()
        path.write_bytes(body)
        source["content_sha256"] = digest(body)
    task = render_task(spec, scenario_name="fixture", variant="vulnerable")
    task.write(pipeline.store.root)
    images = {"target_digest": "sha256:" + "a" * 64, "architecture": "amd64", "dependencies": {},
              "images": {"target": {"image_ref": "demo", "image_digest": "sha256:" + "a" * 64}}}
    outcome = EvaluationOutcome(fixtures.evaluation("released"), {}, [])
    outcome.evaluation["cve_id"] = pipeline.cve_id
    matrix = MatrixResult()
    matrix.validation_signature = validation_signature(spec, task, images)
    for name, value in (("cve-spec.json", spec), ("evidence-index.json", evidence), ("image-set.json", images),
                        ("task-manifest.json", {"tree_digest": _tree_digest(pipeline.store.path("task"))}),
                        ("trials.json", matrix.to_json()), ("evaluation.json", outcome.evaluation)):
        pipeline.store.write_artifact(name, value)
    monkeypatch.setattr(retries.time, "sleep", lambda _: None)
    monkeypatch.setattr(pipeline, "_report", lambda job, task, images, outcome, record, matrix: {"state": job.state, **record})
    return SimpleNamespace(pipeline=pipeline, spec=spec, evidence=evidence, task=task,
                           images=images, matrix=matrix, outcome=outcome)


def _release(ready):
    return ready.pipeline.release(ready.spec, ready.evidence, ready.task, ready.images, ready.matrix, ready.outcome)


def test_release_replay_failure_preserves_staging_and_resumes_only_release(ready, monkeypatch):
    pipeline = ready.pipeline
    old = pipeline.store.path("release/task/environment")
    old.mkdir(parents=True)
    (old / "held.txt").write_text("previous attempt; must not remove")
    built, attempts = [], []
    original = pipeline_mod.build_release

    def build(**kwargs):
        result = original(**kwargs)
        built.append(result.root)
        return result

    def unavailable(*args, **kwargs):
        attempts.append(1)
        raise TaskError("infra_error", "EnvironmentStartTimeoutError")

    monkeypatch.setattr(pipeline_mod, "build_release", build)
    monkeypatch.setattr(pipeline_mod, "recheck_from_release", unavailable)
    with pytest.raises(TaskError) as caught:
        _release(ready)
    assert caught.value.category.code == "infra_error"
    assert caught.value.detail["stage"] == "release"
    assert len(attempts) == 3 and len(built) == 1
    assert built[0].parent.name == "release-staging"
    assert (old / "held.txt").is_file()
    for name in ("collect", "draft", "build", "validate", "solver_review"):
        monkeypatch.setattr(pipeline, name, lambda *a, **k: pytest.fail("upstream stages must not repeat"))
    monkeypatch.setattr(pipeline_mod, "recheck_from_release", lambda *a, **k: {"reward": 1.0, "status": "goal_passed"})
    job = pipeline.store.load()
    job.state = "REPAIRING"
    pipeline.store.save(job)
    result = pipeline._advance("release")
    assert result["state"] == "RELEASED"
    assert Path(result["root"]).name.startswith("release-r1-")
    assert len(built) == 1
    assert (old / "held.txt").read_text() == "previous attempt; must not remove"
    assert read_json(pipeline.store.path("release-stage.json"))["status"] == "published"
    assert release.verify_release(Path(result["root"]), expected_digest=ready.images["target_digest"]) == []


def test_changed_execution_cannot_use_release_checkpoint(ready, monkeypatch):
    monkeypatch.setattr(pipeline_mod, "recheck_from_release", lambda *a, **k: (_ for _ in ()).throw(TaskError("infra_error", "offline")))
    with pytest.raises(TaskError):
        _release(ready)
    spec = ready.pipeline.store.read_artifact("cve-spec.json")
    spec["versions"]["fixed_ref"] = "9.9.9"
    ready.pipeline.store.write_artifact("cve-spec.json", spec)
    assert ready.pipeline._resume_release() is None


def test_environment_start_error_is_not_a_failed_poc(tmp_path):
    (tmp_path / "task").mkdir()
    trial = TrialOutcome("timeout", str(tmp_path / "task"), "task", tmp_path, None,
        {"exception_type": "EnvironmentStartTimeoutError"}, None, None, None, 0)
    adapter = SimpleNamespace(run=lambda *a, **k: SimpleNamespace(job_name="release", trials=[trial]))
    with pytest.raises(TaskError) as caught:
        release.recheck_from_release(adapter, tmp_path)
    assert caught.value.category.code == "infra_error"
    trial.exception, trial.reward, trial.evidence = None, 0.0, {"status": "goal_failed", "health_ok": True}
    assert release.recheck_from_release(adapter, tmp_path)["reward"] == 0.0
