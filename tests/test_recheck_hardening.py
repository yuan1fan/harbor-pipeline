"""Recheck may reuse matching execution, never legacy or changed verifier results."""
from types import SimpleNamespace

from harbor_pipeline import fixtures
from harbor_pipeline.config import Config, Settings
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.evaluator import EvaluationOutcome
from harbor_pipeline.generator import render_task
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.validation_evidence import validation_signature


def prepare(tmp_path, monkeypatch, *, signed):
    pipeline = CvePipeline(config=Config(pipeline=Settings(solver_review=False)),
        cve_id="CVE-2024-23334", run_id="test-recheck", output_root=tmp_path)
    pipeline._capabilities = SimpleNamespace(network_mode="public")
    pipeline.store.create()
    pipeline.store.transition(pipeline.store.load(), "QUARANTINED", "test previous evaluator failure")
    spec, evidence = fixtures.cve_spec(), fixtures.evidence_index()
    spec["cve_id"] = evidence["cve_id"] = pipeline.cve_id
    task = render_task(spec, scenario_name="fixture", variant="vulnerable")
    task.write(pipeline.store.root)
    images = {"target_digest": "sha256:" + "a" * 64, "dependencies": {"measured-package": "1.0"}}
    trials = {"records": [], "expectations": [], "seed_errors": []}
    if signed:
        trials["validation_signature"] = validation_signature(spec, task, images)
    for name, value in (("cve-spec.json", spec), ("evidence-index.json", evidence), ("image-set.json", images), ("trials.json", trials)):
        pipeline.store.write_artifact(name, value)
    def generate(spec, job):
        if job.state == "REPAIRING":
            pipeline.store.transition(pipeline.store.load(), "GENERATED", "regenerated")
        return task, pipeline.store.path("task")
    monkeypatch.setattr(pipeline, "generate", generate)
    monkeypatch.setattr(pipeline, "_report", lambda *args: {"state": pipeline.store.load().state})
    return pipeline, images


def test_missing_execution_signature_forces_build_and_trials(tmp_path, monkeypatch):
    pipeline, images = prepare(tmp_path, monkeypatch, signed=False)
    calls = []
    def build(spec, task, job):
        calls.append("build")
        pipeline.store.transition(pipeline.store.load(), "BUILT", "rebuilt")
        return images
    def validate(*args):
        calls.append("validate")
        pipeline.store.transition(pipeline.store.load(), "QUARANTINED", "new verifier rejected task")
        return MatrixResult(), EvaluationOutcome(fixtures.evaluation("quarantined"), {}, [])
    monkeypatch.setattr(pipeline, "build", build)
    monkeypatch.setattr(pipeline, "validate", validate)
    result = pipeline.recheck()
    assert calls == ["build", "validate"]
    assert result["state"] == "QUARANTINED"
    assert pipeline.store.load().revision == 2
    assert list(pipeline.store.path("recheck-history").glob("*/trials.json"))


def test_evaluator_only_recheck_keeps_measured_identity(tmp_path, monkeypatch):
    import harbor_pipeline.pipeline as pipeline_module
    pipeline, images = prepare(tmp_path, monkeypatch, signed=True)
    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged execution must not rebuild or synthesize a dependency lock")
    monkeypatch.setattr(pipeline, "build", forbidden)
    monkeypatch.setattr(pipeline, "validate", forbidden)
    import harbor_pipeline.backend as backend
    monkeypatch.setattr(backend, "dependency_lock", forbidden)
    monkeypatch.setattr(pipeline_module, "evaluate", lambda **kwargs: EvaluationOutcome(fixtures.evaluation("released"), {}, []))
    monkeypatch.setattr(pipeline, "release", lambda *args: {"ok": True})
    result = pipeline.recheck()
    assert result["state"] == "VALIDATED"
    assert pipeline.store.read_artifact("image-set.json") == images
