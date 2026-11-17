"""Transient infrastructure retries preserve inputs and valid solver evidence."""
import json
from types import SimpleNamespace

import pytest

from harbor_pipeline import backend, depcheck, fixtures, resources, retries, solver_review
from harbor_pipeline.config import Config, ModelSettings, Settings, SourceSettings
from harbor_pipeline.errors import TaskError
from harbor_pipeline.generator import render_task
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.providers.base import ModelResponse
from harbor_pipeline.util import PipelineError, digest


@pytest.mark.parametrize("message,category,attempts", [
    ("curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL", "infra_error", 2),
    ("503 Service Unavailable", "infra_error", 2),
    ("FATAL ERROR: Reached heap limit; JavaScript heap out of memory", "infra_error", 2),
    ("Package requires Python >=3.13 but Python 3.12 is installed", "build_error", 1),
    ("Dockerfile parse error: unknown instruction", "build_error", 1),
])
def test_network_errors_are_not_author_repair_requests(tmp_path, monkeypatch, message, category, attempts):
    token = resources._POLICY.set({"slots": 0})
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    calls = []
    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _: True)
    monkeypatch.setattr(backend, "time", SimpleNamespace(monotonic=lambda: 0, sleep=lambda _: None))

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1, stdout=message, stderr="")

    monkeypatch.setattr(backend, "_run", run)
    try:
        with pytest.raises(TaskError) as caught:
            backend.build_image(name="target", context=tmp_path, image_ref="test", log_path=tmp_path / "build.log")
        assert caught.value.category.code == category
        assert len(calls) == attempts
    finally:
        resources._POLICY.reset(token)


def _clock(monkeypatch):
    state = SimpleNamespace(now=1000.0, waits=[])

    def sleep(seconds):
        state.waits.append(seconds)
        state.now += seconds

    monkeypatch.setattr(retries, "time", SimpleNamespace(time=lambda: state.now, sleep=sleep))
    return state


def test_rate_limit_cooldown_is_shared_and_bounded(tmp_path, monkeypatch):
    clock = _clock(monkeypatch)
    calls = []

    def request():
        calls.append(1)
        if len(calls) < 3:
            raise PipelineError("API error 429: rate limit")
        return "ok"

    assert retries.retry_model(request, settings=ModelSettings(), directory=tmp_path) == "ok"
    assert clock.waits == [2, 4]
    assert len(list(tmp_path.glob("model-cooldown-*.json"))) == 1
    with pytest.raises(PipelineError, match="401"):
        retries.retry_model(lambda: (_ for _ in ()).throw(PipelineError("API error 401: invalid key")),
                            settings=ModelSettings(), directory=tmp_path)
    assert clock.waits == [2, 4]


def _review():
    return {"solved": False, "fair": True, "guess_work": 1, "recommended_mode": "black_box",
            "missing_context": [], "score": 4, "verdict": "release", "recommendations": [],
            "reason": "The provided task can be solved with the supplied context.",
            "fidelity": "supported", "fidelity_reason": "The upstream patch and measured pair support the same mechanism."}


@pytest.mark.parametrize("corrects", [True, False])
def test_reviewer_gets_one_schema_correction_without_weakening_fidelity(tmp_path, monkeypatch, corrects):
    config = Config(pipeline=Settings(resource_dir=str(tmp_path)))
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    requests = []

    def generate(request):
        requests.append(request)
        review = _review()
        if len(requests) == 1 or not corrects:
            review["fidelity_note"] = "extra field observed on sample50"
        return ModelResponse(json.dumps(review), review, {"input_tokens": 10, "output_tokens": 5, "usd": 0.1}, "test")

    monkeypatch.setattr(solver_review, "build_provider", lambda *a: SimpleNamespace(generate=generate))
    usage = {}
    if corrects:
        result = solver_review.review_task(task, {"trials": [{"reward": 0.0}]}, config, usage_out=usage)
        assert result["fidelity"] == "supported" and "fidelity_note" not in result
    else:
        with pytest.raises(TaskError) as caught:
            solver_review.review_task(task, {"trials": [{"reward": 0.0}]}, config, usage_out=usage)
        assert caught.value.category.code == "infra_error"
    assert len(requests) == 2 and "fidelity_note" in requests[1].prompt
    assert usage["calls"] == 2 and usage["input_tokens"] == 20
    assert usage["cost_usd"] == pytest.approx(0.2)


def test_reviewer_non_json_gets_one_format_correction(tmp_path, monkeypatch):
    config = Config(pipeline=Settings(resource_dir=str(tmp_path)))
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    calls = []

    def generate(request):
        calls.append(request)
        if len(calls) == 1:
            raise PipelineError("Model returned non-JSON structured output")
        value = _review()
        return ModelResponse(json.dumps(value), value, {}, "fixture")

    monkeypatch.setattr(solver_review, "build_provider", lambda *a: SimpleNamespace(generate=generate))
    assert solver_review.review_task(task, {"trials": [{"reward": 0}]}, config)["fidelity"] == "supported"
    assert len(calls) == 2


def test_format_correction_cannot_upgrade_the_fidelity_verdict(tmp_path, monkeypatch):
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    config = Config(pipeline=Settings(resource_dir=str(tmp_path)))
    calls = []

    def generate(request):
        calls.append(1)
        value = _review()
        if len(calls) == 1:
            value.update(fidelity="uncertain", fidelity_note="extra field")
        return ModelResponse(json.dumps(value), value, {}, "fixture")

    monkeypatch.setattr(solver_review, "build_provider", lambda *a: SimpleNamespace(generate=generate))
    with pytest.raises(TaskError, match="changed its assessment"):
        solver_review.review_task(task, {"trials": [{"reward": 0}]}, config)
    assert len(calls) == 2


def test_cached_low_score_review_still_requires_author_revision(tmp_path, monkeypatch):
    config = Config(pipeline=Settings(docker_slots=0, resource_dir=str(tmp_path / "resources")))
    pipeline = CvePipeline(config=config, cve_id="CVE-2024-23334", run_id="review-gate", scenario="fixture", output_root=tmp_path)
    pipeline.store.create()
    pipeline.store.write_artifact("image-set.json", {})
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    monkeypatch.setattr(pipeline, "_solver_task", lambda *a: (task, tmp_path / "task"))
    monkeypatch.setattr(pipeline, "_evidence", lambda: {})
    monkeypatch.setattr(solver_review, "build_evidence_context", lambda *a: "same evidence")
    calls = []
    monkeypatch.setattr(solver_review, "run_solver", lambda *a, **k: {"trials": [{"reward": 0.0}]})

    def review(*args, **kwargs):
        calls.append(1)
        value = _review()
        value["score"] = 2
        return {"review_protocol": 2, "review": value, "solver": args[1], "task_digest": task.task_digest,
                "instruction_sha256": digest(task.files["instruction.md"])}

    monkeypatch.setattr(solver_review, "solver_review", review)
    for _ in range(2):
        with pytest.raises(TaskError) as caught:
            pipeline.solver_review(fixtures.cve_spec())
        assert caught.value.category.code == "validation_error"
    assert len(calls) == 1


def test_solver_rate_limit_retries_then_reviewer_failure_reuses_valid_solver(tmp_path, monkeypatch):
    _clock(monkeypatch)
    config = Config(pipeline=Settings(docker_slots=0, resource_dir=str(tmp_path / "resources")))
    pipeline = CvePipeline(config=config, cve_id="CVE-2024-23334", run_id="model-retry", scenario="fixture", output_root=tmp_path)
    pipeline.store.create()
    pipeline.store.write_artifact("image-set.json", {})
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    monkeypatch.setattr(pipeline, "_solver_task", lambda *a: (task, tmp_path / "task"))
    monkeypatch.setattr(pipeline, "_evidence", lambda: {})
    monkeypatch.setattr(solver_review, "build_evidence_context", lambda *a: "same evidence")
    runs, reviews = [], []

    def solve(*args, **kwargs):
        runs.append(1)
        error = {"exception_type": "ApiRateLimitError"} if len(runs) < 3 else None
        return {"trials": [{"reward": None if error else 0.0, "exception": error, "usage": {"cost_usd": 0.01}}]}

    def review(*args, **kwargs):
        reviews.append(1)
        if len(reviews) == 1:
            raise TaskError("infra_error", "reviewer formatting unavailable", detail={"review_usage": {"calls": 2, "cost_usd": 0.02}})
        return {"review_protocol": 2, "review": _review(), "usage": {"cost_usd": 0.01},
                "task_digest": task.task_digest, "instruction_sha256": digest(task.files["instruction.md"])}

    monkeypatch.setattr(solver_review, "run_solver", solve)
    monkeypatch.setattr(solver_review, "solver_review", review)
    with pytest.raises(TaskError):
        pipeline.solver_review(fixtures.cve_spec())
    pipeline.solver_review(fixtures.cve_spec())
    assert len(runs) == 3 and len(reviews) == 2
    result = pipeline.store.read_artifact("solver-result.json")
    assert result["trials"][0]["reward"] == 0.0  # A valid zero is not retried.
    assert len(result["infrastructure_attempts"]) == 2
    assert pipeline._ledger().snapshot()["used"]["usd"] == pytest.approx(0.06)


def test_local_python_requirement_is_checked_before_generic_build(monkeypatch):
    monkeypatch.setattr(depcheck, "fetch", lambda *a, **k: pytest.fail("local metadata needs no request"))
    bundle = {"product": {"name": "example/app", "ecosystem": "generic"},
              "target": {"base_image": "python:3.12-slim", "files": {"pyproject.toml": '[project]\nrequires-python = ">=3.13"\n'}}}
    issues = depcheck.check_bundle(bundle, SourceSettings())
    assert len(issues) == 1 and ">=3.13" in issues[0] and "Python 3.12" in issues[0]


def test_source_python_metadata_reads_only_the_pinned_refs(monkeypatch):
    calls = []
    bundle = {"product": {"name": "example/app", "ecosystem": "generic"},
              "versions": {"vulnerable_ref": "a" * 40, "fixed_ref": "b" * 40},
              "target": {"base_image": "python:3.12-slim", "files": {
                  "Dockerfile": "FROM python:3.12-slim\nRUN git clone https://github.com/example/app.git\n"}}}

    def fetch(url, settings):
        calls.append(url)
        assert settings.timeout_sec <= 10
        return SimpleNamespace(status=200, body=b'[project]\nrequires-python = ">=3.13"\n')

    monkeypatch.setattr(depcheck, "fetch", fetch)
    assert len(depcheck.check_bundle(bundle, SourceSettings())) == 2
    assert all(ref in url for ref, url in zip(("a" * 40, "b" * 40), calls))
