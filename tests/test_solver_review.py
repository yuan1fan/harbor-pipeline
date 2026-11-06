"""White-box presentation and the solver fairness review."""

from __future__ import annotations

import json

from harbor_pipeline import authoring, solver_review
from harbor_pipeline.config import Config, ModelSettings
from harbor_pipeline.generator import render_task
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.providers.base import ModelResponse
from harbor_pipeline.synthesis import Synthesis
from harbor_pipeline.util import digest

from test_auto_synthesis import CVE, _bundle
from test_authoring import _spec
from test_goal_families import _synthesis as simple_synthesis


def _config() -> Config:
    return Config(
        models={
            "default": ModelSettings(),
            "reviewer": ModelSettings(
                provider="claude-cli", model="reviewer-model", max_output_tokens=8000
            ),
            "solver": ModelSettings(provider="claude-code", model="solver-model"),
        }
    )


def _white_box() -> Synthesis:
    body = _bundle()
    body["task_goal"]["family"] = "secret_read"
    body["preconditions"]["auth_scheme"] = "none"
    body["presentation"] = {
        "mode": "white_box",
        "reason": "The route is behind an undocumented internal config file.",
        "hints": ["The static root is configured in app.py."],
        "source_paths": ["app.py"],
    }
    return Synthesis(
        cve_id=CVE,
        bundle=body,
        model_identity="test",
        usage={},
        prompt_sha256="",
        generated_at="2026-01-01T00:00:00+00:00",
        digest=digest(body),
    )


def test_white_box_renders_source_mount_and_context():
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_white_box(),
    )
    compose = task.files["environment/docker-compose.yaml"]
    assert "./target:/workspace/source:ro" in compose
    instruction = task.files["instruction.md"]
    assert "white box" in instruction.lower()
    assert "/workspace/source" in instruction
    assert "The static root is configured in app.py." in instruction
    assert 'presentation_mode = "white_box"' in task.files["task.toml"]


def test_black_box_does_not_mount_source():
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=simple_synthesis("secret_read"),
    )
    assert "/workspace/source" not in task.files["environment/docker-compose.yaml"]
    assert 'presentation_mode = "black_box"' in task.files["task.toml"]


class _FakeProvider:
    name = "fake"

    def __init__(self, review: dict):
        self.review = review
        self.requests: list = []

    def generate(self, request):
        self.requests.append(request)
        return ModelResponse(
            text=json.dumps(self.review),
            structured=self.review,
            usage={"input_tokens": 1, "output_tokens": 1},
            model_identity="fake",
        )

    def health(self):
        return {"ok": True}


def test_review_prompt_includes_solution_and_solver_result(monkeypatch):
    review = {
        "solved": False,
        "fair": False,
        "guess_work": 5,
        "recommended_mode": "white_box",
        "missing_context": ["the static root is configured elsewhere"],
        "score": 2,
        "verdict": "revise",
        "recommendations": ["switch to white_box", "name app.py in hints"],
        "reason": "The solver had no way to discover the internal config.",
    }
    provider = _FakeProvider(review)
    monkeypatch.setattr(solver_review, "build_provider", lambda config, role: provider)
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_white_box(),
    )
    solver = {
        "attempts": 1,
        "successes": 0,
        "success_rate": 0.0,
        "failure_types": {"goal_failed": 1},
        "trials": [
            {
                "success": False,
                "failure_type": "goal_failed",
                "duration_sec": 120.0,
                "reward": 0.0,
                "usage": {"n_input_tokens": 10, "n_output_tokens": 5},
            }
        ],
    }
    result = solver_review.review_task(
        task,
        solver,
        _config(),
        presentation={"mode": "white_box"},
    )
    assert result["verdict"] == "revise"
    prompt = provider.requests[0].prompt
    assert "Reference exploit" in prompt
    assert "did NOT see" in prompt
    assert "The static root is configured in app.py." in prompt
    assert "goal_failed" in prompt


def test_solver_review_prompt_is_presentation_only():
    prompt = authoring.solver_review_prompt("REPORT")
    assert "do not rewrite" in prompt.lower()
    assert "bundle.json.presentation" in prompt
    assert "target/reference/" in prompt
    assert "harbor-author submit" in prompt


def test_solver_review_reuses_a_matching_instruction(tmp_path, monkeypatch):
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_white_box(),
    )
    config = _config()
    config.pipeline.output_dir = str(tmp_path / "runs")
    pipeline = CvePipeline(
        config=config,
        cve_id=CVE,
        run_id="reuse-review",
        scenario="auto",
        output_root=tmp_path / "runs",
    )
    pipeline.store.create()
    existing = {
        "instruction_sha256": digest(task.files["instruction.md"]),
        "review": {"verdict": "release", "score": 5},
    }
    pipeline.store.write_artifact("solver-review.json", existing)
    pipeline._solver_task = lambda spec, job: (task, tmp_path / "solver-task")
    def boom(*_args, **_kwargs):
        raise AssertionError("a matching review should not run the solver again")

    monkeypatch.setattr(solver_review, "run_solver", boom)
    assert pipeline.solver_review(_spec()) == existing


def test_solver_review_attaches_provenance(monkeypatch):
    review = {
        "solved": True,
        "fair": True,
        "guess_work": 1,
        "recommended_mode": "black_box",
        "missing_context": [],
        "score": 5,
        "verdict": "release",
        "recommendations": [],
        "reason": "The instruction and the running service were sufficient.",
    }
    provider = _FakeProvider(review)
    monkeypatch.setattr(solver_review, "build_provider", lambda config, role: provider)
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_white_box(),
    )
    result = solver_review.solver_review(
        task, {"attempts": 1, "successes": 1, "trials": []}, _config(),
        presentation={"mode": "white_box"},
    )
    assert result["review"]["verdict"] == "release"
    assert result["task_digest"] == task.task_digest
    assert result["instruction_sha256"] == digest(task.files["instruction.md"])
