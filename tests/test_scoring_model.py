"""The gate / framework-health / quality-tier scoring model."""

from __future__ import annotations

from pathlib import Path

from harbor_pipeline import evaluator, fixtures
from harbor_pipeline.contracts import load_experiments, load_policy, validate
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.generator import render_task
from harbor_pipeline.harbor_adapter import TrialOutcome, classify_trial
from harbor_pipeline.scenario import _synthesis_entrypoint
from harbor_pipeline.trials import Expectation, evaluate_expectation


def _matrix(expectations: dict | None = None, records: list[dict] | None = None):
    return MatrixResult(
        job=None,
        records=records or [{"experiment_id": "T05", "error_category": None}],
        expectations=expectations or {},
    )


def test_target_unhealthy_with_zero_reward_is_infra():
    """T12's fault target writes reward 0; the status must win."""
    trial = TrialOutcome(
        trial_name="t12",
        task_path="",
        task_name="t12",
        trial_dir=Path("."),
        reward=0.0,
        exception=None,
        evidence={"status": "target_unhealthy"},
        started_at=None,
        finished_at=None,
        duration_sec=0.0,
    )
    assert classify_trial(trial) == "infra_error"


def test_t12_expectation_accepts_a_classified_target_failure():
    trial = TrialOutcome(
        trial_name="t12",
        task_path="",
        task_name="t12",
        trial_dir=Path("."),
        reward=0.0,
        exception=None,
        evidence={"status": "target_unhealthy"},
        started_at=None,
        finished_at=None,
        duration_sec=0.0,
    )
    experiment = next(e for e in load_experiments() if e.id == "T12")
    expectation = evaluate_expectation(experiment, trial)
    assert expectation.met is True
    assert expectation.error_category == "infra_error"


def test_fault_switch_is_in_the_normal_target_and_both_composes():
    entrypoint = _synthesis_entrypoint("node /opt/app/server.js", "/opt/app/secret/token")
    assert "TARGET_FAULT" in entrypoint

    spec = fixtures.cve_spec()
    normal = render_task(
        spec, scenario_name="fixture", variant="vulnerable", fault=False
    )
    assert "TARGET_FAULT" in normal.files["environment/target/entrypoint.sh"]

    faulty = render_task(
        spec, scenario_name="fixture", variant="vulnerable", fault=True
    )
    assert 'TARGET_FAULT: "1"' in faulty.files["environment/docker-compose.yaml"]
    assert 'TARGET_FAULT: "1"' in faulty.files["tests/docker-compose.yaml"]


def test_quality_tier_comes_from_the_alternate_poc():
    spec = {"artifact_identity": [{"digest": "sha256:" + "a" * 64}]}
    evidence = {"sources": [{"status": "ok", "local_path": "x"}]}
    matrix = _matrix({
        "T11": Expectation("T11", True, "status=goal_passed", "goal_passed"),
    })
    quality = evaluator._quality(spec, evidence, matrix)
    assert quality["tier"] == "A"
    assert quality["flags"] == {
        "alternate_poc": "pass",
        "artifact_identity": "1/2",
        "source_coverage": "1/1",
    }

    matrix.expectations["T11"] = Expectation(
        "T11", False, "status=goal_failed", "goal_failed"
    )
    assert evaluator._quality(spec, evidence, matrix)["tier"] == "B"


def test_framework_health_owns_negatives_and_t12():
    expectations = {
        experiment_id: Expectation(experiment_id, True, "ok", "goal_failed")
        for experiment_id in ("T05", "T06", "T07", "T10")
    }
    expectations["T12"] = Expectation("T12", True, "category=infra_error", "target_unhealthy")
    checks = evaluator._framework_health(
        _matrix(expectations), load_policy()
    )
    assert all(check["passed"] for check in checks)

    expectations["T12"] = Expectation(
        "T12", False, "status=artifact_missing category=None", "artifact_missing"
    )
    checks = evaluator._framework_health(
        _matrix(expectations), load_policy()
    )
    assert next(check for check in checks if check["id"] == "fault_T12")["passed"] is False


def test_quality_does_not_block_but_framework_health_does():
    profile = load_policy().profile("qualification")
    task_gates = [{"id": "D3-poc-successes", "passed": True, "detail": "3/3"}]
    healthy = [{"id": "fault_T12", "passed": True, "detail": "ok"}]
    broken = [{"id": "fault_T12", "passed": False, "detail": "artifact_missing"}]

    assert evaluator._blocking(task_gates, healthy, profile) is False
    assert evaluator._blocking(task_gates, broken, profile) is True


def test_evaluation_has_no_weighted_score_and_uses_a_tier():
    spec = fixtures.cve_spec()
    matrix = _matrix()
    outcome = evaluator.evaluate(
        spec=spec,
        evidence={"sources": []},
        matrix=matrix,
        image_set={
            "target_digest": "sha256:" + "b" * 64,
            "dependencies": {},
        },
        policy=load_policy(),
        profile_name="smoke",
        package_issues=[],
        network_isolation="public",
    )
    evaluation = outcome.evaluation
    assert evaluation["quality_score"] is None
    assert evaluation["quality_tier"] in {"A", "B"}
    assert "quality_flags" in evaluation
    assert "framework_health" in evaluation
    assert any(check["id"] == "fault_T12" for check in evaluation["framework_health"])
    # The new schema accepts the gate/tier shape.
    validate("evaluation", evaluation)


def test_fixture_evaluation_validates_under_the_new_schema():
    validate("evaluation", fixtures.evaluation("released"))
