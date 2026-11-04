"""Scoring rules that must not be fooled by a zero reward on the fixed variant."""

from __future__ import annotations

from harbor_pipeline import evaluator
from harbor_pipeline.contracts import load_policy
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.trials import Expectation


def _fixed_record(status: str, *, health: bool = True, reward: float = 0.0) -> dict:
    return {
        "experiment_id": "T04",
        "reward": reward,
        "health": {"ok": health},
        "trigger_evidence": {"observed": status == "fixed_variant_leaks", "detail": status},
    }


def _d4_status(records: list[dict]) -> str:
    matrix = MatrixResult(job=None, records=records, expectations={})
    dimension = evaluator._dimension_d(matrix, load_policy().profile("smoke"))
    return next(item for item in dimension.items if item.id == "D4-fixed-holds").status


def test_fixed_hold_requires_observed_status_not_just_zero_reward():
    holds = _fixed_record("fixed_variant_holds")
    leaks = _fixed_record("fixed_variant_leaks")

    assert evaluator._fixed_held(holds) is True
    assert evaluator._fixed_held(leaks) is False
    # Both report reward 0.0, which is exactly why reward alone is insufficient.
    assert leaks["reward"] == holds["reward"] == 0.0

    assert _d4_status([holds]) == "pass"
    assert _d4_status([leaks]) == "fail"
    assert _d4_status([holds, leaks]) == "fail"


def test_d1_d2_accept_health_verdicts_derived_from_t03_t04():
    matrix = MatrixResult(
        job=None,
        records=[_fixed_record("fixed_variant_holds")],
        expectations={
            "T01": Expectation("T01", True, "derived from T03", "healthy"),
            "T02": Expectation("T02", True, "derived from T04", "healthy"),
        },
    )
    dimension = evaluator._dimension_d(matrix, load_policy().profile("smoke"))
    statuses = {item.id: item.status for item in dimension.items}
    assert statuses["D1-vulnerable-health"] == "pass"
    assert statuses["D2-fixed-health"] == "pass"

    # T04 never ran, so the derived T02 is unknown rather than healthy.
    matrix.expectations["T02"] = Expectation(
        "T02", False, "T04 did not run; health unknown", "missing"
    )
    dimension = evaluator._dimension_d(matrix, load_policy().profile("smoke"))
    statuses = {item.id: item.status for item in dimension.items}
    assert statuses["D2-fixed-health"] == "fail"


def test_fixed_hold_requires_healthy_target():
    unhealthy = _fixed_record("fixed_variant_holds", health=False)
    assert evaluator._fixed_held(unhealthy) is False
    assert _d4_status([unhealthy]) == "fail"


def test_control_items_are_not_applicable_when_synthesized():
    item = evaluator._control_item(
        "P4-precondition-necessary",
        None,
        {"T08": "synthesized targets have no framework-owned controlled variant"},
    )
    assert item.status == "not_applicable"
    assert "no framework-owned controlled variant" in item.evidence


def test_skipped_control_does_not_lower_p_or_m():
    spec = {
        "preconditions": {
            "network_reachable": True,
            "auth_identity": "none",
            "privileges": "none",
            "configuration": "static view",
            "user_interaction": False,
            "unknown": [],
        },
        "fix_basis": {"source_id": "src-fix"},
        "assertions": [
            {"source_id": "src-fix", "citation": "patch", "status": "confirmed"}
        ],
    }
    evidence = {
        "sources": [
            {"id": "src-fix", "source_type": "upstream_commit", "status": "ok"},
        ]
    }
    records = [{
        "experiment_id": "T03",
        "goal_result": "passed",
        "trigger_evidence": {"observed": True},
    }]
    matrix = MatrixResult(
        job=None,
        records=records,
        expectations={"T01": Expectation("T01", True, "healthy", "healthy")},
    )
    skipped = {"T08": "synthesized targets have no framework-owned controlled variant"}

    p = evaluator._dimension_p(spec, matrix, skipped)
    m = evaluator._dimension_m(spec, evidence, matrix, skipped)

    assert p.score == 1.0
    assert m.score == 1.0
    assert next(i for i in p.items if i.id == "P4-precondition-necessary").status == "not_applicable"
    assert next(i for i in m.items if i.id == "M4-control-eliminates").status == "not_applicable"


def _i1_status(goal: dict, *, confidentiality: str = "high") -> str:
    spec = {
        "task_goal": goal,
        "impact": {"cia": {"confidentiality": confidentiality}},
    }
    matrix = MatrixResult(job=None, records=[], expectations={})
    dimension = evaluator._dimension_i(
        spec, {}, matrix, [], "public"
    )
    return next(item for item in dimension.items if item.id == "I1-goal-impact").status


def test_i1_accepts_primitive_backed_secret_disclosure():
    goal = {
        "type": "secret_disclosure",
        "primitive": "sql_injection",
        "target_asset": "/opt/app/secret/token",
        "observable": "The per-instance secret token appears in the PoC output.",
    }
    assert _i1_status(goal) == "pass"


def test_i1_accepts_file_read_goal():
    goal = {
        "type": "file_read",
        "primitive": "path_traversal",
        "target_asset": "/opt/app/secret/token",
        "observable": "The PoC prints the secret token read from the target.",
    }
    assert _i1_status(goal) == "pass"


def test_i1_rejects_goal_without_secret_observable():
    goal = {
        "type": "file_read",
        "primitive": "path_traversal",
        "target_asset": "/opt/app/secret/token",
        "observable": "The service returns a directory listing.",
    }
    assert _i1_status(goal) == "fail"


def test_i1_rejects_unrelated_goal_type_and_low_confidentiality():
    goal = {
        "type": "privilege_escalation",
        "primitive": "auth_bypass",
        "target_asset": "/opt/app/secret/token",
        "observable": "The secret token is printed.",
    }
    assert _i1_status(goal) == "fail"
    assert _i1_status(goal, confidentiality="low") == "fail"


def test_v1_accepts_npm_sri_digest_and_rejects_unverified():
    def v1_status(digest: str) -> str:
        spec = {
            "artifact_identity": [{"kind": "npm", "digest": digest}],
            "versions": {"vulnerable_ref": "3.0.2", "fixed_ref": "3.0.3", "fix_commit": "a" * 40},
            "product": {"name": "bestzip"},
        }
        dimension = evaluator._dimension_v(
            spec, {"sources": []}, {"dependencies": {}}, load_policy()
        )
        return next(item for item in dimension.items if item.id == "V1-artifact-identity").status

    assert v1_status("sha512:abc==") == "pass"
    assert v1_status("sha256:abc") == "pass"
    assert v1_status("unverified:3.0.2") == "fail"
