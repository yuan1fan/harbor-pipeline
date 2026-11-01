"""Deterministic CVE-consistency scoring and admission decisions.

Every sub-item is computed from frozen contracts, generated files, or trial
records. `unknown` never counts as a pass; `not_applicable` needs an explicit
reason and is excluded from the denominator.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from . import SCHEMA_VERSION
from .contracts import Policy, Profile, validate
from .differential import MatrixResult
from .errors import TaskError
from .spec import check_evidence_links, check_spec_consistency
from .util import digest

GOAL_PASSING = "passed"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Item:
    id: str
    status: str  # pass | fail | unknown | not_applicable
    evidence: str

    def to_json(self) -> dict:
        return {"id": self.id, "status": self.status, "evidence": self.evidence}


@dataclass
class Dimension:
    key: str
    weight: float
    items: list[Item]

    @property
    def score(self) -> float:
        countable = [i for i in self.items if i.status != "not_applicable"]
        if not countable:
            return 0.0
        return sum(1 for i in countable if i.status == "pass") / len(countable)

    def to_json(self) -> dict:
        return {
            "weight": self.weight,
            "score": round(self.score, 4),
            "items": [item.to_json() for item in self.items],
        }


@dataclass
class EvaluationOutcome:
    evaluation: dict
    dimensions: dict[str, Dimension]
    hard_conditions: list[dict]

    @property
    def admitted(self) -> bool:
        return self.evaluation["admission_status"] == "released"

    def summary(self) -> dict:
        return {
            "cve_id": self.evaluation["cve_id"],
            "quality_score": self.evaluation["quality_score"],
            "admission_status": self.evaluation["admission_status"],
            "attribution_grade": self.evaluation["attribution_grade"],
            "dimensions": {
                key: {"score": round(dim.score, 3), "weight": dim.weight}
                for key, dim in self.dimensions.items()
            },
            "failed_conditions": [
                hc["id"] for hc in self.hard_conditions if not hc["passed"]
            ],
            "failure_reasons": self.evaluation["failure_reasons"],
        }


def evaluate(
    *,
    spec: dict,
    evidence: dict,
    matrix: MatrixResult,
    image_set: dict,
    policy: Policy,
    profile_name: str = "smoke",
    release_files: dict[str, str] | None = None,
    package_issues: list[str] | None = None,
    network_isolation: str = "public",
    extra_seed_errors: list[str] | None = None,
) -> EvaluationOutcome:
    profile = policy.profile(profile_name)
    artifact_digest = image_set.get("target_digest") or digest(image_set)
    records = matrix.records
    dimensions = {
        "V": _dimension_v(spec, evidence, image_set, policy),
        "P": _dimension_p(spec, matrix),
        "M": _dimension_m(spec, evidence, matrix),
        "D": _dimension_d(matrix, profile),
        "I": _dimension_i(
            spec, evidence, matrix, policy, package_issues or [], network_isolation
        ),
    }
    quality = sum(dim.weight * dim.score for dim in dimensions.values())
    hard = _hard_conditions(
        spec=spec,
        evidence=evidence,
        matrix=matrix,
        policy=policy,
        profile=profile,
        quality=quality,
        network_isolation=network_isolation,
        extra_seed_errors=extra_seed_errors or [],
    )
    failures = [f"{hc['id']}: {hc['detail']}" for hc in hard if not hc["passed"]]
    failures.extend(matrix.errors)
    spec_issues = check_evidence_links(spec, evidence) + check_spec_consistency(spec)
    failures.extend(f"spec: {issue}" for issue in spec_issues)
    valid = sum(1 for r in records if r["error_category"] not in {"infra_error", "build_error"})
    t03 = [r for r in records if r["experiment_id"] == "T03"]
    successes = sum(1 for r in t03 if r["goal_result"] == GOAL_PASSING)
    interval = _wilson(successes, len(t03)) if t03 else [0.0, 0.0]

    if spec.get("attribution_grade") not in profile.allow_attribution_grade:
        failures.append(
            f"attribution grade {spec.get('attribution_grade')} is not allowed by profile {profile.name}"
        )
    if quality < profile.min_quality_score:
        failures.append(
            f"quality score {quality:.1f} is below {profile.min_quality_score:.1f}"
        )
    if valid < profile.min_valid_trials:
        failures.append(
            f"{valid} valid trials is below the {profile.name} minimum of {profile.min_valid_trials}"
        )
    if not artifacts_match(records, artifact_digest):
        failures.append("trial records do not reference the current artifact digest")

    if failures:
        status = "quarantined" if _blocking(hard, spec, profile) else "candidate"
    elif profile.name == "qualification":
        status = "released"
    else:
        status = "candidate"

    evaluation = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": policy.policy_version,
        "cve_id": spec["cve_id"],
        "candidate_revision": _revision(records),
        "artifact_digest": artifact_digest,
        "dimensions": {key: dim.to_json() for key, dim in dimensions.items()},
        "quality_score": round(quality, 2),
        "attribution_grade": spec["attribution_grade"],
        "sample_size": len(t03) or len(records),
        "valid_samples": valid,
        "confidence_interval": [round(interval[0], 4), round(interval[1], 4)],
        "hard_conditions": hard,
        "admission_status": status,
        "failure_reasons": failures,
        "evaluated_at": utc_now(),
    }
    validate("evaluation", evaluation)
    return EvaluationOutcome(evaluation=evaluation, dimensions=dimensions, hard_conditions=hard)


def _dimension_v(spec: dict, evidence: dict, image_set: dict, policy: Policy) -> Dimension:
    identities = spec.get("artifact_identity", [])
    pinned = [
        item for item in identities
        if str(item.get("digest", "")).startswith("sha256:")
        and "unverified" not in str(item.get("digest", ""))
    ]
    sources = evidence.get("sources", [])
    ok_sources = [s for s in sources if s.get("status") == "ok" and s.get("local_path")]
    versions = spec.get("versions", {})
    deps = image_set.get("dependencies", {})
    product = spec.get("product", {}).get("name")
    locked = deps.get(product)
    if locked is None:
        lock_item = Item("V4-build-lock", "unknown", f"{product} is not in the built dependency lock")
    elif locked == versions.get("vulnerable_ref"):
        lock_item = Item("V4-build-lock", "pass", f"built {product}=={locked}")
    else:
        lock_item = Item(
            "V4-build-lock", "fail",
            f"built {product}=={locked}, spec says vulnerable_ref={versions.get('vulnerable_ref')}",
        )
    items = [
        Item("V1-artifact-identity", "pass" if pinned else "fail",
             f"{len(pinned)} pinned artifact identities"),
        Item("V2-version-pair", "pass" if versions.get("vulnerable_ref") != versions.get("fixed_ref")
             and versions.get("fix_commit") else "fail",
             f"{versions.get('vulnerable_ref')} -> {versions.get('fixed_ref')}"),
        Item("V3-sources-local", "pass" if ok_sources else "fail",
             f"{len(ok_sources)}/{len(sources)} sources fetched and saved"),
        lock_item,
    ]
    return Dimension("V", policy.weights["V"], items)


def _dimension_p(spec: dict, matrix: MatrixResult) -> Dimension:
    pre = spec.get("preconditions", {})
    complete = all(
        key in pre for key in
        ("network_reachable", "auth_identity", "privileges", "configuration", "user_interaction")
    ) and not pre.get("unknown")
    t01 = matrix.expectation("T01")
    t08 = matrix.expectation("T08")
    items = [
        Item("P1-preconditions", "pass" if complete else "fail",
             "all precondition fields confirmed" if complete else "preconditions incomplete"),
        Item("P2-unauthenticated", "pass" if pre.get("auth_identity") == "none"
             and pre.get("network_reachable") is True else "fail",
             f"auth={pre.get('auth_identity')} reachable={pre.get('network_reachable')}"),
        Item("P3-target-reachable", "pass" if t01 and t01.met else "fail",
             t01.detail if t01 else "T01 not run"),
        Item("P4-precondition-necessary", "pass" if t08 and t08.met else
             ("not_applicable" if t08 is None else "fail"),
             t08.detail if t08 else "T08 control not run"),
    ]
    return Dimension("P", 15.0, items)


def _dimension_m(spec: dict, evidence: dict, matrix: MatrixResult) -> Dimension:
    fix_source_id = spec.get("fix_basis", {}).get("source_id")
    by_id = {s["id"]: s for s in evidence.get("sources", [])}
    fix_source = by_id.get(fix_source_id, {})
    commit_ok = fix_source.get("source_type") == "upstream_commit" and fix_source.get("status") == "ok"
    cited = any(
        a.get("status") == "confirmed" and a.get("source_id") == fix_source_id
        for a in spec.get("assertions", [])
    )
    t03 = matrix.record_for("T03")
    triggered = bool(t03 and t03["trigger_evidence"]["observed"] and t03["goal_result"] == GOAL_PASSING)
    t08 = matrix.expectation("T08")
    items = [
        Item("M1-fix-source", "pass" if commit_ok else "fail",
             f"fix source {fix_source_id} status={fix_source.get('status')}"),
        Item("M2-root-cause-cited", "pass" if cited else "fail",
             "root-cause assertion cites the fetched fix commit"),
        Item("M3-trigger-observed", "pass" if triggered else "fail",
             f"T03 goal={t03['goal_result'] if t03 else 'missing'}"),
        Item("M4-control-eliminates", "pass" if t08 and t08.met else
             ("not_applicable" if t08 is None else "fail"),
             t08.detail if t08 else "T08 control not run"),
    ]
    return Dimension("M", 25.0, items)


def _dimension_d(matrix: MatrixResult, profile: Profile) -> Dimension:
    t01 = matrix.expectation("T01")
    t02 = matrix.expectation("T02")
    t03_records = [r for r in matrix.records if r["experiment_id"] == "T03"]
    t04_records = [r for r in matrix.records if r["experiment_id"] == "T04"]
    t11 = matrix.expectation("T11")
    negatives = [matrix.expectation(i) for i in ("T05", "T06", "T07", "T10")]
    negatives_ok = all(n and n.met for n in negatives)
    items = [
        Item("D1-vulnerable-health", "pass" if t01 and t01.met else "fail",
             t01.detail if t01 else "T01 not run"),
        Item("D2-fixed-health", "pass" if t02 and t02.met else "fail",
             t02.detail if t02 else "T02 not run"),
        Item("D3-poc-successes", "pass" if t03_records and all(
            r["goal_result"] == GOAL_PASSING for r in t03_records) else "fail",
            f"{sum(1 for r in t03_records if r['goal_result'] == GOAL_PASSING)}/{len(t03_records)} T03 trials passed"),
        Item("D4-fixed-holds", "pass" if t04_records and all(
            r["reward"] == 0.0 for r in t04_records) else "fail",
            f"{len(t04_records)} fixed trials, max reward "
            f"{max((r['reward'] or 0.0) for r in t04_records) if t04_records else 'n/a'}"),
        Item("D5-negative-cases", "pass" if negatives_ok else "fail",
             "; ".join(f"{n.experiment_id}={n.met}" for n in negatives if n) or "not run"),
        Item("D6-alternate-accepted", "pass" if t11 and t11.met else
             ("not_applicable" if t11 is None else "fail"),
             t11.detail if t11 else "T11 not run"),
    ]
    return Dimension("D", 30.0, items)


def _dimension_i(
    spec: dict,
    evidence: dict,
    matrix: MatrixResult,
    policy: Policy,
    package_issues: list[str],
    network_isolation: str,
) -> Dimension:
    goal = spec.get("task_goal", {})
    cia = spec.get("impact", {}).get("cia", {})
    observable = str(goal.get("observable", "")).lower()
    t12 = matrix.expectation("T12")
    valid = [r for r in matrix.records if r["error_category"] not in {"infra_error", "build_error"}]
    infra_rate = 1.0 - (len(valid) / len(matrix.records)) if matrix.records else 1.0
    max_rate = float(policy.hard_conditions.get("max_infra_error_rate", 0.2))
    items = [
        Item("I1-goal-impact", "pass" if goal.get("type") == "file_read"
             and cia.get("confidentiality") == "high"
             and ("secret" in observable or "read" in observable) else "fail",
             f"goal={goal.get('type')} confidentiality={cia.get('confidentiality')}"),
        Item("I2-policy-clean", "pass" if not package_issues else "fail",
             "no instruction or packaging violations" if not package_issues
             else "; ".join(package_issues[:3])),
        Item("I3-infra-rate", "pass" if infra_rate <= max_rate else "fail",
             f"infra error rate {infra_rate:.2f} (limit {max_rate:.2f})"),
        Item("I4-fault-classified", "pass" if t12 and t12.met else
             ("not_applicable" if t12 is None else "fail"),
             t12.detail if t12 else "T12 fault injection not run"),
        Item("I5-network-policy", "pass" if network_isolation in {"allowlist", "public"} else "unknown",
             f"network_mode={network_isolation}"),
    ]
    return Dimension("I", 10.0, items)


def _hard_conditions(
    *,
    spec: dict,
    evidence: dict,
    matrix: MatrixResult,
    policy: Policy,
    profile: Profile,
    quality: float,
    network_isolation: str,
    extra_seed_errors: list[str],
) -> list[dict]:
    conditions = policy.hard_conditions
    t01 = matrix.expectation("T01")
    t02 = matrix.expectation("T02")
    t03 = [r for r in matrix.records if r["experiment_id"] == "T03"]
    t04 = [r for r in matrix.records if r["experiment_id"] == "T04"]
    negatives = {i: matrix.expectation(i) for i in conditions.get("require_negative_cases", [])}
    infra = sum(1 for r in matrix.records if r["error_category"] in {"infra_error", "build_error"})
    infra_rate = infra / len(matrix.records) if matrix.records else 1.0
    unknown_assertions = [a["id"] for a in spec.get("assertions", []) if a["status"] != "confirmed"]

    checks: list[dict] = []

    def add(condition_id: str, passed: bool, detail: str) -> None:
        checks.append({"id": condition_id, "passed": bool(passed), "detail": detail})

    if conditions.get("require_no_unknown_assertions", True):
        add("no_unknown_assertions", not unknown_assertions and not spec.get("unknown_fields"),
            f"unknown assertions={unknown_assertions} unknown fields={spec.get('unknown_fields')}")
    if conditions.get("require_attribution_grade_a", True):
        add("attribution_grade_a", spec.get("attribution_grade") == "A",
            f"grade={spec.get('attribution_grade')}")
    if conditions.get("require_t01_vulnerable_health", True):
        add("t01_vulnerable_health", bool(t01 and t01.met),
            t01.detail if t01 else "missing")
    if conditions.get("require_t02_fixed_health", True):
        add("t02_fixed_health", bool(t02 and t02.met),
            t02.detail if t02 else "missing")
    if conditions.get("require_reference_poc_all_success", True):
        passed = bool(t03) and all(r["goal_result"] == GOAL_PASSING for r in t03)
        add("reference_poc_all_success", passed,
            f"{sum(1 for r in t03 if r['goal_result'] == GOAL_PASSING)}/{len(t03)}")
    if conditions.get("require_zero_fixed_success", True):
        leaks = [r for r in t04 if (r["reward"] or 0.0) > 0.0]
        add("zero_fixed_success", bool(t04) and not leaks,
            f"{len(leaks)} fixed trials succeeded")
    for experiment_id, expectation in negatives.items():
        add(f"negative_{experiment_id}", bool(expectation and expectation.met),
            expectation.detail if expectation else "missing")
    max_rate = float(conditions.get("max_infra_error_rate", 0.2))
    add("infra_error_rate", infra_rate <= max_rate,
        f"{infra_rate:.2f} <= {max_rate:.2f}")
    valid = len(matrix.records) - infra
    add("min_valid_trials", valid >= profile.min_valid_trials,
        f"{valid} >= {profile.min_valid_trials} ({profile.name})")
    if conditions.get("require_paired_samples", True):
        add("paired_samples", bool(t03 and t04),
            f"T03={len(t03)} T04={len(t04)}")
    if conditions.get("require_network_allowlist", False):
        add("network_allowlist", network_isolation == "allowlist",
            f"network_mode={network_isolation}")
    add("seed_stability", not extra_seed_errors,
        "; ".join(extra_seed_errors) if extra_seed_errors else "consistent across seeds")
    add("quality_threshold", quality >= profile.min_quality_score,
        f"{quality:.1f} >= {profile.min_quality_score:.1f}")
    return checks


def _blocking(hard: list[dict], spec: dict, profile: Profile) -> bool:
    """Hard failures are blocking unless only sampling/profile thresholds miss."""
    soft_ids = {"quality_threshold"}
    if profile.name != "qualification":
        soft_ids |= {"min_valid_trials", "network_allowlist"}
    return any(
        not hc["passed"] and hc["id"] not in soft_ids for hc in hard
    )


def artifacts_match(records: Iterable[dict], artifact_digest: str) -> bool:
    return all(record.get("artifact_digest") == artifact_digest for record in records)


def _revision(records: list[dict]) -> int:
    return max((int(r.get("candidate_revision", 1)) for r in records), default=1)


def _wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    centre = p + z * z / (2 * total)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)
    return (max(0.0, (centre - margin) / denominator),
            min(1.0, (centre + margin) / denominator))


def require_admission(outcome: EvaluationOutcome) -> None:
    if outcome.admitted:
        return
    raise TaskError(
        "attribution_failure",
        "Task did not meet release conditions: "
        + "; ".join(outcome.evaluation.get("failure_reasons", [])[:5]),
        detail={"evaluation": outcome.evaluation},
    )
