"""Deterministic CVE-consistency scoring and admission decisions.

Every sub-item is computed from frozen contracts, generated files, or trial
records. `unknown` never counts as a pass; `not_applicable` needs an explicit
reason and is excluded from the denominator.
"""

from __future__ import annotations

import math
import re
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
            "quality_score": self.evaluation.get("quality_score"),
            "quality_tier": self.evaluation.get("quality_tier"),
            "quality_flags": self.evaluation.get("quality_flags"),
            "goal_family": self.evaluation.get("goal_family"),
            "auth_scheme": self.evaluation.get("auth_scheme"),
            "admission_status": self.evaluation["admission_status"],
            "attribution_grade": self.evaluation["attribution_grade"],
            "dimensions": {
                key: {"score": round(dim.score, 3), "weight": dim.weight}
                for key, dim in self.dimensions.items()
            },
            "failed_conditions": [
                hc["id"] for hc in self.hard_conditions if not hc["passed"]
            ],
            "failed_framework": [
                check["id"]
                for check in self.evaluation.get("framework_health", [])
                if not check["passed"]
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
    skipped_experiments: dict[str, str] | None = None,
) -> EvaluationOutcome:
    """Evaluate a candidate with gates, framework health and a quality tier.

    There is deliberately no weighted 100-point score. Most of the old score
    was the admission checklist re-expressed as weights, so among released
    candidates it was constant; the only variance came from advisory probes.
    The evaluation now has three separate layers:

    * ``task_gates``: pass/fail admission checks for this task.
    * ``framework_health``: verifier/fault checks that say the pipeline is
      healthy; a failure is not a task defect and must not be repaired as one.
    * ``quality_tier``: A when the alternate valid PoC is accepted, B otherwise;
      evidence completeness is reported as flags, not as fake precision.
    """
    profile = policy.profile(profile_name)
    artifact_digest = image_set.get("target_digest") or digest(image_set)
    records = matrix.records
    skipped = skipped_experiments or {}
    dimensions = {
        "V": _dimension_v(spec, evidence, image_set, policy),
        "P": _dimension_p(spec, matrix, skipped),
        "M": _dimension_m(spec, evidence, matrix, skipped),
        "D": _dimension_d(matrix, profile),
        "I": _dimension_i(
            spec, evidence, matrix, package_issues or [], network_isolation
        ),
    }
    task_gates = _task_gates(
        spec=spec,
        evidence=evidence,
        matrix=matrix,
        image_set=image_set,
        dimensions=dimensions,
        profile=profile,
        policy=policy,
        network_isolation=network_isolation,
        extra_seed_errors=extra_seed_errors or [],
    )
    framework_health = _framework_health(matrix, policy)
    quality = _quality(spec, evidence, matrix)
    failures = [
        f"{gate['id']}: {gate['detail']}"
        for gate in task_gates
        if not gate["passed"]
    ]
    failures.extend(
        f"framework:{check['id']}: {check['detail']}"
        for check in framework_health
        if not check["passed"]
    )
    failures.extend(matrix.errors)
    valid = sum(
        1 for record in records
        if record["error_category"] not in {"infra_error", "build_error"}
    )
    t03 = [record for record in records if record["experiment_id"] == "T03"]
    successes = sum(1 for record in t03 if record["goal_result"] == GOAL_PASSING)
    interval = _wilson(successes, len(t03)) if t03 else [0.0, 0.0]
    blocking = _blocking(task_gates, framework_health, profile)
    if failures:
        status = "quarantined" if blocking else "candidate"
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
        # Kept as null for old consumers; the release decision uses the gates
        # and the quality tier, never a weighted scalar.
        "quality_score": None,
        "quality_tier": quality["tier"],
        "quality_flags": quality["flags"],
        "goal_family": str((spec.get("task_goal") or {}).get("family") or "secret_read"),
        "auth_scheme": str(
            (spec.get("preconditions") or {}).get("auth_scheme") or "none"
        ),
        "attribution_grade": spec["attribution_grade"],
        "sample_size": len(t03) or len(records),
        "valid_samples": valid,
        "confidence_interval": [round(interval[0], 4), round(interval[1], 4)],
        "hard_conditions": task_gates,
        "task_gates": task_gates,
        "framework_health": framework_health,
        "admission_status": status,
        "failure_reasons": failures,
        "evaluated_at": utc_now(),
    }
    validate("evaluation", evaluation)
    return EvaluationOutcome(
        evaluation=evaluation,
        dimensions=dimensions,
        hard_conditions=task_gates,
    )


def _normalize_package_name(name: str) -> str:
    """PEP 503-style name normalization, also useful for npm/Maven casing."""
    return re.sub(r"[-_.]+", "-", str(name)).strip().lower()


def _locked_dependency(
    deps: dict[str, str], product: str | None
) -> tuple[str | None, str | None]:
    """Find the product in the build lock without assuming registry casing.

    A requirements file may spell ``FlexGet`` while the advisory calls the
    product ``flexget``; Python packaging also treats ``-``/``_``/``.`` as
    equivalent. Missing an entry for that reason is not evidence about the
    task, so the lookup normalizes names before declaring V4 unknown.
    """
    if not product:
        return None, None
    if product in deps:
        return product, deps[product]
    wanted = _normalize_package_name(product)
    for name, version in deps.items():
        if _normalize_package_name(name) == wanted:
            return name, version
    return None, None


def _version_key(version: object) -> str:
    text = str(version or "").strip()
    return text[1:] if text[:1] in {"v", "V"} else text


def _version_tuple(version: object) -> tuple[int, ...]:
    parts = re.findall(r"\d+", _version_key(version))
    return tuple(int(part) for part in parts[:4]) or (0,)


def _affected_subpackage(
    deps: dict[str, str], product: str | None, affected: object
) -> tuple[str, str] | None:
    """Match a pinned subpackage named after the product inside the affected range.

    A monorepo advisory often names the product ("pnpm") while the vulnerable
    code lives in a separately versioned subpackage ("@pnpm/store.cafs"). The
    package lock then has no product entry, but it does pin the subpackage.
    Accept it only when the advisory's affected range names that package and
    the pinned version satisfies the comparator printed next to it.
    """
    if not product:
        return None
    wanted = _normalize_package_name(product)
    text = str(affected or "")
    for name, version in deps.items():
        segments = {
            _normalize_package_name(part)
            for part in name.lstrip("@").replace(":", "/").split("/")
            if part
        }
        if wanted not in segments:
            continue
        index = text.lower().find(name.lower())
        if index < 0:
            continue
        tail = text[index + len(name): index + len(name) + 80]
        match = re.search(r"(<=|>=|==|=|<|>)\s*([0-9][0-9A-Za-z.\-+_]*)", tail)
        if not match:
            continue
        operator, bound = match.group(1), match.group(2)
        actual, limit = _version_tuple(version), _version_tuple(bound)
        satisfied = {
            "<": actual < limit,
            "<=": actual <= limit,
            ">": actual > limit,
            ">=": actual >= limit,
            "=": actual == limit,
            "==": actual == limit,
        }[operator]
        if satisfied:
            return name, version
    return None


def _dimension_v(spec: dict, evidence: dict, image_set: dict, policy: Policy) -> Dimension:
    identities = spec.get("artifact_identity", [])
    pinned = [
        item for item in identities
        if str(item.get("digest", "")).startswith(("sha256:", "sha384:", "sha512:"))
        and "unverified" not in str(item.get("digest", ""))
    ]
    sources = evidence.get("sources", [])
    ok_sources = [s for s in sources if s.get("status") == "ok" and s.get("local_path")]
    versions = spec.get("versions", {})
    deps = image_set.get("dependencies", {})
    product = spec.get("product", {}).get("name")
    locked_name, locked = _locked_dependency(deps, product)
    subpackage = False
    if locked is None:
        match = _affected_subpackage(deps, product, versions.get("affected"))
        if match:
            locked_name, locked = match
            subpackage = True
    expected = versions.get("vulnerable_ref")
    if locked is None:
        lock_item = Item("V4-build-lock", "unknown", f"{product} is not in the built dependency lock")
    elif subpackage:
        lock_item = Item(
            "V4-build-lock", "pass",
            f"built {locked_name}=={locked} within affected range {versions.get('affected')}",
        )
    elif _version_key(locked) == _version_key(expected):
        lock_item = Item("V4-build-lock", "pass", f"built {locked_name}=={locked}")
    else:
        lock_item = Item(
            "V4-build-lock", "fail",
            f"built {locked_name}=={locked}, spec says vulnerable_ref={expected}",
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


def _dimension_p(
    spec: dict, matrix: MatrixResult, skipped: dict[str, str]
) -> Dimension:
    pre = spec.get("preconditions", {})
    complete = all(
        key in pre for key in
        ("network_reachable", "auth_identity", "privileges", "configuration", "user_interaction")
    ) and not pre.get("unknown")
    t01 = matrix.expectation("T01")
    t08 = matrix.expectation("T08")
    identity = str(pre.get("auth_identity") or "none")
    scheme = str(pre.get("auth_scheme") or ("none" if identity == "none" else ""))
    reachable = pre.get("network_reachable") is True
    # Authentication is a precondition, not a disqualifier. When the task
    # declares an authenticated identity, the framework supplies the credential
    # and the verifier re-runs the reference with it stripped: a task that is
    # still solvable without it is not an authenticated task.
    t03_auth = [
        record.get("auth") or {}
        for record in matrix.records
        if record.get("experiment_id") == "T03"
    ]
    t03_auth = [auth for auth in t03_auth if auth]
    if identity == "none":
        auth_ok = scheme in {"", "none"} and reachable
        auth_detail = f"auth=none scheme={scheme or 'none'} reachable={reachable}"
    else:
        clean = all(
            auth.get("required") and not auth.get("noauth_observed")
            for auth in t03_auth
        )
        auth_ok = (
            scheme in {"http_basic", "bearer_token"}
            and reachable
            and (clean or not t03_auth)
        )
        auth_detail = (
            f"auth={identity} scheme={scheme} reachable={reachable} "
            f"noauth_observed={[a.get('noauth_observed') for a in t03_auth] or 'not run'}"
        )
    items = [
        Item("P1-preconditions", "pass" if complete else "fail",
             "all precondition fields confirmed" if complete else "preconditions incomplete"),
        Item("P2-auth-precondition", "pass" if auth_ok else "fail", auth_detail),
        Item("P3-target-reachable", "pass" if t01 and t01.met else "fail",
             t01.detail if t01 else "T01 not run"),
        _control_item("P4-precondition-necessary", t08, skipped),
    ]
    return Dimension("P", 15.0, items)


def _control_item(item_id: str, t08, skipped: dict[str, str]) -> Item:
    """T08 is optional for release and cannot exist for synthesized targets."""
    if t08 is not None:
        return Item(item_id, "pass" if t08.met else "fail", t08.detail)
    reason = skipped.get("T08")
    if reason:
        return Item(item_id, "not_applicable", f"T08 not applicable: {reason}")
    return Item(item_id, "not_applicable", "T08 control not run")


def _dimension_m(
    spec: dict, evidence: dict, matrix: MatrixResult, skipped: dict[str, str]
) -> Dimension:
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
        _control_item("M4-control-eliminates", t08, skipped),
    ]
    return Dimension("M", 25.0, items)


def _fixed_held(record: dict) -> bool:
    """A fixed trial holds only when the reference PoC observed no secret.

    ``reward`` alone is not evidence: the verifier always reports 0.0 on the
    fixed variant, whether the PoC was blocked or the target still leaked. The
    observed status distinguishes the two.
    """
    detail = str((record.get("trigger_evidence") or {}).get("detail") or "")
    health = bool((record.get("health") or {}).get("ok"))
    return detail == "fixed_variant_holds" and health and (record.get("reward") or 0.0) == 0.0


def _dimension_d(matrix: MatrixResult, profile: Profile) -> Dimension:
    """Diagnostic differential items; T05-T07/T10 moved to framework health.

    D6 is the alternate-PoC quality probe; it is reported here for audit and
    drives the quality tier, not the admission gate.
    """
    t01 = matrix.expectation("T01")
    t02 = matrix.expectation("T02")
    t03_records = [r for r in matrix.records if r["experiment_id"] == "T03"]
    t04_records = [r for r in matrix.records if r["experiment_id"] == "T04"]
    t11 = matrix.expectation("T11")
    items = [
        Item("D1-vulnerable-health", "pass" if t01 and t01.met else "fail",
             t01.detail if t01 else "T01 not run"),
        Item("D2-fixed-health", "pass" if t02 and t02.met else "fail",
             t02.detail if t02 else "T02 not run"),
        Item("D3-poc-successes", "pass" if t03_records and all(
            r["goal_result"] == GOAL_PASSING for r in t03_records) else "fail",
            f"{sum(1 for r in t03_records if r['goal_result'] == GOAL_PASSING)}/{len(t03_records)} T03 trials passed"),
        Item("D4-fixed-holds", "pass" if t04_records and all(
            _fixed_held(r) for r in t04_records) else "fail",
            f"{sum(1 for r in t04_records if _fixed_held(r))}/{len(t04_records)} "
            "fixed trials held without disclosure"),
        Item("D6-alternate-accepted", "pass" if t11 and t11.met else
             ("not_applicable" if t11 is None else "fail"),
             t11.detail if t11 else "T11 not run"),
    ]
    return Dimension("D", 30.0, items)


def _dimension_i(
    spec: dict,
    evidence: dict,
    matrix: MatrixResult,
    package_issues: list[str],
    network_isolation: str,
) -> Dimension:
    """Diagnostic integrity items; infra rate and T12 are framework health."""
    goal = spec.get("task_goal", {})
    cia = spec.get("impact", {}).get("cia", {})
    observable = str(goal.get("observable", "")).lower()
    family = str(goal.get("family") or "secret_read")
    if family == "secret_read":
        coherent = (
            goal.get("type") in {"file_read", "secret_disclosure"}
            and cia.get("confidentiality") == "high"
            and any(word in observable for word in ("secret", "token"))
        )
    elif family == "file_write":
        coherent = (
            goal.get("type") == "file_write"
            and cia.get("integrity") == "high"
            and any(word in observable for word in ("marker", "write"))
        )
    elif family == "directory_listing":
        coherent = (
            goal.get("type") == "directory_listing"
            and cia.get("confidentiality") in {"low", "high"}
            and any(word in observable for word in ("filename", "listing", "name"))
        )
    elif family == "server_request":
        coherent = (
            goal.get("type") == "server_request"
            and any(word in observable for word in ("callback", "request", "url"))
            and any(
                cia.get(key) != "none"
                for key in ("confidentiality", "integrity", "availability")
            )
        )
    else:
        coherent = False
    items = [
        # Each family pairs one goal type with the impact axis it actually
        # changes: a token read is confidentiality, a forced marker write is
        # integrity, and a filename listing is at most a low disclosure.
        Item("I1-goal-impact", "pass" if coherent else "fail",
             f"family={family} goal={goal.get('type')} "
             f"primitive={goal.get('primitive', 'unknown')} "
             f"C/I/A={cia.get('confidentiality')}/{cia.get('integrity')}/{cia.get('availability')}"),
        Item("I2-policy-clean", "pass" if not package_issues else "fail",
             "no instruction or packaging violations" if not package_issues
             else "; ".join(package_issues[:3])),
        Item("I5-network-policy", "pass" if network_isolation in {"allowlist", "public"} else "unknown",
             f"network_mode={network_isolation}"),
    ]
    return Dimension("I", 10.0, items)


def _task_gates(
    *,
    spec: dict,
    evidence: dict,
    matrix: MatrixResult,
    image_set: dict,
    dimensions: dict[str, Dimension],
    profile: Profile,
    policy: Policy,
    network_isolation: str,
    extra_seed_errors: list[str],
) -> list[dict]:
    """Pass/fail admission checks that belong to this task.

    The V/P/M items and the D1-D4 health/PoC items are gates. D6 (alternate
    PoC) is a quality flag, T05-T07/T10/T12 are framework health, and T08 is
    not applicable to synthesized targets. T09 is a task gate.
    """
    gates: list[dict] = []

    def add(condition_id: str, passed: bool, detail: str) -> None:
        gates.append({"id": condition_id, "passed": bool(passed), "detail": str(detail)[:1200]})

    for key in ("V", "P", "M"):
        for item in dimensions[key].items:
            if item.status == "not_applicable":
                continue
            add(item.id, item.status == "pass", item.evidence)
    for item in dimensions["D"].items:
        if item.id == "D6-alternate-accepted" or item.status == "not_applicable":
            continue
        add(item.id, item.status == "pass", item.evidence)
    for item in dimensions["I"].items:
        if item.status == "not_applicable":
            continue
        add(item.id, item.status == "pass", item.evidence)

    # Canonical gate ids retained for the repair classifier and the release
    # audit. They mirror D1-D4 but carry the historical names the pipeline
    # already reasons about.
    t01 = matrix.expectation("T01")
    t02 = matrix.expectation("T02")
    t03 = [r for r in matrix.records if r["experiment_id"] == "T03"]
    t04 = [r for r in matrix.records if r["experiment_id"] == "T04"]
    add("t01_vulnerable_health", bool(t01 and t01.met),
        t01.detail if t01 else "missing")
    add("t02_fixed_health", bool(t02 and t02.met),
        t02.detail if t02 else "missing")
    add("reference_poc_all_success",
        bool(t03) and all(r["goal_result"] == GOAL_PASSING for r in t03),
        f"{sum(1 for r in t03 if r['goal_result'] == GOAL_PASSING)}/{len(t03)}")
    add("zero_fixed_success",
        bool(t04) and all(_fixed_held(r) for r in t04),
        f"{sum(1 for r in t04 if not _fixed_held(r))} fixed trials leaked or were unhealthy")

    spec_issues = check_evidence_links(spec, evidence) + check_spec_consistency(spec)
    add("spec_integrity", not spec_issues,
        "; ".join(spec_issues[:6]) if spec_issues else "spec and evidence agree")

    grade = spec.get("attribution_grade")
    allowed = list(profile.allow_attribution_grade)
    add("attribution_profile", grade in allowed,
        f"grade={grade} allowed={allowed}")

    conditions = policy.hard_conditions
    if conditions.get("require_no_unknown_assertions", True):
        unknown = [a["id"] for a in spec.get("assertions", []) if a["status"] != "confirmed"]
        add("no_unknown_assertions", not unknown and not spec.get("unknown_fields"),
            f"unknown assertions={unknown} unknown fields={spec.get('unknown_fields')}")

    if conditions.get("require_attribution_grade_a", True):
        add("attribution_grade_a", grade == "A", f"grade={grade}")

    valid = sum(
        1 for record in matrix.records
        if record["error_category"] not in {"infra_error", "build_error"}
    )
    add("min_valid_trials", valid >= profile.min_valid_trials,
        f"{valid} >= {profile.min_valid_trials} ({profile.name})")

    t03 = [r for r in matrix.records if r["experiment_id"] == "T03"]
    t04 = [r for r in matrix.records if r["experiment_id"] == "T04"]
    if conditions.get("require_paired_samples", True):
        floor = max(profile.min_valid_trials, profile.trials, matrix.matrix_repeats or 0)
        add("paired_samples", len(t03) == len(t04) and len(t03) >= floor,
            f"T03={len(t03)} T04={len(t04)} minimum pairs={floor}")

    add("seed_stability", not extra_seed_errors,
        "; ".join(extra_seed_errors) if extra_seed_errors else "consistent across seeds")
    if profile.name == "qualification":
        by_id = {source["id"]: source for source in evidence.get("sources", [])}
        backed = all(a.get("evidence_quote") and a.get("evidence_sha256") == by_id.get(a.get("source_id"), {}).get("content_sha256") for a in spec.get("assertions", []))
        from .cves import get_optional
        from . import GENERATOR_VERSION
        curated = get_optional(spec["cve_id"])
        curated_ok = bool(curated and spec.get("curation_revision") == GENERATOR_VERSION
                          and spec["versions"]["fix_commit"] == curated.fix_commit
                          and spec["root_cause"]["summary"] == curated.root_cause)
        add("assertion_provenance", bool(spec.get("assertions")) and (backed or curated_ok),
            "requires source excerpts/checksums or the current repository-curated specification")
        add("business_probe_coverage", curated_ok or bool(spec.get("business_probes")),
            "requires normal application-feature probes on both variants")
        seeds = [r for r in matrix.records if r["experiment_id"] == "T09"]
        for variant, status in (("vulnerable", "goal_passed"), ("fixed", "fixed_variant_holds")):
            verified = [r for r in seeds if r.get("variant") == variant
                        and (r.get("_audit") or {}).get("mode") == "clean-rebuild"
                        and (r.get("_audit") or {}).get("no_cache") is True
                        and (r.get("_audit") or {}).get("actual_image_digest")
                        and (r.get("health") or {}).get("ok")
                        and (r.get("trigger_evidence") or {}).get("detail") == status]
            samples = {r.get("seed") for r in verified}
            add(f"clean_rebuild_{variant}", len(samples) >= 3, f"{len(samples)}/3 clean rebuilds")
        for variant, expected in (("vulnerable", spec["versions"]["vulnerable_ref"]), ("fixed", spec["versions"]["fixed_ref"])):
            built = (image_set.get("variants") or {}).get(variant, {})
            identity = built.get("runtime_identity") or {}
            _, installed = _locked_dependency(identity.get("dependencies") or {}, spec["product"]["name"])
            add(f"runtime_identity_{variant}", bool(identity.get("verified")) and identity.get("image") == built.get("target_digest") and _version_key(installed) == _version_key(expected),
                f"installed={installed!r} expected={expected!r}; inspected image={identity.get('image')}")
        for experiment_id in ("T05", "T06", "T07", "T10"):
            actual = [r for r in matrix.records if r["experiment_id"] == experiment_id
                      and (r.get("_audit") or {}).get("mode") != "framework-verifier"]
            add(f"candidate_{experiment_id}", bool(actual), "requires a candidate-specific negative trial")

    artifact_digest = image_set.get("target_digest") or digest(image_set)
    add("artifact_digest", artifacts_match(matrix.records, artifact_digest),
        f"records reference {artifact_digest}")

    if conditions.get("require_network_allowlist", False):
        add("network_allowlist", network_isolation == "allowlist",
            f"network_mode={network_isolation}")
    return gates


def _framework_health(matrix: MatrixResult, policy: Policy) -> list[dict]:
    """Verifier/fault checks that are not task defects.

    A failure here means the grader or the harness is broken; the pipeline
    should stop and fix it, not ask the repair agent to rewrite the task.
    """
    checks: list[dict] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        checks.append({"id": check_id, "passed": bool(passed), "detail": str(detail)[:1200]})

    for experiment_id in policy.hard_conditions.get(
        "require_negative_cases", ["T05", "T06", "T07", "T10"]
    ):
        expectation = matrix.expectation(experiment_id)
        add(
            f"negative_{experiment_id}",
            bool(expectation and expectation.met),
            expectation.detail if expectation else "missing",
        )

    t12 = matrix.expectation("T12")
    if t12 is not None:
        add("fault_T12", bool(t12.met), t12.detail)
    elif matrix.aborted_at:
        # T12 is advisory and runs only after the blocking ladder. A task
        # that already failed T03/T04 never reaches it; that is not a second,
        # framework-level failure.
        add(
            "fault_T12",
            True,
            f"not run: matrix stopped at {matrix.aborted_at}; "
            "T12 only runs after the blocking ladder",
        )
    else:
        add("fault_T12", False, "missing")

    max_rate = float(policy.hard_conditions.get("max_infra_error_rate", 0.2))
    infra = sum(
        1 for record in matrix.records
        if record["error_category"] in {"infra_error", "build_error"}
    )
    rate = infra / len(matrix.records) if matrix.records else 1.0
    add("infra_error_rate", rate <= max_rate, f"{rate:.2f} <= {max_rate:.2f}")
    return checks


def _quality(spec: dict, evidence: dict, matrix: MatrixResult) -> dict:
    """Task quality: the alternate PoC plus evidence completeness flags."""
    t11 = matrix.expectation("T11")
    if t11 is None:
        alternate = "not_run"
    elif t11.met:
        alternate = "pass"
    else:
        alternate = "fail"
    identities = spec.get("artifact_identity", []) or []
    pinned = [
        item for item in identities
        if str(item.get("digest", "")).startswith(("sha256:", "sha384:", "sha512:"))
        and "unverified" not in str(item.get("digest", ""))
    ]
    sources = evidence.get("sources", []) or []
    local = [
        source for source in sources
        if source.get("status") == "ok" and source.get("local_path")
    ]
    flags = {
        "alternate_poc": alternate,
        "artifact_identity": f"{len(pinned)}/2",
        "source_coverage": f"{len(local)}/{len(sources)}",
    }
    return {"tier": "A" if alternate == "pass" else "B", "flags": flags}


def _blocking(
    task_gates: list[dict],
    framework_health: list[dict],
    profile: Profile,
) -> bool:
    """Admission gates block; sampling/profile thresholds are soft for smoke."""
    soft_ids = set()
    if profile.name != "qualification":
        soft_ids |= {"min_valid_trials", "network_allowlist"}
    if any(not check["passed"] for check in framework_health):
        return True
    return any(
        not gate["passed"] and gate["id"] not in soft_ids
        for gate in task_gates
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
