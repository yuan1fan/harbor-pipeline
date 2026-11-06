"""Build, freeze, and check CveSpec records against collected evidence."""

from __future__ import annotations

import copy
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from . import SCHEMA_VERSION
from .contracts import freeze_digest, validate
from .errors import TaskError
from .util import PipelineError

CONFIRMED = "confirmed"
UNKNOWN = "unknown"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def freeze(raw: dict, policy_version: str) -> dict:
    """Validate a raw spec, attach freeze metadata, and compute its digest."""
    spec = copy.deepcopy(raw)
    for key in ("frozen_digest", "frozen_at", "policy_version", "schema_version"):
        spec.pop(key, None)
    spec["schema_version"] = SCHEMA_VERSION
    spec["frozen_at"] = utc_now()
    spec["policy_version"] = policy_version
    spec["frozen_digest"] = freeze_digest(spec)
    validate("cve-spec", spec)
    return spec


def check_evidence_links(spec: dict, evidence: dict, *, run_dir: Path | None = None) -> list[str]:
    """Every citation must point at a fetched source; confirmed facts need ok sources."""
    issues: list[str] = []
    by_id = {source["id"]: source for source in evidence.get("sources", [])}
    if evidence.get("cve_id") != spec.get("cve_id"):
        issues.append("Evidence and spec refer to different CVEs")
    referenced = set()
    for assertion in spec.get("assertions", []):
        source_id = assertion["source_id"]
        referenced.add(source_id)
        source = by_id.get(source_id)
        if source is None:
            issues.append(f"{assertion['id']} cites missing source {source_id}")
            continue
        if assertion["status"] == CONFIRMED and source.get("status") != "ok":
            issues.append(
                f"{assertion['id']} is confirmed but source {source_id} failed to fetch"
            )
        if assertion.get("evidence_quote"):
            if assertion.get("evidence_sha256") != source.get("content_sha256"):
                issues.append(f"{assertion['id']} source checksum changed")
            if run_dir is not None:
                from .provenance import cited_excerpt
                _, _, error = cited_excerpt(assertion, source, run_dir)
                if error:
                    issues.append(f"{assertion['id']}: {error}")
    fix_source = spec.get("fix_basis", {}).get("source_id")
    if fix_source:
        referenced.add(fix_source)
        source = by_id.get(fix_source)
        if source is None:
            issues.append(f"fix_basis cites missing source {fix_source}")
        elif source.get("status") != "ok":
            issues.append(f"fix_basis source {fix_source} failed to fetch")
    for source_id in referenced:
        source = by_id.get(source_id)
        if source and source.get("status") == "ok" and not source.get("local_path"):
            issues.append(f"Source {source_id} has no saved local copy")
    if not any(s.get("source_type") == "upstream_commit" and s.get("status") == "ok"
               for s in evidence.get("sources", [])):
        issues.append("No fetched upstream fix commit is available")
    return issues


def check_spec_consistency(spec: dict) -> list[str]:
    issues: list[str] = []
    unknown_assertions = [a["id"] for a in spec.get("assertions", []) if a["status"] == UNKNOWN]
    if unknown_assertions:
        issues.append(f"Unknown assertions: {', '.join(unknown_assertions)}")
    if spec.get("unknown_fields"):
        issues.append(f"Unknown spec fields: {', '.join(spec['unknown_fields'])}")
    if spec.get("attribution_grade") == "A":
        if unknown_assertions or spec.get("unknown_fields"):
            issues.append("Grade A requires every required assertion to be confirmed")
        if not spec.get("root_cause", {}).get("fix_commit"):
            issues.append("Grade A requires a fix commit")
        if spec.get("versions", {}).get("vulnerable_ref") == spec.get("versions", {}).get("fixed_ref"):
            issues.append("Vulnerable and fixed references must differ")
    goal = spec.get("task_goal", {})
    family = str(goal.get("family") or "secret_read")
    expected_type = {
        "secret_read": {"file_read", "secret_disclosure"},
        "file_write": {"file_write"},
        "directory_listing": {"directory_listing"},
        "server_request": {"server_request"},
        "service_unavailable": {"service_unavailable"},
    }.get(family)
    if expected_type is None:
        issues.append(f"Unknown task_goal.family {family!r}")
    elif goal.get("type") not in expected_type:
        issues.append(
            f"task_goal.family {family!r} requires type in {sorted(expected_type)}, "
            f"got {goal.get('type')!r}"
        )
    observable = str(goal.get("observable", "")).lower()
    keywords = {
        "secret_read": ("secret", "token", "read"),
        "file_write": ("marker", "write"),
        "directory_listing": ("filename", "listing", "name"),
        "server_request": ("callback", "request", "url"),
        "service_unavailable": ("unavailable", "health", "crash", "availability"),
    }.get(family, ("secret", "token", "read"))
    if not any(word in observable for word in keywords):
        issues.append(
            f"{family} goal needs an observable containing one of {keywords}"
        )
    pre = spec.get("preconditions", {})
    identity = str(pre.get("auth_identity") or "none")
    scheme = str(pre.get("auth_scheme") or "")
    if identity == "none":
        if scheme not in {"", "none"}:
            issues.append("auth_scheme requires an authenticated identity")
    elif scheme not in {"http_basic", "bearer_token"}:
        issues.append(
            f"auth_identity {identity!r} requires an auth_scheme, got {scheme!r}"
        )
    return issues


def require_release_ready(spec: dict, evidence: dict, policy) -> None:
    """Raise a classified error if the spec cannot enter a released dataset."""
    issues = check_evidence_links(spec, evidence) + check_spec_consistency(spec)
    if issues:
        raise TaskError("evidence_insufficient", "; ".join(issues), detail={"issues": issues})
    if spec.get("attribution_grade") not in policy.profiles["qualification"].allow_attribution_grade:
        raise TaskError(
            "attribution_failure",
            f"Attribution grade {spec.get('attribution_grade')} is not releasable",
        )
    if spec.get("frozen_digest") != freeze_digest(spec):
        raise TaskError("attribution_failure", "Frozen digest does not match the spec body")


def assert_unchanged(spec: dict, expected_digest: str) -> None:
    if freeze_digest(spec) != expected_digest:
        raise PipelineError("Spec was modified after it was frozen")


def build_from_provider(provider, evidence: dict, policy_version: str) -> dict:
    """Ask a provider for a raw spec, then validate and freeze it."""
    from .providers.base import ModelRequest, ensure_structured
    from .contracts import load_schema

    response = provider.generate(ModelRequest(
        role="spec",
        system=(
            "You are a vulnerability evidence analyst. Extract only facts supported by "
            "the supplied sources. Mark anything not stated as unknown. Never invent "
            "commits, versions, or reproduction steps."
        ),
        prompt=(
            "Build a CveSpec from this evidence index. Cite source ids exactly as given.\n\n"
            + _evidence_summary(evidence)
        ),
        schema=load_schema("cve-spec"),
    ))
    return freeze(ensure_structured(response), policy_version)


def _evidence_summary(evidence: dict) -> str:
    lines = [f"CVE: {evidence.get('cve_id')}"]
    for source in evidence.get("sources", []):
        lines.append(
            f"- {source['id']} [{source['source_type']}] {source['url']} "
            f"status={source['status']} sha256={source['content_sha256']}"
        )
    return "\n".join(lines)


def summary(spec: dict) -> dict[str, Any]:
    return {
        "cve_id": spec["cve_id"],
        "product": spec["product"]["name"],
        "versions": spec["versions"],
        "goal": spec["task_goal"],
        "attribution_grade": spec["attribution_grade"],
        "unknown_fields": list(spec.get("unknown_fields", [])),
        "frozen_digest": spec["frozen_digest"],
    }
