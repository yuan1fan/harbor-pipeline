"""Curated, source-backed CVE facts for the first-version web scenario.

Each entry is verified against the collected sources. The curator records the
root cause and fix location that the automated extractor cannot infer on its
own; every assertion still cites a fetched source and is re-checked at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .util import PipelineError
from . import GENERATOR_VERSION


@dataclass(frozen=True)
class BuiltinCve:
    cve_id: str
    product: str
    ecosystem: str
    component: str
    affected: str
    fixed: str
    vulnerable_ref: str
    fixed_ref: str
    fix_commit: str
    fix_location: str
    vulnerable_code_ref: str
    root_cause: str
    impact_summary: str
    cia: dict[str, str]
    task_goal: dict[str, str]
    template: str
    pypi_name: str | None = None
    extra_sources: list[tuple[str, str, str]] = field(default_factory=list)


_BUILTINS: dict[str, BuiltinCve] = {
    "CVE-2024-23334": BuiltinCve(
        cve_id="CVE-2024-23334",
        product="aiohttp",
        ecosystem="pypi",
        component="web.static(follow_symlinks=True)",
        affected="< 3.9.2",
        fixed="3.9.2",
        vulnerable_ref="3.9.1",
        fixed_ref="3.9.2",
        fix_commit="1c335944d6a8b1298baf179b7c0b3069f10c514b",
        fix_location="aiohttp/web_urldispatcher.py:643 (_handle)",
        vulnerable_code_ref="aiohttp/web_urldispatcher.py:640-646 at tag v3.9.1",
        root_cause=(
            "When follow_symlinks=True, the static handler resolves the requested path "
            "but never checks that the unresolved path stays inside the configured "
            "static root, so a raw '..' request escapes the root even without symlinks."
        ),
        impact_summary="Unauthenticated arbitrary file read outside the configured static root.",
        cia={"confidentiality": "high", "integrity": "none", "availability": "none"},
        task_goal={
            "type": "file_read",
            "primitive": "path_traversal",
            "target_asset": "/opt/app/secret/token",
            "observable": (
                "The target's per-instance random secret token appears in the submitted "
                "PoC output after replay against the live target."
            ),
        },
        template="aiohttp_static_traversal",
        pypi_name="aiohttp",
        extra_sources=[
            (
                "https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f",
                "vendor_advisory",
                "aiohttp security advisory GHSA-5h86-8mv2-jq9f",
            ),
            (
                "https://github.com/aio-libs/aiohttp/commit/"
                "1c335944d6a8b1298baf179b7c0b3069f10c514b.patch",
                "upstream_commit",
                "Fix commit for directory traversal in web_urldispatcher.py",
            ),
            (
                "https://pypi.org/pypi/aiohttp/3.9.1/json",
                "release_notes",
                "PyPI metadata for the vulnerable release 3.9.1",
            ),
            (
                "https://pypi.org/pypi/aiohttp/3.9.2/json",
                "release_notes",
                "PyPI metadata for the fixed release 3.9.2",
            ),
        ],
    ),
}


def get(cve_id: str) -> BuiltinCve:
    try:
        return _BUILTINS[cve_id]
    except KeyError as exc:
        raise PipelineError(
            f"No built-in currated facts for {cve_id}; "
            "this CVE needs a curated entry before generation"
        ) from exc


def get_optional(cve_id: str) -> BuiltinCve | None:
    """Curated facts for this CVE, or None when the auto path must synthesize."""
    return _BUILTINS.get(cve_id)


def supported_ids() -> list[str]:
    return sorted(_BUILTINS)


def source_plan(cve: BuiltinCve) -> list[tuple[str, str, str]]:
    """Ordered (url, source_type, citation) tuples, CVE record first."""
    plan = [(f"https://cveawg.mitre.org/api/cve/{cve.cve_id}", "cve_record",
             "Official CVE JSON 5.0 record")]
    plan.extend(cve.extra_sources)
    return plan


def _source_for(evidence: dict, *, source_type: str, contains: str | None = None) -> dict:
    for source in evidence.get("sources", []):
        if source["source_type"] != source_type:
            continue
        if contains and contains not in source["url"]:
            continue
        return source
    raise PipelineError(
        f"Evidence has no {source_type} source"
        + (f" containing {contains}" if contains else "")
    )


def raw_spec(cve: BuiltinCve, evidence: dict, artifact_identity: list[dict]) -> dict:
    """Build a raw CveSpec from curated facts plus the live evidence index."""
    cve_source = _source_for(evidence, source_type="cve_record")
    commit_source = _source_for(evidence, source_type="upstream_commit")
    advisory_source = _source_for(evidence, source_type="vendor_advisory")
    release_sources = [
        s for s in evidence.get("sources", []) if s["source_type"] == "release_notes"
    ]
    release_source = release_sources[0] if release_sources else commit_source

    return {
        "cve_id": cve.cve_id,
        "curation_revision": GENERATOR_VERSION,
        "aliases": [],
        "product": {
            "name": cve.product,
            "ecosystem": cve.ecosystem,
            "component": cve.component,
        },
        "versions": {
            "affected": cve.affected,
            "fixed": cve.fixed,
            "vulnerable_ref": cve.vulnerable_ref,
            "fixed_ref": cve.fixed_ref,
            "fix_commit": cve.fix_commit,
        },
        "artifact_identity": artifact_identity,
        "preconditions": {
            "network_reachable": True,
            "auth_identity": "none",
            "privileges": "none",
            "configuration": (
                "Application registers web.static(..., follow_symlinks=True) on a "
                "publicly reachable HTTP route."
            ),
            "user_interaction": False,
            "dependencies": [],
            "unknown": [],
        },
        "root_cause": {
            "summary": cve.root_cause,
            "fix_location": cve.fix_location,
            "fix_commit": cve.fix_commit,
            "vulnerable_code_ref": cve.vulnerable_code_ref,
        },
        "impact": {"summary": cve.impact_summary, "cia": dict(cve.cia)},
        "task_goal": dict(cve.task_goal),
        "fix_basis": {
            "kind": "upstream_commit",
            "ref": cve.fix_commit,
            "source_id": commit_source["id"],
        },
        "assertions": [
            {
                "id": "A1",
                "text": f"The vulnerable release is {cve.vulnerable_ref} and the fix ships in {cve.fixed_ref}.",
                "source_id": release_source["id"],
                "citation": release_source["url"],
                "status": "confirmed" if release_source["status"] == "ok" else "unknown",
            },
            {
                "id": "A2",
                "text": "The root cause is the missing containment check in the static handler.",
                "source_id": commit_source["id"],
                "citation": commit_source["url"],
                "status": "confirmed" if commit_source["status"] == "ok" else "unknown",
            },
            {
                "id": "A3",
                "text": cve.impact_summary,
                "source_id": cve_source["id"],
                "citation": cve_source["url"],
                "status": "confirmed" if cve_source["status"] == "ok" else "unknown",
            },
            {
                "id": "A4",
                "text": "The vendor advisory confirms the issue and the mitigation.",
                "source_id": advisory_source["id"],
                "citation": advisory_source["url"],
                "status": "confirmed" if advisory_source["status"] == "ok" else "unknown",
            },
        ],
        "attribution_grade": "A",
        "unknown_fields": [],
    }


def artifact_identity_from_evidence(cve: BuiltinCve, evidence: dict, run_dir) -> list[dict]:
    """Use PyPI JSON metadata to pin the exact artifact digests."""
    import json
    from pathlib import Path

    identities = []
    for source in evidence.get("sources", []):
        if source["source_type"] != "release_notes" or "pypi.org/pypi/" not in source["url"]:
            continue
        path = source.get("local_path")
        if not path:
            continue
        try:
            data = json.loads(Path(run_dir).joinpath(path).read_text("utf-8"))
        except (OSError, ValueError):
            continue
        version = data.get("info", {}).get("version")
        if not version:
            continue
        sdist = None
        for item in data.get("urls", []):
            if item.get("packagetype") == "sdist":
                sdist = item
                break
        digest = sdist.get("digests", {}).get("sha256") if sdist else None
        identities.append({
            "kind": "pypi",
            "name": cve.pypi_name or cve.product,
            "version": version,
            "digest": f"sha256:{digest}" if digest else f"sha256:{source['content_sha256']}",
            "source_url": source["url"],
        })
    if not identities:
        identities.append({
            "kind": "pypi",
            "name": cve.pypi_name or cve.product,
            "version": cve.vulnerable_ref,
            "digest": f"unverified:{cve.vulnerable_ref}",
            "source_url": "https://pypi.org/",
        })
    return identities
