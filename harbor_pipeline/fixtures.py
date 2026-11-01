"""Canonical valid contract examples used by tests and the fixture provider.

These are synthetic (CVE-2024-0001) and never enter a released dataset.
They exist so the whole pipeline can be exercised without network or a model.
"""

from __future__ import annotations


from . import SCHEMA_VERSION
from .contracts import freeze_digest
from .util import digest

NOW = "2026-11-01T00:00:00+00:00"
POLICY_VERSION = "2026-11-01.1"
FIXTURE_CVE = "CVE-2024-0001"


def evidence_index() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": FIXTURE_CVE,
        "collected_at": NOW,
        "sources": [
            {
                "id": "src-cve-record",
                "url": "https://cveawg.mitre.org/api/cve/CVE-2024-0001",
                "fetched_at": NOW,
                "content_sha256": digest({"fixture": "cve-record"}),
                "source_type": "cve_record",
                "citation": "CNA description and CVSS vector",
                "status": "ok",
                "error": None,
                "local_path": "evidence/src-cve-record.json",
                "media_type": "application/json",
                "redirect_chain": [],
            },
            {
                "id": "src-fix-commit",
                "url": "https://github.com/example/project/commit/abcdef1",
                "fetched_at": NOW,
                "content_sha256": digest({"fixture": "fix-commit"}),
                "source_type": "upstream_commit",
                "citation": "Path normalisation guard added in app/static.py",
                "status": "ok",
                "error": None,
                "local_path": "evidence/src-fix-commit.txt",
                "media_type": "text/plain",
                "redirect_chain": [],
            },
            {
                "id": "src-release-notes",
                "url": "https://github.com/example/project/releases/tag/v1.2.4",
                "fetched_at": NOW,
                "content_sha256": digest({"fixture": "release-notes"}),
                "source_type": "release_notes",
                "citation": "Version 1.2.4 fixes CVE-2024-0001",
                "status": "ok",
                "error": None,
                "local_path": "evidence/src-release-notes.txt",
                "media_type": "text/plain",
                "redirect_chain": [],
            },
        ],
    }


def _freeze(spec: dict) -> dict:
    spec["frozen_digest"] = freeze_digest(spec)
    return spec


def cve_spec() -> dict:
    spec = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": FIXTURE_CVE,
        "aliases": [],
        "product": {"name": "example-webapp", "ecosystem": "pypi", "component": "static file handler"},
        "versions": {
            "affected": "1.2.3",
            "fixed": "1.2.4",
            "vulnerable_ref": "v1.2.3",
            "fixed_ref": "v1.2.4",
            "fix_commit": "abcdef1",
        },
        "artifact_identity": [
            {
                "kind": "pypi",
                "name": "example-webapp",
                "version": "1.2.3",
                "digest": "sha256:" + digest({"pypi": "example-webapp-1.2.3"}),
                "source_url": "https://pypi.org/project/example-webapp/1.2.3/",
            }
        ],
        "preconditions": {
            "network_reachable": True,
            "auth_identity": "none",
            "privileges": "none",
            "configuration": "default static route with follow_symlinks enabled",
            "user_interaction": False,
            "dependencies": [],
            "unknown": [],
        },
        "root_cause": {
            "summary": "Path normalisation allowed .. traversal when resolving a static file request.",
            "fix_location": "app/static.py:88",
            "fix_commit": "abcdef1",
            "vulnerable_code_ref": "app/static.py:74",
        },
        "impact": {
            "summary": "Unauthenticated arbitrary file read outside the static root.",
            "cia": {"confidentiality": "high", "integrity": "none", "availability": "none"},
        },
        "task_goal": {
            "type": "file_read",
            "target_asset": "/opt/app/secret/token",
            "observable": "The target's per-instance secret token appears in the submitted PoC output.",
        },
        "fix_basis": {"kind": "upstream_commit", "ref": "abcdef1", "source_id": "src-fix-commit"},
        "assertions": [
            {
                "id": "A1",
                "text": "The vulnerable version is 1.2.3 and the fix ships in 1.2.4.",
                "source_id": "src-release-notes",
                "citation": "Release v1.2.4 notes",
                "status": "confirmed",
            },
            {
                "id": "A2",
                "text": "The root cause is missing path normalisation in app/static.py.",
                "source_id": "src-fix-commit",
                "citation": "Commit abcdef1 diff",
                "status": "confirmed",
            },
            {
                "id": "A3",
                "text": "The goal is reading a file outside the static root without credentials.",
                "source_id": "src-cve-record",
                "citation": "CNA description",
                "status": "confirmed",
            },
        ],
        "attribution_grade": "A",
        "unknown_fields": [],
        "frozen_at": NOW,
        "policy_version": POLICY_VERSION,
    }
    return _freeze(spec)


def build_manifest(variant: str = "vulnerable", revision: int = 1) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": FIXTURE_CVE,
        "candidate_revision": revision,
        "variant": variant,
        "source_commit": "v1.2.3" if variant == "vulnerable" else "v1.2.4",
        "image_ref": f"harbor-cve/{FIXTURE_CVE.lower()}-{variant}:rev{revision}",
        "image_digest": "sha256:" + digest({"image": variant, "revision": revision}),
        "dependency_lock": {"example-webapp": "1.2.3" if variant == "vulnerable" else "1.2.4"},
        "cpu_arch": "x86_64",
        "harbor_version": "0.23.0",
        "generator_version": "generator-1.0.0",
        "prompt_version": "prompts-1.0.0",
        "file_digests": {"instruction.md": digest({"instruction": variant})},
        "control_plan": {"experiments": ["T01", "T02", "T03", "T04"]},
        "seed": 7,
        "task_digest": digest({"task": variant, "revision": revision}),
        "built_at": NOW,
    }


def trial_record(
    experiment_id: str = "T03",
    variant: str = "vulnerable",
    goal_result: str = "passed",
    *,
    observed: bool = True,
    health: bool = True,
    error_category: str | None = None,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "trial_id": f"trial-{experiment_id}-{variant}",
        "run_id": "run-fixture",
        "cve_id": FIXTURE_CVE,
        "candidate_revision": 1,
        "experiment_id": experiment_id,
        "variant": variant,
        "artifact_digest": digest({"image": variant, "revision": 1}),
        "seed": 7,
        "poc_digest": digest({"poc": "reference"}),
        "health": {"ok": health, "details": {"http_status": 200}},
        "trigger_evidence": {
            "observed": observed,
            "detail": "secret token returned" if observed else "no secret token in response",
            "target_response_digest": digest({"response": observed}),
        },
        "goal_result": goal_result,
        "exit_status": 0,
        "error_category": error_category,
        "duration_sec": 1.5,
        "model_meta": None,
        "reward": 1.0 if goal_result == "passed" else 0.0,
        "started_at": NOW,
    }


def evaluation(admission_status: str = "candidate") -> dict:
    def dim(weight: int, score: float = 1.0, status: str = "pass") -> dict:
        return {"weight": weight, "score": score, "items": [{"id": "x", "status": status, "evidence": "fixture"}]}

    return {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "cve_id": FIXTURE_CVE,
        "candidate_revision": 1,
        "artifact_digest": digest({"image": "vulnerable", "revision": 1}),
        "dimensions": {
            "V": dim(20),
            "P": dim(15),
            "M": dim(25),
            "D": dim(30),
            "I": dim(10),
        },
        "quality_score": 100.0,
        "attribution_grade": "A",
        "sample_size": 20,
        "valid_samples": 20,
        "confidence_interval": [0.83, 1.0],
        "hard_conditions": [{"id": "hc-1", "passed": True, "detail": "fixture"}],
        "admission_status": admission_status,
        "failure_reasons": [],
        "evaluated_at": NOW,
    }


def dataset_manifest() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "dataset_version": "2026.11.1",
        "created_at": NOW,
        "tasks": [
            {
                "cve_id": FIXTURE_CVE,
                "task_version": "1.0.0",
                "artifact_digest": digest({"image": "vulnerable", "revision": 1}),
                "project": "example-webapp",
                "root_cause_group": "path-traversal",
                "patch_group": "abcdef1",
                "split": "train",
                "location": "runs/run-fixture/CVE-2024-0001/release/task",
            }
        ],
    }
