"""Initial and author-requested proposals share exact ref verification."""
from dataclasses import replace

import pytest

from harbor_pipeline import discovery, evidence_resolver
from harbor_pipeline import authoring
from harbor_pipeline.agent import AgentOutcome
from harbor_pipeline.errors import TaskError
from harbor_pipeline.util import read_json
from test_author_evidence_review import case, CVE, REPO, OLD_BAD, OLD_FIX, QUOTE


def _proposal(case):
    return {"schema_version": "1.0", "cve_id": CVE, "status": "proposed", "ecosystem": "generic", "package": REPO,
        "vulnerable": {"kind": "commit", "value": OLD_BAD, "repository": REPO},
        "fixed": {"kind": "commit", "value": OLD_FIX, "repository": REPO},
        "fix_commit": OLD_FIX, "fix_source_id": case.initial.fix_source_id,
        "reason": "The upstream parent and patch are the exact candidate pair to validate.",
        "citations": [{"source_id": case.initial.fix_source_id, "quote": QUOTE}]}


def test_initial_resolver_proposal_is_canonical_and_pinned_on_resume(case, monkeypatch):
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", lambda *a, **k:
                        evidence_resolver.ResolverOutcome(status="proposed", proposal=_proposal(case)))
    incomplete = replace(case.initial, vulnerable=None, fixed=None)
    parsed, _ = case.pipeline._resolve_evidence(incomplete, case.collector.save(CVE))
    assert parsed.vulnerable.resolved_commit == OLD_BAD
    assert parsed.fixed.resolved_commit == OLD_FIX
    assert parsed.vulnerable.source_id and parsed.fixed.source_id
    saved = read_json(case.pipeline.store.path("resolver-result.json"))
    assert saved["proposal"]["vulnerable"]["resolved_commit"] == OLD_BAD
    assert saved["proposal"]["vulnerable"]["source_id"]
    assert "resolved_commit" not in saved["raw_proposal"]["vulnerable"]
    monkeypatch.setattr(discovery, "complete_missing_refs", lambda *a, **k: pytest.fail("must not reselect a pinned pair"))
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", lambda *a, **k: pytest.fail("must not call resolver again"))
    case.pipeline._collect_auto(case.pipeline.store.load())
    assert case.pipeline.discovery.vulnerable_ref == OLD_BAD


def test_abbreviated_fix_does_not_bypass_exact_patch_verification(case, monkeypatch):
    proposal = _proposal(case)
    proposal["fix_commit"] = OLD_FIX[:12]
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", lambda *a, **k:
                        evidence_resolver.ResolverOutcome(status="proposed", proposal=proposal))
    with pytest.raises(TaskError) as caught:
        case.pipeline._resolve_evidence(case.initial, case.collector.save(CVE))
    assert caught.value.category.code == "evidence_insufficient"
    assert read_json(case.pipeline.store.path("resolver-result.json"))["status"] == "invalid_proposal"


def test_unverified_initial_proposal_never_overwrites_discovery(case, monkeypatch):
    proposal = _proposal(case)
    proposal["vulnerable"]["resolved_commit"] = "e" * 40
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", lambda *a, **k:
                        evidence_resolver.ResolverOutcome(status="proposed", proposal=proposal))
    with pytest.raises(TaskError) as caught:
        case.pipeline._resolve_evidence(case.initial, case.collector.save(CVE))
    assert caught.value.category.code == "evidence_insufficient"
    assert discovery.load(case.pipeline.store.root, CVE) == case.initial
    assert read_json(case.pipeline.store.path("resolver-result.json"))["status"] == "invalid_proposal"


def test_existing_frozen_pair_mismatch_invalidates_all_dependent_evidence(case):
    store = case.pipeline.store
    store.write_artifact("cve-spec.json", {"versions": {"vulnerable_ref": "wrong", "fixed_ref": OLD_FIX, "fix_commit": OLD_FIX}})
    for name in ("image-set.json", "trials.json", "matrix/progress.json", "solver-review.json", "release-stage.json"):
        store.write_artifact(name, {"old": True})
    case.pipeline._invalidate_discovery_change(case.initial, case.initial)
    for name in ("cve-spec.json", "image-set.json", "trials.json", "matrix/progress.json", "solver-review.json", "release-stage.json"):
        assert not store.path(name).exists()
    assert store.load().revision == 2
    assert list(store.path("discovery-revisions").glob("*/previous/cve-spec.json"))
    assert (case.workspace.root / "poc/reference.py").is_file()


def test_resolved_tag_and_its_commit_are_not_a_frozen_pair_mismatch(case):
    tag = replace(case.initial.vulnerable, kind="tag", value="v1.0.0", resolved_commit=OLD_BAD)
    parsed = replace(case.initial, vulnerable=tag)
    case.pipeline.store.write_artifact("cve-spec.json", {"versions": {
        "vulnerable_ref": OLD_BAD, "fixed_ref": OLD_FIX, "fix_commit": OLD_FIX}})
    case.pipeline._invalidate_discovery_change(parsed, parsed)
    assert case.pipeline.store.load().revision == 1
    assert case.pipeline.store.path("cve-spec.json").is_file()


def test_finished_helper_resumes_author_without_generating_a_task_failure(case, monkeypatch):
    calls = []

    def session(workspace, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return AgentOutcome(status="completed", session_id="same-session",
                                helper_result={"status": "succeeded", "command": "build", "pending_at_exit": False})
        from harbor_pipeline.util import write_json
        write_json(workspace.root / authoring.SUBMISSION_FILE, {"status": "submitted"})
        return AgentOutcome(status="completed", session_id="same-session")

    monkeypatch.setattr(case.pipeline, "_run_author_session_once", session)
    # Simulate a long build that already consumed every failure-resume slot.
    job = case.pipeline.store.load()
    job.attempts["author_job_resume"] = 2
    case.pipeline.store.save(job)
    case.pipeline._run_author_session(case.workspace, prompt="start", resume=None)
    assert len(calls) == 2 and calls[1]["resume"] == "same-session"
    attempts = case.pipeline.store.load().attempts
    assert attempts["author_job_resume"] == 2
    assert attempts["author_helper_success_resume"] == 1


@pytest.mark.parametrize("status", ["timeout", "provider_error", "auth_error"])
def test_resolver_service_failures_are_not_unsupported(case, monkeypatch, status):
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", lambda *a, **k:
                        evidence_resolver.ResolverOutcome(status=status, error="provider unavailable"))
    with pytest.raises(TaskError) as caught:
        case.pipeline._resolve_evidence(case.initial, case.collector.save(CVE))
    assert caught.value.category.code == "infra_error"
