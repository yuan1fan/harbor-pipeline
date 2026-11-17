"""Author -> resolver -> same author, with real checkpoint/ref validation.

Only the two agents and HTTP transport are stubbed; no model or Docker is used.
"""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from harbor_pipeline import author_tool, authoring, evidence_resolver, sources
from harbor_pipeline.agent import AgentOutcome
from harbor_pipeline.config import Config, Settings
from harbor_pipeline.contracts import load_policy
from harbor_pipeline.discovery import Discovery, DiscoveryRef
from harbor_pipeline.discovery_refs import verify_proposed_pair
from harbor_pipeline.errors import TaskError
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.sources import EvidenceCollector, FetchResult
from harbor_pipeline.util import PipelineError, digest, read_json, write_json

CVE = "CVE-2026-99999"
REPO = "example/service"
OLD_FIX, OLD_BAD, FIX, BAD = (char * 40 for char in "cdab")
QUOTE = "load the stored authorization boundary before processing the request"


def record(collector, url, kind, doc):
    body = json.dumps(doc).encode()
    return collector.record(url, kind, "test evidence", FetchResult(url=url, final_url=url, status=200,
        body=body, sha256=digest(body), media_type="application/json"))


def commit(sha, parent=None):
    return {"sha": sha, "html_url": f"https://github.com/{REPO}/commit/{sha}",
            "parents": [{"sha": parent}] if parent else [],
            "files": [{"filename": "service.py", "patch": "@@ -1 +1 @@\n-unchecked()\n+checked()"}],
            "commit": {"message": QUOTE}}


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "fetch", lambda *_: pytest.fail("unexpected network request"))
    config = Config(pipeline=Settings(output_dir=str(tmp_path / "runs"), evidence_resolver=True))
    pipeline = CvePipeline(config=config, cve_id=CVE, run_id="review", scenario="auto")
    pipeline.store.create()
    pipeline.store.transition(pipeline.store.load(), "EVIDENCE_READY", "fixture discovery complete")
    collector = EvidenceCollector(config.sources, pipeline.store.root)
    record(collector, sources.cve_record_url(CVE), "cve_record", {
        "containers": {"cna": {"affected": [{"product": REPO, "repo": f"https://github.com/{REPO}",
            "versions": [{"version": "0", "status": "affected", "lessThan": FIX, "versionType": "git"}]}]}}})
    old_source = record(collector, f"https://api.github.com/repos/{REPO}/commits/{OLD_FIX}", "upstream_commit", commit(OLD_FIX, OLD_BAD))
    old_bad_source = record(collector, f"https://api.github.com/repos/{REPO}/commits/{OLD_BAD}", "other", commit(OLD_BAD))
    initial = Discovery(cve_id=CVE, package=REPO, ecosystem="generic",
        vulnerable=DiscoveryRef("commit", OLD_BAD, repository=REPO, resolved_commit=OLD_BAD, source_id=old_bad_source['id']),
        fixed=DiscoveryRef("commit", OLD_FIX, repository=REPO, resolved_commit=OLD_FIX, source_id=old_source['id']),
        fix_commit=OLD_FIX, fix_source_id=old_source['id'])
    evidence = collector.save(CVE)
    pipeline.discovery = initial
    pipeline.store.write_artifact("discovery.json", initial.to_json())
    pipeline.store.write_artifact("evidence-index.json", evidence)
    workspace = authoring.prepare_workspace(run_dir=pipeline.store.root, cve_id=CVE, discovery=initial,
        evidence=evidence, revision=1, model="test")
    (workspace.root / "target/finding.txt").write_text("Both endpoints retain the unsafe URL fetch; the selected patch only validates filenames.", encoding="utf-8")
    (workspace.root / "poc/reference.py").write_text("# existing author work must survive\n", encoding="utf-8")
    ctx = author_tool.ToolContext(workspace.root, pipeline.store.root, CVE, 1, config, evidence, initial, load_policy())
    calls = []

    def resolve(_self, **kwargs):
        calls.append(kwargs)
        request = kwargs['review_request']
        fixed_source = record(collector, f"https://api.github.com/repos/{REPO}/commits/{FIX}", "upstream_commit", commit(FIX, BAD))
        record(collector, f"https://api.github.com/repos/{REPO}/commits/{BAD}", "other", commit(BAD))
        collector.save(CVE)
        proposal = {"schema_version": "1.0", "cve_id": CVE, "status": "proposed", "ecosystem": "generic", "package": REPO,
            "vulnerable": {"kind": "commit", "value": BAD, "repository": REPO},
            "fixed": {"kind": "commit", "value": FIX, "repository": REPO},
            "fix_commit": FIX, "fix_source_id": fixed_source['id'], "reason": "The author correctly identified an unrelated patch; the replacement checks the actual boundary.",
            "review_request_id": request['request_id'], "citations": [{"source_id": fixed_source['id'], "quote": QUOTE}]}
        return evidence_resolver.ResolverOutcome(status="proposed", proposal=proposal)

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", resolve)
    return SimpleNamespace(pipeline=pipeline, workspace=workspace, ctx=ctx, collector=collector,
                           calls=calls, resolve=resolve, initial=initial)


def request_review(case, **extra):
    payload = {"reason": "Source inspection shows the selected fixed endpoint still has the reported vulnerable path.",
               "citations": [{"path": "target/finding.txt", "quote": "the selected patch only validates filenames"}], **extra}
    write_json(case.workspace.root / "request.json", payload)
    assert author_tool.cmd_request_evidence_review(case.ctx, "request.json") == 0
    return read_json(case.workspace.root / authoring.EVIDENCE_REVIEW_FILE)


def test_complete_discovery_can_request_review_without_changing_refs(case):
    assert case.initial.is_complete
    write_json(case.workspace.submission_path, {"old": True})
    request = request_review(case, suggested_refs={"fixed": {"kind": "commit", "value": FIX}})
    assert case.workspace.status() == "evidence_review"
    assert request['citations'][0]['sha256'] and not case.workspace.submission_path.exists()
    assert read_json(case.pipeline.store.path("discovery.json"))['fix_commit'] == OLD_FIX
    with pytest.raises(PipelineError, match="pending"):
        author_tool.cmd_submit(case.ctx)


@pytest.mark.parametrize("citation", [
    {"path": "target/finding.txt", "quote": "This sentence is not present in the cited file"},
    {"path": "../discovery.json", "quote": "This path escapes the author workspace"},
])
def test_request_needs_real_local_evidence(case, citation):
    with pytest.raises(PipelineError):
        request_review(case, citations=[citation])
    assert not authoring.evidence_review_pending(case.workspace.root)


def test_correction_resumes_same_author_and_invalidates_old_results(case, monkeypatch):
    pipeline, workspace = case.pipeline, case.workspace
    for name in ("synthesis.json", "cve-spec.json", "image-set.json", "trials.json", "evaluation.json", "matrix/progress.json"):
        pipeline.store.write_artifact(name, {"old": True})
    for name in (authoring.BUILD_STATE_FILE, authoring.PROBE_STATE_FILE):
        write_json(workspace.root / name, {"old": True})
    write_json(workspace.root / authoring.COUNTERS_FILE, {"builds": 4})
    write_json(workspace.root / 'inputs/solver-review.json', {'old_pair_feedback': True})
    (pipeline.store.path("task")).mkdir()
    (pipeline.store.path("task/stale.txt")).write_text("old generated tree")
    steps = []

    def author(current, *, prompt, resume):
        steps.append(resume)
        if len(steps) == 1:
            request_review(case)
        else:
            assert resume == "author-session-1" and "pair changed" in prompt
            assert read_json(current.root / "inputs/discovery.json")['fix_commit'] == FIX
            assert not (current.root / "inputs/spec.json").exists()
            assert not (current.root / 'inputs/solver-review.json').exists()
            assert not (current.root / authoring.BUILD_STATE_FILE).exists()
            assert not (current.root / authoring.PROBE_STATE_FILE).exists()
            assert not pipeline.store.path("matrix/progress.json").exists()
            assert not pipeline.store.path("task").exists()
            assert read_json(current.root / authoring.COUNTERS_FILE)['builds'] == 4
            assert "existing author work" in (current.root / "poc/reference.py").read_text()
            write_json(current.submission_path, {"status": "submitted"})
        return AgentOutcome(status="completed", session_id="author-session-1")

    monkeypatch.setattr(pipeline, "_run_author_session_once", author)
    pipeline._run_author_session(workspace, prompt="initial", resume=None)
    assert steps == [None, "author-session-1"] and len(case.calls) == 1
    assert pipeline.discovery.fix_commit == FIX and pipeline.store.load().revision == 2
    assert pipeline.store.load().attempts['evidence_review'] == 1
    assert pipeline._evidence()['sources'][-1]['url'].endswith(BAD)
    assert pipeline.discovery.selection_trace[-1]['rule'] == "author_evidence_review"
    history = next(pipeline.store.path('evidence-reviews').iterdir())
    assert read_json(history / 'review.json')['status'] == 'applied'
    assert read_json(history / 'previous/image-set.json') == {'old': True}


@pytest.mark.parametrize("failure", ["invalid_quote", "wrong_request", "wrong_ref", "no_proposal", "infra_error"])
def test_failed_review_never_continues_with_the_challenged_pair(case, monkeypatch, failure):
    request_review(case)
    pipeline = case.pipeline

    def resolver(instance, **kwargs):
        if failure in {"no_proposal", "infra_error"}:
            return evidence_resolver.ResolverOutcome(status=failure, error="review unavailable")
        outcome = case.resolve(instance, **kwargs)
        if failure == "invalid_quote":
            outcome.proposal['citations'][0]['quote'] = "An invented upstream quote that was never fetched"
        elif failure == "wrong_request":
            outcome.proposal['review_request_id'] = '0' * 64
        else:
            outcome.proposal['vulnerable']['value'] = FIX
        return outcome

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, 'resolve', resolver)
    monkeypatch.setattr(pipeline, '_run_author_session_once', lambda *a, **k: pytest.fail("author must not continue after failed review"))
    with pytest.raises(TaskError) as caught:
        pipeline._run_author_session(case.workspace, prompt="resume", resume="old-session")
    assert caught.value.category.code == ("infra_error" if failure == "infra_error" else "evidence_insufficient")
    assert pipeline.discovery.fix_commit == OLD_FIX
    assert read_json(pipeline.store.path('discovery.json'))['fix_commit'] == OLD_FIX


def test_review_limit_survives_restarts(case, monkeypatch):
    request_review(case)
    job = case.pipeline.store.load()
    job.attempts['evidence_review'] = case.ctx.config.pipeline.max_evidence_reviews
    case.pipeline.store.save(job)
    with pytest.raises(TaskError) as caught:
        case.pipeline._review_author_evidence(case.workspace, "session")
    assert caught.value.category.code == "budget_exhausted" and not case.calls


def test_approved_review_recovers_without_spending_another_resolver_call(case, monkeypatch):
    request_review(case)
    original = case.pipeline._invalidate_evidence_pair
    monkeypatch.setattr(case.pipeline, '_invalidate_evidence_pair', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('interrupted')))
    with pytest.raises(RuntimeError, match='interrupted'):
        case.pipeline._review_author_evidence(case.workspace, "session")
    assert len(case.calls) == 1
    monkeypatch.setattr(case.pipeline, '_invalidate_evidence_pair', original)
    workspace, prompt = case.pipeline._review_author_evidence(case.workspace, "session")
    assert len(case.calls) == 1 and case.pipeline.store.load().revision == 2
    assert read_json(workspace.root / 'inputs/discovery.json')['fix_commit'] == FIX
    assert 'pair changed' in prompt


def test_changed_citation_cannot_reuse_an_old_request(case):
    request_review(case)
    with (case.workspace.root / 'target/finding.txt').open('a') as handle:
        handle.write('\nchanged observation')
    with pytest.raises(TaskError, match='no longer match'):
        case.pipeline._review_author_evidence(case.workspace, "session")
    assert not case.calls


def test_proposed_pair_validation_does_not_silently_select_another_pair(case):
    outcome = case.resolve(None, review_request={'request_id': 'fixture'})
    proposed = Discovery.from_json(outcome.proposal)
    proposed = replace(proposed, vulnerable=DiscoveryRef('commit', FIX, repository=REPO))
    with pytest.raises(PipelineError, match='pair failed'):
        verify_proposed_pair(case.ctx.config.sources, case.pipeline.store.root,
                             case.collector.save(CVE), proposed)
    assert read_json(case.pipeline.store.path('discovery.json'))['fix_commit'] == OLD_FIX


def test_resolver_can_explain_why_the_existing_pair_should_be_retained(case, monkeypatch):
    request = request_review(case)
    pipeline = case.pipeline
    pipeline.store.write_artifact('image-set.json', {'existing_build': True})
    pipeline.store.write_artifact('synthesis.json', {'old_submission': True})
    write_json(case.workspace.root / authoring.PROBE_STATE_FILE, {'ok': True})
    proposal = {**case.initial.to_json(), 'schema_version': '1.0', 'status': 'proposed',
        'review_request_id': request['request_id'],
        'reason': 'The cited file is a wrapper copy; the real upstream source checks the boundary in the selected fix.',
        'citations': [{'source_id': case.initial.fix_source_id, 'quote': QUOTE}]}
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, 'resolve',
                        lambda *a, **k: evidence_resolver.ResolverOutcome(status='proposed', proposal=proposal))
    workspace, prompt = pipeline._review_author_evidence(case.workspace, 'session')
    assert 'retained the pair' in prompt and pipeline.store.load().revision == 1
    assert pipeline.store.read_artifact('image-set.json') == {'existing_build': True}
    assert not pipeline.store.path('synthesis.json').exists()
    assert not (workspace.root / authoring.PROBE_STATE_FILE).exists()


def test_late_author_repair_can_correct_refs_without_double_incrementing_revision(case, monkeypatch):
    pipeline = case.pipeline
    for state in ('SPEC_FROZEN', 'GENERATED', 'BUILT', 'VALIDATING'):
        pipeline.store.transition(pipeline.store.load(), state, 'fixture late stage')
    request_review(case)

    def author(workspace, **kwargs):
        assert read_json(workspace.root / 'inputs/discovery.json')['fix_commit'] == FIX
        write_json(workspace.submission_path, {'status': 'submitted', 'bundle_digest': digest(authoring.assemble_bundle(workspace.root))})
        return AgentOutcome(status='completed', session_id='continued-author')

    monkeypatch.setattr(pipeline, '_run_author_session_once', author)
    monkeypatch.setattr(pipeline, '_consume_author_workspace', lambda *_: None)
    assert pipeline._resume_author(TaskError('attribution_failure', 'reference succeeds against both selected endpoints'))
    job = pipeline.store.load()
    assert job.state == 'REPAIRING' and job.revision == 2
    assert job.attempts['author_resume'] == job.attempts['evidence_review'] == 1


def test_fixed_source_endpoint_must_contain_the_proposed_fix(case):
    outcome = case.resolve(None, review_request={'request_id': 'fixture'})
    later = 'e' * 40
    record(case.collector, f'https://api.github.com/repos/{REPO}/commits/{later}', 'other', commit(later))
    record(case.collector, f'https://api.github.com/repos/{REPO}/compare/{FIX}...{later}?per_page=1&page=2', 'other',
           {'status': 'diverged', 'base_commit': {'sha': FIX}, 'merge_base_commit': {'sha': OLD_BAD}})
    proposed = replace(Discovery.from_json(outcome.proposal), fixed=DiscoveryRef('commit', later, repository=REPO))
    with pytest.raises(PipelineError, match='pair failed'):
        verify_proposed_pair(case.ctx.config.sources, case.pipeline.store.root, case.collector.save(CVE), proposed)


def test_resolver_receives_the_author_findings_and_requires_matching_request(case):
    request = request_review(case)
    prepared = evidence_resolver.prepare_workspace(run_dir=case.pipeline.store.root, cve_id=CVE,
        discovery=case.initial, evidence=case.ctx.evidence, model='test', review_request=request)
    assert read_json(prepared.root / 'inputs/author-evidence-review.json')['citations'] == request['citations']
    assert 'author-evidence-review.json' in evidence_resolver.first_prompt(CVE, request)
    evidence_resolver.prepare_workspace(run_dir=case.pipeline.store.root, cve_id=CVE,
        discovery=case.initial, evidence=case.ctx.evidence, model='test')
    assert not (prepared.root / 'inputs/author-evidence-review.json').exists()


def test_identical_new_findings_cannot_reuse_old_approval_to_bypass_review_limit(case):
    ids = []
    for _ in range(2):
        case.ctx.discovery = case.pipeline.discovery
        ids.append(request_review(case)['request_id'])
        case.pipeline._review_author_evidence(case.workspace, 'session')
    case.ctx.discovery = case.pipeline.discovery
    ids.append(request_review(case)['request_id'])
    assert len(set(ids)) == 3
    with pytest.raises(TaskError) as caught:
        case.pipeline._review_author_evidence(case.workspace, 'session')
    assert caught.value.category.code == 'budget_exhausted' and len(case.calls) == 2
