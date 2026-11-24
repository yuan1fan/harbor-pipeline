"""CVE-named upstream search: bounded, conservative, and atomic ref replacement."""

import json
import urllib.parse
from dataclasses import replace

import pytest

from harbor_pipeline import discovery, discovery_refs, sources
from harbor_pipeline.config import SourceSettings
from harbor_pipeline.errors import TaskError
from harbor_pipeline.sources import EvidenceCollector, FetchResult
from harbor_pipeline.util import digest

CVE = "CVE-2026-99999"
REPO = "example/service"
OLD_FIX = "a" * 40
NEW_FIX = "c" * 40
PARENT = "d" * 40
SECOND = "e" * 40
SEARCH_URL = "https://api.github.com/search/commits?" + urllib.parse.urlencode(
    {"q": f"repo:{REPO} {CVE}", "per_page": 5})


def commit(sha=NEW_FIX, *, message=None, parents=None, files=None, repo=REPO):
    return {
        "sha": sha, "html_url": f"https://github.com/{repo}/commit/{sha}",
        "commit": {"message": message or f"fix(auth): reject existing accounts ({CVE})"},
        "parents": [{"sha": p} for p in (parents if parents is not None else [PARENT])],
        "files": files if files is not None else [
            {"filename": "src/auth.py", "patch": "@@ -1 +1,2 @@\n+if account_exists(email):\n+    return forbidden()\n issue_token(email)"}],
    }


def hit(doc):
    return {k: doc[k] for k in ("sha", "html_url", "commit")}


def search(*documents, **overrides):
    return {"total_count": len(documents), "incomplete_results": False,
            "items": [hit(doc) for doc in documents], **overrides}


def fixture(tmp_path, monkeypatch, response, documents=()):
    collector = EvidenceCollector(SourceSettings(), tmp_path)
    body = json.dumps({"containers": {"cna": {"affected": [{"product": "service", "repo": f"https://github.com/{REPO}",
        "versions": [{"status": "affected", "version": "0", "lessThanOrEqual": "0.2.0", "versionType": "git"}]}]}}}).encode()
    url = sources.cve_record_url(CVE)
    collector.record(url, "cve_record", "fixture CVE", FetchResult(
        url=url, final_url=url, status=200, body=body, sha256=digest(body), media_type="application/json"))
    parsed = discovery.Discovery(cve_id=CVE, package="service", ecosystem="pypi", vulnerable_ref="0.2.0",
        fixed_ref="0.3.1", fix_commit=OLD_FIX, references=(f"https://github.com/{REPO}/commit/{OLD_FIX}",))
    old_doc = commit(OLD_FIX, message="Merge release branch", files=[])
    responses = {SEARCH_URL: response, f"https://api.github.com/repos/{REPO}/commits/{OLD_FIX}": old_doc}
    responses.update({f"https://api.github.com/repos/{REPO}/commits/{doc['sha']}": doc for doc in documents})
    calls = []

    def fetch(url, settings):
        calls.append(url)
        if url not in responses:
            raise TaskError("source_error", f"HTTP 404: {url}")
        body = json.dumps(responses[url]).encode()
        return FetchResult(url=url, final_url=url, status=200, body=body,
                           sha256=digest(body), media_type="application/json")

    monkeypatch.setattr(sources, "fetch", fetch)
    return collector, parsed, calls, responses


def test_search_replaces_both_stale_registry_refs_and_caches_the_pair(tmp_path, monkeypatch):
    fix = commit()
    merge = commit("f" * 40, message=f"Merge pull request: fix {CVE}", parents=[PARENT, SECOND])
    release = commit(SECOND, message=f"chore(release): bump own version\nContains {CVE} fix")
    collector, parsed, calls, _ = fixture(tmp_path, monkeypatch, search(merge, release, fix), [fix])
    original = parsed.to_json()
    evidence, result = discovery_refs.complete_missing_refs(collector.settings, tmp_path, collector.save(CVE), parsed)
    assert result.is_complete
    assert result.vulnerable.kind == result.fixed.kind == "commit"
    assert (result.vulnerable.value, result.fixed.value, result.fix_commit) == (PARENT, NEW_FIX, NEW_FIX)
    assert result.package == REPO and result.ecosystem == "generic"
    assert result.vulnerable.source_id == result.fixed.source_id == result.fix_source_id
    assert parsed.to_json() == original
    assert len(calls) == 3  # old fix metadata, search, one qualified commit
    assert all("pypi.org" not in url for url in calls)
    assert any("cve_named_fix_parent" in note for note in result.notes)
    source = next(s for s in evidence["sources"] if s["id"] == result.fix_source_id)
    assert source["source_type"] == "upstream_commit"
    _, again = discovery_refs.complete_missing_refs(collector.settings, tmp_path, evidence, result)
    assert again == result and len(calls) == 3


def test_plain_subject_with_body_fix_line_is_accepted(tmp_path, monkeypatch):
    # php-src uses a plain subject and states the CVE fix in the body.
    fix = commit(message=f"Avoid state corruption via bailout\n\nFix GHSA-w8hw-w9fx-j79w ({CVE})")
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(fix), [fix])
    evidence, result = discovery_refs.complete_missing_refs(
        collector.settings, tmp_path, collector.save(CVE), parsed
    )
    assert result.is_complete
    assert (result.vulnerable.value, result.fixed.value, result.fix_commit) == (PARENT, NEW_FIX, NEW_FIX)


def test_body_cve_mention_without_a_fix_line_is_not_enough(tmp_path, monkeypatch):
    doc = commit(message=f"Release notes\n\nThis release mentions {CVE} in passing")
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(doc), [doc])
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


@pytest.mark.parametrize("overrides", [
    {"incomplete_results": True}, {"incomplete_results": None}, {"total_count": 6},
    {"total_count": 2}, {"total_count": 1.0}, {"items": [None]},
])
def test_search_must_be_complete_and_bounded(tmp_path, monkeypatch, overrides):
    fix = commit()
    collector, parsed, calls, _ = fixture(tmp_path, monkeypatch, search(fix, **overrides), [fix])
    result = discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO)
    assert result is None and calls == [SEARCH_URL]


@pytest.mark.parametrize("doc", [
    commit(message=f"fix(auth): another CVE ({CVE}0)"),
    commit(message=f"chore(release): bump own version ({CVE})"),
    commit(parents=[PARENT, SECOND]), commit(parents=[]), commit(parents=[NEW_FIX]),
    {**commit(), "parents": {"sha": PARENT}},
    commit(parents=["not-a-sha"]), commit(files=[]),
    commit(files=[{"filename": "docs/security.md", "patch": "@@ -1 +1 @@\n-old\n+fixed"}]),
    commit(files=[{"filename": "tests/test_auth.py", "patch": "@@ -1 +1 @@\n-old\n+assert rejected"}]),
    commit(files=[{"filename": "pkg/__init__.py", "patch": '@@ -1 +1 @@\n-__version__ = "0.2.0"\n+__version__ = "0.3.1"'}]),
    commit(files=[{"filename": "src/auth.py", "patch": "@@ -1 +1 @@\n-# comment\n+# new comment"}]),
    commit(repo="unrelated/service"),
])
def test_non_fix_and_ambiguous_parent_candidates_are_not_selected(tmp_path, monkeypatch, doc):
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(doc), [doc])
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


def test_two_real_fixes_do_not_pick_the_first_result(tmp_path, monkeypatch):
    docs = [commit(), commit(SECOND)]
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(*docs), docs)
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


def test_a_failed_detail_lookup_is_not_evidence_of_unique_fix(tmp_path, monkeypatch):
    first, second = commit(), commit(SECOND)
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(first, second), [first])
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


def test_missing_file_patch_is_not_evidence_of_unique_fix(tmp_path, monkeypatch):
    first = commit()
    second = commit(SECOND, files=[{"filename": "src/auth.py", "changes": 12}])
    collector, parsed, _, _ = fixture(tmp_path, monkeypatch, search(first, second), [first, second])
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


def test_exhausted_budget_does_not_select_a_partially_examined_result_set(tmp_path, monkeypatch):
    docs = [commit(), commit(SECOND)]
    collector, parsed, calls, _ = fixture(tmp_path, monkeypatch, search(*docs), docs)
    metadata = discovery_refs._Metadata(collector, [])
    metadata.requests = discovery_refs.MAX_REF_REQUESTS - 2
    assert discovery_refs._search_fix_pair(parsed, metadata, REPO) is None
    assert len(calls) == 2 and metadata.requests == discovery_refs.MAX_REF_REQUESTS


@pytest.mark.parametrize("mismatch", ["sha", "repository", "message"])
def test_commit_details_must_confirm_search_identity(tmp_path, monkeypatch, mismatch):
    fix = commit()
    collector, parsed, _, responses = fixture(tmp_path, monkeypatch, search(fix), [fix])
    replacement = {"sha": SECOND} if mismatch == "sha" else (
        {"html_url": f"https://github.com/other/repo/commit/{NEW_FIX}"} if mismatch == "repository"
        else {"commit": {"message": "unrelated commit"}})
    responses[f"https://api.github.com/repos/{REPO}/commits/{NEW_FIX}"] = {**fix, **replacement}
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), REPO) is None


def test_a_valid_advertised_fix_does_not_trigger_search(tmp_path, monkeypatch):
    collector, parsed, calls, responses = fixture(tmp_path, monkeypatch, search(commit()), [commit()])
    responses[f"https://api.github.com/repos/{REPO}/commits/{OLD_FIX}"] = commit(OLD_FIX)
    _, result = discovery_refs.complete_missing_refs(collector.settings, tmp_path, collector.save(CVE), parsed)
    assert result.fix_commit == OLD_FIX and SEARCH_URL not in calls


def test_no_identified_repository_means_no_global_search(tmp_path, monkeypatch):
    collector, parsed, calls, _ = fixture(tmp_path, monkeypatch, search(commit()), [commit()])
    assert discovery_refs._search_fix_pair(parsed, discovery_refs._Metadata(collector, []), None) is None
    assert calls == []
    assert discovery_refs._fix_search_repo(replace(parsed, references=()), None, {}, {}) is None
