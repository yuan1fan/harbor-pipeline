"""Evidence/ref selection regressions, including the cached CC fallback path."""

import json
from dataclasses import replace

import pytest

from harbor_pipeline import discovery, evidence_resolver, harvest, sources
from harbor_pipeline.config import Config, Settings, SourceSettings
from harbor_pipeline.discovery import DiscoveryRef
from harbor_pipeline.discovery_refs import complete_missing_refs
from harbor_pipeline.errors import TaskError
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.sources import EvidenceCollector, FetchResult
from harbor_pipeline.util import digest, read_json, write_json
from harbor_pipeline.util import PipelineError

CVE = "CVE-2026-99999"
FIX = "a" * 40
VULN = "b" * 40
REPO = "acme/app"


def _record(collector, url, kind, document):
    body = document.encode() if isinstance(document, str) else json.dumps(document).encode()
    return collector.record(url, kind, "fixture", FetchResult(
        url=url, final_url=url, status=200, body=body,
        sha256=digest(body), media_type="application/json",
    ))


def _fixture(root, versions, *, repo=REPO, extra_products=()):
    collector = EvidenceCollector(SourceSettings(), root)
    item = {"product": "app", "repo": f"https://github.com/{repo}", "versions": versions}
    _record(collector, sources.cve_record_url(CVE), "cve_record", {
        "containers": {"cna": {"affected": [item, *extra_products]}},
    })
    patch = _record(collector, f"https://github.com/{REPO}/commit/{FIX}.patch", "upstream_commit",
                    f"From {FIX} Mon Sep 17 00:00:00 2001\ndiff --git a/app b/app\n@@ -1 +1 @@\n-bad\n+fixed\n")
    parsed = discovery.Discovery(
        cve_id=CVE, package="app", fixed_ref=FIX, fix_commit=FIX, fix_source_id=patch["id"],
    )
    return collector, parsed


def _commit(sha=VULN, parents=(), repo=REPO):
    return {"sha": sha, "html_url": f"https://github.com/{repo}/commit/{sha}",
            "parents": [{"sha": p} for p in parents]}


def _tag(value, sha=VULN):
    return {"ref": f"refs/tags/{value}", "object": {"type": "commit", "sha": sha}}


def _comparison(base=VULN, status="ahead"):
    return {"status": status, "base_commit": {"sha": base}, "merge_base_commit": {"sha": base}}


def _fetch(monkeypatch, responses):
    calls = []
    responses = dict(responses)
    responses.setdefault(f"https://api.github.com/repos/{REPO}/compare/{VULN}...{FIX}?per_page=1&page=2", _comparison())

    def fetch(url, _settings):
        calls.append(url)
        if url not in responses:
            raise TaskError("source_error", f"HTTP 404: {url}")
        body = json.dumps(responses[url]).encode()
        return FetchResult(url=url, final_url=url, status=200, body=body,
                           sha256=digest(body), media_type="application/json")

    monkeypatch.setattr(sources, "fetch", fetch)
    return calls


def _run(collector, parsed):
    return complete_missing_refs(collector.settings, collector.run_dir, collector.save(CVE), parsed)


@pytest.mark.parametrize("row,ref", [
    ({"status": "affected", "version": VULN}, VULN),
    ({"status": "affected", "version": "1.2.3"}, "1.2.3"),
    ({"status": "affected", "version": "0", "lessThanOrEqual": "1.69", "versionType": "semver"}, "1.69"),
    ({"status": "affected", "version": VULN, "lessThanOrEqual": FIX, "versionType": "git"}, VULN),
])
def test_cna_literal_and_inclusive_refs_are_verified(tmp_path, monkeypatch, row, ref):
    collector, parsed = _fixture(tmp_path, [row])
    url = (f"https://api.github.com/repos/{REPO}/commits/{ref}" if ref == VULN
           else f"https://api.github.com/repos/{REPO}/git/ref/tags/{ref}")
    calls = _fetch(monkeypatch, {url: _commit() if ref == VULN else _tag(ref)})
    evidence, actual = _run(collector, parsed)
    assert actual.vulnerable_ref == ref and actual.is_complete
    assert actual.build_ecosystem == "generic"
    assert actual.vulnerable.kind == ("commit" if ref == VULN else "tag")
    assert actual.fix_source_id == parsed.fix_source_id
    assert len(calls) == 2 and len(evidence["sources"]) == 4
    assert any("ref_metadata=src-3-other" in n for n in actual.notes)


def test_v_tag_is_preserved_as_an_actual_source_ref(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}])
    calls = _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/git/ref/tags/v1.2.3": _tag("v1.2.3")})
    _, actual = _run(collector, parsed)
    assert actual.vulnerable_ref == "v1.2.3" and len(calls) == 3


@pytest.mark.parametrize("versions", [
    [{"status": "affected", "version": "0", "lessThan": "1.2.3", "versionType": "semver"}],
    [{"status": "affected", "version": "*"}],
    [{"status": "affected", "version": "1.2.3", "changes": [{"at": "1.2.4", "status": "unaffected"}]}],
    [{"status": "affected", "version": "1.2.3"}, {"status": "unaffected", "version": "1.2.3"}],
    [{"status": "affected", "version": "2.0", "lessThanOrEqual": "1.0"}],
    [{"status": "affected", "version": "2.0", "lessThan": "1.0"}],
    [{"status": "affected", "version": "2.0", "lessThan": "2.0.0"}],
    [{"status": "affected", "version": FIX}],
])
def test_ambiguous_ranges_and_fixed_boundary_do_not_get_guessed(tmp_path, monkeypatch, versions):
    collector, parsed = _fixture(tmp_path, versions)
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, parsed)
    assert actual.vulnerable_ref is None
    assert all("git/ref/tags" not in url for url in calls)


@pytest.mark.parametrize("parents", [[], [VULN, "c" * 40], [FIX], ["not-a-commit"]])
def test_parent_must_be_one_real_distinct_commit(tmp_path, monkeypatch, parents):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": f"< {FIX}"}])
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{FIX}": _commit(FIX, parents)})
    _, actual = _run(collector, parsed)
    assert actual.vulnerable_ref is None


def test_parent_reuses_saved_metadata_and_marks_candidate_only(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "0", "lessThan": FIX, "versionType": "git"}])
    _record(collector, f"https://api.github.com/repos/{REPO}/commits/{FIX}", "other", {
        **_commit(FIX, [VULN]), "files": [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]})
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, parsed)
    assert actual.vulnerable_ref == VULN and calls == []
    assert any("fix_single_parent_candidate" in n and "requires downstream" in n for n in actual.notes)


@pytest.mark.parametrize("problem", ["repo", "product", "metadata_repo", "metadata_sha", "fix_sha", "empty_patch"])
def test_mismatched_identity_or_empty_patch_keeps_resolver_needed(tmp_path, monkeypatch, problem):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}],
                                 repo="other/app" if problem == "repo" else REPO)
    if problem == "product":
        parsed = replace(parsed, package="other-product")
    if problem == "fix_sha":
        parsed = replace(parsed, fix_commit="c" * 40)
    if problem == "empty_patch":
        (tmp_path / collector.sources[1]["local_path"]).write_text("")
    doc = _commit("c" * 40 if problem == "metadata_sha" else VULN,
                  repo="other/app" if problem == "metadata_repo" else REPO)
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{VULN}": doc})
    _, actual = _run(collector, parsed)
    assert not actual.is_complete
    if problem in {"fix_sha", "empty_patch"}:
        assert actual.fix_source_id is None
    else:
        assert actual.vulnerable_ref is None


def test_request_budget_and_transport_failure_fall_through(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [
        {"status": "affected", "version": "1.2.3"},
        {"status": "affected", "version": VULN, "versionType": "git"},
    ])
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, parsed)
    assert not actual.is_complete and len(calls) == 4


@pytest.mark.parametrize("eco", ["pypi", "npm", "go", "maven"])
def test_commit_ref_keeps_identity_but_uses_source_build(tmp_path, monkeypatch, eco):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    calls = _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit()})
    _, actual = _run(collector, replace(parsed, ecosystem=eco))
    assert actual.vulnerable.kind == "commit" and actual.fixed.kind == "commit"
    assert actual.ecosystem == eco and actual.build_ecosystem == "generic"
    assert len(calls) == 2


def test_existing_pair_is_not_replaced_or_refetched(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    source = _record(collector, f"https://api.github.com/repos/{REPO}/git/ref/tags/known-ref", "other", _tag("known-ref"))
    _record(collector, f"https://api.github.com/repos/{REPO}/compare/{VULN}...{FIX}?per_page=1&page=2", "other", _comparison())
    parsed = replace(parsed, vulnerable=DiscoveryRef("tag", "known-ref", repository=REPO,
                     resolved_commit=VULN, source_id=source["id"]),
                     fixed=DiscoveryRef("commit", FIX, repository=REPO,
                                        resolved_commit=FIX, source_id=parsed.fix_source_id))
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, parsed)
    assert replace(actual, selection_trace=()) == parsed and calls == []
    reused = next(event for event in actual.selection_trace if event["rule"] == "cached_pair" and event["outcome"] == "reused")
    assert "unavailable" in reused["reason"]
    evidence, again = _run(collector, actual)
    assert again == actual and calls == []


@pytest.mark.parametrize("valid_identity", [True, False])
def test_cna_release_uses_exact_registry_identity(tmp_path, monkeypatch, valid_identity):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}])
    parsed = replace(parsed, ecosystem="pypi", fixed_ref="1.2.4")
    _fetch(monkeypatch, {
        "https://pypi.org/pypi/app/1.2.3/json": {"info": {"name": "app" if valid_identity else "another-app", "version": "1.2.3"}},
        "https://pypi.org/pypi/app/1.2.4/json": {"info": {"name": "app", "version": "1.2.4"}},
    })
    _, actual = _run(collector, parsed)
    assert actual.vulnerable_ref == ("1.2.3" if valid_identity else None)
    assert actual.ecosystem == "pypi"


@pytest.mark.parametrize("body", ["", "  \n"])
def test_empty_successful_patch_is_not_reused_as_complete_checkpoint(tmp_path, monkeypatch, body):
    config = Config(pipeline=Settings(output_dir=str(tmp_path / "runs"), evidence_resolver=True))
    pipeline = CvePipeline(config=config, cve_id=CVE, run_id="r1", scenario="auto")
    collector, parsed = _fixture(pipeline.store.root, [{"status": "affected", "version": VULN}])
    evidence = collector.save(CVE)
    parsed = replace(parsed, vulnerable_ref=VULN)
    write_json(pipeline.store.root / "discovery.json", parsed.to_json())
    (pipeline.store.root / evidence["sources"][1]["local_path"]).write_text(body)
    recollected = []

    def collect(*args):
        recollected.append(True)
        return evidence, replace(parsed, fix_commit=None, fix_source_id=None)

    calls = []

    def resolve(self, **kwargs):
        calls.append(True)
        return evidence_resolver.ResolverOutcome(status="no_proposal")

    monkeypatch.setattr(discovery, "collect", collect)
    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", resolve)
    with pytest.raises(TaskError, match="no_proposal") as caught:
        pipeline._collect_auto(pipeline.store.create())
    assert caught.value.category.code == "evidence_insufficient"
    assert recollected == [True] and calls == [True]


@pytest.mark.parametrize("recoverable", [True, False])
def test_pipeline_checkpoint_runs_rules_then_cc_if_still_incomplete(tmp_path, monkeypatch, recoverable):
    config = Config(pipeline=Settings(output_dir=str(tmp_path / "runs"), evidence_resolver=True))
    pipeline = CvePipeline(config=config, cve_id=CVE, run_id="r1", scenario="auto")
    collector, parsed = _fixture(pipeline.store.root, [{"status": "affected", "version": VULN}])
    collector.save(CVE)
    write_json(pipeline.store.root / "discovery.json", parsed.to_json())
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit()} if recoverable else {})
    calls = []

    def resolve(self, **kwargs):
        calls.append(kwargs["discovery"])
        return evidence_resolver.ResolverOutcome(status="no_proposal")

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", resolve)
    monkeypatch.setattr(discovery, "collect", lambda *_: pytest.fail("must reuse checkpoint"))
    job = pipeline.store.create()
    if recoverable:
        pipeline._collect_auto(job)
        assert pipeline.discovery.vulnerable_ref == VULN and calls == []
        assert read_json(pipeline.store.root / "discovery.json")["vulnerable"]["value"] == VULN
    else:
        with pytest.raises(TaskError, match="no_proposal") as caught:
            pipeline._collect_auto(job)
        assert caught.value.category.code == "evidence_insufficient"
        assert len(calls) == 1


def test_triage_cache_also_applies_ref_rules(tmp_path, monkeypatch):
    root = tmp_path / CVE
    collector, parsed = _fixture(root, [{"status": "affected", "version": VULN}])
    collector.save(CVE)
    write_json(root / "discovery.json", parsed.to_json())
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit()})
    result = harvest._triage_one(SourceSettings(), {"cve_id": CVE}, cache_dir=tmp_path, no_cache=False)
    assert result.status == "eligible" and result.cache_hit
    assert read_json(root / "discovery.json")["vulnerable"]["value"] == VULN


def test_typed_refs_roundtrip_without_duplicate_legacy_fields():
    parsed = discovery.Discovery(cve_id=CVE, ecosystem="npm", package="app",
        vulnerable=DiscoveryRef("tag", "0.0.14", repository=REPO),
        fixed=DiscoveryRef("commit", FIX, repository=REPO), fix_commit=FIX,
        fix_source_id="fix")
    body = parsed.to_json()
    assert body["vulnerable"]["kind"] == "tag"
    assert body["vulnerable"]["value"] == "0.0.14"
    assert "vulnerable_ref" not in body and "fixed_ref" not in body
    assert discovery.Discovery.from_json(body) == parsed
    assert parsed.build_ecosystem == "generic" and parsed.build_package == REPO
    package = replace(parsed, vulnerable=DiscoveryRef("package_version", "0.0.14", ecosystem="npm", package="app"),
                      fixed=DiscoveryRef("package_version", "0.0.15", ecosystem="npm", package="app"))
    assert package.build_ecosystem == "npm"


def test_legacy_generic_version_remains_unresolved_and_conflicting_dual_fields_fail():
    legacy = discovery.Discovery.from_json({"cve_id": CVE, "ecosystem": "generic",
        "vulnerable_ref": "0.0.14", "fixed_ref": FIX, "fix_commit": FIX, "fix_source_id": "fix"})
    assert legacy.vulnerable.kind == "unresolved" and not legacy.is_complete
    with pytest.raises(PipelineError, match="conflicting"):
        discovery.Discovery.from_json({**legacy.to_json(), "vulnerable_ref": "another"})


@pytest.mark.parametrize("ref", [{"kind": "branch", "value": "main"},
                                 {"kind": "commit", "value": "1.2.3"},
                                 {"kind": "archive", "value": "1.2.3"}])
def test_invalid_ref_types_are_rejected(ref):
    with pytest.raises(PipelineError):
        DiscoveryRef.from_json(ref)


def test_commit_endpoint_for_numeric_branch_does_not_prove_a_git_tag(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}])
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/1.2.3": _commit()})
    _, actual = _run(collector, parsed)
    assert not actual.is_complete


@pytest.mark.parametrize("name_ok", [True, False])
def test_annotated_tag_resolves_its_commit_and_checks_tag_name(tmp_path, monkeypatch, name_ok):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}])
    annotation = "c" * 40
    _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/git/ref/tags/1.2.3": {"ref": "refs/tags/1.2.3", "object": {"type": "tag", "sha": annotation}},
        f"https://api.github.com/repos/{REPO}/git/tags/{annotation}": {"tag": "1.2.3" if name_ok else "wrong", "object": {"type": "commit", "sha": VULN}},
    })
    _, actual = _run(collector, parsed)
    assert actual.is_complete == name_ok
    if name_ok:
        assert actual.vulnerable.kind == "tag" and actual.vulnerable.resolved_commit == VULN


@pytest.mark.parametrize("purl,expected", [
    ("pkg:pypi/real-app@1.2.3", ("pypi", "real-app")),
    ("pkg:npm/%40scope/app@1.2.3", ("npm", "@scope/app")),
    ("pkg:maven/org.example/app@1.2.3", ("maven", "org.example:app")),
    ("pkg:golang/github.com/example/app@v1.2.3", ("go", "github.com/example/app")),
])
def test_package_url_namespace_is_parsed(purl, expected):
    from harbor_pipeline.discovery_refs import _purl
    assert _purl(purl) == expected


def test_purl_and_registry_prereleases_repair_a_display_name(tmp_path, monkeypatch):
    package_item = {"product": "app", "packageURL": "pkg:pypi/real-app", "defaultStatus": "unaffected", "versions": [
        {"status": "affected", "version": "0", "lessThan": "4.0.0b9", "versionType": "python"}]}
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "4.0.0-beta.8"}],
                                 extra_products=[package_item])
    calls = _fetch(monkeypatch, {
        "https://pypi.org/pypi/real-app/json": {"releases": {"4.0.0b8": [], "4.0.0b9": []}},
        "https://pypi.org/pypi/real-app/4.0.0b8/json": {"info": {"name": "real-app", "version": "4.0.0b8"}},
        "https://pypi.org/pypi/real-app/4.0.0b9/json": {"info": {"name": "real-app", "version": "4.0.0b9"}},
    })
    _, actual = _run(collector, replace(parsed, ecosystem="pypi"))
    assert actual.is_complete and actual.package == "real-app"
    assert actual.vulnerable.kind == actual.fixed.kind == "package_version"
    assert actual.vulnerable.value == "4.0.0b8" and all("real-app" in u for u in calls)


def test_registry_candidate_must_respect_affected_lower_bound(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.5.0", "lessThan": "2.0.0"}])
    _fetch(monkeypatch, {
        "https://pypi.org/pypi/app/json": {"releases": {"1.0.0": [], "2.0.0": []}},
        "https://pypi.org/pypi/app/2.0.0/json": {"info": {"name": "app", "version": "2.0.0"}},
        "https://pypi.org/pypi/app/1.0.0/json": {"info": {"name": "app", "version": "1.0.0"}},
    })
    _, actual = _run(collector, replace(parsed, ecosystem="pypi", vulnerable_ref="1.0.0", fixed_ref="2.0.0"))
    assert not actual.is_complete


@pytest.mark.parametrize("prefix", ["0.0.0-", "1.2.4-0.", "1.2.3-beta.1.0."])
def test_go_pseudo_version_maps_to_verified_commit_not_release_digits(tmp_path, monkeypatch, prefix):
    package = "github.com/acme/app/kernel"
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "< 3.6.1"}])
    _record(collector, f"https://api.github.com/advisories?cve_id={CVE}", "vendor_advisory", [{"vulnerabilities": [{
        "package": {"name": package, "ecosystem": "go"},
        "vulnerable_version_range": f"<= {prefix}20260313024916-{VULN[:12]}"}]}])
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{VULN[:12]}": _commit()})
    _, actual = _run(collector, replace(parsed, package=package, ecosystem="go", vulnerable_ref="3.6.0", fixed_ref="3.6.1"))
    assert actual.vulnerable.kind == actual.fixed.kind == "commit"
    assert actual.vulnerable.value == VULN and actual.fixed.value == FIX
    assert actual.build_ecosystem == "generic"


def test_dead_fork_is_retried_only_at_declared_upstream_with_same_sha(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    (tmp_path / collector.sources[1]["local_path"]).write_text("")
    collector.sources[1]["url"] = f"https://github.com/dead/app/commit/{FIX}.patch"
    _record(collector, f"https://api.osv.dev/v1/vulns/{CVE}", "other", {"affected": [{"ranges": [{
        "type": "GIT", "repo": f"https://github.com/{REPO}", "events": [{"fixed": FIX}]}]}]})
    fixed = {**_commit(FIX), "files": [{"filename": "app", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]}
    calls = _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{FIX}": fixed,
                                f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit()})
    parsed = replace(parsed, references=(f"https://github.com/dead/app/commit/{FIX}",))
    evidence, actual = _run(collector, parsed)
    assert actual.is_complete and actual.fix_commit == FIX
    assert any(u.endswith(f"/{REPO}/commits/{FIX}") for u in calls)
    assert next(s for s in evidence["sources"] if s["id"] == actual.fix_source_id)["source_type"] == "upstream_commit"


def test_empty_merge_does_not_invent_fix_evidence_from_another_parent(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    (tmp_path / collector.sources[1]["local_path"]).write_text("")
    p1, p2 = "c" * 40, "d" * 40
    fixed = {**_commit(FIX, [p1, p2]), "files": []}
    comparison = {"status": "ahead", "commits": [{"sha": FIX}],
                  "files": [{"filename": ".github/workflows/publish.yml", "patch": "@@ -1 +1 @@\n-old\n+new"}]}
    calls = _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/commits/{FIX}": fixed,
        f"https://api.github.com/repos/{REPO}/compare/{p2}...{FIX}": comparison,
        f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit(),
    })
    _, actual = _run(collector, replace(parsed, references=(f"https://github.com/{REPO}/commit/{FIX}",)))
    assert not actual.is_complete and actual.fix_source_id is None
    assert all(f"/compare/{p1}" not in u and f"/compare/{p2}" not in u for u in calls)


def test_typed_checkpoint_does_not_trust_a_stale_source_digest(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    source = _record(collector, f"https://api.github.com/repos/{REPO}/commits/{VULN}", "other", _commit())
    parsed = replace(parsed, vulnerable=DiscoveryRef("commit", VULN, repository=REPO, source_id=source["id"]),
                     fixed=DiscoveryRef("commit", FIX, repository=REPO, source_id=parsed.fix_source_id))
    (tmp_path / source["local_path"]).write_text(json.dumps(_commit("c" * 40)))
    _fetch(monkeypatch, {})
    _, actual = _run(collector, parsed)
    assert not actual.is_complete


@pytest.mark.parametrize("has_fix_patch", [True, False])
@pytest.mark.parametrize("old_registry_guess", [True, False])
def test_git_version_range_is_not_reinterpreted_as_pypi_from_matching_project_name(tmp_path, monkeypatch, has_fix_patch, old_registry_guess):
    collector, parsed = _fixture(tmp_path, [
        {"status": "affected", "version": "0", "lessThanOrEqual": "0.2.0", "versionType": "git"},
        {"status": "unaffected", "version": "0.3.1", "versionType": "git"},
    ])
    (tmp_path / collector.sources[1]["local_path"]).write_text("")
    fixed = {**_commit(FIX), "files": [{"filename": "app", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}] if has_fix_patch else []}
    calls = _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/commits/{FIX}": fixed,
        "https://pypi.org/pypi/app/0.2.0/json": {"info": {"name": "app", "version": "0.2.0"}},
        "https://pypi.org/pypi/app/0.3.1/json": {"info": {"name": "app", "version": "0.3.1", "project_urls": {"Source": f"https://github.com/{REPO}"}}},
    })
    parsed = replace(parsed, vulnerable_ref="0.0.6", references=(f"https://github.com/{REPO}/commit/{FIX}",))
    if old_registry_guess:
        parsed = replace(parsed, ecosystem="pypi", vulnerable_ref="0.2.0", fixed_ref="0.3.1")
    _, actual = _run(collector, parsed)
    assert not actual.is_complete
    assert actual.vulnerable.kind == "unresolved"
    assert all("pypi.org" not in url for url in calls)
    assert bool(actual.fix_source_id) == has_fix_patch


def test_cached_registry_guess_cannot_bypass_git_namespace_check(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [
        {"status": "affected", "version": "0", "lessThanOrEqual": "0.2.0", "versionType": "git"},
        {"status": "unaffected", "version": "0.3.1", "versionType": "git"},
    ])
    refs = []
    for version in ("0.2.0", "0.3.1"):
        url = f"https://pypi.org/pypi/app/{version}/json"
        source = _record(collector, url, "release_notes", {"info": {"name": "app", "version": version}})
        refs.append(DiscoveryRef("package_version", version, ecosystem="pypi", package="app", url=url, source_id=source["id"]))
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, replace(parsed, ecosystem="pypi", vulnerable=refs[0], fixed=refs[1]))
    assert not actual.is_complete and actual.vulnerable.kind == "unresolved"
    assert all("pypi.org" not in url for url in calls)


def test_explicit_numeric_git_ref_is_verified_as_a_tag(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "0.0.14", "versionType": "git"}])
    calls = _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/git/ref/tags/0.0.14": _tag("0.0.14")})
    _, actual = _run(collector, parsed)
    assert actual.is_complete and actual.vulnerable.kind == "tag"
    assert all("pypi.org" not in url for url in calls)


@pytest.mark.parametrize("correct_version", [True, False])
def test_wordpress_archive_must_match_slug_and_embedded_version(tmp_path, monkeypatch, correct_version):
    import io
    import urllib.parse
    import zipfile

    slug = "example-plugin"
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "0", "lessThanOrEqual": "1.69", "versionType": "semver"}])
    query = urllib.parse.urlencode({"action": "plugin_information", "request[slug]": slug, "request[fields][versions]": "true"})
    urls = {v: f"https://downloads.wordpress.org/plugin/{slug}.{v}.zip" for v in ("1.69", "1.69.1")}
    _record(collector, f"https://api.wordpress.org/plugins/info/1.2/?{query}", "other", {"slug": slug, "versions": urls})
    _record(collector, f"https://api.github.com/repos/{REPO}/tags?per_page=100", "other", [{"name": "1.69.1", "commit": {"sha": FIX}}])
    for version, url in urls.items():
        stream = io.BytesIO()
        actual_version = version if correct_version or version == "1.69.1" else "0.1"
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(f"{slug}/{slug}.php", f"<?php\n/*\nPlugin Name: Example Plugin\nVersion: {actual_version}\n*/")
        body = stream.getvalue()
        collector.record(url, "release_notes", "archive fixture", FetchResult(
            url=url, final_url=url, status=200, body=body, sha256=digest(body), media_type="application/zip"))
    calls = _fetch(monkeypatch, {})
    _, actual = _run(collector, replace(parsed, references=(f"https://plugins.trac.wordpress.org/browser/{slug}/tags/1.69/plugin.php",)))
    assert actual.is_complete == correct_version and calls == []
    if correct_version:
        assert actual.vulnerable.kind == actual.fixed.kind == "archive"
        assert actual.vulnerable.url == urls["1.69"] and len(actual.vulnerable.sha256) == 64


def test_source_build_types_reach_author_template_without_registry_pin(tmp_path):
    from harbor_pipeline.authoring import _bundle_template

    parsed = discovery.Discovery(cve_id=CVE, package="org.example:app", ecosystem="maven",
        vulnerable=DiscoveryRef("tag", "0.0.14", repository=REPO),
        fixed=DiscoveryRef("commit", FIX, repository=REPO), fix_commit=FIX)
    bundle = _bundle_template(parsed)
    assert bundle["product"]["ecosystem"] == "generic" and bundle["product"]["name"] == REPO
    assert bundle["versions"]["vulnerable_ref"] == "0.0.14"
    assert bundle["versions"]["fixed_ref"] == FIX
    assert FIX not in bundle["versions"]["affected"]


def test_resolver_accepts_typed_refs_and_rejects_namespace_conflicts(tmp_path):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    proposal = {"schema_version": "1.0", "cve_id": CVE, "status": "proposed", "ecosystem": "generic", "package": REPO,
                "vulnerable": {"kind": "tag", "value": "0.0.14", "repository": REPO},
                "fixed": {"kind": "commit", "value": FIX, "repository": REPO},
                "fix_commit": FIX, "fix_source_id": parsed.fix_source_id}
    evidence = collector.save(CVE)
    assert evidence_resolver.validate_proposal(proposal, evidence=evidence, cve_id=CVE, run_dir=tmp_path) == []
    issues = evidence_resolver.validate_proposal({**proposal, "ecosystem": "npm"}, evidence=evidence, cve_id=CVE, run_dir=tmp_path)
    assert any("generic" in issue for issue in issues)
    issues = evidence_resolver.validate_proposal({**proposal, "vulnerable_ref": "another"}, evidence=evidence, cve_id=CVE, run_dir=tmp_path)
    assert any("conflicting" in issue for issue in issues)


def test_resolver_cannot_promote_commit_metadata_without_a_patch(tmp_path):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    source = _record(collector, f"https://api.github.com/repos/{REPO}/commits/{FIX}", "upstream_commit", {
        **_commit(FIX, ["c" * 40, "d" * 40]), "files": []})
    proposal = {"schema_version": "1.0", "cve_id": CVE, "status": "proposed", "ecosystem": "generic",
                "vulnerable": {"kind": "commit", "value": VULN},
                "fixed": {"kind": "commit", "value": FIX},
                "fix_commit": FIX, "fix_source_id": source["id"]}
    issues = evidence_resolver.validate_proposal(proposal, evidence=collector.save(CVE), cve_id=CVE, run_dir=tmp_path)
    assert any("no actual patch" in issue for issue in issues)


@pytest.mark.parametrize("rows,preferred,expected", [
    ([{"status": "affected", "version": "1.2.3"}, {"status": "unaffected", "version": "1.2.4"}], "1.2.3", "1.2.3"),
    ([{"status": "affected", "version": "unspecified", "lessThan": "2.2.0", "versionType": "custom"}], "2.1.0", "2.1.0"),
    ([{"status": "affected", "version": "0", "lessThanOrEqual": "v2.13.2", "versionType": "custom"}], None, "v2.13.2"),
    ([{"status": "affected", "version": "1.0", "lessThan": "1.2.4"},
      {"status": "affected", "version": "2.0", "lessThan": "2.0.2"}], "1.2.3", "1.2.3"),
    ([{"status": "affected", "version": "3.6.0", "lessThan": "3.6.3"},
      {"status": "affected", "version": "1.1.1", "lessThan": "1.1.1zh", "versionType": "custom"}], "openssl-3.6.2", "openssl-3.6.2"),
    ([{"status": "affected", "version": "2.0.0", "lessThan": "2.31.0"}], "@example/pkg@2.30.1", "@example/pkg@2.30.1"),
])
def test_normal_status_ranges_and_scoped_tags_are_resolved(tmp_path, monkeypatch, rows, preferred, expected):
    import urllib.parse
    collector, parsed = _fixture(tmp_path, rows)
    parsed = replace(parsed, vulnerable_ref=preferred)
    url = f"https://api.github.com/repos/{REPO}/git/ref/tags/{urllib.parse.quote(expected, safe='')}"
    _fetch(monkeypatch, {url: _tag(expected)})
    _, actual = _run(collector, parsed)
    assert actual.is_complete and actual.vulnerable.kind == "tag"
    assert actual.vulnerable.value == expected


def test_registry_pair_stays_in_the_branch_of_the_vulnerable_ref(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [
        {"status": "affected", "version": "6.0", "lessThan": "6.0.8", "versionType": "python"},
        {"status": "unaffected", "version": "6.0.8", "versionType": "python"},
        {"status": "affected", "version": "5.2", "lessThan": "5.2.17", "versionType": "python"},
        {"status": "unaffected", "version": "5.2.17", "versionType": "python"},
    ])
    _fetch(monkeypatch, {f"https://pypi.org/pypi/app/{v}/json": {"info": {"name": "app", "version": v}}
                        for v in ("5.2.16", "5.2.17")})
    _, actual = _run(collector, replace(parsed, ecosystem="pypi", vulnerable_ref="5.2.16", fixed_ref="6.0.8"))
    assert actual.is_complete and actual.vulnerable.value == "5.2.16" and actual.fixed.value == "5.2.17"


def test_a_divergent_tag_is_skipped_for_an_affected_ancestor(tmp_path, monkeypatch):
    other = "c" * 40
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}, {"status": "affected", "version": "2.0.1"}])
    _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/git/ref/tags/2.0.1": _tag("2.0.1", other),
        f"https://api.github.com/repos/{REPO}/git/ref/tags/1.2.3": _tag("1.2.3"),
        f"https://api.github.com/repos/{REPO}/compare/{other}...{FIX}?per_page=1&page=2": {
            "status": "diverged", "base_commit": {"sha": other}, "merge_base_commit": {"sha": "e" * 40}},
    })
    _, actual = _run(collector, replace(parsed, vulnerable_ref="2.0.1"))
    assert actual.is_complete and actual.vulnerable.value == "1.2.3"


def test_an_already_patched_tag_is_rejected_before_parent_fallback(tmp_path, monkeypatch):
    parent = "d" * 40
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.2.3"}])
    _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/git/ref/tags/1.2.3": _tag("1.2.3"),
        f"https://api.github.com/repos/{REPO}/compare/{VULN}...{FIX}?per_page=1&page=2": _comparison(status="behind"),
        f"https://api.github.com/repos/{REPO}/commits/{FIX}": {**_commit(FIX, [parent]), "files": [
            {"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad()\n+fixed()"}]},
    })
    _, actual = _run(collector, parsed)
    assert actual.is_complete and actual.vulnerable.kind == "commit" and actual.vulnerable.value == parent


@pytest.mark.parametrize("kind", ["merge", "documentation", "all_unaffected", "contradictory"])
def test_parent_fallback_does_not_manufacture_a_supported_pair(tmp_path, monkeypatch, kind):
    rows = [{"status": "affected", "version": "1.2.3"}]
    if kind == "all_unaffected":
        rows = [{"status": "unaffected", "version": "0", "lessThanOrEqual": "1.2.3"}]
    if kind == "contradictory":
        rows.append({"status": "unaffected", "version": "1.2.3"})
    collector, parsed = _fixture(tmp_path, rows)
    doc = {**_commit(FIX, [VULN, "c" * 40] if kind == "merge" else [VULN]), "files": [
        {"filename": "docs/change.md" if kind == "documentation" else "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]}
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{FIX}": doc})
    _, actual = _run(collector, parsed)
    assert not actual.is_complete


def test_osv_affected_list_can_fill_an_incomplete_cna_enumeration(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "1.3.9"}, {"status": "unaffected", "version": "1.4.5.4"}])
    _record(collector, f"https://api.osv.dev/v1/vulns/{CVE}", "other", {"affected": [{
        "ranges": [{"type": "GIT", "repo": f"https://github.com/{REPO}"}], "versions": ["1.4.5.1"]}]})
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/git/ref/tags/1.4.5.1": _tag("1.4.5.1")})
    _, actual = _run(collector, replace(parsed, vulnerable_ref="1.4.5.1"))
    assert actual.is_complete and actual.vulnerable.value == "1.4.5.1"


@pytest.mark.parametrize("row", [
    {"status": "affected", "version": "0", "lessThan": "2026-07-14c", "versionType": "custom"},
    {"status": "affected", "version": "< b8492"},
    {"status": "affected", "version": "0", "lessThan": "*", "versionType": "semver"},
    {"status": "affected", "version": "0", "lessThan": FIX[:7], "versionType": "git"},
    {"status": "affected", "version": "0", "lessThan": "5.5.3-#182", "versionType": "custom"},
])
def test_opaque_release_range_can_use_verified_application_fix_parent(tmp_path, monkeypatch, row):
    collector, parsed = _fixture(tmp_path, [row])
    _fetch(monkeypatch, {f"https://api.github.com/repos/{REPO}/commits/{FIX}": {
        **_commit(FIX, [VULN]), "files": [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]}})
    _, actual = _run(collector, parsed)
    assert actual.is_complete and actual.vulnerable.kind == "commit" and actual.vulnerable.value == VULN


@pytest.mark.parametrize("status,accepted", [("ahead", True), ("diverged", False)])
def test_parent_must_precede_a_different_declared_git_cutoff(tmp_path, monkeypatch, status, accepted):
    cutoff = "c" * 40
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "0", "lessThan": cutoff, "versionType": "git"}])
    _fetch(monkeypatch, {
        f"https://api.github.com/repos/{REPO}/commits/{FIX}": {**_commit(FIX, [VULN]), "files": [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]},
        f"https://api.github.com/repos/{REPO}/compare/{VULN}...{cutoff}?per_page=1&page=2": _comparison(status=status),
    })
    _, actual = _run(collector, parsed)
    assert actual.is_complete == accepted


def test_default_affected_does_not_erase_an_explicit_status_conflict():
    from harbor_pipeline.discovery_refs import _has_affected_scope
    item = {"defaultStatus": "affected", "versions": [{"version": "1.2.3", "status": "affected"},
                                                       {"version": "1.2.3", "status": "unaffected"}]}
    assert not _has_affected_scope(item, FIX)


@pytest.mark.parametrize("api_available", [True, False])
def test_cached_patch_mailbox_is_rebound_to_the_requested_commit(tmp_path, monkeypatch, api_available):
    merge = "e" * 40
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": VULN}])
    source = collector.sources[1]
    body = (f"From {FIX} Mon Sep 17 00:00:00 2001\nSubject: first unrelated change\n"
            "diff --git a/session.py b/session.py\n@@ -1 +1 @@\n-old\n+new\n"
            f"From {'d' * 40} Mon Sep 17 00:00:00 2001\nSubject: real fix\n"
            "diff --git a/app.py b/app.py\n@@ -1 +1 @@\n-bad\n+fixed\n").encode()
    (tmp_path / source["local_path"]).write_bytes(body)
    source.update(url=f"https://github.com/{REPO}/commit/{merge}.patch", content_sha256=digest(body))
    doc = {**_commit(merge, [VULN, FIX]), "files": [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]}
    responses = {
        f"https://api.github.com/repos/{REPO}/commits/{VULN}": _commit(),
        f"https://api.github.com/repos/{REPO}/compare/{VULN}...{merge}?per_page=1&page=2": _comparison(),
    }
    if api_available:
        responses[f"https://api.github.com/repos/{REPO}/commits/{merge}"] = doc
    calls = _fetch(monkeypatch, responses)
    _, actual = _run(collector, replace(parsed, vulnerable_ref=VULN,
                                        references=(f"https://github.com/{REPO}/commit/{merge}",)))
    if api_available:
        assert actual.is_complete and actual.fixed.value == actual.fix_commit == merge
        assert actual.vulnerable.value == VULN and actual.fix_source_id != parsed.fix_source_id
    else:
        assert not actual.is_complete and actual.fix_source_id is None
        assert f"https://api.github.com/repos/{REPO}/commits/{FIX}" not in calls


def test_one_selector_rejects_wrong_package_and_explains_the_fallback(tmp_path, monkeypatch):
    collector, parsed = _fixture(tmp_path, [
        {"status": "affected", "version": "1.2.0", "lessThan": "1.2.4"},
        {"status": "unaffected", "version": "1.2.4"},
    ])
    calls = _fetch(monkeypatch, {
        "https://pypi.org/pypi/app/1.2.3/json": {"info": {"name": "another-package", "version": "1.2.3"}},
        "https://pypi.org/pypi/app/1.2.2/json": {"info": {"name": "app", "version": "1.2.2"}},
        "https://pypi.org/pypi/app/1.2.4/json": {"info": {"name": "app", "version": "1.2.4"}},
    })
    evidence, actual = _run(collector, replace(parsed, ecosystem="pypi", fixed_ref="1.2.4", affected_range=">= 1.2.0, < 1.2.4"))
    assert actual.is_complete and actual.vulnerable.value == "1.2.2"
    assert len(calls) == len(set(calls)) == 3
    rejected = [e for e in actual.selection_trace if e["rule"] == "registry_identity" and e["outcome"] == "rejected"]
    assert rejected[0]["candidate"]["value"] == "1.2.3" and rejected[0]["source_ids"]
    selected = actual.selection_trace[-1]
    assert selected["vulnerable"] == actual.vulnerable.to_json() and selected["mechanism_verified"] is False
    source_ids = {s["id"] for s in evidence["sources"]}
    assert all(set(e["source_ids"]) <= source_ids for e in actual.selection_trace)
    loaded = discovery.Discovery.from_json(json.loads(json.dumps(actual.to_json())))
    assert loaded == actual
    _, cached = complete_missing_refs(collector.settings, tmp_path, evidence, loaded)
    assert cached == actual and len(calls) == 3


@pytest.mark.parametrize("expression,expected", [
    (">= 1.2.0rc1, < 1.2.0", True), (">= 1.2.0", False),
    ("~1.2.0", None), ("< 2.0.0 garbage", None),
])
def test_release_range_parser_does_not_ignore_prereleases_or_unknown_syntax(expression, expected):
    from harbor_pipeline.discovery_refs import _range_allows
    assert _range_allows(expression, "1.2.0rc2") is expected


@pytest.mark.parametrize("same_fix", [True, False])
def test_osv_repository_name_change_requires_shared_fix_evidence(tmp_path, monkeypatch, same_fix):
    collector, parsed = _fixture(tmp_path, [{"status": "affected", "version": "0", "lessThan": "1.3.0"}])
    declared = "new-owner/app"
    _record(collector, f"https://api.osv.dev/v1/vulns/{CVE}", "other", {"affected": [{
        "ranges": [{"type": "GIT", "repo": f"https://github.com/{declared}"}], "versions": ["app-v1.2.9"],
    }]})
    _fetch(monkeypatch, {
        f"https://api.github.com/repos/{declared}/commits/{FIX}": {
            **_commit(FIX if same_fix else "f" * 40, repo=declared),
            "files": [{"filename": "app.py", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]},
        f"https://api.github.com/repos/{REPO}/git/ref/tags/app-v1.2.9": _tag("app-v1.2.9"),
        f"https://api.github.com/repos/{REPO}/compare/{VULN}...{FIX}?per_page=1&page=2": _comparison(),
    })
    _, actual = _run(collector, parsed)
    assert actual.is_complete == same_fix
    outcomes = [e["outcome"] for e in actual.selection_trace if e["rule"] == "osv_repository_fix"]
    assert outcomes == (["verified"] if same_fix else ["unresolved"])
    if same_fix:
        assert actual.vulnerable.value == "app-v1.2.9" and actual.vulnerable.repository == REPO
