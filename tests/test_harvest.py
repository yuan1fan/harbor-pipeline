"""Harvest, triage, and sharding tests for the 2026-scale path."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from harbor_pipeline import discovery as discovery_mod
from harbor_pipeline.batch import Candidate, plan_batch
from harbor_pipeline.config import SourceSettings
from harbor_pipeline.discovery import Discovery
from harbor_pipeline.harvest import (
    _candidate_from_nvd,
    harvest,
    load_manifest,
    triage,
)
from harbor_pipeline.errors import TaskError
from harbor_pipeline.sources import EvidenceCollector, FetchResult, _request_headers

CVE = "CVE-2026-21440"
COMMIT = "143a16f35602be8561215611582211dec280cae6"


def _nvd_entry(**overrides) -> dict:
    entry = {
        "id": CVE,
        "published": "2026-01-02T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{
            "lang": "en",
            "value": (
                "AdonisJS is a TypeScript web framework. A path traversal in "
                "multipart file handling lets a remote attacker read arbitrary "
                "files from the server."
            ),
        }],
        "affected": [{
            "affectedData": [{
                "vendor": "adonisjs",
                "product": "bodyparser",
                "cpes": ["cpe:2.3:a:adonisjs:bodyparser:*:*:*:*:*:*:*:*"],
            }],
        }],
        "references": [
            {"url": f"https://github.com/adonisjs/bodyparser/commit/{COMMIT}"},
            {"url": "https://github.com/adonisjs/bodyparser/security/advisories/GHSA-xxxx"},
            {"url": "https://registry.npmjs.org/@adonisjs/bodyparser/10.0.0"},
        ],
    }
    entry.update(overrides)
    return entry


def test_nvd_candidate_keeps_commit_and_advisory_priority():
    candidate, reason = _candidate_from_nvd(_nvd_entry(), 2026)
    assert reason == ""
    assert candidate is not None
    assert candidate.cve_id == CVE
    assert "path_traversal" in candidate.primitives
    assert candidate.commit_refs
    assert candidate.advisory_refs
    assert candidate.ecosystem_hint == "npm"
    assert candidate.priority < 20


def test_nvd_candidate_keeps_xss_for_admin_bot_tasks():
    entry = _nvd_entry(descriptions=[{
        "lang": "en",
        "value": "A reflected cross-site scripting issue exists in the search parameter.",
    }])
    candidate, reason = _candidate_from_nvd(entry, 2026)
    assert reason == ""
    assert candidate is not None
    assert "xss" in candidate.primitives


def test_nvd_candidate_rejects_rejected_record():
    candidate, reason = _candidate_from_nvd(_nvd_entry(vulnStatus="Rejected"), 2026)
    assert candidate is None
    assert reason == "rejected CVE"


def test_osv_git_range_recovers_real_fix_release():
    osv = {
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "events": [{"fixed": COMMIT}],
                "database_specific": {
                    "extracted_events": [{
                        "source": "AFFECTED_FIELD",
                        "range": [
                            {"introduced": "4.5.3"},
                            {"fixed": "4.5.5"},
                        ],
                    }],
                },
            }],
            "versions": ["v4.5.4", "v4.5.3"],
        }],
    }
    _, _, _, fixed, affected = discovery_mod._package_facts(osv, [], {})
    assert fixed == "4.5.5"
    assert affected == ">= 4.5.3, < 4.5.5"


def test_osv_git_range_picks_highest_fixed_branch():
    osv = {
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "events": [],
                "database_specific": {
                    "extracted_events": [
                        {"source": "AFFECTED_FIELD",
                         "range": [{"introduced": "2.2.6"}, {"fixed": "2.2.7"}]},
                        {"source": "AFFECTED_FIELD",
                         "range": [{"introduced": "3.0.2"}, {"fixed": "3.0.3"}]},
                    ],
                },
            }],
        }],
    }
    _, _, _, fixed, affected = discovery_mod._package_facts(osv, [], {})
    assert fixed == "3.0.3"
    assert affected == ">= 3.0.2, < 3.0.3"


def test_harvest_reads_cached_feed_and_writes_manifest(tmp_path: Path):
    cache = tmp_path / "cache"
    cache.mkdir()
    feed = {"totalResults": 1, "vulnerabilities": [{"cve": _nvd_entry()}]}
    with gzip.open(cache / "nvdcve-2.0-2026.json.gz", "wt", encoding="utf-8") as handle:
        json.dump(feed, handle)

    output = tmp_path / "candidates.json"
    summary = harvest(
        settings=SourceSettings(),
        year=2026,
        output=output,
        cache_dir=cache,
    )

    assert summary["stats"]["kept"] == 1
    assert summary["stats"]["with_commit"] == 1
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["candidates"][0]["cve_id"] == CVE
    assert load_manifest(output)[0]["cve_id"] == CVE


def test_triage_marks_eligible_only_with_fix_pair(tmp_path: Path, monkeypatch):
    def fake_collect(settings, run_dir, cve_id):
        return {}, Discovery(
            cve_id=cve_id,
            package="bodyparser",
            ecosystem="npm",
            vulnerable_ref="10.0.0",
            fixed_ref="10.0.1",
            fix_commit=COMMIT,
            fix_source_id="src-1-upstream-commit",
        )

    monkeypatch.setattr(discovery_mod, "collect", fake_collect)
    output = tmp_path / "triage.json"
    report = triage(
        settings=SourceSettings(),
        candidates=[{"cve_id": CVE, "priority": 10, "primitive": "path_traversal"}],
        output=output,
        cache_dir=tmp_path / "cache",
        workers=1,
    )
    assert report["stats"]["eligible"] == 1
    assert report["stats"]["yield_rate"] == 1.0
    assert report["candidates"][0]["cve_id"] == CVE
    assert report["candidates"][0]["fixed_ref"] == "10.0.1"
    assert json.loads(output.read_text(encoding="utf-8"))["candidates"]


def test_triage_records_unsupported_without_fix_pair(tmp_path: Path, monkeypatch):
    def fake_collect(settings, run_dir, cve_id):
        return {}, Discovery(
            cve_id=cve_id,
            package="thing",
            ecosystem="pypi",
            vulnerable_ref="1.0",
            notes=("no fetchable upstream fix commit was found",),
        )

    monkeypatch.setattr(discovery_mod, "collect", fake_collect)
    report = triage(
        settings=SourceSettings(),
        candidates=[{"cve_id": CVE, "priority": 10}],
        output=tmp_path / "triage.json",
        cache_dir=tmp_path / "cache",
        workers=1,
    )
    assert report["stats"]["eligible"] == 0
    assert report["stats"]["unsupported"] == 1
    assert "fix commit" in report["unsupported"][0]["reason"]


def test_batch_shards_are_stable_and_disjoint(tmp_path: Path):
    candidates = [Candidate(f"CVE-2026-{index:04d}") for index in range(1, 7)]
    first = plan_batch(
        candidates, run_id="shard-0", profile="smoke", workers=1,
        output_root=tmp_path, shard_index=0, shard_count=2,
    )
    second = plan_batch(
        candidates, run_id="shard-1", profile="smoke", workers=1,
        output_root=tmp_path, shard_index=1, shard_count=2,
    )
    first_ids = [c.cve_id for c in first.candidates]
    second_ids = [c.cve_id for c in second.candidates]
    assert set(first_ids).isdisjoint(second_ids)
    assert sorted(first_ids + second_ids) == [c.cve_id for c in candidates]
    assert first.to_json()["shard_index"] == 0
    assert first.to_json()["shard_count"] == 2


def test_api_credentials_are_host_scoped():
    settings = SourceSettings(github_token="gh-token", nvd_api_key="nvd-key")
    github = _request_headers(settings, "https://api.github.com/advisories?cve_id=x")
    nvd = _request_headers(settings, "https://services.nvd.nist.gov/rest/json/cves/2.0")
    other = _request_headers(settings, "https://api.osv.dev/v1/vulns/x")
    assert github["Authorization"] == "Bearer gh-token"
    assert nvd["apiKey"] == "nvd-key"
    assert "Authorization" not in other
    assert "apiKey" not in other


def test_ecosystem_inferred_from_registry_reference():
    assert discovery_mod._infer_ecosystem(
        ["https://github.com/nfriedly/node-bestzip",
         "https://www.npmjs.com/package/bestzip"]
    ) == "npm"
    assert discovery_mod._infer_ecosystem(
        ["https://pypi.org/project/tornado/"]
    ) == "pypi"
    # A lookalike host must not decide how the build pins a dependency.
    assert discovery_mod._infer_ecosystem(
        ["https://evil.example/npmjs.com/package/bestzip"]
    ) is None


def test_release_tag_prefix_is_normalized():
    assert discovery_mod._normalize_release("v3.0.2") == "3.0.2"
    assert discovery_mod._normalize_release("V1.2.3") == "1.2.3"
    assert discovery_mod._normalize_release("3.0.3") == "3.0.3"
    assert discovery_mod._normalize_release("version-2") == "version-2"
    assert discovery_mod._normalize_release(None) is None


def test_registry_probe_pins_generic_project(tmp_path: Path, monkeypatch):
    body = json.dumps({"info": {"version": "6.5.9"}, "urls": []}).encode()

    def fake_fetch(url, settings):
        if url.endswith("/pypi/tornado/6.5.9/json"):
            return FetchResult(
                url=url,
                final_url=url,
                status=200,
                body=body,
                sha256="0" * 64,
                media_type="application/json",
            )
        raise TaskError("source_error", "HTTP 404")

    monkeypatch.setattr(discovery_mod, "fetch", fake_fetch)
    collector = EvidenceCollector(SourceSettings(), tmp_path)
    notes: list[str] = []

    assert discovery_mod._probe_registries(
        collector, "tornado", "6.5.9", notes
    ) == "pypi"
    assert collector.has_url("https://pypi.org/pypi/tornado/6.5.9/json")
    assert collector.sources[0]["source_type"] == "release_notes"
    # A failed probe must not pollute the evidence index.
    assert len(collector.sources) == 1
    assert any("probed from pypi" in note for note in notes)


def test_registry_probe_falls_through_to_npm(tmp_path: Path, monkeypatch):
    body = json.dumps({"version": "3.0.3", "dist": {"integrity": "sha512-abc=="}}).encode()

    def fake_fetch(url, settings):
        if url.startswith("https://registry.npmjs.org/bestzip/3.0.3"):
            return FetchResult(
                url=url,
                final_url=url,
                status=200,
                body=body,
                sha256="0" * 64,
                media_type="application/json",
            )
        raise TaskError("source_error", "HTTP 404")

    monkeypatch.setattr(discovery_mod, "fetch", fake_fetch)
    collector = EvidenceCollector(SourceSettings(), tmp_path)
    notes: list[str] = []

    assert discovery_mod._probe_registries(
        collector, "bestzip", "3.0.3", notes
    ) == "npm"
    identities = discovery_mod.artifact_identity(
        {"sources": collector.sources},
        tmp_path,
        product="bestzip",
        vulnerable_ref="3.0.2",
    )
    assert identities[0]["kind"] == "npm"
    assert identities[0]["digest"] == "sha512:abc=="


def test_artifact_identity_uses_npm_integrity(tmp_path: Path):
    (tmp_path / "release.json").write_text(
        json.dumps({"version": "3.0.3", "dist": {"integrity": "sha512-abc=="}}),
        encoding="utf-8",
    )
    evidence = {"sources": [{
        "source_type": "release_notes",
        "status": "ok",
        "url": "https://registry.npmjs.org/bestzip/3.0.3",
        "local_path": "release.json",
        "content_sha256": "0" * 64,
    }]}
    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product="bestzip", vulnerable_ref="3.0.2"
    )
    assert identities[0]["kind"] == "npm"
    assert identities[0]["digest"] == "sha512:abc=="


def test_artifact_identity_uses_go_sumdb_dirhash(tmp_path: Path):
    import base64

    raw = bytes(range(32))
    (tmp_path / "sum.txt").write_text(
        f"github.com/foo/bar v1.2.3 h1:{base64.b64encode(raw).decode()}\n"
        f"github.com/foo/bar v1.2.3/go.mod h1:{base64.b64encode(b'other').decode()}\n",
        encoding="utf-8",
    )
    evidence = {"sources": [{
        "source_type": "release_notes",
        "status": "ok",
        "url": "https://sum.golang.org/lookup/github.com/foo/bar@v1.2.3",
        "local_path": "sum.txt",
        "content_sha256": "0" * 64,
    }]}
    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product="github.com/foo/bar", vulnerable_ref="1.2.2"
    )
    assert identities[0]["kind"] == "go"
    assert identities[0]["name"] == "github.com/foo/bar"
    assert identities[0]["version"] == "1.2.3"
    assert identities[0]["digest"] == f"sha256:{raw.hex()}"


def test_artifact_identity_uses_maven_jar_sha256(tmp_path: Path):
    digest = "a" * 64
    (tmp_path / "artifact.sha256").write_text(digest + "\n", encoding="utf-8")
    evidence = {"sources": [{
        "source_type": "release_notes",
        "status": "ok",
        "url": ("https://repo1.maven.org/maven2/org/apache/commons/"
                "commons-lang3/3.12.0/commons-lang3-3.12.0.jar.sha256"),
        "local_path": "artifact.sha256",
        "content_sha256": "0" * 64,
    }]}
    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product="org.apache.commons:commons-lang3",
        vulnerable_ref="3.11.0",
    )
    assert identities[0]["kind"] == "maven"
    assert identities[0]["name"] == "org.apache.commons:commons-lang3"
    assert identities[0]["version"] == "3.12.0"
    assert identities[0]["digest"] == f"sha256:{digest}"


def test_artifact_identity_marks_malformed_maven_checksum_unverified(tmp_path: Path):
    (tmp_path / "artifact.sha256").write_text("<html>error</html>", encoding="utf-8")
    evidence = {"sources": [{
        "source_type": "release_notes",
        "status": "ok",
        "url": ("https://repo1.maven.org/maven2/com/example/app/1.0.0/"
                "app-1.0.0.jar.sha256"),
        "local_path": "artifact.sha256",
        "content_sha256": "1" * 64,
    }]}
    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product="com.example:app", vulnerable_ref="0.9.0"
    )
    assert identities[0]["digest"] == "unverified:" + "1" * 64


def test_dependency_lock_reads_go_mod_and_pom(tmp_path: Path):
    from harbor_pipeline.backend import dependency_lock

    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\n"
        "go 1.22\n\n"
        "require github.com/foo/bar v1.2.3\n\n"
        "require (\n"
        "  github.com/baz/qux v0.4.0\n"
        "  github.com/indirect/dep v2.0.0 // indirect\n"
        "  github.com/moby/moby v20.10.13+incompatible\n"
        ")\n",
        encoding="utf-8",
    )
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.commons</groupId>\n"
        "      <artifactId>commons-lang3</artifactId>\n"
        "      <version>3.11.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )

    lock = dependency_lock(tmp_path)

    assert lock["github.com/foo/bar"] == "1.2.3"
    assert lock["github.com/baz/qux"] == "0.4.0"
    assert lock["github.com/indirect/dep"] == "2.0.0"
    # Go writes ``+incompatible`` for modules without /vN; the spec pins the
    # bare version, so the lock must normalize it away.
    assert lock["github.com/moby/moby"] == "20.10.13"
    assert lock["org.apache.commons:commons-lang3"] == "3.11.0"


def test_dependency_lock_does_not_claim_vendored_upstream_ref(tmp_path: Path):
    """A Dockerfile download reference is not runtime package identity."""
    from harbor_pipeline.backend import dependency_lock

    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.24 AS source\n"
        "RUN curl -fsSL -o /tmp/whodb.tgz "
        '"https://codeload.github.com/clidey/whodb/tar.gz/refs/tags/0.134.0"\n'
        "RUN tar -xzf /tmp/whodb.tgz -C /src\n",
        encoding="utf-8",
    )

    lock = dependency_lock(tmp_path, product="whodb", ref="0.134.0")

    assert "whodb" not in lock  # Source text cannot attest an installed version.


def test_dependency_lock_strips_requirement_extras_and_markers(tmp_path: Path):
    from harbor_pipeline.backend import dependency_lock

    (tmp_path / "requirements.txt").write_text(
        "FlexGet[webui]==3.20.6; python_version >= '3.9'\n"
        "zope.interface>=5.0\n",
        encoding="utf-8",
    )

    lock = dependency_lock(tmp_path)

    assert lock["FlexGet"] == "3.20.6"
    assert lock["zope.interface"] == "unpinned"


def test_dependency_lock_ignores_nonmatching_vendored_ref(tmp_path: Path):
    from harbor_pipeline.backend import dependency_lock

    (tmp_path / "Dockerfile").write_text(
        "RUN curl -fsSL -o /tmp/app.tgz "
        '"https://codeload.github.com/org/app/tar.gz/refs/tags/1.0.0"\n',
        encoding="utf-8",
    )

    assert dependency_lock(tmp_path, product="app", ref="2.0.0") == {}


def test_collect_pins_go_module_versions_and_checksums(tmp_path: Path, monkeypatch):
    import base64
    import hashlib

    from harbor_pipeline import sources as sources_mod
    from harbor_pipeline.sources import cve_record_url

    cve = "CVE-2026-99001"
    commit = "b" * 40
    osv = {
        "id": cve,
        "affected": [{
            "package": {"name": "github.com/foo/bar", "ecosystem": "Go"},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            "versions": ["1.2.2"],
        }],
        "references": [{
            "type": "FIX",
            "url": f"https://github.com/foo/bar/commit/{commit}",
        }],
    }
    raw = bytes(range(32))
    h1 = base64.b64encode(raw).decode()
    sums = {
        "v1.2.3": f"github.com/foo/bar v1.2.3 h1:{h1}\n",
        "v1.2.2": f"github.com/foo/bar v1.2.2 h1:{h1}\n",
    }

    def fake_fetch(url, settings):
        table = {
            cve_record_url(cve): b'{"containers":{"cna":{"affected":[{"product":"bar"}]}}}',
            f"https://api.osv.dev/v1/vulns/{cve}": json.dumps(osv).encode(),
            f"https://github.com/foo/bar/commit/{commit}.patch":
                f"From {commit} Mon Sep 17 00:00:00 2001\n".encode(),
        }
        for version in ("1.2.3", "1.2.2"):
            table[f"https://proxy.golang.org/github.com/foo/bar/@v/v{version}.info"] = (
                json.dumps({"Version": f"v{version}"}).encode()
            )
            table[f"https://sum.golang.org/lookup/github.com/foo/bar@v{version}"] = (
                sums[f"v{version}"].encode()
            )
        body = table.get(url)
        if body is None:
            raise TaskError("source_error", "HTTP 404")
        return FetchResult(
            url=url,
            final_url=url,
            status=200,
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            media_type="application/json",
        )

    # EvidenceCollector resolves fetch from ``sources``, while the registry and
    # checksum helpers call the name bound into ``discovery`` at import time.
    # Both must be patched or the checksum request escapes to the network.
    monkeypatch.setattr(sources_mod, "fetch", fake_fetch)
    monkeypatch.setattr(discovery_mod, "fetch", fake_fetch)
    evidence, discovery = discovery_mod.collect(
        SourceSettings(), tmp_path, cve
    )

    assert discovery.ecosystem == "go"
    assert discovery.package == "github.com/foo/bar"
    assert discovery.fixed_ref == "1.2.3"
    assert discovery.vulnerable_ref == "1.2.2"
    assert discovery.fix_commit == commit

    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product=discovery.package,
        vulnerable_ref=discovery.vulnerable_ref,
    )
    by_version = {item["version"]: item for item in identities}
    assert by_version["1.2.2"]["digest"] == f"sha256:{raw.hex()}"
    assert by_version["1.2.3"]["digest"] == f"sha256:{raw.hex()}"


def test_artifact_identity_normalizes_go_incompatible_version(tmp_path: Path):
    import base64

    raw = bytes(range(32))
    (tmp_path / "sum.txt").write_text(
        f"github.com/moby/moby v20.10.13+incompatible "
        f"h1:{base64.b64encode(raw).decode()}\n",
        encoding="utf-8",
    )
    evidence = {"sources": [{
        "source_type": "release_notes",
        "status": "ok",
        "url": ("https://sum.golang.org/lookup/"
                "github.com/moby/moby@v20.10.13+incompatible"),
        "local_path": "sum.txt",
        "content_sha256": "0" * 64,
    }]}
    identities = discovery_mod.artifact_identity(
        evidence, tmp_path, product="github.com/moby/moby",
        vulnerable_ref="20.10.13",
    )
    assert identities[0]["version"] == "20.10.13"
    assert identities[0]["digest"] == f"sha256:{raw.hex()}"
