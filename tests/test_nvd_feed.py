"""Local NVD yearly-feed index used to avoid the rate-limited CVE API."""

from __future__ import annotations

import gzip
import hashlib
import json
import os

from harbor_pipeline import discovery as discovery_mod
from harbor_pipeline import sources as sources_mod
from harbor_pipeline.config import SourceSettings
from harbor_pipeline.nvd_feed import NvdFeedCache
from harbor_pipeline.sources import EvidenceCollector, FetchResult

CVE = "CVE-2026-0001"


def _entry(cve_id: str, url: str = "https://example.test/commit/abc") -> dict:
    return {"cve": {"id": cve_id, "references": [{"url": url}]}}


def _write_feed(path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"resultsPerPage": len(entries), "vulnerabilities": entries}
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(document, handle)


def _settings(cache_dir=None) -> SourceSettings:
    return SourceSettings(nvd_feed_cache=str(cache_dir) if cache_dir else None)


def test_feed_index_serves_an_api_shaped_record(tmp_path):
    cache = NvdFeedCache(tmp_path)
    _write_feed(cache.feed_path(2026), [_entry(CVE)])

    found = cache.lookup(_settings(), CVE)

    assert found is not None
    document, provenance = found
    assert document["vulnerabilities"][0]["cve"]["id"] == CVE
    assert provenance.records == 1
    expected = hashlib.sha256(cache.feed_path(2026).read_bytes()).hexdigest()
    assert provenance.feed_sha256 == expected
    assert "nvdcve-2.0-2026.json.gz" in provenance.citation()
    assert provenance.feed_url.startswith("https://nvd.nist.gov/feeds/")
    assert not cache.db_path(2026).with_name(
        cache.db_path(2026).name + ".part"
    ).exists()


def test_feed_index_returns_none_for_a_missing_cve(tmp_path):
    cache = NvdFeedCache(tmp_path)
    _write_feed(cache.feed_path(2026), [_entry(CVE)])

    assert cache.lookup(_settings(), "CVE-2026-999999") is None


def test_feed_index_rebuilds_when_the_feed_changes(tmp_path):
    cache = NvdFeedCache(tmp_path)
    feed = cache.feed_path(2026)
    _write_feed(feed, [_entry(CVE)])
    cache.lookup(_settings(), CVE)

    _write_feed(feed, [_entry("CVE-2026-0002")])
    stat = feed.stat()
    os.utime(feed, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))

    assert cache.lookup(_settings(), "CVE-2026-0002") is not None
    assert cache.lookup(_settings(), CVE) is None


def test_discovery_serves_nvd_from_the_feed_without_the_api(tmp_path, monkeypatch):
    cache_dir = tmp_path / "feed"
    cache = NvdFeedCache(cache_dir)
    _write_feed(cache.feed_path(2026), [_entry(CVE)])
    settings = _settings(cache_dir)

    requested: list[str] = []

    def fail_fetch(url, *args, **kwargs):
        requested.append(url)
        raise AssertionError(f"unexpected fetch {url}")

    monkeypatch.setattr(discovery_mod, "fetch", fail_fetch)
    collector = EvidenceCollector(settings, tmp_path / "run")
    notes: list[str] = []

    entry = discovery_mod._nvd_evidence(collector, settings, CVE, notes)

    assert entry["status"] == "ok"
    assert entry["url"].startswith("https://nvd.nist.gov/feeds/")
    assert requested == []
    assert notes == []
    payload = json.loads((tmp_path / "run" / entry["local_path"]).read_text())
    assert payload["vulnerabilities"][0]["cve"]["id"] == CVE


def test_discovery_falls_back_to_the_api_for_a_cve_not_in_the_snapshot(
    tmp_path, monkeypatch
):
    cache_dir = tmp_path / "feed"
    cache = NvdFeedCache(cache_dir)
    _write_feed(cache.feed_path(2026), [_entry(CVE)])
    settings = _settings(cache_dir)

    requested: list[str] = []

    def fake_fetch(url, *args, **kwargs):
        requested.append(url)
        body = json.dumps({"vulnerabilities": []}).encode("utf-8")
        return FetchResult(
            url=url,
            final_url=url,
            status=200,
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            media_type="application/json",
        )

    # EvidenceCollector.add resolves ``fetch`` in the sources module.
    monkeypatch.setattr(sources_mod, "fetch", fake_fetch)
    collector = EvidenceCollector(settings, tmp_path / "run")
    notes: list[str] = []

    entry = discovery_mod._nvd_evidence(collector, settings, "CVE-2026-999999", notes)

    assert entry["url"] == discovery_mod.NVD_URL.format(cve_id="CVE-2026-999999")
    assert requested == [entry["url"]]
    assert any("not in the cached NVD feed" in note for note in notes)


def test_discovery_falls_back_when_the_feed_is_unreadable(tmp_path, monkeypatch):
    cache_dir = tmp_path / "feed"
    cache = NvdFeedCache(cache_dir)
    cache.feed_path(2026).parent.mkdir(parents=True, exist_ok=True)
    cache.feed_path(2026).write_bytes(b"not gzip")
    settings = _settings(cache_dir)

    def fake_fetch(url, *args, **kwargs):
        body = b'{"vulnerabilities": []}'
        return FetchResult(
            url=url,
            final_url=url,
            status=200,
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            media_type="application/json",
        )

    # EvidenceCollector.add resolves ``fetch`` in the sources module.
    monkeypatch.setattr(sources_mod, "fetch", fake_fetch)
    collector = EvidenceCollector(settings, tmp_path / "run")
    notes: list[str] = []

    entry = discovery_mod._nvd_evidence(collector, settings, CVE, notes)

    assert entry["url"] == discovery_mod.NVD_URL.format(cve_id=CVE)
    assert any("NVD feed cache unavailable" in note for note in notes)
