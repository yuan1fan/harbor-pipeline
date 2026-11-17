"""Compare deterministic discovery against historical evidence, without agents/Docker.

Only the new ref-verification requests may use the network. All original source
requests replay the same saved bodies/errors for both implementations. The
metadata cache makes the resulting experiment repeatable offline.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import shutil
import sys
import time
import urllib.parse
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harbor_pipeline import discovery, discovery_refs, evidence_resolver, sources  # noqa: E402
from harbor_pipeline.config import Config, Settings, load_config  # noqa: E402
from harbor_pipeline.errors import TaskError  # noqa: E402
from harbor_pipeline.pipeline import CvePipeline  # noqa: E402
from harbor_pipeline.util import read_json, write_json  # noqa: E402

TARGETS = ("2419", "40501", "5328", "8113", "22661", "28428")
CONTROLS = ("10130", "11470", "2531", "32749", "79785")
FIELDS = ("package", "ecosystem", "vulnerable_ref", "fixed_ref", "fix_commit", "fix_source_id")


def facts(parsed):
    result = {key: getattr(parsed, key) for key in FIELDS}
    if hasattr(parsed, "vulnerable"):
        result.update({"vulnerable": parsed.vulnerable.to_json() if parsed.vulnerable else None,
                       "fixed": parsed.fixed.to_json() if parsed.fixed else None})
    return result


def complete(parsed):
    if hasattr(parsed, "is_complete"):
        return parsed.is_complete
    return bool(all(getattr(parsed, key) for key in FIELDS[2:])
                and parsed.vulnerable_ref != parsed.fixed_ref)


def snapshot(root):
    paths = [root / name for name in ("state.json", "discovery.json", "evidence-index.json")]
    paths.extend((root / "evidence").glob("*"))
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths if p.is_file()}


class Transport:
    def __init__(self, original, metadata_dir, allow_network):
        self.original = original
        self.index = read_json(original / "evidence-index.json")
        self.entries = {s["url"]: s for s in self.index["sources"]}
        for source in self.index["sources"]:
            if "NVD CVE 2.0 record" in source.get("citation", ""):
                self.entries[discovery.NVD_URL.format(cve_id=self.index["cve_id"])] = source
        self.metadata_dir = metadata_dir
        self.allow_network = allow_network
        self.ref_request = False
        self.network_fetch = sources.fetch
        self.events = []

    def fetch(self, url, settings):
        entry = self.entries.get(url)
        if self.ref_request:
            # Historical API responses can be patch text, even at a JSON URL.
            # Reuse valid commit JSON; otherwise obtain the required metadata.
            if entry and entry["status"] == "ok":
                try:
                    saved = read_json(self.original / entry["local_path"])
                    if isinstance(saved, (dict, list)) and saved:
                        return self.saved(url, entry)
                except (ValueError, OSError):
                    pass
            return self.metadata(url, settings)
        if entry:
            return self.saved(url, entry)
        # Some original registry probes failed without recording a source.
        raise TaskError("source_error", f"No historical source recorded for {url}")

    def saved(self, url, entry):
        if entry["status"] != "ok":
            raise TaskError("source_error", entry.get("error") or "historical fetch failure")
        body = (self.original / entry["local_path"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["content_sha256"]
        return sources.FetchResult(
            url=url, final_url=url, status=200, body=body,
            sha256=entry["content_sha256"], media_type=entry.get("media_type", "text/plain"),
            fetched_at=entry["fetched_at"],
        )

    def metadata(self, url, settings):
        parsed = urllib.parse.urlsplit(url)
        if parsed.hostname not in {"api.github.com", "pypi.org", "registry.npmjs.org", "proxy.golang.org", "repo1.maven.org", "api.wordpress.org", "downloads.wordpress.org"}:
            raise TaskError("source_error", "Replay permits only discovery metadata/registry requests")
        key = hashlib.sha256(url.encode()).hexdigest()
        path = self.metadata_dir / f"{key}.json"
        if path.exists():
            cached = read_json(path)
            self.events.append({"url": url, "mode": "metadata_cache", "error": cached.get("error")})
        else:
            if not self.allow_network:
                raise TaskError("source_error", f"Offline metadata cache miss: {url}")
            started = time.monotonic()
            try:
                result = self.network_fetch(url, settings)
                cached = {"url": url, "body_base64": base64.b64encode(result.body).decode(),
                          "sha256": result.sha256, "media_type": result.media_type,
                          "fetched_at": result.fetched_at}
            except TaskError as exc:
                cached = {"url": url, "error": str(exc)}
            self.metadata_dir.mkdir(parents=True, exist_ok=True)
            write_json(path, cached)
            self.events.append({"url": url, "mode": "network", "error": cached.get("error"),
                                "elapsed_sec": round(time.monotonic() - started, 3)})
        if cached.get("error"):
            raise TaskError("source_error", cached["error"])
        body = base64.b64decode(cached["body_base64"]) if "body_base64" in cached else cached["body"].encode("utf-8")
        assert hashlib.sha256(body).hexdigest() == cached["sha256"]
        return sources.FetchResult(url=url, final_url=url, status=200, body=body,
                                   sha256=cached["sha256"], media_type=cached["media_type"],
                                   fetched_at=cached["fetched_at"])


def replay(args):
    spec = importlib.util.spec_from_file_location("harbor_pipeline._discovery_before", args.baseline)
    before = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = before
    spec.loader.exec_module(before)
    settings = replace(load_config(args.config).sources, nvd_feed_cache=None, timeout_sec=15)
    results = []
    metadata_dir = args.metadata_cache or args.output / "metadata-cache"
    get_metadata = discovery_refs._Metadata.source
    suffixes = args.cves if args.cves else (*TARGETS, *CONTROLS, *args.extra_cves)
    for suffix in dict.fromkeys(suffixes):
        cve_id = "CVE-2026-" + suffix
        original = args.batch / cve_id
        hashes = snapshot(original)
        transport = Transport(original, metadata_dir, args.allow_network)

        def metadata(self, url, *a, **kw):
            transport.ref_request = True
            try:
                return get_metadata(self, url, *a, **kw)
            finally:
                transport.ref_request = False

        resolver_calls = []

        def resolve(self, **kwargs):
            resolver_calls.append(facts(kwargs["discovery"]))
            return evidence_resolver.ResolverOutcome(status="no_proposal")

        with (patch.object(sources, "fetch", transport.fetch),
              patch.object(before, "fetch", transport.fetch),
              patch.object(discovery, "fetch", transport.fetch),
              patch.object(discovery_refs._Metadata, "source", metadata),
              patch.object(evidence_resolver.EvidenceResolver, "resolve", resolve)):
            _, baseline = before.collect(settings, args.output / "before" / cve_id, cve_id)
            _, after = discovery.collect(settings, args.output / "after" / cve_id, cve_id)
            fresh_events = list(transport.events)
            config = Config(pipeline=Settings(output_dir=str(args.output / "cached"), evidence_resolver=True),
                            sources=settings)
            pipeline = CvePipeline(config=config, cve_id=cve_id, run_id="replay", scenario="auto")
            pipeline.store.root.mkdir(parents=True, exist_ok=True)
            for name in ("discovery.json", "evidence-index.json"):
                shutil.copy2(original / name, pipeline.store.root / name)
            shutil.copytree(original / "evidence", pipeline.store.root / "evidence", dirs_exist_ok=True)
            error = None
            try:
                pipeline._collect_auto(pipeline.store.create())
            except TaskError as exc:
                error = {"category": exc.category.code, "message": str(exc)}
            first_cached_calls = len(resolver_calls)
            previous_requests = len(transport.events)
            try:
                pipeline._collect_auto(pipeline.store.load())
            except TaskError:
                pass
            typed_cache_requests = len(transport.events) - previous_requests
        unchanged = hashes == snapshot(original)
        row = {
            "cve_id": cve_id, "group": "target" if suffix in TARGETS else "control" if suffix in CONTROLS else "holdout",
            "before": facts(baseline), "after": facts(after),
            "before_fields_complete": complete(baseline), "after_fields_complete": complete(after),
            "after_notes": list(after.notes), "cached_path": facts(pipeline.discovery),
            "cached_resolver_calls": first_cached_calls, "cached_error": error,
            "typed_cache_requests": typed_cache_requests,
            "metadata_requests_fresh": fresh_events, "all_metadata_requests": transport.events,
            "original_unchanged": unchanged, "original_hashes": hashes,
        }
        assert unchanged, f"Original evidence changed: {cve_id}"
        results.append(row)
        write_json(args.output / "results.json", {"results": results})
        print(f"{cve_id}: {baseline.vulnerable_ref} -> {after.vulnerable_ref}; "
              f"complete={complete(baseline)}->{complete(after)}; cached_CC={first_cached_calls}", flush=True)
    summary = {
        "method": "Same historical evidence/errors; only new ref metadata may be fetched. No LLM, author, Docker, or validation stages.",
        "baseline_sha256": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        "target_count": len(TARGETS),
        "case_count": len(results),
        "typed_pair_count": sum(bool(r["after"].get("vulnerable") and r["after"].get("fixed")
                                     and r["after"]["vulnerable"]["kind"] != "unresolved"
                                     and r["after"]["fixed"]["kind"] != "unresolved") for r in results),
        "ready_count": sum(r["after_fields_complete"] for r in results),
        "still_incomplete": [r["cve_id"] for r in results if not r["after_fields_complete"]],
        "targets_complete_before": sum(r["before_fields_complete"] for r in results if r["group"] == "target"),
        "targets_complete_after": sum(r["after_fields_complete"] for r in results if r["group"] == "target"),
        "originals_unchanged": all(r["original_unchanged"] for r in results),
        "network_requests": sum(e["mode"] == "network" for r in results for e in r["all_metadata_requests"]),
        "limitation": "Discovery candidates only. Complete fields do not establish package mapping, mechanism correctness, or releasability, especially in controls.",
    }
    write_json(args.output / "results.json", {"summary": summary, "results": results})
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-cache", type=Path)
    parser.add_argument("--config", type=Path, help="optional source settings; models are not used")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--extra-cves", nargs="*", default=[], help="extra numeric CVE-2026 suffixes for holdout regression")
    parser.add_argument("--cves", nargs="+", help="explicit numeric CVE-2026 suffixes instead of the default comparison cohort")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output must be a new directory (historical runs are never overwritten)")
    if any(not suffix.isdigit() for suffix in [*args.extra_cves, *(args.cves or [])]):
        parser.error("CVE selections accept numeric CVE-2026 suffixes only")
    replay(args)
