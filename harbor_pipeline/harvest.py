"""Harvest CVE candidates from the NVD yearly feed and triage their evidence.

The NVD feed is the inventory, not the task. A harvested id still has to pass
the same evidence discovery as any other CVE. This module therefore has two
deliberately separate stages:

* ``harvest`` downloads one yearly feed, extracts web-facing candidate ids,
  and ranks them by the presence of a public fix commit or advisory. It makes
  no model call and produces no task.
* ``triage`` runs evidence discovery only. It records ``eligible`` when a real
  vulnerable/fixed release pair and a fetched upstream fix commit exist, and
  records ``unsupported`` with the discovery notes otherwise.

The output of triage is a candidate list that ``batch --scenario auto`` can
consume directly. Keeping harvest and triage separate means a 80k-CVE feed can
be inspected and re-ranked without spending Docker or model budget.
"""

from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION
from . import discovery as discovery_mod
from .config import SourceSettings
from .errors import TaskError
from .nvd_feed import FEED_URL as NVD_FEED
from .sources import download
from .util import PipelineError, read_json, write_json

_COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.IGNORECASE)
_WEB_RE = re.compile(
    r"\b(remote|remotely|http|https|web|server|service|endpoint|api|request|"
    r"url|route|handler|proxy|gateway|multipart|upload)\b",
    re.IGNORECASE,
)
_NON_SERVER_RE = re.compile(
    r"\b(kernel|android|ios|iphone|browser|chrome|firefox|edge|safari|"
    r"physical|local attacker|local user|client-side|bluetooth|wifi|wi-fi|usb|"
    r"firmware|bios|uefi|denial of service|dos|race condition|clickjacking)\b",
    re.IGNORECASE,
)
_REJECTED_RE = re.compile(r"^\s*\*\*\s*reject|rejected reason", re.IGNORECASE)
_SECRET_PRIMITIVES: dict[str, re.Pattern[str]] = {
    "path_traversal": re.compile(
        r"path traversal|directory traversal|arbitrary file read|"
        r"local file inclusion|\blfi\b|file inclusion",
        re.IGNORECASE,
    ),
    "file_read": re.compile(
        r"file disclosure|file read|read arbitrary files|arbitrary file|"
        r"directory listing|sensitive file|file download",
        re.IGNORECASE,
    ),
    "file_write": re.compile(
        r"arbitrary file write|file write|write arbitrary files?|"
        r"zip slip|zip-slip|path traversal.*write|symlink.*write|"
        r"write files? (?:outside|to an arbitrary)",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(r"server-side request forgery|\bssrf\b", re.IGNORECASE),
    "sql_injection": re.compile(r"sql injection|\bsqli\b", re.IGNORECASE),
    "command_injection": re.compile(
        r"command injection|os command|shell injection|argument injection",
        re.IGNORECASE,
    ),
    "code_execution": re.compile(
        r"remote code execution|\brce\b|arbitrary code execution|code injection",
        re.IGNORECASE,
    ),
    "deserialization": re.compile(
        r"deserializ|pickle|unserialize|unsafe deserialization", re.IGNORECASE
    ),
    "xxe": re.compile(r"xml external entit|\bxxe\b", re.IGNORECASE),
    "template_injection": re.compile(
        r"server-side template injection|\bssti\b|template injection", re.IGNORECASE
    ),
    "auth_bypass": re.compile(
        r"authentication bypass|authorization bypass|auth bypass|"
        r"missing authentication|improper access control|broken access control|"
        r"\bidor\b|insecure direct object",
        re.IGNORECASE,
    ),
    "information_disclosure": re.compile(
        r"information disclosure|sensitive information|expose .*"
        r"(token|credential|secret)|leak .*(token|credential|secret)",
        re.IGNORECASE,
    ),
}
_NON_DISCLOSURE_RE = re.compile(
    r"cross-site scripting|\bxss\b|cross-site request forgery|\bcsrf\b|"
    r"open redirect|denial of service|\bdos\b|clickjacking",
    re.IGNORECASE,
)
_ECOSYSTEM_HOSTS = {
    "pypi.org": "pypi",
    "npmjs.com": "npm",
    "npmjs.org": "npm",
    "repo.maven.apache.org": "maven",
    "search.maven.org": "maven",
    "nuget.org": "nuget",
    "pkg.go.dev": "go",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class HarvestCandidate:
    cve_id: str
    published: str
    description: str
    vendor: str = ""
    product: str = ""
    cpes: tuple[str, ...] = ()
    primitives: tuple[str, ...] = ()
    commit_refs: tuple[str, ...] = ()
    advisory_refs: tuple[str, ...] = ()
    osv_refs: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    ecosystem_hint: str = ""
    priority: int = 40
    prefilter_reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageResult:
    cve_id: str
    status: str
    reason: str
    priority: int = 100
    primitive: str = ""
    package: str | None = None
    ecosystem: str | None = None
    vulnerable_ref: str | None = None
    fixed_ref: str | None = None
    fix_commit: str | None = None
    notes: list[str] = field(default_factory=list)
    cache_hit: bool = False
    elapsed_sec: float = 0.0
    error_category: str | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Harvest
# ---------------------------------------------------------------------------


def harvest(
    *,
    settings: SourceSettings,
    year: int,
    output: Path,
    cache_dir: Path,
    limit: int | None = None,
    include_all: bool = False,
    refresh: bool = False,
) -> dict:
    """Download one NVD yearly feed and write a ranked candidate manifest."""
    if year < 1999 or year > 2100:
        raise PipelineError(f"Unreasonable CVE year: {year}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    feed_path = cache_dir / f"nvdcve-2.0-{year}.json.gz"
    url = NVD_FEED.format(year=year)
    if refresh or not feed_path.is_file():
        source = download(url, settings, feed_path)
    else:
        source = {
            "url": url,
            "path": str(feed_path),
            "sha256": _file_sha256(feed_path),
            "size": feed_path.stat().st_size,
            "fetched_at": None,
            "cached": True,
        }
    try:
        with gzip.open(feed_path, "rt", encoding="utf-8-sig") as handle:
            feed = json.load(handle)
    except (OSError, ValueError) as exc:
        raise PipelineError(f"NVD feed {feed_path} is not readable gzip JSON: {exc}") from exc

    vulnerabilities = feed.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        raise PipelineError("NVD feed has no vulnerabilities array")

    candidates: list[HarvestCandidate] = []
    dropped: Counter[str] = Counter()
    total = 0
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            dropped["malformed entry"] += 1
            continue
        cve = entry.get("cve") or {}
        total += 1
        candidate, reason = _candidate_from_nvd(cve, year, include_all=include_all)
        if candidate is None:
            dropped[reason] += 1
            continue
        candidates.append(candidate)

    candidates.sort(key=lambda c: (c.priority, c.cve_id))
    kept_total = len(candidates)
    if limit is not None and limit >= 0 and len(candidates) > limit:
        dropped[f"excluded by limit {limit}"] += len(candidates) - limit
        candidates = candidates[:limit]

    stats = {
        "feed_total": total,
        "feed_declared_total": feed.get("totalResults", total),
        "matched_year": total - dropped.get("not the requested year", 0),
        "kept": len(candidates),
        "kept_before_limit": kept_total,
        "dropped": dict(sorted(dropped.items())),
        "with_commit": sum(1 for c in candidates if c.commit_refs),
        "with_advisory": sum(1 for c in candidates if c.advisory_refs),
        "with_osv": sum(1 for c in candidates if c.osv_refs),
        "by_priority": dict(sorted(Counter(c.priority for c in candidates).items())),
        "by_primitive": dict(
            sorted(
                Counter(
                    primitive
                    for candidate in candidates
                    for primitive in candidate.primitives
                ).items()
            )
        ),
        "by_ecosystem_hint": dict(
            sorted(Counter(c.ecosystem_hint for c in candidates if c.ecosystem_hint).items())
        ),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "year": year,
        "generated_at": utc_now(),
        "source": source,
        "stats": stats,
        "candidates": [c.to_json() for c in candidates],
    }
    write_json(output, manifest)
    manifest["output"] = str(output)
    return manifest


def _candidate_from_nvd(
    cve: dict, year: int, *, include_all: bool = False
) -> tuple[HarvestCandidate | None, str]:
    cve_id = str(cve.get("id") or "")
    if not cve_id.startswith(f"CVE-{year}-"):
        return None, "not the requested year"
    if str(cve.get("vulnStatus") or "").casefold() == "rejected":
        return None, "rejected CVE"
    description = _description(cve)
    if not description and not include_all:
        return None, "no English description"
    if _REJECTED_RE.search(description):
        return None, "rejected CVE"
    vendor, product, cpes = _components(cve)
    references, commit_refs, advisory_refs, osv_refs = _references(cve)
    primitives = tuple(_classify(description))
    if include_all:
        return HarvestCandidate(
            cve_id=cve_id,
            published=str(cve.get("published") or ""),
            description=description[:4000],
            vendor=vendor,
            product=product,
            cpes=tuple(cpes[:12]),
            primitives=primitives,
            commit_refs=tuple(commit_refs[:8]),
            advisory_refs=tuple(advisory_refs[:8]),
            osv_refs=tuple(osv_refs[:8]),
            references=tuple(references[:40]),
            ecosystem_hint=_ecosystem_hint(references),
            priority=100,
            prefilter_reason="include-all",
        ), ""
    if not product and not any(_cpe_part(cpe) == "a" for cpe in cpes):
        return None, "no application component"
    if not primitives:
        return None, "no supported primitive"
    if _NON_SERVER_RE.search(description) and not (commit_refs or advisory_refs):
        return None, "non-server or local-only"
    if not (_WEB_RE.search(description) or commit_refs or advisory_refs or osv_refs):
        return None, "no web/network evidence"
    ecosystem_hint = _ecosystem_hint(references)
    priority = _priority(commit_refs, advisory_refs, osv_refs, primitives, ecosystem_hint)
    return HarvestCandidate(
        cve_id=cve_id,
        published=str(cve.get("published") or ""),
        description=description[:4000],
        vendor=vendor,
        product=product,
        cpes=tuple(cpes[:12]),
        primitives=primitives,
        commit_refs=tuple(commit_refs[:8]),
        advisory_refs=tuple(advisory_refs[:8]),
        osv_refs=tuple(osv_refs[:8]),
        references=tuple(references[:40]),
        ecosystem_hint=ecosystem_hint,
        priority=priority,
        prefilter_reason="matched web-facing secret-disclosure pattern",
    ), ""


def _description(cve: dict) -> str:
    parts = [
        str(item.get("value") or "").strip()
        for item in cve.get("descriptions") or []
        if isinstance(item, dict) and item.get("lang") == "en"
    ]
    return re.sub(r"\s+", " ", " ".join(part for part in parts if part)).strip()


def _components(cve: dict) -> tuple[str, str, list[str]]:
    vendor = product = ""
    cpes: list[str] = []
    for affected in cve.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for item in affected.get("affectedData") or []:
            if not isinstance(item, dict):
                continue
            vendor = vendor or str(item.get("vendor") or "")
            product = product or str(item.get("product") or "")
            cpes.extend(str(cpe) for cpe in item.get("cpes") or [] if isinstance(cpe, str))
    for configuration in cve.get("configurations") or []:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("criteria"):
                    cpes.append(str(match["criteria"]))
    for cpe in cpes:
        _, cpe_vendor, cpe_product = _cpe_parts(cpe)
        if not vendor and cpe_vendor and cpe_vendor not in {"*", "-"}:
            vendor = cpe_vendor
        if not product and cpe_product and cpe_product not in {"*", "-"}:
            product = cpe_product
    return vendor, product, list(dict.fromkeys(cpes))


def _cpe_parts(cpe: str) -> tuple[str, str, str]:
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[2], parts[3], parts[4]
    return "", "", ""


def _cpe_part(cpe: str) -> str:
    return _cpe_parts(cpe)[0]


def _references(cve: dict) -> tuple[list[str], list[str], list[str], list[str]]:
    references: list[str] = []
    commits: list[str] = []
    advisories: list[str] = []
    osv: list[str] = []
    for item in cve.get("references") or []:
        url = str(item.get("url") or "") if isinstance(item, dict) else str(item or "")
        if not url:
            continue
        if url not in references:
            references.append(url)
        if _COMMIT_RE.search(url):
            commits.append(url)
        lowered = url.casefold()
        if "ghsa-" in lowered or "/security/advisories/" in lowered:
            advisories.append(url)
        if "osv.dev" in lowered:
            osv.append(url)
    return references, commits, advisories, osv


def _classify(description: str) -> list[str]:
    found = [
        name for name, pattern in _SECRET_PRIMITIVES.items()
        if pattern.search(description)
    ]
    if not found and _NON_DISCLOSURE_RE.search(description):
        return []
    return found


def _ecosystem_hint(references: Iterable[str]) -> str:
    for url in references:
        lowered = url.casefold()
        for host, ecosystem in _ECOSYSTEM_HOSTS.items():
            if host in lowered:
                return ecosystem
    return ""


def _priority(
    commits: list[str],
    advisories: list[str],
    osv: list[str],
    primitives: tuple[str, ...],
    ecosystem_hint: str,
) -> int:
    """Lower is processed first; this is a yield heuristic, not a support gate."""
    score = 40
    if commits:
        score -= 12
    if advisories or osv:
        score -= 10
    if ecosystem_hint in {"pypi", "npm"}:
        score -= 4
    if "path_traversal" in primitives or "file_read" in primitives:
        score -= 2
    return max(1, score)


def _file_sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


def load_manifest(path: Path) -> list[dict[str, Any]]:
    data = read_json(Path(path))
    entries = data.get("candidates", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise PipelineError("Candidate manifest must contain a candidates array")
    candidates: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, str):
            value: dict[str, Any] = {"cve_id": entry}
        elif isinstance(entry, dict):
            value = dict(entry)
        else:
            continue
        cve_id = str(value.get("cve_id") or "").strip().upper()
        if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", cve_id):
            continue
        value["cve_id"] = cve_id
        value["priority"] = int(value.get("priority", 40))
        candidates.append(value)
    candidates.sort(key=lambda item: (item["priority"], item["cve_id"]))
    return candidates


def triage(
    *,
    settings: SourceSettings,
    candidates: list[dict[str, Any]],
    output: Path,
    cache_dir: Path,
    workers: int = 4,
    limit: int | None = None,
    no_cache: bool = False,
) -> dict:
    """Run discovery-only evidence checks and write the eligible subset."""
    selected = candidates[:limit] if limit is not None else list(candidates)
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: list[TriageResult] = []
    started = datetime.now(timezone.utc)

    def work(candidate: dict[str, Any]) -> TriageResult:
        return _triage_one(
            settings, candidate, cache_dir=cache_dir, no_cache=no_cache
        )

    if selected:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(selected)))) as pool:
            futures = {pool.submit(work, candidate): candidate for candidate in selected}
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - triage must classify every input
                    result = TriageResult(
                        cve_id=candidate["cve_id"],
                        status="error",
                        reason=f"{type(exc).__name__}: {exc}",
                        priority=int(candidate.get("priority", 40)),
                        error_category="infra_error",
                    )
                results.append(result)
    results.sort(key=lambda item: (item.status != "eligible", item.priority, item.cve_id))

    eligible = [r for r in results if r.status == "eligible"]
    unsupported = [r for r in results if r.status == "unsupported"]
    errors = [r for r in results if r.status == "error"]
    stats = {
        "inputs": len(selected),
        "eligible": len(eligible),
        "unsupported": len(unsupported),
        "errors": len(errors),
        "yield_rate": round(len(eligible) / len(selected), 4) if selected else 0.0,
        "cache_hits": sum(1 for r in results if r.cache_hit),
        "by_status": dict(sorted(Counter(r.status for r in results).items())),
        "by_ecosystem": dict(
            sorted(Counter(r.ecosystem or "unknown" for r in eligible).items())
        ),
        "by_primitive": dict(
            sorted(Counter(r.primitive or "unknown" for r in eligible).items())
        ),
        "elapsed_sec": round(
            (datetime.now(timezone.utc) - started).total_seconds(), 2
        ),
    }
    by_id = {str(c.get("cve_id")): c for c in candidates}
    candidate_entries = []
    for result in eligible:
        base = dict(by_id.get(result.cve_id, {}))
        base.update({
            "cve_id": result.cve_id,
            "priority": result.priority,
            "primitive": result.primitive,
            "package": result.package,
            "ecosystem": result.ecosystem,
            "vulnerable_ref": result.vulnerable_ref,
            "fixed_ref": result.fixed_ref,
            "fix_commit": result.fix_commit,
            "triage_status": "eligible",
        })
        candidate_entries.append(base)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "stats": stats,
        "candidates": candidate_entries,
        "unsupported": [r.to_json() for r in unsupported],
        "errors": [r.to_json() for r in errors],
    }
    write_json(output, report)
    report["output"] = str(output)
    return report


def _triage_one(
    settings: SourceSettings,
    candidate: dict[str, Any],
    *,
    cache_dir: Path,
    no_cache: bool,
) -> TriageResult:
    cve_id = str(candidate["cve_id"])
    priority = int(candidate.get("priority", 40))
    primitive = str(
        candidate.get("primitive")
        or (candidate.get("primitives") or [""])[0]
        or ""
    )
    run_dir = cache_dir / cve_id
    started = datetime.now(timezone.utc)
    discovery = None
    cache_hit = False
    if not no_cache:
        try:
            discovery = discovery_mod.load(run_dir, cve_id)
            cache_hit = True
        except (OSError, ValueError, PipelineError):
            discovery = None
    if discovery is None:
        try:
            _, discovery = discovery_mod.collect(settings, run_dir, cve_id)
        except TaskError as exc:
            return TriageResult(
                cve_id=cve_id,
                status="error" if exc.category.code != "unsupported" else "unsupported",
                reason=str(exc),
                priority=priority,
                primitive=primitive,
                error_category=exc.category.code,
                elapsed_sec=round(
                    (datetime.now(timezone.utc) - started).total_seconds(), 2
                ),
            )
        except Exception as exc:  # noqa: BLE001 - classify every candidate
            return TriageResult(
                cve_id=cve_id,
                status="error",
                reason=f"{type(exc).__name__}: {exc}",
                priority=priority,
                primitive=primitive,
                error_category="infra_error",
                elapsed_sec=round(
                    (datetime.now(timezone.utc) - started).total_seconds(), 2
                ),
            )
    notes = list(discovery.notes)
    if not discovery.has_fix_pair:
        reason = "; ".join(notes) or "no vulnerable/fixed release pair and fix commit"
        return TriageResult(
            cve_id=cve_id,
            status="unsupported",
            reason=reason,
            priority=priority,
            primitive=primitive,
            package=discovery.package,
            ecosystem=discovery.ecosystem,
            vulnerable_ref=discovery.vulnerable_ref,
            fixed_ref=discovery.fixed_ref,
            fix_commit=discovery.fix_commit,
            notes=notes,
            cache_hit=cache_hit,
            elapsed_sec=round(
                (datetime.now(timezone.utc) - started).total_seconds(), 2
            ),
        )
    if not discovery.package:
        return TriageResult(
            cve_id=cve_id,
            status="unsupported",
            reason="no package identity could be derived from public records",
            priority=priority,
            primitive=primitive,
            vulnerable_ref=discovery.vulnerable_ref,
            fixed_ref=discovery.fixed_ref,
            fix_commit=discovery.fix_commit,
            notes=notes,
            cache_hit=cache_hit,
            elapsed_sec=round(
                (datetime.now(timezone.utc) - started).total_seconds(), 2
            ),
        )
    return TriageResult(
        cve_id=cve_id,
        status="eligible",
        reason="real release pair and fetched upstream fix commit",
        priority=priority - 5 if discovery.ecosystem in {"pypi", "npm"} else priority,
        primitive=primitive,
        package=discovery.package,
        ecosystem=discovery.ecosystem or "generic",
        vulnerable_ref=discovery.vulnerable_ref,
        fixed_ref=discovery.fixed_ref,
        fix_commit=discovery.fix_commit,
        notes=notes,
        cache_hit=cache_hit,
        elapsed_sec=round(
            (datetime.now(timezone.utc) - started).total_seconds(), 2
        ),
    )


__all__ = [
    "HarvestCandidate",
    "TriageResult",
    "NVD_FEED",
    "harvest",
    "triage",
    "load_manifest",
]
