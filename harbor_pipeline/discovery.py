"""Automatic evidence discovery for an arbitrary CVE id.

The curated pool in :mod:`harbor_pipeline.cves` is a seed, not a gate. This
module collects public records, identity/version hints and upstream patches.
The shared selector in :mod:`harbor_pipeline.discovery_refs` owns candidate
ordering, typed-ref validation and the persisted selection trace.

Evidence completeness is not a verdict that the CVE's mechanism reproduces.
Unverified refs remain unresolved for the calling pipeline to handle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import SourceSettings
from .discovery_refs import _ref_version, complete_missing_refs
from .errors import TaskError
from .nvd_feed import NvdFeedCache
from .sources import EvidenceCollector, FetchResult, cve_record_url, fetch as fetch
from .util import PipelineError, read_json, write_json

OSV_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories?cve_id={cve_id}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

_ECOSYSTEMS = {
    "pip": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "go",
    "nuget": "nuget",
    "rubygems": "generic",
    "rust": "generic",
    "composer": "generic",
    "actions": "generic",
    "docker": "docker",
    "debian": "apt",
    "ubuntu": "apt",
    "alpine": "apt",
}

# Package registries named in CVE references. OSV's Git-only records omit the
# package ecosystem, so the reference set is the deterministic signal that lets
# discovery fetch real release metadata and pin an artifact.
_ECOSYSTEM_HOSTS: tuple[tuple[str, str], ...] = (
    ("registry.npmjs.org", "npm"),
    ("npmjs.com", "npm"),
    ("pypi.org", "pypi"),
    ("repo1.maven.org", "maven"),
    ("mvnrepository.com", "maven"),
    ("nuget.org", "nuget"),
    ("proxy.golang.org", "go"),
    ("pkg.go.dev", "go"),
)

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_RELEASE_PREFIX_RE = re.compile(r"^[vV](?=\d)")
_COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})")
_PYPI_VERSION_RE = re.compile(r"/pypi/([^/]+)/([^/]+)/json")
_NPM_VERSION_RE = re.compile(r"registry\.npmjs\.org/(.+)/([^/]+)$")
_GO_CHECKSUM_RE = re.compile(
    r"sum\.golang\.org/lookup/(?P<module>.+)@v(?P<version>[^/]+)$"
)
_MAVEN_CHECKSUM_RE = re.compile(
    r"repo1\.maven\.org/maven2/(?P<group>.+)/(?P<artifact>[^/]+)/"
    r"(?P<version>[^/]+)/(?P=artifact)-(?P=version)\.jar\.sha256$"
)


@dataclass(frozen=True)
class DiscoveryRef:
    """A ref's namespace is explicit; a numeric string is never assumed to be a tag."""

    kind: str
    value: str
    ecosystem: str | None = None
    package: str | None = None
    repository: str | None = None
    resolved_commit: str | None = None
    url: str | None = None
    sha256: str | None = None
    source_id: str | None = None

    def __post_init__(self):
        if self.kind not in {"package_version", "tag", "commit", "archive", "unresolved"}:
            raise PipelineError(f"unknown discovery ref kind: {self.kind!r}")
        if not isinstance(self.value, str) or not self.value.strip():
            raise PipelineError("discovery ref value must be a nonempty string")
        if self.kind == "commit" and not _SHA_RE.fullmatch(self.value):
            raise PipelineError("commit ref must be a Git SHA, not a release version")
        if self.resolved_commit and not re.fullmatch(r"[0-9a-f]{40}", self.resolved_commit):
            raise PipelineError("resolved_commit must be a full Git SHA")
        if self.kind == "archive" and (not self.url or not re.fullmatch(r"[0-9a-f]{64}", self.sha256 or "")):
            raise PipelineError("archive ref requires its URL and SHA-256")

    def to_json(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_json(cls, data: dict) -> "DiscoveryRef":
        if not isinstance(data, dict):
            raise PipelineError("discovery ref must be an object with kind/value")
        try:
            return cls(**data)
        except TypeError as exc:
            raise PipelineError(f"invalid discovery ref: {exc}") from exc


_UNSET = object()


def _legacy_ref(value, ecosystem, package) -> DiscoveryRef | None:
    if not value:
        return None
    value = str(value)
    if re.fullmatch(r"[0-9a-f]{40}", value):
        return DiscoveryRef("commit", value)
    if ecosystem in {"pypi", "npm", "go", "maven", "nuget", "apt", "docker"}:
        return DiscoveryRef("package_version", value, ecosystem=ecosystem, package=package)
    return DiscoveryRef("unresolved", value)


@dataclass(frozen=True, init=False)
class Discovery:
    """Deterministic facts derived from the collected evidence."""

    cve_id: str
    package: str | None = None
    ecosystem: str | None = None
    component: str | None = None
    vulnerable: DiscoveryRef | None = None
    fixed: DiscoveryRef | None = None
    fix_commit: str | None = None
    fix_source_id: str | None = None
    aliases: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    affected_range: str | None = None
    selection_trace: tuple[dict, ...] = ()

    def __init__(
        self, cve_id, package=None, ecosystem=None, component=None,
        vulnerable=None, fixed=None, fix_commit=None, fix_source_id=None,
        aliases=(), references=(), notes=(), affected_range=None, selection_trace=(), *,
        vulnerable_ref=_UNSET, fixed_ref=_UNSET,
    ):
        # Constructor aliases keep older callers/checkpoints readable. New
        # JSON has a single canonical representation, never duplicate refs.
        if vulnerable_ref is not _UNSET:
            vulnerable = _legacy_ref(vulnerable_ref, ecosystem, package)
        if fixed_ref is not _UNSET:
            fixed = _legacy_ref(fixed_ref, ecosystem, package)
        if isinstance(vulnerable, dict):
            vulnerable = DiscoveryRef.from_json(vulnerable)
        if isinstance(fixed, dict):
            fixed = DiscoveryRef.from_json(fixed)
        values = locals()
        for field in self.__dataclass_fields__:
            object.__setattr__(self, field, values[field])

    @property
    def vulnerable_ref(self) -> str | None:
        return self.vulnerable.value if self.vulnerable else None

    @property
    def fixed_ref(self) -> str | None:
        return self.fixed.value if self.fixed else None

    @property
    def build_ecosystem(self) -> str | None:
        if any(ref and ref.kind in {"tag", "commit", "archive"} for ref in (self.vulnerable, self.fixed)):
            return "generic"
        return self.ecosystem

    @property
    def build_package(self) -> str | None:
        if self.build_ecosystem == "generic":
            for ref in (self.fixed, self.vulnerable):
                if ref and ref.repository:
                    return ref.repository
        return self.package

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["vulnerable"] = self.vulnerable.to_json() if self.vulnerable else None
        data["fixed"] = self.fixed.to_json() if self.fixed else None
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Discovery":
        refs = {}
        for key in ("vulnerable", "fixed"):
            if key in data:
                refs[key] = DiscoveryRef.from_json(data[key]) if data[key] is not None else None
                legacy = data.get(key + "_ref")
                if legacy is not None and (not refs[key] or refs[key].value != legacy):
                    raise PipelineError(f"conflicting typed and legacy {key} refs")
            else:
                refs[key + "_ref"] = data.get(key + "_ref")
        return cls(
            cve_id=data["cve_id"],
            package=data.get("package"),
            ecosystem=data.get("ecosystem"),
            component=data.get("component"),
            **refs,
            fix_commit=data.get("fix_commit"),
            fix_source_id=data.get("fix_source_id"),
            aliases=tuple(data.get("aliases") or ()),
            references=tuple(data.get("references") or ()),
            notes=tuple(data.get("notes") or ()),
            affected_range=data.get("affected_range"),
            selection_trace=tuple(data.get("selection_trace") or ()),
        )

    @property
    def has_fix_pair(self) -> bool:
        return bool(self.vulnerable_ref and self.fixed_ref and self.fix_commit)

    @property
    def is_complete(self) -> bool:
        return bool(self.has_fix_pair and self.fix_source_id
                    and self.vulnerable_ref != self.fixed_ref
                    and self.vulnerable.kind != "unresolved"
                    and self.fixed.kind != "unresolved"
                    and not (self.vulnerable.resolved_commit
                             and self.vulnerable.resolved_commit == self.fixed.resolved_commit))


def collect(settings: SourceSettings, run_dir: Path, cve_id: str) -> tuple[dict, Discovery]:
    """Fetch, parse, and persist evidence for any CVE id.

    The first pass reads the official CVE record plus OSV, the GitHub Advisory
    Database, and NVD. The second pass follows the fix-commit references those
    records expose and fetches the patch itself, which is what later grounds
    the root-cause assertions.
    """
    run_dir = Path(run_dir)
    collector = EvidenceCollector(settings, run_dir)
    cve_source = collector.add(
        cve_record_url(cve_id), "cve_record", "Official CVE JSON 5.0 record"
    )
    if cve_source["status"] != "ok":
        message = f"Cannot fetch the official CVE record for {cve_id}: {cve_source['error']}"
        # A 404 on the authoritative record means the id has no public record;
        # retrying cannot help, so record it as a quantified negative result.
        category = "unsupported" if "HTTP 404" in str(cve_source.get("error")) else "source_error"
        raise TaskError(category, message, detail={"source_id": cve_source["id"]})

    osv_source = collector.add(
        OSV_URL.format(cve_id=cve_id), "other", "OSV vulnerability record"
    )
    advisory_source = collector.add(
        GITHUB_ADVISORY_URL.format(cve_id=cve_id),
        "vendor_advisory",
        "GitHub Advisory Database entry",
    )
    notes: list[str] = []
    nvd_source = _nvd_evidence(collector, settings, cve_id, notes)

    cve_record = _source_json(cve_source, run_dir, notes, "official CVE record")
    osv_record = _source_json(osv_source, run_dir, notes, "OSV record")
    advisories = _source_json(advisory_source, run_dir, notes, "GitHub advisories")
    nvd_record = _source_json(nvd_source, run_dir, notes, "NVD record")

    aliases = _aliases(cve_record, osv_record, advisories)
    references = _references(cve_record, osv_record, advisories, nvd_record)

    package, ecosystem, component, fixed_ref, vulnerable_range = _package_facts(
        osv_record, advisories, cve_record
    )
    if not ecosystem:
        # Git-only OSV records carry no package ecosystem. The registries cited
        # by the CVE record do, and that is what lets discovery fetch the real
        # release metadata instead of leaving the candidate generic.
        ecosystem = _infer_ecosystem(references)
        if ecosystem:
            notes.append(f"ecosystem inferred from references: {ecosystem}")

    # This layer collects hints only. The typed-ref selector owns version
    # ordering, registry lookup, range checks and final pair validation.
    fix_commit, fix_source_id = _fetch_fix_commit(collector, references, notes)

    evidence = collector.save(cve_id)
    discovery = Discovery(
        cve_id=cve_id,
        package=package,
        ecosystem=ecosystem,
        component=component,
        fixed_ref=fixed_ref or fix_commit,
        affected_range=vulnerable_range,
        fix_commit=fix_commit,
        fix_source_id=fix_source_id,
        aliases=tuple(aliases),
        references=tuple(references),
        notes=tuple(notes),
    )
    evidence, discovery = complete_missing_refs(settings, run_dir, evidence, discovery)
    write_json(run_dir / "discovery.json", discovery.to_json())
    return evidence, discovery


def _nvd_evidence(
    collector: EvidenceCollector,
    settings: SourceSettings,
    cve_id: str,
    notes: list[str],
) -> dict[str, Any]:
    """Serve the NVD record from the local yearly feed, else from the API.

    An anonymous triage of 13,687 candidates spends about 22.8 hours waiting on
    the NVD rate limit and turns every 429 into a ``source_error`` that
    pollutes the yield statistics. The yearly feed holds the same records, so
    it is consulted first when a cache directory is configured.

    A cache miss is not a verdict: a CVE published after the snapshot, an
    unindexable feed, or a missing file all fall through to the API, and the
    reason is recorded in the discovery notes.
    """
    cache_dir = getattr(settings, "nvd_feed_cache", None)
    if cache_dir:
        try:
            cache = NvdFeedCache(
                Path(cache_dir),
                max_age_sec=int(
                    getattr(settings, "nvd_feed_max_age_sec", 7 * 24 * 3600)
                ),
            )
            found = cache.lookup(settings, cve_id)
        except (TaskError, PipelineError, OSError, ValueError) as exc:
            notes.append(f"NVD feed cache unavailable: {exc}")
            found = None
        if found is not None:
            document, provenance = found
            # The evidence index cites the feed and its digest rather than
            # pretending the record was fetched per-CVE from the API.
            body = json.dumps(
                document, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")
            result = FetchResult(
                url=provenance.feed_url,
                final_url=provenance.feed_url,
                status=200,
                body=body,
                sha256=hashlib.sha256(body).hexdigest(),
                media_type="application/json",
            )
            return collector.record(
                provenance.feed_url, "other", provenance.citation(), result
            )
        notes.append(f"{cve_id} is not in the cached NVD feed snapshot")
    return collector.add(
        NVD_URL.format(cve_id=cve_id), "other", "NVD CVE 2.0 record"
    )


def load(run_dir: Path, cve_id: str) -> Discovery:
    data = read_json(Path(run_dir) / "discovery.json")
    discovery = Discovery.from_json(data)
    if discovery.cve_id != cve_id:
        raise PipelineError(
            f"discovery.json refers to {discovery.cve_id}, not {cve_id}"
        )
    return discovery


def checkpoint_evidence_usable(evidence: dict, run_dir: Path) -> bool:
    """A cached success entry must still have its nonempty local evidence body."""
    return all(
        any(s.get("source_type") == kind and s.get("status") == "ok"
            and _local_text(s, run_dir).strip()
            for s in evidence.get("sources") or [])
        for kind in ("cve_record", "upstream_commit")
    )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _source_json(source: dict, run_dir: Path, notes: list[str], label: str) -> Any:
    if source["status"] != "ok":
        notes.append(f"{label} unavailable: {source.get('error')}")
        return None
    path = Path(run_dir) / source["local_path"]
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        notes.append(f"{label} is not valid JSON: {exc}")
        return None


def _aliases(cve_record: Any, osv_record: Any, advisories: Any) -> list[str]:
    values: set[str] = set()
    if isinstance(osv_record, dict):
        for alias in osv_record.get("aliases") or []:
            if isinstance(alias, str):
                values.add(alias)
    if isinstance(advisories, list):
        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            for identifier in advisory.get("identifiers") or []:
                value = identifier.get("value") if isinstance(identifier, dict) else None
                if isinstance(value, str):
                    values.add(value)
    return sorted(values)


def _references(*records: Any) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for record in records:
        urls: list[str] = []
        if isinstance(record, list):
            for advisory in record:
                if isinstance(advisory, dict):
                    urls.extend(str(u) for u in advisory.get("references") or [])
        elif isinstance(record, dict):
            for ref in record.get("references") or []:
                if isinstance(ref, dict) and ref.get("url"):
                    urls.append(str(ref["url"]))
                elif isinstance(ref, str):
                    urls.append(ref)
            cna = (
                record.get("containers", {}).get("cna", {})
                if isinstance(record.get("containers"), dict)
                else {}
            )
            for ref in cna.get("references") or []:
                if isinstance(ref, dict) and ref.get("url"):
                    urls.append(str(ref["url"]))
            for vuln in record.get("vulnerabilities") or []:
                for ref in (vuln.get("cve") or {}).get("references") or []:
                    if isinstance(ref, dict) and ref.get("url"):
                        urls.append(str(ref["url"]))
        for url in urls:
            if url not in seen:
                seen.add(url)
                values.append(url)
    return values


def _infer_ecosystem(references: list[str]) -> str | None:
    """Map a registry URL cited by the CVE record to a package ecosystem.

    Only an exact host or a subdomain counts; a lookalike host must not decide
    how the build pins a dependency.
    """
    for url in references:
        host = (urllib.parse.urlsplit(url).hostname or "").casefold()
        for suffix, ecosystem in _ECOSYSTEM_HOSTS:
            if host == suffix or host.endswith("." + suffix):
                return ecosystem
    return None


def _normalize_release(value: str | None) -> str | None:
    """Drop a leading release-tag ``v`` from a package version."""
    if not value:
        return value
    text = str(value).strip()
    return text[1:] if _RELEASE_PREFIX_RE.match(text) else text


def _normalize_go_version(value: str) -> str:
    """Strip the ``v`` tag prefix and the ``+incompatible`` module suffix.

    Modules older than ``go.mod`` major-version paths are fetched as
    ``v20.10.13+incompatible`` but the advisory and the spec name ``20.10.13``.
    Keeping both sides normalized is what lets the build lock compare equal.
    """
    text = value.strip()
    if text.startswith("v"):
        text = text[1:]
    return text.removesuffix("+incompatible")


def _package_facts(
    osv_record: Any, advisories: Any, cve_record: Any
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Return (package, ecosystem, component, fixed version, affected range)."""
    package = ecosystem = component = fixed = affected_range = None
    if isinstance(advisories, list):
        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            for vuln in advisory.get("vulnerabilities") or []:
                pkg = vuln.get("package") or {}
                name = pkg.get("name")
                if not name:
                    continue
                package = str(name)
                ecosystem = _ECOSYSTEMS.get(str(pkg.get("ecosystem", "")).lower())
                affected_range = vuln.get("vulnerable_version_range")
                # GitHub's REST API returns a plain string here, while its
                # GraphQL shape nests an identifier object.
                patched = vuln.get("first_patched_version") or ""
                if isinstance(patched, dict):
                    patched = patched.get("identifier") or ""
                if patched:
                    fixed = str(patched)
                break
            if package:
                break
    if isinstance(osv_record, dict):
        for item in osv_record.get("affected") or []:
            pkg = item.get("package") or {}
            if not package and pkg.get("name"):
                package = str(pkg["name"])
                ecosystem = _ECOSYSTEMS.get(str(pkg.get("ecosystem", "")).lower())
            for rng in item.get("ranges") or []:
                for event in rng.get("events") or []:
                    value = event.get("fixed")
                    if value and not _SHA_RE.match(str(value)) and not fixed:
                        fixed = str(value)
        # OSV records imported from a Git range often put commit hashes in
        # `events.fixed` and keep the real release range in
        # `database_specific.extracted_events`. Without this fallback every
        # such CVE appears to have no fixed release even though the advisory
        # names one.
        extracted_fixed, extracted_range = _osv_extracted_range(osv_record)
        if not fixed and extracted_fixed:
            fixed = extracted_fixed
            if not affected_range:
                affected_range = extracted_range
    if not package and isinstance(cve_record, dict):
        cna = cve_record.get("containers", {}).get("cna", {})
        for item in cna.get("affected") or []:
            if item.get("product"):
                package = str(item["product"])
                component = str(item.get("product"))
                break
    if not component and isinstance(osv_record, dict):
        component = str(osv_record.get("summary") or "")[:200] or None
    if isinstance(cve_record, dict):
        from .discovery_refs import _package_mapping

        mapping, _ = _package_mapping(cve_record, package)
        if mapping:
            ecosystem, package = mapping
    return package, ecosystem, component, fixed, affected_range


def _osv_extracted_range(
    osv_record: dict,
) -> tuple[str | None, str | None]:
    """Recover a real release fix from OSV's extracted Git events.

    The direct ``ranges.events.fixed`` value is often a commit hash. The
    extraction metadata retains the original version range, which is what a
    build can actually pin. Prefer ``AFFECTED_FIELD`` and, when several
    branches are fixed, the highest fixed release.
    """
    candidates: list[tuple[str, str | None, str]] = []
    for item in osv_record.get("affected") or []:
        if not isinstance(item, dict):
            continue
        for rng in item.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            database = rng.get("database_specific") or {}
            for event in database.get("extracted_events") or []:
                if not isinstance(event, dict):
                    continue
                introduced = fixed = None
                for bound in event.get("range") or []:
                    if not isinstance(bound, dict):
                        continue
                    value = bound.get("fixed")
                    if value and not _SHA_RE.match(str(value)):
                        fixed = _normalize_release(str(value))
                    value = bound.get("introduced")
                    if value and not _SHA_RE.match(str(value)):
                        introduced = _normalize_release(str(value))
                if fixed:
                    candidates.append((str(event.get("source") or ""), introduced, fixed))
    if not candidates:
        return None, None
    preferred = [item for item in candidates if item[0] == "AFFECTED_FIELD"] or candidates
    ordered = [item for item in preferred if _ref_version(item[2]) is not None]
    if not ordered:
        return None, None
    _, introduced, fixed = max(ordered, key=lambda item: _ref_version(item[2]))
    affected = f">= {introduced}, < {fixed}" if introduced else f"< {fixed}"
    return fixed, affected


def _fetch_fix_commit(
    collector: EvidenceCollector, references: list[str], notes: list[str]
) -> tuple[str | None, str | None]:
    """Fetch the first upstream commit patch that is reachable and public."""
    candidates: list[str] = []
    for url in references:
        match = _COMMIT_RE.search(url)
        if not match:
            continue
        clean = url.split("#", 1)[0].split("?", 1)[0]
        if not clean.endswith((".patch", ".diff")):
            clean = clean.rstrip("/") + ".patch"
        if clean not in candidates:
            candidates.append(clean)
    for url in candidates[:3]:
        attempts = [url]
        api_url = _github_api_commit(url)
        if api_url and api_url not in attempts:
            attempts.append(api_url)
        for attempt in attempts:
            fetched = collector.add(
                attempt,
                "upstream_commit",
                "Upstream fix commit referenced by the CVE records",
            )
            if fetched["status"] == "ok":
                text = _local_text(fetched, collector.run_dir)
                if not text.strip():
                    notes.append(f"fix commit response from {attempt} is empty; trying the next source")
                    continue
                sha = _commit_sha(text, url)
                if not sha:
                    notes.append(f"fix source {attempt} is not an unambiguous single commit; trying direct commit metadata")
                    continue
                return sha, fetched["id"]
            notes.append(f"fix commit fetch failed for {attempt}: {fetched.get('error')}")
    return None, None


def _github_api_commit(url: str) -> str | None:
    """Map a github.com commit page/patch to the API commit endpoint."""
    match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})",
        url,
    )
    if not match:
        return None
    owner, repo, sha = match.groups()
    return f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"


def _commit_sha(text: str, url: str) -> str | None:
    match = _COMMIT_RE.search(url)
    short = match.group(1) if match else None
    full = re.findall(r"^From ([0-9a-f]{40})\b", text, re.MULTILINE)
    if len(full) > 1:
        # GitHub merge .patch responses can be a mailbox of several commits.
        # Its first entry is not necessarily the CVE's fix or the requested ref.
        return None
    if full:
        return full[0]
    try:
        document = json.loads(text)
        sha = document.get("sha") if isinstance(document, dict) else None
        if sha:
            return sha if re.fullmatch(r"[0-9a-f]{40}", str(sha)) and (not short or sha.startswith(short)) else None
    except ValueError:
        pass
    for candidate in re.findall(r"\b[0-9a-f]{40}\b", text[:4000]):
        if not short or candidate.startswith(short):
            return candidate
    return short


def _go_module_path(package: str) -> str:
    """Encode a Go module path the way the module proxy expects it.

    Uppercase letters are escaped as ``!`` plus the lowercase letter, so a
    module such as ``github.com/BurntSushi/toml`` is addressable on the proxy.
    """
    return "".join(
        "!" + char.lower() if char.isupper() else char for char in package
    )


def _go_module_unescape(path: str) -> str:
    """Undo the proxy's ``!`` case encoding so names match the spec package."""
    return re.sub(r"!([a-z])", lambda match: match.group(1).upper(), path)


def _registry_url(ecosystem: str, package: str, version: str) -> str | None:
    if ecosystem == "pypi":
        return (
            f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/"
            f"{urllib.parse.quote(version, safe='')}/json"
        )
    if ecosystem == "npm":
        return (
            f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}/"
            f"{urllib.parse.quote(version, safe='')}"
        )
    if ecosystem == "go":
        module = urllib.parse.quote(_go_module_path(package), safe="/!")
        return f"https://proxy.golang.org/{module}/@v/v{version}.info"
    if ecosystem == "maven" and ":" in package:
        group, artifact = package.split(":", 1)
        group_path = urllib.parse.quote(group.replace(".", "/"), safe="/")
        artifact = urllib.parse.quote(artifact, safe="")
        return (
            f"https://repo1.maven.org/maven2/{group_path}/{artifact}/"
            f"{urllib.parse.quote(version, safe='')}/{artifact}-{version}.pom"
        )
    return None


def _checksum_url(ecosystem: str, package: str, version: str) -> str | None:
    """A URL whose body carries a content hash for the published artifact."""
    if ecosystem == "go":
        module = urllib.parse.quote(_go_module_path(package), safe="/!")
        return f"https://sum.golang.org/lookup/{module}@v{version}"
    if ecosystem == "maven" and ":" in package:
        group, artifact = package.split(":", 1)
        group_path = urllib.parse.quote(group.replace(".", "/"), safe="/")
        artifact = urllib.parse.quote(artifact, safe="")
        return (
            f"https://repo1.maven.org/maven2/{group_path}/{artifact}/"
            f"{urllib.parse.quote(version, safe='')}/{artifact}-{version}.jar.sha256"
        )
    return None


def _local_text(source: dict, run_dir: Path) -> str:
    path = Path(run_dir) / source.get("local_path", "")
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Artifact identity
# ---------------------------------------------------------------------------


def _parse_go_checksum(text: str, version: str) -> str | None:
    """Return the hex form of a Go module's ``h1:`` dirhash, if present.

    The checksum database answers with one line per module version::

        github.com/owner/module v1.2.3 h1:<base64>

    plus a second line for ``/go.mod``. ``h1`` is base64(SHA-256(file list)),
    so decoding it yields the 32-byte SHA-256 digest the ``sha256:`` prefix
    promises.
    """
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] != version:
            continue
        if not parts[2].startswith("h1:"):
            continue
        try:
            raw = base64.b64decode(parts[2][3:], validate=True)
        except ValueError:
            return None
        return raw.hex() if len(raw) == 32 else None
    return None


def _parse_maven_checksum(text: str) -> str | None:
    """Return a Maven ``.sha256`` body as lowercase hex, if well formed."""
    value = text.strip().split()[0] if text.strip() else ""
    return value.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", value) else None


def artifact_identity(
    evidence: dict, run_dir: Path, *, product: str, vulnerable_ref: str
) -> list[dict]:
    """Pin package artifacts when the registry exposes a digest.

    PyPI sdists carry a SHA-256 and npm tarballs carry an SRI integrity hash.
    Go publishes the module's ``h1:`` dirhash through the checksum database and
    Maven ships a ``.jar.sha256`` next to the artifact; both are read as text,
    not JSON. Records without a registry hash are kept but marked unverified so
    the missing identity is visible in the score instead of being fabricated.
    """
    identities: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for source in evidence.get("sources", []):
        if source.get("source_type") != "release_notes" or source.get("status") != "ok":
            continue
        url = source["url"]
        go = _GO_CHECKSUM_RE.search(url)
        maven = _MAVEN_CHECKSUM_RE.search(url)
        pypi = _PYPI_VERSION_RE.search(url)
        npm = _NPM_VERSION_RE.search(url)
        # Downloaded wheels/archives may share this source category. They are
        # not registry metadata and must never be decoded as UTF-8 text here.
        if not any((go, maven, pypi, npm)):
            continue
        path = Path(run_dir) / source.get("local_path", "")
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            continue
        if go:
            module = _go_module_unescape(
                urllib.parse.unquote(go.group("module"))
            )
            raw_version = go.group("version")
            version = _normalize_go_version(raw_version)
            key = ("go", module, version)
            if key in seen:
                continue
            seen.add(key)
            checksum = _parse_go_checksum(text, f"v{raw_version}")
            identities.append({
                "kind": "go",
                "name": module,
                "version": version,
                "digest": f"sha256:{checksum}" if checksum
                else f"unverified:{source['content_sha256']}",
                "source_url": url,
            })
            continue
        if maven:
            group = urllib.parse.unquote(maven.group("group")).replace("/", ".")
            artifact = urllib.parse.unquote(maven.group("artifact"))
            version = maven.group("version")
            name = f"{group}:{artifact}"
            key = ("maven", name, version)
            if key in seen:
                continue
            seen.add(key)
            checksum = _parse_maven_checksum(text)
            identities.append({
                "kind": "maven",
                "name": name,
                "version": version,
                "digest": f"sha256:{checksum}" if checksum
                else f"unverified:{source['content_sha256']}",
                "source_url": url,
            })
            continue
        try:
            body = json.loads(text)
        except ValueError:
            continue
        if pypi:
            name = urllib.parse.unquote(pypi.group(1))
            version = str((body.get("info") or {}).get("version") or pypi.group(2))
            digest_value = None
            for item in body.get("urls") or []:
                if item.get("packagetype") == "sdist":
                    digest_value = (item.get("digests") or {}).get("sha256")
                    break
            if not digest_value:
                for item in body.get("urls") or []:
                    digest_value = (item.get("digests") or {}).get("sha256")
                    if digest_value:
                        break
            key = ("pypi", name, version)
            if key in seen:
                continue
            seen.add(key)
            identities.append({
                "kind": "pypi",
                "name": name,
                "version": version,
                "digest": f"sha256:{digest_value}" if digest_value
                else f"unverified:{source['content_sha256']}",
                "source_url": url,
            })
            continue
        if npm:
            name = urllib.parse.unquote(npm.group(1))
            version = str(body.get("version") or npm.group(2))
            key = ("npm", name, version)
            if key in seen:
                continue
            seen.add(key)
            dist = body.get("dist") or {}
            digest_value = None
            # The registry's SRI value is a real content hash of the published
            # tarball, so it pins the artifact just like the PyPI sha256.
            algo, _, encoded = str(dist.get("integrity") or "").partition("-")
            if algo in {"sha256", "sha384", "sha512"} and encoded:
                digest_value = f"{algo}:{encoded}"
            identities.append({
                "kind": "npm",
                "name": name,
                "version": version,
                "digest": digest_value or f"unverified:{source['content_sha256']}",
                "source_url": url,
            })
    if identities:
        return identities
    return [{
        "kind": "source",
        "name": product,
        "version": vulnerable_ref,
        "digest": f"unverified:{vulnerable_ref}",
        "source_url": "https://cveawg.mitre.org/",
    }]


__all__ = [
    "Discovery",
    "collect",
    "load",
    "artifact_identity",
    "OSV_URL",
    "GITHUB_ADVISORY_URL",
    "NVD_URL",
]
