"""Restricted source collection.

Network content is data, never instructions. Every hop is checked against an
explicit host allowlist and a public-IP policy; DNS is pinned to the checked
addresses for the duration of the request to blunt rebinding.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import SCHEMA_VERSION
from .config import SourceSettings
from .errors import TaskError
from .util import write_json

DEFAULT_MAX_REDIRECTS = 5


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class FetchResult:
    url: str
    final_url: str
    status: int
    body: bytes
    sha256: str
    media_type: str
    redirect_chain: list[str] = field(default_factory=list)
    fetched_at: str = field(default_factory=utc_now)

    @property
    def size(self) -> int:
        return len(self.body)


@dataclass(frozen=True)
class AllowedAddress:
    host: str
    port: int
    addresses: tuple[str, ...]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_addresses(host: str, port: int) -> AllowedAddress:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TaskError("source_error", f"Cannot resolve {host}: {exc}") from exc
    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise TaskError("source_error", f"Invalid resolved address {raw!r}") from exc
        if not address.is_global or address.is_multicast:
            raise TaskError(
                "source_error",
                f"Refusing non-public address {raw} for {host}",
                detail={"host": host, "address": raw},
            )
        addresses.append(raw)
    if not addresses:
        raise TaskError("source_error", f"No addresses for {host}")
    return AllowedAddress(host=host, port=port, addresses=tuple(dict.fromkeys(addresses)))


_DNS_LOCK = threading.Lock()
_DNS_USERS = 0
_DNS_STATE = threading.local()
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def _pinned_getaddrinfo(host, port, *args, **kwargs):
    """Resolve only the host pinned for the calling thread.

    A process-wide monkeypatch is unavoidable with urllib, but the pinned
    address itself is thread-local. Parallel source collection therefore
    cannot make one candidate's DNS answer satisfy another candidate's
    request.
    """
    allowed = getattr(_DNS_STATE, "allowed", None)
    if allowed is not None and str(host).casefold() == allowed.host.casefold():
        results = []
        for raw in allowed.addresses:
            family = socket.AF_INET6 if ":" in raw else socket.AF_INET
            sockaddr = (
                (raw, port or allowed.port, 0, 0)
                if family == socket.AF_INET6
                else (raw, port or allowed.port)
            )
            results.append(
                (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)
            )
        return results
    return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)


@contextlib.contextmanager
def _pinned_dns(allowed: AllowedAddress) -> Iterator[None]:
    global _DNS_USERS
    previous = getattr(_DNS_STATE, "allowed", None)
    with _DNS_LOCK:
        if _DNS_USERS == 0:
            socket.getaddrinfo = _pinned_getaddrinfo
        _DNS_USERS += 1
    _DNS_STATE.allowed = allowed
    try:
        yield
    finally:
        _DNS_STATE.allowed = previous
        with _DNS_LOCK:
            _DNS_USERS -= 1
            if _DNS_USERS == 0:
                socket.getaddrinfo = _ORIGINAL_GETADDRINFO


def validate_url(settings: SourceSettings, url: str) -> AllowedAddress:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise TaskError("source_error", f"Only https is allowed: {url}")
    if not parsed.hostname:
        raise TaskError("source_error", f"URL has no host: {url}")
    host = parsed.hostname.casefold()
    allowed_hosts = {h.casefold() for h in settings.allowed_hosts}
    if host not in allowed_hosts:
        raise TaskError("source_error", f"Host {host} is not in allowed_hosts")
    port = parsed.port or 443
    if port != 443:
        raise TaskError("source_error", f"Only port 443 is allowed, got {port}")
    if parsed.username or parsed.password:
        raise TaskError("source_error", "Credentials in source URLs are not allowed")
    return _public_addresses(host, port)


def fetch(url: str, settings: SourceSettings, max_redirects: int = DEFAULT_MAX_REDIRECTS) -> FetchResult:
    """Fetch with bounded retries for transient transport failures only."""
    attempts = 3
    last: TaskError | None = None
    for attempt in range(attempts):
        try:
            return _fetch_once(url, settings, max_redirects=max_redirects)
        except TaskError as exc:
            message = str(exc).lower()
            transient = "fetch failed" in message or "timed out" in message
            if not transient:
                raise
            last = exc
            if attempt + 1 < attempts:
                time.sleep(0.5 * (2 ** attempt))
    raise last or TaskError("source_error", f"Fetch failed for {url}")


def download(
    url: str,
    settings: SourceSettings,
    destination: Path,
    *,
    max_bytes: int = 512 * 1024 * 1024,
) -> dict:
    """Download a bounded public feed to disk with the same URL policy.

    This is intentionally separate from :func:`fetch`: bulk harvest feeds are
    far larger than a single evidence source, but they still must pass the
    HTTPS, allowlist, public-address, and DNS-pinning checks.
    """
    bounded = SourceSettings(
        allowed_hosts=list(settings.allowed_hosts),
        max_bytes=max_bytes,
        timeout_sec=max(settings.timeout_sec, 120),
        github_token=settings.github_token,
        nvd_api_key=settings.nvd_api_key,
    )
    result = fetch(url, bounded)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".part")
    temporary.write_bytes(result.body)
    temporary.replace(destination)
    return {
        "url": result.url,
        "final_url": result.final_url,
        "status": result.status,
        "sha256": result.sha256,
        "size": result.size,
        "media_type": result.media_type,
        "fetched_at": result.fetched_at,
        "path": str(destination),
    }


def _request_headers(settings: SourceSettings, url: str) -> dict[str, str]:
    """Attach credentials only to the exact host that owns them.

    Redirects are followed manually, so a token can never be forwarded to a
    different allowlisted host.
    """
    headers = {
        "User-Agent": "harbor-cve-pipeline/0.1 (source collector)",
        "Accept": "*/*",
    }
    host = (urllib.parse.urlsplit(url).hostname or "").casefold()
    if host == "api.github.com" and settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if host == "services.nvd.nist.gov" and settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    return headers


def _fetch_once(url: str, settings: SourceSettings, max_redirects: int = DEFAULT_MAX_REDIRECTS) -> FetchResult:
    current = url
    chain: list[str] = []
    opener = urllib.request.build_opener(_NoRedirect())
    for _ in range(max_redirects + 1):
        allowed = validate_url(settings, current)
        request = urllib.request.Request(
            current,
            headers=_request_headers(settings, current),
        )
        with _pinned_dns(allowed):
            try:
                response = opener.open(request, timeout=settings.timeout_sec)
            except urllib.error.HTTPError as exc:
                if exc.code in {301, 302, 303, 307, 308}:
                    location = exc.headers.get("Location")
                    if not location:
                        raise TaskError("source_error", f"Redirect without Location from {current}")
                    target = urllib.parse.urljoin(current, location)
                    if target in chain:
                        raise TaskError("source_error", f"Redirect loop at {target}")
                    chain.append(current)
                    current = target
                    continue
                raise TaskError(
                    "source_error",
                    f"HTTP {exc.code} fetching {current}",
                    detail={"status": exc.code},
                ) from exc
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                raise TaskError("source_error", f"Fetch failed for {current}: {exc}") from exc
            with response:
                body = response.read(settings.max_bytes + 1)
                if len(body) > settings.max_bytes:
                    raise TaskError(
                        "source_error",
                        f"Response exceeds {settings.max_bytes} bytes",
                        detail={"url": current, "max_bytes": settings.max_bytes},
                    )
                return FetchResult(
                    url=url,
                    final_url=current,
                    status=response.status,
                    body=body,
                    sha256=hashlib.sha256(body).hexdigest(),
                    media_type=response.headers.get_content_type(),
                    redirect_chain=chain,
                )
    raise TaskError("source_error", f"Too many redirects fetching {url}", detail={"chain": chain})


def cve_record_url(cve_id: str) -> str:
    return f"https://cveawg.mitre.org/api/cve/{cve_id}"


def parse_cve_record(body: bytes) -> dict:
    try:
        record = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TaskError("source_error", f"CVE record is not valid JSON: {exc}") from exc
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    descriptions = [d.get("value", "") for d in cna.get("descriptions", []) if d.get("lang") == "en"]
    references = []
    for ref in cna.get("references", []):
        if "url" in ref:
            references.append({"url": ref["url"], "tags": list(ref.get("tags", []))})
    affected = []
    for item in cna.get("affected", []):
        versions = [v.get("version") for v in item.get("versions", []) if v.get("status") == "affected"]
        affected.append({"product": item.get("product"), "vendor": item.get("vendor"), "versions": versions})
    metrics = []
    for metric in cna.get("metrics", []):
        metrics.extend(metric.values())
    return {
        "cve_id": record.get("cveMetadata", {}).get("cveId"),
        "state": record.get("cveMetadata", {}).get("state"),
        "title": cna.get("title"),
        "descriptions": descriptions,
        "references": references,
        "affected": affected,
        "metrics": metrics,
    }


@dataclass
class EvidenceCollector:
    settings: SourceSettings
    run_dir: Path
    fetched_at: str = field(default_factory=utc_now)
    sources: list[dict] = field(default_factory=list)

    def add(self, url: str, source_type: str, citation: str) -> dict:
        """Fetch one source, persist it, and return its evidence entry.

        Collection is incremental because automatic discovery has to read the
        CVE record before it knows which references deserve a second fetch.
        """
        evidence_dir = self.run_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        source_id = f"src-{len(self.sources) + 1}-{source_type.replace('_', '-')}"
        try:
            result = fetch(url, self.settings)
        except TaskError as exc:
            # Persist the failure snapshot too: the evidence contract
            # requires a traceable local artifact for every source, and an
            # empty local_path would make the index unverifiable.
            snapshot = json.dumps(
                {"url": url, "error": str(exc), "category": exc.category.code},
                sort_keys=True,
            ).encode("utf-8")
            local_name = f"{source_id}.error.json"
            (evidence_dir / local_name).write_bytes(snapshot)
            entry = {
                "id": source_id,
                "url": url,
                "fetched_at": self.fetched_at,
                "content_sha256": hashlib.sha256(snapshot).hexdigest(),
                "source_type": source_type,
                "citation": citation,
                "status": "error",
                "error": str(exc),
                "local_path": f"evidence/{local_name}",
                "media_type": "application/json",
                "redirect_chain": [],
            }
            self.sources.append(entry)
            return entry
        return self.record(url, source_type, citation, result)

    def record(
        self,
        url: str,
        source_type: str,
        citation: str,
        result: FetchResult,
    ) -> dict:
        """Persist an already fetched body as evidence.

        Probes use this after a direct fetch so that a registry that does not
        publish a package does not leave a failed source in the evidence index.
        """
        evidence_dir = self.run_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        source_id = f"src-{len(self.sources) + 1}-{source_type.replace('_', '-')}"
        suffix = _suffix_for(result.media_type, result.final_url)
        local_name = f"{source_id}{suffix}"
        (evidence_dir / local_name).write_bytes(result.body)
        entry = {
            "id": source_id,
            "url": url,
            "fetched_at": result.fetched_at,
            "content_sha256": result.sha256,
            "source_type": source_type,
            "citation": citation,
            "status": "ok",
            "error": None,
            "local_path": f"evidence/{local_name}",
            "media_type": result.media_type,
            "redirect_chain": result.redirect_chain,
        }
        self.sources.append(entry)
        return entry

    def has_url(self, url: str) -> bool:
        return any(source.get("url") == url for source in self.sources)

    def save(self, cve_id: str) -> dict:
        index = {
            "schema_version": SCHEMA_VERSION,
            "cve_id": cve_id,
            "collected_at": self.fetched_at,
            "sources": list(self.sources),
        }
        write_json(self.run_dir / "evidence-index.json", index)
        return index

    def collect(self, cve_id: str, urls: list[tuple[str, str, str]]) -> dict:
        """Fetch (url, source_type, citation) tuples and write the evidence index."""
        for url, source_type, citation in urls:
            self.add(url, source_type, citation)
        return self.save(cve_id)


def _suffix_for(media_type: str, url: str) -> str:
    if media_type == "application/json" or url.endswith(".json"):
        return ".json"
    if media_type.startswith("text/"):
        return ".txt"
    path_suffix = Path(urllib.parse.urlsplit(url).path).suffix
    return path_suffix if path_suffix else ".bin"


def default_urls(cve_id: str, record: dict) -> list[tuple[str, str, str]]:
    """Build a bounded citation set from the official record's references."""
    urls: list[tuple[str, str, str]] = [
        (cve_record_url(cve_id), "cve_record", "Official CVE JSON 5.0 record"),
    ]
    seen = {cve_record_url(cve_id)}
    for ref in record.get("references", []):
        url = ref["url"]
        if url in seen:
            continue
        tags = set(ref.get("tags", []))
        if "/commit/" in url:
            source_type, citation = "upstream_commit", "Upstream fix commit referenced by the CVE record"
        elif "/security/advisories/" in url or "advisory" in url.lower():
            source_type, citation = "vendor_advisory", "Vendor security advisory referenced by the CVE record"
        elif "releases/tag" in url or "/releases/" in url:
            source_type, citation = "release_notes", "Release notes referenced by the CVE record"
        elif "x_refsource_CONFIRM" in tags:
            source_type, citation = "vendor_advisory", "Confirmation reference from the CVE record"
        else:
            continue
        seen.add(url)
        urls.append((url, source_type, citation))
        if len(urls) >= 4:
            break
    return urls


__all__ = [
    "FetchResult", "AllowedAddress", "fetch", "download", "validate_url",
    "parse_cve_record", "default_urls", "cve_record_url", "EvidenceCollector",
]
