"""Per-CVE NVD records served from a locally indexed yearly feed.

The NVD CVE API allows five requests per 30 seconds without a key. Triage of
the 13,687-candidate manifest needs one NVD record per candidate, which is
about 22.8 hours of pure rate-limit wait, and every 429 becomes a
``source_error`` that pollutes the yield statistics. The yearly feed carries
the same records as a single ~43 MB download.

This module indexes the feed once into SQLite and answers each lookup from
disk. A CVE newer than the snapshot, an unreadable feed, or a lookup miss all
fall back to the API: the cache can make a run faster, never make it fail.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from .config import SourceSettings
from .errors import TaskError
from .sources import download
from .util import PipelineError, file_lock, utc_now_text, write_json

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

# The feed for a year is regenerated continuously while it is current, but a
# week-old snapshot still resolves almost every candidate; misses fall back to
# the API. A shorter window would re-download 43 MB per week of a campaign.
DEFAULT_MAX_AGE_SEC = 7 * 24 * 3600

# NVD publishes yearly feeds from 2002 onward. Probing older years would only
# produce a 404 per lookup, so they go straight to the API fallback.
MIN_FEED_YEAR = 2002

_SHA_CACHE: dict[str, tuple[int, int, str]] = {}


@dataclass(frozen=True)
class FeedProvenance:
    year: int
    feed_url: str
    feed_sha256: str
    feed_size: int
    feed_mtime_ns: int
    records: int
    built_at: str
    built_at_epoch: float
    database: str
    database_bytes: int
    elapsed_sec: float

    def citation(self) -> str:
        return (
            f"NVD CVE 2.0 record from the local yearly feed "
            f"nvdcve-2.0-{self.year}.json.gz (sha256 {self.feed_sha256})"
        )

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


class NvdFeedCache:
    """Index one NVD yearly feed and answer per-CVE lookups from it."""

    def __init__(self, root: Path, *, max_age_sec: int = DEFAULT_MAX_AGE_SEC):
        self.root = Path(root)
        self.max_age_sec = max(1, int(max_age_sec))

    def feed_path(self, year: int) -> Path:
        return self.root / f"nvdcve-2.0-{year}.json.gz"

    def db_path(self, year: int) -> Path:
        return self.root / f"nvdcve-2.0-{year}.records.sqlite"

    def meta_path(self, year: int) -> Path:
        return self.root / f"nvdcve-2.0-{year}.records.json"

    def lookup(
        self, settings: SourceSettings, cve_id: str
    ) -> tuple[dict[str, Any], FeedProvenance] | None:
        """Return the NVD API 2.0 document for one CVE, or ``None``.

        ``None`` means "not in this snapshot": the caller must ask the API
        rather than treat the candidate as unsupported.
        """
        year = _year_of(cve_id)
        provenance = self.ensure(settings, year)
        database = self.db_path(year)
        connection = None
        try:
            # ``with sqlite3.connect(...)`` commits but never closes; the open
            # handle would then block a rebuild's os.replace on Windows.
            connection = sqlite3.connect(str(database), timeout=30)
            row = connection.execute(
                "SELECT record FROM cve WHERE id = ?", (str(cve_id).upper(),)
            ).fetchone()
        except sqlite3.Error as exc:
            raise TaskError(
                "source_error", f"NVD feed index {database} is unreadable: {exc}"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        if not row:
            return None
        return {"vulnerabilities": [json.loads(row[0])]}, provenance

    def ensure(
        self, settings: SourceSettings, year: int, *, refresh: bool = False
    ) -> FeedProvenance:
        """Download the feed if needed and (re)build the index under a lock.

        Concurrent workers and shards on one host share the cache directory;
        the lock makes the first caller build it while the rest wait, so no
        reader can ever open a half-written database.
        """
        if year < MIN_FEED_YEAR:
            raise PipelineError(
                f"NVD publishes yearly feeds from {MIN_FEED_YEAR}; no feed for {year}"
            )
        self.root.mkdir(parents=True, exist_ok=True)
        if not refresh:
            cached = self._current(year)
            if cached is not None:
                return cached
        with file_lock(self.root / f"nvd-feed-{year}"):
            if not refresh:
                cached = self._current(year)
                if cached is not None:
                    return cached
            feed = self.feed_path(year)
            if refresh or not feed.is_file() or self._stale(feed):
                download(FEED_URL.format(year=year), settings, feed)
            return self._build(year, feed)

    # -- internals ---------------------------------------------------------

    def _current(self, year: int) -> FeedProvenance | None:
        meta = self.meta_path(year)
        database = self.db_path(year)
        feed = self.feed_path(year)
        if not (meta.is_file() and database.is_file() and feed.is_file()):
            return None
        try:
            data = json.loads(meta.read_text(encoding="utf-8-sig"))
            stat = feed.stat()
        except (OSError, ValueError):
            return None
        # Size and mtime identify the snapshot without hashing 43 MB on every
        # lookup; ``harvest --refresh`` replaces the file, which changes both.
        if (
            int(data.get("feed_size") or -1) != stat.st_size
            or int(data.get("feed_mtime_ns") or -1) != stat.st_mtime_ns
        ):
            return None
        if time.time() - float(data.get("built_at_epoch") or 0) >= self.max_age_sec:
            return None
        try:
            return FeedProvenance(**{k: data[k] for k in FeedProvenance.__annotations__})
        except (KeyError, TypeError, ValueError):
            return None

    def _stale(self, feed: Path) -> bool:
        try:
            return time.time() - feed.stat().st_mtime >= self.max_age_sec
        except OSError:
            return True

    def _build(self, year: int, feed: Path) -> FeedProvenance:
        started = time.monotonic()
        stat = feed.stat()
        sha256 = _file_sha256(feed)
        database = self.db_path(year)
        temporary = database.with_name(database.name + ".part")
        for leftover in (temporary, temporary.with_name(temporary.name + "-journal")):
            if leftover.exists():
                leftover.unlink()
        connection = sqlite3.connect(str(temporary))
        try:
            # The index is a rebuildable cache, not primary storage; skipping
            # the journal halves the build time and costs at most one rebuild.
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute(
                "CREATE TABLE cve (id TEXT PRIMARY KEY, record TEXT NOT NULL)"
            )
            records = 0
            for entry in _iter_vulnerabilities(feed):
                cve = entry.get("cve") if isinstance(entry, dict) else None
                if not isinstance(cve, dict):
                    continue
                cve_id = str(cve.get("id") or "").strip().upper()
                if not cve_id:
                    continue
                connection.execute(
                    "INSERT OR REPLACE INTO cve (id, record) VALUES (?, ?)",
                    (cve_id, json.dumps(entry, separators=(",", ":"), ensure_ascii=False)),
                )
                records += 1
            connection.commit()
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise TaskError(
                "source_error", f"NVD feed {feed} could not be indexed: {exc}"
            ) from exc
        finally:
            connection.close()
        _replace_with_retry(temporary, database)
        provenance = FeedProvenance(
            year=year,
            feed_url=FEED_URL.format(year=year),
            feed_sha256=sha256,
            feed_size=stat.st_size,
            feed_mtime_ns=stat.st_mtime_ns,
            records=records,
            built_at=utc_now_text(),
            built_at_epoch=time.time(),
            database=str(database),
            database_bytes=database.stat().st_size,
            elapsed_sec=round(time.monotonic() - started, 2),
        )
        write_json(self.meta_path(year), provenance.to_json())
        return provenance


def _iter_vulnerabilities(path: Path) -> Iterator[Any]:
    """Walk the feed's ``vulnerabilities`` array one entry at a time.

    ``json.load`` on a 485 MB feed builds a multi-gigabyte object graph that a
    host running several shards cannot afford. ``raw_decode`` keeps peak memory
    at the feed text itself.
    """
    with gzip.open(path, "rt", encoding="utf-8-sig") as handle:
        text = handle.read()
    marker = text.find('"vulnerabilities"')
    if marker < 0:
        raise ValueError("feed has no vulnerabilities array")
    start = text.find("[", marker)
    if start < 0:
        raise ValueError("feed vulnerabilities is not an array")
    decoder = json.JSONDecoder()
    index = start + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n,":
            index += 1
            continue
        if char == "]":
            return
        entry, index = decoder.raw_decode(text, index)
        yield entry
    raise ValueError("feed vulnerabilities array is unterminated")


def _replace_with_retry(source: Path, destination: Path, attempts: int = 20) -> None:
    """Replace the index, tolerating a reader still holding it on Windows.

    A rebuild happens only when the snapshot expires; a concurrent lookup can
    hold the old file open for a few milliseconds, which on Windows blocks
    ``os.replace`` until that handle closes.
    """
    for attempt in range(attempts):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if attempt + 1 == attempts:
                raise
            time.sleep(0.1)


def _file_sha256(path: Path) -> str:
    stat = path.stat()
    key = str(path.resolve())
    cached = _SHA_CACHE.get(key)
    if cached and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
        return cached[2]
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    _SHA_CACHE[key] = (stat.st_size, stat.st_mtime_ns, value)
    return value


def _year_of(cve_id: str) -> int:
    parts = str(cve_id).split("-")
    if len(parts) < 2 or not parts[1].isdigit():
        raise PipelineError(f"CVE id has no year: {cve_id!r}")
    return int(parts[1])


__all__ = ["FEED_URL", "FeedProvenance", "NvdFeedCache"]
