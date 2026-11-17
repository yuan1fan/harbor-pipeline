"""Shared version selection and validation for fresh and cached discovery refs.

These produce build candidates with structured reasons, not a verdict that the
CVE is reproducible. Ambiguous products/ranges and unavailable refs stay unresolved.
"""

from __future__ import annotations

import json
import io
import hashlib
import re
import urllib.parse
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from .config import SourceSettings
from .sources import EvidenceCollector
from packaging.version import InvalidVersion, Version

if TYPE_CHECKING:
    from .discovery import Discovery

_SHA = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[vV]?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?")
MAX_REF_REQUESTS = 8
MAX_FIX_SEARCH_RESULTS = 5
_FIX_SUBJECT = re.compile(r"^(?:fix|security)(?:\([^()\r\n]+\))?!?:\s", re.IGNORECASE)


_OPEN_BOUND = {"", "0", "*", "unspecified", "n/a", "unknown"}


def _ref_version(value):
    """Compare release labels without changing the actual Git/package ref."""
    parsed = _version(value)
    if parsed is not None:
        return parsed
    match = re.search(r"(?:[/@_-])[vV]?(\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?)$", str(value))
    return _version(match.group(1)) if match else None


def _row_match(row, value):
    """True/False/None: a matching row, a nonmatch, or undecidable syntax."""
    start = str(row.get("version") or "").strip()
    upper = str(row.get("lessThanOrEqual") or "").strip()
    exclusive = str(row.get("lessThan") or "").strip()
    if upper and exclusive:
        return None
    shorthand = re.fullmatch(r"(<|<=)\s*(\S+)", start) if not upper and not exclusive else None
    if shorthand:
        start = "0"
        if shorthand[1] == "<":
            exclusive = shorthand[2]
        else:
            upper = shorthand[2]
    is_git = row.get("versionType") == "git" or any(_SHA.fullmatch(v) for v in (start, upper, exclusive) if v)
    if not upper and not exclusive:
        if start.lower() in _OPEN_BOUND:
            match = None
        elif is_git:
            match = value == start
        else:
            left, right = _ref_version(value), _ref_version(start)
            match = left == right if left is not None and right is not None else value == start
    elif is_git:
        # No lexical/numeric ordering of commits. An explicit endpoint can
        # still be recognized; other membership requires Git evidence.
        match = True if value == upper or (value == start and start.lower() not in _OPEN_BOUND) else (
            False if value == exclusive else None)
    else:
        current, end = _ref_version(value), _ref_version(upper or exclusive)
        lower = None if start.lower() in _OPEN_BOUND else _ref_version(start)
        if current is None or end is None or (lower is None and start.lower() not in _OPEN_BOUND):
            match = None
        else:
            match = (lower is None or current >= lower) and (current <= end if upper else current < end)
    return None if match and row.get("changes") else match


def _item_status(item, value):
    matched, uncertain = set(), []
    for row in item.get("versions") or []:
        if not isinstance(row, dict):
            continue
        match = _row_match(row, value)
        if match is True:
            matched.add(row.get("status", "unknown"))
        elif match is None:
            uncertain.append(row)
    if {"affected", "unaffected"} <= matched:
        return "conflict"
    if "unaffected" in matched:
        return "unaffected"
    if "unknown" in matched:
        return "unknown"
    if "affected" in matched:
        return "unknown" if any(r.get("status") != "affected" or r.get("changes") for r in uncertain) else "affected"
    return "unknown" if uncertain else item.get("defaultStatus", "unknown")


def _known_refs(osv, discovery, repo):
    values = []
    for item in osv.get("affected") or []:
        package = item.get("package") or {}
        same_package = str(package.get("name") or "").casefold() == str(discovery.package or "").casefold()
        same_repo = any((_repo(str(r.get("repo") or "")) or "").casefold() == repo.casefold()
                        for r in item.get("ranges") or [] if r.get("type") == "GIT")
        if same_package or same_repo:
            values.extend(v for v in item.get("versions") or [] if isinstance(v, str))
    return tuple(dict.fromkeys(values))


def _affected_refs(metadata, osv, discovery, repo):
    known = _known_refs(osv, discovery, repo)
    if known:
        return known
    # A renamed/transferred repository can appear under two names in the
    # records. Reuse its version hints only after checking the identical fix
    # in that declared repository; every tag still resolves in the fix repo.
    for declared in _repositories(osv, {})[:2]:
        hints = _known_refs(osv, discovery, declared)
        if declared.casefold() == repo.casefold() or not hints:
            continue
        document, source_id = metadata.commit(declared, discovery.fix_commit)
        if document and _has_patch(json.dumps(document)):
            metadata.decision("osv_repository_fix", "verified", "OSV repository contains the same fix SHA; its version hints still require tag and ancestry checks",
                              repository=declared, fix_repository=repo, source_ids=[source_id])
            return hints
        metadata.decision("osv_repository_fix", "unresolved", "OSV repository did not verify the same fix; its version hints were not imported",
                          repository=declared, source_ids=[source_id])
    return ()


def _supported_affected(item, value, known=()):
    status = _item_status(item, value)
    if status == "affected":
        return True
    if status != "unknown" or value not in known:
        return False
    if any(r.get("lessThan") or r.get("lessThanOrEqual") or r.get("changes")
           or str(r.get("version") or "").startswith(("<", ">"))
           for r in item.get("versions") or [] if isinstance(r, dict)):
        return False
    # OSV's explicit affected list may fill a CNA enumeration gap. It must
    # never override an unaffected entry or an unresolved status change.
    return not any((_row_match(row, value) is not False)
                   and (row.get("changes") or row.get("status") != "affected")
                   for row in item.get("versions") or [] if isinstance(row, dict))


def _has_affected_scope(item, fix):
    # Contradictory explicit statuses are different from an opaque but
    # legitimate release scheme (dates, build numbers, or Git references).
    if any(_item_status(item, str(r.get("version") or "")) == "conflict"
           for r in item.get("versions") or [] if isinstance(r, dict)):
        return False
    if item.get("defaultStatus") == "affected":
        return True
    for row in item.get("versions") or []:
        if row.get("status") != "affected" or row.get("changes"):
            continue
        start = str(row.get("version") or "").strip()
        upper, exclusive = row.get("lessThanOrEqual"), row.get("lessThan")
        shorthand = re.fullmatch(r"(<|<=)\s*(\S+)", start) if not upper and not exclusive else None
        if shorthand:
            start = "0"
            if shorthand[1] == "<":
                exclusive = shorthand[2]
            else:
                upper = shorthand[2]
        if upper and exclusive:
            continue
        if upper or exclusive:
            end = _ref_version(upper or exclusive)
            lower = _ref_version(start)
            if end is not None and (start.lower() in _OPEN_BOUND or (lower is not None and (
                    lower <= end if upper else lower < end))):
                return True
            if end is None and start.lower() in _OPEN_BOUND and str(upper or exclusive).strip():
                # This does not order or map the opaque versions. It permits
                # only the independently verified fix/parent counterfactual.
                return True
        elif start.lower() not in _OPEN_BOUND and start != fix and _item_status(item, start) == "affected":
            return True
    return False


def _repo(url: str) -> str | None:
    parsed = urllib.parse.urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname == "api.github.com" and len(parts) >= 3 and parts[0] == "repos":
        parts = parts[1:]
    elif parsed.hostname != "github.com":
        return None
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1].removesuffix('.git')}"


def _text(source: dict, root: Path) -> str:
    if source.get("status") != "ok" or not source.get("local_path"):
        return ""
    try:
        raw = (root / source["local_path"]).read_bytes()
        if source.get("content_sha256") != hashlib.sha256(raw).hexdigest():
            return ""
        return raw.decode("utf-8-sig")
    except (OSError, UnicodeError):
        return ""


def _json(text: str) -> dict:
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _has_patch(text: str) -> bool:
    if "diff --git " in text and "\n@@ " in text:
        return True
    return any(
        isinstance(item, dict) and str(item.get("patch") or "").strip()
        for item in _json(text).get("files") or []
    )


def _patch_sha(source, root):
    from .discovery import _commit_sha

    text = _text(source, root)
    sha = _commit_sha(text, str(source.get("url") or "")) if _has_patch(text) else None
    return sha if _SHA.fullmatch(str(sha or "")) else None


def _affected(record: dict, package: str | None, repo: str) -> tuple[dict | None, str]:
    """Select one exact product, without package alias or fuzzy-name guesses."""
    matches = []
    cna = (record.get("containers") or {}).get("cna") or {}
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        names = [item.get("packageName"), item.get("product")]
        identities = {str(n).casefold() for n in names if n}
        package_names = {str(package).casefold()}
        if package and (":" in package or "/" in package):
            package_names.add(repo.split('/')[-1].casefold())
        if not (package_names & identities):
            continue
        repos = [_repo(str(item[key])) for key in ("repo", "collectionURL") if item.get(key)]
        purl = str(item.get("packageURL") or "")
        if purl.startswith("pkg:github/"):
            repos.append(purl[len("pkg:github/"):].split("@", 1)[0].split("?", 1)[0])
        if any(r and r.casefold() != repo.casefold() for r in repos):
            return None, "CNA repository conflicts with the fix repository"
        matches.append(item)
    if len(matches) > 1:
        return None, "multiple matching CNA products need reconciliation"
    if not matches:
        return None, "no unique exact CNA product match"
    return matches[0], ""


def _candidates(item: dict, fix: str, preferred=None, known=(), *, fixed_hint=None, affected_range=None) -> tuple[list[tuple[str, str]], bool, str]:
    """Return (literal candidates, fix-parent allowed, ambiguity reason).

    Git hashes are never ordered. In particular a git lessThanOrEqual value
    can itself be the fix; only its explicit affected start is considered.
    """
    refs = {}
    rows = [r for r in item.get("versions") or [] if isinstance(r, dict)]
    parent_allowed = False
    for row in rows:
        if row.get("status") != "affected" or row.get("changes"):
            continue
        start = str(row.get("version") or "").strip()
        upper = str(row.get("lessThanOrEqual") or "").strip()
        exclusive = str(row.get("lessThan") or "").strip()
        if upper and exclusive:
            continue
        parent_allowed = parent_allowed or (
            (start == "0" and exclusive == fix and row.get("versionType") == "git")
            or start == f"< {fix}"
        )
        for value, rule in ((upper, "cna_inclusive_upper"), (start, "cna_affected_ref")):
            if (value and value.lower() not in _OPEN_BOUND and value != fix
                    and not value.startswith(("<", ">"))
                    and (_SHA.fullmatch(value) or _ref_version(value) is not None)
                    and _supported_affected(item, value)):
                refs[value] = rule
    parent_allowed = parent_allowed or (
        any(r.get("status") == "affected" for r in rows)
        and any(r.get("status") == "unaffected" and r.get("versionType") == "git"
                and r.get("version") == fix for r in rows)
    )
    for value in known:
        if value != fix and _supported_affected(item, value, known):
            refs.setdefault(value, "osv_affected_ref")
    if not preferred:
        preferred = max((v for v in known if _release_allowed(item, v, known, fixed_hint, affected_range)),
                        key=_ref_version, default=None)
    if preferred and preferred != fix and _supported_affected(item, preferred, known):
        refs[preferred] = "known_affected_ref"
    def priority(value):
        if refs[value] == "cna_inclusive_upper":
            group = 3
        elif _SHA.fullmatch(value):
            group = 2
        else:
            group = 1
        return group, _ref_version(value) or Version("0")
    ordered = sorted(refs, key=priority, reverse=True)
    if preferred in ordered:
        ordered.remove(preferred)
        ordered.insert(0, preferred)
    reason = "" if ordered or parent_allowed else "no unambiguous affected ref matches the recorded version statuses/ranges"
    return [(v, refs[v]) for v in ordered[:2]], parent_allowed, reason


class _Metadata:
    """Reuse evidence bodies and bound all additional ref lookups per candidate."""

    def __init__(self, collector: EvidenceCollector, notes: list[str]):
        self.collector = collector
        self.notes = notes
        self.requests = 0
        self.attempted = set()
        self.trace = []

    def decision(self, rule, outcome, reason, *, candidate=None, source_ids=(), **details):
        event = {"rule": rule, "outcome": outcome, "reason": reason,
                 "source_ids": list(dict.fromkeys(s for s in source_ids if s)), **details}
        if candidate is not None:
            event["candidate"] = candidate
        if event not in self.trace:
            self.trace.append(event)

    def source(self, url: str, source_type="other", *, json_required=False) -> dict:
        for source in reversed(self.collector.sources):
            same_url = source.get("url") == url
            if not same_url and urllib.parse.urlsplit(url).hostname == "pypi.org":
                def pypi_key(candidate):
                    parsed = urllib.parse.urlsplit(candidate)
                    parts = parsed.path.split("/")
                    if parsed.hostname == "pypi.org" and len(parts) == 5 and parts[1] == "pypi":
                        return re.sub(r"[-_.]+", "-", urllib.parse.unquote(parts[2])).casefold(), parts[3]
                    return None
                key = pypi_key(url)
                same_url = key is not None and key == pypi_key(str(source.get("url") or ""))
            if same_url and source.get("status") == "ok":
                body = _text(source, self.collector.run_dir)
                path = self.collector.run_dir / source.get("local_path", "")
                if (path.is_file() and path.stat().st_size
                        and hashlib.sha256(path.read_bytes()).hexdigest() == source.get("content_sha256")
                        and (not json_required or _json(body))):
                    return source
        if self.requests >= MAX_REF_REQUESTS or url in self.attempted:
            self.decision("source_lookup", "unresolved", "request budget exhausted" if url not in self.attempted
                          else "source already attempted in this selection", candidate=url)
            return {}
        self.requests += 1
        self.attempted.add(url)
        result = self.collector.add(url, source_type, "Deterministic discovery ref verification")
        if result.get("status") != "ok":
            self.decision("source_lookup", "unresolved", str(result.get("error") or "source unavailable"),
                          candidate=url, source_ids=[result.get("id")])
        return result

    def get(self, url: str, source_type="other") -> tuple[dict, str | None]:
        source = self.source(url, source_type, json_required=True)
        document = _json(_text(source, self.collector.run_dir))
        if not document:
            self.notes.append(f"ref metadata unavailable: {url} ({source.get('error') or 'not JSON'})")
        return document, source.get("id")

    def commit(self, repo: str, ref: str, source_type="other") -> tuple[dict, str | None]:
        url = f"https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
        document, source_id = self.get(url, source_type)
        sha = str(document.get("sha") or "")
        if not _SHA.fullmatch(sha) or (re.fullmatch(r"[0-9a-f]{7,40}", ref) and not sha.startswith(ref)):
            self.decision("git_commit_identity", "rejected" if document else "unresolved", "commit metadata did not match the requested SHA",
                          candidate={"repository": repo, "value": ref}, source_ids=[source_id])
            return {}, None
        response_repo = _repo(str(document.get("html_url") or document.get("url") or ""))
        if not response_repo or response_repo.casefold() != repo.casefold():
            self.decision("git_commit_identity", "rejected", "commit metadata belongs to a different repository",
                          candidate={"repository": repo, "value": ref}, source_ids=[source_id])
            return {}, None
        self.decision("git_commit_identity", "verified", "repository and commit SHA match",
                      candidate={"repository": repo, "value": sha}, source_ids=[source_id])
        return document, source_id

    def tag(self, repo: str, value: str):
        from .discovery import DiscoveryRef

        for tag in dict.fromkeys((value, value if value.startswith(("v", "V")) else "v" + value)):
            url = f"https://api.github.com/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
            document, source_id = self.get(url)
            if document.get("ref") != f"refs/tags/{tag}":
                continue
            obj = document.get("object") or {}
            if obj.get("type") == "tag" and _SHA.fullmatch(str(obj.get("sha") or "")):
                document, source_id = self.get(f"https://api.github.com/repos/{repo}/git/tags/{obj['sha']}")
                if document.get("tag") != tag:
                    continue
                obj = document.get("object") or {}
            if obj.get("type") == "commit" and _SHA.fullmatch(str(obj.get("sha") or "")):
                ref = DiscoveryRef("tag", tag, repository=repo, resolved_commit=obj["sha"], source_id=source_id)
                self.decision("git_tag_identity", "verified", "exact tag resolved to its commit", candidate=ref.to_json(), source_ids=[source_id])
                return ref
        return None

    def precedes(self, repo, base, head):
        """Verify ancestry without downloading the potentially huge file diff."""
        endpoint = f"https://api.github.com/repos/{repo}/compare/{base}...{head}"
        document = {}
        for source in self.collector.sources:
            if str(source.get("url") or "").split("?", 1)[0] == endpoint:
                cached = _json(_text(source, self.collector.run_dir))
                if cached.get("base_commit", {}).get("sha") == base:
                    document = cached
                    break
        if not document:
            # GitHub includes changed files only on page 1. The ancestry
            # summary remains available on page 2, even for a one-commit gap.
            document, _ = self.get(endpoint + "?per_page=1&page=2")
        if (document.get("status") == "ahead" and document.get("base_commit", {}).get("sha") == base
                and document.get("merge_base_commit", {}).get("sha") == base):
            self.decision("git_ancestry", "verified", "vulnerable commit is an ancestor of the fix", repository=repo, base=base, fixed=head)
            return True
        if document.get("base_commit", {}).get("sha") == base and document.get("status") in {"behind", "diverged", "identical"}:
            self.decision("git_ancestry", "rejected", "commit is not strictly before the fix", repository=repo, base=base, fixed=head,
                          comparison_status=document["status"])
            return False
        return None


def _records(collector):
    cve, osv, advisories = {}, {}, []
    for source in collector.sources:
        body = _text(source, collector.run_dir)
        if source.get("source_type") == "cve_record":
            cve = _json(body)
        elif "api.osv.dev/" in source.get("url", ""):
            osv = _json(body)
        elif "api.github.com/advisories?" in source.get("url", ""):
            try:
                data = json.loads(body)
                advisories = data if isinstance(data, list) else []
            except ValueError:
                pass
    return cve, osv, advisories


def _registry_identified(discovery, osv, advisories):
    from .discovery import _ECOSYSTEMS

    def matches(package):
        return (package.get("name") == discovery.package
                and _ECOSYSTEMS.get(str(package.get("ecosystem") or "").lower()) == discovery.ecosystem)

    return (any(matches(v.get("package") or {}) for a in advisories for v in a.get("vulnerabilities") or [])
            or any(matches(a.get("package") or {}) for a in osv.get("affected") or []))


def _purl(value):
    """The supported package-url namespaces; no fuzzy project alias table."""
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None
    kind, _, path = value[4:].partition("/")
    path = path.split("?", 1)[0].split("#", 1)[0]
    if "@" in path[1:]:
        path = path.rsplit("@", 1)[0]
    name = urllib.parse.unquote(path)
    if kind == "maven":
        name = name.replace("/", ":", 1)
    if kind in {"pypi", "npm", "golang", "maven"} and name:
        return ("go" if kind == "golang" else kind, name)
    return None


def _package_mapping(record, package):
    items = (record.get("containers") or {}).get("cna", {}).get("affected") or []
    explicit = []
    for item in items:
        if not isinstance(item, dict):
            continue
        names = (item.get("product"), item.get("packageName"))
        mapping = _purl(item.get("packageURL"))
        identities = {str(n).casefold() for n in names if n}
        if mapping:
            identities.add(mapping[1].casefold())
        if package and package.casefold() not in identities:
            continue
        if mapping:
            explicit.append((mapping, item))
    identities = {mapping for mapping, _ in explicit}
    if len(identities) == 1:
        return explicit[0]
    return None, None


def _repositories(osv, record):
    values = []
    for item in osv.get("affected") or []:
        for rng in item.get("ranges") or []:
            if rng.get("type") == "GIT" and (repo := _repo(str(rng.get("repo") or ""))):
                values.append(repo)
    for item in (record.get("containers") or {}).get("cna", {}).get("affected") or []:
        for key in ("repo", "collectionURL"):
            if repo := _repo(str(item.get(key) or "")):
                values.append(repo)
    return list(dict.fromkeys(values))


def _fix(discovery, metadata, osv, record):
    """Repair an empty/dead patch URL, including the same SHA in a declared upstream."""
    collector = metadata.collector
    source = next((s for s in collector.sources if s.get("id") == discovery.fix_source_id), {})
    body = _text(source, collector.run_dir)
    sha = _patch_sha(source, collector.run_dir)
    repo = _repo(str(source.get("url") or ""))
    if len(re.findall(r"^From [0-9a-f]{40}\b", body, re.MULTILINE)) > 1:
        from .discovery import DiscoveryRef, _commit_sha, _github_api_commit

        api_url = _github_api_commit(str(source.get("url") or ""))
        if api_url:
            document, source_id = metadata.get(api_url, "upstream_commit")
            resolved = _commit_sha(json.dumps(document), str(source.get("url") or "")) if document else None
            response_repo = _repo(str(document.get("html_url") or document.get("url") or ""))
            if (resolved and response_repo and response_repo.casefold() == (repo or "").casefold()
                    and _has_patch(json.dumps(document))):
                metadata.notes.append(f"multi-commit patch mailbox replaced by requested commit metadata: {resolved}; source={source_id}")
                for entry in collector.sources:
                    if entry["id"] == source_id:
                        entry["source_type"] = "upstream_commit"
                return replace(discovery, fix_commit=resolved, fix_source_id=source_id,
                    fixed=DiscoveryRef("commit", resolved, repository=repo, resolved_commit=resolved, source_id=source_id)), repo
        # Do not recover the obsolete first mailbox entry via its own API URL.
        metadata.notes.append("multi-commit patch mailbox has no verified requested commit metadata")
        return replace(discovery, fix_commit=None, fix_source_id=None), repo
    if repo and sha and sha == discovery.fix_commit:
        return discovery, repo
    hashes = [discovery.fix_commit] if discovery.fix_commit else []
    referenced = []
    for url in discovery.references:
        match = re.search(r"/commit/([0-9a-f]{40})(?:\b|\.)", url)
        if match:
            hashes.append(match[1])
            if repo_url := _repo(url):
                referenced.append(repo_url)
    for item in osv.get("affected") or []:
        for rng in item.get("ranges") or []:
            for event in rng.get("events") or []:
                if _SHA.fullmatch(str(event.get("fixed") or "")):
                    hashes.append(event["fixed"])
    hashes = list(dict.fromkeys(hashes))
    if len(hashes) != 1:
        return replace(discovery, fix_commit=None, fix_source_id=None), repo
    expected = hashes[0]
    repos = {r.casefold(): r for r in [*_repositories(osv, record), *referenced]}
    for candidate_repo in list(repos.values())[:3]:
        doc, source_id = metadata.commit(candidate_repo, expected, "upstream_commit")
        if doc:
            repo = candidate_repo
            if not _has_patch(json.dumps(doc)):
                metadata.notes.append(f"referenced commit {expected} has no file diff; its fix evidence remains unresolved")
        if doc and _has_patch(json.dumps(doc)):
            # A previously cached commit JSON may have been fetched as metadata.
            for entry in collector.sources:
                if entry["id"] == source_id:
                    entry["source_type"] = "upstream_commit"
            metadata.notes.append(f"fix recovered from declared repository {candidate_repo}, same SHA {expected}; source={source_id}")
            return replace(discovery, fix_commit=expected, fix_source_id=source_id), candidate_repo
    return replace(discovery, fix_commit=expected, fix_source_id=None), repo


def _fix_search_repo(discovery, repo, osv, record):
    """Search only an identified upstream, never every GitHub link in an advisory."""
    if repo:
        return repo
    declared = _repositories(osv, record)
    for ref in (record.get("containers") or {}).get("cna", {}).get("references") or []:
        if isinstance(ref, dict) and "product" in (ref.get("tags") or []):
            if value := _repo(str(ref.get("url") or "")):
                declared.append(value)
    if not declared:
        declared = [_repo(url) for url in discovery.references if "/commit/" in url]
    unique = {value.casefold(): value for value in declared if value}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _application_patch(document):
    """Conservative search filter: reject docs/tests and pure own-version bumps.

    This is a candidate filter, not a proof of the CVE mechanism. Dependency
    edits can be substantive; the presence of a Python file alone is not.
    """
    version_line = re.compile(
        r"(?:__version__|VERSION|version|[\"']version[\"'])\s*[:=]\s*[\"'][^\"']+[\"']\s*,?\s*$"
    )
    for file in document.get("files") or []:
        if not isinstance(file, dict) or not file.get("filename"):
            continue
        path = str(file.get("filename") or "").lower()
        parts = path.split("/")
        name = parts[-1]
        if (any(p in {"test", "tests", "docs", "doc", "documentation", "__tests__"} for p in parts[:-1])
                or name.startswith(("test_", "readme", "changelog", "license"))
                or name.endswith((".md", ".rst", ".txt", "_test.go", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))):
            continue
        changes = [line[1:].strip() for line in str(file.get("patch") or "").splitlines()
                   if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
        changes = [line for line in changes if line and not line.startswith(("#", "//", "/*", "*", "<!--"))]
        if changes and not all(version_line.fullmatch(line) for line in changes):
            return True
    return False


def _search_fix_pair(discovery, metadata, repo):
    """Find one CVE-named fix and replace the whole pair with fix/unique-parent."""
    from .discovery import DiscoveryRef

    def defer(message):
        metadata.notes.append(message)
        metadata.decision("cve_named_fix_parent", "unresolved", message)

    if not repo:
        defer("CVE commit search requires an identified upstream repository")
        return None
    exact_cve = re.compile(r"(?<![A-Za-z0-9])" + re.escape(discovery.cve_id) + r"(?![A-Za-z0-9])", re.IGNORECASE)
    query = urllib.parse.urlencode({"q": f"repo:{repo} {discovery.cve_id}", "per_page": MAX_FIX_SEARCH_RESULTS})
    document, search_id = metadata.get("https://api.github.com/search/commits?" + query)
    items, total = document.get("items"), document.get("total_count")
    if (document.get("incomplete_results") is not False or type(total) is not int
            or not isinstance(items, list) or not 0 <= total <= MAX_FIX_SEARCH_RESULTS
            or len(items) != total):
        defer("CVE commit search deferred: result set unavailable, incomplete, or over the bounded limit")
        return None
    if not items:
        defer(f"CVE commit search found no matching commits in {repo}")
        return None
    seen, eligible = set(), []
    for hit in items:
        if (not isinstance(hit, dict) or not isinstance(hit.get("commit"), dict)
                or not isinstance(hit.get("repository") or {}, dict)):
            defer("CVE commit search deferred: malformed search hit")
            return None
        sha = str(hit.get("sha") or "")
        hit_repo = str((hit.get("repository") or {}).get("full_name") or _repo(str(hit.get("html_url") or "")) or "")
        if not _SHA.fullmatch(sha) or sha in seen or hit_repo.casefold() != repo.casefold():
            defer("CVE commit search deferred: duplicate/invalid SHA or repository mismatch")
            return None
        seen.add(sha)
        message = str((hit.get("commit") or {}).get("message") or "")
        subject = message.splitlines()[0] if message else ""
        if not exact_cve.search(message) or not _FIX_SUBJECT.match(subject):
            continue
        commit, source_id = metadata.commit(repo, sha)
        if not commit:
            # A failed lookup is an unexamined candidate, not evidence that the
            # other successfully fetched candidate is unique.
            defer("CVE commit search deferred: a potential fix could not be inspected within the source budget")
            return None
        message = str(commit.get("commit", {}).get("message") or "") if isinstance(commit.get("commit"), dict) else ""
        subject = message.splitlines()[0] if message else ""
        if not exact_cve.search(message) or not _FIX_SUBJECT.match(subject):
            defer("CVE commit search deferred: search hit and commit metadata disagree")
            return None
        parents = commit.get("parents") or []
        if not isinstance(parents, list) or len(parents) != 1 or not isinstance(parents[0], dict):
            continue
        files = commit.get("files")
        if (not isinstance(files, list) or any(not isinstance(file, dict) for file in files)
                or any(file.get("changes") and not file.get("patch") for file in files)):
            defer("CVE commit search deferred: a potential fix has unavailable file patches")
            return None
        parent = str(parents[0].get("sha") or "")
        if not _SHA.fullmatch(parent) or parent == sha or not _application_patch(commit):
            continue
        eligible.append((sha, parent, source_id))
    if len(eligible) != 1:
        defer(f"CVE commit search deferred: {len(eligible)} eligible single-parent fixes")
        return None
    sha, parent, source_id = eligible[0]
    for source in metadata.collector.sources:
        if source["id"] == source_id:
            source["source_type"] = "upstream_commit"
    metadata.notes.append(
        f"deterministic ref rule=cve_named_fix_parent: search={search_id}; fix={source_id}; "
        f"replaced both refs with commit {parent} -> {sha}; supersedes advertised fix {discovery.fix_commit}; "
        "candidate requires downstream vulnerable/fixed differential validation"
    )
    # Return both sides together. Do not let the registry/CNA-version fallback
    # below combine this newly found fix with a stale vulnerable package ref.
    return replace(
        discovery, package=repo, ecosystem="generic",
        vulnerable=DiscoveryRef("commit", parent, repository=repo, resolved_commit=parent, source_id=source_id),
        fixed=DiscoveryRef("commit", sha, repository=repo, resolved_commit=sha, source_id=source_id),
        fix_commit=sha, fix_source_id=source_id,
        references=tuple(dict.fromkeys([*discovery.references, f"https://github.com/{repo}/commit/{sha}"])),
    )


def _version(value):
    if _SHA.fullmatch(str(value)):
        return None
    try:
        return Version(str(value).lstrip("vV"))
    except InvalidVersion:
        return None


def _release_pair(item, preferred=None, fixed_hint=None):
    """Select one consistent release branch instead of rejecting other branches."""
    rows = [r for r in item.get("versions") or [] if isinstance(r, dict)]
    affected = [r for r in rows if r.get("status") == "affected" and r.get("versionType") != "git" and not r.get("changes")]
    if not affected:
        return None, None, None
    pool = []
    for row in affected:
        for value in (row.get("lessThanOrEqual"), row.get("version")):
            if (value and str(value).lower() not in _OPEN_BOUND and _version(value) is not None
                    and _supported_affected(item, value)):
                pool.append(value)
    if preferred and _ref_version(preferred) is not None and _supported_affected(item, preferred):
        bad = preferred
    else:
        # A known fixed release can select a branch if there is no usable
        # vulnerable hint. Otherwise choose a literal declared affected value.
        branch = [r for r in affected if r.get("lessThan") == fixed_hint] if fixed_hint else []
        narrowed = [v for v in pool if any(_row_match(r, v) is True for r in branch)] if branch else pool
        bad = max(narrowed, key=_ref_version) if narrowed else None
    matching = [r for r in affected if bad and _row_match(r, bad) is True]
    if not matching and len(affected) == 1:
        matching = affected
    bounds = [str(r["lessThan"]) for r in matching if r.get("lessThan") and _version(r["lessThan"]) is not None]
    exclusive = min(bounds, key=_version) if bounds else None
    good = [str(r["version"]) for r in rows if r.get("status") == "unaffected" and r.get("versionType") != "git"
            and not r.get("changes") and not r.get("lessThan") and not r.get("lessThanOrEqual")
            and _version(r.get("version")) is not None and _item_status(item, str(r["version"])) == "unaffected"]
    if exclusive and (_item_status(item, exclusive) == "unaffected" or exclusive == fixed_hint):
        good.append(exclusive)
    if fixed_hint and _version(fixed_hint) is not None and _item_status(item, fixed_hint) not in {"affected", "conflict"}:
        good.append(fixed_hint)
    good = [v for v in good if not bad or _ref_version(v) > _ref_version(bad)]
    return bad, min(good, key=_version) if good else None, exclusive


def _registry_ref(metadata, ecosystem, package, value, *, expected_repo=None):
    from .discovery import DiscoveryRef, _normalize_go_version, _normalize_release, _registry_url

    if not value or _SHA.fullmatch(value):
        return None
    value = _normalize_release(value)
    if ecosystem == "go":
        value = _normalize_go_version(value)
    if ecosystem == "pypi":
        version = _version(value)
        if version is None:
            return None
        value = str(version)
    url = _registry_url(ecosystem, package, value)
    if not url:
        return None
    source = metadata.source(url, "release_notes")
    body = _text(source, metadata.collector.run_dir)
    document = _json(body)
    valid = False
    if ecosystem in {"pypi", "npm"}:
        identity = (document.get("info") or {}) if ecosystem == "pypi" else document
        name = str(identity.get("name") or "")
        def normalize(x):
            return re.sub(r"[-_.]+", "-", x).casefold() if ecosystem == "pypi" else x
        actual = str(identity.get("version") or "")
        valid = normalize(name) == normalize(package) and actual == value
        if valid and expected_repo:
            urls = list((identity.get("project_urls") or {}).values())
            urls.append(identity.get("home_page") or "")
            repository = document.get("repository") or {}
            urls.append(repository.get("url", "") if isinstance(repository, dict) else repository)
            valid = any((_repo(str(u).removeprefix("git+")) or "").casefold() == expected_repo.casefold() for u in urls)
        package = name or package
    elif ecosystem == "go":
        valid = str(document.get("Version") or "").lstrip("v") == value.lstrip("v")
    elif ecosystem == "maven":
        import xml.etree.ElementTree as ET
        try:
            pom = ET.fromstring(body)
            fields = {e.tag.rsplit("}", 1)[-1]: (e.text or "").strip() for e in pom}
            group, artifact = package.split(":", 1)
            valid = fields.get("artifactId") == artifact and fields.get("version") == value
            valid = valid and (fields.get("groupId") in (None, group))
        except (ET.ParseError, ValueError):
            pass
    if valid:
        ref = DiscoveryRef("package_version", value, ecosystem=ecosystem, package=package, url=url, source_id=source["id"])
        metadata.decision("registry_identity", "verified", "registry package name and version match",
                          candidate=ref.to_json(), source_ids=[source["id"]])
        return ref
    metadata.decision("registry_identity", "rejected" if source.get("status") == "ok" else "unresolved",
                      "registry identity did not verify", candidate={"kind": "package_version", "ecosystem": ecosystem,
                      "package": package, "value": value}, source_ids=[source.get("id")])
    return None


def _range_allows(expression, value):
    """Evaluate advisory release comparisons using the same version parser as CNA.

    Unsupported syntax is unknown, never silently discarded. Git SHAs are
    excluded by _version; a registry version is not a Git range endpoint.
    """
    if not expression:
        return True
    current = _ref_version(value)
    if current is None:
        return None
    outcomes = []
    for branch in expression.split("||"):
        clauses = re.findall(r"(>=|<=|==|>|<|=)\s*([^\s,]+)", branch)
        remainder = re.sub(r"(>=|<=|==|>|<|=)\s*([^\s,]+)", "", branch).strip(" ,")
        if not clauses or remainder:
            outcomes.append(None)
            continue
        result = True
        for operator, bound in clauses:
            end = _version(bound)
            if end is None:
                result = None
                break
            if not {">=": current >= end, "<=": current <= end, ">": current > end,
                    "<": current < end, "=": current == end, "==": current == end}[operator]:
                result = False
        outcomes.append(result)
    return True if True in outcomes else None if None in outcomes else False


def _release_allowed(item, value, known=(), fixed_hint=None, affected_range=None):
    version, boundary = _ref_version(value), _ref_version(fixed_hint)
    return (version is not None and _range_allows(affected_range, value) is True
            and (not item or not item.get("versions") or _supported_affected(item, value, known))
            and (boundary is None or version < boundary))


def _registry_candidates(metadata, item, ecosystem, package, old_vulnerable, old_fixed, *, known=(), affected_range=None):
    def plain(value):
        for separator in ("@", "=="):
            prefix = package + separator
            if value and value.startswith(prefix):
                return value[len(prefix):]
        return value
    old_vulnerable, old_fixed = plain(old_vulnerable), plain(old_fixed)
    known = tuple(plain(v) for v in known)
    has_rows = bool(item and item.get("versions"))

    def allowed(value):
        return _version(value) is not None and _release_allowed(item, value, known, old_fixed, affected_range)

    hints = [v for v in dict.fromkeys([old_vulnerable, *known]) if v]
    eligible, excluded = [], []
    for value in hints:
        if allowed(value):
            eligible.append(value)
        else:
            excluded.append(value)
    if excluded:
        metadata.decision("affected_release_filter", "filtered", "release labels outside the supported namespace, affected scope or fix boundary were excluded; full input remains in the cited records",
                          source_ids=[s.get("id") for s in metadata.collector.sources if s.get("source_type") in {"cve_record", "vendor_advisory"}
                                      or "api.osv.dev/" in s.get("url", "")],
                          input_count=len(hints), eligible_count=len(eligible), excluded_count=len(excluded),
                          excluded_examples=excluded[:5])
    if old_vulnerable in excluded:
        metadata.decision("affected_release", "rejected", "previous vulnerable hint is outside the supported affected scope or fix boundary",
                          candidate=old_vulnerable)
    preferred = old_vulnerable if old_vulnerable in eligible else max(eligible, key=_version, default=None)
    if has_rows:
        bad, good, exclusive = _release_pair(item, preferred, old_fixed)
    else:
        bad, good, exclusive = preferred, old_fixed, old_fixed if _version(old_fixed) is not None else None
    if bad and not allowed(bad):
        bad = None
    if not good and old_fixed and (_SHA.fullmatch(old_fixed) or _item_status(item, old_fixed) not in {"affected", "conflict"}):
        good = old_fixed
    # Preserve the bounded near-fix preference of collection, but every probe
    # now uses the same range predicate and registry identity validator. A
    # generated label is only a query, never evidence that a release exists.
    nearby = re.fullmatch(r"(.*?)(\d+)([^0-9]*)", str(good or "")) if _version(good) is not None else None
    if not old_vulnerable and affected_range and nearby:
        prefix, number, suffix = nearby.groups()
        for delta in range(1, min(4, int(number)) + 1):
            candidate = f"{prefix}{int(number) - delta}{suffix}"
            if not allowed(candidate):
                metadata.decision("nearby_release", "rejected", "numeric neighbor is outside the supported affected scope", candidate=candidate)
                continue
            verified = _registry_ref(metadata, ecosystem, package, candidate)
            if verified:
                bad = verified.value
                metadata.decision("nearby_release", "candidate", "first existing release in bounded near-fix probes, with matching registry identity and affected scope",
                                  candidate=verified.to_json(), source_ids=[verified.source_id])
                break
    # Only the actual registry's list decides which prerelease precedes a fix.
    if exclusive and (not bad or _version(bad) is None or _version(bad) >= _version(exclusive)):
        bad = None
    if not bad and exclusive and ecosystem in {"pypi", "npm"}:
        url = (f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/json" if ecosystem == "pypi"
               else f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}")
        doc, catalog_source = metadata.get(url)
        published = doc.get("releases" if ecosystem == "pypi" else "versions") or {}
        candidates = [v for v in published if allowed(v) and _version(v) < _version(exclusive)]
        if candidates:
            bad = max(candidates, key=_version)
            metadata.decision("published_affected_release", "candidate", "highest published version satisfying the affected scope and fix boundary",
                              candidate=bad, source_ids=[catalog_source])
    metadata.decision("registry_pair_candidates", "candidate" if bad else "unresolved",
                      "release candidates constrained by CNA/OSV/advisory versions; registry identity still required",
                      vulnerable=bad, fixed=good, affected_range=affected_range)
    return bad, good


def _go_boundary(advisories, package):
    boundaries = set()
    for advisory in advisories:
        for vuln in advisory.get("vulnerabilities") or []:
            if (vuln.get("package") or {}).get("name") != package:
                continue
            match = re.fullmatch(r"\s*<=\s*v?\d+\.\d+\.\d+-(?:0\.|[0-9A-Za-z.-]+\.0\.)?(\d{14})-([0-9a-f]{12,40})(?:\+incompatible)?\s*", str(vuln.get("vulnerable_version_range") or ""))
            if match:
                boundaries.add(match.group(2))
    return next(iter(boundaries)) if len(boundaries) == 1 else None


def _wordpress_slug(references):
    slugs = set()
    for url in references:
        parsed = urllib.parse.urlsplit(url)
        match = None
        if parsed.hostname == "plugins.trac.wordpress.org":
            match = re.match(r"/browser/([a-z0-9-]+)/", parsed.path)
        elif parsed.hostname == "wordpress.org":
            match = re.match(r"/plugins/([a-z0-9-]+)(?:/|$)", parsed.path)
        if match:
            slugs.add(match.group(1))
    return next(iter(slugs)) if len(slugs) == 1 else None


def _wordpress_archive(metadata, slug, version, url):
    from .discovery import DiscoveryRef

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "downloads.wordpress.org":
        return None
    if parsed.path != f"/plugin/{slug}.{version}.zip":
        return None
    source = metadata.source(url, "release_notes")
    if source.get("status") != "ok":
        return None
    raw = (metadata.collector.run_dir / source["local_path"]).read_bytes()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            # Inspect headers only, without extracting or executing the plugin.
            files = [i for i in archive.infolist() if i.filename.startswith(slug + "/")
                     and i.filename.count("/") == 1 and i.filename.endswith(".php")
                     and i.file_size <= 256_000]
            for info in files[:20]:
                header = archive.read(info).decode("utf-8", errors="replace")[:8192]
                if not re.search(r"(?im)^\s*(?:\*\s*)?Plugin Name:", header):
                    continue
                match = re.search(r"(?im)^\s*(?:\*\s*)?Version:\s*([^\s*]+)", header)
                if match and match.group(1) == version:
                    return DiscoveryRef("archive", version, ecosystem="wordpress", package=slug,
                                        url=url, sha256=source["content_sha256"], source_id=source["id"])
    except (zipfile.BadZipFile, RuntimeError, OSError):
        pass
    metadata.notes.append(f"WordPress archive identity could not be verified: {url}")
    return None


def _wordpress_pair(metadata, slug, item, repo, fix):
    bad, good, _ = _release_pair(item or {})
    if not bad:
        return None, None
    query = urllib.parse.urlencode({"action": "plugin_information", "request[slug]": slug,
                                   "request[fields][versions]": "true"})
    info, _ = metadata.get(f"https://api.wordpress.org/plugins/info/1.2/?{query}")
    if info.get("slug") != slug:
        return None, None
    versions = info.get("versions") or {}
    if not good:
        source = metadata.source(f"https://api.github.com/repos/{repo}/tags?per_page=100")
        try:
            tags = json.loads(_text(source, metadata.collector.run_dir))
        except ValueError:
            tags = []
        if isinstance(tags, list):
            matches = [str(t.get("name") or "").lstrip("vV") for t in tags
                       if isinstance(t, dict) and (t.get("commit") or {}).get("sha") == fix]
            matches = [v for v in matches if v in versions]
            if len(set(matches)) == 1:
                good = matches[0]
    vulnerable = _wordpress_archive(metadata, slug, bad, str(versions.get(bad) or ""))
    fixed = _wordpress_archive(metadata, slug, good, str(versions.get(good) or "")) if good else None
    return vulnerable, fixed


def _verify_ref(metadata, ref, fix_commit):
    """One identity check shared by newly selected refs and saved checkpoints."""
    source = next((s for s in metadata.collector.sources if s.get("id") == ref.source_id), {})
    body = _text(source, metadata.collector.run_dir)
    if ref.kind == "package_version":
        actual = _registry_ref(metadata, ref.ecosystem, ref.package, ref.value) if ref.package else None
    elif ref.kind == "archive":
        actual = _wordpress_archive(metadata, ref.package, ref.value, ref.url or "")
    elif ref.kind == "tag":
        actual = metadata.tag(ref.repository, ref.value) if ref.repository else None
    elif ref.kind == "commit" and body:
        doc = _json(body)
        parents = doc.get("parents") or []
        parent = (doc.get("sha") == fix_commit and len(parents) == 1
                  and isinstance(parents[0], dict) and parents[0].get("sha") == ref.value)
        same_repo = (_repo(source.get("url", "")) or "").casefold() == (ref.repository or "").casefold()
        return same_repo and ref.resolved_commit == ref.value and (
            doc.get("sha") == ref.value or _patch_sha(source, metadata.collector.run_dir) == ref.value or parent)
    else:
        return False
    return bool(actual and actual == ref)


def _verify_pair(metadata, discovery):
    """Validate metadata identities and ancestry, not CVE mechanism correctness."""
    if not discovery.is_complete:
        return False
    collector = metadata.collector
    fix_source = next((s for s in collector.sources if s.get("id") == discovery.fix_source_id), {})
    if _patch_sha(fix_source, collector.run_dir) != discovery.fix_commit:
        return False
    if any(r.kind == "package_version" for r in (discovery.vulnerable, discovery.fixed)):
        record, osv, advisories = _records(collector)
        _, item = _package_mapping(record, discovery.package)
        if item is None:
            item, _ = _affected(record, discovery.package, _repo(fix_source.get("url", "")) or "")
        if (any(r.get("versionType") == "git" and r.get("status") == "affected" for r in (item or {}).get("versions") or [])
                and not _registry_identified(discovery, osv, advisories)):
            return False
    for ref in (discovery.vulnerable, discovery.fixed):
        if not _verify_ref(metadata, ref, discovery.fix_commit):
            metadata.decision("ref_identity", "rejected", "selected ref does not match its saved evidence",
                              candidate=ref.to_json(), source_ids=[ref.source_id])
            return False
    if discovery.vulnerable.resolved_commit and discovery.fixed.resolved_commit:
        parent = False
        for source in collector.sources:
            if source.get("id") not in {discovery.fix_source_id, discovery.vulnerable.source_id}:
                continue
            doc = _json(_text(source, collector.run_dir))
            parents = doc.get("parents") or []
            parent = parent or (doc.get("sha") == discovery.fix_commit and len(parents) == 1
                                and isinstance(parents[0], dict) and parents[0].get("sha") == discovery.vulnerable.resolved_commit)
        same_repo = discovery.vulnerable.repository.casefold() == discovery.fixed.repository.casefold()
        if not same_repo or (not parent and metadata.precedes(discovery.fixed.repository,
                discovery.vulnerable.resolved_commit, discovery.fix_commit) is not True):
            metadata.decision("git_ancestry", "rejected", "vulnerable commit was not verified before fixed in the same repository",
                              candidate=discovery.vulnerable.to_json())
            return False
        if discovery.fixed.resolved_commit != discovery.fix_commit and metadata.precedes(
                discovery.fixed.repository, discovery.fix_commit, discovery.fixed.resolved_commit) is not True:
            metadata.decision("git_ancestry", "rejected", "fixed endpoint does not contain the reported fix",
                              candidate=discovery.fixed.to_json())
            return False
    return True


def verify_proposed_pair(settings, run_dir, evidence, discovery):
    """Resolve and validate exactly the proposed pair, without selecting another.

    Used for author-requested corrections: falling back to automatic selection
    could otherwise silently reinstate the pair that the author challenged.
    """
    from .discovery import DiscoveryRef
    from .util import PipelineError

    collector = EvidenceCollector(settings, Path(run_dir), sources=[dict(s) for s in evidence.get("sources", [])])
    metadata = _Metadata(collector, list(discovery.notes))
    metadata.trace = list(discovery.selection_trace)
    fix_source = next((s for s in collector.sources if s.get("id") == discovery.fix_source_id), {})
    repo = _repo(str(fix_source.get("url") or ""))
    if not repo or _patch_sha(fix_source, collector.run_dir) != discovery.fix_commit:
        raise PipelineError("proposed fix is not backed by a matching upstream patch")
    checked = {}
    try:
        for role in ("vulnerable", "fixed"):
            ref = getattr(discovery, role)
            actual = None
            if ref and ref.kind == "package_version":
                actual = _registry_ref(metadata, ref.ecosystem or discovery.ecosystem, ref.package or discovery.package, ref.value)
            elif ref and ref.kind in {"tag", "commit"}:
                repository = ref.repository or repo
                if repository.casefold() != repo.casefold():
                    raise PipelineError("proposed source endpoints and fix must belong to the same repository")
                if ref.kind == "tag":
                    actual = metadata.tag(repository, ref.value)
                elif ref.value == discovery.fix_commit:
                    actual = DiscoveryRef("commit", ref.value, repository=repository, resolved_commit=ref.value,
                                          source_id=discovery.fix_source_id)
                else:
                    doc, source_id = metadata.commit(repository, ref.value)
                    if doc:
                        actual = DiscoveryRef("commit", doc["sha"], repository=repository, resolved_commit=doc["sha"], source_id=source_id)
            elif ref and ref.kind == "archive":
                actual = _wordpress_archive(metadata, ref.package, ref.value, ref.url)
            if not actual:
                raise PipelineError(f"proposed {role} ref could not be verified")
            if ref.resolved_commit and ref.resolved_commit != actual.resolved_commit:
                raise PipelineError(f"proposed {role} resolved_commit does not match upstream")
            if ref.sha256 and ref.sha256 != actual.sha256:
                raise PipelineError(f"proposed {role} archive digest does not match upstream")
            checked[role] = actual
        candidate = replace(discovery, **checked)
        if not _verify_pair(metadata, candidate):
            raise PipelineError("proposed pair failed shared identity/ancestry validation")
        return _finish(metadata, candidate, "reviewed_ref_pair")
    finally:
        collector.save(discovery.cve_id)


def _finish(metadata, discovery, rule):
    from .discovery import DiscoveryRef, _checksum_url

    if discovery.is_complete and not _verify_pair(metadata, discovery):
        metadata.decision("pair_validation", "rejected", "shared identity/ancestry validation failed")
        discovery = replace(discovery, vulnerable=DiscoveryRef("unresolved", discovery.vulnerable.value))
    # Artifact pins are fetched for the selected package refs only, never for
    # a discarded preliminary release. They share the metadata request budget.
    for ref in (discovery.vulnerable, discovery.fixed):
        if ref and ref.kind == "package_version" and ref.ecosystem in {"go", "maven"}:
            url = _checksum_url(ref.ecosystem, ref.package, ref.value)
            if url and metadata.source(url, "release_notes").get("status") != "ok" and ref.ecosystem == "go":
                metadata.source(url + "+incompatible", "release_notes")
    metadata.decision(rule or "no_supported_pair", "selected" if discovery.is_complete else "unresolved",
                      "metadata-complete build candidate; CVE mechanism requires downstream validation" if discovery.is_complete
                      else "no complete pair passed the available evidence checks",
                      vulnerable=discovery.vulnerable.to_json() if discovery.vulnerable else None,
                      fixed=discovery.fixed.to_json() if discovery.fixed else None,
                      fix_commit=discovery.fix_commit, mechanism_verified=False,
                      source_ids=[discovery.fix_source_id, discovery.vulnerable.source_id if discovery.vulnerable else None,
                                  discovery.fixed.source_id if discovery.fixed else None])
    return metadata.collector.save(discovery.cve_id), replace(discovery, notes=tuple(dict.fromkeys(metadata.notes)),
                                                             selection_trace=tuple(metadata.trace))



def complete_missing_refs(
    settings: SourceSettings, run_dir: Path, evidence: dict, discovery: Discovery,
) -> tuple[dict, Discovery]:
    """Resolve typed build refs, including incomplete or incorrectly mapped caches."""
    from .discovery import DiscoveryRef, _package_facts

    root = Path(run_dir)
    sources = evidence.get("sources") or []
    collector = EvidenceCollector(settings, root, sources=[dict(s) for s in sources])
    cached = _Metadata(collector, [])
    cached.requests = MAX_REF_REQUESTS  # cache validation must never fetch
    if _verify_pair(cached, discovery):
        last = discovery.selection_trace[-1] if discovery.selection_trace else {}
        if (last.get("vulnerable") == discovery.vulnerable.to_json() and last.get("fixed") == discovery.fixed.to_json()
                and last.get("fix_commit") == discovery.fix_commit):
            return evidence, discovery
        cached.notes = list(discovery.notes)
        cached.decision("cached_pair", "reused", "saved identities and ancestry revalidated; original selection history is unavailable")
        return _finish(cached, discovery, "cached_pair")
    notes = [note for note in discovery.notes if not note.startswith("deterministic ref rule=")]
    metadata = _Metadata(collector, notes)
    record, osv, advisories = _records(collector)
    if not discovery.affected_range:
        discovery = replace(discovery, affected_range=_package_facts(osv, advisories, record)[4])
    metadata.decision("input_evidence", "candidate", "version hints are reselected and verified through the shared ref pipeline",
                      source_ids=[s.get("id") for s in collector.sources if s.get("source_type") in {"cve_record", "vendor_advisory"}
                                  or "api.osv.dev/" in s.get("url", "")],
                      vulnerable_hint=discovery.vulnerable_ref, fixed_hint=discovery.fixed_ref,
                      affected_range=discovery.affected_range)
    mapping, purl_item = _package_mapping(record, discovery.package)
    if mapping:
        ecosystem, package = mapping
        if (ecosystem, package) != (discovery.ecosystem, discovery.package):
            notes.append(f"package identity from CNA packageURL: {ecosystem}:{package}")
        discovery = replace(discovery, ecosystem=ecosystem, package=package)
        metadata.decision("package_url_identity", "verified", "CNA packageURL explicitly identifies the registry package",
                          ecosystem=ecosystem, package=package)
    discovery, repo = _fix(discovery, metadata, osv, record)
    metadata.decision("upstream_fix", "verified" if discovery.fix_source_id else "unresolved",
                      "commit identity and nonempty patch checked; semantic relevance is not established" if discovery.fix_source_id
                      else "advertised fix lacks verified patch evidence", candidate=discovery.fix_commit,
                      source_ids=[discovery.fix_source_id])
    if not discovery.fix_source_id:
        searched = _search_fix_pair(discovery, metadata, _fix_search_repo(discovery, repo, osv, record))
        if searched is not None:
            stale = ("no concrete vulnerable release", "no fixed release", "no fetchable upstream fix commit")
            notes[:] = [note for note in notes if not note.startswith(stale)]
            return _finish(metadata, searched, "cve_named_fix_parent")
    rule = ""
    if not discovery.fix_commit or not repo:
        discovery = replace(discovery, fixed=None)
    else:
        fixed = DiscoveryRef("commit", discovery.fix_commit, repository=repo,
                             resolved_commit=discovery.fix_commit, source_id=discovery.fix_source_id)
        vulnerable = None
        item, reason = (purl_item, "") if purl_item else _affected(record, discovery.package, repo)
        known = _affected_refs(metadata, osv, discovery, repo)
        metadata.decision("affected_scope", "matched" if item else "unresolved", reason or "CNA product matched to the selected package/repository",
                          source_ids=[s.get("id") for s in collector.sources if s.get("source_type") == "cve_record"],
                          package=discovery.package, repository=repo, versions=(item or {}).get("versions", []),
                          default_status=(item or {}).get("defaultStatus"))
        # GHSA/OSV can identify a registry package even when CNA uses a
        # different product display name. Explicit repository conflicts still
        # require reconciliation; absence of a CNA name match is not one.
        registry_identified = _registry_identified(discovery, osv, advisories)
        registry_allowed = not reason or (reason == "no unique exact CNA product match" and registry_identified)
        git_namespace = any(r.get("versionType") == "git" and r.get("status") == "affected"
                            for r in (item or {}).get("versions") or [])
        if git_namespace and not registry_identified:
            registry_allowed = False
            notes.append("CNA versionType=git retained: registry publication alone does not map Git refs to package versions")
            metadata.decision("ref_namespace", "rejected", "Git affected ranges cannot be coerced into a same-named registry release")
        slug = _wordpress_slug(discovery.references)
        if slug and item and not reason:
            vulnerable, published_fixed = _wordpress_pair(metadata, slug, item, repo, discovery.fix_commit)
            fixed = published_fixed or fixed
            rule = "wordpress_verified_archive"

        # A Go pseudo-version names a commit, not the numeric release prefix.
        boundary = _go_boundary(advisories, discovery.package) if discovery.ecosystem == "go" else None
        if not vulnerable and boundary and registry_allowed:
            document, source_id = metadata.commit(repo, boundary)
            if document and document["sha"] != discovery.fix_commit:
                vulnerable = DiscoveryRef("commit", document["sha"], repository=repo,
                                           resolved_commit=document["sha"], source_id=source_id)
                rule = "go_pseudo_version_commit"

        if not vulnerable and discovery.ecosystem in {"pypi", "npm", "maven", "go"} and not boundary and registry_allowed:
            bad, good = _registry_candidates(metadata, item, discovery.ecosystem, discovery.package,
                                             discovery.vulnerable_ref, discovery.fixed_ref, known=known,
                                             affected_range=discovery.affected_range)
            if good and not _SHA.fullmatch(good):
                published_fixed = _registry_ref(metadata, discovery.ecosystem, discovery.package, good)
                if published_fixed:
                    vulnerable = _registry_ref(metadata, discovery.ecosystem, discovery.package, bad)
                    if vulnerable:
                        fixed, rule = published_fixed, "cna_registry_pair"

        if not vulnerable and not slug and not reason:
            candidates, parent_allowed, ambiguity = _candidates(item, discovery.fix_commit,
                discovery.vulnerable_ref, known, fixed_hint=discovery.fixed_ref,
                affected_range=discovery.affected_range) if item else ([], False, reason)
            rows = (item or {}).get("versions") or []
            unaffected_commits = {r.get("version") for r in rows if r.get("status") == "unaffected"
                                  and _SHA.fullmatch(str(r.get("version") or ""))}
            if ambiguity and not candidates:
                notes.append(f"deterministic refs deferred: {ambiguity}")
            for candidate, candidate_rule in candidates:
                if candidate == discovery.fix_commit:
                    continue
                if _SHA.fullmatch(candidate):
                    document, source_id = metadata.commit(repo, candidate)
                    if document:
                        vulnerable = DiscoveryRef("commit", document["sha"], repository=repo,
                                                   resolved_commit=document["sha"], source_id=source_id)
                else:
                    vulnerable = metadata.tag(repo, candidate)
                if vulnerable and vulnerable.resolved_commit in {discovery.fix_commit, *unaffected_commits}:
                    metadata.decision(candidate_rule, "rejected", "candidate equals the fix or is explicitly unaffected",
                                      candidate=vulnerable.to_json())
                    vulnerable = None
                if vulnerable:
                    precedes = metadata.precedes(repo, vulnerable.resolved_commit, discovery.fix_commit)
                    if precedes is not True:
                        notes.append(f"candidate {candidate} did not verify as an ancestor of the fix ({precedes})")
                        metadata.decision(candidate_rule, "rejected" if precedes is False else "unresolved",
                                          "candidate did not verify as an ancestor of the fix", candidate=candidate)
                        vulnerable = None
                        if precedes is None:
                            break
                if vulnerable:
                    rule = candidate_rule
                    break
                metadata.decision(candidate_rule, "unresolved", "candidate tag/commit identity could not be resolved", candidate=candidate)
            # A missing/stale release tag must not prevent a source build.
            # For a verified application fix, its single parent is a bounded
            # counterfactual candidate. Do not use this for an all-unaffected
            # record, a contradictory literal, an empty diff, or a merge.
            has_scope = _has_affected_scope(item or {}, discovery.fix_commit)
            if not vulnerable and discovery.fix_source_id and (parent_allowed or has_scope):
                document, source_id = metadata.commit(repo, discovery.fix_commit)
                parents = document.get("parents") or []
                if (isinstance(parents, list) and len(parents) == 1 and isinstance(parents[0], dict)
                        and _application_patch(document)):
                    parent = str(parents[0].get("sha") or "")
                    if _SHA.fullmatch(parent) and parent not in {discovery.fix_commit, *unaffected_commits}:
                        git_ends = {str(r.get("lessThan") or r.get("lessThanOrEqual") or "") for r in rows
                                    if r.get("status") == "affected" and r.get("versionType") == "git"
                                    and str(r.get("version") or "").lower() in _OPEN_BOUND}
                        bounds_verified = all(end == discovery.fix_commit or not _SHA.fullmatch(end)
                                              or metadata.precedes(repo, parent, end) is True for end in git_ends)
                        if bounds_verified:
                            vulnerable = DiscoveryRef("commit", parent, repository=repo,
                                                       resolved_commit=parent, source_id=source_id)
                            rule = "fix_single_parent_candidate"
                            metadata.decision(rule, "candidate", "single parent of an application-code change, with supported affected scope",
                                              candidate=vulnerable.to_json(), source_ids=[source_id])
            # Prefer an existing source tag for source-only projects; only
            # then probe a registry whose metadata binds back to this repo.
            if not vulnerable and discovery.ecosystem in (None, "generic") and item and not git_namespace:
                bad, good, _ = _release_pair(item, discovery.vulnerable_ref, discovery.fixed_ref)
                if bad and good:
                    for ecosystem in ("pypi", "npm"):
                        published_fixed = _registry_ref(metadata, ecosystem, discovery.package, good, expected_repo=repo)
                        if published_fixed:
                            vulnerable = _registry_ref(metadata, ecosystem, published_fixed.package, bad)
                            if vulnerable:
                                discovery = replace(discovery, ecosystem=ecosystem, package=published_fixed.package)
                                fixed, rule = published_fixed, "cna_registry_pair"
                                break
            if not vulnerable and discovery.ecosystem in {"pypi", "npm"} and registry_allowed and not git_namespace:
                bad, _ = _registry_candidates(metadata, item, discovery.ecosystem, discovery.package,
                                                 discovery.vulnerable_ref, discovery.fixed_ref, known=known,
                                                 affected_range=discovery.affected_range)
                vulnerable = _registry_ref(metadata, discovery.ecosystem, discovery.package, bad,
                    expected_repo=None if registry_identified or purl_item else repo)
                if vulnerable:
                    rule = "registry_vulnerable_with_source_fix"

        if vulnerable:
            notes.append(f"deterministic ref rule={rule}; vulnerable={vulnerable.kind}:{vulnerable.value}; "
                         f"fixed={fixed.kind}:{fixed.value}; ref_metadata={vulnerable.source_id}; "
                         "candidate requires downstream vulnerable/fixed differential validation")
        elif discovery.vulnerable_ref:
            vulnerable = DiscoveryRef("unresolved", discovery.vulnerable_ref)
        if reason:
            notes.append(f"deterministic refs deferred: {reason}")
            metadata.decision("product_identity", "unresolved", reason)
        discovery = replace(discovery, vulnerable=vulnerable, fixed=fixed)
        if discovery.is_complete:
            stale = ("no concrete vulnerable release", "no fixed release", "no fetchable upstream fix commit")
            notes[:] = [n for n in notes if not n.startswith(stale)]
    return _finish(metadata, discovery, rule)
