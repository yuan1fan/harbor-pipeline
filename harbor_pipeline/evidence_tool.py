"""Restricted helper for the evidence-resolver session.

The resolver uses native web tools for research and this helper to register
evidence, query allowlisted registry/GitHub endpoints, and submit a
reconciliation proposal. This helper's network access goes through
:mod:`harbor_pipeline.sources`, so the existing https/allowlist/public-IP/DNS
policy still applies.

This module is intentionally separate from ``author_tool``. The author helper
can build images and write target files; the resolver must not be able to do
either.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config, SourceSettings, load_config
from .registry import lookup
from .sources import EvidenceCollector
from .util import PipelineError, read_json, utc_now_text, write_json

PROPOSAL_FILE = "reconciliation.json"
RESOLVER_EVIDENCE_INDEX = "resolver-evidence-index.json"

_ALLOWED_SOURCE_TYPES = {
    "cve_record",
    "vendor_advisory",
    "upstream_commit",
    "release_notes",
    "reproduction_reference",
    "other",
}
_SOURCE_TYPE_ALIASES = {"registry_metadata": "other", "registry": "other"}
_FETCH_TYPE_CHOICES = sorted(_ALLOWED_SOURCE_TYPES | set(_SOURCE_TYPE_ALIASES))
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")


@dataclass(frozen=True)
class ToolContext:
    workspace: Path
    run_dir: Path
    cve_id: str
    settings: SourceSettings


def _config_from_env() -> Config:
    path = os.environ.get("HARBOR_EVIDENCE_CONFIG", "").strip()
    if path:
        candidate = Path(path)
        if candidate.is_file():
            config = load_config(candidate)
        else:
            config = Config()
    else:
        config = Config()
    # The parent deliberately strips GITHUB_TOKEN from the model environment.
    # The helper receives only a private token-file path so authenticated
    # GitHub API calls remain available without exposing the credential to the
    # resolver session.
    token_path = os.environ.get("HARBOR_HELPER_GITHUB_TOKEN_FILE", "").strip()
    if token_path:
        try:
            token = Path(token_path).read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
        if token:
            config.sources.github_token = token
    return config


def _context() -> ToolContext:
    raw = os.environ.get("HARBOR_EVIDENCE_WORKSPACE", "").strip()
    if not raw:
        raise PipelineError("HARBOR_EVIDENCE_WORKSPACE is not set")
    workspace = Path(raw).resolve()
    raw_run = os.environ.get("HARBOR_EVIDENCE_RUN_DIR", "").strip()
    run_dir = Path(raw_run).resolve() if raw_run else workspace.parent
    index_path = run_dir / "evidence-index.json"
    if not index_path.is_file():
        raise PipelineError(f"evidence index is missing: {index_path}")
    index = read_json(index_path)
    cve_id = str(index.get("cve_id") or "")
    if not cve_id:
        raise PipelineError("evidence index has no cve_id")
    config = _config_from_env()
    return ToolContext(
        workspace=workspace,
        run_dir=run_dir,
        cve_id=cve_id,
        settings=config.sources,
    )


def _load_collector(ctx: ToolContext) -> tuple[EvidenceCollector, dict[str, Any]]:
    index = read_json(ctx.run_dir / "evidence-index.json")
    collector = EvidenceCollector(settings=ctx.settings, run_dir=ctx.run_dir)
    collector.fetched_at = str(index.get("collected_at") or utc_now_text())
    collector.sources = list(index.get("sources") or [])
    return collector, index


def _save_collector(collector: EvidenceCollector, ctx: ToolContext) -> dict[str, Any]:
    return collector.save(ctx.cve_id)


def _existing_source(collector: EvidenceCollector, url: str) -> dict[str, Any] | None:
    for source in collector.sources:
        if source.get("url") == url and source.get("status") == "ok":
            return source
    return None


def _record_url(
    ctx: ToolContext,
    url: str,
    source_type: str,
    citation: str,
) -> tuple[dict[str, Any], bytes | None]:
    source_type = _SOURCE_TYPE_ALIASES.get(source_type, source_type)
    if source_type not in _ALLOWED_SOURCE_TYPES:
        raise PipelineError(f"unsupported source_type {source_type!r}")
    collector, _ = _load_collector(ctx)
    existing = _existing_source(collector, url)
    if existing is not None:
        return existing, _read_source(existing, ctx.run_dir)
    entry = collector.add(url, source_type, citation)
    _save_collector(collector, ctx)
    return entry, (_read_source(entry, ctx.run_dir) if entry.get("status") == "ok" else None)


def _read_source(source: dict[str, Any], run_dir: Path) -> bytes:
    local = str(source.get("local_path") or "")
    if not local:
        return b""
    path = (run_dir / local).resolve()
    try:
        path.relative_to(run_dir.resolve())
    except ValueError as exc:
        raise PipelineError("source path escapes the run directory") from exc
    return path.read_bytes() if path.is_file() else b""


def _json_body(entry: dict[str, Any], body: bytes | None) -> Any:
    if entry.get("status") != "ok" or body is None:
        raise PipelineError(str(entry.get("error") or "source fetch failed"))
    try:
        return json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PipelineError(f"source is not valid JSON: {exc}") from exc


def _print(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def cmd_list(ctx: ToolContext, args: argparse.Namespace) -> int:
    index = read_json(ctx.run_dir / "evidence-index.json")
    sources = []
    for source in index.get("sources", [])[:100]:
        sources.append(
            {
                "id": source.get("id"),
                "type": source.get("source_type"),
                "status": source.get("status"),
                "url": source.get("url"),
                "citation": source.get("citation"),
                "local_path": source.get("local_path"),
            }
        )
    _print({"cve_id": ctx.cve_id, "sources": sources, "count": len(index.get("sources", []))})
    return 0


def cmd_show(ctx: ToolContext, args: argparse.Namespace) -> int:
    index = read_json(ctx.run_dir / "evidence-index.json")
    source = next(
        (item for item in index.get("sources", []) if item.get("id") == args.source_id),
        None,
    )
    if source is None:
        _print({"ok": False, "error": f"unknown source {args.source_id}"})
        return 1
    body = _read_source(source, ctx.run_dir)
    text = body.decode("utf-8", errors="replace")
    limit = max(1000, min(int(args.limit), 50000))
    _print(
        {
            "id": source.get("id"),
            "type": source.get("source_type"),
            "status": source.get("status"),
            "url": source.get("url"),
            "citation": source.get("citation"),
            "size": len(body),
            "truncated": len(text) > limit,
            "body": text[:limit],
        }
    )
    return 0


def cmd_registry(ctx: ToolContext, args: argparse.Namespace) -> int:
    result = lookup(args.ecosystem, args.name, ctx.settings)
    _print({"ecosystem": args.ecosystem, "name": args.name, **result})
    return 0 if "error" not in result else 1


def _github_json(ctx: ToolContext, url: str, source_type: str, citation: str) -> Any:
    entry, body = _record_url(ctx, url, source_type, citation)
    if entry.get("status") != "ok":
        _print({"ok": False, "source": entry.get("id"), "error": entry.get("error")})
        return None
    try:
        return _json_body(entry, body)
    except PipelineError as exc:
        _print({"ok": False, "source": entry.get("id"), "error": str(exc)})
        return None


def cmd_github(ctx: ToolContext, args: argparse.Namespace) -> int:
    if not _REPO.fullmatch(args.repo):
        _print({"ok": False, "error": "repo must be owner/name"})
        return 1
    if args.action == "tags":
        url = f"https://api.github.com/repos/{args.repo}/tags?per_page=100"
        data = _github_json(ctx, url, "release_notes", f"GitHub tags for {args.repo}")
        if data is None:
            return 1
        rows = [
            {"name": item.get("name"), "sha": (item.get("commit") or {}).get("sha")}
            for item in data
            if isinstance(item, dict)
        ]
        _print({"repo": args.repo, "tags": rows[:100]})
        return 0
    if args.action == "releases":
        url = f"https://api.github.com/repos/{args.repo}/releases?per_page=30"
        data = _github_json(ctx, url, "release_notes", f"GitHub releases for {args.repo}")
        if data is None:
            return 1
        rows = [
            {
                "tag_name": item.get("tag_name"),
                "name": item.get("name"),
                "draft": item.get("draft"),
                "prerelease": item.get("prerelease"),
                "published_at": item.get("published_at"),
            }
            for item in data
            if isinstance(item, dict)
        ]
        _print({"repo": args.repo, "releases": rows[:30]})
        return 0
    if args.action in {"commit", "parent"}:
        if not _SHA.fullmatch(args.sha):
            _print({"ok": False, "error": "sha must be hex"})
            return 1
        url = f"https://api.github.com/repos/{args.repo}/commits/{args.sha}"
        data = _github_json(ctx, url, "upstream_commit", f"GitHub commit {args.repo}@{args.sha}")
        if data is None:
            return 1
        parents = [
            item.get("sha") for item in data.get("parents") or [] if isinstance(item, dict)
        ]
        if args.action == "parent":
            _print({"repo": args.repo, "sha": data.get("sha"), "parents": parents})
        else:
            commit = data.get("commit") or {}
            _print(
                {
                    "repo": args.repo,
                    "sha": data.get("sha"),
                    "parents": parents,
                    "message": str(commit.get("message") or "")[:3000],
                    "date": (commit.get("committer") or {}).get("date"),
                }
            )
        return 0
    _print({"ok": False, "error": f"unknown github action {args.action!r}"})
    return 1


def cmd_fetch(ctx: ToolContext, args: argparse.Namespace) -> int:
    entry, body = _record_url(ctx, args.url, args.source_type, args.citation)
    _print(
        {
            "ok": entry.get("status") == "ok",
            "source": entry.get("id"),
            "type": entry.get("source_type"),
            "url": entry.get("url"),
            "status": entry.get("status"),
            "size": len(body or b""),
            "error": entry.get("error"),
        }
    )
    return 0 if entry.get("status") == "ok" else 1


def cmd_propose(ctx: ToolContext, args: argparse.Namespace) -> int:
    from .evidence_resolver import validate_proposal

    path = (ctx.workspace / args.file).resolve()
    try:
        path.relative_to(ctx.workspace.resolve())
    except ValueError:
        _print({"ok": False, "error": "proposal path escapes the resolver workspace"})
        return 1
    if not path.is_file():
        _print({"ok": False, "error": f"proposal file not found: {args.file}"})
        return 1
    try:
        proposal = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        _print({"ok": False, "error": f"proposal is not valid JSON: {exc}"})
        return 1
    evidence = read_json(ctx.run_dir / "evidence-index.json")
    review_path = ctx.workspace / "inputs/author-evidence-review.json"
    issues = validate_proposal(
        proposal,
        evidence=evidence,
        cve_id=ctx.cve_id,
        run_dir=ctx.run_dir,
        review_request=read_json(review_path) if review_path.is_file() else None,
    )
    if issues:
        _print({"ok": False, "issues": issues})
        return 1
    write_json(ctx.run_dir / PROPOSAL_FILE, proposal)
    _print(
        {
            "ok": True,
            "status": proposal.get("status"),
            "confidence": proposal.get("confidence"),
            "vulnerable": proposal.get("vulnerable", proposal.get("vulnerable_ref")),
            "fixed": proposal.get("fixed", proposal.get("fixed_ref")),
            "fix_source_id": proposal.get("fix_source_id"),
            "proposal": str(ctx.run_dir / PROPOSAL_FILE),
        }
    )
    return 0


def cmd_status(ctx: ToolContext, args: argparse.Namespace) -> int:
    index = read_json(ctx.run_dir / "evidence-index.json")
    sources = index.get("sources", [])
    _print(
        {
            "cve_id": ctx.cve_id,
            "sources": len(sources),
            "ok": sum(1 for item in sources if item.get("status") == "ok"),
            "errors": sum(1 for item in sources if item.get("status") != "ok"),
            "proposal": (ctx.run_dir / PROPOSAL_FILE).exists(),
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harbor-evidence")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    list_cmd = sub.add_parser("list", help="list collected evidence sources")
    list_cmd.set_defaults(func=cmd_list)

    show_cmd = sub.add_parser("show", help="show one collected source")
    show_cmd.add_argument("source_id")
    show_cmd.add_argument("--limit", type=int, default=30000)
    show_cmd.set_defaults(func=cmd_show)

    registry_cmd = sub.add_parser("registry", help="query published versions")
    registry_cmd.add_argument("ecosystem", choices=["pypi", "npm", "go", "maven"])
    registry_cmd.add_argument("name")
    registry_cmd.set_defaults(func=cmd_registry)

    github_cmd = sub.add_parser("github", help="query allowlisted GitHub API facts")
    github_cmd.add_argument("action", choices=["tags", "releases", "commit", "parent"])
    github_cmd.add_argument("repo")
    github_cmd.add_argument("sha", nargs="?")
    github_cmd.set_defaults(func=cmd_github)

    fetch_cmd = sub.add_parser("fetch", help="fetch and persist one allowlisted source")
    fetch_cmd.add_argument("url")
    fetch_cmd.add_argument("--type", dest="source_type", default="other", choices=_FETCH_TYPE_CHOICES)
    fetch_cmd.add_argument("--citation", default="Evidence resolver source")
    fetch_cmd.set_defaults(func=cmd_fetch)

    propose_cmd = sub.add_parser("propose", help="validate and submit reconciliation.json")
    propose_cmd.add_argument("--file", default=PROPOSAL_FILE)
    propose_cmd.set_defaults(func=cmd_propose)

    status_cmd = sub.add_parser("status", help="show resolver evidence status")
    status_cmd.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often default to GBK; an evidence page may contain
    # emoji or non-CJK Unicode. Never let a display-encoding error turn a
    # successful helper query into an exit code.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    args = build_parser().parse_args(argv)
    try:
        ctx = _context()
        return int(args.func(ctx, args))
    except (PipelineError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
