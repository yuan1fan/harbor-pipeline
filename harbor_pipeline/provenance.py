"""Check exact source excerpts and constrain version-pair construction."""
from pathlib import Path

from .util import digest

VERSION_MANIFESTS = {"requirements.txt", "package.json", "package-lock.json", "go.mod", "go.sum", "pom.xml", "Dockerfile"}


def cited_excerpt(entry: dict, source: dict, run_dir: Path | None) -> tuple[str, str, str | None]:
    if run_dir is None or source.get("status") != "ok":
        return "", "", "source body is unavailable"
    path = (run_dir / str(source.get("local_path") or "")).resolve()
    if not path.is_relative_to(run_dir.resolve()) or not path.is_file():
        return "", "", "source file is missing or outside the evidence directory"
    content = path.read_bytes()
    checksum = digest(content)
    if checksum != source.get("content_sha256"):
        return "", checksum, "source checksum does not match the evidence index"
    body = content.decode("utf-8-sig", errors="replace")
    quote = str(entry.get("evidence_quote") or entry.get("text") or "").strip()
    if len(quote) < 12 or quote not in body:
        return quote, checksum, "evidence_quote must be an exact excerpt (at least 12 characters) of the cited source"
    return quote, checksum, None


def version_pair_issues(target: dict, versions: dict) -> list[str]:
    """Both variants share application code; only a release pin may differ.

    Complex vendored patches should be represented by two upstream refs. A
    hand-edited fixed application is not sufficient evidence of an upstream fix.
    """
    files = target.get("files") or {}
    overrides = target.get("fixed_overrides") or {}
    vulnerable = str(versions.get("vulnerable_ref") or "")
    fixed = str(versions.get("fixed_ref") or "")
    issues = []
    for name, body in files.items():
        if "{{REF}}" in str(body) and Path(name).name not in VERSION_MANIFESTS:
            issues.append(f"target.files.{name}: upstream ref substitution is limited to dependency/build manifests, not application logic")
    for name, body in overrides.items():
        original = files.get(name)
        if not isinstance(original, str) or not isinstance(body, str):
            issues.append(f"fixed_overrides.{name}: both variants must contain the same application files")
            continue
        if original == body:
            continue
        # Substituting the framework placeholder is the only allowed change.
        if "{{REF}}" in original and body in {original.replace("{{REF}}", fixed), original}:
            continue
        if Path(name).name in VERSION_MANIFESTS and vulnerable and fixed and original.replace(vulnerable, fixed) == body:
            continue
        issues.append(f"fixed_overrides.{name}: application/config changes are forbidden; use the same source with an upstream version/commit pin")
    if not any("{{REF}}" in str(body) for body in files.values()) and not overrides:
        issues.append("version pair has no upstream ref substitution")
    return issues
