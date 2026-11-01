from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


class PipelineError(Exception):
    """A recoverable task failure, recorded before quarantine."""


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)


def digest(value: Any) -> str:
    data = value if isinstance(value, bytes) else json_text(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json_text(value) + "\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def child_path(root: Path, name: str) -> Path:
    """Reject traversal, Windows aliases, drive names, and existing symlink escapes."""
    parts = PurePosixPath(name).parts
    if not parts or "\\" in name or ":" in name or "\x00" in name:
        raise PipelineError(f"Unsafe artifact path: {name!r}")
    if PurePosixPath(name).is_absolute() or any(p in {".", ".."} for p in parts):
        raise PipelineError(f"Unsafe artifact path: {name!r}")
    for part in parts:
        if part.endswith((".", " ")) or re.match(r"(?i)^(con|prn|aux|nul|com\d|lpt\d)(\.|$)", part):
            raise PipelineError(f"Unsafe Windows artifact name: {name!r}")
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise PipelineError(f"Artifact escapes workspace: {name!r}")
    return target


def write_files(root: Path, files: list[dict], prefixes: tuple[str, ...]) -> None:
    seen: set[str] = set()
    total = 0
    for item in files:
        name, content = item["path"], item["content"]
        normalized = str(PurePosixPath(name))
        if normalized != name or name.casefold() in seen:
            raise PipelineError(f"Duplicate or noncanonical file: {name}")
        seen.add(name.casefold())
        if not any(name == p or name.startswith(p.rstrip("/") + "/") for p in prefixes):
            raise PipelineError(f"Role cannot write {name}")
        total += len(content.encode("utf-8"))
        if total > 4_000_000 or len(files) > 80:
            raise PipelineError("Generated bundle exceeds file/size budget")
        path = child_path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.replace("\r\n", "\n"), encoding="utf-8", newline="\n")


def tree_hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PipelineError(f"Symlinks are not allowed in bundles: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return result
