from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


class PipelineError(Exception):
    """A recoverable task failure, recorded before quarantine."""


def image_base(cve_id: str, variant: str, revision: int) -> str:
    """Local tag base for a task's prebuilt agent/target/verifier images.

    The revision is part of the tag so a repaired task never reuses the image
    built from the previous task files. Keep this format in sync with
    ``backend.build_task_images``.
    """
    return f"harbor-pipeline/{cve_id.lower()}-{variant}-r{int(revision)}"


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def no_window_kwargs() -> dict[str, Any]:
    """Keep Windows from opening a console window for every child process.

    A batch starts thousands of ``docker``, ``harbor`` and ``claude`` children
    from a parent with no visible console, and each console application would
    otherwise flash its own window. ``CREATE_NO_WINDOW`` gives the child an
    invisible console that its own children (``docker compose``, ``git``)
    inherit. Every call site passes this through; it is a no-op on POSIX.
    """
    if os.name != "nt":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}


def hidden_console_kwargs() -> dict[str, Any]:
    """Spawn a uv-shim binary with a console that is already hidden.

    ``harbor`` and ``claude`` are installed as uv trampolines. When their
    parent has no console at all (``CREATE_NO_WINDOW``), the trampoline calls
    ``AllocConsole`` itself, and Windows 11 opens a visible Windows Terminal
    window for it. Handing the child its own console that starts hidden stops
    the trampoline from allocating one, and the grandchildren (``docker
    compose``, ``git``) inherit the hidden console, so no window appears while
    stdout/stderr pipes still work. Measured with ``GetConsoleWindow`` from a
    grandchild: six calls produced one visible window with ``CREATE_NO_WINDOW``
    and none with this.
    """
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "creationflags": subprocess.CREATE_NEW_CONSOLE,
        "startupinfo": startupinfo,
    }


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


LOCK_TIMEOUT_SEC = 60.0


@contextmanager
def file_lock(path: Path, *, timeout_sec: float = LOCK_TIMEOUT_SEC) -> Iterator[None]:
    """Hold an exclusive cross-process lock named after ``path``.

    A ledger or a cache is shared by every worker and every shard on a host, so
    a check-then-write has to be serialized across processes, not only across
    threads. The lock is advisory and local-filesystem only: NFS and SMB do not
    guarantee these semantics, which is why the ledger must live on a local
    volume.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    deadline = time.monotonic() + timeout_sec
    with open(lock_path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise PipelineError(f"Timed out waiting for lock {lock_path}")
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
        if total > 8_000_000 or len(files) > 160:
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
