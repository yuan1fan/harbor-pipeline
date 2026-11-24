"""Read untrusted live files in a disposable container, never on the host.

Only the writable author-files bind is visible here. Even a concurrent symlink
replacement cannot make a host helper read host credentials or framework state.
"""
import base64
import json
import os
from pathlib import Path
import sys

ROOT = Path("/workspace")
IGNORED = {".git", "node_modules", ".venv", "__pycache__", ".cache", ".pytest_cache", ".mypy_cache"}


def read(name, limit=4_000_000):
    if not name or name.startswith("/") or "\\" in name or ":" in name or ".." in name.split("/"):
        raise ValueError("Unsafe workspace path")
    path = ROOT
    for component in name.split("/"):
        path /= component
        if path.is_symlink():
            raise ValueError("Linked workspace paths are not accepted")
    if not path.resolve().is_relative_to(ROOT) or not path.is_file():
        raise ValueError("Missing workspace file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Workspace file is too large")
    return data


def tree(folder):
    root = ROOT / folder
    if root.is_symlink():
        raise ValueError("Linked source directory")
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in IGNORED]
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise ValueError("Linked source directory")
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            relative = (Path(directory) / name).relative_to(root).as_posix()
            if len(result) >= 24 or len(relative) > 120:
                raise ValueError("Source tree exceeds the file count/path limit")
            content = read(folder + "/" + relative, 240000).decode("utf-8")
            if len(content) > 60000:
                raise ValueError("Source file exceeds 60000 characters")
            result[relative] = content
    return result


def capture(request):
    if request["kind"] == "file":
        return {"data": base64.b64encode(read(request["name"])).decode("ascii")}
    if request["kind"] != "bundle":
        raise ValueError("Unknown capture operation")
    bundle = json.loads(read("bundle.json"))
    if not isinstance(bundle, dict):
        raise ValueError("bundle.json must be an object")
    target = bundle.get("target")
    if not isinstance(target, dict):
        target = {}
    target["files"], target["fixed_overrides"] = tree("target"), tree("target-fixed")
    bundle["target"] = target
    bundle["poc"] = {"reference": read("poc/reference.py").decode("utf-8")}
    return {"bundle": bundle}


if __name__ == "__main__":
    try:
        print(json.dumps(capture(json.loads(sys.argv[1]))))
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
