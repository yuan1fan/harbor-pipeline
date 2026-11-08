"""Persistent, resource-bounded author workspaces and live target debugging."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .backend import docker_binary
from .util import PipelineError, digest, no_window_kwargs

OWNER_LABEL = "harbor-pipeline.author-workspace"


def _owner(workspace: Path) -> str:
    return digest(str(workspace.resolve()))[:24]


def _name(workspace: Path, kind: str) -> str:
    if kind not in {"scratch", "vulnerable", "fixed"}:
        raise PipelineError("Unknown author container kind")
    return f"harbor-author-{_owner(workspace)}-{kind}"


def _run(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run([docker_binary(), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout, **no_window_kwargs())


def inspect(workspace: Path, kind: str) -> dict | None:
    result = _run(["inspect", _name(workspace, kind)])
    if result.returncode:
        return None
    data = json.loads(result.stdout)[0]
    labels = data.get("Config", {}).get("Labels") or {}
    if labels.get(OWNER_LABEL) != _owner(workspace):
        raise PipelineError("Container ownership mismatch; refusing to use or delete it")
    return data


def stop(workspace: Path, kind: str) -> dict:
    if inspect(workspace, kind):
        result = _run(["rm", "-f", _name(workspace, kind)])
        if result.returncode:
            raise PipelineError(result.stderr[-1000:])
    return {"ok": True, "status": "stopped", "kind": kind}


def cleanup(workspace: Path) -> None:
    for kind in ("scratch", "vulnerable", "fixed"):
        try:
            stop(workspace, kind)
        except (PipelineError, OSError, subprocess.SubprocessError):
            pass


def start(workspace: Path, *, kind: str, image: str, network: str = "none", ttl: int = 7200) -> dict:
    if network not in {"none", "bridge"}:
        raise PipelineError("Author scratch network must be 'none' or 'bridge'")
    if kind != "scratch" and network != "none":
        raise PipelineError("Vulnerable and fixed debug targets must use network=none")
    previous = inspect(workspace, kind)
    if previous:
        labels = previous.get("Config", {}).get("Labels") or {}
        if previous.get("State", {}).get("Running") and labels.get("harbor-pipeline.requested-image") == image:
            return {"ok": True, "status": "running", "container": _name(workspace, kind), "reused": True}
        stop(workspace, kind)
    args = ["run", "-d", "--name", _name(workspace, kind),
            "--label", f"{OWNER_LABEL}={_owner(workspace)}",
            "--label", f"harbor-pipeline.requested-image={image}",
            "--network", network, "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if kind == "scratch":
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000
        args += ["--user", f"{uid}:{gid}", "--tmpfs", "/workspace:rw,mode=1777", "--workdir", "/workspace"]
        for folder, readonly in (("target", False), ("target-fixed", False), ("poc", False), ("inputs", True)):
            path = workspace / folder
            path.mkdir(exist_ok=True)
            if path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()):
                raise PipelineError(f"Unsafe scratch mount: {folder}")
            mount = f"type=bind,src={path.resolve()},dst=/workspace/{folder}" + (",readonly" if readonly else "")
            args += ["--mount", mount]
        args += ["--entrypoint", "sleep", image, str(max(60, min(ttl, 14400)))]
    else:
        # No host files or sockets are mounted into vulnerable applications.
        args += [image]
    result = _run(args, timeout=120)
    if result.returncode:
        raise PipelineError(result.stderr[-2000:])
    return {"ok": True, "status": "started", "container": _name(workspace, kind), "network": network}


def execute(workspace: Path, kind: str, command: str, *, timeout: int = 120) -> dict:
    data = inspect(workspace, kind)
    if not data or not data.get("State", {}).get("Running"):
        raise PipelineError(f"Start the {kind} debug container first")
    try:
        result = _run(["exec", _name(workspace, kind), "sh", "-lc", command], timeout=max(5, min(timeout, 600)))
        return {"ok": result.returncode == 0, "exit": result.returncode,
                "output": (result.stdout + result.stderr)[-20000:], "kind": kind}
    except subprocess.TimeoutExpired:
        # Killing only docker exec's client leaves the command running. Remove
        # this owned container to enforce the timeout on the whole process tree.
        stop(workspace, kind)
        return {"ok": False, "exit": 124, "output": "timeout; debug container stopped", "kind": kind}


def logs(workspace: Path, kind: str) -> dict:
    data = inspect(workspace, kind)
    if not data:
        raise PipelineError("Debug container does not exist")
    result = _run(["logs", "--tail", "200", _name(workspace, kind)])
    return {"ok": result.returncode == 0, "state": data.get("State"),
            "output": (result.stdout + result.stderr)[-20000:]}
