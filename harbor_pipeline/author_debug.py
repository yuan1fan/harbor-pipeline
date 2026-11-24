"""Persistent, resource-bounded author workspaces and live target debugging."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .backend import docker_binary
from .resources import limited
from .util import PipelineError, digest, no_window_kwargs

OWNER_LABEL = "harbor-pipeline.author-workspace"
NETWORK_OWNER_LABEL = "harbor-pipeline.author-network"
DEBUG_NETWORK = "debug"
EGRESS_NETWORK = "egress"


def _owner(workspace: Path) -> str:
    return digest(str(workspace.resolve()))[:24]


def _name(workspace: Path, kind: str) -> str:
    if kind not in {"scratch", "vulnerable", "fixed"}:
        raise PipelineError("Unknown author container kind")
    return f"harbor-author-{_owner(workspace)}-{kind}"


def _network_name(workspace: Path, suffix: str) -> str:
    return f"harbor-author-{_owner(workspace)}-{suffix}"


def _ensure_network(workspace: Path, suffix: str, *, internal: bool) -> str:
    """Create the candidate-owned network once and reject foreign ones."""
    name = _network_name(workspace, suffix)
    inspected = _run(["network", "inspect", name])
    if inspected.returncode == 0:
        data = json.loads(inspected.stdout)[0]
        labels = data.get("Labels") or {}
        if labels.get(NETWORK_OWNER_LABEL) != _owner(workspace):
            raise PipelineError("Author network ownership mismatch; refusing to use it")
        return name
    args = ["network", "create", "--label", f"{NETWORK_OWNER_LABEL}={_owner(workspace)}"]
    if internal:
        args.append("--internal")
    args.append(name)
    created = _run(args, timeout=60)
    if created.returncode:
        raise PipelineError(created.stderr[-1000:])
    return name


def _connected(data: dict) -> set[str]:
    return set(((data.get("NetworkSettings") or {}).get("Networks") or {}))


def _attach(container: str, network: str, alias: str) -> None:
    result = _run(["network", "connect", "--alias", alias, network, container], timeout=60)
    if result.returncode:
        detail = (result.stdout + result.stderr).lower()
        if "already exists" in detail or "already attached" in detail or "already connected" in detail:
            return
        raise PipelineError(result.stderr[-1000:])


def _remove_network(workspace: Path, suffix: str) -> None:
    name = _network_name(workspace, suffix)
    inspected = _run(["network", "inspect", name])
    if inspected.returncode:
        return
    labels = (json.loads(inspected.stdout)[0].get("Labels") or {})
    if labels.get(NETWORK_OWNER_LABEL) != _owner(workspace):
        return
    _run(["network", "rm", name], timeout=60)


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
    for suffix in (DEBUG_NETWORK, EGRESS_NETWORK):
        try:
            _remove_network(workspace, suffix)
        except (PipelineError, OSError, subprocess.SubprocessError):
            pass


def suspend(workspace: Path) -> None:
    """Stop owned containers but keep their writable layer for --resume.

    Installed tools, cloned repositories and dependency caches then survive a
    model session without keeping the containers resident between turns.
    """
    for kind in ("scratch", "vulnerable", "fixed"):
        try:
            if inspect(workspace, kind):
                _run(["stop", "--time", "10", _name(workspace, kind)], timeout=60)
        except (PipelineError, OSError, subprocess.SubprocessError):
            pass


def _prepare_scratch(workspace: Path, args: list[str], image: str, ttl: int) -> None:
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    args += [
        "--user", f"{uid}:{gid}",
        "--tmpfs", "/workspace:rw,mode=1777",
        "--workdir", "/workspace",
        # Keep pip/npm caches and the default HOME on the persistent workspace
        # instead of the container layer.
        "--env", "HOME=/workspace/tools/home",
        "--env", "PIP_CACHE_DIR=/workspace/tools/pip-cache",
        "--env", "npm_config_cache=/workspace/tools/npm-cache",
        "--env", "NPM_CONFIG_PREFIX=/workspace/tools/node",
        "--env", "GOPATH=/workspace/tools/go",
        "--env", "GOCACHE=/workspace/tools/go/cache",
        "--env", "GOMODCACHE=/workspace/tools/go/pkg/mod",
    ]
    for folder, readonly in (
        ("target", False),
        ("target-fixed", False),
        ("poc", False),
        ("research", False),
        ("tools", False),
        ("inputs", True),
    ):
        path = workspace / folder
        path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()):
            raise PipelineError(f"Unsafe scratch mount: {folder}")
        if folder == "tools":
            for child in (
                "home", "pip-cache", "npm-cache", "node",
                "go/cache", "go/pkg/mod",
            ):
                (path / child).mkdir(parents=True, exist_ok=True)
        mount = f"type=bind,src={path.resolve()},dst=/workspace/{folder}" + (",readonly" if readonly else "")
        args += ["--mount", mount]
    args += ["--entrypoint", "sleep", image, str(max(60, min(ttl, 14400)))]


@limited("debug-start")
def start(workspace: Path, *, kind: str, image: str, network: str = "none", ttl: int = 7200) -> dict:
    if network not in {"none", "bridge"}:
        raise PipelineError("Author scratch network must be 'none' or 'bridge'")
    if kind != "scratch" and network != "none":
        raise PipelineError("Vulnerable and fixed debug targets must use network=none")
    runtime_lab = None
    if kind != "scratch" and (workspace / ".harbor/runtime.json").is_file():
        # The container author runtime owns the candidate's internal lab
        # network. Debug targets must join that network, not a separate one.
        from .author_runtime import _owned

        candidate = f"harbor-author-{_owner(workspace)}-lab"
        if not _owned("network", candidate, workspace):
            raise PipelineError("Author debug network is missing")
        runtime_lab = candidate
    if runtime_lab:
        debug_net = runtime_lab
        egress_net = None
    else:
        debug_net = _ensure_network(workspace, DEBUG_NETWORK, internal=True)
        egress_net = (
            _ensure_network(workspace, EGRESS_NETWORK, internal=False)
            if kind == "scratch" and network == "bridge"
            else None
        )
    primary = egress_net or debug_net
    alias = "author" if kind == "scratch" else f"target-{kind}"
    required = [(debug_net, alias)]
    if egress_net:
        required.append((egress_net, alias))
    previous = inspect(workspace, kind)
    if previous:
        labels = previous.get("Config", {}).get("Labels") or {}
        mode = str((previous.get("HostConfig") or {}).get("NetworkMode") or "")
        # Docker refuses to attach another network to a container created with
        # network=none. Recreate those legacy containers instead of failing.
        reusable = labels.get("harbor-pipeline.requested-image") == image and mode != "none"
        if reusable:
            was_running = bool(previous.get("State", {}).get("Running"))
            if not was_running:
                resumed = _run(["start", _name(workspace, kind)], timeout=60)
                if resumed.returncode:
                    raise PipelineError(resumed.stderr[-1000:])
            attached = _connected(previous)
            for name, net_alias in required:
                if name not in attached:
                    _attach(_name(workspace, kind), name, net_alias)
            return {
                "ok": True,
                "status": "running" if was_running else "resumed",
                "container": _name(workspace, kind),
                "reused": True,
                "network": network,
            }
        stop(workspace, kind)
    args = ["run", "-d", "--name", _name(workspace, kind),
            "--label", f"{OWNER_LABEL}={_owner(workspace)}",
            "--label", f"harbor-pipeline.requested-image={image}",
            "--network", primary, "--network-alias", alias,
            "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if kind == "scratch":
        _prepare_scratch(workspace, args, image, ttl)
    else:
        # No host files or sockets are mounted into vulnerable applications.
        args += [image]
    result = _run(args, timeout=120)
    if result.returncode:
        raise PipelineError(result.stderr[-2000:])
    if primary != debug_net:
        _attach(_name(workspace, kind), debug_net, alias)
    return {
        "ok": True,
        "status": "started",
        "container": _name(workspace, kind),
        "network": network,
        "networks": [primary, debug_net] if primary != debug_net else [primary],
    }


@limited("debug-exec")
def execute(workspace: Path, kind: str, command: str, *, timeout: int = 120) -> dict:
    data = inspect(workspace, kind)
    if not data or not data.get("State", {}).get("Running"):
        raise PipelineError(f"Start the {kind} debug container first")
    try:
        result = _run(["exec", _name(workspace, kind), "sh", "-lc", command], timeout=max(5, min(timeout, 600)))
        return {"ok": result.returncode == 0, "exit": result.returncode,
                "output": (result.stdout + result.stderr)[-20000:], "kind": kind}
    except subprocess.TimeoutExpired:
        # Killing only docker exec's client leaves the command running. Restart
        # the owned container so the whole process tree dies while the
        # writable layer (installed tools, downloads) survives for --resume.
        restarted = _run(["restart", "--time", "5", _name(workspace, kind)], timeout=60)
        if restarted.returncode:
            stop(workspace, kind)
            return {"ok": False, "exit": 124, "output": "timeout; debug container stopped", "kind": kind}
        return {"ok": False, "exit": 124, "output": "timeout; debug container restarted", "kind": kind}


def logs(workspace: Path, kind: str) -> dict:
    data = inspect(workspace, kind)
    if not data:
        raise PipelineError("Debug container does not exist")
    result = _run(["logs", "--tail", "200", _name(workspace, kind)])
    return {"ok": result.returncode == 0, "state": data.get("State"),
            "output": (result.stdout + result.stderr)[-20000:]}
