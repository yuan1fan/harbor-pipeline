"""Host-wide admission for Docker work, shared by workers and author helpers.

Candidate/LLM concurrency is independent of expensive build/probe/trial work.
The queue lives outside author workspaces. Dead processes are reclaimed; low
memory or disk space delays new work rather than changing any CVE verdict.
"""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import sys
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path

from .errors import TaskError
from .state import _pid_alive
from .util import file_lock, read_json, write_json

ENV_NAME = "HARBOR_PIPELINE_RESOURCES"
_POLICY: ContextVar[dict | None] = ContextVar("docker_resource_policy", default=None)
_DEPTH: ContextVar[int] = ContextVar("docker_resource_depth", default=0)


def configure(settings, *, inherit: bool = False, output_dir: Path | None = None) -> dict:
    if inherit and os.environ.get(ENV_NAME):
        policy = json.loads(os.environ[ENV_NAME])
    else:
        policy = {
            "slots": settings.docker_slots,
            "directory": str(Path(settings.resource_dir).resolve()),
            "min_memory_mb": settings.min_free_memory_mb,
            "min_disk_gb": settings.min_free_disk_gb,
            "wait_sec": settings.resource_wait_sec,
            "prune_images": settings.prune_images,
            "disk_paths": [str(Path(output_dir or settings.output_dir).resolve())],
        }
        # Output relocation alone does not relocate Docker Desktop's VHDX.
        if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
            policy["disk_paths"].append(str(Path(os.environ["LOCALAPPDATA"]) / "Docker" / "wsl"))
        policy["disk_paths"].extend(str(Path(p).resolve()) for p in settings.resource_disk_paths)
    _POLICY.set(policy)
    return policy


def policy() -> dict:
    current = _POLICY.get()
    if current is not None:
        return current
    return json.loads(os.environ.get(ENV_NAME, '{"slots": 0}'))


def child_environment() -> dict[str, str]:
    return {ENV_NAME: json.dumps(policy())}


def available_memory_mb() -> float:
    if os.name == "nt":
        class Memory(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong) for name in
                ("total", "available", "page_total", "page_available", "virtual_total", "virtual_available", "extended")
            ]
        data = Memory()
        data.length = ctypes.sizeof(data)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(data)):
            raise OSError("Cannot read Windows available memory")
        return data.available / 2**20
    values = Path("/proc/meminfo").read_text().splitlines()
    for value in values:
        if value.startswith("MemAvailable:"):
            return int(value.split()[1]) / 1024
    raise OSError("Cannot read MemAvailable")


def pressure_reason(config: dict) -> str:
    try:
        memory = available_memory_mb()
        if memory < config["min_memory_mb"]:
            return f"available host memory {memory:.0f} MiB < reserve {config['min_memory_mb']} MiB"
        for name in config["disk_paths"]:
            path = Path(name)
            while not path.exists() and path != path.parent:
                path = path.parent
            free = shutil.disk_usage(path).free / 2**30
            if free < config["min_disk_gb"]:
                return f"free disk at {path}: {free:.1f} GiB < reserve {config['min_disk_gb']} GiB"
    except OSError as exc:
        return f"resource measurement unavailable: {exc}"
    return ""


@contextmanager
def docker_work(kind: str, *, units: int = 1, poll_sec: float = 2.0):
    config = policy()
    if not config.get("slots") or _DEPTH.get():
        yield
        return
    units = max(1, int(units))
    if units > config["slots"]:
        raise TaskError("infra_error", f"{kind} needs {units} Docker slots, configured {config['slots']}")
    path = Path(config["directory"]) / "docker-queue.json"
    token = uuid.uuid4().hex
    record = {"id": token, "pid": os.getpid(), "kind": kind, "units": units,
              "capacity": config["slots"], "status": "waiting", "queued_at": time.time()}
    started = time.monotonic()
    announced = False
    depth_token = None
    try:
        while True:
            with file_lock(path):
                state = read_json(path) if path.is_file() else {"entries": []}
                entries = [entry for entry in state["entries"] if _pid_alive(entry["pid"])]
                own = next((entry for entry in entries if entry["id"] == token), None)
                if own is None:
                    own = dict(record)
                    entries.append(own)
                # Conflicting configs sharing one queue use the stricter limit.
                capacity = min([config["slots"], *[entry["capacity"] for entry in entries]])
                used = sum(entry["units"] for entry in entries if entry["status"] == "running")
                first = next(entry for entry in entries if entry["status"] == "waiting")
                reason = pressure_reason(config)
                ready = first["id"] == token and used + units <= capacity and not reason
                own["reason"] = reason or f"Docker slots in use: {used}/{capacity}"
                if ready:
                    own.update(status="running", admitted_at=time.time(), reason="")
                write_json(path, {"entries": entries})
            if ready:
                depth_token = _DEPTH.set(1)
                yield
                return
            if not announced:
                print(f"[resources] waiting for {kind}: {own['reason']}", file=sys.stderr, flush=True)
                announced = True
            if time.monotonic() - started >= config["wait_sec"]:
                raise TaskError("infra_error", f"Resource wait timed out for {kind}: {own['reason']}")
            time.sleep(poll_sec)
    finally:
        if depth_token is not None:
            _DEPTH.reset(depth_token)
        with file_lock(path):
            state = read_json(path) if path.is_file() else {"entries": []}
            write_json(path, {"entries": [entry for entry in state["entries"] if entry["id"] != token]})


def limited(kind: str, *, concurrency_arg: str | None = None):
    """Bound one Docker phase; nested inspections share its admission."""
    def decorate(function):
        @wraps(function)
        def run(*args, **kwargs):
            slots = policy().get("slots", 0)
            units = 1
            if slots and concurrency_arg:
                extra = dict(kwargs.get("extra") or {})
                requested = extra.get("n_concurrent_trials", kwargs.get(concurrency_arg, 1))
                units = min(slots, max(1, int(requested)))
                kwargs[concurrency_arg] = units
                if "n_concurrent_trials" in extra:
                    extra["n_concurrent_trials"] = units
                    kwargs["extra"] = extra
            with docker_work(kind, units=units):
                return function(*args, **kwargs)
        return run
    return decorate
