"""Host checks that keep Docker Desktop stable across large batches.

The failures this guards against are environmental, not task defects: a daemon
that is still initializing, a nearly full disk, hundreds of leftover trial
images, long-lived networks that stopped containers no longer keep alive, and a
Windows port reservation that covers an application port. None of them should
turn into a crashed batch.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .backend import prune_orphan_task_resources
from .util import no_window_kwargs

_SIZE = re.compile(r"^([0-9.]+)\s*([kKMGTP]?B)$")
_EXCLUDED_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s*\*?\s*$")

# Ports the local (non-Harbor) stacks need reserved. Harbor trials use compose
# `expose`, not host `ports`, so they are unaffected by Windows reservations.
DEFAULT_REQUIRED_PORTS: tuple[int, ...] = (1514, 1515, 55000)


def _run(command: list[str], timeout: float = 30.0):
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            **no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def parse_size(text: str) -> float:
    """Return bytes for strings like ``1.23GB`` (Docker's df output)."""
    match = _SIZE.match(text.strip())
    if not match:
        return 0.0
    value, unit = float(match.group(1)), match.group(2).upper()
    return value * {
        "B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15,
    }[unit]


def parse_excluded_ranges(output: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for line in output.splitlines():
        match = _EXCLUDED_ROW.match(line)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                ranges.append((start, end))
    return ranges


def port_excluded(port: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= port <= end for start, end in ranges)


def _count_build_history() -> int | None:
    """Best-effort count of Docker Desktop's build-history entries.

    The directory name has changed across releases. If none of the known
    locations exists, return None instead of guessing.
    """
    roots = []
    for variable in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            roots.extend([
                Path(base) / "Docker" / "build-history",
                Path(base) / "Docker" / "Builds",
            ])
    for root in roots:
        if not root.is_dir():
            continue
        count = 0
        for _ in root.rglob("*"):
            count += 1
            if count > 50_000:
                break
        return count
    return None


def _check(status: str, check_id: str, detail: str) -> dict:
    return {"id": check_id, "status": status, "detail": detail}


def run_preflight(
    *,
    output_dir: Path,
    workers: int,
    trial_workers: int,
    min_free_gb: float = 60.0,
    required_ports: tuple[int, ...] = DEFAULT_REQUIRED_PORTS,
    task_memory_mb: int = 2048,
    clean: bool = False,
    clean_images: bool = False,
) -> dict:
    checks: list[dict] = []
    cleaned: dict[str, list[str]] = {"containers": [], "networks": [], "images": []}

    docker = shutil.which("docker")
    info = _run(
        [docker, "info", "--format", "{{.ServerVersion}}|{{.MemTotal}}|{{.NCPU}}"],
        timeout=30,
    ) if docker else None
    if info is None or info.returncode != 0:
        detail = "docker is not on PATH" if not docker else "docker info did not answer within 30s"
        checks.append(_check("fail", "docker-daemon", detail))
        return {"ok": False, "checks": checks, "cleaned": cleaned}

    server_version, mem_total, ncpu = (info.stdout.strip().split("|") + ["", "", ""])[:3]
    mem_total_gb = int(mem_total or 0) / 1e9
    checks.append(_check(
        "pass", "docker-daemon",
        f"server={server_version} cpus={ncpu} memory={mem_total_gb:.1f}GB",
    ))

    # Disk headroom.
    try:
        free_gb = shutil.disk_usage(output_dir if output_dir.exists() else output_dir.parent).free / 1e9
    except OSError:
        free_gb = 0.0
    if free_gb < 10:
        checks.append(_check("fail", "disk-free", f"{free_gb:.1f}GB free; need at least 10GB"))
    elif free_gb < min_free_gb:
        checks.append(_check("warn", "disk-free", f"{free_gb:.1f}GB free; below the {min_free_gb:.0f}GB target"))
    else:
        checks.append(_check("pass", "disk-free", f"{free_gb:.1f}GB free"))

    # Docker's own usage summary.
    df = _run([docker, "system", "df"], timeout=60)
    if df is not None and df.returncode == 0:
        reclaimable = 0.0
        for line in df.stdout.splitlines():
            stripped = line.strip()
            columns = stripped.split()
            if stripped.startswith("Build Cache") and columns:
                # "Build Cache  962  0  16.64GB  16.64GB"
                reclaimable += parse_size(columns[-1])
            elif stripped.startswith(("Images", "Containers", "Local Volumes")) and len(columns) >= 4:
                # Images/Containers end with a "(NN%)" column.
                value = columns[-2] if columns[-1].startswith("(") else columns[-1]
                reclaimable += parse_size(value)
        checks.append(_check(
            "warn" if reclaimable > 80e9 else "pass",
            "docker-space",
            f"{reclaimable / 1e9:.1f}GB reclaimable (docker system df)",
        ))

    # Leftover Harbor resources.
    containers = _run(
        [docker, "ps", "-a", "--filter", "name=task__", "--format", "{{.Names}}"],
        timeout=60,
    )
    task_containers = (
        [name for name in (containers.stdout.split() if containers else []) if name.startswith("task__")]
    )
    images = _run(
        [docker, "images", "--filter", "reference=task__*", "--format", "{{.Size}}"],
        timeout=120,
    )
    task_image_sizes = images.stdout.split() if images is not None and images.returncode == 0 else []
    task_image_bytes = sum(parse_size(size) for size in task_image_sizes)
    if task_containers or task_image_sizes:
        status = "warn"
        detail = (
            f"{len(task_containers)} exited task container(s), "
            f"{len(task_image_sizes)} task image(s) ({task_image_bytes / 1e9:.1f}GB logical)"
        )
    else:
        status, detail = "pass", "no leftover task containers or images"
    checks.append(_check(status, "task-leftovers", detail))

    # Networks: task leftovers are safe to delete; user networks are not.
    networks = _run(
        [docker, "network", "ls", "--filter", "dangling=true", "--format", "{{.Name}}"],
        timeout=60,
    )
    dangling = networks.stdout.split() if networks is not None and networks.returncode == 0 else []
    task_networks = [name for name in dangling if name.startswith("task__")]
    user_networks = [name for name in dangling if not name.startswith("task__")]
    if user_networks:
        checks.append(_check(
            "warn", "user-networks-dangling",
            "stopped containers no longer keep these alive; a global network prune "
            f"would remove them: {', '.join(user_networks)}",
        ))
    else:
        checks.append(_check("pass", "user-networks-dangling", "no user networks dangling"))

    if clean:
        cleaned = prune_orphan_task_resources(images=clean_images)
        if cleaned["containers"] or cleaned["networks"] or cleaned["images"]:
            checks.append(_check(
                "pass", "task-cleanup",
                "removed "
                f"{len(cleaned['containers'])} container(s), "
                f"{len(cleaned['networks'])} network(s), "
                f"{len(cleaned['images'])} image(s)",
            ))
        else:
            checks.append(_check("pass", "task-cleanup", "nothing to remove"))
    elif task_networks:
        checks.append(_check(
            "warn", "task-networks",
            f"{len(task_networks)} dangling task network(s); run with --clean",
        ))

    # Windows port reservations.
    if os.name == "nt":
        excluded = _run(["netsh", "int", "ipv4", "show", "excludedportrange", "protocol=tcp"])
        ranges = parse_excluded_ranges(excluded.stdout) if excluded is not None else []
        missing = [port for port in required_ports if not port_excluded(port, ranges)]
        if missing:
            checks.append(_check(
                "warn", "port-exclusions",
                f"ports not reserved: {missing}; a WinNAT block can cover them after a reboot",
            ))
        else:
            checks.append(_check(
                "pass", "port-exclusions",
                f"reserved: {', '.join(f'{start}-{end}' for start, end in ranges)}",
            ))

    # Concurrency versus the WSL memory limit.
    peak_trials = max(1, workers) * max(1, trial_workers)
    estimate_gb = peak_trials * task_memory_mb / 1024 + 2.0
    if estimate_gb > mem_total_gb * 0.85:
        checks.append(_check(
            "fail", "memory-budget",
            f"{peak_trials} peak trials need ~{estimate_gb:.1f}GB of "
            f"{mem_total_gb:.1f}GB; lower --workers/--trial-workers",
        ))
    elif estimate_gb > mem_total_gb * 0.7:
        checks.append(_check(
            "warn", "memory-budget",
            f"{peak_trials} peak trials need ~{estimate_gb:.1f}GB of {mem_total_gb:.1f}GB",
        ))
    else:
        checks.append(_check(
            "pass", "memory-budget",
            f"{peak_trials} peak trials need ~{estimate_gb:.1f}GB of {mem_total_gb:.1f}GB",
        ))

    # Docker Desktop build history is the known startup-stall trigger.
    history = _count_build_history()
    if history is None:
        checks.append(_check("pass", "build-history", "no Docker Desktop build-history directory found"))
    elif history > 5000:
        checks.append(_check(
            "warn", "build-history",
            f"{history} build-history entries; clear them before the batch "
            "(Docker Desktop > Builds, or move the directory aside while stopped)",
        ))
    else:
        checks.append(_check("pass", "build-history", f"{history} entries"))

    failed = any(check["status"] == "fail" for check in checks)
    return {"ok": not failed, "checks": checks, "cleaned": cleaned}
