#!/usr/bin/env python3
"""Stop a running Harbor batch and its whole child tree.

Ctrl-C on ``run_batch_progress.py`` only terminates its direct child. Native
author sessions, Docker buildx/build processes and ``harbor-author`` helper
processes are grandchildren, so they survive and keep the batch alive. This
script finds every process belonging to one run id, terminates the tree, and
removes the run's scratch/debug containers.

Run state is deliberately left untouched: the same run id resumes from each
candidate's state.json.

Examples::

    python scripts/pause_batch.py --run-id scale-100-open-20261108 --dry-run
    python scripts/pause_batch.py --run-id scale-100-open-20261108 --yes
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil


def _cmdline(process: psutil.Process) -> str:
    try:
        return " ".join(process.cmdline())
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _cwd(process: psutil.Process) -> str:
    try:
        return str(process.cwd())
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _belongs(process: psutil.Process, run_id: str) -> bool:
    command = _cmdline(process)
    if run_id in command:
        return True
    cwd = _cwd(process)
    if cwd and f"runs{os.sep}{run_id}" in cwd:
        return True
    # helper processes are started with cwd inside the run workspace and do
    # not always carry the run id on their command line.
    return "harbor-author" in command and f"{os.sep}{run_id}{os.sep}" in cwd


def _collect(run_id: str) -> tuple[list[psutil.Process], set[int]]:
    current = psutil.Process(os.getpid())
    protected = {current.pid}
    try:
        protected.update(parent.pid for parent in current.parents())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    roots: list[psutil.Process] = []
    seen: set[int] = set()
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        if process.pid in protected:
            continue
        try:
            if not _belongs(process, run_id):
                continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        roots.append(process)
        seen.add(process.pid)

    # Include descendants even when their own command line is opaque.
    targets: dict[int, psutil.Process] = {p.pid: p for p in roots}
    for root in roots:
        try:
            for child in root.children(recursive=True):
                if child.pid not in protected:
                    targets[child.pid] = child
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # A second pass catches helpers whose cwd contains the run id and whose
    # parent has already been reparented.
    for process in psutil.process_iter(["pid", "name"]):
        if process.pid in targets or process.pid in protected:
            continue
        try:
            if _belongs(process, run_id):
                targets[process.pid] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return list(targets.values()), protected


def _scratch_containers() -> list[str]:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}} {{.Names}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    names: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        container_id, name = parts
        if name.startswith("harbor-author-") and name.endswith("-scratch"):
            names.append(container_id)
    return names


def _stop_tree(processes: list[psutil.Process]) -> None:
    # Ask every process to stop first, then force whatever remains. On Windows
    # terminate() is TerminateProcess, so this is already forceful there.
    for process in processes:
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(processes, timeout=10)
    for process in alive:
        try:
            process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(alive, timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dry-run", action="store_true", help="only print what would stop")
    parser.add_argument("--yes", action="store_true", help="stop without an interactive confirmation")
    parser.add_argument("--keep-containers", action="store_true", help="do not remove scratch containers")
    args = parser.parse_args()

    processes, _ = _collect(args.run_id)
    containers = [] if args.keep_containers else _scratch_containers()

    print(f"run: {args.run_id}")
    print(f"processes: {len(processes)}")
    for process in sorted(processes, key=lambda item: item.pid):
        try:
            print(f"  {process.pid:6d} {process.name():20s} {_cmdline(process)[:180]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    print(f"scratch containers: {containers or 'none'}")

    if args.dry_run:
        print("dry-run: nothing stopped")
        return 0
    if not processes and not containers:
        print("nothing to stop")
        return 0
    if not args.yes:
        answer = input("Stop these processes and remove scratch containers? [y/N] ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("cancelled")
            return 1

    if processes:
        _stop_tree(processes)
    for container in containers:
        subprocess.run(["docker", "rm", "-f", container], timeout=60)
    print("batch paused; run state was left intact")
    print("resume with the same run id, e.g. the previous run_batch_progress.py command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
