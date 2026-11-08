#!/usr/bin/env python3
"""Keep a Harbor batch alive until every candidate reaches a terminal state.

The batch itself already retries candidate-level failures. This supervisor only
handles process-level exits (OOM kill, terminal closed, gateway crash): it
restarts the same run id, which resumes from the per-candidate state files.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

TERMINAL = {"RELEASED", "QUARANTINED", "UNSUPPORTED"}


def _counts(run_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not run_dir.is_dir():
        return counts
    for child in run_dir.iterdir():
        if not child.is_dir() or not child.name.startswith("CVE-"):
            continue
        try:
            state = json.loads((child / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        name = str(state.get("state") or "unknown")
        counts[name] = counts.get(name, 0) + 1
    return counts


def _done(counts: dict[str, int]) -> int:
    return sum(counts.get(name, 0) for name in TERMINAL)


def _pipeline_pid(run_id: str) -> int | None:
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        name = (process.info.get("name") or "").lower()
        if not name.startswith("python"):
            continue
        command = " ".join(process.info.get("cmdline") or [])
        if "harbor_pipeline" in command and "batch" in command and run_id in command:
            return int(process.info["pid"])
    return None


def _launch(args, log_path: Path) -> subprocess.Popen:
    command = [
        sys.executable,
        "-u",
        "-m",
        "harbor_pipeline",
        "-c",
        args.config,
        "batch",
        "--input",
        str(args.input),
        "--run-id",
        args.run_id,
        "--profile",
        args.profile,
        "--workers",
        str(args.workers),
        "--trial-workers",
        str(args.trial_workers),
    ]
    if args.limit:
        command.extend(["--limit", str(args.limit)])
    log = log_path.open("a", encoding="utf-8")
    log.write(f"\n=== supervisor restart {datetime.now().isoformat(timespec='seconds')} ===\n")
    log.flush()
    return subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--profile", default="qualification")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--trial-workers", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--config", default="pipeline.scale.toml")
    parser.add_argument("--output-dir", type=Path, default=Path("runs"))
    parser.add_argument("--poll", type=float, default=300.0)
    args = parser.parse_args()

    total = min(
        len(json.loads(args.input.read_text(encoding="utf-8"))),
        args.limit or 10**9,
    )
    run_dir = args.output_dir / args.run_id
    log_path = args.output_dir / f"{args.run_id}-batch.log"
    status_path = args.output_dir / f"{args.run_id}-supervisor.log"
    restarts = 0

    while True:
        counts = _counts(run_dir)
        done = _done(counts)
        pid = _pipeline_pid(args.run_id)
        stamp = datetime.now().isoformat(timespec="seconds")
        line = f"{stamp} done={done}/{total} running={pid} restarts={restarts} counts={counts}\n"
        with status_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        if done >= total:
            return 0
        if pid is None:
            child = _launch(args, log_path)
            restarts += 1
            with status_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{stamp} launched pid={child.pid}\n")
        time.sleep(args.poll)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
