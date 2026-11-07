#!/usr/bin/env python3
"""Run (or watch) a Harbor batch with a live progress bar.

The batch writes its own log to ``runs/<run-id>-batch.log``; this wrapper
renders one in-place line from the per-candidate ``state.json`` files and
prints a final tally when the child exits.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TERMINAL = ("RELEASED", "QUARANTINED", "UNSUPPORTED")
BAR_WIDTH = 30


def _candidate_count(path: Path, limit: int | None) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{path} is not a candidate list")
    return min(len(data), limit) if limit else len(data)


def _scan(run_dir: Path) -> dict[str, dict]:
    states: dict[str, dict] = {}
    if not run_dir.is_dir():
        return states
    for child in run_dir.iterdir():
        if not child.is_dir() or not child.name.startswith("CVE-"):
            continue
        try:
            states[child.name] = json.loads(
                (child / "state.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            continue
    return states


def _elapsed(updated_at: object) -> str:
    try:
        stamp = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        minutes = max(0, int((datetime.now(timezone.utc) - stamp).total_seconds() / 60))
    except (TypeError, ValueError):
        return ""
    return f"{minutes}m" if minutes else "<1m"


def _line(states: dict[str, dict], total: int) -> str:
    counts = {name: 0 for name in TERMINAL}
    running: list[str] = []
    for cve, state in states.items():
        name = str(state.get("state") or "")
        if name in counts:
            counts[name] += 1
        elif name:
            running.append(f"{cve} {name} {_elapsed(state.get('updated_at'))}".strip())
    done = sum(counts.values())
    pct = int(done * 100 / total) if total else 0
    filled = int(BAR_WIDTH * done / total) if total else 0
    bar = "#" * filled + "-" * (BAR_WIDTH - filled)
    detail = ", ".join(sorted(running)[:3]) or "idle"
    return (
        f"[{bar}] {done}/{total} {pct:3d}% | "
        f"R {counts['RELEASED']} Q {counts['QUARANTINED']} U {counts['UNSUPPORTED']} | "
        f"{detail}"
    )


def _draw(text: str, width: int) -> int:
    sys.stdout.write("\r" + text.ljust(width))
    sys.stdout.flush()
    return max(width, len(text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="candidate JSON list")
    parser.add_argument("--run-id", required=True, help="run id to create or resume")
    parser.add_argument("--profile", default="qualification")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--trial-workers", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--config", default="pipeline.scale.toml")
    parser.add_argument("--output-dir", type=Path, default=Path("runs"))
    parser.add_argument("--poll", type=float, default=2.0)
    parser.add_argument(
        "--watch-only",
        action="store_true",
        help="do not launch a batch; only monitor an existing run",
    )
    parser.add_argument("--json", action="store_true", help="pass --json to the batch")
    args = parser.parse_args()

    run_dir = args.output_dir / args.run_id
    log_path = args.output_dir / f"{args.run_id}-batch.log"
    total = _candidate_count(args.input, args.limit)

    child: subprocess.Popen | None = None
    if not args.watch_only:
        run_dir.mkdir(parents=True, exist_ok=True)
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
        if args.json:
            command.append("--json")
        log = log_path.open("w", encoding="utf-8")
        print(f"batch log: {log_path}")
        print(f"run dir:   {run_dir}")
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)

    width = 0
    try:
        while True:
            width = _draw(_line(_scan(run_dir), total), width)
            if child is not None and child.poll() is not None:
                break
            if child is None:
                states = _scan(run_dir)
                if states and all(
                    str(s.get("state")) in TERMINAL for s in states.values()
                ) and len(states) >= total:
                    break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
        print("interrupted")
        return 130

    sys.stdout.write("\n")
    states = _scan(run_dir)
    counts = {name: 0 for name in TERMINAL}
    for state in states.values():
        name = str(state.get("state") or "")
        if name in counts:
            counts[name] += 1
    print(
        f"finished: {sum(counts.values())}/{total} terminal | "
        f"released {counts['RELEASED']} quarantined {counts['QUARANTINED']} "
        f"unsupported {counts['UNSUPPORTED']}"
    )
    if not args.watch_only:
        print(f"log:    {log_path}")
        print(f"report: {run_dir / 'report.json'}")
    if child is not None:
        return child.returncode or 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
