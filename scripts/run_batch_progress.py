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

import psutil

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


def _log_tail(path: Path, offset: int, *, max_bytes: int = 8192) -> str:
    """Read diagnostics from this invocation only, with bounded allocation."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(offset, handle.tell() - max_bytes))
            text = handle.read(max_bytes).decode("utf-8", errors="replace")
        return "\n".join(text.strip().splitlines()[-25:])
    except OSError:
        return "(could not read this invocation's log)"


def _stamp(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _terminate_tree(process: subprocess.Popen) -> None:
    """Stop the batch and every author/build helper it spawned.

    ``Popen.terminate()`` only stops the direct child on Windows. The native
    Claude Code authors, ``harbor-author`` helpers and Docker builds are
    grandchildren, so a plain Ctrl-C used to leave them running after this
    wrapper exited. Kill the whole tree instead.
    """
    try:
        parent = psutil.Process(process.pid)
        targets = parent.children(recursive=True) + [parent]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        targets = []
    for item in targets:
        try:
            item.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(targets, timeout=10)
    for item in alive:
        try:
            item.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(alive, timeout=5)


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
    report_path = run_dir / "batch-report.json"
    report_before = _stamp(report_path)
    log_offset = 0
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
            "--output-dir",
            str(args.output_dir),
        ]
        if args.limit:
            command.extend(["--limit", str(args.limit)])
        if args.json:
            command.append("--json")
        print(f"batch log: {log_path}", flush=True)
        print(f"run dir:   {run_dir}", flush=True)
        with log_path.open("ab") as log:
            log.write(f"\n=== batch invocation {datetime.now(timezone.utc).isoformat()} ===\n".encode("utf-8"))
            log.flush()
            log_offset = log.tell()
            try:
                child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            except OSError as exc:
                print(f"failed to start batch: {exc}", file=sys.stderr)
                return 2

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
            _terminate_tree(child)
        print("interrupted")
        return 130

    sys.stdout.write("\n")
    states = _scan(run_dir)
    counts = {name: 0 for name in TERMINAL}
    for state in states.values():
        name = str(state.get("state") or "")
        if name in counts:
            counts[name] += 1
    done = sum(counts.values())
    exit_code = child.returncode if child is not None else 0
    report_after = _stamp(report_path)
    new_report = report_after is not None and report_after != report_before
    # Exit 3 is a normal completed batch with quarantined tasks only if the
    # batch actually wrote its report. Old states do not prove a new run ended.
    completed = done >= total and (
        args.watch_only or (exit_code in (0, 3) and new_report)
    )
    label = "finished" if completed else ("failed" if exit_code else "incomplete")
    print(
        f"{label}: {done}/{total} terminal | "
        f"released {counts['RELEASED']} quarantined {counts['QUARANTINED']} "
        f"unsupported {counts['UNSUPPORTED']} | exit code {exit_code}"
    )
    if not args.watch_only:
        print(f"log:    {log_path}")
        if new_report:
            print(f"report: {report_path}")
        else:
            print("report: not generated by this invocation; progress above is saved state")
        if not completed:
            tail = _log_tail(log_path, log_offset)
            if tail:
                print("This invocation's log tail:\n" + tail, file=sys.stderr)
    if child is not None:
        return exit_code or (0 if completed else 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
