#!/usr/bin/env python3
"""Retry the four solver-budget Q candidates on an existing run.

These four tasks already completed author/build/validate. Their only failure was
the solver budget: three hit the 60-turn cap and one hit the $5 budget. This
script normalizes the stored Q error to a retryable solver-budget failure,
resets the infrastructure retry counter, and resumes the existing run with
``pipeline.solver120.toml`` (120 turns, $12).

Preview:
    python scripts/retry_solver_4.py --dry-run

Run:
    python scripts/retry_solver_4.py

The script refuses to touch a released candidate. It is sequential so only one
solver trial is active at a time.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
RUN_ID = "retry-9-20261120"
CONFIG = ROOT / "pipeline.solver120.toml"
CVES = [
    "CVE-2026-6249",
    "CVE-2026-71502",
    "CVE-2026-75920",
    "CVE-2026-60120",
]
BATCH_MARKERS = ("harbor_pipeline", "batch", RUN_ID)


def _has_live_batch() -> bool:
    for process in psutil.process_iter(["pid", "cmdline"]):
        try:
            command = " ".join(process.info.get("cmdline") or [])
            if all(marker in command for marker in BATCH_MARKERS):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def _solver_failure(cve: str) -> tuple[str, str]:
    """Return (kind, raw terminal summary) from the recorded solver result."""
    path = ROOT / "runs" / RUN_ID / cve / "solver-result.json"
    if not path.is_file():
        return "unknown", "solver-result.json is missing"
    data = json.loads(path.read_text(encoding="utf-8"))
    trials = data.get("trials") or []
    if not trials:
        return "unknown", "solver result has no trials"
    exception = trials[0].get("exception") or {}
    message = str(exception.get("exception_message") or "")
    if re.search(r"(?i)error_max_turns|Reached maximum number of turns|\bmax_turns\b", message):
        return "max_turns", "Reached maximum number of turns"
    if re.search(r"(?i)error_max_budget_usd|Reached maximum budget|\bbudget_exhausted\b", message):
        return "max_budget", "Reached maximum budget"
    return "unknown", str(exception.get("exception_type") or "solver exception")


def _prepare(cve: str, *, apply: bool) -> str:
    state_path = ROOT / "runs" / RUN_ID / cve / "state.json"
    if not state_path.is_file():
        return f"missing state.json for {cve}"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("state") == "RELEASED":
        return f"{cve}: already RELEASED; skipped"
    if state.get("state") != "QUARANTINED":
        return f"{cve}: state is {state.get('state')}; not a solver Q; skipped"
    kind, summary = _solver_failure(cve)
    if kind == "unknown":
        return f"{cve}: solver failure is not a turn/budget cap: {summary}; skipped"
    if apply:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state["error"] = {
            "auto_repairable": False,
            "category": "infra_error",
            "detail": {
                "solver_failure_type": kind,
                "solver_terminal_reason": summary,
                "reclassified_solver_budget": True,
                "retryable_model": True,
            },
            "message": (
                "Solver exhausted its turn budget; retry with the 120-turn solver config"
                if kind == "max_turns"
                else "Solver exhausted its USD budget; retry with the $12 solver config"
            ),
            "recovery": {"action": "retry", "reason": "solver budget exhausted"},
            "retryable": True,
            "terminal_state": "QUARANTINED",
        }
        state.setdefault("attempts", {})["retry"] = 0
        state.setdefault("history", []).append({
            "at": now,
            "from": "QUARANTINED",
            "to": "QUARANTINED",
            "note": f"reset solver {kind} budget for 120-turn retry",
        })
        state["updated_at"] = now
        state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return f"{cve}: prepared {kind} -> retryable solver Q"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="run even if a batch process is still alive")
    args = parser.parse_args()

    if not CONFIG.is_file():
        parser.error(f"missing config: {CONFIG}")
    if _has_live_batch() and not args.force:
        parser.error(f"a batch for {RUN_ID} is still running; pause it first")

    os.chdir(ROOT)
    os.environ["PYTHONPATH"] = str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")

    print("run:", RUN_ID)
    print("config:", CONFIG)
    for cve in CVES:
        print(_prepare(cve, apply=not args.dry_run))
    if args.dry_run:
        print("\ndry-run: no state changed, no solver started")
        return 0

    results: dict[str, str] = {}
    for cve in CVES:
        state_path = ROOT / "runs" / RUN_ID / cve / "state.json"
        before = json.loads(state_path.read_text(encoding="utf-8")).get("state") if state_path.is_file() else "missing"
        if before == "RELEASED":
            results[cve] = "RELEASED (skipped)"
            continue
        print("\n" + "=" * 90)
        print(f"running solver retry for {cve}")
        command = [
            sys.executable,
            "-m",
            "harbor_pipeline",
            "-c",
            str(CONFIG),
            "run",
            "--cve",
            cve,
            "--run-id",
            RUN_ID,
            "--profile",
            "qualification",
            "--workers",
            "1",
            "--trial-workers",
            "1",
        ]
        process = subprocess.run(command, cwd=ROOT)
        if state_path.is_file():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            results[cve] = str(state.get("state") or f"exit {process.returncode}")
        else:
            results[cve] = f"missing state (exit {process.returncode})"

    print("\n" + "=" * 90)
    print("summary")
    for cve in CVES:
        print(f"  {cve}: {results.get(cve, 'unknown')}")
    return 0 if all(value == "RELEASED" for value in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
