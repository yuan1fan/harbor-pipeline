#!/usr/bin/env python3
"""Requeue resolved UNSUPPORTED candidates and run their author/build/matrix tests.

This is a thin orchestrator around the existing CLI. It does not implement a
new pipeline stage and does not touch the source run: each candidate is copied
into a fresh ``EVIDENCE_READY`` run by ``requeue-resolved``.

Default flow per candidate:

    requeue-resolved -> run --until build -> run --until validate

``--until validate`` stops before solver/reviewer/release, so this is an
authoring/build/matrix smoke test, not a publication run.

Examples:

    python scripts/run_resolved_tests.py --dry-run
    python scripts/run_resolved_tests.py --run-id resolved-20261116-all --workers 2
    python scripts/run_resolved_tests.py --cve CVE-2026-2419 --until build
    python scripts/run_resolved_tests.py --run-id resolved-20261116-all --resume

Candidate processes can run concurrently with ``--workers``. The pipeline's
cross-process Docker admission still limits build/probe concurrency, and the
model gateway has its own concurrency limit, so ``--workers 2`` or ``3`` is a
better starting point than 9.

Logs and a summary are written under ``work/resolved-tests/<run-id>/`` by
default.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
_PRINT_LOCK = threading.Lock()

# Sources are the resolver replay copies, not the original scale-100 run.
DEFAULT_CANDIDATES: dict[str, str] = {
    "CVE-2026-10130": "work/resolver-eval/CVE-2026-10130",
    "CVE-2026-11470": "work/resolver-eval/CVE-2026-11470",
    "CVE-2026-2419": "work/resolver-test/CVE-2026-2419",
    "CVE-2026-2531": "work/resolver-eval/CVE-2026-2531",
    "CVE-2026-32749": "work/resolver-eval/CVE-2026-32749",
    "CVE-2026-40501": "work/resolver-eval/CVE-2026-40501",
    "CVE-2026-5328": "work/resolver-eval/CVE-2026-5328",
    "CVE-2026-8113": "work/resolver-eval/CVE-2026-8113",
    "CVE-2026-22661": "work/resolver-test/CVE-2026-22661",
}

BUILD_SUCCESS = {"BUILT", "VALIDATING", "VALIDATED", "RELEASED"}
VALIDATE_SUCCESS = {"VALIDATED", "RELEASED"}


def _say(message: str) -> None:
    with _PRINT_LOCK:
        print(message, flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _read_state(run_root: Path, cve: str) -> dict[str, Any]:
    path = run_root / cve / "state.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _run(
    command: list[str],
    *,
    log_path: Path,
    dry_run: bool,
) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    printable = " ".join(str(part) for part in command)
    _say(f"$ {printable}")
    if dry_run:
        return 0
    with log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"$ {printable}\n")
        log.flush()
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            log.write(f"\nERROR: {exc}\n")
            return 2
        log.write(
            f"\nEXIT: {completed.returncode}  "
            f"ELAPSED: {time.monotonic() - started:.1f}s\n"
        )
        return completed.returncode


def _status_line(state: str, error: dict[str, Any] | None) -> str:
    if error:
        category = str(error.get("category") or "")
        message = str(error.get("message") or "").replace("\n", " ")[:160]
        return f"{state} [{category}] {message}"
    return state


def _process_candidate(
    *,
    cve: str,
    source: Path,
    args: argparse.Namespace,
    run_root: Path,
    log_root: Path,
) -> dict[str, Any]:
    _say(f"=== {cve}")
    if not (source / "discovery.json").is_file():
        _say(f"  SKIP: source discovery missing: {source}")
        return {
            "cve_id": cve,
            "state": "MISSING_SOURCE",
            "source": str(source),
            "ok": False,
        }

    state = _read_state(run_root, cve)
    state_name = str(state.get("state") or "")
    requeued = False

    # Reusing the same --run-id is the normal way to resume after a pause.
    # Only a terminal state needs a fresh run id; an existing EVIDENCE_READY/
    # BUILT state must not be treated as "requeue failed" merely because the
    # helper's copy already exists.
    if state_name and state_name not in {"UNSUPPORTED", "QUARANTINED"}:
        _say(f"  resume: existing new-run state is {state_name}; skip requeue")
        requeued = True
    elif state_name in {"UNSUPPORTED", "QUARANTINED"}:
        _say(f"  ERROR: new run is already terminal ({state_name}); use a new --run-id")
        return {
            "cve_id": cve,
            "state": state_name,
            "source": str(source),
            "error": state.get("error"),
            "ok": False,
        }
    else:
        command = [
            sys.executable,
            "-m",
            "harbor_pipeline",
            "-c",
            args.config,
            "requeue-resolved",
            "--cve",
            cve,
            "--source-run-dir",
            str(source),
            "--run-id",
            args.run_id,
            "--output-dir",
            str(args.output_dir),
            "--json",
        ]
        code = _run(
            command,
            log_path=log_root / f"{cve}-requeue.log",
            dry_run=args.dry_run,
        )
        state = _read_state(run_root, cve)
        state_name = str(state.get("state") or "")
        requeued = args.dry_run or (code == 0 and state_name == "EVIDENCE_READY")
        _say(f"  requeue: exit={code} state={state_name or 'unknown'}")

    if not requeued:
        return {
            "cve_id": cve,
            "state": state_name or "REQUEUE_FAILED",
            "source": str(source),
            "error": state.get("error"),
            "ok": False,
        }

    if args.until == "requeue":
        return {
            "cve_id": cve,
            "state": "DRY_RUN" if args.dry_run else "EVIDENCE_READY",
            "source": str(source),
            "ok": True,
        }

    command = [
        sys.executable,
        "-m",
        "harbor_pipeline",
        "-c",
        args.config,
        "run",
        "--cve",
        cve,
        "--run-id",
        args.run_id,
        "--until",
        "build",
        "--output-dir",
        str(args.output_dir),
        "--json",
    ]
    code = _run(
        command,
        log_path=log_root / f"{cve}-build.log",
        dry_run=args.dry_run,
    )
    state = _read_state(run_root, cve)
    state_name = str(state.get("state") or "")
    build_ok = args.dry_run or (
        code in (0, 3) and state_name in BUILD_SUCCESS
    )
    _say(f"  build: exit={code} state={state_name or 'unknown'}")
    if not build_ok:
        return {
            "cve_id": cve,
            "state": state_name or "BUILD_FAILED",
            "source": str(source),
            "error": state.get("error"),
            "ok": False,
        }

    if args.until == "build":
        return {
            "cve_id": cve,
            "state": "DRY_RUN" if args.dry_run else (state_name or "BUILT"),
            "source": str(source),
            "ok": True,
        }

    command = [
        sys.executable,
        "-m",
        "harbor_pipeline",
        "-c",
        args.config,
        "run",
        "--cve",
        cve,
        "--run-id",
        args.run_id,
        "--until",
        "validate",
        "--output-dir",
        str(args.output_dir),
        "--json",
    ]
    code = _run(
        command,
        log_path=log_root / f"{cve}-validate.log",
        dry_run=args.dry_run,
    )
    state = _read_state(run_root, cve)
    state_name = str(state.get("state") or "")
    validate_ok = args.dry_run or (
        code == 0 and state_name in VALIDATE_SUCCESS
    )
    _say(f"  validate: exit={code} state={state_name or 'unknown'}")
    return {
        "cve_id": cve,
        "state": "DRY_RUN" if args.dry_run else (state_name or "VALIDATE_FAILED"),
        "source": str(source),
        "error": state.get("error"),
        "ok": validate_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-id",
        default=f"resolved-tests-{_now()}",
        help="new run id; must not already contain the selected candidates",
    )
    parser.add_argument("--config", default="pipeline.scale.toml")
    parser.add_argument("--output-dir", type=Path, default=Path("runs"))
    parser.add_argument(
        "--log-dir",
        type=Path,
        help="log/summary directory (default: work/resolved-tests/<run-id>)",
    )
    parser.add_argument(
        "--cve",
        action="append",
        dest="cves",
        help="restrict to one or more CVE ids (repeatable)",
    )
    parser.add_argument(
        "--until",
        choices=("requeue", "build", "validate", "all"),
        default="all",
        help="stop after requeue/build/validate, or run all (default)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="concurrent candidate processes (default 1; try 2-3, not 9)",
    )
    parser.add_argument(
        "--stop-on-fail",
        action="store_true",
        help="stop at the first failed candidate; requires --workers 1",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="if the new run already has a candidate state, skip requeue and continue",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.stop_on_fail and args.workers > 1:
        parser.error("--stop-on-fail requires --workers 1")

    selected = dict(DEFAULT_CANDIDATES)
    if args.cves:
        unknown = sorted(set(args.cves) - set(DEFAULT_CANDIDATES))
        if unknown:
            parser.error(f"unknown candidate(s): {', '.join(unknown)}")
        selected = {cve: selected[cve] for cve in args.cves}

    run_root = (args.output_dir / args.run_id).resolve()
    log_root = (
        args.log_dir
        if args.log_dir
        else ROOT / "work" / "resolved-tests" / args.run_id
    ).resolve()
    log_root.mkdir(parents=True, exist_ok=True)
    summary_path = log_root / "summary.json"

    _say(f"run:      {run_root}")
    _say(f"logs:     {log_root}")
    _say(f"mode:     {args.until}")
    _say(f"workers:  {args.workers}")
    _say("")

    results: dict[str, dict[str, Any]] = {}
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def run_one(cve: str, source: str) -> dict[str, Any]:
        return _process_candidate(
            cve=cve,
            source=(ROOT / source).resolve(),
            args=args,
            run_root=run_root,
            log_root=log_root,
        )

    if args.workers == 1:
        for cve, source in selected.items():
            result = run_one(cve, source)
            results[cve] = result
            if args.stop_on_fail and not result.get("ok"):
                break
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(run_one, cve, source): cve
                for cve, source in selected.items()
            }
            for future in as_completed(futures):
                cve = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - one candidate must not kill the run
                    result = {
                        "cve_id": cve,
                        "state": "SCRIPT_ERROR",
                        "error": {
                            "category": "infra_error",
                            "message": f"{type(exc).__name__}: {exc}",
                        },
                        "ok": False,
                    }
                results[cve] = result

    ordered = {cve: results[cve] for cve in selected if cve in results}
    failures = sum(1 for result in ordered.values() if not result.get("ok"))
    summary = {
        "run_id": args.run_id,
        "run_dir": str(run_root),
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "until": args.until,
        "workers": args.workers,
        "candidates": ordered,
        "failures": failures,
        "not_run": [cve for cve in selected if cve not in ordered],
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    _say("\n=== summary")
    for cve, result in ordered.items():
        _say(
            f"{cve:18} "
            f"{_status_line(str(result.get('state')), result.get('error'))}"
        )
    if summary["not_run"]:
        _say("not run:          " + ", ".join(summary["not_run"]))
    _say(f"\nfailures: {failures}")
    _say(f"summary:  {summary_path}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
