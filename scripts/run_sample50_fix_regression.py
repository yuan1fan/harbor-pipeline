#!/usr/bin/env python3
"""Run the eight-CVE sample50 recovery regression from this worktree.

Preview: python scripts/run_sample50_fix_regression.py --dry-run
Start:   python scripts/run_sample50_fix_regression.py
Resume:  python scripts/run_sample50_fix_regression.py --run-id <id> --resume

Uses a fresh run by default, checks local regressions first, and then delegates
the full release run to run_batch_progress.py. A case without its historical
transient fault does not prove that fault-handling branch was exercised.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tomllib
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "candidates/sample50-fix-regression-20261117.json"
CONFIG = ROOT / "pipeline.sample50-regression.toml"
LOCAL_TESTS = [
    "tests/test_sample50_lifecycle.py", "tests/test_sample50_xss.py",
    "tests/test_sample50_release.py", "tests/test_sample50_resolver.py",
    "tests/test_sample50_retries.py",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="sample50-fix-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--resume", action="store_true", help="continue the same run after its previous driver has stopped")
    parser.add_argument("--dry-run", action="store_true", help="print the plan; no tests, Docker cleanup, or model calls")
    parser.add_argument("--skip-unit-tests", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.run_id):
        parser.error("run-id must be a plain directory name")
    if not 1 <= args.workers <= 8:
        parser.error("workers must be between 1 and 8")
    cases = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ids = [item["cve_id"] for item in cases]
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    settings = config["pipeline"]
    if not settings.get("evidence_resolver") or not settings.get("solver_review"):
        parser.error("resolver and solver/reviewer must stay enabled for this regression")
    output = ROOT / "runs"
    run_dir = output / args.run_id
    if run_dir.exists():
        if not args.resume:
            parser.error("run already exists; choose a new run-id or use --resume")
        previous = run_dir / "batch-plan.json"
        if previous.is_file():
            old = json.loads(previous.read_text(encoding="utf-8"))
            if set(old.get("candidates", [])) != set(ids):
                parser.error("existing run has a different candidate set; use a new run-id")
        else:
            # Older normal batches did not write batch-plan.json. Resume is
            # safe when every existing CVE directory belongs to this manifest.
            existing = {path.name for path in run_dir.glob("CVE-*") if path.is_dir()}
            if existing and not existing <= set(ids):
                parser.error("existing states have a different candidate set; use a new run-id")
    elif args.resume:
        parser.error("cannot resume a run that does not exist")
    launch = [
        str(ROOT / "scripts/run_batch_progress.py"), "--input", str(MANIFEST),
        "--config", str(CONFIG), "--run-id", args.run_id, "--profile", "qualification",
        "--workers", str(args.workers), "--trial-workers", "1", "--output-dir", str(output),
    ]
    plan = {
        "run_id": args.run_id, "worktree": str(ROOT), "run_dir": str(run_dir),
        "candidates": ids, "workers": args.workers, "docker_slots": settings["docker_slots"],
        "trial_workers": 1, "until": "release", "profile": "qualification",
        "resource_dir": str((ROOT / settings["resource_dir"]).resolve()),
        "nvd_cache": str((ROOT / config["sources"]["nvd_feed_cache"]).resolve()),
        "command": [sys.executable, *launch], "local_tests": LOCAL_TESTS,
        "resume": args.resume, "imports_original_batch_sessions_or_verdicts": False,
    }
    print(json.dumps(plan, indent=2, ensure_ascii=False), flush=True)
    if args.dry_run:
        return 0
    # The child CLI must import this worktree even if another checkout is
    # installed with pip -e or is present in the caller's PYTHONPATH.
    os.chdir(ROOT)
    os.environ["PYTHONPATH"] = str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")
    log_root = ROOT / "work/sample50-fix-regression" / args.run_id
    log_root.mkdir(parents=True, exist_ok=True)
    plan["code_sha256"] = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "harbor_pipeline").rglob("*.py"))
    }
    plan["config_sha256"] = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    plan["manifest_sha256"] = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    (log_root / f"launch-{stamp}.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not args.skip_unit_tests:
        result = subprocess.run([sys.executable, "-m", "pytest", *LOCAL_TESTS, "-o", "addopts=", "-q", "-ra",
                                 f"--junitxml={log_root / ('local-tests-' + stamp + '.xml')}"], cwd=ROOT)
        if result.returncode:
            print("Local regression failed; the CVE batch was not started.", file=sys.stderr)
            return result.returncode
    sys.argv = launch
    # Keep the existing progress runner's Ctrl-C/owned-child cleanup behavior.
    runpy.run_path(launch[0], run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
