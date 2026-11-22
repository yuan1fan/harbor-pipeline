#!/usr/bin/env python3
"""Reopen CVE-2026-75920 for a white-box author repair.

The reviewer returned ``revise`` with ``recommended_mode=white_box``, but the
author-resume allowance was already exhausted, so a plain ``run`` would stop at
the exhausted validation_error. This script only resets that repair budget and
marks the stored validation error as author-repairable. The existing
``solver-review.json`` is left intact and is fed back to the author.

Preview:
    python scripts/reset_75920_repair.py --dry-run

Apply:
    python scripts/reset_75920_repair.py

Then:
    python -m harbor_pipeline -c pipeline.solver120.toml run \
      --cve CVE-2026-75920 --run-id retry-9-20261120 \
      --profile qualification --workers 1
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN_ID = "retry-9-20261120"
CVE = "CVE-2026-75920"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_dir = ROOT / "runs" / RUN_ID / CVE
    state_path = run_dir / "state.json"
    review_path = run_dir / "solver-review.json"
    if not state_path.is_file():
        parser.error(f"missing state: {state_path}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("state") != "QUARANTINED":
        print(f"{CVE}: state is {state.get('state')}, not QUARANTINED; nothing to reset")
        return 0
    review = {}
    if review_path.is_file():
        review = json.loads(review_path.read_text(encoding="utf-8"))
    verdict = (review.get("review") or {}).get("verdict")
    mode = (review.get("review") or {}).get("recommended_mode")
    print(f"{CVE}: review verdict={verdict} recommended_mode={mode}")
    if verdict != "revise":
        print("warning: stored review is not a revise verdict; resetting anyway for operator retry")

    error = state.setdefault("error", {})
    detail = error.setdefault("detail", {})
    print("before:", {
        "attempts": state.get("attempts"),
        "category": error.get("category"),
        "recovery": detail.get("recovery_action") or error.get("recovery"),
    })
    if not args.dry_run:
        state.setdefault("attempts", {})["author_resume"] = 0
        state["attempts"]["repair"] = 0
        state["attempts"]["retry"] = 0
        detail["recovery_action"] = "author"
        detail["recovery_reason"] = "reviewer requested white_box presentation repair"
        state.setdefault("history", []).append({
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "from": "QUARANTINED",
            "to": "QUARANTINED",
            "note": "reset author repair allowance for white_box revision",
        })
        state["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("after:", {
            "attempts": state.get("attempts"),
            "category": error.get("category"),
            "recovery": detail.get("recovery_action"),
        })
        print("reset complete; solver-review.json preserved")
    else:
        print("dry-run: no state changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
