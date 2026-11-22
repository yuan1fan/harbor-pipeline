#!/usr/bin/env python3
"""Reclassify environment-blocked author declines from UNSUPPORTED to QUARANTINED.

Older runs recorded every ``harbor-author decline`` as UNSUPPORTED. A decline
caused by free disk, Docker, host memory, or an unreachable test network is an
infrastructure/capability failure, not a CVE verdict. This migration changes
only those states; a real CVE decline remains UNSUPPORTED.

Preview:
    python scripts/reclassify_infra_unsupported.py --run-id <run-id>

Apply:
    python scripts/reclassify_infra_unsupported.py --run-id <run-id> --apply

Stop the batch before applying, free disk space, then resume the same run.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harbor_pipeline import authoring
from harbor_pipeline.util import write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runs")
    parser.add_argument("--cve", help="only reclassify this CVE")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    run_dir = (args.output_dir / args.run_id).resolve()
    if not run_dir.is_dir():
        parser.error(f"run directory does not exist: {run_dir}")

    changed = 0
    for state_path in sorted(run_dir.glob("CVE-*/state.json")):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("state") != "UNSUPPORTED":
            continue
        if args.cve and state_path.parent.name.upper() != args.cve.upper():
            continue
        error = state.get("error") or {}
        reason = str(error.get("message") or "")
        category = authoring.decline_category(reason)
        if category != "infra_error":
            print(f"keep     {state_path.parent.name}: real CVE decline")
            continue
        changed += 1
        print(f"reclass  {state_path.parent.name}: UNSUPPORTED -> QUARANTINED (infra)")
        if not args.apply:
            continue
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state["state"] = "QUARANTINED"
        state["error"] = {
            "auto_repairable": False,
            "category": "infra_error",
            "detail": {
                "reclassified_infra_decline": True,
                "previous_category": "unsupported",
            },
            "message": reason[:4000],
            "recovery": {
                "action": "retry",
                "reason": "host/infrastructure decline reclassified",
            },
            "retryable": True,
            "terminal_state": "QUARANTINED",
        }
        attempts = state.setdefault("attempts", {})
        attempts["retry"] = 0
        state.setdefault("history", []).append({
            "at": now,
            "from": "UNSUPPORTED",
            "to": "QUARANTINED",
            "note": "reclassified infrastructure decline",
        })
        state["updated_at"] = now
        write_json(state_path, state)

    print(f"{changed} candidate(s) matched")
    if changed and not args.apply:
        print("dry-run: no state files changed; add --apply after freeing disk")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
