"""Report production yield separately from independent task correctness."""
from __future__ import annotations

import random
from collections import Counter, defaultdict
from pathlib import Path

from .evaluator import _wilson
from .release import verify_release
from .util import PipelineError, read_json, utc_now_text, write_json


def build_quality_report(run_dir: Path, *, sample_size: int = 30, seed: int = 0, review_file: Path | None = None) -> dict:
    run_dir = run_dir.resolve()
    reviews = read_json(review_file).get("reviews", []) if review_file else []
    if not isinstance(reviews, list):
        raise PipelineError("Review file must contain a reviews array")
    by_review = {}
    for review in reviews:
        if (review.get("independent") is not True or not review.get("reviewer")
                or not review.get("task_digest") or review.get("verdict") not in {"accepted", "rejected"}):
            raise PipelineError("Each independent review needs reviewer, task_digest, independent=true and accepted/rejected verdict")
        key = (review.get("cve_id"), review["task_digest"])
        if key in by_review:
            raise PipelineError(f"Duplicate independent review: {key[0]}")
        by_review[key] = review
    counts, failures = Counter(), Counter()
    tasks = []
    for state_path in sorted(run_dir.glob("CVE-*/state.json")):
        state = read_json(state_path)
        counts[state["state"]] += 1
        error = state.get("error") or {}
        if error.get("category"):
            failures[error["category"]] += 1
        root = state_path.parent
        if state["state"] != "RELEASED":
            continue
        release = root / "release"
        try:
            issues = verify_release(release)
            spec = read_json(release / "spec.json")
            manifest = read_json(release / "build-manifest.json")
            evaluation = read_json(release / "evaluation.json")
        except (OSError, PipelineError, ValueError) as exc:
            tasks.append({"cve_id": state["cve_id"], "package_issues": [str(exc)], "independent_review": "unreviewed"})
            continue
        review = by_review.get((state["cve_id"], manifest.get("task_digest")))
        tasks.append({
            "cve_id": state["cve_id"], "task_digest": manifest.get("task_digest"),
            "project": spec["product"]["name"], "ecosystem": spec["product"]["ecosystem"],
            "goal_family": (spec.get("task_goal") or {}).get("family", "secret_read"),
            "quality_tier": evaluation.get("quality_tier"), "package_issues": issues,
            "solver_reviewed": (root / "solver-review.json").is_file(),
            "independent_review": review["verdict"] if review else "unreviewed",
            "reviewer": review.get("reviewer") if review else None,
            "release_path": str(release),
        })
    accepted = sum(t["independent_review"] == "accepted" for t in tasks)
    reviewed = sum(t["independent_review"] != "unreviewed" for t in tasks)
    strata = defaultdict(list)
    for task in tasks:
        strata[(task.get("ecosystem", "unknown"), task.get("goal_family", "unknown"))].append(task)
    rng = random.Random(seed)
    for group in strata.values():
        rng.shuffle(group)
    sample = []
    groups = [strata[key] for key in sorted(strata)]
    while len(sample) < max(0, sample_size) and any(groups):
        for group in groups:
            if group and len(sample) < sample_size:
                sample.append(group.pop())
    budget = read_json(run_dir / "budget.json") if (run_dir / "budget.json").is_file() else None
    inputs = sum(counts.values())
    return {
        "schema_version": "1.0", "generated_at": utc_now_text(), "run_dir": str(run_dir),
        "denominator": "candidate state records in this run; not the CVE population",
        "inputs": inputs, "states": dict(counts), "failures": dict(failures),
        "release_rate": counts["RELEASED"] / inputs if inputs else None,
        "independent_correctness": {
            "reviewed": reviewed, "accepted": accepted, "unreviewed": len(tasks) - reviewed,
            "accuracy": accepted / reviewed if reviewed else None,
            "wilson_95": _wilson(accepted, reviewed) if reviewed else None,
        },
        "accounted_usage": budget.get("used") if budget else None,
        "training_effect": None,
        "training_effect_note": "Requires held-out before/after model evaluations; publication and oracle success do not measure learning gains.",
        "sampling": {"method": "round-robin ecosystem/goal-family strata", "seed": seed, "requested": sample_size, "sample": sample},
        "tasks": tasks,
    }


def write_quality_report(run_dir: Path, output: Path, **kwargs) -> dict:
    report = build_quality_report(run_dir, **kwargs)
    write_json(output, report)
    return report
