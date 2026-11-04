"""Candidate batches: deduplication, shared budgets, isolation and reports.

A batch never shares a candidate directory between workers. The only shared
object is the budget ledger, which is atomic on disk. Every input, including a
duplicate or an unsupported CVE id, ends with a terminal state in the report.
"""

from __future__ import annotations

import json
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Iterable

from . import SCHEMA_VERSION
from .backend import prune_task_images
from .budget import Ledger
from .config import Config
from .contracts import MAX_MATRIX_REPEATS, load_experiments, load_policy
from .repair import MAX_BUILD_RUNS, MAX_VERIFIER_RUNS
from .cves import supported_ids
from .release import write_dataset_manifest
from .util import PipelineError, read_json, write_json
from .worker import CandidateJob, run_candidate

_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Candidate:
    cve_id: str
    priority: int = 100
    notes: str = ""


@dataclass
class BatchPlan:
    run_id: str
    root: Path
    candidates: list[Candidate]
    unsupported: list[dict] = field(default_factory=list)
    duplicates: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    profile: str = "smoke"
    workers: int = 1
    shard_index: int = 0
    shard_count: int = 1
    limits: dict[str, float] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "run_id": self.run_id,
            "root": str(self.root),
            "profile": self.profile,
            "workers": self.workers,
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "candidates": [c.cve_id for c in self.candidates],
            "unsupported": self.unsupported,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "limits": self.limits,
        }


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def load_candidates(source: str | Path | None) -> tuple[list[Candidate], list[dict]]:
    """Parse a candidate list from JSON, TOML, a comma list, or the built-ins."""
    if source is None or str(source).strip().lower() == "builtin":
        return [Candidate(cve_id) for cve_id in supported_ids()], []
    text_source = str(source).strip()
    path = Path(text_source)
    if path.is_file():
        raw = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() == ".toml":
            data = tomllib.loads(raw)
        else:
            data = json.loads(raw)
        entries = data.get("candidates", []) if isinstance(data, dict) else data
    elif path.suffix.lower() in {".json", ".toml"}:
        raise PipelineError(f"Candidate file does not exist: {path}")
    else:
        entries = [part for part in re.split(r"[,\s]+", text_source) if part]

    if not isinstance(entries, list):
        raise PipelineError("Candidate input must be a list")
    candidates: list[Candidate] = []
    rejected: list[dict] = []
    for entry in entries:
        if isinstance(entry, str):
            value = {"cve_id": entry}
        elif isinstance(entry, dict):
            value = entry
        else:
            rejected.append({"input": str(entry), "reason": "not a CVE id or object"})
            continue
        cve_id = str(value.get("cve_id") or value.get("id") or "").strip()
        if not _CVE_RE.match(cve_id.upper()):
            rejected.append({"input": cve_id or str(entry), "reason": "invalid CVE id"})
            continue
        candidates.append(
            Candidate(
                cve_id=cve_id.upper(),
                priority=int(value.get("priority", 100)),
                notes=str(value.get("notes", "")),
            )
        )
    return candidates, rejected


def plan_batch(
    candidates: Iterable[Candidate],
    *,
    rejected: Iterable[dict] = (),
    run_id: str,
    profile: str,
    workers: int,
    limit: int | None = None,
    output_root: Path | None = None,
    max_repairs: int = 2,
    shard_index: int = 0,
    shard_count: int = 1,
    per_candidate_calls: int = 48,
    per_candidate_tokens: int = 540_000,
    per_candidate_usd: float = 9.0,
) -> BatchPlan:
    """Deduplicate candidates and size the shared budget.

    Any well-formed CVE id is a candidate: the pipeline discovers evidence and
    decides UNSUPPORTED only when public records cannot support a differential
    task. Support is a per-CVE outcome, never a property of a curated list.
    """
    policy = load_policy()
    profile_policy = policy.profile(profile)

    ordered = sorted(candidates, key=lambda c: (c.priority, c.cve_id))
    seen: dict[str, str] = {}
    unique: list[Candidate] = []
    duplicates: list[dict] = []
    unsupported: list[dict] = []
    for candidate in ordered:
        key = candidate.cve_id.upper()
        if key in seen:
            duplicates.append({"cve_id": key, "duplicate_of": seen[key]})
            continue
        seen[key] = key
        unique.append(Candidate(cve_id=key, priority=candidate.priority, notes=candidate.notes))
    if shard_count < 1 or not 0 <= shard_index < shard_count:
        raise PipelineError(
            f"Invalid shard {shard_index}/{shard_count}; need 0 <= index < count"
        )
    if shard_count > 1:
        # Stable modulo sharding keeps the same candidate on the same worker
        # across retries, while every shard can run as an independent process.
        unique = [
            candidate for index, candidate in enumerate(unique)
            if index % shard_count == shard_index
        ]
    if limit is not None:
        for dropped in unique[limit:]:
            unsupported.append({
                "cve_id": dropped.cve_id,
                "state": "UNSUPPORTED",
                "reason": f"excluded by batch limit {limit}",
            })
        unique = unique[:limit]

    mandatory = len([e for e in load_experiments() if e.id not in {"T03", "T04", "T09"}])
    repairs = max(0, max_repairs)
    # The batch ledger is sized before any bundle exists, so it must cover the
    # largest repeat count an author may request. The limit is a ceiling, not a
    # spend: the actual reservation follows the bundle.
    repeats = max(profile_policy.trials, MAX_MATRIX_REPEATS)
    # Each repair reruns the full matrix at a new revision, so the trial budget
    # per candidate covers the original run plus every repair attempt. The
    # repair agent may execute up to MAX_VERIFIER_RUNS paired verifier trials
    # and MAX_BUILD_RUNS build-only cycles.
    per_candidate = (
        (mandatory + 2 * repeats + 3) * (repairs + 1)
        + 2 * MAX_VERIFIER_RUNS * repairs
    )
    n = max(1, len(unique))
    limits = {
        "trials": float(per_candidate * n + 30),
        # Six images per revision plus six images per build or verifier tool
        # call in a repair.
        "builds": float(
            (
                6 * (repairs + 1)
                + 6 * (MAX_VERIFIER_RUNS + MAX_BUILD_RUNS) * repairs
            ) * n
            + 6
        ),
        "wall_sec": float(7200 * n),
        # The ledger is shared by every worker in the batch, so the per-candidate
        # model ceilings have to be multiplied out here. Leaving them at the
        # ledger defaults (12 calls / 180k tokens for the whole run) would stop
        # a campaign after the first few candidates.
        "calls": float(per_candidate_calls * n + 24),
        "tokens": float(per_candidate_tokens * n),
        "usd": float(per_candidate_usd * n),
    }
    root = (output_root or Path("runs")) / run_id
    return BatchPlan(
        run_id=run_id,
        root=root,
        candidates=unique,
        unsupported=unsupported,
        duplicates=duplicates,
        rejected=list(rejected),
        profile=profile,
        workers=max(1, workers),
        shard_index=shard_index,
        shard_count=shard_count,
        limits=limits,
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def run_batch(
    plan: BatchPlan,
    config: Config,
    *,
    scenario: str | None = None,
    output_root: Path | None = None,
    workers: int | None = None,
    prune_images: bool | None = None,
) -> dict:
    """Run every planned candidate in isolated threads under one ledger."""
    root = plan.root if output_root is None else output_root / plan.run_id
    root.mkdir(parents=True, exist_ok=True)
    ledger = Ledger.load_or_create(root / "budget.json", limits=plan.limits)
    # A run directory outlives a batch. The ledger it carries was sized by
    # whichever batch created it, and killed matrices leave reservations that
    # nothing will ever commit; both would starve this batch before it starts.
    ledger.raise_limits(plan.limits)
    ledger.reclaim_orphans(root)
    concurrency = max(1, workers or plan.workers)
    cleanup = config.pipeline.prune_images if prune_images is None else prune_images
    started_at = utc_now()

    results: dict[str, dict] = {}
    for item in plan.unsupported:
        results[item["cve_id"]] = _terminal_unsupported(plan.run_id, item)
    for item in plan.rejected:
        label = item.get("input") or "invalid-input"
        results[f"rejected:{label}"] = _terminal_unsupported(
            plan.run_id,
            {"cve_id": label, "state": "UNSUPPORTED", "reason": item["reason"]},
        )

    def job_for(candidate: Candidate) -> CandidateJob:
        return CandidateJob(
            cve_id=candidate.cve_id,
            run_id=plan.run_id,
            profile=plan.profile,
            scenario=scenario,
            # CvePipeline appends the run id itself; hand it the parent of the
            # run directory so every worker resumes <root>/<run-id>/<cve>.
            output_root=root.parent,
            ledger=ledger,
        )

    reports_dir = root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    if plan.candidates:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(plan.candidates))) as pool:
            futures = {
                pool.submit(run_candidate, job_for(candidate), config): candidate
                for candidate in plan.candidates
            }
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    payload = future.result()
                except Exception as exc:  # noqa: BLE001 - isolation backstop
                    payload = _terminal_unsupported(
                        plan.run_id,
                        {
                            "cve_id": candidate.cve_id,
                            "state": "QUARANTINED",
                            "reason": f"worker raised {type(exc).__name__}: {exc}",
                        },
                    )
                    payload["error"] = {
                        "category": "infra_error",
                        "message": f"{type(exc).__name__}: {exc}",
                        "retryable": True,
                    }
                if cleanup and payload.get("state") in {"RELEASED", "QUARANTINED", "UNSUPPORTED"}:
                    payload["pruned_images"] = _prune_candidate_images(root, candidate.cve_id)
                results[candidate.cve_id] = payload
                write_json(reports_dir / f"{candidate.cve_id}.json", payload)

    summary = _summary(plan, results, root, ledger.snapshot(), started_at)
    _write_dataset(plan, results, root, summary)
    write_json(root / "batch-report.json", summary)
    return summary


def _prune_candidate_images(root: Path, cve_id: str) -> list[str]:
    """Drop a finished candidate's build images; never fail the batch for it."""
    try:
        image_set = read_json(root / cve_id / "image-set.json")
    except (OSError, PipelineError):
        return []
    bases = image_set.get("tag_bases") or [image_set.get("tag_base")]
    removed: list[str] = []
    for base in bases:
        if not base:
            continue
        try:
            removed.extend(prune_task_images(str(base)))
        except Exception:  # noqa: BLE001 - storage cleanup is best effort
            continue
    return removed


def _summary(
    plan: BatchPlan,
    results: dict[str, dict],
    root: Path,
    budget: dict,
    started_at: str,
) -> dict:
    entries = []
    for cve_id, payload in results.items():
        error = payload.get("error") or {}
        entries.append({
            "cve_id": cve_id,
            "state": payload.get("state"),
            "admission_status": payload.get("admission_status"),
            "quality_score": payload.get("quality_score"),
            "quality_tier": payload.get("quality_tier"),
            "error_category": error.get("category"),
            "error_message": error.get("message"),
            "attempts": payload.get("attempts", 0),
            "report_path": payload.get("report_path")
            or str(root / "reports" / f"{cve_id}.json"),
        })
    entries.sort(key=lambda item: (item["state"], item["cve_id"]))
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    categories: dict[str, int] = {}
    for entry in entries:
        if entry["error_category"]:
            categories[entry["error_category"]] = categories.get(entry["error_category"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "batch_run_id": plan.run_id,
        "profile": plan.profile,
        "workers": plan.workers,
        "started_at": started_at,
        "finished_at": utc_now(),
        "counts": {
            "inputs": len(plan.candidates) + len(plan.unsupported) + len(plan.rejected),
            "candidates": len(plan.candidates),
            "duplicates": len(plan.duplicates),
            "rejected": len(plan.rejected),
            **counts,
        },
        "yield": _yield_summary(plan, counts),
        "state_counts": counts,
        "error_categories": categories,
        "candidates": entries,
        "difficulty_baseline": _difficulty_baseline(results, root),
        "budget": budget,
        "report_path": str(root / "batch-report.json"),
        "plan": plan.to_json(),
    }


def _write_dataset(
    plan: BatchPlan,
    results: dict[str, dict],
    root: Path,
    summary: dict,
) -> None:
    manifest_path = root / "dataset-manifest.json"
    # A run directory outlives a single batch. Tonight's two releases arrived in
    # two separate invocations, and each one rewrote this file with only its own
    # entries, so the earlier RELEASED task silently vanished from the dataset.
    # Keep the union, keyed by CVE id so a re-run cannot leave two rows.
    merged: dict[str, dict] = {}
    if manifest_path.is_file():
        try:
            previous = read_json(manifest_path).get("tasks") or []
        except (PipelineError, OSError, ValueError):
            previous = []
        for entry in previous:
            if isinstance(entry, dict) and entry.get("cve_id"):
                merged[str(entry["cve_id"])] = entry
    for payload in results.values():
        release = payload.get("release") or {}
        entry = release.get("dataset_entry")
        if entry and payload.get("state") == "RELEASED":
            merged[str(entry["cve_id"])] = entry
    entries = [merged[key] for key in sorted(merged)]
    summary["dataset"] = {
        "entries": entries,
        "path": None,
        "split_audit": {"ok": True, "conflicts": []},
    }
    if not entries:
        return
    manifest_path = write_dataset_manifest(entries, manifest_path)
    conflicts = _split_conflicts(entries)
    summary["dataset"] = {
        "entries": entries,
        "path": str(manifest_path),
        "split_audit": {
            "ok": not conflicts,
            "conflicts": conflicts,
        },
    }


def _split_conflicts(entries: list[dict]) -> list[dict]:
    """Grouping keys must never appear in two dataset splits."""
    seen: dict[tuple[str, str], str] = {}
    conflicts: list[dict] = []
    for entry in entries:
        key = (entry["project"], entry["root_cause_group"])
        split = entry["split"]
        previous = seen.setdefault(key, split)
        if previous != split:
            conflicts.append({
                "project": key[0],
                "root_cause_group": key[1],
                "splits": sorted({previous, split}),
            })
    return conflicts


def _yield_summary(plan: BatchPlan, counts: dict[str, int]) -> dict:
    inputs = len(plan.candidates) + len(plan.unsupported) + len(plan.rejected)
    released = counts.get("RELEASED", 0)
    return {
        "inputs": inputs,
        "released": released,
        "release_rate": round(released / inputs, 4) if inputs else 0.0,
    }


def _difficulty_baseline(results: dict[str, dict], root: Path) -> dict:
    durations: list[float] = []
    successes = 0
    total = 0
    seeds: dict[str, set] = {}
    for cve_id, payload in results.items():
        for record in payload.get("trials") or []:
            if record.get("experiment_id") == "T03":
                total += 1
                durations.append(float(record.get("duration_sec", 0.0)))
                successes += 1 if record.get("goal_result") == "passed" else 0
            if record.get("experiment_id") == "T09":
                seeds.setdefault(cve_id, set()).add(record.get("goal_result"))
    model_baseline = None
    note = "not measured; run `harbor-pipeline benchmark` against a released task"
    path = root / "model-baseline.json"
    if path.is_file():
        try:
            measured = read_json(path)
        except (OSError, ValueError) as exc:
            note = f"model-baseline.json is unreadable: {exc}"
        else:
            model_baseline = {
                key: measured.get(key)
                for key in (
                    "measured_at",
                    "agent",
                    "model_name",
                    "model_endpoint_host",
                    "model_identity",
                    "task_digest",
                    "environment_overlay",
                    "fixed_settings",
                    "attempts",
                    "successes",
                    "success_rate",
                    "median_duration_sec",
                    "usage",
                    "failure_types",
                )
            }
            model_baseline["path"] = str(path)
            note = "measured against a released task; not a task-quality signal"
    return {
        "oracle_success_rate": successes / total if total else 0.0,
        "oracle_median_seconds": median(durations) if durations else 0.0,
        "oracle_samples": total,
        "seed_consistent": all(values == {"passed"} for values in seeds.values()),
        # The oracle rate is only an upper bound on solvability. Model
        # difficulty comes from an explicit, recorded agent run.
        "model_baseline": model_baseline,
        "model_baseline_note": note,
    }


def _terminal_unsupported(run_id: str, item: dict) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": item["cve_id"],
        "run_id": run_id,
        "state": item.get("state", "UNSUPPORTED"),
        "task_digest": None,
        "image_digest": None,
        "quality_score": None,
        "quality_tier": None,
        "admission_status": None,
        "release": None,
        "evaluation": None,
        "trials": [],
        "error": {
            "category": "unsupported",
            "message": item.get("reason", "unsupported candidate"),
            "retryable": False,
        },
        "budget": {},
        "attempts": 0,
    }
