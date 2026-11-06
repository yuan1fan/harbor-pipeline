"""Command line interface for the CVE Harbor task pipeline.

Commands map one-to-one onto resumable pipeline stages. Every command accepts
``--run-id`` so an interrupted job can be continued instead of restarted.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from . import harvest as harvest_mod
from .backend import prune_orphan_task_resources
from .batch import load_candidates, plan_batch, run_batch
from .benchmark import measure_model_baseline, prepare_benchmark_task, write_model_baseline
from .config import load_config
from .cves import supported_ids
from .harbor_adapter import HarborAdapter, doctor
from .nvd_feed import NvdFeedCache
from .pipeline import CvePipeline
from .state import new_run_id
from .contracts import load_policy
from .util import PipelineError, read_json

STAGES = ("collect", "freeze", "generate", "build", "validate", "solver", "release")

EXIT_CODES = {
    "DISCOVERED": 3,
    "EVIDENCE_READY": 3,
    "SPEC_FROZEN": 3,
    "GENERATED": 3,
    "BUILT": 3,
    "VALIDATING": 3,
    "VALIDATED": 0,
    "RELEASED": 0,
    "REPAIRING": 3,
    "QUARANTINED": 3,
    "UNSUPPORTED": 4,
}


def _default_config() -> Path | None:
    candidate = Path("pipeline.toml")
    return candidate if candidate.is_file() else None


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", type=Path, help="override runs/ output root")
    parser.add_argument("--run-id", help="reuse an existing run id to resume it")
    parser.add_argument("--profile", default="smoke", help="acceptance profile")
    parser.add_argument(
        "--scenario",
        help="scenario template, or 'auto' to synthesize a task from evidence",
    )
    parser.add_argument("--workers", type=int, default=None, help="concurrent CVE jobs")
    parser.add_argument(
        "--trial-workers",
        type=int,
        default=None,
        help="concurrent trials inside one CVE job (overrides pipeline.trial_workers)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def _add_cve(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cve",
        required=True,
        help="any CVE id, e.g. CVE-2023-40587; curated CVEs reuse their template",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harbor-pipeline",
        description="Evidence-driven CVE task generation and differential validation",
    )
    parser.add_argument("-c", "--config", type=Path, help="pipeline TOML (default: ./pipeline.toml)")
    parser.add_argument("--version", action="version", version=f"harbor-pipeline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    quality_cmd = sub.add_parser("quality", help="audit released packages and independently reviewed correctness without model calls")
    quality_cmd.add_argument("--run-dir", type=Path, required=True)
    quality_cmd.add_argument("--output", type=Path, required=True)
    quality_cmd.add_argument("--sample-size", type=int, default=30)
    quality_cmd.add_argument("--seed", type=int, default=0)
    quality_cmd.add_argument("--review-file", type=Path)
    merge_cmd = sub.add_parser("dataset-merge", help="merge shards and recompute leakage-safe global splits")
    merge_cmd.add_argument("--input", type=Path, nargs="+", required=True)
    merge_cmd.add_argument("--output", type=Path, required=True)
    archive_cmd = sub.add_parser("archive-release", help="export measured images and a pinned executable task for offline replay")
    archive_cmd.add_argument("--release-dir", type=Path, required=True)
    archive_cmd.add_argument("--output-dir", type=Path, required=True)

    doctor_cmd = sub.add_parser("doctor", help="check host, Harbor, Docker and policy")
    doctor_cmd.add_argument("--json", action="store_true")
    doctor_cmd.add_argument(
        "--agent",
        action="store_true",
        help="also run a tiny native Claude Code session (Read/Write tools)",
    )

    preflight_cmd = sub.add_parser(
        "preflight", help="check Docker, disk, ports and concurrency before a batch"
    )
    preflight_cmd.add_argument("--output-dir", type=Path)
    preflight_cmd.add_argument("--workers", type=int)
    preflight_cmd.add_argument("--trial-workers", type=int)
    preflight_cmd.add_argument("--min-free-gb", type=float, default=60.0)
    preflight_cmd.add_argument("--task-memory-mb", type=int, default=2048)
    preflight_cmd.add_argument(
        "--require-port", type=int, action="append", dest="required_port",
        help="port that must be excluded from the Windows dynamic range (repeatable)",
    )
    preflight_cmd.add_argument(
        "--clean", action="store_true",
        help="remove exited task__* containers and dangling task__* networks",
    )
    preflight_cmd.add_argument(
        "--clean-images", action="store_true",
        help="also remove project-scoped task__* images",
    )
    preflight_cmd.add_argument("--json", action="store_true")

    run_cmd = sub.add_parser("run", help="run one CVE end to end")
    _add_cve(run_cmd)
    _add_output_args(run_cmd)
    run_cmd.add_argument("--until", choices=STAGES, default="release")

    recheck_cmd = sub.add_parser(
        "recheck",
        help="re-score a QUARANTINED candidate after a verifier/evaluator fix",
    )
    _add_cve(recheck_cmd)
    _add_output_args(recheck_cmd)

    for stage in STAGES:
        stage_cmd = sub.add_parser(stage, help=f"advance one CVE up to {stage}")
        _add_cve(stage_cmd)
        _add_output_args(stage_cmd)

    batch_cmd = sub.add_parser("batch", help="run several CVEs with a shared ledger")
    batch_cmd.add_argument(
        "--input",
        help="JSON/TOML candidate file, comma-separated ids, or 'builtin'",
    )
    batch_cmd.add_argument("--limit", type=int, help="maximum candidates in this batch")
    batch_cmd.add_argument(
        "--shard-index", type=int, default=0,
        help="zero-based shard to run on this host",
    )
    batch_cmd.add_argument(
        "--shard-count", type=int, default=1,
        help="number of stable shards across production hosts",
    )
    batch_cmd.add_argument(
        "--plan-only", action="store_true",
        help="write the resolved plan and exit without building anything",
    )
    batch_cmd.add_argument(
        "--prune-images", action="store_true",
        help="remove a candidate's images after it reaches a terminal state",
    )
    _add_output_args(batch_cmd)

    harvest_cmd = sub.add_parser(
        "harvest", help="download an NVD year feed and rank CVE candidates"
    )
    harvest_cmd.add_argument("--year", type=int, default=2026)
    harvest_cmd.add_argument(
        "--output", type=Path, help="candidate manifest (default candidates/cve-<year>.json)"
    )
    harvest_cmd.add_argument(
        "--cache-dir", type=Path, default=Path("work/harvest"),
        help="directory for the cached NVD feed",
    )
    harvest_cmd.add_argument("--limit", type=int, help="keep the best N candidates")
    harvest_cmd.add_argument(
        "--include-all", action="store_true",
        help="skip the web-facing prefilter and include every id in the year",
    )
    harvest_cmd.add_argument("--refresh", action="store_true", help="re-download the feed")
    harvest_cmd.add_argument("--json", action="store_true")

    triage_cmd = sub.add_parser(
        "triage", help="run discovery-only evidence checks on a candidate manifest"
    )
    triage_cmd.add_argument("--input", type=Path, required=True)
    triage_cmd.add_argument("--output", type=Path, help="eligible-candidate manifest")
    triage_cmd.add_argument(
        "--cache-dir", type=Path, default=Path("work/triage"),
        help="per-CVE evidence cache; reruns do not refetch",
    )
    triage_cmd.add_argument("--workers", type=int, default=4)
    triage_cmd.add_argument("--limit", type=int)
    triage_cmd.add_argument("--no-cache", action="store_true")
    triage_cmd.add_argument("--json", action="store_true")

    nvd_cmd = sub.add_parser(
        "nvd-cache",
        help="index a cached NVD yearly feed so triage avoids the rate-limited API",
    )
    nvd_cmd.add_argument("--year", type=int, default=2026)
    nvd_cmd.add_argument(
        "--cache-dir",
        type=Path,
        help="feed and index directory (default: [sources].nvd_feed_cache)",
    )
    nvd_cmd.add_argument("--refresh", action="store_true", help="re-download the feed")
    nvd_cmd.add_argument("--json", action="store_true")

    resume_cmd = sub.add_parser("resume", help="continue an interrupted run")
    _add_cve(resume_cmd)
    _add_output_args(resume_cmd)
    resume_cmd.add_argument("--until", choices=STAGES, default="release")

    report_cmd = sub.add_parser("report", help="summarise a run or one candidate")
    report_cmd.add_argument("--run-id", required=True)
    report_cmd.add_argument("--cve", help="restrict to one CVE")
    report_cmd.add_argument("--output-dir", type=Path)
    report_cmd.add_argument("--json", action="store_true")

    bench_cmd = sub.add_parser(
        "benchmark", help="measure a credentialed agent's difficulty on a released task"
    )
    bench_cmd.add_argument("--run-id", required=True)
    bench_cmd.add_argument("--cve", help="released CVE to measure")
    bench_cmd.add_argument("--output-dir", type=Path)
    bench_cmd.add_argument("--agent", default="claude-code", help="Harbor agent name")
    bench_cmd.add_argument(
        "--model", default="deepseek-flash-cyber", help="agent model name"
    )
    bench_cmd.add_argument("--attempts", type=int, default=3)
    bench_cmd.add_argument("--max-turns", type=int, default=30)
    bench_cmd.add_argument("--max-budget-usd", default="2.0")
    bench_cmd.add_argument("--timeout-sec", type=int)
    bench_cmd.add_argument(
        "--from-job",
        type=Path,
        help="summarize an existing model-baseline job instead of running a new one",
    )
    bench_cmd.add_argument(
        "--docker-image",
        help="prebuilt agent runtime image; the released task is copied and only "
        "environment/Dockerfile is replaced with FROM <image>",
    )
    bench_cmd.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "archive-release":
        from .image_archive import archive_release_images
        try:
            print(json.dumps(archive_release_images(args.release_dir, args.output_dir), indent=2))
            return 0
        except (OSError, ValueError, PipelineError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "dataset-merge":
        from .dataset import merge_manifests
        try:
            print(json.dumps(merge_manifests(args.input, args.output), indent=2))
            return 0
        except (OSError, ValueError, PipelineError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "quality":
        from .quality_report import write_quality_report
        try:
            report = write_quality_report(args.run_dir, args.output, sample_size=args.sample_size,
                                          seed=args.seed, review_file=args.review_file)
        except (OSError, ValueError, PipelineError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({key: value for key, value in report.items() if key not in {"tasks", "sampling"}}, indent=2))
        return 0
    try:
        config = load_config(args.config or _default_config())
    except FileNotFoundError as exc:
        print(f"error: configuration not found: {exc}", file=sys.stderr)
        return 2
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "doctor":
            return _doctor(config, args)
        if args.command == "preflight":
            return _preflight(config, args)
        if args.command == "batch":
            return _batch(config, args)
        if args.command == "harvest":
            return _harvest(config, args)
        if args.command == "triage":
            return _triage(config, args)
        if args.command == "nvd-cache":
            return _nvd_cache(config, args)
        if args.command == "report":
            return _report_command(config, args)
        if args.command == "benchmark":
            return _benchmark(config, args)
        if args.command == "recheck":
            return _recheck(config, args)
        return _single(config, args)
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------
# Single candidate
# ---------------------------------------------------------------------------


def _recheck(config, args) -> int:
    if not args.run_id:
        print(
            "error: recheck needs --run-id pointing at the quarantined run",
            file=sys.stderr,
        )
        return 2
    output_root = Path(args.output_dir) if args.output_dir else None
    prune_orphan_task_resources()
    pipeline = CvePipeline(
        config=config,
        cve_id=args.cve,
        run_id=args.run_id,
        profile=args.profile,
        scenario=args.scenario,
        workers=args.workers or config.pipeline.trial_workers,
        output_root=output_root,
    )
    report = pipeline.recheck()
    payload = report.to_json()
    payload["report_path"] = str(pipeline.root / "report.json")
    _write_json(Path(payload["report_path"]), payload)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _print_report(payload)
    return EXIT_CODES.get(report.state, 3)


def _single(config, args) -> int:
    until = "release" if args.command == "run" else args.command
    until = getattr(args, "until", until) if args.command in {"run", "resume"} else until
    run_id = args.run_id or new_run_id("run")
    output_root = Path(args.output_dir) if args.output_dir else None
    # A killed earlier attempt leaves unused task__* networks behind; enough
    # of them exhaust Docker's address pools and every trial fails to start.
    prune_orphan_task_resources()
    pipeline = CvePipeline(
        config=config,
        cve_id=args.cve,
        run_id=run_id,
        profile=args.profile,
        scenario=args.scenario,
        workers=args.workers or config.pipeline.trial_workers,
        output_root=output_root,
    )
    report = pipeline.run(until=until)
    payload = report.to_json()
    payload["report_path"] = str(pipeline.root / "report.json")
    _write_json(Path(payload["report_path"]), payload)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _print_report(payload)
    return EXIT_CODES.get(report.state, 3)


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------


def _batch(config, args) -> int:
    if args.trial_workers:
        # Trial concurrency is the memory-critical knob: every trial starts its
        # own compose project with a target and an attacker container, so the
        # load is workers × trial_workers. A host shared with other work needs
        # a lower value than a dedicated campaign machine.
        config.pipeline.trial_workers = max(1, args.trial_workers)
    run_id = args.run_id or new_run_id("batch")
    output_root = Path(args.output_dir) if args.output_dir else Path(config.pipeline.output_dir)
    # Reclaim networks from killed trials before Docker's address pool runs out.
    prune_orphan_task_resources()
    candidates, rejected = load_candidates(args.input)
    if config.pipeline.authoring == "agent":
        author = config.model_for("author")
        attempts = config.pipeline.author_max_resumes + 2
        per_calls = author.max_turns * attempts
        per_tokens = config.pipeline.max_total_tokens * attempts
        per_usd = (
            author.max_budget_usd * attempts
            + config.pipeline.solver_max_budget_usd
            * config.pipeline.solver_attempts
            * attempts
        )
    else:
        # A repair reruns synthesis (with up to three JSON retries) and the
        # matrix, so calls scale with max_repairs + 1 attempts.
        per_calls = config.pipeline.max_calls * (config.pipeline.max_repairs + 2)
        per_tokens = config.pipeline.max_total_tokens * (config.pipeline.max_repairs + 1)
        per_usd = config.models["default"].max_budget_usd * (
            config.pipeline.max_repairs + 2
        )
    plan = plan_batch(
        candidates,
        rejected=rejected,
        run_id=run_id,
        profile=args.profile,
        workers=args.workers or config.pipeline.workers,
        limit=args.limit,
        output_root=output_root,
        max_repairs=config.pipeline.max_repairs,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        per_candidate_calls=per_calls,
        per_candidate_tokens=per_tokens,
        per_candidate_usd=per_usd,
    )
    if args.plan_only:
        plan_path = plan.root / "batch-plan.json"
        payload = plan.to_json()
        payload["plan_path"] = str(plan_path)
        _write_json(plan_path, payload)
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(
                f"batch plan {plan.run_id}: {len(plan.candidates)} candidates "
                f"shard={plan.shard_index}/{plan.shard_count} -> {plan_path}"
            )
        return 0
    summary = run_batch(
        plan,
        config,
        scenario=args.scenario,
        output_root=output_root,
        workers=args.workers or config.pipeline.workers,
        prune_images=args.prune_images or config.pipeline.prune_images,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        _print_batch(summary)
    return 0 if summary["counts"].get("QUARANTINED", 0) == 0 else 3


# ---------------------------------------------------------------------------
# Harvest and triage
# ---------------------------------------------------------------------------


def _harvest(config, args) -> int:
    output = args.output or Path(f"candidates/cve-{args.year}.json")
    summary = harvest_mod.harvest(
        settings=config.sources,
        year=args.year,
        output=output,
        cache_dir=args.cache_dir,
        limit=args.limit,
        include_all=args.include_all,
        refresh=args.refresh,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        stats = summary["stats"]
        print(f"harvest {args.year}: {stats['kept']} candidates -> {summary['output']}")
        print(
            f"  feed={stats['feed_total']} kept={stats['kept']} "
            f"with_commit={stats['with_commit']} with_advisory={stats['with_advisory']}"
        )
        if stats.get("by_primitive"):
            print(f"  primitives: {json.dumps(stats['by_primitive'], ensure_ascii=False)}")
        if stats.get("dropped"):
            print(f"  dropped: {json.dumps(stats['dropped'], ensure_ascii=False)}")
    return 0


def _triage(config, args) -> int:
    candidates = harvest_mod.load_manifest(args.input)
    output = args.output or args.input.with_name(args.input.stem + "-triage.json")
    summary = harvest_mod.triage(
        settings=config.sources,
        candidates=candidates,
        output=output,
        cache_dir=args.cache_dir,
        workers=args.workers,
        limit=args.limit,
        no_cache=args.no_cache,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        stats = summary["stats"]
        print(f"triage {args.input}: {stats['eligible']} eligible -> {summary['output']}")
        print(
            f"  inputs={stats['inputs']} eligible={stats['eligible']} "
            f"unsupported={stats['unsupported']} errors={stats['errors']} "
            f"yield={stats['yield_rate']:.3f} cache_hits={stats['cache_hits']}"
        )
        if stats.get("by_ecosystem"):
            print(f"  ecosystems: {json.dumps(stats['by_ecosystem'], ensure_ascii=False)}")
    return 0


def _nvd_cache(config, args) -> int:
    cache_dir = args.cache_dir or config.sources.nvd_feed_cache
    if not cache_dir:
        print(
            "error: set [sources].nvd_feed_cache or pass --cache-dir",
            file=sys.stderr,
        )
        return 2
    cache = NvdFeedCache(
        Path(cache_dir), max_age_sec=config.sources.nvd_feed_max_age_sec
    )
    provenance = cache.ensure(config.sources, args.year, refresh=args.refresh)
    payload = provenance.to_json() | {"cache_dir": str(cache_dir)}
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(
            f"nvd feed {args.year}: {provenance.records} records indexed in "
            f"{provenance.elapsed_sec}s ({provenance.feed_sha256[:12]}, "
            f"{provenance.database_bytes} bytes) -> {provenance.database}"
        )
    return 0


# ---------------------------------------------------------------------------
# Model difficulty baseline
# ---------------------------------------------------------------------------


def _benchmark(config, args) -> int:
    root = Path(args.output_dir) if args.output_dir else Path(config.pipeline.output_dir)
    run_dir = (root / args.run_id).resolve()
    releases = sorted(
        path.parents[2].name
        for path in run_dir.glob("CVE-*/release/task/task.toml")
    )
    if args.cve:
        if args.cve not in releases:
            print(f"error: {args.cve} has no released task under {run_dir}", file=sys.stderr)
            return 2
        cve_id = args.cve
    elif len(releases) == 1:
        cve_id = releases[0]
    else:
        print(
            "error: choose --cve; run has "
            + (f"{len(releases)} released tasks" if releases else "no released tasks"),
            file=sys.stderr,
        )
        return 2
    source_task = run_dir / cve_id / "release" / "task"
    task_digest = None
    manifest_path = run_dir / cve_id / "release" / "build-manifest.json"
    if manifest_path.is_file():
        task_digest = str(read_json(manifest_path).get("task_digest") or "")
    task_dir = source_task
    if args.docker_image and args.from_job is None:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        task_dir = prepare_benchmark_task(
            source_task,
            run_dir / "model-benchmark" / cve_id / f"task-{stamp}",
            args.docker_image,
        )
    adapter = HarborAdapter(
        jobs_dir=run_dir / "model-jobs",
        run_root=run_dir,
        timeout_sec=config.pipeline.command_timeout_sec,
    )
    result = measure_model_baseline(
        adapter,
        task_dir,
        agent=args.agent,
        model_name=args.model,
        attempts=args.attempts,
        max_turns=args.max_turns,
        max_budget_usd=args.max_budget_usd,
        timeout_sec=args.timeout_sec or 3600,
        task_digest=task_digest,
        environment_overlay=args.docker_image,
        source_task_dir=source_task,
        from_job=args.from_job,
    )
    result["cve_id"] = cve_id
    result["benchmark_task_dir"] = str(task_dir)
    path = write_model_baseline(run_dir, result)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"model baseline {cve_id}: {args.agent}/{args.model}")
        print(
            f"  success {result['successes']}/{result['attempts']} "
            f"({result['success_rate']:.2f}), median {result['median_duration_sec']}s"
        )
        if result.get("environment_overlay"):
            print(f"  environment overlay: {result['environment_overlay']}")
        if result.get("model_identity"):
            print(f"  identity: {json.dumps(result['model_identity'], ensure_ascii=False)}")
        if result.get("failure_types"):
            print(f"  failures: {json.dumps(result['failure_types'], ensure_ascii=False)}")
        usage = result.get("usage") or {}
        if usage.get("cost_usd") is not None:
            print(f"  cost_usd: {usage['cost_usd']}")
        print(f"  report: {path}")
    return 0


# ---------------------------------------------------------------------------
# Doctor and report
# ---------------------------------------------------------------------------


def _preflight(config, args) -> int:
    from .preflight import DEFAULT_REQUIRED_PORTS, run_preflight

    output_dir = Path(args.output_dir) if args.output_dir else Path(config.pipeline.output_dir)
    result = run_preflight(
        output_dir=output_dir,
        workers=args.workers or config.pipeline.workers,
        trial_workers=args.trial_workers or config.pipeline.trial_workers,
        min_free_gb=args.min_free_gb,
        required_ports=tuple(args.required_port or DEFAULT_REQUIRED_PORTS),
        task_memory_mb=args.task_memory_mb,
        clean=args.clean,
        clean_images=args.clean_images,
    )
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    else:
        symbols = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
        for check in result["checks"]:
            print(f"{symbols[check['status']]:4}  {check['id']}: {check['detail']}")
        print("preflight ok" if result["ok"] else "preflight failed")
    return 0 if result["ok"] else 1


def _doctor(config, args) -> int:
    adapter = HarborAdapter(
        jobs_dir=Path(config.pipeline.output_dir) / "doctor-jobs",
        run_root=Path(config.pipeline.output_dir) / "doctor",
        timeout_sec=config.pipeline.command_timeout_sec,
    )
    policy_summary = _policy_summary()
    require_allowlist = bool(
        load_policy().hard_conditions.get("require_network_allowlist", False)
    )
    report = doctor(adapter, require_network_allowlist=require_allowlist)
    report["supported_cves"] = supported_ids()
    report["policy"] = policy_summary
    report["models"] = _model_health(config)
    if getattr(args, "agent", False):
        agent_report = _agent_doctor(config)
        report["agent"] = agent_report
        report["ok"] = bool(report.get("ok")) and bool(agent_report.get("ok"))
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"python {report['python']} on {report['platform']}")
        for check in report["checks"]:
            mark = "ok" if check["ok"] else "FAIL"
            print(f"  [{mark}] {check['name']}: {check['detail']}")
        print(f"supported CVEs: {', '.join(report['supported_cves']) or 'none'}")
        print(f"profiles: {', '.join(report['policy']['profiles'])}")
        for role, health in report["models"].items():
            state = "ok" if health.get("ok") else "unavailable"
            detail = health.get("model") or health.get("error", "")
            print(f"  model[{role}]: {state} ({detail})")
        agent = report.get("agent")
        if agent:
            mark = "ok" if agent.get("ok") else "FAIL"
            print(
                f"  [{mark}] native agent: status={agent.get('status')} "
                f"turns={agent.get('turns')} {agent.get('error', '')[:200]}"
            )
    return 0 if report["ok"] else 1


def _agent_doctor(config) -> dict:
    """Run one tiny native session to prove auth, tools and permissions work."""
    import dataclasses
    import tempfile

    from .agent import ClaudeCodeAgent, build_agent_settings
    from .util import write_json

    settings = dataclasses.replace(
        config.model_for("author"), max_turns=8, max_budget_usd=0.5, timeout_sec=120
    )
    config = dataclasses.replace(
        config,
        models={**config.models, "author": settings},
    )
    root = Path(tempfile.mkdtemp(prefix="harbor-agent-doctor-"))
    workspace = root / "ws"
    workspace.mkdir()
    (workspace / "hello.txt").write_text("AUTHOR-OK\n", encoding="utf-8")
    permissions = build_agent_settings(settings.model)
    permissions["permissions"]["allow"] = ["Read", "Write", "Edit", "Grep", "Glob"]
    settings_path = root / "settings.json"
    write_json(settings_path, permissions)
    try:
        agent = ClaudeCodeAgent(config, role="author")
        outcome = agent.run(
            prompt=(
                "Read hello.txt and write its exact contents to answer.txt. "
                "If the Write tool is unavailable, use Edit to create answer.txt. "
                "Then stop."
            ),
            workspace=workspace,
            contract=(
                "You are a native-tool smoke test. Use Read and Write/Edit only."
            ),
            settings_path=settings_path,
        )
    except Exception as exc:  # noqa: BLE001 - doctor must report, not raise
        return {"ok": False, "status": "unavailable", "error": str(exc)}
    answer = workspace / "answer.txt"
    ok = answer.is_file() and answer.read_text(
        encoding="utf-8", errors="replace"
    ).strip() == "AUTHOR-OK"
    return {
        "ok": ok,
        "status": outcome.status,
        "session_id": outcome.session_id,
        "turns": outcome.turns,
        "usd": outcome.usd,
        "error": outcome.error[:1000],
        "workspace": str(workspace),
    }


def _report_command(config, args) -> int:
    root = Path(args.output_dir) if args.output_dir else Path(config.pipeline.output_dir)
    run_dir = (root / args.run_id).resolve()
    if not run_dir.is_dir():
        print(f"error: no run at {run_dir}", file=sys.stderr)
        return 2
    batch_report = run_dir / "batch-report.json"
    if batch_report.is_file() and not args.cve:
        payload = read_json(batch_report)
        _print_or_json(payload, args.json)
        return 0
    if args.cve:
        path = run_dir / args.cve / "report.json"
        if not path.is_file():
            path = run_dir / "reports" / f"{args.cve}.json"
        if not path.is_file():
            print(f"error: no report for {args.cve} under {run_dir}", file=sys.stderr)
            return 2
        _print_or_json(read_json(path), args.json)
        return 0
    summary = _scan_run(run_dir)
    _print_or_json(summary, args.json)
    return 0


def _scan_run(run_dir: Path) -> dict:
    entries = []
    for state_path in sorted(run_dir.glob("CVE-*/state.json")):
        state = read_json(state_path)
        entries.append({
            "cve_id": state["cve_id"],
            "run_id": state["run_id"],
            "state": state["state"],
            "revision": state["revision"],
            "error": state.get("error"),
            "artifacts": sorted(state.get("artifacts", {})),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_dir.name,
        "tasks": entries,
        "state_counts": _counts(e["state"] for e in entries),
    }


def _model_health(config) -> dict:
    """Advisory provider health; template generation does not require a model."""
    from .providers import build_provider

    health: dict = {}
    for role in ("default", "repairer"):
        try:
            health[role] = dict(build_provider(config, role).health())
        except Exception as exc:  # noqa: BLE001 - absence is reported, not fatal
            health[role] = {"ok": False, "error": str(exc)}
    if config.pipeline.authoring == "agent":
        try:
            from .agent import ClaudeCodeAgent

            health["author"] = ClaudeCodeAgent(config, role="author").health()
        except Exception as exc:  # noqa: BLE001 - absence is reported
            health["author"] = {"ok": False, "error": str(exc)}
    return health


def _policy_summary() -> dict:
    policy = load_policy()
    return {
        "policy_version": policy.policy_version,
        "weights": policy.weights,
        "profiles": {
            name: {
                "trials": profile.trials,
                "min_valid_trials": profile.min_valid_trials,
            }
            for name, profile in policy.profiles.items()
        },
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _counts(values) -> dict:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _print_or_json(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _print_report(payload: dict) -> None:
    print(f"{payload['cve_id']}  {payload['state']}")
    if payload.get("admission_status"):
        quality = payload.get("quality_tier") or payload.get("quality_score")
        print(
            f"  admission={payload['admission_status']} "
            f"quality={quality} "
            f"trials={len(payload.get('trials') or [])}"
        )
    if payload.get("image_digest"):
        print(f"  artifact={payload['image_digest']}")
    if payload.get("task_digest"):
        print(f"  task_digest={payload['task_digest']}")
    if payload.get("release"):
        print(f"  release={payload['release'].get('root')}")
    error = payload.get("error")
    if error:
        print(f"  error[{error.get('category')}]: {error.get('message')}")
    budget = payload.get("budget", {})
    used = budget.get("used", {})
    if used:
        print(
            "  budget: "
            + ", ".join(f"{k}={v:g}" for k, v in sorted(used.items()) if v)
        )


def _print_batch(summary: dict) -> None:
    print(f"batch {summary['batch_run_id']}  profile={summary['profile']}")
    print("  states: " + ", ".join(f"{k}={v}" for k, v in sorted(summary["counts"].items())))
    for item in summary["candidates"]:
        tail = ""
        if item.get("admission_status"):
            quality = item.get("quality_tier") or item.get("quality_score")
            tail = f" admission={item['admission_status']} quality={quality}"
        if item.get("error_category"):
            tail += f" error={item['error_category']}"
        print(f"  {item['cve_id']}: {item['state']}{tail}")
    dataset = summary.get("dataset", {})
    if dataset.get("entries"):
        print(f"  dataset: {dataset['path']} ({len(dataset['entries'])} tasks)")
        audit = dataset.get("split_audit", {})
        print(f"  split audit: {'ok' if audit.get('ok') else 'conflict'}")
    baseline = summary.get("difficulty_baseline", {})
    if baseline:
        print(
            f"  oracle reference success {baseline['oracle_success_rate']:.2f}, "
            f"median {baseline['oracle_median_seconds']:.1f}s"
        )
        model = baseline.get("model_baseline")
        if model:
            print(
                f"  model baseline: {model.get('agent')}/{model.get('model_name')} "
                f"success {model.get('successes')}/{model.get('attempts')} "
                f"({model.get('success_rate')}), "
                f"median {model.get('median_duration_sec')}s"
            )
        else:
            print(f"  model baseline: {baseline.get('model_baseline_note')}")
    print(f"  report: {summary['report_path']}")


if __name__ == "__main__":
    raise SystemExit(main())
