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
from .batch import load_candidates, plan_batch, run_batch
from .benchmark import measure_model_baseline, prepare_benchmark_task, write_model_baseline
from .config import load_config
from .cves import supported_ids
from .harbor_adapter import HarborAdapter, doctor
from .pipeline import CvePipeline
from .state import new_run_id
from .contracts import load_policy
from .util import PipelineError, read_json

STAGES = ("collect", "freeze", "generate", "build", "validate", "release")

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
    parser.add_argument("--scenario", help="override the scenario template")
    parser.add_argument("--workers", type=int, default=None, help="concurrent CVE jobs")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def _add_cve(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cve", required=True, help="built-in CVE id, e.g. CVE-2024-23334")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harbor-pipeline",
        description="Evidence-driven CVE task generation and differential validation",
    )
    parser.add_argument("-c", "--config", type=Path, help="pipeline TOML (default: ./pipeline.toml)")
    parser.add_argument("--version", action="version", version=f"harbor-pipeline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor_cmd = sub.add_parser("doctor", help="check host, Harbor, Docker and policy")
    doctor_cmd.add_argument("--json", action="store_true")

    run_cmd = sub.add_parser("run", help="run one CVE end to end")
    _add_cve(run_cmd)
    _add_output_args(run_cmd)
    run_cmd.add_argument("--until", choices=STAGES, default="release")

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
    _add_output_args(batch_cmd)

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
    bench_cmd.add_argument("--model", default="sonnet", help="agent model name")
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
        if args.command == "batch":
            return _batch(config, args)
        if args.command == "report":
            return _report_command(config, args)
        if args.command == "benchmark":
            return _benchmark(config, args)
        return _single(config, args)
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------
# Single candidate
# ---------------------------------------------------------------------------


def _single(config, args) -> int:
    until = "release" if args.command == "run" else args.command
    until = getattr(args, "until", until) if args.command in {"run", "resume"} else until
    run_id = args.run_id or new_run_id("run")
    output_root = Path(args.output_dir) if args.output_dir else None
    pipeline = CvePipeline(
        config=config,
        cve_id=args.cve,
        run_id=run_id,
        profile=args.profile,
        scenario=args.scenario,
        workers=args.workers or config.pipeline.workers,
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
    run_id = args.run_id or new_run_id("batch")
    output_root = Path(args.output_dir) if args.output_dir else Path(config.pipeline.output_dir)
    candidates, rejected = load_candidates(args.input)
    plan = plan_batch(
        candidates,
        rejected=rejected,
        run_id=run_id,
        profile=args.profile,
        workers=args.workers or config.pipeline.workers,
        limit=args.limit,
        output_root=output_root,
        max_repairs=config.pipeline.max_repairs,
    )
    summary = run_batch(
        plan,
        config,
        scenario=args.scenario,
        output_root=output_root,
        workers=args.workers or config.pipeline.workers,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        _print_batch(summary)
    return 0 if summary["counts"].get("QUARANTINED", 0) == 0 else 3


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
    return 0 if report["ok"] else 1


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
                "min_quality_score": profile.min_quality_score,
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
        print(
            f"  admission={payload['admission_status']} "
            f"quality={payload['quality_score']} "
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
            tail = f" admission={item['admission_status']} quality={item.get('quality_score')}"
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
