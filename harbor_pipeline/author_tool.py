"""The ``harbor-author`` helper used by the native authoring agent.

This is the only external command the agent can run. It exposes a bounded set
of operations (validate, build, probe, exec, registry, submit, decline) and
keeps the fixed acceptance gates outside the agent's workspace. Every long
operation writes a full log under ``.harbor/`` and returns a compact JSON
summary on stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import author_probe
from . import discovery as discovery_mod
from . import registry as registry_mod
from . import synthesis as synthesis_mod
from .authoring import (
    BUILD_STATE_FILE,
    BUNDLE_FILE,
    COUNTERS_FILE,
    DECLINED_FILE,
    JOB_STATE_FILE,
    PROBE_STATE_FILE,
    SUBMISSION_FILE,
    assemble_bundle,
    validate_workspace,
)
from .backend import build_image, run_in_image
from .config import Config, load_config
from .contracts import load_policy
from .discovery import Discovery
from .errors import TaskError
from .generator import render_task
from .spec import check_evidence_links, check_spec_consistency, freeze
from .util import (
    PipelineError,
    digest,
    file_lock,
    image_base as image_tag_base,
    read_json,
    tree_hashes,
    utc_now_text,
    write_json,
)

DEFAULT_LIMITS = {"builds": 8, "probes": 20, "execs": 20, "registry": 12}


@dataclass
class ToolContext:
    workspace: Path
    run_dir: Path
    cve_id: str
    revision: int
    config: Config
    evidence: dict
    discovery: Discovery
    policy: Any


def _workspace() -> Path:
    value = os.environ.get("HARBOR_AUTHOR_WORKSPACE") or os.getcwd()
    workspace = Path(value).resolve()
    if not (workspace / BUNDLE_FILE).is_file():
        raise PipelineError(
            f"{workspace} is not an authoring workspace: {BUNDLE_FILE} is missing"
        )
    return workspace


def _load_context() -> ToolContext:
    workspace = _workspace()
    run_dir = workspace.parent
    cve_id = run_dir.name
    if not cve_id.startswith("CVE-"):
        raise PipelineError(f"Run directory {run_dir} does not name a CVE")
    config_path = os.environ.get("HARBOR_AUTHOR_CONFIG")
    if config_path and Path(config_path).is_file():
        try:
            config = load_config(Path(config_path))
        except PipelineError:
            # A config that references a secret the helper is not allowed to
            # see must not block authoring; the defaults keep the same source
            # allowlist and budgets.
            config = Config()
    else:
        config = Config()
    try:
        revision = int(os.environ.get("HARBOR_AUTHOR_REVISION") or 1)
    except ValueError:
        revision = 1
    try:
        state = read_json(run_dir / "state.json")
        revision = int(state.get("revision") or revision)
    except (OSError, ValueError):
        pass
    evidence = read_json(run_dir / "evidence-index.json")
    discovery = discovery_mod.load(run_dir, cve_id)
    return ToolContext(
        workspace=workspace,
        run_dir=run_dir,
        cve_id=cve_id,
        revision=revision,
        config=config,
        evidence=evidence,
        discovery=discovery,
        policy=load_policy(),
    )


def _limit(ctx: ToolContext, kind: str) -> int:
    pipeline = ctx.config.pipeline
    return {
        "builds": pipeline.author_build_runs,
        "probes": pipeline.author_probe_runs,
        "execs": pipeline.author_exec_runs,
        "registry": DEFAULT_LIMITS["registry"],
    }.get(kind, DEFAULT_LIMITS.get(kind, 1))


def _charge(ctx: ToolContext, kind: str) -> None:
    path = ctx.workspace / COUNTERS_FILE
    limit = _limit(ctx, kind)
    with file_lock(path):
        data = read_json(path) if path.is_file() else {}
        used = int(data.get(kind, 0))
        if used >= limit:
            raise PipelineError(
                f"{kind} budget exhausted ({used}/{limit}); stop and submit or decline"
            )
        data[kind] = used + 1
        data["updated_at"] = utc_now_text()
        write_json(path, data)


def _counters(ctx: ToolContext) -> dict:
    path = ctx.workspace / COUNTERS_FILE
    return read_json(path) if path.is_file() else {}


def _job_start(ctx: ToolContext, kind: str, **extra: Any) -> None:
    write_json(
        ctx.workspace / JOB_STATE_FILE,
        {
            "kind": kind,
            "status": "running",
            "pid": os.getpid(),
            "started_at": utc_now_text(),
            **extra,
        },
    )


def _job_finish(ctx: ToolContext, state: str, **extra: Any) -> None:
    path = ctx.workspace / JOB_STATE_FILE
    data = read_json(path) if path.is_file() else {}
    data.update({"status": state, "finished_at": utc_now_text(), **extra})
    write_json(path, data)


def _job_status(ctx: ToolContext) -> dict:
    path = ctx.workspace / JOB_STATE_FILE
    return read_json(path) if path.is_file() else {}


# ---------------------------------------------------------------------------
# Bundle/spec assembly
# ---------------------------------------------------------------------------


def _synthesis(ctx: ToolContext, bundle: dict) -> synthesis_mod.Synthesis:
    return synthesis_mod.Synthesis(
        cve_id=ctx.cve_id,
        bundle=bundle,
        model_identity="claude-code",
        usage={},
        prompt_sha256="",
        generated_at=utc_now_text(),
        digest=digest(bundle),
    )


def _spec_for(ctx: ToolContext, bundle: dict) -> dict:
    synthesis = _synthesis(ctx, bundle)
    identity = discovery_mod.artifact_identity(
        ctx.evidence,
        ctx.run_dir,
        product=synthesis.product["name"],
        vulnerable_ref=synthesis.versions["vulnerable_ref"],
    )
    raw = synthesis_mod.build_spec(
        synthesis,
        evidence=ctx.evidence,
        discovery=ctx.discovery,
        artifact_identity_value=identity,
        policy_version=ctx.policy.policy_version,
    )
    # A stable timestamp keeps the frozen digest identical across the separate
    # build/probe/submit helper processes. auth_material derives credentials
    # from that digest, so using utc_now() here made the target and verifier
    # disagree on APP_PASS/AUTH_PASSWORD.
    spec = freeze(
        raw,
        ctx.policy.policy_version,
        frozen_at="2000-01-01T00:00:00+00:00",
    )
    issues = check_evidence_links(spec, ctx.evidence, run_dir=ctx.run_dir) + check_spec_consistency(spec)
    if issues:
        raise PipelineError("; ".join(issues))
    return spec


def _render_variants(
    ctx: ToolContext,
    spec: dict,
    bundle: dict,
    *,
    base_images: dict[str, dict],
) -> dict[str, Path]:
    synthesis = _synthesis(ctx, bundle)
    root = ctx.run_dir / "author-probe" / f"r{ctx.revision}"
    tasks: dict[str, Path] = {}
    for variant in ("vulnerable", "fixed"):
        task = render_task(
            spec,
            scenario_name="synthesized",
            variant=variant,
            probe="reference",
            network_mode="public",
            allowed_hosts=("target",),
            synthesis=synthesis,
            revision=ctx.revision,
            prebuilt=True,
            prebuilt_base=image_tag_base(ctx.cve_id, variant, ctx.revision),
            environment_image=base_images["environment"]["image_ref"],
            verifier_image=base_images["verifier"]["image_ref"],
            paired_verification=False,  # probe_pair explicitly replays both images
        )
        task_dir = task.write(root / variant)
        tasks[variant] = task_dir
    return tasks


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_validate(ctx: ToolContext) -> int:
    bundle, notes, issues = validate_workspace(
        workspace=ctx.workspace,
        run_dir=ctx.run_dir,
        evidence=ctx.evidence,
        discovery=ctx.discovery,
        config=ctx.config,
    )
    payload = {
        "ok": not issues,
        "issues": issues[:30],
        "notes": notes[:10],
        "bundle_digest": digest(bundle) if bundle else "",
        "target_files": sorted((bundle.get("target") or {}).get("files", {})),
    }
    _print(payload)
    return 0 if not issues else 1


def cmd_build(ctx: ToolContext, *, variant: str = "both", quiet: bool = False) -> int:
    bundle, notes, issues = validate_workspace(
        workspace=ctx.workspace,
        run_dir=ctx.run_dir,
        evidence=ctx.evidence,
        discovery=ctx.discovery,
        config=ctx.config,
    )
    if issues:
        if not quiet:
            _print({"ok": False, "stage": "validate", "issues": issues[:30]})
        return 1
    try:
        spec = _spec_for(ctx, bundle)
    except PipelineError as exc:
        if not quiet:
            _print({"ok": False, "stage": "spec", "issues": [str(exc)]})
        return 1
    _job_start(ctx, "build", variant=variant)
    try:
        base_images = author_probe.ensure_base_images(
            probe_root=ctx.run_dir / "author-probe" / "base-images",
            log_dir=ctx.workspace / ".harbor",
            timeout_sec=ctx.config.pipeline.command_timeout_sec,
        )
        tasks = _render_variants(ctx, spec, bundle, base_images=base_images)
    except Exception as exc:  # noqa: BLE001 - report the render/base failure
        _job_finish(ctx, "failed", stage="prepare", error=str(exc)[:2000])
        if not quiet:
            _print({"ok": False, "stage": "prepare", "error": str(exc)[:3000]})
        return 1
    _charge(ctx, "builds")
    results: dict[str, dict] = {}
    variants = ("vulnerable", "fixed") if variant == "both" else (variant,)
    for name in variants:
        task_dir = tasks[name]
        context = task_dir / "environment" / "target"
        image_ref = image_tag_base(ctx.cve_id, name, ctx.revision) + "-target"
        log_path = ctx.workspace / ".harbor" / f"build-{name}.log"
        try:
            build = build_image(
                name=f"target-{name}",
                context=context,
                image_ref=image_ref,
                log_path=log_path,
                timeout_sec=ctx.config.pipeline.command_timeout_sec,
            )
        except TaskError as exc:
            _job_finish(
                ctx, "failed", stage="build", variant=name,
                error=str(exc)[-3000:], log=str(log_path),
            )
            if not quiet:
                _print(
                    {
                        "ok": False,
                        "stage": "build",
                        "variant": name,
                        "error": str(exc)[-3000:],
                        "log": str(log_path),
                    }
                )
            return 1
        results[name] = {
            "image_ref": build.image_ref,
            "image_digest": build.image_digest,
            "source_digest": digest(tree_hashes(context)),
            "task_dir": str(task_dir),
            "cached": build.cached,
            "log": str(log_path),
        }
    state_path = ctx.workspace / BUILD_STATE_FILE
    previous = read_json(state_path) if state_path.is_file() else {}
    merged = dict(previous.get("variants") or {})
    merged.update(results)
    write_json(
        state_path,
        {
            "revision": ctx.revision,
            "bundle_digest": digest(bundle),
            "spec_digest": spec["frozen_digest"],
            "variants": merged,
            "base": base_images,
            "updated_at": utc_now_text(),
        },
    )
    _job_finish(
        ctx,
        "succeeded",
        stage="built",
        variants={name: item["image_ref"] for name, item in results.items()},
    )
    if not quiet:
        _print(
            {
                "ok": True,
                "stage": "built",
                "variants": {
                    name: {
                        "image": item["image_ref"],
                        "cached": item.get("cached"),
                        "log": item["log"],
                    }
                    for name, item in results.items()
                },
            }
        )
    return 0


def _load_build_state(ctx: ToolContext, bundle: dict) -> dict:
    path = ctx.workspace / BUILD_STATE_FILE
    state = read_json(path) if path.is_file() else {}
    if state.get("bundle_digest") != digest(bundle):
        return {}
    variants = state.get("variants") or {}
    if not all(variants.get(name, {}).get("image_ref") for name in ("vulnerable", "fixed")):
        return {}
    return state


def _ensure_built(ctx: ToolContext, bundle: dict) -> dict:
    state = _load_build_state(ctx, bundle)
    if state:
        return state
    code = cmd_build(ctx, quiet=True)
    if code != 0:
        raise PipelineError("build failed before probe")
    state = _load_build_state(ctx, bundle)
    if not state:
        raise PipelineError("build state is missing after a successful build")
    return state


def cmd_probe(ctx: ToolContext, *, alternate: bool = False, quiet: bool = False) -> int:
    bundle, notes, issues = validate_workspace(
        workspace=ctx.workspace,
        run_dir=ctx.run_dir,
        evidence=ctx.evidence,
        discovery=ctx.discovery,
        config=ctx.config,
    )
    if issues:
        if not quiet:
            _print({"ok": False, "stage": "validate", "issues": issues[:30]})
        return 1
    try:
        spec = _spec_for(ctx, bundle)
    except PipelineError as exc:
        if not quiet:
            _print({"ok": False, "stage": "spec", "issues": [str(exc)]})
        return 1
    _job_start(ctx, "probe", alternate=alternate)
    try:
        state = _ensure_built(ctx, bundle)
    except PipelineError as exc:
        _job_finish(ctx, "failed", stage="build", error=str(exc)[:2000])
        if not quiet:
            _print({"ok": False, "stage": "build", "error": str(exc)})
        return 1
    variants = state["variants"]
    submitted_name = "alternate.py" if alternate else "reference.py"
    submitted = ctx.workspace / "poc" / submitted_name
    if not submitted.is_file():
        _job_finish(ctx, "failed", stage="probe", error=f"missing poc/{submitted_name}")
        if not quiet:
            _print({"ok": False, "stage": "probe", "error": f"missing poc/{submitted_name}"})
        return 1
    _charge(ctx, "probes")
    # The same submitted file is used for both variants; the reference stays
    # the trusted reference in tests/reference_poc.py.
    work_root = ctx.run_dir / "author-probe" / f"probe-r{ctx.revision}-{int(alternate)}"
    summary = author_probe.probe_pair(
        spec=spec,
        target_images={name: variants[name].get("image_digest") or variants[name]["image_ref"] for name in variants},
        verifier_image=state["base"]["verifier"].get("image_digest") or state["base"]["verifier"]["image_ref"],
        task_dirs={name: Path(variants[name]["task_dir"]) for name in variants},
        submitted={name: submitted for name in variants},
        work_root=work_root,
        cve_id=ctx.cve_id,
        timeout_sec=max(300, min(900, ctx.config.pipeline.command_timeout_sec)),
    )
    _job_finish(
        ctx,
        "succeeded" if summary.get("ok") else "failed",
        stage="probe",
        probe_status=summary.get("status"),
        fixed_status=summary.get("fixed_status"),
    )
    write_json(
        ctx.workspace / PROBE_STATE_FILE,
        {
            "bundle_digest": digest(bundle),
            "spec_digest": spec["frozen_digest"],
            "alternate": alternate,
            **summary,
            "updated_at": utc_now_text(),
        },
    )
    if not quiet:
        _print(summary)
    return 0 if summary.get("ok") else 1


def cmd_submit(ctx: ToolContext) -> int:
    bundle, notes, issues = validate_workspace(
        workspace=ctx.workspace,
        run_dir=ctx.run_dir,
        evidence=ctx.evidence,
        discovery=ctx.discovery,
        config=ctx.config,
    )
    if issues:
        _print({"ok": False, "stage": "validate", "issues": issues[:30]})
        return 1
    try:
        spec = _spec_for(ctx, bundle)
    except PipelineError as exc:
        _print({"ok": False, "stage": "spec", "issues": [str(exc)]})
        return 1
    state_path = ctx.workspace / PROBE_STATE_FILE
    probe = read_json(state_path) if state_path.is_file() else {}
    if probe.get("bundle_digest") != digest(bundle) or probe.get("alternate"):
        code = cmd_probe(ctx, alternate=False, quiet=True)
        if code != 0:
            return 1
        probe = read_json(state_path)
    if not probe.get("ok"):
        _print({"ok": False, "stage": "probe", "probe": probe})
        return 1
    # The pipeline re-assembles the same tree to detect a submission that was
    # edited after `submit`; record the raw assembly digest for that check and
    # the normalized body digest for humans.
    raw = assemble_bundle(ctx.workspace)
    write_json(
        ctx.workspace / SUBMISSION_FILE,
        {
            "status": "submitted",
            "cve_id": ctx.cve_id,
            "revision": ctx.revision,
            "bundle_digest": digest(raw),
            "normalized_digest": digest(bundle),
            "spec_digest": spec["frozen_digest"],
            "probe": probe,
            "submitted_at": utc_now_text(),
        },
    )
    _print(
        {
            "ok": True,
            "status": "submitted",
            "bundle_digest": digest(raw),
            "normalized_digest": digest(bundle),
            "probe": {
                "status": probe.get("status"),
                "fixed_status": probe.get("fixed_status"),
                "noauth_observed": probe.get("noauth_observed"),
            },
        }
    )
    return 0


def cmd_decline(ctx: ToolContext, reason: str) -> int:
    reason = reason.strip()
    if not reason:
        _print({"ok": False, "error": "a decline reason is required"})
        return 2
    write_json(
        ctx.workspace / DECLINED_FILE,
        {
            "status": "declined",
            "cve_id": ctx.cve_id,
            "reason": reason[:1000],
            "declined_at": utc_now_text(),
        },
    )
    _print({"ok": True, "status": "declined", "reason": reason[:1000]})
    return 0


def cmd_exec(ctx: ToolContext, command: str, timeout: int, variant: str = "vulnerable") -> int:
    _charge(ctx, "execs")
    state_path = ctx.workspace / BUILD_STATE_FILE
    state = read_json(state_path) if state_path.is_file() else {}
    built = (state.get("variants") or {}).get(variant) or {}
    image = built.get("image_digest") or built.get("image_ref")
    if not image:
        _print({"ok": False, "error": f"build the {variant} target first"})
        return 1
    result = run_in_image(
        image,
        command,
        timeout=max(5, min(int(timeout), 180)),
        log_path=ctx.workspace / ".harbor" / "exec.log",
    )
    _print({"ok": result.get("exit") == 0, **result})
    return 0 if result.get("exit") == 0 else 1


def cmd_registry(ctx: ToolContext, ecosystem: str, name: str) -> int:
    _charge(ctx, "registry")
    result = registry_mod.lookup(ecosystem, name, ctx.config.sources)
    _print({"ok": "error" not in result, **result})
    return 0 if "error" not in result else 1


def cmd_status(ctx: ToolContext) -> int:
    build = read_json(ctx.workspace / BUILD_STATE_FILE) if (ctx.workspace / BUILD_STATE_FILE).is_file() else {}
    probe = read_json(ctx.workspace / PROBE_STATE_FILE) if (ctx.workspace / PROBE_STATE_FILE).is_file() else {}
    logs = sorted(
        ((ctx.workspace / ".harbor").glob("*.log")),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:5]
    _print(
        {
            "workspace": str(ctx.workspace),
            "counters": _counters(ctx),
            "job": _job_status(ctx),
            "build": {
                "bundle_digest": build.get("bundle_digest"),
                "variants": sorted((build.get("variants") or {})),
            },
            "probe": {
                "bundle_digest": probe.get("bundle_digest"),
                "ok": probe.get("ok"),
                "status": probe.get("status"),
                "fixed_status": probe.get("fixed_status"),
            },
            "logs": [
                {
                    "path": str(path),
                    "tail": path.read_text(encoding="utf-8", errors="replace")[-2000:],
                }
                for path in logs
            ],
        }
    )
    return 0


def _print(payload: dict) -> None:
    # ASCII-escaped output is safe on a cp936 console and still readable by the
    # agent; the full logs on disk are UTF-8.
    print(json.dumps(payload, indent=2, ensure_ascii=True, default=str))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harbor-author")
    sub = parser.add_subparsers(dest="subcommand", required=True)
    sub.add_parser("validate", help="assemble and run deterministic checks")
    build_cmd = sub.add_parser("build", help="build both target images")
    build_cmd.add_argument("--variant", choices=("both", "vulnerable", "fixed"), default="both")
    probe_cmd = sub.add_parser("probe", help="run the real verifier pair")
    probe_cmd.add_argument("--alternate", action="store_true")
    exec_cmd = sub.add_parser("exec", help="run a command in the vulnerable image")
    exec_cmd.add_argument("--timeout", type=int, default=60)
    exec_cmd.add_argument("--variant", choices=("vulnerable", "fixed"), default="vulnerable")
    exec_cmd.add_argument("command", nargs=argparse.REMAINDER)
    registry_cmd = sub.add_parser("registry", help="published versions")
    registry_cmd.add_argument("ecosystem")
    registry_cmd.add_argument("name")
    sub.add_parser("submit", help="record a verified submission")
    decline_cmd = sub.add_parser("decline", help="decline this CVE")
    decline_cmd.add_argument("--reason", required=True)
    sub.add_parser("status", help="show counters and recent logs")
    shell_cmd = sub.add_parser("shell", help="general shell in a persistent author sandbox, available before build")
    shell_cmd.add_argument("--timeout", type=int, default=120)
    shell_cmd.add_argument("--runtime", choices=("configured", "python", "node", "go", "java"), default="configured")
    shell_cmd.add_argument("command", nargs=argparse.REMAINDER)
    debug_cmd = sub.add_parser("debug", help="start, inspect, execute in, or stop a live target")
    debug_cmd.add_argument("action", choices=("start", "exec", "logs", "stop"))
    debug_cmd.add_argument("--variant", choices=("vulnerable", "fixed"), default="vulnerable")
    debug_cmd.add_argument("--timeout", type=int, default=120)
    debug_cmd.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("cleanup", help="remove this author's sandbox and debug containers")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = _load_context()
        if args.subcommand in {"shell", "debug", "cleanup"}:
            from . import author_debug
            if args.subcommand == "cleanup":
                author_debug.cleanup(ctx.workspace)
                _print({"ok": True})
                return 0
            _charge(ctx, "execs")
            command = list(args.command)
            if command and command[0] == "--":
                command = command[1:]
            if args.subcommand == "shell":
                if not command:
                    raise PipelineError("shell needs a command after --")
                runtime_image = {
                    "configured": ctx.config.pipeline.author_sandbox_image,
                    "python": "python:3.12-slim-bookworm", "node": "node:24-bookworm-slim",
                    "go": "golang:1.25-bookworm", "java": "maven:3.9-eclipse-temurin-17",
                }[args.runtime]
                author_debug.start(ctx.workspace, kind="scratch", image=runtime_image,
                                   network=ctx.config.pipeline.author_sandbox_network)
                result = author_debug.execute(ctx.workspace, "scratch", shlex.join(command), timeout=args.timeout)
            elif args.action == "start":
                state = read_json(ctx.workspace / BUILD_STATE_FILE)
                built = (state.get("variants") or {}).get(args.variant) or {}
                image = built.get("image_digest") or built.get("image_ref")
                if not image:
                    raise PipelineError(f"Build {args.variant} before starting its debug service")
                result = author_debug.start(ctx.workspace, kind=args.variant, image=image)
            elif args.action == "exec":
                if not command:
                    raise PipelineError("debug exec needs a command after --")
                result = author_debug.execute(ctx.workspace, args.variant, shlex.join(command), timeout=args.timeout)
            elif args.action == "logs":
                result = author_debug.logs(ctx.workspace, args.variant)
            else:
                result = author_debug.stop(ctx.workspace, args.variant)
            _print(result)
            return 0 if result.get("ok") else 1
        if args.subcommand == "validate":
            return cmd_validate(ctx)
        if args.subcommand == "build":
            return cmd_build(ctx, variant=args.variant)
        if args.subcommand == "probe":
            return cmd_probe(ctx, alternate=args.alternate)
        if args.subcommand == "exec":
            command = list(args.command)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                _print({"ok": False, "error": "exec needs a command after --"})
                return 2
            # The shell already split the agent's command into argv. Re-quote
            # each argument so `node -e "..."` reaches the container as one
            # shell string instead of losing its quotes.
            return cmd_exec(ctx, shlex.join(command), args.timeout, args.variant)
        if args.subcommand == "registry":
            return cmd_registry(ctx, args.ecosystem, args.name)
        if args.subcommand == "submit":
            return cmd_submit(ctx)
        if args.subcommand == "decline":
            return cmd_decline(ctx, args.reason)
        if args.subcommand == "status":
            return cmd_status(ctx)
        _print({"ok": False, "error": f"unknown command {args.subcommand!r}"})
        return 2
    except PipelineError as exc:
        _print({"ok": False, "error": str(exc)})
        return 1
    except Exception as exc:  # noqa: BLE001 - the agent must see the failure
        _print({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
