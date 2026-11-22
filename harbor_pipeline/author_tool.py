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
import time
import uuid
from contextlib import contextmanager
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
    EVIDENCE_REVIEW_FILE,
    JOB_STATE_FILE,
    PROBE_STATE_FILE,
    SUBMISSION_FILE,
    assemble_bundle,
    evidence_review_pending,
    evidence_review_request,
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
    from .resources import configure
    configure(config.pipeline, inherit=True)
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
    path = ctx.workspace / JOB_STATE_FILE
    previous = read_json(path) if path.is_file() else {}
    write_json(
        path,
        {
            **({"helper": previous["helper"]} if previous.get("helper") else {}),
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


@contextmanager
def _helper_operation(ctx, command):
    """One workspace mutation at a time, including nested build/probe calls."""
    from .processes import identity
    from .resources import _PROGRESS

    lock = file_lock(ctx.workspace / ".harbor/helper", timeout_sec=0)
    try:
        lock.__enter__()
    except PipelineError as exc:
        raise PipelineError("Another harbor-author command is still running. End this session so the pipeline can wait and resume it with the result.") from exc
    path = ctx.workspace / JOB_STATE_FILE
    helper = {"pid": os.getpid(), "created": identity(os.getpid()), "command": command,
              "operation_id": uuid.uuid4().hex,
              "session_token": os.environ.get("HARBOR_AUTHOR_SESSION_RUN", ""),
              "status": "running", "started_at": utc_now_text(), "waited_sec": 0.0}
    wait_started = None

    def update(status, **extra):
        nonlocal wait_started
        now = time.monotonic()
        if status == "waiting" and wait_started is None:
            wait_started = now
        elif status != "waiting" and wait_started is not None:
            helper["waited_sec"] += now - wait_started
            wait_started = None
        helper.update(status=status, heartbeat_at=utc_now_text(), **extra)
        data = read_json(path) if path.is_file() else {}
        if (data.get("helper") or {}).get("operation_id") != helper["operation_id"]:
            data = {"kind": command, "status": "running", "pid": helper["pid"]}
        if status in {"succeeded", "failed"}:
            helper["error_category"] = extra.get("error_category") or data.get("error_category") or helper.get("error_category")
            helper["error"] = extra.get("error") or data.get("error") or helper.get("error")
        write_json(path, {**data, "helper": dict(helper)})

    callback = _PROGRESS.set(update)
    code = [1]
    try:
        update("running")
        yield lambda result: code.__setitem__(0, result)
    except TaskError as exc:
        update("failed", error_category=exc.category.code, error=str(exc))
        raise
    except PipelineError as exc:
        update("failed", error_category="budget_exhausted" if "budget exhausted" in str(exc).lower() else None, error=str(exc))
        raise
    finally:
        try:
            update("succeeded" if code[0] == 0 else "failed", exit_code=code[0], finished_at=utc_now_text())
        finally:
            _PROGRESS.reset(callback)
            lock.__exit__(None, None, None)


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
            timeout_sec=getattr(ctx.config.pipeline, "author_build_timeout_sec", ctx.config.pipeline.command_timeout_sec),
        )
        tasks = _render_variants(ctx, spec, bundle, base_images=base_images)
    except Exception as exc:  # noqa: BLE001 - report the render/base failure
        _job_finish(ctx, "failed", stage="prepare", error=str(exc)[:2000])
        if not quiet:
            _print({"ok": False, "stage": "prepare", "error": str(exc)[:3000]})
        return 1
    charged = False

    def charge_build():
        nonlocal charged
        if not charged:
            _charge(ctx, "builds")
            charged = True
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
                timeout_sec=getattr(ctx.config.pipeline, "author_build_timeout_sec", ctx.config.pipeline.command_timeout_sec),
                reuse=True, on_build=charge_build,
            )
        except TaskError as exc:
            _job_finish(
                ctx, "failed", stage="build", variant=name,
                error=str(exc)[-3000:], error_category=exc.category.code, log=str(log_path),
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
            "reused": build.reused,
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
                        "reused": item.get("reused", False),
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
    from .backend import docker_binary
    from .build_cache import image_identity
    docker = docker_binary()
    for image in [*variants.values(), *(state.get("base") or {}).values()]:
        identity = image.get("image_digest")
        if not identity or image_identity(docker, identity) != identity:
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


def cmd_probe(ctx: ToolContext, *, quiet: bool = False) -> int:
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
    _job_start(ctx, "probe")
    try:
        state = _ensure_built(ctx, bundle)
    except PipelineError as exc:
        _job_finish(ctx, "failed", stage="build", error=str(exc)[:2000])
        if not quiet:
            _print({"ok": False, "stage": "build", "error": str(exc)})
        return 1
    variants = state["variants"]
    submitted_name = "reference.py"
    submitted = ctx.workspace / "poc" / submitted_name
    if not submitted.is_file():
        _job_finish(ctx, "failed", stage="probe", error=f"missing poc/{submitted_name}")
        if not quiet:
            _print({"ok": False, "stage": "probe", "error": f"missing poc/{submitted_name}"})
        return 1
    _charge(ctx, "probes")
    # The same submitted file is used for both variants; the reference stays
    # the trusted reference in tests/reference_poc.py.
    work_root = ctx.run_dir / "author-probe" / f"probe-r{ctx.revision}-0"
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
            **summary,
            "updated_at": utc_now_text(),
        },
    )
    if not quiet:
        _print(summary)
    return 0 if summary.get("ok") else 1


def cmd_submit(ctx: ToolContext) -> int:
    if evidence_review_pending(ctx.workspace):
        raise PipelineError("evidence review is pending; end this session so the pipeline can invoke the resolver")
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
        code = cmd_probe(ctx, quiet=True)
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
    # A successful submission supersedes an earlier exploratory decline.
    # Do not clear that decision before validation and the probe succeed.
    (ctx.workspace / DECLINED_FILE).unlink(missing_ok=True)
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
    (ctx.workspace / SUBMISSION_FILE).unlink(missing_ok=True)
    if evidence_review_pending(ctx.workspace):
        pending = read_json(ctx.workspace / EVIDENCE_REVIEW_FILE)
        write_json(ctx.workspace / EVIDENCE_REVIEW_FILE, {**pending, "status": "cancelled"})
    _print({"ok": True, "status": "declined", "reason": reason[:1000]})
    return 0


def cmd_request_evidence_review(ctx: ToolContext, file: str) -> int:
    if not ctx.config.pipeline.evidence_resolver or ctx.config.pipeline.max_evidence_reviews == 0:
        raise PipelineError("author evidence review is disabled by pipeline configuration")
    if evidence_review_pending(ctx.workspace):
        _print({"ok": True, "status": "evidence_review_requested", "next": "End this author session; a request is already pending."})
        return 0
    path = (ctx.workspace / file).resolve()
    if not path.is_relative_to(ctx.workspace.resolve()) or not path.is_file() or path.stat().st_size > 64000:
        raise PipelineError("request file must be a JSON file inside the author workspace, at most 64 KB")
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise PipelineError("evidence review request must be a JSON object")
    request = evidence_review_request(ctx.workspace, ctx.discovery, {**payload, "request_nonce": uuid.uuid4().hex})
    write_json(ctx.workspace / EVIDENCE_REVIEW_FILE, {**request, "status": "requested", "requested_at": utc_now_text()})
    for marker in (SUBMISSION_FILE, DECLINED_FILE):
        (ctx.workspace / marker).unlink(missing_ok=True)
    _print({"ok": True, "status": "evidence_review_requested", "request_id": request["request_id"],
            "next": "End this author session now. The pipeline will review the evidence and resume you with its result."})
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
            "evidence_review": read_json(ctx.workspace / EVIDENCE_REVIEW_FILE) if (ctx.workspace / EVIDENCE_REVIEW_FILE).is_file() else None,
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
    sub.add_parser("probe", help="run the real verifier pair")
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
    review_cmd = sub.add_parser("request-evidence-review", help="ask the evidence resolver to review an incorrect version/fix pair")
    review_cmd.add_argument("--file", required=True)
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


def _dispatch(ctx, args):
    from .resources import policy as resource_policy
    if args.subcommand in {"build", "probe"} and resource_policy().get("slots"):
        # Debug targets are disposable; retaining both while starting a
        # full probe doubles the candidate's target memory footprint.
        from . import author_debug
        for kind in ("vulnerable", "fixed"):
            author_debug.stop(ctx.workspace, kind)
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
        return cmd_probe(ctx)
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
    if args.subcommand == "request-evidence-review":
        return cmd_request_evidence_review(ctx, args.file)
    if args.subcommand == "status":
        return cmd_status(ctx)
    _print({"ok": False, "error": f"unknown command {args.subcommand!r}"})
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = _load_context()
        if args.subcommand == "status":
            return cmd_status(ctx)
        with _helper_operation(ctx, args.subcommand) as complete:
            result = _dispatch(ctx, args)
            complete(result)
            return result
    except PipelineError as exc:
        _print({"ok": False, "error": str(exc)})
        return 1
    except Exception as exc:  # noqa: BLE001 - the agent must see the failure
        _print({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
