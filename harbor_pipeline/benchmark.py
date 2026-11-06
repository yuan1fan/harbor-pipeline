"""Model difficulty baselines measured on an immutable released task.

The oracle proves a task is solvable; it does not say how hard the task is for
a model. This module runs a fixed, credentialed agent against the released
task under a recorded prompt, tool and budget configuration, then stores
success rate, latency, token/cost usage and failure types. The measurement is
intentionally separate from task qualification: a model failing is not a task
defect, and a model succeeding is not proof that the verifier is correct.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import statistics
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .harbor_adapter import HarborAdapter, TrialOutcome
from .util import PipelineError, read_json, write_json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def measure_model_baseline(
    adapter: HarborAdapter,
    task_dir: Path,
    *,
    agent: str = "claude-code",
    model_name: str | None = "deepseek-flash-cyber",
    attempts: int = 3,
    max_turns: int | None = 30,
    max_budget_usd: str | None = "2.0",
    timeout_sec: int | None = None,
    setup_timeout_sec: int = 1800,
    agent_env: dict[str, str] | None = None,
    task_digest: str | None = None,
    environment_overlay: str | None = None,
    source_task_dir: Path | None = None,
    from_job: Path | None = None,
    job_name: str = "model-baseline",
) -> dict:
    """Run ``attempts`` independent agent trials against one released task."""
    task_dir = Path(task_dir).resolve()
    if not (task_dir / "task.toml").is_file():
        raise PipelineError(f"No Harbor task at {task_dir}")
    if attempts < 1:
        raise PipelineError("Model baseline needs at least one attempt")

    kwargs: dict = {}
    if max_turns is not None:
        kwargs["max_turns"] = max_turns
    if max_budget_usd is not None:
        kwargs["max_budget_usd"] = str(max_budget_usd)
    resolved_env = _agent_environment(agent_env)
    if from_job is not None:
        job_dir = Path(from_job).resolve()
        if not (job_dir / "result.json").is_file():
            raise PipelineError(f"No completed Harbor job at {job_dir}")
        job_name = job_dir.name
        trials = adapter.parse_trials(job_dir)
        if trials and trials[0].task_path:
            task_dir = Path(trials[0].task_path).resolve()
    else:
        outcome = adapter.run(
            [task_dir],
            agent=agent,
            job_name=job_name,
            n_concurrent=1,
            n_attempts=attempts,
            agent_model=model_name,
            agent_kwargs=kwargs or None,
            agent_env=resolved_env or None,
            agent_setup_timeout_sec=max(1, int(setup_timeout_sec)),
            timeout_sec=timeout_sec,
        )
        job_dir = outcome.job_dir
        job_name = outcome.job_name
        trials = outcome.trials
    if not trials:
        raise PipelineError("Model baseline job produced no trials")

    records = [_trial_record(trial) for trial in trials]
    successes = sum(1 for record in records if record["success"])
    durations = [record["duration_sec"] for record in records]
    usage = _sum_usage(records)
    failure_types: dict[str, int] = {}
    for record in records:
        if record["failure_type"]:
            failure_types[record["failure_type"]] = failure_types.get(record["failure_type"], 0) + 1

    result = {
        "schema_version": "1.0",
        "measured_at": utc_now(),
        "job_name": job_name,
        "job_dir": str(job_dir),
        "task_dir": str(task_dir),
        "source_task_dir": str(source_task_dir.resolve()) if source_task_dir else str(task_dir),
        "environment_overlay": environment_overlay,
        "environment_overlay_digest": overlay_digest(task_dir) if environment_overlay else None,
        "task_digest": task_digest if task_digest is not None else _task_digest(task_dir),
        "prompt_sha256": _prompt_digest(task_dir),
        "agent": agent,
        "model_name": model_name,
        "model_endpoint_host": _endpoint_host(resolved_env),
        "model_identity": _model_identity(records),
        "fixed_settings": {
            "attempts": attempts,
            "n_concurrent": 1,
            "max_turns": max_turns,
            "max_budget_usd": max_budget_usd,
            "timeout_sec": timeout_sec,
            "setup_timeout_sec": setup_timeout_sec,
            "agent_env_vars": sorted(resolved_env),
        },
        "attempts": len(records),
        "successes": successes,
        "success_rate": round(successes / len(records), 4),
        "median_duration_sec": round(statistics.median(durations), 2) if durations else None,
        "usage": usage,
        "failure_types": failure_types,
        "trials": records,
    }
    return result


def prepare_benchmark_task(source_task: Path, dest: Path, docker_image: str) -> Path:
    """Copy a released task and point its agent image at a prepared runtime.

    Some hosts cannot install an agent toolchain during a trial (for example a
    package mirror that is slow or unreachable). Prebuilding the *agent
    runtime* keeps the instruction, tests, verifier and target image byte
    identical while making setup deterministic. The overlay Dockerfile only
    replaces the main service image; qualification and release never use this
    copy.
    """
    source_task = Path(source_task).resolve()
    dest = Path(dest).resolve()
    if not (source_task / "task.toml").is_file():
        raise PipelineError(f"No Harbor task at {source_task}")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source_task, dest)
    dockerfile = dest / "environment" / "Dockerfile"
    dockerfile.write_text(
        "# Benchmark-only overlay: the task environment is inherited unchanged\n"
        f"FROM {docker_image}\n",
        encoding="utf-8",
    )
    return dest


def overlay_digest(task_dir: Path) -> str:
    dockerfile = Path(task_dir) / "environment" / "Dockerfile"
    if not dockerfile.is_file():
        return ""
    return "sha256:" + hashlib.sha256(dockerfile.read_bytes()).hexdigest()


def write_model_baseline(run_root: Path, result: dict) -> Path:
    path = run_root / "model-baseline.json"
    write_json(path, result)
    return path


def _agent_environment(overrides: dict[str, str] | None) -> dict[str, str]:
    """Forward the host's provider credentials into the agent container.

    Harbor does not copy the caller's environment into the agent. Only the
    provider variables listed here are forwarded; values are never written to
    the baseline artifact, only their names.
    """
    names = (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
    )
    forwarded = {name: os.environ[name] for name in names if os.environ.get(name)}
    if overrides:
        forwarded.update(overrides)
    return forwarded


def _endpoint_host(env: dict[str, str]) -> str | None:
    base = env.get("ANTHROPIC_BASE_URL")
    if not base:
        return None
    return urlparse(base).hostname


def _trial_record(trial: TrialOutcome) -> dict:
    data: dict = {}
    result_path = trial.trial_dir / "result.json"
    if result_path.is_file():
        try:
            data = read_json(result_path)
        except (OSError, ValueError):
            data = {}
    agent_result = data.get("agent_result") or {}
    reward = trial.reward
    success = isinstance(reward, (int, float)) and float(reward) >= 1.0
    failure = None
    if trial.exception is not None:
        failure = str(
            trial.exception.get("type")
            or trial.exception.get("name")
            or "agent_exception"
        )
    elif not success:
        failure = trial.evidence_status if reward is None else "goal_failed"
    return {
        "trial_name": trial.trial_name,
        "task_name": trial.task_name,
        "trial_dir": str(trial.trial_dir),
        "reward": reward,
        "success": success,
        "evidence_status": trial.evidence_status,
        "duration_sec": round(trial.duration_sec, 2),
        "exception": trial.exception,
        "failure_type": failure,
        "usage": {
            key: agent_result.get(key)
            for key in (
                "n_input_tokens",
                "n_cache_tokens",
                "n_output_tokens",
                "cost_usd",
            )
        },
        "agent_info": data.get("agent_info"),
    }


def _sum_usage(records: list[dict]) -> dict:
    totals = {
        "n_input_tokens": 0,
        "n_cache_tokens": 0,
        "n_output_tokens": 0,
        "cost_usd": 0.0,
    }
    seen = {key: False for key in totals}
    for record in records:
        for key in totals:
            value = (record.get("usage") or {}).get(key)
            if isinstance(value, (int, float)):
                totals[key] += value
                seen[key] = True
    return {key: (round(value, 6) if key == "cost_usd" else value) if seen[key] else None
            for key, value in totals.items()}


def _model_identity(records: list[dict]) -> dict | None:
    for record in records:
        info = record.get("agent_info") or {}
        model_info = info.get("model_info")
        if model_info:
            return {
                "agent_name": info.get("name"),
                "agent_version": info.get("version"),
                "model_info": model_info,
            }
    return None


def _prompt_digest(task_dir: Path) -> str:
    instruction = task_dir / "instruction.md"
    if not instruction.is_file():
        return ""
    return "sha256:" + hashlib.sha256(instruction.read_bytes()).hexdigest()


def _task_digest(task_dir: Path) -> str:
    manifest = task_dir.parent / "build-manifest.json"
    if manifest.is_file():
        try:
            return str(read_json(manifest).get("task_digest") or "")
        except (OSError, ValueError):
            pass
    return ""
