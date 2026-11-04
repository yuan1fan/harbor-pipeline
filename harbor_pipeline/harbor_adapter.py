"""Harbor 0.23 integration: capability probes, job execution, and result parsing.

The adapter is deliberately thin. Harbor remains the source of truth for task
validation, image builds, container lifecycle, artifact transfer, and reward
reading; the pipeline only writes JobConfig files and reads the resulting trial
directories.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import TaskError
from .util import PipelineError, hidden_console_kwargs, no_window_kwargs, read_json, write_json

HARBOR_VERSION_REQUIRED = "0.23.0"

# Matches the probe Harbor itself uses before enabling nftables egress control.
_EGRESS_PROBE_IMAGE = (
    "alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
)
_EGRESS_PROBE_SCRIPT = (
    "if [ ! -f /proc/config.gz ]; then exit 0; fi; "
    "zcat /proc/config.gz 2>/dev/null | grep -qE '^CONFIG_NFT_FIB_INET=[ym]'"
)

_TRIAL_DIR_RE = re.compile(r"^[A-Za-z0-9_.-]+__[A-Za-z0-9]+$")
_SECRET_ENV_RE = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Capabilities:
    harbor_version: str
    docker_version: str | None
    linux_containers: bool
    network_allowlist: bool
    network_mode: str
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "harbor_version": self.harbor_version,
            "docker_version": self.docker_version,
            "linux_containers": self.linux_containers,
            "network_allowlist": self.network_allowlist,
            "network_mode": self.network_mode,
            "notes": list(self.notes),
        }


@dataclass
class TrialOutcome:
    trial_name: str
    task_path: str
    task_name: str
    trial_dir: Path
    reward: float | None
    exception: dict | None
    evidence: dict | None
    started_at: str | None
    finished_at: str | None
    duration_sec: float

    @property
    def evidence_status(self) -> str:
        return str((self.evidence or {}).get("status", "missing"))

    @property
    def error_category(self) -> str | None:
        return classify_trial(self)


@dataclass
class JobOutcome:
    job_name: str
    job_dir: Path
    config_path: Path
    stdout_path: Path
    returncode: int
    result: dict
    trials: list[TrialOutcome]

    def by_task_path(self) -> dict[str, TrialOutcome]:
        return {str(Path(t.task_path).resolve()).casefold(): t for t in self.trials}


def classify_trial(trial: TrialOutcome) -> str | None:
    """Map an observed trial to the pipeline error taxonomy.

    A trial that produced a reward is never an infrastructure error, even when
    the agent failed: the task was exercised. Failures before scoring are
    classified by the evidence status the trusted verifier recorded.
    """
    if trial.exception is not None:
        name = str(trial.exception.get("type") or trial.exception.get("name") or "")
        if "Build" in name or "Docker" in name or "Image" in name:
            return "build_error"
        return "infra_error"
    # A verifier can write reward 0 even when the target never came up: the
    # verifier's health check fails before scoring. The observed status is the
    # stronger signal, so classify it before the "has a reward" shortcut. T12
    # exists precisely to exercise this path.
    status = trial.evidence_status
    if status in {"target_unhealthy", "verifier_error", "missing"}:
        return "infra_error"
    if trial.reward is not None:
        return None
    if status in {"oracle_failure"}:
        return "oracle_failure"
    return None


class HarborAdapter:
    def __init__(
        self,
        *,
        binary: str = "harbor",
        jobs_dir: Path,
        run_root: Path,
        timeout_sec: int = 3600,
    ):
        self.binary = binary
        self.jobs_dir = jobs_dir
        self.run_root = run_root
        self.timeout_sec = timeout_sec

    # -- environment -------------------------------------------------------

    def locate(self) -> str:
        resolved = shutil.which(self.binary)
        if not resolved:
            raise TaskError(
                "infra_error",
                f"Harbor CLI {self.binary!r} is not on PATH; install Harbor "
                f"{HARBOR_VERSION_REQUIRED} and re-run",
            )
        return resolved

    def version(self) -> str:
        # ``harbor`` is a uv trampoline: it allocates its own console when the
        # parent has none, which is what popped a window per call.
        completed = subprocess.run(
            [self.locate(), "--version"], capture_output=True, text=True, timeout=60,
            **hidden_console_kwargs(),
        )
        if completed.returncode != 0:
            raise TaskError("infra_error", f"harbor --version failed: {completed.stderr.strip()}")
        match = re.search(r"\d+\.\d+\.\d+", completed.stdout)
        if not match:
            raise TaskError("infra_error", f"Cannot parse Harbor version: {completed.stdout!r}")
        return match.group(0)

    def docker_version(self) -> str | None:
        docker = shutil.which("docker")
        if not docker:
            return None
        completed = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=60,
            **no_window_kwargs(),
        )
        return completed.stdout.strip() or None if completed.returncode == 0 else None

    def network_allowlist_supported(self, docker: str | None = None) -> bool:
        docker = docker or shutil.which("docker")
        if not docker:
            return False
        try:
            completed = subprocess.run(
                [docker, "run", "--rm", _EGRESS_PROBE_IMAGE, "sh", "-c", _EGRESS_PROBE_SCRIPT],
                capture_output=True,
                text=True,
                timeout=90,
                **no_window_kwargs(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def capabilities(self, *, probe_allowlist: bool = True) -> Capabilities:
        version = self.version()
        docker_version = self.docker_version()
        allowlist = self.network_allowlist_supported() if probe_allowlist else False
        notes = []
        if version != HARBOR_VERSION_REQUIRED:
            notes.append(
                f"Harbor {version} differs from the pinned {HARBOR_VERSION_REQUIRED}; "
                "task and job schemas were snapshotted from the pinned release"
            )
        if docker_version is None:
            notes.append("Docker daemon is unavailable")
        if not allowlist:
            notes.append(
                "The Docker host cannot enforce network_mode='allowlist' "
                "(missing CONFIG_NFT_FIB_INET); generated tasks use 'public' "
                "and the release gate records reduced network isolation"
            )
        return Capabilities(
            harbor_version=version,
            docker_version=docker_version,
            linux_containers=docker_version is not None,
            network_allowlist=allowlist,
            network_mode="allowlist" if allowlist else "public",
            notes=notes,
        )

    # -- job execution -----------------------------------------------------

    def _job_name(self, prefix: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"

    def run(
        self,
        task_paths: list[Path],
        *,
        agent: str = "oracle",
        job_name: str = "harbor-cve",
        n_concurrent: int = 1,
        verifier_env: dict[str, str] | None = None,
        extra: dict | None = None,
        timeout_sec: int | None = None,
        n_attempts: int = 1,
        agent_model: str | None = None,
        agent_kwargs: dict | None = None,
        agent_env: dict[str, str] | None = None,
        agent_setup_timeout_sec: float | None = None,
    ) -> JobOutcome:
        if not task_paths:
            raise PipelineError("No tasks to run")
        self.locate()
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        name = self._job_name(job_name)
        config = {
            "job_name": name,
            "jobs_dir": str(self.jobs_dir.resolve()),
            "n_attempts": max(1, int(n_attempts)),
            "n_concurrent_trials": max(1, int(n_concurrent)),
            "quiet": True,
            "tasks": [{"path": str(Path(path).resolve())} for path in task_paths],
            "agents": [{
                "name": agent,
                **({"model_name": agent_model} if agent_model else {}),
                **({"kwargs": dict(agent_kwargs)} if agent_kwargs else {}),
                **({"env": _persisted_agent_env(agent_env)} if agent_env else {}),
                **(
                    {"override_setup_timeout_sec": float(agent_setup_timeout_sec)}
                    if agent_setup_timeout_sec is not None
                    else {}
                ),
            }],
        }
        if verifier_env:
            config["verifier"] = {"env": dict(verifier_env)}
        if extra:
            config.update(extra)
        config_dir = (self.run_root / "harbor-configs").resolve()
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / f"{name}.json"
        write_json(config_path, config)
        log_path = config_dir / f"{name}.log"

        command = [self.locate(), "run", "-c", str(config_path), "-y"]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=str(self.run_root),
                capture_output=True,
                text=True,
                timeout=timeout_sec or self.timeout_sec,
                **hidden_console_kwargs(),
            )
            stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            log_path.write_text(f"{stdout}\n{stderr}\nTIMEOUT\n", encoding="utf-8")
            raise TaskError(
                "infra_error",
                f"Harbor job {name} exceeded {timeout_sec or self.timeout_sec}s",
                detail={"job_name": name, "log": str(log_path)},
            ) from exc
        log_path.write_text(f"{stdout}\n{stderr}\n", encoding="utf-8")
        elapsed = time.monotonic() - started

        job_dir = self.jobs_dir / name
        result_path = job_dir / "result.json"
        if not result_path.is_file():
            category = "build_error" if _looks_like_build_failure(stdout + stderr) else "infra_error"
            raise TaskError(
                category,
                f"Harbor job {name} produced no result.json (exit {returncode})",
                detail={"job_name": name, "log": str(log_path), "elapsed_sec": round(elapsed, 1)},
            )
        result = read_json(result_path)
        # Harbor checkpoints result.json while the job is still running, so a
        # job that died mid-flight leaves a readable file with a null
        # ``finished_at`` and most trials still pending. Accepting it would
        # grade a truncated matrix as if it were complete.
        if result.get("finished_at") is None:
            stats = result.get("stats") or {}
            raise TaskError(
                "infra_error",
                f"Harbor job {name} did not finish (exit {returncode}, "
                f"{stats.get('n_completed_trials', 0)}/"
                f"{result.get('n_total_trials', '?')} trials complete)",
                detail={"job_name": name, "log": str(log_path)},
            )
        trials = self.parse_trials(job_dir)
        if not trials:
            raise TaskError(
                "infra_error",
                f"Harbor job {name} has no trial directories",
                detail={"job_dir": str(job_dir)},
            )
        return JobOutcome(
            job_name=name,
            job_dir=job_dir,
            config_path=config_path,
            stdout_path=log_path,
            returncode=returncode,
            result=result,
            trials=trials,
        )

    def parse_trials(self, job_dir: Path) -> list[TrialOutcome]:
        trials = []
        for child in sorted(job_dir.iterdir()):
            if not child.is_dir() or not _TRIAL_DIR_RE.match(child.name):
                continue
            result_path = child / "result.json"
            data = read_json(result_path) if result_path.is_file() else {}
            config = read_json(child / "config.json") if (child / "config.json").is_file() else {}
            task_path = str(
                (data.get("task_id") or {}).get("path")
                or (config.get("task") or {}).get("path")
                or ""
            )
            task_name = str(data.get("task_name") or "")
            rewards = (data.get("verifier_result") or {}).get("rewards") or {}
            reward = rewards.get("reward")
            if reward is None and (child / "verifier" / "reward.txt").is_file():
                try:
                    reward = float((child / "verifier" / "reward.txt").read_text().strip())
                except ValueError:
                    reward = None
            evidence_path = child / "verifier" / "evidence.json"
            evidence = read_json(evidence_path) if evidence_path.is_file() else None
            exception = data.get("exception_info")
            trials.append(TrialOutcome(
                trial_name=child.name,
                task_path=task_path,
                task_name=task_name,
                trial_dir=child,
                reward=float(reward) if isinstance(reward, (int, float)) else None,
                exception=exception,
                evidence=evidence,
                started_at=data.get("started_at"),
                finished_at=data.get("finished_at"),
                duration_sec=_duration(data),
            ))
        return trials


def _persisted_agent_env(env: dict[str, str]) -> dict[str, str]:
    """Serialize agent env without writing credential values to disk.

    Harbor resolves ``${VAR}`` from the process environment when it builds the
    trial. Credentials must therefore be supplied by the caller's environment;
    a literal secret that is not present there is rejected rather than written
    into the job config.
    """
    persisted: dict[str, str] = {}
    for key, value in env.items():
        if _SECRET_ENV_RE.search(key):
            if os.environ.get(key) != value:
                raise PipelineError(
                    f"Secret {key} is not available in the process environment; "
                    "refusing to write it to the Harbor job config"
                )
            persisted[key] = f"${{{key}}}"
        else:
            persisted[key] = value
    return persisted


def _duration(data: dict) -> float:
    start, end = data.get("started_at"), data.get("finished_at")
    if not start or not end:
        return 0.0
    try:
        begin = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        finish = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    return max(0.0, (finish - begin).total_seconds())


def _looks_like_build_failure(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "failed to build",
            "failed to solve",
            "build failed",
            "dockerfile",
            "error response from daemon: pull access denied",
        )
    )


def doctor(adapter: HarborAdapter, *, require_network_allowlist: bool = False) -> dict:
    """Environment diagnostics used by both the CLI and the handoff report."""
    report: dict = {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": sys.platform,
        "checks": [],
    }
    ok = True

    def check(name: str, passed: bool, detail: str) -> None:
        nonlocal ok
        ok = ok and passed
        report["checks"].append({"name": name, "ok": passed, "detail": detail})

    try:
        version = adapter.version()
        check("harbor", version == HARBOR_VERSION_REQUIRED, f"harbor {version}")
    except TaskError as exc:
        check("harbor", False, str(exc))
    docker_version = adapter.docker_version()
    check("docker", docker_version is not None, f"docker {docker_version}" if docker_version else "daemon unavailable")
    if docker_version:
        allowlist = adapter.network_allowlist_supported()
        check(
            "network_allowlist",
            allowlist or not require_network_allowlist,
            "nftables egress control available"
            if allowlist
            else (
                "unsupported by this Docker host; tasks fall back to public networking"
                + ("" if require_network_allowlist else " (optional by policy)")
            ),
        )
    try:
        write_json(adapter.run_root / ".doctor", {"at": utc_now(), "report": report})
    except OSError:
        pass
    report["ok"] = ok
    return report
