from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .util import PipelineError


@dataclass
class Settings:
    output_dir: str = "runs"
    # CLI only: reuse a complete saved Claude endpoint/auth pair when no
    # connection overrides are set in the shell. Values stay in process env.
    inherit_claude_settings: bool = False
    workers: int = 1
    # Trials inside one candidate's differential matrix. In a batch this is
    # multiplied by the candidate concurrency, so keep it small: each trial
    # starts its own compose project (target plus attacker container).
    trial_workers: int = 2
    # Remove a candidate's build images once it reaches a terminal state.
    # Enable for campaign runs; keep it off when iterating on a single task.
    prune_images: bool = False
    # BuildKit cache is the other long-run disk consumer. After each finished
    # candidate, keep at most this many GB of build cache.
    build_cache_keep_gb: int = 20
    # Host-wide heavy operations, independent of candidate/LLM concurrency.
    # Zero disables admission for compatibility with small standalone runs.
    docker_slots: int = 0
    resource_dir: str = "work/resources"
    min_free_memory_mb: int = 4096
    min_free_disk_gb: int = 15
    resource_wait_sec: int = 7200
    wsl_reclaim_memory: bool = True
    resource_disk_paths: list[str] = field(default_factory=list)
    archive_images: bool = False
    max_repairs: int = 2
    # Infrastructure retries are independent of author repair attempts.
    max_infra_retries: int = 2
    stage_retry_attempts: int = 2
    # Optional T09: three no-cache rebuilds per variant, beyond normal trials.
    cold_rebuild: bool = False
    trials: int = 5
    min_trials: int = 5
    max_calls: int = 12
    max_total_tokens: int = 180000
    max_context_bytes: int = 600000
    command_timeout_sec: int = 300
    python_image: str = "python:3.12.10-slim-bookworm"
    require_harbor_lint: bool = True
    # ``agent`` authors with a native Claude Code session; ``legacy`` keeps
    # the old one-shot draft plus JSON repair loop available for one release.
    authoring: str = "agent"
    # Run a small native evidence-resolver session only when discovery cannot
    # derive a concrete pair or the author challenges it. It cannot build or author.
    evidence_resolver: bool = False
    max_evidence_reviews: int = 2
    author_max_resumes: int = 2
    author_build_runs: int = 8
    author_probe_runs: int = 20
    author_exec_runs: int = 20
    author_sandbox_image: str = "python:3.12-slim-bookworm"
    author_sandbox_network: str = "none"
    # Solver feedback: run a real claude-code solver against the task, then
    # review it with the intended solution. A revise verdict resumes the author.
    solver_review: bool = True
    solver_attempts: int = 1
    solver_max_turns: int = 40
    solver_max_budget_usd: float = 3.0
    # The Harbor task's [agent] timeout, and the enclosing job timeout.
    solver_agent_timeout_sec: int = 1800
    solver_timeout_sec: int = 2700
    solver_min_score: int = 3


@dataclass
class ModelSettings:
    provider: str = "claude-cli"
    model: str = "deepseek-flash-cyber"
    timeout_sec: int = 300
    max_output_tokens: int = 18000
    max_budget_usd: float = 3.0
    api_base: str = "https://api.anthropic.com"
    api_version: str = "2023-06-01"
    # Native agent sessions only. Completion providers ignore these.
    max_turns: int = 80
    autocompact: str = "400k"


@dataclass
class SourceSettings:
    allowed_hosts: list[str] = field(default_factory=lambda: ["raw.githubusercontent.com", "github.com", "www.cve.org", "nvd.nist.gov", "cveawg.mitre.org", "pypi.org", "api.osv.dev", "api.github.com", "services.nvd.nist.gov", "registry.npmjs.org", "proxy.golang.org", "sum.golang.org", "repo1.maven.org", "api.wordpress.org", "downloads.wordpress.org"])
    max_bytes: int = 1500000
    timeout_sec: int = 30
    # Serve per-CVE NVD records from a cached yearly feed instead of the
    # rate-limited API. Point it at the harvest cache to reuse one download.
    nvd_feed_cache: str | None = None
    nvd_feed_max_age_sec: int = 7 * 24 * 3600
    # Optional credentials are read from the environment by load_config, never
    # from the TOML file, so a token cannot be committed by accident.
    github_token: str | None = None
    nvd_api_key: str | None = None


@dataclass
class Config:
    pipeline: Settings = field(default_factory=Settings)
    models: dict[str, ModelSettings] = field(default_factory=lambda: {"default": ModelSettings()})
    sources: SourceSettings = field(default_factory=SourceSettings)
    # The file this configuration came from, so a helper process can reload
    # the same source limits and authoring budgets.
    source_path: Path | None = None

    def model_for(self, role: str) -> ModelSettings:
        return self.models.get(role, self.models["default"])


def _expand(value):
    if isinstance(value, str):
        def replace(match):
            name = match.group(1)
            if not os.environ.get(name):
                raise PipelineError(f"Set environment variable {name} referenced in configuration")
            return os.environ[name]
        return re.sub(r"\$\{([A-Z_][A-Z_0-9]*)\}", replace, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_config(path: Path | None = None) -> Config:
    raw = _expand(tomllib.loads(path.read_text(encoding="utf-8-sig"))) if path else {}
    try:
        defaults = raw.get("models", {}).get("default", {})
        config = Config(
            pipeline=Settings(**raw.get("pipeline", {})),
            models={name: ModelSettings(**(defaults | data)) for name, data in raw.get("models", {"default": {}}).items()},
            sources=SourceSettings(**raw.get("sources", {})),
            source_path=Path(path).resolve() if path else None,
        )
        config.models.setdefault("default", ModelSettings(**defaults))
    except TypeError as exc:
        raise PipelineError(f"Invalid configuration: {exc}") from exc
    # Credentials stay out of the TOML and out of run artifacts. At scale,
    # authenticated API limits are required for GitHub advisories and NVD.
    config.sources.github_token = os.environ.get("GITHUB_TOKEN") or config.sources.github_token
    config.sources.nvd_api_key = os.environ.get("NVD_API_KEY") or config.sources.nvd_api_key
    settings = config.pipeline
    for name in ("docker_slots", "min_free_memory_mb", "min_free_disk_gb"):
        if type(getattr(settings, name)) is not int or getattr(settings, name) < 0:
            raise PipelineError(f"{name} must be a nonnegative integer")
    for name in ("resource_wait_sec", "build_cache_keep_gb", "stage_retry_attempts"):
        if type(getattr(settings, name)) is not int or getattr(settings, name) < 1:
            raise PipelineError(f"{name} must be a positive integer")
    if not isinstance(settings.resource_dir, str) or not settings.resource_dir.strip():
        raise PipelineError("resource_dir must be a nonempty local directory")
    if not isinstance(settings.resource_disk_paths, list) or any(not isinstance(p, str) or not p for p in settings.resource_disk_paths):
        raise PipelineError("resource_disk_paths must be a list of paths")
    for name in ("cold_rebuild", "archive_images", "prune_images", "solver_review", "evidence_resolver", "require_harbor_lint", "inherit_claude_settings", "wsl_reclaim_memory"):
        if not isinstance(getattr(settings, name), bool):
            raise PipelineError(f"{name} must be a boolean")
    for name in ("workers", "trial_workers", "trials", "min_trials", "max_calls", "max_total_tokens", "max_context_bytes", "command_timeout_sec"):
        if not isinstance(getattr(settings, name), int) or getattr(settings, name) < 1:
            raise PipelineError(f"{name} must be a positive integer")
    if settings.max_repairs < 0:
        raise PipelineError("max_repairs must be nonnegative")
    if settings.authoring not in {"agent", "legacy"}:
        raise PipelineError("authoring must be 'agent' or 'legacy'")
    if settings.author_sandbox_network not in {"none", "bridge"}:
        raise PipelineError("author_sandbox_network must be 'none' or 'bridge'")
    for name in ("author_max_resumes", "author_build_runs", "author_probe_runs", "author_exec_runs", "max_evidence_reviews", "max_infra_retries"):
        if not isinstance(getattr(settings, name), int) or getattr(settings, name) < 0:
            raise PipelineError(f"{name} must be a nonnegative integer")
    for name in (
        "solver_attempts",
        "solver_max_turns",
        "solver_agent_timeout_sec",
        "solver_timeout_sec",
    ):
        if not isinstance(getattr(settings, name), int) or getattr(settings, name) < 1:
            raise PipelineError(f"{name} must be a positive integer")
    if settings.solver_max_budget_usd <= 0:
        raise PipelineError("solver_max_budget_usd must be positive")
    if not 1 <= settings.solver_min_score <= 5:
        raise PipelineError("solver_min_score must be between 1 and 5")
    for model in config.models.values():
        if model.provider not in {"claude-cli", "anthropic", "fixture", "claude-code"}:
            raise PipelineError(f"Unknown provider: {model.provider}")
        if model.timeout_sec <= 0 or model.max_output_tokens < 1 or model.max_budget_usd <= 0:
            raise PipelineError("Model budgets and timeouts must be positive")
        if model.provider == "claude-code" and model.max_turns < 1:
            raise PipelineError("max_turns must be positive for claude-code")
    return config
