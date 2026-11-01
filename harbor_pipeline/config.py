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
    workers: int = 1
    max_repairs: int = 2
    trials: int = 5
    min_trials: int = 5
    max_calls: int = 12
    max_total_tokens: int = 180000
    max_context_bytes: int = 600000
    command_timeout_sec: int = 300
    python_image: str = "python:3.12.10-slim-bookworm"
    require_harbor_lint: bool = True


@dataclass
class ModelSettings:
    provider: str = "claude-cli"
    model: str = "sonnet"
    timeout_sec: int = 300
    max_output_tokens: int = 18000
    max_budget_usd: float = 3.0
    api_base: str = "https://api.anthropic.com"
    api_version: str = "2023-06-01"


@dataclass
class SourceSettings:
    allowed_hosts: list[str] = field(default_factory=lambda: ["raw.githubusercontent.com", "github.com", "www.cve.org", "nvd.nist.gov", "cveawg.mitre.org", "pypi.org"])
    max_bytes: int = 1500000
    timeout_sec: int = 30


@dataclass
class Config:
    pipeline: Settings = field(default_factory=Settings)
    models: dict[str, ModelSettings] = field(default_factory=lambda: {"default": ModelSettings()})
    sources: SourceSettings = field(default_factory=SourceSettings)

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
        )
        config.models.setdefault("default", ModelSettings(**defaults))
    except TypeError as exc:
        raise PipelineError(f"Invalid configuration: {exc}") from exc
    settings = config.pipeline
    for name in ("workers", "trials", "min_trials", "max_calls", "max_total_tokens", "max_context_bytes", "command_timeout_sec"):
        if not isinstance(getattr(settings, name), int) or getattr(settings, name) < 1:
            raise PipelineError(f"{name} must be a positive integer")
    if settings.max_repairs < 0:
        raise PipelineError("max_repairs must be nonnegative")
    for model in config.models.values():
        if model.provider not in {"claude-cli", "anthropic", "fixture"}:
            raise PipelineError(f"Unknown provider: {model.provider}")
        if model.timeout_sec <= 0 or model.max_output_tokens < 1 or model.max_budget_usd <= 0:
            raise PipelineError("Model budgets and timeouts must be positive")
    return config
