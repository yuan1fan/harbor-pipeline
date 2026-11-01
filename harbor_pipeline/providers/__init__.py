"""Provider registry. Configuration names map to implementations here."""

from __future__ import annotations

from ..config import Config
from ..util import PipelineError
from .base import ModelProvider, ModelRequest, ModelResponse

_REGISTRY = {
    "fixture": ("harbor_pipeline.providers.fixture", "FixtureProvider"),
    "anthropic": ("harbor_pipeline.providers.anthropic_api", "AnthropicProvider"),
    "claude-cli": ("harbor_pipeline.providers.claude_cli", "ClaudeCliProvider"),
}


def build_provider(config: Config, role: str = "default") -> ModelProvider:
    settings = config.model_for(role)
    try:
        module_name, class_name = _REGISTRY[settings.provider]
    except KeyError as exc:
        raise PipelineError(f"Unknown provider {settings.provider!r}") from exc
    module = __import__(module_name, fromlist=[class_name])
    return getattr(module, class_name)(settings)


__all__ = ["ModelProvider", "ModelRequest", "ModelResponse", "build_provider"]
