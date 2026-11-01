"""Provider contract.

A provider returns text plus, when a JSON schema is supplied, a parsed
structured object. It never executes host commands and never sees the
pipeline's credentials beyond its own configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..util import PipelineError


@dataclass(frozen=True)
class ModelRequest:
    role: str
    system: str
    prompt: str
    schema: dict | None = None
    max_output_tokens: int = 18000
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelResponse:
    text: str
    structured: dict | None
    usage: dict[str, Any]
    model_identity: str
    raw: dict[str, Any] = field(default_factory=dict)


class ModelProvider(Protocol):
    name: str

    def generate(self, request: ModelRequest) -> ModelResponse: ...

    def health(self) -> dict[str, Any]: ...


def ensure_structured(response: ModelResponse) -> dict:
    if response.structured is None:
        raise PipelineError(
            f"Model {response.model_identity} did not return structured output"
        )
    return response.structured
