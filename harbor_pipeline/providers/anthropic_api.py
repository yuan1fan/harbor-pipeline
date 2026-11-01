"""Anthropic Messages API provider using only the standard library."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from ..config import ModelSettings
from ..util import PipelineError
from .base import ModelRequest, ModelResponse


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, settings: ModelSettings):
        self.settings = settings
        self.model = settings.model
        if not self.model or self.model.startswith("${"):
            raise PipelineError("Set CLAUDE_MODEL to an exact model id")
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise PipelineError("ANTHROPIC_API_KEY is not set")
        if settings.max_budget_usd <= 0:
            raise PipelineError("max_budget_usd must be positive")

    def _payload(self, request: ModelRequest) -> dict:
        system = request.system
        if request.schema is not None:
            system += (
                "\nReturn only a JSON object matching the supplied schema. "
                "Do not wrap it in markdown."
            )
        return {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "system": system,
            "messages": [{"role": "user", "content": request.prompt}],
        }

    def generate(self, request: ModelRequest) -> ModelResponse:
        payload = self._payload(request)
        body = json.dumps(payload).encode("utf-8")
        url = f"{self.settings.api_base.rstrip('/')}/v1/messages"
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": self.settings.api_version,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.settings.timeout_sec) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise PipelineError(f"Anthropic API error {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PipelineError(f"Anthropic API unavailable: {exc}") from exc

        text = "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        )
        structured = None
        if request.schema is not None:
            try:
                structured = json.loads(text)
            except ValueError as exc:
                raise PipelineError("Model returned non-JSON structured output") from exc
        usage = data.get("usage", {})
        return ModelResponse(
            text=text,
            structured=structured,
            usage={
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "usd": None,
            },
            model_identity=data.get("model", self.model),
            raw=data,
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.name, "model": self.model}
