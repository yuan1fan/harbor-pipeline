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
        self.api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get(
            "ANTHROPIC_AUTH_TOKEN"
        )
        if not self.api_key:
            raise PipelineError("ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN is not set")
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
            # Some gateway models default to extended reasoning and can spend
            # the whole output budget before emitting a single text block.
            "thinking": {"type": "disabled"},
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
            structured = _parse_json_object(text)
            if structured is None:
                stop = data.get("stop_reason")
                hint = (
                    " (output_token_limit)" if stop == "max_tokens" else ""
                )
                raise PipelineError(
                    f"Model returned non-JSON structured output: stop_reason={stop!r}, "
                    f"chars={len(text)}{hint}, tail={text[-200:]!r}"
                )
        usage = _usage(data.get("usage", {}), request.system, request.prompt)
        return ModelResponse(
            text=text,
            structured=structured,
            usage=usage,
            model_identity=data.get("model", self.model),
            raw=data,
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.name, "model": self.model}


def _usage(usage: dict, system: str, prompt: str) -> dict:
    """Return budget-accounting tokens, including cached prompt tokens.

    The gateway reports ``cache_read_input_tokens`` separately from
    ``input_tokens``, and has also returned a small fraction of a long prompt
    (134 tokens for an 8 KB prompt). A budget that trusts such a number cannot
    enforce ``max_total_tokens``, so an implausibly low report is replaced by
    the usual four-characters-per-token estimate and flagged.
    """
    reported = sum(
        int(usage.get(key, 0) or 0)
        for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    )
    estimated = max(1, (len(system) + len(prompt)) // 4)
    result = {
        "input_tokens": reported,
        "output_tokens": int(usage.get("output_tokens", 0) or 0),
        "usd": None,
    }
    # Keep normal reports, including cache hits; only reject a report below a
    # quarter of the prompt-length estimate.
    if reported < estimated // 4:
        result["input_tokens"] = estimated
        result["input_tokens_estimated"] = True
        result["input_tokens_reported"] = reported
    return result


def _parse_json_object(text: str) -> dict | None:
    """Parse the first complete JSON object, tolerating fences and prose.

    Model outputs routinely wrap the object in a sentence and sometimes leave
    literal newlines inside string values. ``strict=False`` accepts the control
    characters, and ``raw_decode`` stops at the end of the first complete
    object, so trailing commentary cannot invalidate an otherwise good bundle.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.endswith("```"):
            stripped = stripped[:-3]
        stripped = stripped.strip()
    for candidate in (stripped, text[text.find("{"): text.rfind("}") + 1]):
        if not candidate:
            continue
        try:
            value = json.loads(candidate, strict=False)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value

    decoder = json.JSONDecoder(strict=False)
    best: tuple[int, dict] | None = None
    tried = 0
    for index, char in enumerate(text):
        if char != "{" or tried >= 200:
            continue
        tried += 1
        try:
            value, _ = decoder.raw_decode(text[index:])
        except ValueError:
            continue
        if isinstance(value, dict) and (best is None or len(value) > best[0]):
            best = (len(value), value)
    return best[1] if best else None
