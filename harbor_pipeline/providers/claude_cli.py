"""Provider that shells out to a locally installed Claude Code CLI.

The CLI is treated as an untrusted text generator: its stdout is parsed, its
environment is scrubbed of pipeline secrets, and no host files are mounted.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from ..config import ModelSettings
from ..util import PipelineError, hidden_console_kwargs
from .base import ModelRequest, ModelResponse

_SECRET_ENV = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
)


class ClaudeCliProvider:
    name = "claude-cli"

    def __init__(self, settings: ModelSettings):
        self.settings = settings
        self.binary = shutil.which("claude")
        if not self.binary:
            raise PipelineError("claude CLI is not on PATH")
        self.model = settings.model

    def _env(self) -> dict[str, str]:
        return {k: v for k, v in os.environ.items() if k not in _SECRET_ENV}

    def generate(self, request: ModelRequest) -> ModelResponse:
        # The system prompt travels with the prompt because this provider has
        # no separate system channel. Dropping it would silently lose the
        # role's safety and output constraints.
        prompt = request.prompt
        if request.system:
            prompt = f"{request.system.strip()}\n\n{prompt}"
        if request.schema is not None:
            prompt += "\n\nReturn only JSON matching this schema:\n"
            prompt += json.dumps(request.schema)
        # The prompt goes over stdin: evidence bundles exceed the Windows
        # command-line limit (~32 KB) and argv is visible to other processes.
        # ``--tools ""`` disables every built-in tool: the prompt contains
        # untrusted evidence-derived code, and with tools enabled the CLI
        # executes host commands and exhausts --max-turns instead of replying.
        base = [
            self.binary,
            "-p",
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--tools",
            "",
        ]
        # Gateway aliases (for example deepseek-flash-cyber) are accepted by the
        # CLI's configured default but rejected as an explicit --model value.
        # Try the configured model first, then fall back to the CLI default.
        for model_args in (["--model", self.model], []):
            try:
                completed = subprocess.run(
                    base + model_args,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=self.settings.timeout_sec,
                    env=self._env(),
                    cwd=os.getcwd(),
                    check=False,
                    # ``claude`` is also a uv trampoline and allocates a
                    # visible console without one of its own.
                    **hidden_console_kwargs(),
                )
            except subprocess.TimeoutExpired as exc:
                raise PipelineError("claude CLI timed out") from exc
            if completed.returncode == 0:
                break
            if model_args and "unrecognized_model" in (completed.stderr or ""):
                continue
            break
        if completed.returncode != 0:
            raise PipelineError(
                f"claude CLI failed ({completed.returncode}): {completed.stderr[:400]}"
            )
        try:
            data = json.loads(completed.stdout)
        except ValueError as exc:
            raise PipelineError("claude CLI returned non-JSON output") from exc
        text = data.get("result", "") if isinstance(data, dict) else str(data)
        structured = None
        if request.schema is not None:
            try:
                structured = json.loads(_unfence(text))
            except ValueError as exc:
                # Echo the head of the reply: without it a repair that keeps
                # failing looks identical to a provider outage.
                raise PipelineError(
                    "claude CLI returned non-JSON structured output: "
                    f"{text.strip()[:200]!r}"
                ) from exc
        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        return ModelResponse(
            text=text,
            structured=structured,
            usage={
                # Cached prompt tokens are reported separately but still count
                # against the campaign token budget.
                "input_tokens": sum(
                    int(usage.get(key, 0) or 0)
                    for key in (
                        "input_tokens",
                        "cache_creation_input_tokens",
                        "cache_read_input_tokens",
                    )
                ),
                "output_tokens": usage.get("output_tokens", 0),
                "usd": data.get("total_cost_usd") if isinstance(data, dict) else None,
            },
            model_identity=str(data.get("model", self.model)) if isinstance(data, dict) else self.model,
            raw=data if isinstance(data, dict) else {"raw": str(data)},
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.name, "model": self.model, "binary": self.binary}


def _unfence(text: str) -> str:
    """Strip a Markdown code fence around a JSON reply.

    The synthesizer occasionally wraps the object in ```json even when the
    prompt asks for raw JSON. Parsing that as text fails and wastes a retry,
    so the fence is removed before decoding.
    """
    candidate = text.strip()
    if candidate.startswith("```"):
        newline = candidate.find("\n")
        if newline != -1:
            candidate = candidate[newline + 1 :]
            if candidate.rstrip().endswith("```"):
                candidate = candidate.rstrip()[:-3]
            candidate = candidate.strip()
    if candidate.startswith("{") or candidate.startswith("["):
        return candidate
    # Some replies open with a sentence ("Here is the JSON:"). Everything
    # after the first brace is still schema-checked and path-checked, so a
    # wrong object fails the same way a wrong prose reply does.
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end > start:
        return candidate[start : end + 1]
    return candidate
