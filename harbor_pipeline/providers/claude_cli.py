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
from ..util import PipelineError
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
        prompt = request.prompt
        if request.schema is not None:
            prompt += "\n\nReturn only JSON matching this schema:\n"
            prompt += json.dumps(request.schema)
        command = [
            self.binary,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--model",
            self.model,
            "--max-turns",
            "1",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.timeout_sec,
                env=self._env(),
                cwd=os.getcwd(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PipelineError("claude CLI timed out") from exc
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
                structured = json.loads(text)
            except ValueError as exc:
                raise PipelineError("claude CLI returned non-JSON structured output") from exc
        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        return ModelResponse(
            text=text,
            structured=structured,
            usage={
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "usd": data.get("total_cost_usd") if isinstance(data, dict) else None,
            },
            model_identity=str(data.get("model", self.model)) if isinstance(data, dict) else self.model,
            raw=data if isinstance(data, dict) else {"raw": str(data)},
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.name, "model": self.model, "binary": self.binary}
