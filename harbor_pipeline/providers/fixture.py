"""Deterministic provider used for smoke tests and offline CI.

It returns canned, contract-valid objects for each role. It is intentionally
unable to invent new scenarios: the generator consumes only the fixed plan.
"""

from __future__ import annotations

import json
from typing import Any

from .. import fixtures
from ..util import digest
from .base import ModelRequest, ModelResponse


class FixtureProvider:
    name = "fixture"

    def __init__(self, settings: Any = None, **_kwargs: Any) -> None:
        self.settings = settings
        self.calls: list[dict] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls.append({"role": request.role, "prompt_digest": digest(request.prompt)})
        if request.role == "spec":
            body = fixtures.cve_spec()
        elif request.role == "scenario":
            body = {
                "template": "fixture",
                "parameters": {},
                "notes": "fixture provider selects the built-in fixture scenario",
            }
        elif request.role in {"repair", "repairer"}:
            body = {"files": [], "reason": "fixture provider never repairs"}
        else:
            body = {"status": "ok", "role": request.role}
        text = json.dumps(body, sort_keys=True)
        return ModelResponse(
            text=text,
            structured=body,
            usage={"input_tokens": 0, "output_tokens": 0, "usd": 0.0},
            model_identity="fixture/deterministic-v1",
            raw={"fixture": True},
        )

    def health(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.name, "model": "fixture/deterministic-v1"}
