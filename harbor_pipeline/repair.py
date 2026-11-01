"""Bounded, auditable model-assisted repair of environment build failures.

The repairer may only rewrite existing files under ``environment/``. The
instruction, verifier, reference solution, and frozen spec are never editable,
so a model can fix packaging or dependency problems but cannot change what the
task asks or how it is graded.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .budget import Ledger
from .config import Config, ModelSettings
from .errors import TaskError
from .providers import build_provider
from .providers.base import ModelRequest, ModelResponse, ensure_structured
from .util import PipelineError, digest

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 1_000_000

REPAIR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["files", "reason"],
    "properties": {
        "reason": {"type": "string"},
        "files": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
    },
}

SYSTEM = """\
You repair a containerised security-training task that failed to build.
Return JSON only. You may edit existing files under environment/ and nothing
else. Never add new files, never touch instruction.md, tests/, solution/, or
task.toml, and never weaken a vulnerability or its detection. Keep the change
minimal and explain it in `reason`."""


@dataclass
class RepairResult:
    files: dict[str, str]
    reason: str
    model_identity: str
    usage: dict[str, Any]
    error: str | None = None


class RepairEngine:
    def __init__(self, config: Config, ledger: Ledger, *, role: str = "repairer"):
        self.config = config
        self.ledger = ledger
        self.role = role
        self.settings: ModelSettings = config.model_for(role)
        self.provider = build_provider(config, role)

    @property
    def identity(self) -> str:
        return getattr(self.provider, "name", "unknown")

    def repair(
        self,
        *,
        cve_id: str,
        revision: int,
        error: TaskError,
        files: dict[str, str],
        previous: dict[str, str] | None = None,
    ) -> RepairResult:
        editable = {
            name: body
            for name, body in files.items()
            if name.startswith("environment/")
        }
        prompt = self._prompt(error=error, files=editable, previous=previous or {})
        estimated = max(1, len(prompt) // 4) + self.settings.max_output_tokens
        reservation = f"{cve_id}-repair-{revision}"
        try:
            self.ledger.reserve(reservation, {"calls": 1, "tokens": estimated})
        except PipelineError as exc:
            raise TaskError("budget_exhausted", str(exc)) from exc
        try:
            response = self.provider.generate(
                ModelRequest(
                    role=self.role,
                    system=SYSTEM,
                    prompt=prompt,
                    schema=REPAIR_SCHEMA,
                    max_output_tokens=self.settings.max_output_tokens,
                    metadata={"cve_id": cve_id, "revision": revision},
                )
            )
        except Exception as exc:  # noqa: BLE001 - any provider fault is non-fatal
            self.ledger.refund(reservation)
            return RepairResult({}, "", "unavailable", {}, error=str(exc))

        usage = _usage(response)
        self.ledger.commit(reservation, {
            "calls": 1,
            "tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            **({"usd": float(usage["usd"])} if isinstance(usage.get("usd"), (int, float)) else {}),
        })
        try:
            body = ensure_structured(response)
            applied = _validate(body, editable, previous or {})
        except PipelineError as exc:
            return RepairResult({}, "", response.model_identity, usage, error=str(exc))
        return RepairResult(
            files=applied,
            reason=str(body.get("reason", ""))[:2000],
            model_identity=response.model_identity,
            usage=usage,
        )

    def _prompt(self, *, error: TaskError, files: dict[str, str], previous: dict[str, str]) -> str:
        chunks = [
            f"The task failed with {error.category.code}: {error}",
            "Current environment files:",
        ]
        budget = max(4000, self.config.pipeline.max_context_bytes)
        used = 0
        for name, body in sorted(files.items()):
            block = f"--- {name} ---\n{body}\n"
            if used + len(block) > budget:
                break
            chunks.append(block)
            used += len(block)
        if previous:
            chunks.append("Edits already applied by earlier repair attempts:")
            for name, body in sorted(previous.items()):
                chunks.append(f"--- {name} (current) ---\n{body}\n")
        chunks.append(
            "Return only files that must change. The JSON schema is provided separately."
        )
        return "\n".join(chunks)


def _usage(response: ModelResponse) -> dict[str, Any]:
    usage = dict(response.usage or {})
    usage.setdefault("input_tokens", 0)
    usage.setdefault("output_tokens", 0)
    return usage


def _validate(
    body: dict[str, Any],
    editable: dict[str, str],
    previous: dict[str, str],
) -> dict[str, str]:
    if not isinstance(body, dict):
        raise PipelineError("Repair response is not an object")
    entries = body.get("files")
    if not isinstance(entries, list):
        raise PipelineError("Repair response has no files list")
    applied: dict[str, str] = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise PipelineError("Repair file entry is not an object")
        path = entry.get("path")
        content = entry.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            raise PipelineError("Repair file entry needs string path and content")
        if not path.startswith("environment/") or "/" not in path or ".." in path.split("/"):
            raise PipelineError(f"Repair may not modify {path!r}")
        if path not in editable:
            raise PipelineError(f"Repair may not create or touch {path!r}")
        size = len(content.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            raise PipelineError(f"Repair for {path} exceeds {MAX_FILE_BYTES} bytes")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise PipelineError("Repair exceeds the total size limit")
        if content == editable[path] or content == previous.get(path):
            continue
        applied[path] = content
    return applied


def repair_log_entry(
    *,
    attempt: int,
    result: RepairResult,
    error: TaskError,
    files_before: dict[str, str],
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "error_category": error.category.code,
        "error_message": str(error),
        "model": result.model_identity,
        "reason": result.reason,
        "changed": sorted(result.files),
        "digests": {
            name: digest(body) for name, body in sorted(result.files.items())
        },
        "usage": result.usage,
        "failure": result.error,
        "files_before": sorted(files_before),
    }
