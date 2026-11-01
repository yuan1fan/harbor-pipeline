"""Error taxonomy shared by every pipeline stage.

Each category declares whether the failure is worth retrying, whether the
auto-repair loop may touch it, and what final state the job should reach.
The names are part of the data contract; do not rename without a policy bump.
"""

from __future__ import annotations

from dataclasses import dataclass

from .util import PipelineError


@dataclass(frozen=True)
class ErrorClass:
    code: str
    retryable: bool
    auto_repairable: bool
    terminal_state: str
    description: str


ERROR_CLASSES: dict[str, ErrorClass] = {
    "source_error": ErrorClass(
        "source_error", True, False, "QUARANTINED",
        "A source snapshot could not be fetched, parsed, or verified.",
    ),
    "evidence_insufficient": ErrorClass(
        "evidence_insufficient", False, False, "QUARANTINED",
        "Sources do not support the required facts; unknown fields remain.",
    ),
    "generation_error": ErrorClass(
        "generation_error", False, True, "QUARANTINED",
        "The model produced files outside its role or without a required artifact.",
    ),
    "build_error": ErrorClass(
        "build_error", False, True, "QUARANTINED",
        "A candidate image or Harbor package failed to build or lint.",
    ),
    "infra_error": ErrorClass(
        "infra_error", True, False, "QUARANTINED",
        "Docker, Harbor, or the host failed; the candidate was never exercised.",
    ),
    "oracle_failure": ErrorClass(
        "oracle_failure", True, True, "QUARANTINED",
        "The reference solution did not reach the goal on a healthy vulnerable build.",
    ),
    "attribution_failure": ErrorClass(
        "attribution_failure", False, True, "QUARANTINED",
        "The differential does not tie the task goal to the target fix.",
    ),
    "grader_failure": ErrorClass(
        "grader_failure", False, True, "QUARANTINED",
        "The verifier accepted a negative case or rejected a known-good submission.",
    ),
    "budget_exhausted": ErrorClass(
        "budget_exhausted", False, False, "QUARANTINED",
        "A hard budget (calls, tokens, wall clock, trials, disk) was exhausted.",
    ),
    "unsupported": ErrorClass(
        "unsupported", False, False, "UNSUPPORTED",
        "The CVE cannot be represented by the first-version web scenario contract.",
    ),
}


def error_class(code: str) -> ErrorClass:
    try:
        return ERROR_CLASSES[code]
    except KeyError as exc:
        raise PipelineError(f"Unknown error category: {code!r}") from exc


class TaskError(PipelineError):
    """A classified pipeline failure carrying a contract category."""

    def __init__(self, category: str, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.category = error_class(category)
        self.detail = detail or {}

    def as_record(self) -> dict:
        return {
            "category": self.category.code,
            "message": str(self),
            "retryable": self.category.retryable,
            "auto_repairable": self.category.auto_repairable,
            "terminal_state": self.category.terminal_state,
            "detail": self.detail,
        }
