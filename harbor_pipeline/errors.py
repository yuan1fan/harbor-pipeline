"""Error taxonomy shared by every pipeline stage.

Each category declares whether the failure is worth retrying, whether the
auto-repair loop may touch it, and what final state the job should reach.
The names are part of the data contract; do not rename without a policy bump.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

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
    "validation_error": ErrorClass(
        "validation_error", False, True, "QUARANTINED",
        "The differential failed in the synthesized application: healthy target, "
        "rejected negatives, but the reference exploit reached no secret.",
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


def recovery_decision(error) -> dict[str, str]:
    """Choose who can change the outcome; quarantine is only the checkpoint."""
    if isinstance(error, dict):
        code, message, detail = error.get("category"), str(error.get("message") or ""), error.get("detail") or {}
    else:
        code, message, detail = error.category.code, str(error), error.detail
    if code in {"budget_exhausted", "unsupported"}:
        return {"action": "stop", "reason": "budget exhausted" if code == "budget_exhausted" else "explicitly unsupported"}
    override = detail.get("recovery_action")
    if override in {"author", "resolver", "retry", "blocked", "stop"}:
        return {"action": override, "reason": str(detail.get("recovery_reason") or message)[:1200]}
    if code in {"infra_error", "source_error"}:
        context = message + " " + str(detail.get("solver_failure_type") or "")
        if detail.get("author_status") == "auth_error" or detail.get("resolver_status") == "auth_error" or re.search(r"(?i)AuthenticationError|invalid[ _-]*(?:api[ _-]*)?(?:key|token)|unauthorized|"
                     r"authentication failed|missing (?:api.key|credentials)|not logged in|HTTP(?:/\S+)?\s+401\b", context):
            return {"action": "blocked", "reason": "credentials/configuration must be corrected before this stage can run"}
        if re.search(r"(?i)(?:docker|harbor|claude)(?: CLI)? is not on PATH|framework fault-injection check T12 failed", context):
            return {"action": "blocked", "reason": "missing runtime or failed framework self-test requires an external fix"}
        return {"action": "retry", "reason": "retry the failed stage with unchanged task inputs"}
    category = ERROR_CLASSES.get(str(code))
    if category and category.auto_repairable:
        return {"action": "author", "reason": "return task/source/PoC defects to their author without changing acceptance rules"}
    if isinstance(error, dict) and not code and error.get("retryable"):
        return {"action": "retry", "reason": "legacy report explicitly permits a bounded stage retry"}
    return {"action": "blocked", "reason": "no supported automatic repair is available for this evidence or configuration"}


class TaskError(PipelineError):
    """A classified pipeline failure carrying a contract category."""

    def __init__(self, category: str, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.category = error_class(category)
        self.detail = detail or {}

    def as_record(self) -> dict:
        recovery = recovery_decision(self)
        return {
            "category": self.category.code,
            "message": str(self),
            "retryable": recovery["action"] == "retry",
            "auto_repairable": recovery["action"] == "author",
            "recovery": recovery,
            "terminal_state": self.category.terminal_state,
            "detail": self.detail,
        }
