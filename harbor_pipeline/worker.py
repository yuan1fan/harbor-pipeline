"""Worker-side execution of one candidate.

Workers never raise into the batch: every input must end with a recorded
terminal state, including unexpected host failures. Each worker owns one
candidate directory, so no two workers share a lease or a task tree.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .errors import TaskError
from .pipeline import CvePipeline
from .util import PipelineError


@dataclass
class CandidateJob:
    cve_id: str
    run_id: str
    profile: str
    scenario: str | None
    output_root: Path
    ledger: object


def execute_pipeline(pipeline: CvePipeline, *, retries: int) -> dict:
    """Run or resume until the pipeline reports a non-retryable outcome."""
    attempts = 0
    while True:
        attempts += 1
        report = pipeline.run()
        error = report.error or {}
        if not error.get("retryable"):
            break
        if attempts > retries:
            break
    payload = report.to_json()
    payload["attempts"] = attempts
    return payload


def run_candidate(job: CandidateJob, config: Config) -> dict:
    """Build the pipeline for one candidate and never let it escape."""
    try:
        pipeline = CvePipeline(
            config=config,
            cve_id=job.cve_id,
            run_id=job.run_id,
            profile=job.profile,
            scenario=job.scenario,
            workers=1,
            ledger=job.ledger,
            output_root=job.output_root,
        )
        payload = execute_pipeline(
            pipeline, retries=max(0, config.pipeline.max_repairs)
        )
        payload["report_path"] = str(pipeline.root / "report.json")
        return payload
    except TaskError as exc:
        return _failure(job, exc)
    except PipelineError as exc:
        category = "unsupported" if "No built-in" in str(exc) else "infra_error"
        return _failure(job, TaskError(category, str(exc)))
    except Exception as exc:  # noqa: BLE001 - a worker must always report
        return _failure(
            job,
            TaskError("infra_error", f"{type(exc).__name__}: {exc}"),
            traceback=traceback.format_exc(limit=5),
        )


def _failure(job: CandidateJob, error: TaskError, *, traceback: str | None = None) -> dict:
    record = error.as_record()
    if traceback:
        record["traceback"] = traceback
    return {
        "schema_version": "1.0",
        "cve_id": job.cve_id,
        "run_id": job.run_id,
        "state": error.category.terminal_state,
        "task_digest": None,
        "image_digest": None,
        "quality_score": None,
        "admission_status": None,
        "release": None,
        "evaluation": None,
        "trials": [],
        "error": record,
        "budget": {},
        "attempts": 0,
    }
