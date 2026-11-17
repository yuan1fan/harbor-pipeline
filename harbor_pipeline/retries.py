"""Small stage-local retries; infrastructure failures never change task inputs."""
from __future__ import annotations

import re
import time
from pathlib import Path

from .errors import TaskError
from .util import PipelineError, digest, file_lock, read_json, write_json


TRANSIENT_BUILD = re.compile(
    r"(?i)ECONNRESET|ETIMEDOUT|EAI_AGAIN|TLS|SSL_ERROR|SSL certificate|"
    r"Temporary failure|(?:502|503|504)\s+(?:Bad Gateway|Service Unavailable|Gateway)|"
    r"Could not resolve host|Connection (?:reset|refused)|network is unreachable|"
    r"unexpected EOF|read: connection|context deadline exceeded|i/o timeout|"
    r"Too Many Requests|rate.limit|HTTP(?:/\S+)?\s+(?:429|502|503|504)|"
    r"out of memory|OOMKilled|cannot allocate memory|signal: killed|exit code:?\s*137\b"
)
TRANSIENT_MODEL = re.compile(
    r"(?i)rate.?limit|too many requests|\b429\b|\b50[234]\b|overloaded|"
    r"temporarily unavailable|connection (?:reset|refused)|timed?\s*out|timeout|API unavailable"
)


def retry_model(operation, *, settings, directory, attempts=3):
    """Coordinate a short cooldown for callers using the same API endpoint."""
    path = Path(directory).resolve() / f"model-cooldown-{digest(settings.api_base)[:16]}.json"
    for attempt in range(attempts):
        if path.is_file():
            try:
                delay = min(30, max(0, float(read_json(path).get("not_before", 0)) - time.time()))
            except (OSError, ValueError, TypeError):
                delay = 0
            if delay:
                time.sleep(delay)
        try:
            return operation()
        except PipelineError as exc:
            transient = TRANSIENT_MODEL.search(str(exc)) or bool(getattr(exc, "detail", {}).get("retryable_model"))
            if not transient or attempt + 1 == attempts:
                raise
            delay = min(30, 2 ** (attempt + 1))
            with file_lock(path):
                try:
                    previous = read_json(path) if path.is_file() else {}
                except (OSError, ValueError):
                    previous = {}
                write_json(path, {"not_before": max(float(previous.get("not_before", 0)), time.time() + delay),
                                  "reason": "transient_model_service_failure"})


def add_usage(total, usage):
    cost = float(total.get("cost_usd") or 0) + float(usage.get("cost_usd", usage.get("usd", 0)) or 0)
    for key, value in usage.items():
        if isinstance(value, (int, float)) and key not in {"usd", "cost_usd"}:
            total[key] = total.get(key, 0) + value
    total["cost_usd"] = cost
    total["calls"] = total.get("calls", 0) + 1


def retry_infrastructure(operation, *, attempts=3, delay_sec=2.0, on_retry=None):
    """Only an explicitly retryable infrastructure/source error may retry here."""
    for attempt in range(attempts):
        try:
            return operation()
        except TaskError as exc:
            if exc.category.code not in {"infra_error", "source_error"}:
                raise
            if attempt + 1 == attempts:
                exc.detail = {**(exc.detail or {}), "automatic_retry_exhausted": True,
                              "stage_attempts": attempts}
                raise
            if on_retry:
                on_retry(attempt + 1, exc)
            time.sleep(min(30.0, delay_sec * 2**attempt))
