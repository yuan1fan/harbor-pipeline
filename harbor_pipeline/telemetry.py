"""Append-only per-candidate stage/call accounting, separate from budget limits.

Events are the source of truth. The JSON view is rebuilt under the same lock;
parent stages aggregate metered descendants instead of charging them twice.
No prompts, credentials, model responses or exception messages are recorded.
"""
from __future__ import annotations

import json
import math
import os
import time
import uuid
import warnings
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from .util import PipelineError, file_lock, read_json, write_json

EVENTS = "stage-events.jsonl"
SUMMARY = "stage-usage.json"
_CURRENT = ContextVar("stage_meter", default=None)
_DETAILS = ContextVar("stage_meter_details", default={})
FIELDS = ("input_tokens", "uncached_input_tokens", "output_tokens", "cache_read_input_tokens",
          "cache_creation_input_tokens", "total_tokens", "cost_usd")


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def usage(raw=None, *, source="accounting", cost=None):
    """Normalize reported counters, keeping missing measurements unknown.

    Native Claude reports uncached/cache input separately. Harbor's n_input
    already includes cache input; n_cache is a subset and must not be added.
    Provider accounting input is inclusive, and may carry a separate estimate.
    """
    raw = raw if isinstance(raw, dict) else {}
    result = dict.fromkeys(FIELDS)
    result.update(source=source, estimated_input_tokens=None)
    if source == "anthropic":
        result.update(uncached_input_tokens=_number(raw.get("input_tokens")),
                      output_tokens=_number(raw.get("output_tokens")),
                      cache_read_input_tokens=_number(raw.get("cache_read_input_tokens")),
                      cache_creation_input_tokens=_number(raw.get("cache_creation_input_tokens")))
        inputs = [result[k] for k in ("uncached_input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")]
        if all(v is not None for v in inputs):
            result["input_tokens"] = sum(inputs)
    elif source == "harbor":
        result.update(input_tokens=_number(raw.get("n_input_tokens")), output_tokens=_number(raw.get("n_output_tokens")),
                      cache_read_input_tokens=_number(raw.get("n_cache_tokens")))
    else:
        reported = raw.get("input_tokens_reported") if raw.get("input_tokens_estimated") else raw.get("input_tokens")
        result.update(input_tokens=_number(reported), output_tokens=_number(raw.get("output_tokens")),
                      cache_read_input_tokens=_number(raw.get("cache_read_input_tokens")),
                      cache_creation_input_tokens=_number(raw.get("cache_creation_input_tokens")))
        if raw.get("input_tokens_estimated"):
            result["estimated_input_tokens"] = _number(raw.get("input_tokens"))
    result["cost_usd"] = _number(cost if cost is not None else raw.get("cost_usd", raw.get("usd")))
    if result["input_tokens"] is not None and result["output_tokens"] is not None:
        result["total_tokens"] = result["input_tokens"] + result["output_tokens"]
    result["status"] = "reported" if result["total_tokens"] is not None else "partial" if any(result[k] is not None for k in FIELDS) else "unknown"
    return result


def _zero():
    return {**{key: 0 for key in FIELDS}, "status": "not_incurred", "source": "cache_or_no_model"}


def _aggregate(units):
    if not units:
        return {**_zero(), "known": {key: 0 for key in FIELDS}, "missing": {key: 0 for key in FIELDS}}
    values = [row.get("reported_usage") or usage() for row in units]
    result = {key: sum(v[key] for v in values) if all(v.get(key) is not None for v in values) else None for key in FIELDS}
    result["known"] = {key: sum(v.get(key) or 0 for v in values) for key in FIELDS}
    result["missing"] = {key: sum(v.get(key) is None for v in values) for key in FIELDS}
    result["status"] = "reported" if result["total_tokens"] is not None else (
        "partial" if any(v.get(key) is not None for v in values for key in FIELDS) else "unknown")
    return result


def _events(path):
    records, malformed = [], 0
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict) and item.get("invocation_id"):
                        records.append(item)
                    else:
                        malformed += 1
                except ValueError:
                    malformed += 1
    return records, malformed


def summarize(events, malformed=0):
    rows = {}
    for event in events:
        identity = event["invocation_id"]
        rows.setdefault(identity, {}).update({k: v for k, v in event.items() if k != "event"})
    children = {}
    for row in rows.values():
        children.setdefault(row.get("parent_id"), []).append(row)

    def metered(row, visited=()):
        if row["invocation_id"] in visited:
            return []
        if row.get("cache_hit"):
            return []
        descendants = [unit for child in children.get(row["invocation_id"], [])
                       for unit in metered(child, (*visited, row["invocation_id"]))]
        if descendants:
            return descendants
        if row.get("expects_usage") or row.get("reported_usage") is not None:
            return [row]
        return []

    all_units = {}
    for row in rows.values():
        if not row.get("finished_at"):
            row["status"] = "unfinished"
        units = metered(row)
        row["usage"] = _aggregate(units)
        row["usage_invocation_ids"] = [unit["invocation_id"] for unit in units]
        all_units.update((unit["invocation_id"], unit) for unit in units)
    roles = {}
    for unit in all_units.values():
        roles.setdefault(unit["stage"], []).append(unit)
    first = next(iter(rows.values()), {})
    return {"schema_version": "1.0", "cve_id": first.get("cve_id"), "run_id": first.get("run_id"),
            "coverage": "recorded invocations only; pre-existing cached artifacts are not historical billing records",
            "stages": list(rows.values()), "totals": _aggregate(list(all_units.values())),
            "by_stage": {name: {"invocations": len(units), "usage": _aggregate(units),
                                "metered_elapsed_sec": sum(_number(u.get("reported_duration_sec"))
                                    if _number(u.get("reported_duration_sec")) is not None else u.get("elapsed_sec", 0) for u in units)}
                         for name, units in roles.items()},
            "root_elapsed_sec": sum(r.get("elapsed_sec", 0) for r in rows.values() if not r.get("parent_id")),
            "metered_invocations": len(all_units), "incomplete_stages": sum(not r.get("finished_at") for r in rows.values()),
            "malformed_event_lines": malformed,
            "note": "Stage times include their children; usage totals count each metered invocation once. Null means unknown; known is a partial subtotal."}


def rebuild(root):
    path = Path(root) / EVENTS
    if not path.is_file():
        raise PipelineError("No stage events exist for this candidate; historical usage cannot be reconstructed as zero")
    with file_lock(path):
        events, malformed = _events(path)
        report = summarize(events, malformed)
        write_json(Path(root) / SUMMARY, report)
        return report


@contextmanager
def details(**values):
    token = _DETAILS.set({**_DETAILS.get(), **values})
    try:
        yield
    finally:
        _DETAILS.reset(token)


def current():
    return _CURRENT.get()


def label(name, default=None):
    return _DETAILS.get().get(name, default)


class Stage:
    def __init__(self, stage, *, root=None, cve_id=None, kind="stage", expects_usage=False, **metadata):
        parent = current()
        self.root = Path(root).resolve() if root is not None else parent.root if parent else None
        self.enabled = self.root is not None
        parent = parent if parent and parent.root == self.root else None
        parent_id = parent.record["invocation_id"] if parent else None
        inherited = {key: parent.record[key] for key in ("reason", "repair_round", "review_request_id", "call_reason")
                     if parent and key in parent.record}
        self.record = {"invocation_id": uuid.uuid4().hex, "parent_id": parent_id, "stage": stage, "kind": kind,
                       "cve_id": cve_id or (parent.record["cve_id"] if parent else self.root.name if self.root else None),
                       "run_id": self.root.parent.name if self.root else None, "expects_usage": expects_usage,
                       **inherited, **_DETAILS.get(), **metadata}

    def _revision(self):
        try:
            return read_json(self.root / "state.json").get("revision")
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _append(self, event):
        if not self.enabled:
            return
        path = self.root / EVENTS
        try:
            with file_lock(path):
                events, malformed = _events(path)
                if event == "started":
                    self.record["attempt"] = 1 + sum(e.get("event") == "started" and e.get("stage") == self.record["stage"]
                                                      and e.get("kind") == self.record["kind"] for e in events)
                payload = {"event": event, **self.record}
                # Preserve a torn last line, but separate the next valid event.
                with path.open("a+b") as handle:
                    if handle.tell():
                        handle.seek(-1, 2)
                        if handle.read(1) != b"\n":
                            handle.write(b"\n")
                    handle.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
                write_json(self.root / SUMMARY, summarize([*events, payload], malformed))
        except (OSError, PipelineError) as exc:
            warnings.warn(f"Stage accounting unavailable ({type(exc).__name__}); task execution continues", RuntimeWarning)

    def __enter__(self):
        self.started = time.monotonic()
        self.record.update(started_at=datetime.now(timezone.utc).isoformat(timespec="microseconds"), status="running",
                           revision=self._revision() if self.enabled else None, pid=os.getpid())
        self._append("started")
        self.token = _CURRENT.set(self)
        return self

    def set_usage(self, raw, *, source="accounting", cost=None):
        self.record["reported_usage"] = usage(raw, source=source, cost=cost)

    def outcome(self, outcome, *, source="anthropic"):
        session_id = getattr(outcome, "session_id", None) or (getattr(outcome, "session", None) or {}).get("session_id")
        self.record.update(status=outcome.status, session_id=session_id, turns=outcome.turns)
        self.set_usage(outcome.usage, source=source, cost=outcome.usd)

    def cache(self, artifact):
        self.record.update(cache_hit=True, cache_source=artifact, status="cached")

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc is not None:
                self.record.update(status="failed" if isinstance(exc, Exception) else "interrupted", error_type=type(exc).__name__)
                category = getattr(exc, "category", None)
                if category:
                    self.record["error_category"] = category.code
                captured = getattr(exc, "metering_usage", None)
                if captured:
                    self.record["reported_usage"] = captured
            elif self.record["status"] == "running":
                self.record["status"] = "completed"
            self.record.update(finished_at=datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                               elapsed_sec=round(max(0, time.monotonic() - self.started), 6),
                               revision_after=self._revision() if self.enabled else None)
            self._append("finished")
        finally:
            _CURRENT.reset(self.token)
        return False


def pipeline_stage(name, *, expects_usage=False):
    def decorate(function):
        @wraps(function)
        def measured(self, *args, **kwargs):
            with Stage(name, root=self.store.root, cve_id=self.cve_id, expects_usage=expects_usage) as stage:
                result = function(self, *args, **kwargs)
                if hasattr(result, "state"):
                    stage.record["task_state"] = result.state
                    error = getattr(result, "error", None)
                    if error:
                        stage.record.update(status="failed", error_category=error.get("category"))
                return result
        return measured
    return decorate


def response_usage(response):
    raw = getattr(response, "raw", {}) or {}
    if isinstance(raw.get("usage"), dict):
        cost = raw.get("total_cost_usd")
        if cost is None:
            cost = response.usage.get("cost_usd", response.usage.get("usd"))
        result = usage(raw["usage"], source="anthropic", cost=cost)
        if response.usage.get("input_tokens_estimated"):
            result["estimated_input_tokens"] = _number(response.usage.get("input_tokens"))
        return result
    return usage(response.usage)


def model_request(provider, request, *, stage="reviewer", model=None, reason=None, generate=None):
    if generate is None and getattr(provider.generate, "_stage_metered", False):
        with details(call_reason=reason):
            return provider.generate(request)
    with Stage(stage, kind="model_call", expects_usage=True, model=model,
               provider=getattr(provider, "name", None), call_reason=reason) as meter:
        response = (generate or provider.generate)(request)
        meter.record["reported_usage"] = response_usage(response)
        meter.record["model"] = response.model_identity
        return response


def metered_provider(provider, role, model):
    original = provider.generate

    @wraps(original)
    def generate(request):
        return model_request(provider, request, stage=role, model=model, reason=label("call_reason"), generate=original)

    generate._stage_metered = True
    provider.generate = generate
    return provider
