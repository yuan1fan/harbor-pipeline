"""Atomic checkpoints for successful oracle trials and independent cold seeds."""
from __future__ import annotations

import copy
import re
from pathlib import Path

from .trials import Expectation
from .util import digest, read_json, write_json
from .validation_evidence import execution_files


def seed_succeeded(record: dict) -> bool:
    variant = record.get("variant")
    status, reward = ("goal_passed", 1.0) if variant == "vulnerable" else ("fixed_variant_holds", 0.0)
    audit = record.get("_audit") or {}
    return (
        variant in {"vulnerable", "fixed"} and record.get("experiment_id") == "T09"
        and record.get("error_category") is None and record.get("reward") == reward
        and (record.get("health") or {}).get("ok") is True
        and (record.get("trigger_evidence") or {}).get("detail") == status
        and audit.get("mode") == "clean-rebuild" and audit.get("no_cache") is True
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(audit.get("actual_image_digest", ""))))
    )


class ExecutionProgress:
    def __init__(self, path: Path, signature: str):
        self.path, self.signature = path, signature
        self.entries = {}
        try:
            data = read_json(path)
            if data.get("protocol") == 1 and data.get("signature") == signature:
                self.entries = dict(data.get("entries") or {})
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _get(self, key, task):
        entry = self.entries.get(key)
        if not isinstance(entry, dict) or entry.get("input") != digest(execution_files(task)):
            return None
        value = entry.get("value")
        if not isinstance(value, dict) or entry.get("sha256") != digest(value):
            return None
        record = value.get("record") or {}
        if not isinstance(record, dict):
            return None
        audit = record.get("_audit") or {}
        if not isinstance(audit, dict) or not isinstance(audit.get("trial_dir"), str):
            return None
        # Keep original trial artifacts available for the release audit.
        if not audit.get("trial_dir") or not Path(audit["trial_dir"]).is_dir():
            return None
        return copy.deepcopy(value)

    def _put(self, key, task, value):
        self.entries[key] = {"input": digest(execution_files(task)),
                             "sha256": digest(value), "value": copy.deepcopy(value)}
        write_json(self.path, {"protocol": 1, "signature": self.signature, "entries": self.entries})

    def _mark_reused(self, record, revision):
        audit = record.setdefault("_audit", {})
        audit["reuse"] = {"execution_signature": self.signature, "candidate_revision": revision,
                          "source_revision": record.get("candidate_revision")}
        return record

    def get_case(self, key, case, revision):
        value = self._get(key, case.task)
        if value is None:
            return None
        record, verdict = value.get("record", {}), value.get("verdict", {})
        if not isinstance(verdict, dict):
            return None
        if (verdict.get("met") is not True or verdict.get("experiment_id") != case.id
                or record.get("experiment_id") != case.id
                or (case.id != "T12" and (record.get("error_category") or record.get("reward") is None))):
            return None
        try:
            expectation = Expectation(**verdict)
        except TypeError:
            return None
        return self._mark_reused(record, revision), expectation

    def put_case(self, key, case, record, verdict):
        if verdict.met and (case.id == "T12" or (record.get("error_category") is None
                                                 and record.get("reward") is not None)):
            self._put(key, case.task, {"record": record, "verdict": verdict.to_json()})

    def get_seed(self, key, task, revision, seed, variant):
        value = self._get(key, task)
        record = value.get("record", {}) if value else {}
        if seed_succeeded(record) and record.get("seed") == seed and record.get("variant") == variant:
            return self._mark_reused(record, revision)
        return None

    def put_seed(self, key, task, record):
        if seed_succeeded(record):
            self._put(key, task, {"record": record})
