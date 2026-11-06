"""Job state machine, atomic checkpoints, and a recoverable per-job lease."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import TaskError
from .util import PipelineError, child_path, digest, read_json, write_json

STATES: tuple[str, ...] = (
    "DISCOVERED",
    "EVIDENCE_READY",
    "SPEC_FROZEN",
    "GENERATED",
    "BUILT",
    "VALIDATING",
    "VALIDATED",
    "RELEASED",
    "REPAIRING",
    "QUARANTINED",
    "UNSUPPORTED",
)

TRANSITIONS: dict[str, frozenset[str]] = {
    "DISCOVERED": frozenset({"EVIDENCE_READY", "QUARANTINED", "UNSUPPORTED"}),
    "EVIDENCE_READY": frozenset({"SPEC_FROZEN", "QUARANTINED", "UNSUPPORTED", "REPAIRING"}),
    "SPEC_FROZEN": frozenset({"GENERATED", "QUARANTINED", "UNSUPPORTED"}),
    "GENERATED": frozenset({"BUILT", "QUARANTINED", "REPAIRING"}),
    "BUILT": frozenset({"VALIDATING", "QUARANTINED", "REPAIRING"}),
    "VALIDATING": frozenset({"VALIDATED", "QUARANTINED", "REPAIRING"}),
    "VALIDATED": frozenset({"RELEASED", "QUARANTINED", "REPAIRING"}),
    "RELEASED": frozenset(),
    "REPAIRING": frozenset({"GENERATED", "QUARANTINED"}),
    "QUARANTINED": frozenset({"REPAIRING", "VALIDATED"}),
    "UNSUPPORTED": frozenset(),
}

TERMINAL_STATES = frozenset({"RELEASED", "QUARANTINED", "UNSUPPORTED"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"


@dataclass
class Job:
    run_id: str
    cve_id: str
    state: str
    revision: int = 1
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    attempts: dict[str, int] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    error: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "cve_id": self.cve_id,
            "state": self.state,
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "attempts": dict(self.attempts),
            "artifacts": dict(self.artifacts),
            "history": list(self.history),
            "error": self.error,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_json(cls, data: dict) -> "Job":
        job = cls(
            run_id=data["run_id"],
            cve_id=data["cve_id"],
            state=data["state"],
            revision=int(data.get("revision", 1)),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
            attempts=dict(data.get("attempts", {})),
            artifacts=dict(data.get("artifacts", {})),
            history=list(data.get("history", [])),
            error=data.get("error"),
            metadata=dict(data.get("metadata", {})),
        )
        if job.state not in STATES:
            raise PipelineError(f"Job has unknown state {job.state!r}")
        return job


def _pid_alive(pid: int) -> bool:
    """Best-effort liveness check used to reclaim a dead process's lease.

    ``os.kill(pid, 0)`` would terminate the target on Windows, so that path
    uses OpenProcess. When the check cannot be performed, the caller keeps the
    lease: a false "dead" answer would let two runs write one job directory.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        error_invalid_parameter = 87
        # use_last_error keeps the error from OpenProcess from being clobbered
        # by ctypes' own Win32 calls.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            # A nonexistent pid yields ERROR_INVALID_PARAMETER. Access denied
            # means the process exists but the handle cannot be queried; that
            # must count as alive or two runs could share one job directory.
            return ctypes.get_last_error() != error_invalid_parameter
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


class Lease:
    """A simple exclusive file lease with an expiry, safe across processes."""

    def __init__(self, path: Path, owner: str, lease_sec: int = 3600):
        self.path = path
        self.owner = owner
        self.lease_sec = lease_sec

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.lease_sec
        record = {"owner": self.owner, "expires_at": deadline, "pid": os.getpid()}
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                existing = self._read()
                expired = bool(existing) and existing.get("expires_at", 0) < time.time()
                # A killed worker leaves a lease that is otherwise valid for an
                # hour. Reclaiming it keeps batch resume prompt, but only when
                # the recorded process is provably gone.
                dead = (
                    bool(existing)
                    and existing.get("pid") is not None
                    and not _pid_alive(int(existing.get("pid") or 0))
                )
                if expired or dead:
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise PipelineError(
                    f"Job is leased by {existing.get('owner') if existing else 'unknown'}"
                )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record))
            return

    def renew(self) -> None:
        if not self.path.exists():
            raise PipelineError("Lease was lost; refusing to continue")
        existing = self._read()
        if existing.get("owner") != self.owner:
            raise PipelineError("Lease is owned by another worker")
        write_json(self.path, {
            "owner": self.owner,
            "expires_at": time.time() + self.lease_sec,
            "pid": os.getpid(),
        })

    def release(self) -> None:
        try:
            existing = self._read()
            if existing.get("owner") == self.owner:
                self.path.unlink()
        except FileNotFoundError:
            pass

    def is_held(self) -> bool:
        """True when a live, unexpired owner still holds this lease.

        Used to decide whether a budget reservation belongs to work that may
        still commit; reading the file is not enough, because a killed worker
        leaves one behind until its expiry.
        """
        existing = self._read()
        if not existing:
            return False
        if existing.get("expires_at", 0) < time.time():
            return False
        pid = existing.get("pid")
        return pid is None or _pid_alive(int(pid))

    def _read(self) -> dict:
        try:
            return read_json(self.path)
        except (OSError, ValueError):
            return {}

    def __enter__(self) -> "Lease":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()


class JobStore:
    """Owns runs/<run-id>/<cve-id>/ and every atomic checkpoint within it."""

    def __init__(self, root: Path, run_id: str, cve_id: str):
        if not str(cve_id).startswith("CVE-"):
            raise PipelineError(f"Invalid CVE id: {cve_id!r}")
        if "/" in run_id or "\\" in run_id or ":" in run_id or run_id in {".", ".."}:
            raise PipelineError(f"Invalid run id: {run_id!r}")
        self.root = child_path(root, run_id) / cve_id
        self.state_path = self.root / "state.json"
        self.lease = Lease(
            self.root / ".lease",
            owner=f"{os.getpid()}-{uuid.uuid4().hex[:8]}",
            lease_sec=3600,
        )

    # -- lifecycle ---------------------------------------------------------

    def create(self) -> Job:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            return self.load()
        job = Job(run_id=self.root.parent.name, cve_id=self.root.name, state="DISCOVERED")
        job.history.append({"at": job.created_at, "from": None, "to": "DISCOVERED", "note": "created"})
        self.save(job)
        return job

    def load(self) -> Job:
        if not self.state_path.is_file():
            raise PipelineError(f"No job state at {self.state_path}")
        return Job.from_json(read_json(self.state_path))

    def save(self, job: Job) -> None:
        job.updated_at = utc_now()
        write_json(self.state_path, job.to_json())

    def transition(self, job: Job, to_state: str, note: str = "", outputs: dict[str, str] | None = None) -> Job:
        if to_state not in STATES:
            raise PipelineError(f"Unknown state: {to_state!r}")
        allowed = TRANSITIONS.get(job.state, frozenset())
        if to_state not in allowed:
            raise PipelineError(f"Illegal transition {job.state} -> {to_state}")
        previous = job.state
        job.state = to_state
        # A successful transition supersedes any earlier failure; the history
        # below still records what happened.
        job.error = None
        job.updated_at = utc_now()
        job.history.append({"at": job.updated_at, "from": previous, "to": to_state, "note": note})
        if outputs:
            job.artifacts.update(outputs)
        if to_state in {"QUARANTINED", "UNSUPPORTED"}:
            job.metadata.pop("pending_error", None)
        self.save(job)
        return job

    def fail(self, job: Job, error: TaskError, note: str = "") -> Job:
        job.error = error.as_record()
        job.history.append({
            "at": utc_now(),
            "from": job.state,
            "to": error.category.terminal_state,
            "note": note or error.category.code,
            "error": error.as_record(),
        })
        job.state = error.category.terminal_state
        job.updated_at = utc_now()
        self.save(job)
        return job

    # -- artifacts ---------------------------------------------------------

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def write_artifact(self, name: str, value: Any) -> Path:
        """Write a JSON artifact and record its digest on the job."""
        target = child_path(self.root, name)
        write_json(target, value)
        job = self.load()
        job.artifacts[name] = digest(value)
        self.save(job)
        return target

    def read_artifact(self, name: str) -> Any:
        job = self.load()
        target = child_path(self.root, name)
        if not target.is_file():
            raise PipelineError(f"Missing artifact {name}")
        value = read_json(target)
        if name in job.artifacts and digest(value) != job.artifacts[name]:
            raise PipelineError(f"Artifact {name} no longer matches its frozen digest")
        return value

    def checkpoint(self) -> dict[str, Any]:
        """Return the state plus digests of every recorded artifact."""
        job = self.load()
        present = {}
        for name, recorded in job.artifacts.items():
            target = child_path(self.root, name)
            if not target.is_file():
                present[name] = None
                continue
            try:
                actual = digest(read_json(target))
            except (OSError, ValueError):
                actual = None
            present[name] = actual if actual == recorded else "__changed__"
        return {
            "state": job.state,
            "revision": job.revision,
            "artifacts": present,
            "valid": all(v == job.artifacts[k] for k, v in present.items() if v is not None),
        }

    def resume(self) -> Job:
        """Load a job and verify the last checkpoint is still consistent."""
        job = self.load()
        check = self.checkpoint()
        if not check["valid"]:
            broken = [k for k, v in check["artifacts"].items() if v not in (job.artifacts.get(k), None)]
            raise PipelineError(
                f"Checkpoint is stale for {', '.join(broken)}; the candidate must be rebuilt"
            )
        return job
