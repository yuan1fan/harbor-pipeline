"""Atomic budget ledger with reservations.

A reservation is checked against committed usage plus all live reservations,
so several workers sharing a ledger cannot collectively overspend.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import PipelineError, read_json, write_json

# Ledgers are shared by every worker in a batch. Mutations therefore happen
# under both an in-process lock and an inter-process file lock, and every
# mutation reloads the ledger from disk first so concurrent reservations cannot
# overwrite one another.
_PROCESS_LOCK = threading.RLock()
_LOCK_TIMEOUT_SEC = 60.0


@contextmanager
def _file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    deadline = time.time() + _LOCK_TIMEOUT_SEC
    with open(lock_path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise PipelineError(f"Timed out waiting for budget lock {lock_path}")
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

DEFAULT_LIMITS: dict[str, float] = {
    "calls": 12,
    "tokens": 180000,
    "context_bytes": 600000,
    "usd": 3.0,
    "wall_sec": 3600.0,
    "builds": 10,
    "trials": 60,
    "disk_bytes": 4_000_000_000,
}


@dataclass
class Ledger:
    path: Path
    limits: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    used: dict[str, float] = field(default_factory=dict)
    reservations: dict[str, dict[str, float]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.limits = {k: float(v) for k, v in self.limits.items()}
        for key in self.limits:
            self.used.setdefault(key, 0.0)

    # -- persistence -------------------------------------------------------

    @classmethod
    def load_or_create(cls, path: Path, limits: dict[str, float] | None = None) -> "Ledger":
        if path.is_file():
            data = read_json(path)
            ledger = cls(
                path=path,
                limits={**DEFAULT_LIMITS, **data.get("limits", {})},
                used=dict(data.get("used", {})),
                reservations=dict(data.get("reservations", {})),
                events=list(data.get("events", [])),
            )
            ledger._validate()
            return ledger
        return cls(path=path, limits={**DEFAULT_LIMITS, **(limits or {})})

    def save(self) -> None:
        self._mutate(self._save_unlocked)

    def _save_unlocked(self) -> None:
        write_json(self.path, {
            "limits": self.limits,
            "used": self.used,
            "reservations": self.reservations,
            "events": self.events[-500:],
        })

    def _validate(self) -> None:
        unknown = set(self.limits) ^ set(DEFAULT_LIMITS)
        if unknown:
            raise PipelineError(f"Unknown budget keys: {sorted(unknown)}")

    def _mutate(self, action):
        """Lock, reload the on-disk ledger, apply `action`, and return its result."""
        with _PROCESS_LOCK, _file_lock(self.path):
            self._reload()
            return action()

    def _reload(self) -> None:
        if not self.path.is_file():
            return
        data = read_json(self.path)
        self.limits = {**DEFAULT_LIMITS, **data.get("limits", {})}
        self.used = {k: float(v) for k, v in data.get("used", {}).items()}
        self.reservations = {
            rid: {k: float(v) for k, v in amounts.items()}
            for rid, amounts in data.get("reservations", {}).items()
        }
        self.events = list(data.get("events", []))

    # -- control -----------------------------------------------------------

    def _reserved_for(self, kind: str, exclude: str | None = None) -> float:
        return sum(
            r.get(kind, 0.0)
            for rid, r in self.reservations.items()
            if rid != exclude
        )

    def available(self, kind: str) -> float:
        return self._mutate(lambda: self._available_unlocked(kind))

    def _available_unlocked(self, kind: str) -> float:
        return self.limits[kind] - self.used.get(kind, 0.0) - self._reserved_for(kind)

    def reserve(self, rid: str, amounts: dict[str, float], *, reuse: bool = False) -> None:
        def action() -> None:
            if rid in self.reservations:
                if not reuse:
                    raise PipelineError(f"Duplicate reservation {rid}")
                if self.reservations[rid] != {k: float(v) for k, v in amounts.items()}:
                    raise PipelineError(f"Reservation {rid} exists with different amounts")
                return
            self._reserve_unlocked(rid, amounts)

        self._mutate(action)

    def _reserve_unlocked(self, rid: str, amounts: dict[str, float]) -> None:
        for kind, amount in amounts.items():
            if kind not in self.limits:
                raise PipelineError(f"Unknown budget kind: {kind}")
            if amount < 0:
                raise PipelineError("Reservation amounts must be nonnegative")
            if amount > self._available_unlocked(kind):
                raise PipelineError(
                    f"Budget exhausted for {kind}: requested {amount}, "
                    f"available {self._available_unlocked(kind):.2f}"
                )
        self.reservations[rid] = {k: float(v) for k, v in amounts.items()}
        self.events.append({"op": "reserve", "id": rid, "amounts": amounts})
        self._save_unlocked()

    def commit(self, rid: str, actual: dict[str, float] | None = None) -> None:
        def action() -> None:
            reservation = self.reservations.pop(rid, None)
            if reservation is None:
                raise PipelineError(f"Unknown reservation {rid}")
            charges = reservation if actual is None else {**reservation, **actual}
            for kind, amount in charges.items():
                if kind not in self.limits:
                    raise PipelineError(f"Unknown budget kind: {kind}")
                extra = float(amount) - float(reservation.get(kind, 0.0))
                if extra > 0 and extra > self._available_unlocked(kind):
                    raise PipelineError(
                        f"Budget exhausted for {kind}: actual usage exceeds the reservation"
                    )
                self.used[kind] = self.used.get(kind, 0.0) + float(amount)
            self.events.append({"op": "commit", "id": rid, "amounts": charges})
            self._save_unlocked()

        self._mutate(action)

    def refund(self, rid: str) -> None:
        def action() -> None:
            if self.reservations.pop(rid, None) is None:
                raise PipelineError(f"Unknown reservation {rid}")
            self.events.append({"op": "refund", "id": rid})
            self._save_unlocked()

        self._mutate(action)

    def charge(self, kind: str, amount: float) -> None:
        """Immediate charge for work that cannot be pre-reserved."""

        def action() -> None:
            if kind not in self.limits:
                raise PipelineError(f"Unknown budget kind: {kind}")
            if amount > self._available_unlocked(kind):
                raise PipelineError(f"Budget exhausted for {kind}")
            self.used[kind] = self.used.get(kind, 0.0) + float(amount)
            self.events.append({"op": "charge", "kind": kind, "amount": amount})
            self._save_unlocked()

        self._mutate(action)

    def snapshot(self) -> dict[str, Any]:
        return self._mutate(self._snapshot_unlocked)

    def _snapshot_unlocked(self) -> dict[str, Any]:
        return {
            "limits": dict(self.limits),
            "used": dict(self.used),
            "reserved": {
                kind: self._reserved_for(kind) for kind in self.limits
            },
            "remaining": {
                kind: self.limits[kind] - self.used.get(kind, 0.0) - self._reserved_for(kind)
                for kind in self.limits
            },
        }
