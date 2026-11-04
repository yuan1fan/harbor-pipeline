"""Atomic budget ledger with reservations.

A reservation is checked against committed usage plus all live reservations,
so several workers sharing a ledger cannot collectively overspend.
"""

from __future__ import annotations

import os
import re
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Same liveness rule as job leases: reclaim only when the owner is provably
# gone, because a false "dead" answer would let two runs spend one budget.
from .state import _pid_alive
from .util import PipelineError, file_lock, read_json, write_json

# Ledgers are shared by every worker in a batch. Mutations therefore happen
# under both an in-process lock and an inter-process file lock, and every
# mutation reloads the ledger from disk first so concurrent reservations cannot
# overwrite one another.
_PROCESS_LOCK = threading.RLock()

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

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
    owners: dict[str, dict[str, Any]] = field(default_factory=dict)
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
                owners=dict(data.get("owners", {})),
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
            "owners": self.owners,
            "events": self.events[-500:],
        })

    def _validate(self) -> None:
        unknown = set(self.limits) ^ set(DEFAULT_LIMITS)
        if unknown:
            raise PipelineError(f"Unknown budget keys: {sorted(unknown)}")

    def _mutate(self, action):
        """Lock, reload the on-disk ledger, apply `action`, and return its result."""
        with _PROCESS_LOCK, file_lock(self.path):
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
        # Ledgers written before owners existed have reservations without an
        # owner record; those are never reclaimed automatically.
        self.owners = {
            rid: owner for rid, owner in data.get("owners", {}).items()
            if rid in self.reservations
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
                if self.reservations[rid] == {k: float(v) for k, v in amounts.items()}:
                    return
                # A killed batch leaves its reservations behind. Without this
                # reclaim, re-running the same revision (with a different
                # profile, or after a job timeout) fails as budget_exhausted
                # and the candidate is quarantined as unrepairable.
                if not self._owner_is_stale(rid):
                    raise PipelineError(f"Reservation {rid} exists with different amounts")
                self.reservations.pop(rid, None)
                self.owners.pop(rid, None)
                self.events.append({"op": "reclaim", "id": rid, "reason": "stale owner"})
            self._reserve_unlocked(rid, amounts)

        self._mutate(action)

    def raise_limits(self, limits: dict[str, float]) -> None:
        """Grow the ledger to cover a new batch in a shared run directory.

        A run directory outlives one batch, but the ledger it carries was sized
        by whichever batch created it. Keeping the old, smaller ceiling makes
        every later batch fail as budget_exhausted before it runs anything.
        Limits only ever move up: a batch may add work, never spend a smaller
        envelope that an earlier one was sized for.
        """

        def action() -> None:
            changed = {
                kind: float(amount)
                for kind, amount in limits.items()
                if kind in self.limits and float(amount) > self.limits[kind]
            }
            if not changed:
                return
            self.limits.update(changed)
            self.events.append({"op": "raise_limits", "amounts": changed})
            self._save_unlocked()

        self._mutate(action)

    def reclaim_orphans(self, run_root: Path) -> list[str]:
        """Drop reservations no live job can ever commit.

        A killed or timed-out matrix leaves its reservation behind. Nothing
        will refill it, and because one ledger is shared by every candidate in
        the run directory, the leaked amount slowly starves later batches.
        A reservation is live exactly while its candidate's job lease is held:
        every reserve/commit pair happens inside that lease, so a reservation
        without one can never be committed.
        """
        from .state import Lease

        def action() -> list[str]:
            dropped: list[str] = []
            for rid in list(self.reservations):
                cve = rid.split("-trials-")[0].split("-build-")[0]
                # The id comes from a JSON file on disk, so it is untrusted:
                # never join a path segment that is not a CVE id.
                if not _CVE_ID.fullmatch(cve):
                    self.reservations.pop(rid, None)
                    self.owners.pop(rid, None)
                    self.events.append({"op": "reclaim", "id": rid, "reason": "malformed"})
                    dropped.append(rid)
                    continue
                if Lease(run_root / cve / ".lease", owner="reclaim").is_held():
                    continue
                self.reservations.pop(rid, None)
                self.owners.pop(rid, None)
                self.events.append({"op": "reclaim", "id": rid, "reason": "orphaned"})
                dropped.append(rid)
            if dropped:
                self._save_unlocked()
            return dropped

        return self._mutate(action)

    def _owner_is_stale(self, rid: str) -> bool:
        owner = self.owners.get(rid)
        if not owner:
            return False
        if owner.get("host") != socket.gethostname():
            # Another machine may still be running this reservation.
            return False
        return not _pid_alive(int(owner.get("pid", 0)))

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
        self.owners[rid] = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self.events.append({"op": "reserve", "id": rid, "amounts": amounts})
        self._save_unlocked()

    def commit(self, rid: str, actual: dict[str, float] | None = None) -> None:
        def action() -> None:
            reservation = self.reservations.pop(rid, None)
            self.owners.pop(rid, None)
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
            self.owners.pop(rid, None)
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
