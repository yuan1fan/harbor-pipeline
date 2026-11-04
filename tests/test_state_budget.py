import pytest

from harbor_pipeline.budget import Ledger
from harbor_pipeline.errors import TaskError, error_class
from harbor_pipeline.state import JobStore
from harbor_pipeline.util import PipelineError


def test_state_machine_happy_path(tmp_path):
    store = JobStore(tmp_path, "run-1", "CVE-2024-0001")
    job = store.create()
    assert job.state == "DISCOVERED"
    for target in ["EVIDENCE_READY", "SPEC_FROZEN", "GENERATED", "BUILT", "VALIDATING", "VALIDATED", "RELEASED"]:
        store.transition(job, target)
    assert store.load().state == "RELEASED"
    with pytest.raises(PipelineError):
        store.transition(job, "GENERATED")


def test_illegal_transition_is_rejected(tmp_path):
    store = JobStore(tmp_path, "run-2", "CVE-2024-0001")
    job = store.create()
    with pytest.raises(PipelineError, match="Illegal transition"):
        store.transition(job, "RELEASED")


def test_classified_failure_moves_to_terminal_state(tmp_path):
    store = JobStore(tmp_path, "run-3", "CVE-2024-0001")
    job = store.create()
    store.fail(job, TaskError("evidence_insufficient", "missing fix commit"))
    loaded = store.load()
    assert loaded.state == "QUARANTINED"
    assert loaded.error["category"] == "evidence_insufficient"


def test_unsupported_maps_to_unsupported(tmp_path):
    store = JobStore(tmp_path, "run-4", "CVE-2024-0001")
    job = store.create()
    store.fail(job, TaskError("unsupported", "kernel bug"))
    assert store.load().state == "UNSUPPORTED"


def test_artifact_digest_guard(tmp_path):
    store = JobStore(tmp_path, "run-5", "CVE-2024-0001")
    store.create()
    store.write_artifact("spec.json", {"value": 1})
    assert store.read_artifact("spec.json") == {"value": 1}
    target = store.path("spec.json")
    target.write_text('{"value": 2}', encoding="utf-8")
    with pytest.raises(PipelineError, match="frozen digest"):
        store.read_artifact("spec.json")
    assert store.checkpoint()["valid"] is False


def test_lease_blocks_second_worker(tmp_path):
    store = JobStore(tmp_path, "run-6", "CVE-2024-0001")
    store.create()
    first = store.lease
    first.acquire()
    second = JobStore(tmp_path, "run-6", "CVE-2024-0001").lease
    with pytest.raises(PipelineError, match="leased"):
        second.acquire()
    first.release()
    second.acquire()
    second.release()


def test_budget_reservation_prevents_overspend(tmp_path):
    ledger = Ledger(tmp_path / "ledger.json", limits={"calls": 2, "tokens": 10, "context_bytes": 10, "usd": 1, "wall_sec": 100, "builds": 1, "trials": 2, "disk_bytes": 1000})
    ledger.reserve("r1", {"calls": 1, "tokens": 5})
    with pytest.raises(PipelineError, match="exhausted"):
        ledger.reserve("r2", {"calls": 2})
    ledger.commit("r1", {"calls": 1, "tokens": 4})
    assert ledger.available("calls") == 1
    assert ledger.available("tokens") == 6
    ledger.reserve("r3", {"calls": 1})
    ledger.refund("r3")
    assert ledger.available("calls") == 1


def test_budget_persists(tmp_path):
    path = tmp_path / "ledger.json"
    ledger = Ledger(path, limits={"calls": 3, "tokens": 10, "context_bytes": 10, "usd": 1, "wall_sec": 100, "builds": 1, "trials": 2, "disk_bytes": 1000})
    ledger.charge("calls", 1)
    again = Ledger.load_or_create(path)
    assert again.used["calls"] == 1
    assert again.available("calls") == 2


def _write_ledger_with_reservation(path, *, owners):
    import json

    path.write_text(json.dumps({
        "limits": {},
        "used": {},
        "reservations": {"CVE-2024-0001-trials-3": {"trials": 51}},
        "owners": owners,
        "events": [],
    }), encoding="utf-8")


def test_budget_reclaims_a_reservation_from_a_dead_owner(tmp_path):
    """A killed batch leaves a reservation behind. Re-running the same
    revision with a different profile must reclaim it instead of failing as
    budget_exhausted, which would quarantine the candidate for good."""
    import os
    import socket

    path = tmp_path / "ledger.json"
    _write_ledger_with_reservation(path, owners={
        "CVE-2024-0001-trials-3": {
            "pid": 2**22 + 4242,
            "host": socket.gethostname(),
        },
    })
    ledger = Ledger.load_or_create(path)
    ledger.reserve("CVE-2024-0001-trials-3", {"trials": 17}, reuse=True)
    assert ledger.reservations["CVE-2024-0001-trials-3"] == {"trials": 17.0}
    assert ledger.owners["CVE-2024-0001-trials-3"]["pid"] == os.getpid()
    assert any(event["op"] == "reclaim" for event in ledger.events)


def test_budget_keeps_a_reservation_without_an_owner_record(tmp_path):
    """Ledgers written before owners existed must never be reclaimed
    implicitly: the pipeline cannot prove their owner is gone."""
    path = tmp_path / "ledger.json"
    _write_ledger_with_reservation(path, owners={})
    ledger = Ledger.load_or_create(path)
    with pytest.raises(PipelineError, match="different amounts"):
        ledger.reserve("CVE-2024-0001-trials-3", {"trials": 17}, reuse=True)


def test_budget_reclaims_reservations_without_a_live_lease(tmp_path):
    """A killed matrix leaves a reservation nothing can commit. Only a held
    job lease proves the reservation is still live."""
    import json
    import os
    import time

    run_root = tmp_path / "run"
    (run_root / "CVE-2024-0001").mkdir(parents=True)
    (run_root / "CVE-2024-0001" / ".lease").write_text(json.dumps({
        "owner": "live",
        "expires_at": time.time() + 600,
        "pid": os.getpid(),
    }), encoding="utf-8")
    (run_root / "CVE-2024-0002").mkdir(parents=True)
    ledger = Ledger(tmp_path / "ledger.json")
    ledger.reserve("CVE-2024-0001-trials-3", {"trials": 10})
    ledger.reserve("CVE-2024-0002-trials-3", {"trials": 10})
    ledger.reserve("CVE-2024-0003-trials-1", {"trials": 10})

    dropped = ledger.reclaim_orphans(run_root)
    assert sorted(dropped) == ["CVE-2024-0002-trials-3", "CVE-2024-0003-trials-1"]
    assert list(ledger.reservations) == ["CVE-2024-0001-trials-3"]


def test_budget_limits_only_grow_when_a_run_directory_is_reused(tmp_path):
    ledger = Ledger(tmp_path / "ledger.json", limits={**{
        "calls": 12, "tokens": 180000, "context_bytes": 600000, "usd": 3.0,
        "wall_sec": 3600.0, "builds": 10, "trials": 60, "disk_bytes": 4_000_000_000,
    }, "trials": 10})
    ledger.raise_limits({"trials": 5, "calls": 99})
    assert ledger.limits["trials"] == 10
    assert ledger.limits["calls"] == 99
    again = Ledger.load_or_create(tmp_path / "ledger.json")
    assert again.limits["calls"] == 99


def test_error_taxonomy_is_complete():
    for code in [
        "source_error", "evidence_insufficient", "generation_error", "build_error",
        "infra_error", "oracle_failure", "attribution_failure", "grader_failure",
        "budget_exhausted", "unsupported",
    ]:
        assert error_class(code).code == code
    with pytest.raises(PipelineError):
        error_class("nope")


def test_lease_reclaims_a_dead_owner(tmp_path):
    import json
    import os

    from harbor_pipeline.state import Lease

    path = tmp_path / ".lease"
    path.write_text(json.dumps({
        "owner": "dead-owner",
        "expires_at": 1e12,
        "pid": 2**22 + 12345,
    }), encoding="utf-8")

    lease = Lease(path, owner="new-owner")
    lease.acquire()
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["owner"] == "new-owner"
        assert record["pid"] == os.getpid()
    finally:
        lease.release()


def test_pid_alive_keeps_a_lease_when_access_is_denied(monkeypatch):
    import ctypes
    import os

    from harbor_pipeline import state

    if os.name != "nt":
        pytest.skip("OpenProcess liveness check is Windows-only")

    class FakeKernel32:
        def OpenProcess(self, *_args):
            return 0

    # ERROR_ACCESS_DENIED means the process exists but cannot be queried.
    # Reclaiming its lease here would let two runs write one job directory.
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5)
    assert state._pid_alive(1234) is True


def test_lease_refuses_a_live_owner(tmp_path):
    import json
    import os

    from harbor_pipeline.state import Lease

    path = tmp_path / ".lease"
    path.write_text(json.dumps({
        "owner": "live-owner",
        "expires_at": 1e12,
        "pid": os.getpid(),
    }), encoding="utf-8")

    with pytest.raises(PipelineError, match="leased by live-owner"):
        Lease(path, owner="new-owner").acquire()
