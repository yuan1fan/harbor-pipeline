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


def test_error_taxonomy_is_complete():
    for code in [
        "source_error", "evidence_insufficient", "generation_error", "build_error",
        "infra_error", "oracle_failure", "attribution_failure", "grader_failure",
        "budget_exhausted", "unsupported",
    ]:
        assert error_class(code).code == code
    with pytest.raises(PipelineError):
        error_class("nope")
