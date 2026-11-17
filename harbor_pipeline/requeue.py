"""Controlled requeue of a terminal candidate after evidence resolution.

``UNSUPPORTED`` is a terminal state. The evidence resolver can fill a missing
version pair, but it must not silently mutate the old run: that would destroy
the audit trail and rewrite historical yield statistics. This module copies
the resolved evidence into a fresh run whose state starts at
``EVIDENCE_READY``. The old run remains untouched.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import depcheck, evidence_resolver
from .config import Config
from .discovery import Discovery
from .state import JobStore
from .util import PipelineError, digest, read_json, utc_now_text, write_json


@dataclass(frozen=True)
class RequeueResult:
    cve_id: str
    source_run_dir: Path
    new_run_id: str
    new_run_dir: Path
    state: str
    proposal_digest: str
    evidence_sources: int

    def to_json(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "source_run_dir": str(self.source_run_dir),
            "new_run_id": self.new_run_id,
            "new_run_dir": str(self.new_run_dir),
            "state": self.state,
            "proposal_digest": self.proposal_digest,
            "evidence_sources": self.evidence_sources,
        }


def _resolver_payload(source_run_dir: Path) -> tuple[str, dict[str, Any]]:
    path = source_run_dir / "resolver-result.json"
    if not path.is_file():
        # Earlier resolver replays wrote the validated proposal as
        # reconciliation.json but did not yet persist resolver-result.json.
        # Accept that artifact only when the proposal itself says proposed.
        fallback = source_run_dir / "reconciliation.json"
        if fallback.is_file():
            proposal = read_json(fallback)
            if not isinstance(proposal, dict):
                raise PipelineError("reconciliation.json must be an object")
            return str(proposal.get("status") or ""), proposal
        raise PipelineError(f"missing resolver-result.json under {source_run_dir}")
    data = read_json(path)
    if not isinstance(data, dict):
        raise PipelineError("resolver-result.json must be an object")
    # The pipeline writes ResolverOutcome directly; the standalone CLI writes
    # a wrapper with cve_id/run_dir/resolver. Accept both so replay artifacts
    # and pipeline checkpoints use the same requeue path.
    if isinstance(data.get("resolver"), dict):
        outcome = data["resolver"]
    else:
        outcome = data
    status = str(outcome.get("status") or "")
    proposal = outcome.get("proposal")
    if status != "proposed" or not isinstance(proposal, dict):
        raise PipelineError(
            f"resolver did not produce a proposed result (status={status!r})"
        )
    return status, proposal


def _check_discovery_pair(discovery: Discovery, evidence: dict, config: Config) -> None:
    missing = [
        name
        for name in ("vulnerable_ref", "fixed_ref", "fix_commit", "fix_source_id")
        if not getattr(discovery, name)
    ]
    if missing:
        raise PipelineError(f"discovery is missing {', '.join(missing)}")
    if discovery.vulnerable_ref == discovery.fixed_ref:
        raise PipelineError("vulnerable_ref and fixed_ref must differ")
    bundle = {
        "product": {
            "name": discovery.build_package or "",
            "ecosystem": discovery.build_ecosystem or "",
            "component": discovery.component or "",
        },
        "versions": {
            "vulnerable_ref": discovery.vulnerable_ref,
            "fixed_ref": discovery.fixed_ref,
        },
        "target": {
            "base_image": config.pipeline.python_image,
            "files": {},
        },
    }
    issues = depcheck.check_bundle(bundle, config.sources)
    if issues:
        raise PipelineError("; ".join(issues))


def requeue_resolved(
    *,
    source_run_dir: Path,
    cve_id: str,
    output_root: Path,
    new_run_id: str,
    config: Config,
) -> RequeueResult:
    """Copy a resolved, terminal candidate into a fresh EVIDENCE_READY run."""
    source_run_dir = Path(source_run_dir).resolve()
    state_path = source_run_dir / "state.json"
    if not state_path.is_file():
        raise PipelineError(f"missing state.json under {source_run_dir}")
    source_state = read_json(state_path)
    if source_state.get("state") != "UNSUPPORTED":
        raise PipelineError(
            "requeue-resolved only accepts an UNSUPPORTED source run; "
            f"got {source_state.get('state')!r}"
        )

    status, proposal = _resolver_payload(source_run_dir)
    evidence = read_json(source_run_dir / "evidence-index.json")
    discovery = Discovery.from_json(read_json(source_run_dir / "discovery.json"))
    if discovery.cve_id != cve_id:
        raise PipelineError("discovery cve_id does not match --cve")
    issues = evidence_resolver.validate_proposal(
        proposal,
        evidence=evidence,
        cve_id=cve_id,
        run_dir=source_run_dir,
    )
    if issues:
        raise PipelineError("; ".join(issues))
    _check_discovery_pair(discovery, evidence, config)

    output_root = Path(output_root).resolve()
    store = JobStore(output_root, new_run_id, cve_id)
    if store.root.exists():
        raise PipelineError(f"new run already exists: {store.root}")

    evidence_src = source_run_dir / "evidence"
    if not evidence_src.is_dir():
        raise PipelineError(f"missing evidence directory under {source_run_dir}")
    store.root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(evidence_src, store.root / "evidence")
    for name in (
        "evidence-index.json",
        "discovery.json",
        "resolver-result.json",
        "resolver-session.json",
        "reconciliation.json",
    ):
        source = source_run_dir / name
        if source.is_file():
            (store.root / name).write_bytes(source.read_bytes())

    job = store.create()
    job.metadata.update(
        {
            "requeued_from": str(source_run_dir),
            "requeued_from_state": str(source_state.get("state")),
            "requeued_at": utc_now_text(),
        }
    )
    store.save(job)
    job = store.transition(
        job,
        "EVIDENCE_READY",
        "requeued after evidence resolver",
    )
    requeue_record = {
        "cve_id": cve_id,
        "source_run_dir": str(source_run_dir),
        "source_state": str(source_state.get("state")),
        "resolver_status": status,
        "proposal": proposal,
        "proposal_digest": digest(proposal),
        "evidence_digest": digest(evidence),
        "new_run_id": new_run_id,
        "requeued_at": utc_now_text(),
    }
    write_json(store.root / "requeue.json", requeue_record)
    job = store.load()
    job.artifacts["requeue.json"] = digest(requeue_record)
    store.save(job)
    return RequeueResult(
        cve_id=cve_id,
        source_run_dir=source_run_dir,
        new_run_id=new_run_id,
        new_run_dir=store.root,
        state=job.state,
        proposal_digest=requeue_record["proposal_digest"],
        evidence_sources=len(evidence.get("sources", [])),
    )
