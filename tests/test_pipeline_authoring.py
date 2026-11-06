"""Pipeline integration points for the native authoring path."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from harbor_pipeline import authoring
from harbor_pipeline.agent import AgentOutcome
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.synthesis import Synthesis
from harbor_pipeline.util import digest

from test_auto_synthesis import CVE, _bundle, _discovery
from test_authoring import _run_dir, _write_author_files, _config


def _pipeline(tmp_path: Path) -> CvePipeline:
    config = _config()
    config.pipeline.output_dir = str(tmp_path / "runs")
    pipeline = CvePipeline(
        config=config,
        cve_id=CVE,
        run_id="author-test",
        scenario="auto",
        output_root=tmp_path / "runs",
    )
    pipeline.store.create()
    return pipeline


def test_consume_author_workspace_writes_synthesis(tmp_path: Path, monkeypatch):
    pipeline = _pipeline(tmp_path)
    run_dir, evidence = _run_dir(tmp_path)
    shutil.copytree(run_dir / "evidence", pipeline.store.root / "evidence")
    pipeline.store.write_artifact("evidence-index.json", evidence)
    pipeline.store.write_artifact("discovery.json", _discovery().to_json())
    pipeline.store.transition(
        pipeline.store.load(), "EVIDENCE_READY", "test evidence"
    )
    pipeline.discovery = _discovery()
    workspace = authoring.prepare_workspace(
        run_dir=pipeline.store.root,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="deepseek-flash[1m]",
    )
    _write_author_files(workspace.root)
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )
    raw = authoring.assemble_bundle(workspace.root)
    (workspace.root / "submission.json").write_text(
        json.dumps(
            {
                "status": "submitted",
                "bundle_digest": digest(raw),
                "probe": {"ok": True},
            }
        ),
        encoding="utf-8",
    )
    outcome = AgentOutcome(
        status="completed",
        session_id="session-1",
        turns=7,
        usage={"input_tokens": 100, "output_tokens": 20},
        usd=0.1,
    )
    synthesis = pipeline._consume_author_workspace(workspace, outcome)
    assert synthesis.session_id == "session-1"
    assert synthesis.turns == 7
    assert synthesis.author_status == "submitted"
    assert pipeline.store.path("synthesis.json").is_file()
    assert pipeline.store.read_artifact("synthesis.json")["session_id"] == "session-1"


def test_consume_author_workspace_rejects_a_stale_submission(tmp_path: Path, monkeypatch):
    pipeline = _pipeline(tmp_path)
    run_dir, evidence = _run_dir(tmp_path)
    shutil.copytree(run_dir / "evidence", pipeline.store.root / "evidence")
    pipeline.store.write_artifact("evidence-index.json", evidence)
    pipeline.store.write_artifact("discovery.json", _discovery().to_json())
    pipeline.store.transition(
        pipeline.store.load(), "EVIDENCE_READY", "test evidence"
    )
    pipeline.discovery = _discovery()
    workspace = authoring.prepare_workspace(
        run_dir=pipeline.store.root,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="m",
    )
    _write_author_files(workspace.root)
    (workspace.root / "submission.json").write_text(
        json.dumps({"status": "submitted", "bundle_digest": "0" * 64}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )
    try:
        pipeline._consume_author_workspace(workspace, AgentOutcome(status="completed"))
    except Exception as exc:
        assert "digest" in str(exc)
    else:  # pragma: no cover - the assertion is the contract
        raise AssertionError("a stale submission was accepted")


def test_draft_runs_the_native_author_and_renders(tmp_path: Path, monkeypatch):
    pipeline = _pipeline(tmp_path)
    run_dir, evidence = _run_dir(tmp_path)
    shutil.copytree(run_dir / "evidence", pipeline.store.root / "evidence")
    pipeline.store.write_artifact("evidence-index.json", evidence)
    pipeline.store.write_artifact("discovery.json", _discovery().to_json())
    pipeline.store.transition(
        pipeline.store.load(), "EVIDENCE_READY", "test evidence"
    )
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )

    def fake_run(self, *, prompt, workspace, contract, settings_path, extra_env=None, resume=None):
        _write_author_files(Path(workspace))
        raw = authoring.assemble_bundle(Path(workspace))
        (Path(workspace) / "submission.json").write_text(
            json.dumps({"status": "submitted", "bundle_digest": digest(raw)}),
            encoding="utf-8",
        )
        return AgentOutcome(
            status="completed", session_id="session-native", turns=5, usd=0.2
        )

    monkeypatch.setattr("harbor_pipeline.pipeline.ClaudeCodeAgent.run", fake_run)
    synthesis = pipeline.draft(evidence)
    assert synthesis.session_id == "session-native"
    assert synthesis.bundle["task_goal"]["family"] == "secret_read"
    spec = pipeline.freeze(evidence)
    assert spec["cve_id"] == CVE
    task, task_dir = pipeline.generate(spec)
    assert task_dir.is_dir()
    assert "instruction.md" in task.files
    assert "tests/verify.py" in task.files
    assert pipeline.store.read_artifact("synthesis.json")["session_id"] == "session-native"


def test_freeze_recomputes_when_the_author_changes_the_bundle(tmp_path: Path):
    pipeline = _pipeline(tmp_path)
    run_dir, evidence = _run_dir(tmp_path)
    pipeline.store.write_artifact("evidence-index.json", evidence)
    pipeline.store.write_artifact("discovery.json", _discovery().to_json())
    pipeline.store.transition(
        pipeline.store.load(), "EVIDENCE_READY", "test evidence"
    )
    pipeline.discovery = _discovery()

    first = _bundle()
    first["task_goal"]["family"] = "secret_read"
    first["preconditions"]["auth_scheme"] = "none"
    pipeline.synthesis = Synthesis(
        cve_id=CVE,
        bundle=first,
        model_identity="test",
        usage={},
        prompt_sha256="",
        generated_at="2026-01-01T00:00:00+00:00",
        digest=digest(first),
    )
    spec = pipeline.freeze(evidence)
    assert spec["root_cause"]["summary"].startswith("NUL bytes")

    second = _bundle()
    second["root_cause"]["summary"] = "A second, corrected root cause."
    second["task_goal"]["family"] = "secret_read"
    second["preconditions"]["auth_scheme"] = "none"
    pipeline.synthesis = Synthesis(
        cve_id=CVE,
        bundle=second,
        model_identity="test",
        usage={},
        prompt_sha256="",
        generated_at="2026-01-01T00:00:01+00:00",
        digest=digest(second),
    )
    refreshed = pipeline.freeze(evidence)
    assert refreshed["root_cause"]["summary"] == "A second, corrected root cause."
    assert refreshed["frozen_digest"] != spec["frozen_digest"]
