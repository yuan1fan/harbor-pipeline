"""Regression for a successful submission following an exploratory decline."""

import shutil
from types import SimpleNamespace

import pytest

from harbor_pipeline import authoring, author_tool
from harbor_pipeline.agent import AgentOutcome
from harbor_pipeline.errors import TaskError
from harbor_pipeline.util import digest, read_json, write_json

from test_auto_synthesis import CVE, _discovery
from test_authoring import _run_dir, _write_author_files
from test_pipeline_authoring import _pipeline


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    pipeline = _pipeline(tmp_path)
    run_dir, evidence = _run_dir(tmp_path)
    shutil.copytree(run_dir / "evidence", pipeline.store.root / "evidence")
    pipeline.store.write_artifact("evidence-index.json", evidence)
    pipeline.store.write_artifact("discovery.json", _discovery().to_json())
    pipeline.store.transition(pipeline.store.load(), "EVIDENCE_READY", "test evidence")
    pipeline.discovery = _discovery()
    workspace = authoring.prepare_workspace(
        run_dir=pipeline.store.root,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="test",
    )
    _write_author_files(workspace.root)
    monkeypatch.setattr("harbor_pipeline.depcheck.check_bundle", lambda *args: [])
    return pipeline, workspace


def write_legacy_decisions(workspace, *, declined_at="2026-11-08T22:35:05+00:00"):
    write_json(workspace.declined_path, {
        "status": "declined", "reason": "test", "declined_at": declined_at,
    })
    write_json(workspace.submission_path, {
        "status": "submitted",
        "submitted_at": "2026-11-08T23:07:22+00:00",
        "bundle_digest": digest(authoring.assemble_bundle(workspace.root)),
        "probe": {"ok": True},
    })


def test_later_successful_submission_survives_old_decline(prepared):
    pipeline, workspace = prepared
    write_legacy_decisions(workspace)

    result = pipeline._consume_author_workspace(
        workspace, AgentOutcome(status="completed", session_id="historical-session")
    )

    assert result.author_status == "submitted"
    assert pipeline.store.read_artifact("synthesis.json")["session_id"] == "historical-session"
    # Consuming historical records must not rewrite their evidence.
    assert read_json(workspace.declined_path)["reason"] == "test"


def test_later_decline_supersedes_old_submission(prepared):
    pipeline, workspace = prepared
    write_legacy_decisions(workspace, declined_at="2026-11-08T23:08:00+00:00")

    with pytest.raises(TaskError) as caught:
        pipeline._consume_author_workspace(workspace, AgentOutcome(status="completed"))

    assert caught.value.category.code == "unsupported"
    assert not pipeline.store.path("synthesis.json").exists()


def test_later_submission_still_requires_unchanged_contents(prepared):
    pipeline, workspace = prepared
    write_legacy_decisions(workspace)
    (workspace.root / "target" / "app.py").write_text("print('changed')\n", encoding="utf-8")

    with pytest.raises(TaskError, match="digest") as caught:
        pipeline._consume_author_workspace(workspace, AgentOutcome(status="completed"))

    assert caught.value.category.code == "generation_error"


@pytest.mark.parametrize("declined_at", ["invalid", "2026-11-08T23:07:22+00:00"])
def test_ambiguous_legacy_decisions_require_a_new_decision(prepared, declined_at):
    pipeline, workspace = prepared
    write_legacy_decisions(workspace, declined_at=declined_at)

    with pytest.raises(TaskError, match="Conflicting author decisions") as caught:
        pipeline._consume_author_workspace(workspace, AgentOutcome(status="completed"))

    assert caught.value.category.code == "generation_error"


def submission_context(tmp_path, monkeypatch, *, probe_ok):
    ctx = SimpleNamespace(
        workspace=tmp_path / "author", run_dir=tmp_path, cve_id=CVE,
        revision=1, evidence={}, discovery=None, config=None,
    )
    bundle = {"target": "validated fixture"}
    monkeypatch.setattr(author_tool, "validate_workspace", lambda **kwargs: (bundle, [], []))
    monkeypatch.setattr(author_tool, "_spec_for", lambda *args: {"frozen_digest": "a" * 64})
    monkeypatch.setattr(author_tool, "assemble_bundle", lambda *args: bundle)
    write_json(ctx.workspace / authoring.PROBE_STATE_FILE, {
        "bundle_digest": digest(bundle), "alternate": False, "ok": probe_ok,
        "status": "goal_passed" if probe_ok else "oracle_failure",
        "fixed_status": "fixed_variant_holds",
    })
    return ctx


def test_successful_decisions_replace_the_opposite_marker(tmp_path, monkeypatch):
    ctx = submission_context(tmp_path, monkeypatch, probe_ok=True)
    assert author_tool.cmd_decline(ctx, "exploratory decline") == 0
    assert author_tool.cmd_submit(ctx) == 0
    assert (ctx.workspace / authoring.SUBMISSION_FILE).is_file()
    assert not (ctx.workspace / authoring.DECLINED_FILE).exists()

    assert author_tool.cmd_decline(ctx, "new finding invalidates submission") == 0
    assert not (ctx.workspace / authoring.SUBMISSION_FILE).exists()
    assert read_json(ctx.workspace / authoring.DECLINED_FILE)["reason"] == "new finding invalidates submission"


def test_failed_submission_preserves_the_decline(tmp_path, monkeypatch):
    ctx = submission_context(tmp_path, monkeypatch, probe_ok=False)
    assert author_tool.cmd_decline(ctx, "not validated yet") == 0

    assert author_tool.cmd_submit(ctx) == 1
    assert read_json(ctx.workspace / authoring.DECLINED_FILE)["reason"] == "not validated yet"
    assert not (ctx.workspace / authoring.SUBMISSION_FILE).exists()
