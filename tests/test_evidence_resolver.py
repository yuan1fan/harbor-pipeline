import argparse
import json
from pathlib import Path
from harbor_pipeline import evidence_resolver, evidence_tool
from harbor_pipeline.config import Config, ModelSettings, Settings, SourceSettings
from harbor_pipeline.discovery import Discovery
from harbor_pipeline.sources import FetchResult
from harbor_pipeline.util import read_json, write_json


def _source(source_id="src-1-upstream-commit", status="ok", source_type="upstream_commit"):
    return {
        "id": source_id,
        "url": "https://api.github.com/repos/acme/app/commits/" + "a" * 40,
        "fetched_at": "2026-11-16T00:00:00+00:00",
        "content_sha256": "a" * 64,
        "source_type": source_type,
        "citation": "test source",
        "status": status,
        "error": None,
        "local_path": f"evidence/{source_id}.json",
        "media_type": "application/json",
        "redirect_chain": [],
    }


def _evidence(*sources):
    return {
        "schema_version": "1.0",
        "cve_id": "CVE-2026-99999",
        "collected_at": "2026-11-16T00:00:00+00:00",
        "sources": list(sources),
    }


def _discovery(**overrides):
    values = {
        "cve_id": "CVE-2026-99999",
        "package": "acme",
        "ecosystem": "pypi",
        "component": "acme",
        "vulnerable_ref": None,
        "fixed_ref": None,
        "fix_commit": None,
        "fix_source_id": None,
        "aliases": (),
        "references": (),
        "notes": (),
    }
    values.update(overrides)
    return Discovery(**values)


def _proposal(**overrides):
    values = {
        "schema_version": "1.0",
        "cve_id": "CVE-2026-99999",
        "status": "proposed",
        "confidence": "high",
        "package": "acme",
        "ecosystem": "pypi",
        "component": "acme",
        "vulnerable_ref": "1.2.3",
        "fixed_ref": "1.2.4",
        "fix_commit": "a" * 40,
        "fix_source_id": "src-1-upstream-commit",
        "reason": "tag 1.2.3 precedes the fix and 1.2.4 is the patched release",
        "citations": [
            {"source_id": "src-1-upstream-commit", "quote": "fix the traversal check"}
        ],
        "unresolved": [],
    }
    values.update(overrides)
    return values


def _write_sources(run_dir: Path, evidence, fix_commit=None):
    from harbor_pipeline.util import digest
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence").mkdir(exist_ok=True)
    for source in evidence.get("sources", []):
        local = str(source.get("local_path") or "")
        if local:
            body = b'{"ok": true}'
            if source.get("source_type") == "upstream_commit":
                sha = fix_commit or "a" * 40
                source["url"] = "https://api.github.com/repos/acme/app/commits/" + sha
                body = ("From " + sha + " Mon Sep 17 00:00:00 2001\n"
                        "Subject: fix the traversal check\ndiff --git a/app b/app\n"
                        "@@ -1 +1 @@\n-bad\n+fixed\n").encode()
            (run_dir / local).write_bytes(body)
            source["content_sha256"] = digest(body)
    write_json(run_dir / "evidence-index.json", evidence)


def _write_run(tmp_path: Path, discovery=None, evidence=None):
    run_dir = tmp_path / "CVE-2026-99999"
    run_dir.mkdir(parents=True)
    discovery = discovery or _discovery()
    evidence = evidence or _evidence(_source())
    write_json(run_dir / "discovery.json", discovery.to_json())
    write_json(run_dir / "evidence-index.json", evidence)
    _write_sources(run_dir, evidence, fix_commit=discovery.fix_commit)
    return run_dir, discovery, evidence


def test_workspace_has_read_only_inputs_and_external_helper(tmp_path):
    run_dir, discovery, evidence = _write_run(tmp_path)
    workspace = evidence_resolver.prepare_workspace(
        run_dir=run_dir,
        cve_id="CVE-2026-99999",
        discovery=discovery,
        evidence=evidence,
        model="test-model",
    )

    assert (workspace.root / "inputs" / "discovery.json").is_file()
    assert (workspace.root / "inputs" / "evidence-index.json").is_file()
    assert (workspace.root / "CLAUDE.md").is_file()
    assert (run_dir / "resolver-bin" / "harbor-evidence").is_file()
    settings = read_json(workspace.settings_path)
    assert settings["model"] == "test-model"
    assert "Bash(harbor-evidence:*)" in settings["permissions"]["allow"]
    assert "WebFetch" in settings["permissions"]["deny"]
    assert "Write(inputs/**)" in settings["permissions"]["deny"]
    assert "Bash(head:*)" in settings["permissions"]["deny"]


def test_proposal_requires_ok_upstream_commit_source():
    evidence = _evidence(_source(status="error"))
    issues = evidence_resolver.validate_proposal(
        _proposal(), evidence=evidence, cve_id="CVE-2026-99999"
    )
    assert any("not an ok source" in issue for issue in issues)

    evidence = _evidence(_source(source_type="release_notes"))
    issues = evidence_resolver.validate_proposal(
        _proposal(), evidence=evidence, cve_id="CVE-2026-99999"
    )
    assert any("not an upstream_commit" in issue for issue in issues)


def test_proposal_requires_generic_ecosystem_for_commit_ref():
    evidence = _evidence(_source())
    issues = evidence_resolver.validate_proposal(
        _proposal(fixed_ref="a" * 40, ecosystem="pypi"),
        evidence=evidence,
        cve_id="CVE-2026-99999",
    )
    assert any("raw-commit fixed_ref" in issue for issue in issues)
    assert evidence_resolver.validate_proposal(
        _proposal(fixed_ref="a" * 40, ecosystem="generic"),
        evidence=evidence,
        cve_id="CVE-2026-99999",
    ) == []


def test_proposal_rejects_zero_byte_fix_source(tmp_path):
    source = _source()
    source["content_sha256"] = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    evidence = _evidence(source)
    issues = evidence_resolver.validate_proposal(
        _proposal(), evidence=evidence, cve_id="CVE-2026-99999"
    )
    assert any("zero-byte" in issue for issue in issues)

    # The same empty file is also caught when the run directory is available.
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "src-1-upstream-commit.json").write_bytes(b"")
    source["content_sha256"] = "a" * 64
    issues = evidence_resolver.validate_proposal(
        _proposal(),
        evidence=_evidence(source),
        cve_id="CVE-2026-99999",
        run_dir=tmp_path,
    )
    assert any("empty" in issue or "too short" in issue for issue in issues)


def test_proposal_accepts_supported_pair_and_rejects_equal_refs():
    evidence = _evidence(_source())
    assert evidence_resolver.validate_proposal(
        _proposal(), evidence=evidence, cve_id="CVE-2026-99999"
    ) == []
    issues = evidence_resolver.validate_proposal(
        _proposal(fixed_ref="1.2.3"), evidence=evidence, cve_id="CVE-2026-99999"
    )
    assert any("must differ" in issue for issue in issues)


def test_apply_proposal_updates_discovery_and_reloads_evidence(tmp_path):
    run_dir, discovery, evidence = _write_run(tmp_path)
    resolved, refreshed = evidence_resolver.apply_proposal(
        discovery=discovery,
        proposal=_proposal(),
        evidence=evidence,
        run_dir=run_dir,
    )

    assert resolved.vulnerable_ref == "1.2.3"
    assert resolved.fixed_ref == "1.2.4"
    assert resolved.fix_source_id == "src-1-upstream-commit"
    assert "resolver:" in resolved.notes[-1]
    assert refreshed["cve_id"] == "CVE-2026-99999"
    assert read_json(run_dir / "discovery.json")["vulnerable"]["value"] == "1.2.3"


def test_resolver_validates_against_sources_fetched_during_session(tmp_path):
    run_dir, discovery, evidence = _write_run(tmp_path)

    class Runner:
        def run(self, *, prompt, workspace, contract, settings_path, extra_env=None, resume=None):
            # Simulate the helper recording a new commit after the session
            # started, then writing a proposal that cites it.
            index = read_json(run_dir / "evidence-index.json")
            new_source = _source("src-2-upstream-commit")
            (run_dir / "evidence" ).mkdir(exist_ok=True)
            from harbor_pipeline.util import digest
            body = json.dumps({"sha": "b" * 40, "files": [{"filename": "app", "patch": "@@ -1 +1 @@\n-bad\n+fixed"}]}).encode()
            (run_dir / "evidence" / "src-2-upstream-commit.json").write_bytes(body)
            new_source["content_sha256"] = digest(body)
            new_source["url"] = "https://api.github.com/repos/acme/app/commits/" + "b" * 40
            index["sources"].append(new_source)
            write_json(run_dir / "evidence-index.json", index)
            write_json(
                workspace / "reconciliation.json",
                _proposal(fix_commit="b" * 40, fix_source_id="src-2-upstream-commit"),
            )
            from harbor_pipeline.agent import AgentOutcome

            return AgentOutcome(status="completed", turns=2, usd=0.01)

    result = evidence_resolver.EvidenceResolver(
        Config(
            models={
                "default": ModelSettings(),
                "resolver": ModelSettings(provider="claude-code"),
            }
        ),
        runner=Runner(),
    ).resolve(
        run_dir=run_dir,
        cve_id="CVE-2026-99999",
        discovery=discovery,
        evidence=evidence,
    )
    assert result.status == "proposed"
    assert result.proposal["fix_source_id"] == "src-2-upstream-commit"


def test_resolver_does_not_reuse_a_stale_proposal(tmp_path):
    run_dir, discovery, evidence = _write_run(tmp_path)
    (run_dir / "reconciliation.json").write_text(
        json.dumps(_proposal()), encoding="utf-8"
    )

    class Runner:
        def run(self, *, prompt, workspace, contract, settings_path, extra_env=None, resume=None):
            from harbor_pipeline.agent import AgentOutcome

            return AgentOutcome(status="completed", turns=1)

    result = evidence_resolver.EvidenceResolver(
        Config(
            models={
                "default": ModelSettings(),
                "resolver": ModelSettings(provider="claude-code"),
            }
        ),
        runner=Runner(),
    ).resolve(
        run_dir=run_dir,
        cve_id="CVE-2026-99999",
        discovery=discovery,
        evidence=evidence,
    )
    assert result.status == "no_proposal"
    assert not (run_dir / "reconciliation.json").exists()


def test_resolver_returns_unsupported_proposal(tmp_path):
    run_dir, discovery, evidence = _write_run(tmp_path)

    class Runner:
        def run(self, *, prompt, workspace, contract, settings_path, extra_env=None, resume=None):
            write_json(
                workspace / "reconciliation.json",
                {
                    "schema_version": "1.0",
                    "cve_id": "CVE-2026-99999",
                    "status": "unsupported",
                    "confidence": "high",
                    "reason": "no published fixed release",
                },
            )
            from harbor_pipeline.agent import AgentOutcome

            return AgentOutcome(status="completed", turns=1)

    result = evidence_resolver.EvidenceResolver(
        Config(
            models={
                "default": ModelSettings(),
                "resolver": ModelSettings(provider="claude-code"),
            }
        ),
        runner=Runner(),
    ).resolve(
        run_dir=run_dir,
        cve_id="CVE-2026-99999",
        discovery=discovery,
        evidence=evidence,
    )
    assert result.status == "unsupported"
    assert "no published fixed release" in result.proposal["reason"]


def test_github_helper_records_allowlisted_source(tmp_path, monkeypatch):
    run_dir, _, evidence = _write_run(tmp_path)
    ctx = evidence_tool.ToolContext(
        workspace=run_dir / "resolver",
        run_dir=run_dir,
        cve_id="CVE-2026-99999",
        settings=SourceSettings(),
    )
    payload = json.dumps(
        [{"name": "v1.2.3", "commit": {"sha": "a" * 40}}]
    ).encode("utf-8")
    body_sha = __import__("hashlib").sha256(payload).hexdigest()

    def fake_fetch(url, settings, max_redirects=5):
        return FetchResult(
            url=url,
            final_url=url,
            status=200,
            body=payload,
            sha256=body_sha,
            media_type="application/json",
        )

    monkeypatch.setattr("harbor_pipeline.sources.fetch", fake_fetch)
    args = argparse.Namespace(repo="acme/app", action="tags", sha=None)
    assert evidence_tool.cmd_github(ctx, args) == 0
    index = read_json(run_dir / "evidence-index.json")
    assert index["sources"][-1]["source_type"] == "release_notes"
    assert index["sources"][-1]["status"] == "ok"
    assert "api.github.com" in index["sources"][-1]["url"]


def test_github_helper_rejects_bad_repo(capsys):
    ctx = evidence_tool.ToolContext(
        workspace=Path("."),
        run_dir=Path("."),
        cve_id="CVE-2026-99999",
        settings=SourceSettings(),
    )
    args = argparse.Namespace(repo="not-a-repo", action="tags", sha=None)
    assert evidence_tool.cmd_github(ctx, args) == 1
    assert "owner/name" in capsys.readouterr().out


def test_requeue_creates_fresh_evidence_ready_run(tmp_path):
    from harbor_pipeline.requeue import requeue_resolved

    run_dir, _, _ = _write_run(
        tmp_path,
        discovery=_discovery(
            package="acme/app",
            ecosystem="generic",
            vulnerable_ref="a" * 40,
            fixed_ref="b" * 40,
            fix_commit="b" * 40,
            fix_source_id="src-1-upstream-commit",
        ),
    )
    write_json(run_dir / "state.json", {"state": "UNSUPPORTED"})
    proposal = _proposal(
        package="acme/app",
        ecosystem="generic",
        vulnerable_ref="a" * 40,
        fixed_ref="b" * 40,
        fix_commit="b" * 40,
    )
    write_json(
        run_dir / "resolver-result.json",
        {
            "cve_id": "CVE-2026-99999",
            "resolver": {"status": "proposed", "proposal": proposal},
        },
    )
    result = requeue_resolved(
        source_run_dir=run_dir,
        cve_id="CVE-2026-99999",
        output_root=tmp_path / "runs",
        new_run_id="requeued",
        config=Config(pipeline=Settings(output_dir=str(tmp_path / "runs"))),
    )

    assert result.state == "EVIDENCE_READY"
    assert (result.new_run_dir / "evidence-index.json").is_file()
    assert (result.new_run_dir / "discovery.json").is_file()
    assert (result.new_run_dir / "requeue.json").is_file()
    new_state = read_json(result.new_run_dir / "state.json")
    assert new_state["state"] == "EVIDENCE_READY"
    assert any(
        item["note"] == "requeued after evidence resolver"
        for item in new_state["history"]
    )
    # The source run remains terminal and untouched.
    assert read_json(run_dir / "state.json")["state"] == "UNSUPPORTED"


def test_requeue_accepts_reconciliation_fallback(tmp_path):
    from harbor_pipeline.requeue import requeue_resolved

    run_dir, _, _ = _write_run(
        tmp_path,
        discovery=_discovery(
            package="acme/app",
            ecosystem="generic",
            vulnerable_ref="a" * 40,
            fixed_ref="b" * 40,
            fix_commit="b" * 40,
            fix_source_id="src-1-upstream-commit",
        ),
    )
    write_json(run_dir / "state.json", {"state": "UNSUPPORTED"})
    write_json(
        run_dir / "reconciliation.json",
        _proposal(
            package="acme/app",
            ecosystem="generic",
            vulnerable_ref="a" * 40,
            fixed_ref="b" * 40,
            fix_commit="b" * 40,
        ),
    )
    result = requeue_resolved(
        source_run_dir=run_dir,
        cve_id="CVE-2026-99999",
        output_root=tmp_path / "runs",
        new_run_id="requeued",
        config=Config(pipeline=Settings(output_dir=str(tmp_path / "runs"))),
    )
    assert result.state == "EVIDENCE_READY"


def test_requeue_rejects_a_non_unsupported_source(tmp_path):
    from harbor_pipeline.requeue import requeue_resolved

    run_dir, _, _ = _write_run(tmp_path)
    write_json(run_dir / "state.json", {"state": "QUARANTINED"})
    try:
        requeue_resolved(
            source_run_dir=run_dir,
            cve_id="CVE-2026-99999",
            output_root=tmp_path / "runs",
            new_run_id="requeued",
            config=Config(pipeline=Settings(output_dir=str(tmp_path / "runs"))),
        )
    except Exception as exc:
        assert "UNSUPPORTED" in str(exc)
    else:
        raise AssertionError("requeue accepted a non-UNSUPPORTED source")


def test_pipeline_applies_resolver_proposal(tmp_path, monkeypatch):
    from harbor_pipeline import discovery as discovery_mod
    from harbor_pipeline.pipeline import CvePipeline

    evidence = _evidence(
        _source("src-1-cve-record", source_type="cve_record"),
        _source("src-2-upstream-commit"),
    )
    incomplete = _discovery()
    config = Config(
        pipeline=Settings(output_dir=str(tmp_path / "runs"), evidence_resolver=True),
        models={
            "default": ModelSettings(),
            "resolver": ModelSettings(provider="claude-code"),
        },
    )
    monkeypatch.setattr(
        discovery_mod,
        "collect",
        lambda settings, run_dir, cve_id: (evidence, incomplete),
    )

    def fake_resolve(self, **kwargs):
        return evidence_resolver.ResolverOutcome(
            status="proposed",
            proposal=_proposal(
                fix_source_id="src-2-upstream-commit",
                citations=[
                    {
                        "source_id": "src-2-upstream-commit",
                        "quote": "fix the traversal check",
                    }
                ],
            ),
        )

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", fake_resolve)
    pipeline = CvePipeline(
        config=config, cve_id="CVE-2026-99999", run_id="r1", scenario="auto"
    )
    _write_sources(pipeline.store.root, evidence)
    pipeline._collect_auto(pipeline.store.create())

    assert pipeline.discovery.vulnerable_ref == "1.2.3"
    assert pipeline.discovery.fixed_ref == "1.2.4"
    assert read_json(pipeline.store.root / "discovery.json")["fixed"]["value"] == "1.2.4"
    assert (pipeline.store.root / "resolver-result.json").is_file()


def test_pipeline_resolver_runs_only_for_incomplete_discovery(tmp_path, monkeypatch):
    from harbor_pipeline import discovery as discovery_mod
    from harbor_pipeline.pipeline import CvePipeline

    run_dir = tmp_path / "runs" / "r1" / "CVE-2026-99999"
    run_dir.mkdir(parents=True)
    discovery = _discovery(vulnerable_ref="1.2.3", fixed_ref="1.2.4", fix_commit="a" * 40, fix_source_id="src-2-upstream-commit")
    evidence = _evidence(
        _source("src-1-cve-record", source_type="cve_record"),
        _source("src-2-upstream-commit"),
    )
    write_json(run_dir / "evidence-index.json", evidence)
    write_json(run_dir / "discovery.json", discovery.to_json())

    _write_sources(run_dir, evidence)

    config = Config(
        pipeline=Settings(output_dir=str(tmp_path / "runs"), evidence_resolver=True),
        models={
            "default": ModelSettings(),
            "resolver": ModelSettings(provider="claude-code"),
        },
    )
    pipeline = CvePipeline(config=config, cve_id="CVE-2026-99999", run_id="r1", scenario="auto")
    called = {"n": 0}

    def fake_resolve(self, **kwargs):
        called["n"] += 1
        return evidence_resolver.ResolverOutcome(status="no_proposal")

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, "resolve", fake_resolve)
    # A complete discovery must not spend a resolver session.
    monkeypatch.setattr(discovery_mod, "complete_missing_refs", lambda settings, root, evidence, parsed: (evidence, parsed))
    pipeline._collect_auto(pipeline.store.create())
    assert called["n"] == 0
