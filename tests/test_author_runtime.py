"""Unit tests for the container author runtime and host service."""
import json
import os
from pathlib import Path

import pytest

from harbor_pipeline import agent, author_runtime, author_service
from harbor_pipeline.config import Config, ModelSettings
from harbor_pipeline.util import PipelineError


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "case" / "author"
    for folder in ("target", "target-fixed", "poc", "inputs", ".harbor"):
        (workspace / folder).mkdir(parents=True)
    (workspace / "target" / "app.py").write_text("vulnerable\n", encoding="utf-8")
    (workspace / "target-fixed" / "app.py").write_text("fixed\n", encoding="utf-8")
    (workspace / "poc" / "reference.py").write_text("print('x')\n", encoding="utf-8")
    (workspace / "bundle.json").write_text('{"cve_id": "CVE-0000-0000"}\n', encoding="utf-8")
    (workspace / "CLAUDE.md").write_text("contract\n", encoding="utf-8")
    return workspace


def test_prepare_live_seeds_once_and_keeps_author_edits(tmp_path):
    workspace = _workspace(tmp_path)
    live = author_runtime.prepare_live(workspace)
    assert (live / "target" / "app.py").read_text(encoding="utf-8") == "vulnerable\n"
    assert (live / "poc" / "reference.py").is_file()
    assert (live / "research").is_dir() and (live / "tools").is_dir()
    (live / "target" / "app.py").write_text("author edit\n", encoding="utf-8")
    assert author_runtime.prepare_live(workspace) == live
    assert (live / "target" / "app.py").read_text(encoding="utf-8") == "author edit\n"


def test_prepare_live_refuses_an_unrecognized_directory(tmp_path):
    workspace = _workspace(tmp_path)
    live = workspace.parent / "author-files"
    live.mkdir(parents=True)
    (live / "foreign.txt").write_text("do not overwrite\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="refusing to overwrite"):
        author_runtime.prepare_live(workspace)


def test_local_file_rejects_traversal_and_links(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.txt").write_text("ok", encoding="utf-8")
    assert author_service.local_file(root, "ok.txt") == root / "ok.txt"
    with pytest.raises(PipelineError):
        author_service.local_file(root, "../outside.txt")
    with pytest.raises(PipelineError):
        author_service.local_file(root, "/etc/passwd")
    if os.name == "nt":
        import _winapi

        outside = tmp_path / "outside"
        outside.mkdir()
        _winapi.CreateJunction(str(outside), str(root / "linked"))
    else:
        (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(PipelineError, match="Linked"):
        author_service.local_file(root, "linked/secret.txt")


def test_snapshot_freezes_captured_sources_into_the_host_workspace(tmp_path):
    workspace = _workspace(tmp_path)
    live = author_runtime.prepare_live(workspace)
    captured = {
        "bundle": {
            "cve_id": "CVE-0000-0000",
            "target": {
                "files": {"app.py": "captured vulnerable\n"},
                "fixed_overrides": {"app.py": "captured fixed\n"},
            },
            "poc": {"reference": "print('captured')\n"},
        }
    }

    def capture(request):
        assert request == {"kind": "bundle"}
        return captured

    argv = author_service.snapshot(workspace, live, ["submit"], capture=capture)
    assert argv == ["submit"]
    assert (workspace / "target" / "app.py").read_text(encoding="utf-8") == "captured vulnerable\n"
    assert (workspace / "target-fixed" / "app.py").read_text(encoding="utf-8") == "captured fixed\n"
    assert (workspace / "poc" / "reference.py").read_text(encoding="utf-8") == "print('captured')\n"
    metadata = json.loads((workspace / "bundle.json").read_text(encoding="utf-8"))
    assert "files" not in metadata["target"]
    assert (workspace / ".harbor" / "source-snapshot.json").is_file()


def test_snapshot_leaves_read_only_operations_alone(tmp_path):
    workspace = _workspace(tmp_path)
    live = author_runtime.prepare_live(workspace)
    argv = ["debug", "--variant", "vulnerable", "start"]
    assert author_service.snapshot(workspace, live, argv) is argv


def test_agent_uses_the_container_runtime_for_authors(tmp_path, monkeypatch):
    called = {}

    def fake_session(runner, **kwargs):
        called.update(kwargs)
        return agent.AgentOutcome(status="completed", result_text="ok")

    monkeypatch.setattr("harbor_pipeline.author_runtime.run_session", fake_session)
    workspace = _workspace(tmp_path)
    settings = workspace.parent / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    config = Config(models={
        "default": ModelSettings(provider="claude-code", model="m"),
        "author": ModelSettings(provider="claude-code", model="m"),
    })
    config.pipeline.author_runtime = "container"
    outcome = agent.ClaudeCodeAgent(config, role="author").run(
        prompt="p", workspace=workspace, contract="c", settings_path=settings
    )
    assert outcome.status == "completed"
    assert called["workspace"] == workspace
    assert called["prompt"] == "p"


def test_unrestricted_shell_only_applies_to_the_author_profile():
    author = agent.build_agent_settings("m", unrestricted_shell=True)
    assert "Bash" in author["permissions"]["allow"]
    resolver = agent.build_agent_settings(
        "m", profile=agent.RESOLVER_PROFILE, unrestricted_shell=True
    )
    assert "Bash" not in resolver["permissions"]["allow"]


def test_config_defaults_to_the_container_runtime():
    from harbor_pipeline.config import Settings

    settings = Settings()
    assert settings.author_runtime == "container"
    assert settings.author_memory_mb >= 256
    assert 0 < settings.author_cpus <= 64
