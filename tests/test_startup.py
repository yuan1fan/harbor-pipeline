import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from harbor_pipeline.connection_env import inherited_connection
from harbor_pipeline.util import PipelineError


def _config(tmp_path, enabled=True):
    path = tmp_path / "pipeline.toml"
    path.write_text(
        f'[pipeline]\ninherit_claude_settings = {str(enabled).lower()}\n'
        '[models.default]\nprovider = "fixture"\n'
        'api_base = "${ANTHROPIC_BASE_URL}"\n', encoding="utf-8",
    )
    return path


def _settings(tmp_path, env=None):
    path = tmp_path / "settings.json"
    values = env if env is not None else {
        "ANTHROPIC_BASE_URL": "https://fixture.invalid",
        "ANTHROPIC_AUTH_TOKEN": "fixture-secret-do-not-log",
        "AWS_SECRET_ACCESS_KEY": "must-not-import",
        "ANTHROPIC_MODEL": "must-not-override",
    }
    path.write_text(json.dumps({"env": values, "permissions": {"allow": ["Bash(*)"]}}), encoding="utf-8")
    return path


def test_connection_inherits_only_complete_allowlisted_group(tmp_path):
    source_env = {}
    result = inherited_connection(_config(tmp_path), environ=source_env, settings_path=_settings(tmp_path))
    assert result == {"ANTHROPIC_BASE_URL": "https://fixture.invalid",
                      "ANTHROPIC_AUTH_TOKEN": "fixture-secret-do-not-log"}
    assert source_env == {}


@pytest.mark.parametrize("explicit", [
    {"ANTHROPIC_BASE_URL": "https://override.invalid"},
    {"ANTHROPIC_API_KEY": "explicit-key"},
    {"ANTHROPIC_AUTH_TOKEN": "explicit-token", "ANTHROPIC_BASE_URL": "https://override.invalid"},
    {"CLAUDE_CODE_OAUTH_TOKEN": "explicit-oauth"},
])
def test_explicit_connection_never_mixes_with_saved_credentials(tmp_path, explicit):
    assert inherited_connection(_config(tmp_path), environ=explicit, settings_path=tmp_path / "missing.json") == {}


def test_connection_inheritance_requires_opt_in(tmp_path):
    assert inherited_connection(_config(tmp_path, False), environ={}, settings_path=tmp_path / "missing.json") == {}


def test_incomplete_saved_pair_does_not_expose_credentials(tmp_path):
    path = _settings(tmp_path, {"ANTHROPIC_AUTH_TOKEN": "do-not-print-me"})
    with pytest.raises(PipelineError, match="complete endpoint/authentication pair") as exc:
        inherited_connection(_config(tmp_path), environ={}, settings_path=path)
    assert "do-not-print-me" not in str(exc.value)


def test_check_config_uses_saved_connection_without_docker_or_models(tmp_path, monkeypatch, capsys):
    from harbor_pipeline import cli
    config = _config(tmp_path)
    _settings(tmp_path)
    monkeypatch.setattr(cli, "prune_orphan_task_resources", lambda: pytest.fail("no Docker calls"))
    with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(tmp_path)}, clear=True):
        assert cli.main(["-c", str(config), "check-config", "--json"]) == 0
        assert os.environ["ANTHROPIC_AUTH_TOKEN"] == "fixture-secret-do-not-log"
    output = capsys.readouterr()
    assert json.loads(output.out)["ok"] is True
    assert "fixture-secret-do-not-log" not in output.out + output.err
    assert "https://fixture.invalid" not in output.out + output.err


def _wrapper():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_batch_progress.py"
    spec = importlib.util.spec_from_file_location("batch_progress_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wrapper_input(tmp_path, state):
    candidate = "CVE-2026-12345"
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps([candidate]), encoding="utf-8")
    output = tmp_path / "output"
    run = output / "test-run"
    (run / candidate).mkdir(parents=True)
    (run / candidate / "state.json").write_text(json.dumps({"state": state}), encoding="utf-8")
    return input_path, output, run


def test_failed_launch_shows_current_error_and_exit_code_not_stale_success(tmp_path, monkeypatch, capsys):
    wrapper = _wrapper()
    input_path, output, run = _wrapper_input(tmp_path, "RELEASED")
    log = output / "test-run-batch.log"
    log.write_bytes(b"OLD ERROR MUST NOT APPEAR\n")
    (run / "batch-report.json").write_text('{"old": true}', encoding="utf-8")
    command_seen = []

    def failed(command, *, stdout, stderr):
        command_seen.extend(command)
        stdout.write(b"error: Set environment variable ANTHROPIC_BASE_URL referenced in configuration\n")
        stdout.flush()
        return SimpleNamespace(returncode=2, poll=lambda: 2)

    monkeypatch.setattr(wrapper.subprocess, "Popen", failed)
    monkeypatch.setattr(sys, "argv", ["run_batch_progress.py", "--input", str(input_path),
                                     "--run-id", "test-run", "--output-dir", str(output)])
    assert wrapper.main() == 2
    captured = capsys.readouterr()
    assert "failed:" in captured.out and "exit code 2" in captured.out
    assert "finished:" not in captured.out
    assert "not generated by this invocation" in captured.out
    assert "ANTHROPIC_BASE_URL" in captured.err
    assert "OLD ERROR" not in captured.err
    assert log.read_bytes().startswith(b"OLD ERROR")
    assert command_seen[command_seen.index("--output-dir") + 1] == str(output)


def test_completed_batch_with_quarantine_reports_the_real_batch_report(tmp_path, monkeypatch, capsys):
    wrapper = _wrapper()
    input_path, output, run = _wrapper_input(tmp_path, "QUARANTINED")

    def completed(command, *, stdout, stderr):
        (run / "batch-report.json").write_text('{"completed": true}', encoding="utf-8")
        return SimpleNamespace(returncode=3, poll=lambda: 3)

    monkeypatch.setattr(wrapper.subprocess, "Popen", completed)
    monkeypatch.setattr(sys, "argv", ["run_batch_progress.py", "--input", str(input_path),
                                     "--run-id", "test-run", "--output-dir", str(output)])
    assert wrapper.main() == 3
    captured = capsys.readouterr()
    assert "finished: 1/1" in captured.out
    assert str(run / "batch-report.json") in captured.out
    assert "failed:" not in captured.out


def test_log_tail_tolerates_non_utf8_bytes_and_stays_bounded(tmp_path):
    wrapper = _wrapper()
    path = tmp_path / "output.log"
    path.write_bytes(b"old error\n" + b"x" * 20000 + b"\nerror: \xb3\n")
    text = wrapper._log_tail(path, 10, max_bytes=128)
    assert "error:" in text
    assert "old error" not in text
    assert len(text) < 130
