"""The bot must still read its token after the verifier consumes its copy."""
import sys
from types import ModuleType, SimpleNamespace

import pytest

from harbor_pipeline import author_probe, fixtures, scenario
from harbor_pipeline.generator import render_task
from harbor_pipeline.goals import BOT_SECRET_FILE
from test_goal_families import _synthesis


def _bot(monkeypatch):
    module = ModuleType("playwright")
    monkeypatch.setitem(sys.modules, "playwright", module)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=lambda: None))
    namespace = {"__name__": "bot_test"}
    exec(compile(scenario._BOT, "generated-bot.py", "exec"), namespace)
    return namespace


def test_real_generated_verifier_deletes_only_its_own_token(tmp_path, monkeypatch):
    token = "a" * 48
    verifier_token, bot_token = tmp_path / "expected-token", tmp_path / "bot-token"
    verifier_token.write_text(token)
    bot_token.write_text(token)
    ctx = scenario.ScenarioContext(cve_id="CVE-0000-0000", product="demo", variant="vulnerable",
        probe="reference", version="1", secret_path="/opt/app/secret/token", spec_digest="a" * 64,
        attribution_grade="A", goal_family="secret_read", goal_primitive="xss")
    verifier = {"__name__": "verifier_test"}
    exec(compile(scenario._verify_script(ctx), "generated-verify.py", "exec"), verifier)
    verifier["SECRET_FILE"] = str(verifier_token)
    bot = _bot(monkeypatch)
    bot["SECRET_FILE"] = str(bot_token)
    assert verifier["expected_secret"]() == token
    assert not verifier_token.exists()
    assert bot["read_secret"]() == token
    handler = bot["Bot"].__new__(bot["Bot"])
    handler.path = "/health"
    responses = []
    handler._send = lambda code, body: responses.append((code, body))
    handler.do_GET()
    assert responses[-1] == (200, b"ready")
    bot_token.unlink()
    handler.do_GET()
    assert responses[-1][0] == 503
    assert token.encode() not in responses[-1][1]
    entrypoint = scenario._synthesis_entrypoint("python app.py", ctx)
    assert f'printf \'%s\' "$SECRET" > {BOT_SECRET_FILE}' in entrypoint


@pytest.mark.parametrize("render", ["author", "matrix"])
def test_bot_private_volume_is_not_mounted_by_untrusted_verifier(tmp_path, render):
    spec = fixtures.cve_spec()
    spec["task_goal"]["primitive"] = "xss"
    spec["task_goal"]["family"] = "secret_read"
    if render == "author":
        text = author_probe.compose_text(spec=spec, target_image="target", verifier_image="verifier",
            tests_dir=tmp_path, logs_dir=tmp_path, submitted_poc=tmp_path / "poc", variant="vulnerable")
    else:
        synthesis = _synthesis("secret_read")
        task = render_task(spec, scenario_name="synthesized", variant="vulnerable", synthesis=synthesis)
        text = task.files["tests/docker-compose.yaml"]
    main = text.split("  main:\n", 1)[1].split("\n  ", 1)[0] if "  main:\n" in text else ""
    # A service boundary has exactly two spaces; nested YAML fields have more.
    import re
    main = re.search(r"(?ms)^  main:\n(.*?)(?=^  \S|^volumes:|\Z)", text).group(1)
    assert "bot-data" not in main and "/bot-oracle" not in main
    assert 'BOT_SECRET_FILE: "/bot-oracle/token"' in text
    assert "bot-data:/bot-oracle:ro" in text
    assert "bot:\n        condition: service_healthy" in text
    if render == "matrix":
        assert "fixed-bot-data:/bot-oracle:ro" in text
        assert "bot-fixed:\n        condition: service_healthy" in text


def test_bot_reads_bounded_application_login_setup(tmp_path, monkeypatch):
    setup = {
        "reason": "the sink is behind the administrator login",
        "steps": [
            {"action": "goto", "path": "/admin/login"},
            {"action": "fill", "selector": "input[name=email]", "value": "admin@example.test"},
            {"action": "fill", "selector": "input[name=password]", "value": "test-password"},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "wait_for", "selector": "#admin-dashboard"},
        ],
    }
    path = tmp_path / "setup.json"
    path.write_text(__import__("json").dumps(setup), encoding="utf-8")
    bot = _bot(monkeypatch)
    bot["SETUP_FILE"] = str(path)
    assert bot["read_setup"]() == setup["steps"]
    setup["steps"][0]["path"] = "//evil.example/"
    path.write_text(__import__("json").dumps(setup), encoding="utf-8")
    with pytest.raises(ValueError):
        bot["read_setup"]()
