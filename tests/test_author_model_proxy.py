"""Credential scope and streaming over real loopback sockets. No external provider."""
import http.client
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from harbor_pipeline import agent, author_debug, authoring
from harbor_pipeline.author_model_proxy import ModelAuthError, author_model_proxy
from harbor_pipeline.config import Config, ModelSettings
from harbor_pipeline.util import PipelineError, write_json


MODEL = "fixture-model"
HOST_KEY = "fixture-upstream-api-key"
HOST_BEARER = "fixture-upstream-bearer"


@contextmanager
def upstream(respond):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, self.headers, payload))
            respond(self, payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/gateway", requests
        finally:
            server.shutdown()
            thread.join()


def post(client, *, path="/v1/messages", model=MODEL, key=None, headers=None, max_tokens=4):
    url = urlsplit(client["ANTHROPIC_BASE_URL"])
    conn = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
    try:
        conn.request("POST", path, json.dumps({"model": model, "max_tokens": max_tokens, "messages": []}),
                     {"Content-Type": "application/json", "x-api-key": key or client["ANTHROPIC_API_KEY"],
                      **(headers or {})})
        with conn.getresponse() as reply:
            return reply.status, reply.read()
    finally:
        conn.close()


def ok(handler, _):
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(b'{"input_tokens":2}')


@pytest.fixture(autouse=True)
def clean_connection(monkeypatch):
    for name in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("api_key,bearer", [(HOST_KEY, None), (None, HOST_BEARER), (HOST_KEY, HOST_BEARER)])
def test_host_auth_and_path_prefix_never_come_from_child(monkeypatch, api_key, bearer):
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", api_key)
    if bearer:
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", bearer)
    with upstream(ok) as (base, requests), author_model_proxy(ModelSettings(api_base=base, model=MODEL+"[1m]")) as relay:
        client = relay.child_environment()
        assert not any(v in str(client) for v in (HOST_KEY, HOST_BEARER))
        assert post(client, key="other-session")[0] == 401
        assert post(client, model="other-provider-model")[0] == 403
        assert post(client, max_tokens=999999)[0] == 400
        assert post(client, path="/v1/experiments")[0] == 404
        status, body = post(client, path="/v1/messages/count_tokens?beta=true",
                            headers={"Cookie": "out-of-scope", "X-Forwarded-Host": "ignored",
                                     "anthropic-beta": "fixture", "anthropic-version": "2023-06-01"})
        assert status == 200 and json.loads(body)["input_tokens"] == 2
        assert len(requests) == 1
        path, headers, _ = requests[0]
        assert path == "/gateway/v1/messages/count_tokens?beta=true"
        assert headers.get("x-api-key") == api_key
        assert headers.get("Authorization") == ("Bearer " + bearer if bearer else None)
        assert headers["anthropic-beta"] == "fixture"
        assert "Cookie" not in headers and "X-Forwarded-Host" not in headers


def test_stream_is_incremental_and_ticket_is_revoked(monkeypatch):
    release = threading.Event()

    def stream(handler, _):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.end_headers()
        handler.wfile.write(b"event: ping\ndata: {}\n\n")
        handler.wfile.flush()
        if release.wait(5):
            handler.wfile.write(f"data: {HOST_BEARER}\n\n".encode())

    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", HOST_BEARER)
    with upstream(stream) as (base, _):
        settings = ModelSettings(api_base=base, model=MODEL)
        with author_model_proxy(settings) as relay:
            env = relay.child_environment()
            url = urlsplit(env["ANTHROPIC_BASE_URL"])
            conn = http.client.HTTPConnection(url.hostname, url.port, timeout=2)
            try:
                conn.request("POST", "/v1/messages", json.dumps({"model": MODEL, "max_tokens": 4}),
                             {"Content-Type": "application/json", "Authorization": "Bearer " + env["ANTHROPIC_API_KEY"]})
                with conn.getresponse() as reply:
                    assert reply.status == 200 and reply.readline() == b"event: ping\n"
                    release.set()
                    assert b"data: [redacted]" in reply.read()
            finally:
                release.set()
                conn.close()
        with pytest.raises(OSError):
            post(env)
        with author_model_proxy(settings) as resumed:
            assert post(resumed.child_environment(), key=env["ANTHROPIC_API_KEY"])[0] == 401


def test_upstream_redirect_and_error_text_cannot_forward_credentials(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", HOST_KEY)
    with upstream(ok) as (destination, hits):
        def redirect(handler, _):
            handler.send_response(307)
            handler.send_header("Location", destination)
            handler.end_headers()
            handler.wfile.write(HOST_KEY.encode())

        with upstream(redirect) as (source, _), author_model_proxy(ModelSettings(api_base=source, model=MODEL)) as relay:
            status, body = post(relay.child_environment())
            assert status == 502 and HOST_KEY.encode() not in body and not hits


def test_session_teardown_interrupts_a_live_model_stream(monkeypatch):
    disconnected = threading.Event()

    def stream(handler, _):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.end_headers()
        handler.wfile.write(b"event: ping\n\n")
        handler.wfile.flush()
        handler.connection.settimeout(3)
        try:
            if handler.connection.recv(1) == b"":
                disconnected.set()
        except ConnectionResetError:
            disconnected.set()

    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", HOST_BEARER)
    with upstream(stream) as (base, _):
        with author_model_proxy(ModelSettings(api_base=base, model=MODEL)) as relay:
            client = relay.child_environment()
            url = urlsplit(client["ANTHROPIC_BASE_URL"])
            conn = http.client.HTTPConnection(url.hostname, url.port, timeout=2)
            conn.request("POST", "/v1/messages", json.dumps({"model": MODEL, "max_tokens": 4}),
                         {"Content-Type": "application/json", "x-api-key": client["ANTHROPIC_API_KEY"]})
            reply = conn.getresponse()
            assert reply.readline() == b"event: ping\n"
        try:
            assert disconnected.wait(2), "upstream remained connected after the author exited"
        finally:
            reply.close()
            conn.close()


@pytest.mark.skipif(not shutil.which("sh"), reason="requires the author helper's POSIX shell")
def test_helper_process_has_no_model_credential(tmp_path):
    package = tmp_path / "harbor_pipeline"
    package.mkdir()
    (package / "__init__.py").touch()
    (package / "author_tool.py").write_text(
        'import os, sys\n'
        'sys.exit(int("ANTHROPIC_API_KEY" in os.environ or "ANTHROPIC_AUTH_TOKEN" in os.environ))\n',
        encoding="utf-8")
    wrapper = tmp_path / "harbor-author"
    wrapper.write_text(authoring._WRAPPER, encoding="utf-8", newline="\n")
    env = agent.agent_environment(workspace=tmp_path, repo_root=tmp_path)
    env.update(HARBOR_AUTHOR_PYTHON=sys.executable, PYTHONPATH=str(tmp_path),
               ANTHROPIC_API_KEY="session-ticket", ANTHROPIC_AUTH_TOKEN="session-ticket")
    subprocess.run([shutil.which("sh"), str(wrapper), "status"], env=env, cwd=tmp_path, check=True, timeout=15)


def test_plaintext_remote_origin_and_missing_host_auth_fail_before_launch(tmp_path, monkeypatch):
    with pytest.raises(PipelineError, match="HTTPS"):
        with author_model_proxy(ModelSettings(api_base="http://example.invalid/")):
            pytest.fail("untrusted origin started")
    with pytest.raises(ModelAuthError):
        with author_model_proxy(ModelSettings()):
            pytest.fail("unauthenticated relay started")
    monkeypatch.setattr(agent.shutil, "which", lambda _: "claude")
    monkeypatch.setattr(agent.ClaudeCodeAgent, "_run_process", lambda *a, **kw: pytest.fail("author was launched"))
    config = Config()
    config.pipeline.author_runtime = "host"
    runner = agent.ClaudeCodeAgent(config)
    result = runner.run(prompt="test", workspace=tmp_path / "author",
                        contract="", settings_path=tmp_path / "unused")
    assert result.status == "auth_error"


def test_history_migration_copies_only_requested_candidate_transcript(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    workspace = tmp_path / "case" / "author"
    session = str(uuid.uuid4())
    legacy = Path.home() / ".claude"
    source = legacy / "projects" / "candidate" / (session + ".jsonl")
    source.parent.mkdir(parents=True)
    old_line = json.dumps({"sessionId": session, "cwd": str(workspace), "text": HOST_KEY}) + "\n"
    source.write_text(old_line, encoding="utf-8")
    (source.parent / "unrelated.jsonl").write_text(old_line, encoding="utf-8")
    (legacy / "settings.json").write_text(HOST_KEY, encoding="utf-8")
    def redact(text):
        return text.replace(HOST_KEY, "[redacted]")
    other = agent._author_cli_state(tmp_path / "other" / "author", session, redact)
    assert not list(other.rglob("*.jsonl"))
    profile = agent._author_cli_state(workspace, session, redact)
    saved = profile / "projects" / "candidate" / source.name
    assert saved.read_text(encoding="utf-8") == redact(old_line)
    assert not (profile / "settings.json").exists() and not (saved.parent / "unrelated.jsonl").exists()
    saved.write_text("new conversation state", encoding="utf-8")
    agent._author_cli_state(workspace, session, redact)
    assert saved.read_text(encoding="utf-8") == "new conversation state"


def test_author_profile_rejects_a_link_to_another_home(tmp_path):
    linked_home = tmp_path / "other-home"
    linked_home.mkdir()
    if os.name == "nt":
        # Directory junctions do not require the Windows symlink privilege.
        import _winapi
        _winapi.CreateJunction(str(linked_home), str(tmp_path / "author-cli"))
    else:
        (tmp_path / "author-cli").symlink_to(linked_home, target_is_directory=True)
    with pytest.raises(PipelineError, match="local to its candidate"):
        agent._author_cli_state(tmp_path / "author", None, str)
    assert not (linked_home / ".claude").exists()


@pytest.mark.skipif(os.environ.get("HARBOR_TEST_CLAUDE_CLI") != "1" or not shutil.which("claude"),
                    reason="local CLI smoke test with a loopback mock model")
def test_installed_cli_resumes_through_proxy(tmp_path, monkeypatch):
    def respond(handler, payload):
        if "count_tokens" in handler.path:
            return ok(handler, payload)
        msg = {"id": "msg_offline_test", "type": "message", "role": "assistant", "model": MODEL,
               "content": [], "stop_reason": None, "stop_sequence": None,
               "usage": {"input_tokens": 3, "output_tokens": 0}}
        handler.send_response(200)
        if not payload.get("stream"):
            msg.update(content=[{"type": "text", "text": "OK"}], stop_reason="end_turn")
            handler.send_header("Content-Type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(msg).encode())
            return
        handler.send_header("Content-Type", "text/event-stream")
        handler.end_headers()
        for event in [
            {"type": "message_start", "message": msg},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "OK"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
             "usage": {"output_tokens": 1}},
            {"type": "message_stop"},
        ]:
            handler.wfile.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())

    monkeypatch.setenv("ANTHROPIC_API_KEY", HOST_KEY)
    monkeypatch.setattr(author_debug, "suspend", lambda _: None)
    workspace = tmp_path / "candidate" / "author"
    workspace.mkdir(parents=True)
    path = workspace.parent / "settings.json"
    write_json(path, agent.build_agent_settings(MODEL))
    with upstream(respond) as (base, requests):
        config = Config(models={"default": ModelSettings(model=MODEL, api_base=base, max_turns=2, timeout_sec=40)})
        config.pipeline.author_runtime = "host"
        runner = agent.ClaudeCodeAgent(config, profile=replace(agent.AUTHOR_PROFILE, tool_list="", allowed_tools=""))
        kwargs = {"workspace": workspace, "contract": "Answer with OK.", "settings_path": path}
        first = runner.run(prompt="Remember the harmless label HELLO_FIRST.", **kwargs)
        assert first.status == "completed" and first.result_text == "OK", first.error
        resumed = runner.run(prompt="Confirm HELLO_SECOND.", resume=first.session_id, **kwargs)
        assert resumed.status == "completed" and resumed.session_id == first.session_id, resumed.error
        messages = [json.dumps(req["messages"]) for _, _, req in requests]
        assert any("HELLO_FIRST" in m and "HELLO_SECOND" in m for m in messages)
        projects = workspace.parent / "author-cli" / ".claude" / "projects"
        assert list(projects.glob(f"*/{first.session_id}.jsonl"))
    for artifact in workspace.parent.rglob("*"):
        if artifact.is_file():
            assert HOST_KEY.encode() not in artifact.read_bytes()
