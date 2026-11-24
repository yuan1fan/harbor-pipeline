"""Per-invocation host service for an untrusted author container.

The client supplies helper argv, never a host workspace, command or upstream
URL. Model credentials stay in this process. A random capability expires when
the session closes; model requests are bounded independently of the client.
"""
from __future__ import annotations

import hashlib
import base64
import hmac
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import authoring
from .util import PipelineError, digest, hidden_console_kwargs, read_json, write_json

HELPERS = {"validate", "build", "probe", "exec", "registry", "submit", "decline",
           "request-evidence-review", "status", "debug", "cleanup"}


def local_file(root: Path, name: str, *, limit: int = 4_000_000) -> Path:
    """Reject links, junctions and path traversal before reading client files."""
    if name.startswith("/workspace/"):
        name = name[len("/workspace/"):]
    if not name or name.startswith("/") or "\\" in name or ":" in name or ".." in name.split("/"):
        raise PipelineError("Expected a file inside /workspace")
    root = root.resolve()
    path = root
    for part in name.split("/"):
        path = path / part
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise PipelineError("Linked author files are not accepted")
    if not path.resolve().is_relative_to(root) or not path.is_file() or path.stat().st_size > limit:
        raise PipelineError("Missing or oversized author file")
    return path


def snapshot(workspace: Path, live: Path, argv: list[str], *, capture=None) -> list[str]:
    """Freeze only submission sources, never trust control files from the client."""
    if argv[0] not in {"validate", "build", "probe", "submit", "request-evidence-review"}:
        return argv
    if capture:
        raw = capture({"kind": "bundle"})["bundle"]
    else:
        local_file(live, "bundle.json")
        local_file(live, "poc/reference.py")
        for name in ("target", "target-fixed", "poc"):
            path = live / name
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                raise PipelineError("Linked source directories are not accepted")
        raw = authoring.assemble_bundle(live)
    # All subsequent validation, rendering and probing sees these exact bytes.
    for folder, files in (("target", raw["target"]["files"]),
                          ("target-fixed", raw["target"]["fixed_overrides"]),
                          ("poc", {"reference.py": raw["poc"]["reference"]})):
        target = workspace / folder
        stage = workspace / ".harbor" / ("snapshot-" + uuid.uuid4().hex)
        stage.mkdir(parents=True)
        for name, content in files.items():
            if not name or name.startswith("/") or "\\" in name or ":" in name or ".." in name.split("/"):
                raise PipelineError("Unsafe captured source path")
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        if target.exists():
            if target.is_symlink() or target.resolve().parent != workspace.resolve():
                raise PipelineError("Unsafe host snapshot directory")
            old = workspace / ".harbor" / ("old-" + uuid.uuid4().hex)
            target.rename(old)
            stage.rename(target)
            if not old.resolve().is_relative_to((workspace / ".harbor").resolve()):
                raise PipelineError("Unsafe obsolete snapshot")
            shutil.rmtree(old)
        else:
            stage.rename(target)
    metadata = dict(raw)
    metadata["target"] = {k: v for k, v in raw["target"].items() if k not in {"files", "fixed_overrides"}}
    metadata.pop("poc", None)
    write_json(workspace / "bundle.json", metadata)
    write_json(workspace / ".harbor/source-snapshot.json", {"digest": digest(raw)})
    if argv[0] == "request-evidence-review":
        if len(argv) != 3 or argv[1] != "--file":
            raise PipelineError("Use request-evidence-review --file <workspace file>")
        request_name = argv[2].removeprefix("/workspace/")
        request_bytes = (base64.b64decode(capture({"kind": "file", "name": request_name})["data"])
                         if capture else local_file(live, request_name, limit=64000).read_bytes())
        if len(request_bytes) > 64000:
            raise PipelineError("Evidence review request exceeds 64 KB")
        payload = json.loads(request_bytes)
        if not isinstance(payload, dict) or not isinstance(payload.get("citations"), list):
            raise PipelineError("Invalid evidence review request")
        # Copy cited research bytes into host-owned storage. Input/log citations
        # already exist in the host workspace and must never be overwritten.
        for item in payload["citations"][:8]:
            name = item.get("path", "") if isinstance(item, dict) else ""
            if name.startswith("/workspace/"):
                name = name[len("/workspace/"):]
                item["path"] = name
            if name.startswith(("inputs/", ".harbor/", "target/", "target-fixed/", "poc/")):
                local_file(workspace, name)
            else:
                body = (base64.b64decode(capture({"kind": "file", "name": name})["data"])
                        if capture else local_file(live, name).read_bytes())
                dest = ".harbor/citations/" + hashlib.sha256(body).hexdigest() + ".txt"
                (workspace / dest).parent.mkdir(parents=True, exist_ok=True)
                (workspace / dest).write_bytes(body)
                item["path"] = dest
        write_json(workspace / ".harbor/review-request.json", payload)
        return ["request-evidence-review", "--file", ".harbor/review-request.json"]
    return argv


class AuthorService:
    def __init__(self, *, config, workspace: Path, live: Path, invocation: str,
                 extra_env=None, after_helper=None, capture=None, bind="0.0.0.0"):
        from .agent import agent_environment
        self.config, self.workspace, self.live = config, workspace, live
        self.invocation = invocation
        self.after_helper = after_helper
        self.capture = capture
        self.token = secrets.token_urlsafe(32)
        self.closed = threading.Event()
        self.operation = threading.Lock()
        self.active = threading.Event()
        self.process = None
        self.requests = 0
        self.request_lock = threading.Lock()
        self.connections = set()
        self.model_slots = threading.BoundedSemaphore(2)
        self.env = agent_environment(workspace=workspace, repo_root=Path(__file__).resolve().parent.parent,
                                     extra_env=extra_env)
        self.env["HARBOR_AUTHOR_SESSION_RUN"] = invocation
        settings = config.model_for("author")
        self.upstream = urlsplit(os.environ.get("ANTHROPIC_BASE_URL") or settings.api_base)
        if (self.upstream.scheme not in {"http", "https"} or not self.upstream.hostname
                or self.upstream.username or self.upstream.password or self.upstream.query or self.upstream.fragment):
            raise PipelineError("Invalid author model endpoint")
        self.key = os.environ.get("ANTHROPIC_API_KEY") or ""
        self.bearer = os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""
        if not self.key and not self.bearer:
            raise PipelineError("Set the author model API key or auth token on the host")
        if any(c in self.key + self.bearer for c in "\r\n\0"):
            raise PipelineError("Invalid model credentials")
        self.model = re.sub(r"\[[^]]+\]$", "", settings.model)
        self.request_limit = max(32, settings.max_turns * 8)
        self.server = ThreadingHTTPServer((bind, 0), self.handler())
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .1}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.closed.set()
        self.cancel_helper()
        with self.request_lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                if connection.sock:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                connection.close()
            except OSError:
                pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def cancel_helper(self):
        from .backend import _kill_tree
        process = self.process
        if process is not None and process.poll() is None:
            _kill_tree(process)

    def wait(self, deadline):
        waited = self.active.is_set()
        while self.active.is_set():
            if time.monotonic() >= deadline:
                self.cancel_helper()
                raise TimeoutError("Author helper exceeded its wall limit")
            time.sleep(.1)
        return waited

    def helper(self, args):
        if (not isinstance(args, list) or not args or len(args) > 128
                or any(not isinstance(a, str) or "\0" in a or len(a) > 32000 for a in args)
                or args[0] not in HELPERS):
            raise PipelineError("Unsupported author operation")
        if not self.operation.acquire(blocking=False):
            raise PipelineError("Another helper is running; wait for its result")
        self.active.set()
        try:
            args = snapshot(self.workspace, self.live, args, capture=self.capture)
            if self.closed.is_set():
                raise PipelineError("Author session has ended")
            log = self.workspace / ".harbor" / ("rpc-" + uuid.uuid4().hex + ".log")
            with log.open("wb") as output:
                self.process = subprocess.Popen(
                    [sys.executable, "-m", "harbor_pipeline.author_tool", *args],
                    cwd=str(self.workspace), env=self.env, stdout=output, stderr=subprocess.STDOUT,
                    start_new_session=os.name != "nt", **hidden_console_kwargs())
                code = self.process.wait()
            with log.open("rb") as handle:
                handle.seek(max(0, log.stat().st_size - 2_000_000))
                text = handle.read().decode("utf-8", "replace")
            for path, alias in ((self.workspace.parent / "author-probe", "/artifacts/probe"),
                                (self.workspace, "/workspace"),
                                (self.workspace.parent, "/candidate")):
                for value in (json.dumps(str(path))[1:-1], str(path), path.as_posix()):
                    text = text.replace(value, alias)
            for secret in (self.key, self.bearer, self.token):
                text = text.replace(secret, "[redacted]")
            if self.after_helper:
                self.after_helper(args)
            return {"exit_code": code, "output": text}
        finally:
            self.process = None
            self.active.clear()
            self.operation.release()

    def handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(300)

            def reply(self, status, value):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def do_POST(self):
                self.handle_request()

            def do_GET(self):
                self.handle_request()

            def handle_request(self):
                supplied = self.headers.get("x-api-key") or self.headers.get("Authorization", "").removeprefix("Bearer ")
                if service.closed.is_set() or not hmac.compare_digest(supplied, service.token):
                    self.reply(401, {"error": "Author capability is invalid or expired"})
                    return
                helper = self.path == "/helper" and self.command == "POST"
                model = self.path in {"/model/v1/messages", "/model/v1/messages?beta=true", "/model/v1/messages/count_tokens"} and self.command == "POST"
                if not (helper or model):
                    self.reply(404, {"error": "Unsupported endpoint"})
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if self.headers.get("Transfer-Encoding") or not 0 < size <= (65536 if helper else 16_000_000):
                        raise PipelineError("Invalid request size")
                    body = self.rfile.read(size)
                    if len(body) != size:
                        raise PipelineError("Incomplete request")
                    payload = json.loads(body)
                    if not isinstance(payload, dict):
                        raise PipelineError("Expected a JSON object")
                    if helper:
                        self.reply(200, service.helper(payload.get("argv")))
                    else:
                        self.model_request(payload)
                except (PipelineError, ValueError) as exc:
                    self.reply(400, {"error": str(exc)})
                except (BrokenPipeError, ConnectionError, OSError):
                    self.close_connection = True
                except Exception:
                    self.reply(500, {"error": "Host operation failed; inspect the host logs"})

            def model_request(self, payload):
                if not service.model_slots.acquire(blocking=False):
                    self.reply(429, {"error": "Author model concurrency exhausted"})
                    return
                connection = None
                sent = False
                try:
                    with service.request_lock:
                        if service.requests >= service.request_limit:
                            self.reply(429, {"error": "Author model request budget exhausted"})
                            return
                        service.requests += 1
                    payload["model"] = service.model
                    headers = {name: self.headers[name] for name in
                               ("anthropic-version", "anthropic-beta", "user-agent") if name in self.headers}
                    headers.update({"Content-Type": "application/json", "Accept-Encoding": "identity"})
                    if service.key:
                        headers["x-api-key"] = service.key
                    if service.bearer:
                        headers["Authorization"] = "Bearer " + service.bearer
                    factory = http.client.HTTPSConnection if service.upstream.scheme == "https" else http.client.HTTPConnection
                    connection = factory(service.upstream.hostname, service.upstream.port, timeout=300)
                    with service.request_lock:
                        service.connections.add(connection)
                    path = service.upstream.path.rstrip("/") + self.path.removeprefix("/model")
                    # No redirect following: credentials only reach the configured upstream.
                    connection.request("POST", path, body=json.dumps(payload).encode(), headers=headers)
                    response = connection.getresponse()
                    if response.status != 200:
                        body = response.read(65536).decode("utf-8", "replace")
                        for secret in (service.key, service.bearer):
                            body = body.replace(secret, "[redacted]")
                        self.reply(response.status if not 300 <= response.status < 400 else 502,
                                   {"error": body})
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    sent = True
                    self.close_connection = True
                    # read1 forwards available SSE bytes without waiting for a full buffer.
                    while not service.closed.is_set():
                        chunk = response.read1(16384)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (OSError, http.client.HTTPException):
                    if not sent:
                        self.reply(502, {"error": "Author model upstream unavailable"})
                finally:
                    if connection:
                        with service.request_lock:
                            service.connections.discard(connection)
                        connection.close()
                    service.model_slots.release()

        return Handler
