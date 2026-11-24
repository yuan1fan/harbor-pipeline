"""A loopback Messages API relay with a credential valid for one author invocation."""
from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import os
import secrets
import socket
import threading
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import ModelSettings
from .util import PipelineError


class ModelAuthError(PipelineError):
    pass


_ROUTES = {base + suffix for base in ("/v1/messages", "/v1/messages/count_tokens")
           for suffix in ("", "?beta=true")}
_MAX_BODY = 32 * 1024 * 1024


def _upstream_url(value: str):
    try:
        url = urlsplit(value)
        # Accessing port also checks malformed and out-of-range ports.
        port = url.port
        host = url.hostname
    except ValueError:
        raise PipelineError("Invalid host model endpoint") from None
    if (not host or port == 0 or url.username is not None or url.password is not None
            or url.query or url.fragment or "\\" in value or not value.isascii()
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
        raise PipelineError("Invalid host model endpoint")
    if url.scheme != "https":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if url.scheme != "http" or not loopback:
            raise PipelineError("The host model endpoint requires HTTPS, or HTTP on loopback")
    return url


class _Relay(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, settings: ModelSettings):
        self.url = _upstream_url(os.environ.get("ANTHROPIC_BASE_URL") or settings.api_base)
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        bearer = os.environ.get("ANTHROPIC_AUTH_TOKEN")
        if not api_key and not bearer:
            raise ModelAuthError("Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN on the host for the author model proxy")
        self._secrets = [value for value in (api_key, bearer) if value]
        if any(not value.isascii() or not value.isprintable() for value in self._secrets):
            raise ModelAuthError("Invalid host model credential")
        self.auth_headers = {}
        if api_key:
            self.auth_headers["x-api-key"] = api_key
        if bearer:
            self.auth_headers["Authorization"] = "Bearer " + bearer
        self.ticket = secrets.token_urlsafe(32)
        self._secrets = sorted({*self._secrets, self.ticket}, key=len, reverse=True)
        self._secret_bytes = tuple(s.encode() for s in self._secrets)
        self.model = settings.model.removesuffix("[1m]")
        self.api_version = settings.api_version
        self.request_timeout = min(settings.timeout_sec, 300)
        self.output_limit = settings.max_output_tokens
        self.remaining = settings.max_turns * 4  # includes retries, counting and context management
        self.closed = False
        self.lock = threading.Lock()
        self.sockets: set[socket.socket] = set()
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(("127.0.0.1", 0), _Handler)

    def child_environment(self) -> dict[str, str]:
        return {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{self.server_port}",
                "ANTHROPIC_API_KEY": self.ticket,
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.model,
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(self.output_limit),
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}

    def redact(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "[redacted]")
        return text

    def redact_line(self, line: bytes) -> bytes:
        for value in self._secret_bytes:
            line = line.replace(value, b"[redacted]")
        return line

    def track(self, sock: socket.socket) -> bool:
        with self.lock:
            if self.closed:
                return False
            self.sockets.add(sock)
            return True

    def forget(self, sock: socket.socket) -> None:
        with self.lock:
            self.sockets.discard(sock)

    def charge(self) -> bool:
        with self.lock:
            if self.closed or self.remaining <= 0:
                return False
            self.remaining -= 1
            return True

    def revoke(self) -> None:
        with self.lock:
            self.closed = True
            active = tuple(self.sockets)
        for sock in active:
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        if not self.track(request):
            self.slots.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.forget(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.forget(request)
            self.slots.release()


class _Handler(BaseHTTPRequestHandler):
    server: _Relay
    timeout = 20

    def log_message(self, *args):
        # Request lines, headers and payloads are never part of pipeline logs.
        pass

    def error(self, status: int, message: str):
        body = json.dumps({"type": "error", "error": {"type": "api_error", "message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        keys = list(self.headers.get_all("x-api-key", []))
        keys.extend(value.removeprefix("Bearer ") for value in self.headers.get_all("Authorization", [])
                    if value.startswith("Bearer "))
        if not keys or not all(hmac.compare_digest(key.encode("utf-8"), self.server.ticket.encode()) for key in keys):
            self.error(401, "Author session credential rejected")
            return
        if self.path not in _ROUTES:
            self.error(404, "Unsupported model API path")
            return
        sizes = self.headers.get_all("Content-Length", [])
        if (len(sizes) != 1 or not sizes[0].isascii() or not sizes[0].isdigit() or len(sizes[0]) > 9
                or not 0 < int(sizes[0]) <= _MAX_BODY or "Transfer-Encoding" in self.headers):
            self.error(413, "Expected a bounded JSON request")
            return
        if self.headers.get_content_type() != "application/json" or self.headers.get("Content-Encoding", "identity") != "identity":
            self.error(415, "Expected an uncompressed JSON request")
            return
        body = self.rfile.read(int(sizes[0]))
        try:
            payload = json.loads(body)
        except (ValueError, RecursionError):
            payload = None
        if len(body) != int(sizes[0]) or not isinstance(payload, dict):
            self.error(400, "Invalid JSON request")
            return
        if payload.get("model") != self.server.model:
            self.error(403, "Model is outside this author session")
            return
        if self.path.partition("?")[0] == "/v1/messages":
            limit = payload.get("max_tokens")
            if type(limit) is not int or not 0 < limit <= self.server.output_limit:
                self.error(400, "max_tokens is outside the configured author output limit")
                return
        if not self.server.charge():
            self.error(429, "Author session request limit reached")
            return
        self.forward(body)

    def forward(self, body: bytes):
        relay = self.server
        url = relay.url
        cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        connection = cls(url.hostname, url.port, timeout=relay.request_timeout)
        sock = None
        started = False
        try:
            connection.connect()
            sock = connection.sock
            if not relay.track(sock):
                return
            headers = {"Content-Type": "application/json", "Accept-Encoding": "identity",
                       "anthropic-version": self.headers.get("anthropic-version", relay.api_version),
                       **relay.auth_headers}
            if "anthropic-beta" in self.headers:
                headers["anthropic-beta"] = self.headers["anthropic-beta"]
            if any("\r" in v or "\n" in v for v in headers.values()):
                self.error(400, "Invalid API headers")
                return
            # http.client sends to this fixed origin and never follows redirects.
            connection.request("POST", url.path.rstrip("/") + self.path, body=body, headers=headers)
            with connection.getresponse() as upstream:
                if upstream.status != 200:
                    code = upstream.status if 400 <= upstream.status < 600 else 502
                    self.error(code, f"Host model endpoint returned HTTP {upstream.status}")
                    return
                media = upstream.headers.get_content_type()
                if media not in {"application/json", "text/event-stream"} or upstream.getheader("Content-Encoding", "identity") != "identity":
                    self.error(502, "Unexpected content from host model endpoint")
                    return
                self.send_response(200)
                self.send_header("Content-Type", media)
                self.end_headers()
                started = True
                # SSE is line framed. Flush each line as it arrives, including
                # the empty line ending an event. Redact a reflected credential
                # even when it was split between TCP packets.
                while line := upstream.readline(_MAX_BODY + 1):
                    if len(line) > _MAX_BODY:
                        return
                    self.wfile.write(relay.redact_line(line))
                    self.wfile.flush()
        except (OSError, http.client.HTTPException, ValueError):
            if not started:
                with suppress(OSError):
                    self.error(502, "Host model endpoint is unavailable")
        finally:
            if sock is not None:
                relay.forget(sock)
            connection.close()


@contextmanager
def author_model_proxy(settings: ModelSettings):
    with _Relay(settings) as relay:
        thread = threading.Thread(target=relay.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield relay
        finally:
            relay.revoke()
            relay.shutdown()
            thread.join()
