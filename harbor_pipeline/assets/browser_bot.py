#!/usr/bin/env python3
"""Victim browser with an isolated, preconfigured application login session."""
import copy
import hashlib
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

TARGET_URL = os.environ.get("BOT_TARGET_URL", "http://target:8080").rstrip("/")
SECRET_FILE = os.environ.get("BOT_SECRET_FILE", "/bot-oracle/token")
SETUP_FILE = os.environ.get("BOT_SETUP_FILE", "/bot-oracle/setup.json")
COOKIE_NAME = os.environ.get("BOT_COOKIE_NAME", "harbor_secret")
PORT = int(os.environ.get("BOT_PORT", "8090"))
TARGET_HOST = urlsplit(TARGET_URL).hostname or "target"
_LOCK = threading.Lock()
_SIGNATURE = None
_STATE = None
_ERROR = False
_RUNNING = False


def read_secret():
    with open(SECRET_FILE, encoding="utf-8") as handle:
        value = handle.read().strip()
    if not re.fullmatch(r"[0-9a-f]{48}", value):
        raise ValueError("bot token is missing or malformed")
    return value


def target_url(value):
    parsed, target = urlsplit(value), urlsplit(TARGET_URL)
    if (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) != (
        target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80)
    ) or parsed.username or parsed.password:
        raise ValueError("bot only visits the configured target origin")
    return value


def read_setup():
    try:
        with open(SETUP_FILE, encoding="utf-8") as handle:
            text = handle.read(32_001)
    except FileNotFoundError:
        return []
    if len(text) > 32_000:
        raise ValueError("bot setup is too large")
    setup = json.loads(text)
    if not isinstance(setup, dict) or set(setup) - {"steps", "reason"}:
        raise ValueError("invalid bot setup")
    steps = setup.get("steps", [])
    if not isinstance(steps, list) or len(steps) > 12:
        raise ValueError("invalid bot setup steps")
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError("invalid bot setup action")
        action = step.get("action")
        keys = {"goto": {"action", "path"}, "fill": {"action", "selector", "value"},
                "click": {"action", "selector"}, "wait_for": {"action", "selector"}}.get(action)
        if keys is None or set(step) != keys or any(not isinstance(v, str) or not v or len(v) > 2000 for v in step.values()):
            raise ValueError("invalid bot setup action")
        if action == "goto":
            path = step["path"]
            if not path.startswith("/") or path.startswith("//") or any(c in path for c in "\\\r\n"):
                raise ValueError("setup navigation must use a relative target path")
            target_url(TARGET_URL + path)
    if steps and (steps[0]["action"] != "goto" or steps[-1]["action"] != "wait_for"):
        raise ValueError("bot setup must navigate first and verify readiness last")
    return steps


def initialize_storage(steps):
    """Normal app login/setup only; the goal cookie is installed afterwards."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            context = browser.new_context()
            page = context.new_page()
            for step in steps:
                action = step["action"]
                if action == "goto":
                    page.goto(target_url(TARGET_URL + step["path"]), wait_until="domcontentloaded", timeout=10000)
                elif action == "fill":
                    page.locator(step["selector"]).fill(step["value"], timeout=10000)
                elif action == "click":
                    page.locator(step["selector"]).click(timeout=10000)
                elif action == "wait_for":
                    page.locator(step["selector"]).wait_for(state="visible", timeout=10000)
                target_url(page.url)  # Reject redirects out of the configured target.
            state = context.storage_state()
            state["cookies"] = [c for c in state.get("cookies", []) if c.get("name") != COOKIE_NAME]
            return state
        finally:
            browser.close()


def session_ready():
    global _SIGNATURE, _STATE, _ERROR, _RUNNING
    steps = read_setup()
    if not steps:
        return True
    signature = hashlib.sha256(json.dumps(steps, sort_keys=True).encode()).hexdigest()

    def warmup():
        global _STATE, _ERROR, _RUNNING
        try:
            state = initialize_storage(steps)
        except Exception:
            with _LOCK:
                _ERROR, _RUNNING = True, False
        else:
            with _LOCK:
                _STATE, _RUNNING = state, False

    with _LOCK:
        if signature != _SIGNATURE and not _RUNNING:
            _SIGNATURE, _STATE, _ERROR = signature, None, False
            _RUNNING = True
            threading.Thread(target=warmup, daemon=True).start()
        return signature == _SIGNATURE and _STATE is not None and not _ERROR


def storage_state():
    if not session_ready():
        raise ValueError("bot application session is not ready")
    with _LOCK:
        return copy.deepcopy(_STATE) if _STATE is not None else {"cookies": [], "origins": []}


class Bot(BaseHTTPRequestHandler):
    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if self.path != "/visit":
            self._send(404, b"not found")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 8192:
                raise ValueError("invalid visit payload")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) != {"url"}:
                raise ValueError("only a target URL may be supplied by the PoC")
            url = target_url(str(payload["url"]))
            secret, state = read_secret(), storage_state()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                try:
                    context = browser.new_context(storage_state=state)
                    context.add_cookies([{"name": COOKIE_NAME, "value": secret, "domain": TARGET_HOST,
                                         "path": "/", "httpOnly": False, "secure": False}])
                    page = context.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    page.wait_for_timeout(3000)
                finally:
                    browser.close()
            self._send(200, b"ok")
        except Exception:
            # Never return application-session cookies, credentials or the goal token.
            self._send(500, b"bot visit failed; check target readiness and browser setup")

    def do_GET(self):
        if self.path != "/health":
            self._send(404, b"not found")
            return
        try:
            read_secret()
            if not session_ready():
                raise ValueError("bot login is not ready")
            self._send(200, b"ready")
        except (OSError, ValueError, TypeError):
            self._send(503, b"bot token or application session is not ready")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Bot).serve_forever()
