"""Trusted fixed-side verifier service; its network has no vulnerable target."""
import hmac
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.respond(200 if self.path == "/health" else 404, b"ok")

    def do_POST(self):
        try:
            token = Path("/control/token").read_text().strip()
        except OSError:
            token = ""
        if not token or not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
            self.respond(403, b"forbidden")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if self.path != "/check" or not 0 < length <= 1_000_000:
            self.respond(400, b"invalid request")
            return
        Path("/logs/artifacts/poc").write_bytes(self.rfile.read(length))
        evidence_path = Path("/logs/verifier/evidence.json")
        evidence_path.unlink(missing_ok=True)
        try:
            subprocess.run([sys.executable, "/tests/fixed/verify.py"],
                env={**os.environ, "TARGET_HOST": "target", "VERIFY_REFERENCE_PATH": "/tests/fixed/reference_poc.py"},
                timeout=170, check=True)
            evidence = json.loads(evidence_path.read_text())
        except Exception as exc:
            evidence = {"status": "verifier_error", "error": str(exc)}
        self.respond(200, json.dumps(evidence).encode())

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    for name in ("/tests", "/logs/verifier", "/logs/artifacts"):
        Path(name).mkdir(parents=True, exist_ok=True)
        os.chmod(name, 0o700)
    HTTPServer(("0.0.0.0", 8082), Handler).serve_forever()
