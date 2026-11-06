"""Opt-in Linux container checks; no model calls and no vulnerable external target."""
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from harbor_pipeline.scenario import ScenarioContext, _TEST_SH, _synthesis_entrypoint, _verify_script

pytestmark = pytest.mark.skipif(os.environ.get("HARBOR_RUN_DOCKER_TESTS") != "1", reason="set HARBOR_RUN_DOCKER_TESTS=1 for container regression tests")


def container(script):
    name = "harbor-hardening-test-" + uuid.uuid4().hex[:12]
    try:
        result = subprocess.run(["docker", "run", "--rm", "--name", name, "--network", "none",
            "--memory", "256m", "--cpus", "1", "-i", "python:3.12-slim-bookworm", "python", "-"],
            input=script, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)


def context(**kw):
    return ScenarioContext(cve_id="CVE-0000-0000", product="demo", variant="vulnerable",
        probe="reference", version="1", secret_path="/opt/app/secret/token",
        spec_digest="a" * 64, attribution_grade="A", **kw)


def test_listing_answer_rotates_even_with_a_supplied_old_name():
    script = "ENTRY=" + repr(_synthesis_entrypoint("true", context(goal_family="directory_listing"))) + "\n" + r'''
import json, subprocess, os
from pathlib import Path
Path('/entry.sh').write_text(ENTRY)
names=[]
for _ in range(2):
    subprocess.run(['sh','/entry.sh'],env=dict(os.environ,LISTING_NAME='known.txt'),check=True)
    names.append(Path('/listing/expected').read_text())
print(json.dumps({'names':names,'mode':oct(Path('/listing').stat().st_mode & 0o777)}))
'''
    result = container(script)
    assert len(set(result["names"])) == 2
    assert "known.txt" not in result["names"]
    assert result["mode"] == "0o700"


def test_real_replay_user_is_checked_against_both_targets():
    from dataclasses import replace
    payload = {
        "verify": _verify_script(context(paired_verification=True)), "test": _TEST_SH,
        "fixed_verify": _verify_script(replace(context(), variant="fixed")),
        "runner": (Path(__file__).parents[1] / "harbor_pipeline/assets/fixed_runner.py").read_text(),
    }
    script = "PAYLOAD=" + repr(payload) + "\n" + r'''
import json, os, subprocess, threading
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
subprocess.run(['useradd','--create-home','--shell','/bin/sh','replay'],check=True)
with open('/etc/hosts','a') as f: f.write('\n127.0.0.2 target\n127.0.0.1 fixed-runner\n')
for folder in ['/tests/fixed','/logs/artifacts','/logs/verifier','/oracle','/oracle-fixed','/control']:
    Path(folder).mkdir(parents=True,exist_ok=True)
for folder in ['/oracle','/oracle-fixed']: os.chmod(folder,0o700)
Path('/tests/verify.py').write_text(PAYLOAD['verify'])
Path('/tests/test.sh').write_text(PAYLOAD['test'])
Path('/tests/fixed/verify.py').write_text(PAYLOAD['fixed_verify'])
Path('/tests/fixed_runner.py').write_text(PAYLOAD['runner'])
def handler(token, fixed):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ['/health','/static/hello.txt']:
                body=b'hello' if self.path.endswith('hello.txt') else b'ok'
            elif self.path=='/shortcut' or (self.path=='/secret' and not fixed): body=token.encode()
            else:
                self.send_error(403);return
            self.send_response(200);self.end_headers();self.wfile.write(body)
        def log_message(self,*args): pass
    return Handler
servers=[ThreadingHTTPServer(('127.0.0.1',8080),handler('a'*48,False)),ThreadingHTTPServer(('127.0.0.2',8080),handler('b'*48,True))]
for server in servers: threading.Thread(target=server.serve_forever,daemon=True).start()
def poc(route):
    return '#!/usr/bin/env python3\nimport os,urllib.request\ntry:\n print(urllib.request.urlopen("http://"+os.environ["TARGET_HOST"]+":8080'+route+'").read().decode())\nexcept Exception:\n pass\n'
Path('/tests/reference_poc.py').write_text(poc('/secret'))
Path('/tests/fixed/reference_poc.py').write_text(poc('/secret'))
worker=subprocess.Popen(['python','/tests/fixed_runner.py'],env=dict(os.environ,VERIFY_SECRET_FILE='/oracle-fixed/expected-token'))
import time,urllib.request
for _ in range(50):
    try:
        urllib.request.urlopen('http://127.0.0.1:8082/health');break
    except Exception: time.sleep(0.1)
results={}
for label,artifact in [('valid',poc('/secret')),('unrelated_shortcut',poc('/shortcut')),('forged',"#!/usr/bin/env python3\nprint('f'*48)\n")]:
    Path('/oracle/expected-token').write_text('a'*48)
    Path('/oracle-fixed/expected-token').write_text('b'*48)
    Path('/logs/artifacts/poc').write_text(artifact)
    result=subprocess.run(['bash','/tests/test.sh'],env=dict(os.environ,TARGET_HOST='127.0.0.1'),capture_output=True,text=True,timeout=25)
    evidence=json.loads(Path('/logs/verifier/evidence.json').read_text())
    results[label]={'reward':evidence['reward'],'status':evidence['status'],'fixed':evidence.get('fixed_replay',{}).get('status')}
print(json.dumps(results))
worker.terminate();worker.wait(timeout=5)
for server in servers: server.shutdown()
'''
    result = container(script)
    assert result["valid"]["reward"] == 1
    assert result["unrelated_shortcut"]["reward"] == 0
    assert result["unrelated_shortcut"]["fixed"] == "fixed_variant_leaks"
    assert result["forged"]["reward"] == 0


def test_author_sandbox_persists_edits_and_protects_evidence(tmp_path):
    from harbor_pipeline import author_debug
    for folder in ("target", "target-fixed", "poc", "inputs"):
        (tmp_path / folder).mkdir()
    (tmp_path / "inputs/evidence.txt").write_text("original")
    try:
        author_debug.start(tmp_path, kind="scratch", image="python:3.12-slim-bookworm", ttl=120)
        result = author_debug.execute(tmp_path, "scratch", "printf changed > /workspace/target/example.txt")
        assert result["ok"]
        assert (tmp_path / "target/example.txt").read_text() == "changed"
        assert author_debug.execute(tmp_path, "scratch", "cat /workspace/target/example.txt")["output"] == "changed"
        assert not author_debug.execute(tmp_path, "scratch", "printf bad > /workspace/inputs/evidence.txt")["ok"]
        assert (tmp_path / "inputs/evidence.txt").read_text() == "original"
    finally:
        author_debug.cleanup(tmp_path)


def test_generated_compose_runs_the_fixed_replay_on_an_isolated_network(tmp_path):
    """Exercise the generated topology and RPC, not a mocked verifier result."""
    from harbor_pipeline.generator import render_task
    from harbor_pipeline import fixtures
    from test_goal_families import _synthesis
    spec = fixtures.cve_spec()
    synthesis = _synthesis("secret_read")
    synthesis.target["files"]["app.py"] = '''from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
VERSION="{{REF}}"
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ('/health','/business'): body=b'ok'
        elif self.path=='/shortcut' or (self.path=='/secret' and VERSION=='v1.2.3'):
            body=Path('/opt/app/secret/token').read_bytes()
        else:
            self.send_error(403); return
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
'''
    def poc(path):
        return '#!/usr/bin/env python3\nimport os,urllib.request\ntry:\n print(urllib.request.urlopen("http://"+os.environ["TARGET_HOST"]+":8080' + path + '").read().decode())\nexcept Exception:\n pass\n'
    synthesis.poc["reference"] = poc("/secret")
    task = render_task(spec, scenario_name="synthesized", variant="vulnerable", synthesis=synthesis)
    target_dockerfile = 'FROM python:3.12-slim-bookworm\nWORKDIR /opt/app\nCOPY app.py /opt/app/app.py\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT ["sh","/entrypoint.sh"]\n'
    task.files["environment/target/Dockerfile"] = target_dockerfile
    task.files["tests/fixed-target/Dockerfile"] = target_dockerfile
    task.files["tests/Dockerfile"] = 'FROM python:3.12-slim-bookworm\nRUN useradd --create-home --shell /bin/sh replay\nCOPY . /tests\nRUN chmod 0755 /tests/test.sh\n'
    root = task.write(tmp_path)
    override = root / "tests/main.yaml"
    override.write_text('services:\n  main:\n    build: .\n    command: ["/tests/test.sh"]\n    volumes:\n      - ./submitted:/logs/artifacts/poc:ro\n')
    rendered = subprocess.run(['docker','compose','-f',str(root/'tests/docker-compose.yaml'),'-f',str(override),'config','--format','json'], capture_output=True,text=True,timeout=30)
    assert rendered.returncode == 0, rendered.stderr
    config = json.loads(rendered.stdout)
    for name in ("target", "target-fixed"):
        config["services"][name]["healthcheck"].update(
            test=["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"],
            interval="1s", timeout="3s", retries=30, start_period="1s")
    assert not set(config["services"]["main"]["networks"]) & set(config["services"]["target-fixed"]["networks"])
    compose = root / "tests/resolved.json"
    compose.write_text(json.dumps(config))
    project = "harbor-hardening-" + uuid.uuid4().hex[:10]
    prefix = ["docker", "compose", "-p", project, "-f", str(compose)]
    try:
        built = subprocess.run([*prefix,"build"],capture_output=True,text=True,timeout=180)
        assert built.returncode == 0, built.stderr[-4000:]
        for case, path, expected in (("normal", "/secret", 1), ("shortcut", "/shortcut", 0)):
            (root / "tests/submitted").write_text(poc(path))
            completed = subprocess.run([*prefix,"up","--abort-on-container-exit","--exit-code-from","main"],capture_output=True,text=True,timeout=120)
            assert completed.returncode == 0, completed.stderr[-3000:]
            output = tmp_path / (case + ".json")
            copied = subprocess.run([*prefix,"cp","main:/logs/verifier/evidence.json",str(output)],capture_output=True,text=True,timeout=30)
            assert copied.returncode == 0, copied.stderr
            evidence = json.loads(output.read_text())
            assert evidence["reward"] == expected, evidence
            assert "fixed_replay" in evidence
            subprocess.run([*prefix,"down","-v"],capture_output=True,timeout=60)
    finally:
        subprocess.run([*prefix,"down","-v","--rmi","local"],capture_output=True,timeout=60)
