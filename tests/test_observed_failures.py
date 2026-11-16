"""Small regressions from completed scale-100-open-20261108 candidates.

These replay the failing stage without spending another author/solver session.
"""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import threading
import time

import pytest

from harbor_pipeline import backend, discovery, solver_review
from harbor_pipeline.config import Config
from harbor_pipeline.errors import TaskError


@pytest.fixture(autouse=True)
def no_host_resource_queue():
    from harbor_pipeline import resources
    token = resources._POLICY.set({"slots": 0})
    yield
    resources._POLICY.reset(token)


@pytest.mark.parametrize("output", [
    # CVE-2026-119705, CVE-2026-19040 and CVE-2026-2207.
    'ERROR: error during connect: Head "http://dockerDesktopLinuxEngine/_ping": '
    'open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.',
    # CVE-2026-22200.
    'ERROR: failed to build: failed to receive status: rpc error: code = Unavailable '
    'desc = error reading from server: EOF',
])
def test_docker_connection_failures_are_not_author_repair_requests(tmp_path, monkeypatch, output):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "_run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr=output))
    with pytest.raises(TaskError) as caught:
        backend.build_image(name="base-verifier", context=tmp_path,
                            image_ref="test", log_path=tmp_path / "build.log")
    assert caught.value.category.code == "infra_error"
    assert caught.value.category.auto_repairable is False


def test_bad_dockerfile_remains_a_repairable_build_error(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("not a dockerfile\n")
    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "_run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="Dockerfile parse error: unknown instruction: NOT"))
    with pytest.raises(TaskError) as caught:
        backend.build_image(name="target", context=tmp_path, image_ref="test", log_path=tmp_path / "build.log")
    assert caught.value.category.code == "build_error"
    assert caught.value.category.auto_repairable is True


def test_unresponsive_daemon_never_starts_a_30_minute_build(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: False)
    monkeypatch.setattr(backend, "_run", lambda *a, **k: pytest.fail("must fail before starting a build"))
    with pytest.raises(TaskError) as caught:
        backend.build_image(name="base-verifier", context=tmp_path, image_ref="test", log_path=tmp_path / "build.log")
    assert caught.value.category.code == "infra_error"


@pytest.mark.parametrize("available, category", [(True, "build_error"), (False, "infra_error")])
def test_build_timeout_checks_daemon_before_deciding_to_repair(tmp_path, monkeypatch, available, category):
    class Process:
        calls = 0
        returncode = None
        def wait(self, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("docker", 1)
            self.returncode = 0
            return 0
        def poll(self):
            return self.returncode

    monkeypatch.setattr(backend.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(backend, "_kill_tree", lambda _proc: None)
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: available)
    with pytest.raises(TaskError) as caught:
        backend._run(["docker", "build"], timeout=1, log_path=tmp_path / "timeout.log")
    assert caught.value.category.code == category


def test_build_output_is_visible_before_process_finishes_and_tail_is_bounded(tmp_path):
    path = tmp_path / "live.log"
    outcome = []
    command = [sys.executable, "-c", "import time;print('BUILD_PROGRESS',flush=True);time.sleep(2);print('x'*150000)"]
    thread = threading.Thread(target=lambda: outcome.append(backend._run(command, timeout=10, log_path=path)))
    thread.start()
    try:
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if path.exists() and b"\nBUILD_PROGRESS\n" in path.read_bytes().replace(b"\r\n", b"\n"):
                break
            time.sleep(0.02)
        assert thread.is_alive(), "progress must be observable while the build is running"
        assert b"\nBUILD_PROGRESS\n" in path.read_bytes().replace(b"\r\n", b"\n")
    finally:
        thread.join(12)
    assert not thread.is_alive()
    assert outcome[0].returncode == 0
    assert len(outcome[0].stdout) <= 100_000
    assert path.stat().st_size > 150_000


def test_windows_localized_taskkill_output_does_not_break_timeout_cleanup(monkeypatch):
    monkeypatch.setattr(backend, "os", SimpleNamespace(name="nt"))
    fallback = []
    def taskkill(_args, **kwargs):
        # The observed b3 byte is valid GBK output but invalid strict UTF-8.
        b"\xb3\xc9\xb9\xa6".decode("utf-8", errors=kwargs.get("errors", "strict"))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(backend.subprocess, "run", taskkill)
    backend._kill_tree(SimpleNamespace(pid=12345, kill=lambda: fallback.append(True)))
    assert not fallback


def test_empty_successful_patch_uses_existing_api_fallback(tmp_path):
    # CVE-2026-10130: HTTP success saved a zero-byte upstream-commit file.
    sha = "e6a49f508191d0f1bdad0f146da43819e7849f18"
    url = f"https://github.com/FalkorDB/QueryWeaver/commit/{sha}.patch"
    calls = []

    class Collector:
        run_dir = tmp_path

        def add(self, attempt, *_args):
            calls.append(attempt)
            path = tmp_path / f"source-{len(calls)}.txt"
            path.write_text("" if len(calls) == 1 else f'{{"sha":"{sha}","files":[{{"patch":"+fixed"}}]}}')
            return {"id": f"src-{len(calls)}", "status": "ok", "local_path": path.name}

    notes = []
    actual_sha, source_id = discovery._fetch_fix_commit(Collector(), [url], notes)
    assert actual_sha == sha
    assert source_id == "src-2"
    assert calls[-1].startswith("https://api.github.com/repos/")
    assert any("empty" in note.lower() for note in notes)


def test_all_empty_patches_cannot_be_used_as_fix_evidence(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("")
    collector = SimpleNamespace(run_dir=tmp_path, add=lambda *_args: {
        "id": "empty", "status": "ok", "local_path": path.name})
    actual = discovery._fetch_fix_commit(collector, [
        "https://github.com/FalkorDB/QueryWeaver/commit/" + "a" * 40], [])
    assert actual == (None, None)


def test_commit_api_requests_json_when_patch_media_is_empty():
    from harbor_pipeline.sources import _request_headers
    from harbor_pipeline.config import SourceSettings
    headers = _request_headers(SourceSettings(), "https://api.github.com/repos/FalkorDB/QueryWeaver/commits/" + "a" * 40)
    assert headers["Accept"] == "application/vnd.github+json"


def test_failed_solver_auth_stops_before_reviewer_and_author(tmp_path, monkeypatch):
    # CVE-2026-119653: the recorded exception_type was ignored by review flow.
    monkeypatch.setattr(solver_review, "build_provider", lambda *_args: pytest.fail("reviewer must not be called"))
    solver = {"attempts": 1, "successes": 0, "trials": [{
        "reward": None, "failure_type": "agent_exception",
        "exception": {"exception_type": "AgentAuthenticationError", "exception_message": "authentication failed"},
    }]}
    with pytest.raises(TaskError) as caught:
        solver_review.review_task(SimpleNamespace(files={}), solver, Config())
    assert caught.value.category.code == "infra_error"
    assert "AgentAuthenticationError" in str(caught.value)


def test_valid_unsolved_solver_can_still_be_reviewed(monkeypatch):
    # A real zero reward is different from a failed authentication/setup.
    solver_review.require_valid_solver({"trials": [{"reward": 0.0, "exception": None}]})


def test_benchmark_keeps_the_harbor_exception_type(tmp_path):
    from harbor_pipeline.benchmark import _trial_record
    from harbor_pipeline.harbor_adapter import TrialOutcome
    trial = TrialOutcome(trial_name="saved-solver", task_path=str(tmp_path), task_name="task",
                         trial_dir=tmp_path, reward=None,
                         exception={"exception_type": "AgentAuthenticationError"}, evidence=None,
                         started_at=None, finished_at=None, duration_sec=0.1)
    assert _trial_record(trial)["failure_type"] == "AgentAuthenticationError"


def test_large_dependency_inventory_cannot_hide_available_fix_from_reviewer(tmp_path):
    # CVE-2026-21894/27498 each had >420k metadata chars before the 90k cutoff.
    spec = {"product": {"name": "n8n"}, "fix_basis": {"source_id": "fix"}}
    for name, body in (("other", "x" * 20_000), ("fix", "the available upstream patch fixes the real node")):
        (tmp_path / name).write_text(body)
    sources = [{"id": "other", "status": "ok", "source_type": "other", "url": "https://example.invalid/info", "local_path": "other"},
               {"id": "fix", "status": "ok", "source_type": "upstream_commit", "url": "https://example.invalid/fix", "local_path": "fix"}]
    dependencies = {f"transitive-{i}": "1.2.3" for i in range(20_000)}
    dependencies["n8n"] = "2.2.1"
    images = {"variants": {"vulnerable": {"target_digest": "sha256:test", "runtime_identity": {
        "image": "sha256:test", "verified": True, "dependencies": dependencies}}}}
    context = solver_review.build_evidence_context(spec, images, {"sources": sources}, tmp_path)
    assert len(context) < 90_000
    assert "the available upstream patch" in context[:90_000]
    assert context.index("### fix") < context.index("### other")
    assert '"version": "2.2.1"' in context
    assert "transitive-19999" not in context


def test_xss_runtime_installs_python_package_matching_browser_image():
    # CVE-2026-15920: official image supplied browsers, not the Python package.
    from harbor_pipeline import goals
    asset = Path(__file__).parents[1] / "harbor_pipeline/assets/base_bot.Dockerfile"
    assert asset.is_file()
    text = asset.read_text()
    assert "mcr.microsoft.com/playwright/python:v1.48.0-jammy" in text
    assert "playwright==1.48.0" in text
    assert goals.BOT_IMAGE.startswith("harbor-pipeline/base-bot:")


def _post_export_log(tmp_path, *, fatal=False):
    log = tmp_path / "build.log"
    text = (
        "#10 exporting layers 1.0s done\n"
        "#10 naming to docker.io/example/target:latest done\n"
        "#10 unpacking to docker.io/example/target:latest 0.2s done\n"
        "#10 DONE 1.2s\n"
    )
    if fatal:
        text += "ERROR: failed to solve: manifest rejected\n"
    log.write_text(text + "\nTIMEOUT\n", encoding="utf-8")
    return log


def test_post_export_timeout_recovers_the_tagged_image(tmp_path, monkeypatch):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    log = _post_export_log(tmp_path)
    image_id = "sha256:" + "a" * 64

    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "_run", lambda *args, **kwargs: (_ for _ in ()).throw(
        TaskError("build_error", "Build exceeded 1s: docker build")))
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=image_id + "\n", stderr=""))
    monkeypatch.setattr(backend, "inspect_image", lambda *args, **kwargs: (image_id, "amd64"))
    monkeypatch.setattr(backend, "dependency_lock", lambda _context: {})

    built = backend.build_image(
        name="target", context=context, image_ref="example/target:latest",
        log_path=log, timeout_sec=1,
    )
    assert built.image_digest == image_id
    assert (log.parent / "build.log.iid").read_text(encoding="ascii").strip() == image_id


def test_post_export_timeout_without_a_tag_is_infra_error(tmp_path, monkeypatch):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    log = _post_export_log(tmp_path)

    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "_run", lambda *args, **kwargs: (_ for _ in ()).throw(
        TaskError("build_error", "Build exceeded 1s: docker build")))
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="No such image"))

    with pytest.raises(TaskError) as caught:
        backend.build_image(
            name="target", context=context, image_ref="example/target:latest",
            log_path=log, timeout_sec=1,
        )
    assert caught.value.category.code == "infra_error"
    assert caught.value.detail.get("post_export_hang") is True


def test_failed_export_timeout_remains_a_build_error(tmp_path, monkeypatch):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    log = _post_export_log(tmp_path, fatal=True)

    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "_run", lambda *args, **kwargs: (_ for _ in ()).throw(
        TaskError("build_error", "Build exceeded 1s: docker build")))

    with pytest.raises(TaskError) as caught:
        backend.build_image(
            name="target", context=context, image_ref="example/target:latest",
            log_path=log, timeout_sec=1,
        )
    assert caught.value.category.code == "build_error"
