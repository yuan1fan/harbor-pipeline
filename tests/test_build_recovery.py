"""Recover completed Docker exports without accepting stale/failed builds.

No Docker daemon is used: elapsed-time checks use a fake clock, and one smoke
test stops an owned Python child that simulates a stuck build CLI.
"""

import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from harbor_pipeline import backend, resources
from harbor_pipeline.errors import TaskError


IMAGE_ID = "sha256:" + "a" * 64
ATTEMPT_ID = "b" * 32
EXPORT_LOG = (
    "#10 exporting to image\n"
    "#10 exporting layers 1.0s done\n"
    "#10 naming to docker.io/example/target:latest done\n"
    "#10 unpacking to docker.io/example/target:latest 0.2s done\n"
    "#10 DONE 1.2s\n"
)


@pytest.fixture(autouse=True)
def isolated_resources():
    token = resources._POLICY.set({"slots": 0})
    yield
    resources._POLICY.reset(token)


@pytest.fixture
def build_env(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _docker: True)
    monkeypatch.setattr(backend, "inspect_image", lambda *a, **k: (IMAGE_ID, "amd64"))
    monkeypatch.setattr(backend, "dependency_lock", lambda _context: {})
    return dict(name="target", context=tmp_path, image_ref="example/target:latest",
                log_path=tmp_path / "build.log")


@pytest.fixture
def stalled_cli(monkeypatch):
    clock = SimpleNamespace(now=0.0)
    processes = []

    class Process:
        def __init__(self, command, *, stdout, **_kwargs):
            self.args = command
            self.returncode = None
            self.killed_at = None
            self.handle = stdout
            self.exit_at = None
            self.exit_code = 0
            self.on_wait = lambda: None
            processes.append(self)

        def wait(self, *, timeout):
            if self.returncode is not None:
                return self.returncode
            clock.now += timeout
            self.on_wait()
            if self.exit_at is not None and clock.now >= self.exit_at:
                self.returncode = self.exit_code
                return self.returncode
            raise subprocess.TimeoutExpired(self.args, timeout)

        def poll(self):
            return self.returncode

        def write(self, text):
            self.handle.write(text.encode("utf-8"))
            self.handle.flush()

    def kill(proc):
        proc.killed_at = clock.now
        proc.returncode = -9

    monkeypatch.setattr(backend, "time", SimpleNamespace(
        monotonic=lambda: clock.now, sleep=lambda delay: setattr(clock, "now", clock.now + delay)))
    monkeypatch.setattr(backend.subprocess, "Popen", Process)
    monkeypatch.setattr(backend, "_kill_tree", kill)
    return SimpleNamespace(clock=clock, processes=processes, Process=Process)


def _attempt_from_command(command):
    prefix = backend._BUILD_ATTEMPT_LABEL + "="
    return next(arg.removeprefix(prefix) for arg in command if arg.startswith(prefix))


def test_completed_build_recovers_early_with_current_image(build_env, stalled_cli, monkeypatch):
    inspections = []

    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    def inspect(command, **kwargs):
        proc = stalled_cli.processes[0]
        inspections.append((stalled_cli.clock.now, kwargs["timeout"]))
        assert command[:3] == ["docker", "image", "inspect"]
        return SimpleNamespace(returncode=0, stdout=IMAGE_ID + " " + _attempt_from_command(proc.args))

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    for budget in (900, 1800):
        stalled_cli.clock.now = 0
        stalled_cli.processes.clear()
        built = backend.build_image(**build_env, timeout_sec=budget, no_cache=True)
        proc = stalled_cli.processes[0]
        assert 15 <= proc.killed_at <= 20
        assert built.duration_sec < 30
        assert built.image_digest == IMAGE_ID
        assert "--no-cache" in proc.args
        assert "--progress=plain" in proc.args
        assert build_env["log_path"].with_suffix(".log.iid").read_text().strip() == IMAGE_ID
        log = build_env["log_path"].read_text()
        assert "RECOVERED_POST_EXPORT" in log
        assert "TIMEOUT" not in log
    assert len(inspections) == 2
    assert all(timeout <= 5 for _, timeout in inspections)


def test_grace_period_starts_after_a_long_build_exports(build_env, stalled_cli, monkeypatch):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write("#9 [final] RUN make\n")

        def progress():
            if stalled_cli.clock.now >= 600:
                proc.write(EXPORT_LOG)
                proc.on_wait = lambda: None

        proc.on_wait = progress
        return proc

    def inspect(*args, **kwargs):
        proc = stalled_cli.processes[0]
        return SimpleNamespace(returncode=0, stdout=IMAGE_ID + " " + _attempt_from_command(proc.args))

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    assert backend.build_image(**build_env, timeout_sec=900).image_digest == IMAGE_ID
    assert 615 <= stalled_cli.processes[0].killed_at <= 620


@pytest.mark.parametrize("output", [
    IMAGE_ID + " previous-attempt",  # Same tag, stale build.
    IMAGE_ID,                       # Legacy image without a build marker.
    "not-an-image-id " + ATTEMPT_ID,
    "",
])
def test_recovery_rejects_unproven_image(tmp_path, monkeypatch, output):
    log, iid = tmp_path / "build.log", tmp_path / "build.iid"
    log.write_text(EXPORT_LOG)
    monkeypatch.setattr(backend.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=output))
    assert backend._recover_image_after_export(
        "docker", "example/target:latest", iid, log, attempt_id=ATTEMPT_ID,
    ) is None
    assert not iid.exists()


@pytest.mark.parametrize("log_text", [
    "#4 [3/4] RUN make\n#4 still compiling\n",
    EXPORT_LOG.replace("#10 unpacking to docker.io/example/target:latest 0.2s done\n", ""),
    EXPORT_LOG.replace("0.2s done", "0.2s"),
    EXPORT_LOG.replace("#10 unpacking", "#11 unpacking"),
    EXPORT_LOG.replace("#10 DONE 1.2s\n", ""),
    EXPORT_LOG + "ERROR: failed to solve: manifest rejected\n",
])
def test_incomplete_or_failed_export_keeps_full_build_timeout(
    build_env, stalled_cli, monkeypatch, log_text,
):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(log_text)
        return proc

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", lambda *a, **k: pytest.fail("must not inspect an unfinished export"))
    with pytest.raises(TaskError) as caught:
        backend.build_image(**build_env, timeout_sec=60)
    assert caught.value.category.code == "build_error"
    assert stalled_cli.processes[0].killed_at == 60
    assert "TIMEOUT" in build_env["log_path"].read_text()
    assert "RECOVERED_POST_EXPORT" not in build_env["log_path"].read_text()


def test_stale_tag_and_iid_cannot_recover_even_at_full_timeout(build_env, stalled_cli, monkeypatch):
    iid = build_env["log_path"].with_suffix(".log.iid")
    iid.write_text(IMAGE_ID)

    def start(command, **kwargs):
        assert not iid.exists()
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=IMAGE_ID + " previous-attempt"))
    with pytest.raises(TaskError) as caught:
        backend.build_image(**build_env, timeout_sec=60)
    assert caught.value.category.code == "infra_error"
    assert caught.value.detail["post_export_hang"] is True
    assert stalled_cli.processes[0].killed_at == 60
    assert not iid.exists()


def test_unresponsive_inspect_is_bounded_and_does_not_accept_image(build_env, stalled_cli, monkeypatch):
    probes = []

    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    def inspect(command, *, timeout, **kwargs):
        probes.append((stalled_cli.clock.now, timeout))
        stalled_cli.clock.now += timeout
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    with pytest.raises(TaskError) as caught:
        backend.build_image(**build_env, timeout_sec=40)
    assert caught.value.category.code == "infra_error"
    assert stalled_cli.processes[0].killed_at == 40
    assert all(timeout <= 5 for _, timeout in probes)
    assert len(probes) <= 3  # Throttled live probes plus the final timeout fallback.


@pytest.mark.parametrize("exit_code", [0, 1])
def test_process_exit_during_probe_takes_precedence(build_env, stalled_cli, monkeypatch, exit_code):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    def inspect(*args, **kwargs):
        proc = stalled_cli.processes[0]
        proc.returncode = exit_code
        return SimpleNamespace(returncode=0, stdout=IMAGE_ID + " " + _attempt_from_command(proc.args))

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    if exit_code:
        with pytest.raises(TaskError) as caught:
            backend.build_image(**build_env)
        assert caught.value.category.code == "build_error"
    else:
        assert backend.build_image(**build_env).image_digest == IMAGE_ID
    assert stalled_cli.processes[0].killed_at is None
    assert "RECOVERED_POST_EXPORT" not in build_env["log_path"].read_text()


def test_late_export_error_during_inspect_is_not_success(build_env, stalled_cli, monkeypatch):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    def inspect(*args, **kwargs):
        proc = stalled_cli.processes[0]
        proc.write("ERROR: failed to solve: late export failure\n")
        return SimpleNamespace(returncode=0, stdout=IMAGE_ID + " " + _attempt_from_command(proc.args))

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    with pytest.raises(TaskError) as caught:
        backend.build_image(**build_env, timeout_sec=60)
    assert caught.value.category.code == "build_error"
    assert stalled_cli.processes[0].killed_at == 60
    assert not build_env["log_path"].with_suffix(".log.iid").exists()


def test_normal_build_exits_without_recovery_or_kill(build_env, stalled_cli, monkeypatch):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        proc.exit_at = 4
        proc.on_wait = lambda: build_env["log_path"].with_suffix(".log.iid").write_text(IMAGE_ID)
        return proc

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", lambda *a, **k: pytest.fail("normal exit needs no recovery probe"))
    assert backend.build_image(**build_env).image_digest == IMAGE_ID
    assert stalled_cli.processes[0].killed_at is None
    assert stalled_cli.clock.now == 4


def test_registry_retry_uses_new_identity_and_discards_previous_iid(build_env, monkeypatch):
    attempts = []
    iid = build_env["log_path"].with_suffix(".log.iid")

    def run(command, **kwargs):
        assert not iid.exists()
        attempts.append(_attempt_from_command(command))
        iid.write_text(IMAGE_ID)
        if len(attempts) == 1:
            return subprocess.CompletedProcess(command, 1, "503 Service Unavailable", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr(backend, "time", SimpleNamespace(monotonic=lambda: 0, sleep=lambda _: None))
    assert backend.build_image(**build_env).image_digest == IMAGE_ID
    assert len(attempts) == len(set(attempts)) == 2


def test_success_exit_without_new_iid_does_not_reuse_previous_build(build_env, monkeypatch):
    build_env["log_path"].with_suffix(".log.iid").write_text(IMAGE_ID)
    monkeypatch.setattr(backend, "_run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""))
    with pytest.raises(TaskError, match="valid immutable image ID") as caught:
        backend.build_image(**build_env)
    assert caught.value.category.code == "build_error"


def test_real_stalled_child_is_stopped_before_build_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "_EXPORT_POLL_SEC", 0.05)
    monkeypatch.setattr(backend, "_EXPORT_GRACE_SEC", 0.1)
    monkeypatch.setattr(backend, "daemon_available", lambda _: pytest.fail("must not reach the build timeout"))
    command = [sys.executable, "-u", "-c", f"import time; print({EXPORT_LOG!r}, flush=True); time.sleep(30)"]
    started = time.monotonic()
    result = backend._run(command, timeout=20, log_path=tmp_path / "child.log",
                          recover_export=lambda _remaining: IMAGE_ID)
    assert result.returncode == 0
    assert time.monotonic() - started < 10
    assert "RECOVERED_POST_EXPORT" in result.stdout
    assert "TIMEOUT" not in result.stdout


def test_failed_cli_cleanup_is_not_reported_as_success(build_env, stalled_cli, monkeypatch):
    def start(command, **kwargs):
        proc = stalled_cli.Process(command, **kwargs)
        proc.write(EXPORT_LOG)
        return proc

    def inspect(*args, **kwargs):
        proc = stalled_cli.processes[0]
        return SimpleNamespace(returncode=0, stdout=IMAGE_ID + " " + _attempt_from_command(proc.args))

    monkeypatch.setattr(backend.subprocess, "Popen", start)
    monkeypatch.setattr(backend.subprocess, "run", inspect)
    monkeypatch.setattr(backend, "_kill_tree", lambda _proc: None)
    with pytest.raises(TaskError, match="could not be stopped") as caught:
        backend.build_image(**build_env)
    assert caught.value.category.code == "infra_error"
    assert "RECOVERED_POST_EXPORT" not in build_env["log_path"].read_text()


@pytest.mark.parametrize("owns_group", [True, False])
def test_posix_cleanup_never_kills_the_parent_process_group(monkeypatch, owns_group):
    group_kills, child_kills = [], []
    monkeypatch.setattr(backend, "signal", SimpleNamespace(SIGKILL=9))
    monkeypatch.setattr(backend, "os", SimpleNamespace(
        name="posix", getpgid=lambda _pid: 123 if owns_group else 999,
        killpg=lambda pid, _signal: group_kills.append(pid)))
    backend._kill_tree(SimpleNamespace(pid=123, kill=lambda: child_kills.append(123)))
    assert group_kills == ([123] if owns_group else [])
    assert child_kills == ([] if owns_group else [123])
