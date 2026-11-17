"""Local regressions for admission, background helpers and owned CLI trees."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from harbor_pipeline import agent, author_debug, author_tool, authoring, processes, resources
from harbor_pipeline.util import PipelineError, no_window_kwargs, read_json


@pytest.fixture(autouse=True)
def isolated_policy():
    token = resources._POLICY.set({"slots": 0})
    yield
    resources._POLICY.reset(token)


def _reclaimer(tmp_path, monkeypatch, *, recover=True, engine="linux|Docker Desktop"):
    state = SimpleNamespace(host=1024, now=1000, commands=[])
    config = {"slots": 2, "directory": str(tmp_path), "min_memory_mb": 4096,
              "min_disk_gb": 0, "disk_paths": [str(tmp_path)], "wait_sec": 1,
              "wsl_reclaim_memory": True}
    monkeypatch.setattr(resources, "os", SimpleNamespace(name="nt", environ={}, getpid=os.getpid))
    monkeypatch.setattr(resources, "available_memory_mb", lambda: state.host)
    monkeypatch.setattr(resources.shutil, "which", lambda _: "docker")
    monkeypatch.setattr(resources, "time", SimpleNamespace(time=lambda: state.now, monotonic=time.monotonic, sleep=time.sleep))

    def command(argv, **kwargs):
        state.commands.append(argv)
        if argv[:2] == ["docker", "context"]:
            text = "npipe:////./pipe/dockerDesktopLinuxEngine"
        elif argv[0] == "docker":
            text = engine
        elif argv[-1] == "/proc/meminfo":
            text = "MemAvailable: 18000000 kB\nCached: 9000000 kB\nBuffers: 1000000 kB\nShmem: 500000 kB\nDirty: 250000 kB\nWriteback: 100000 kB\n"
        else:
            assert argv[-1] == "echo 1 > /proc/sys/vm/drop_caches"
            if recover:
                state.host = 6000
            text = ""
        assert kwargs["timeout"] <= 5
        return SimpleNamespace(returncode=0, stdout=text)

    monkeypatch.setattr(resources.subprocess, "run", command)
    return config, state


def test_zero_used_slots_reclaim_then_recheck_host_before_admitting(tmp_path, monkeypatch):
    config, state = _reclaimer(tmp_path, monkeypatch)
    resources._POLICY.set(config)
    events = []
    token = resources._PROGRESS.set(lambda status, **details: events.append((status, details)))
    try:
        with resources.docker_work("build", poll_sec=0.001):
            assert state.host >= config["min_memory_mb"]
    finally:
        resources._PROGRESS.reset(token)
    record = read_json(tmp_path / "wsl-reclaim.json")
    assert record["wsl_available_mb"] > 17000
    assert record["clean_cache_estimate_mb"] == (10000000 - 850000) / 1024
    assert record["host_before_mb"] == 1024 and record["host_after_mb"] == 6000
    assert events[0][0] == "waiting"
    assert any("resource_waited_sec" in details for _, details in events)
    assert read_json(tmp_path / "docker-queue.json")["entries"] == []


def test_reclaim_is_bounded_and_never_substitutes_guest_memory_for_host_memory(tmp_path, monkeypatch):
    config, state = _reclaimer(tmp_path, monkeypatch, recover=False)
    for _ in range(4):
        resources.recover_wsl_memory(config, wait_id="same-stalled-job")
        state.now += 61
    assert sum(argv[-1] == "echo 1 > /proc/sys/vm/drop_caches" for argv in state.commands) == 2
    assert "available host memory" in resources.pressure_reason(config)


def test_reclaim_does_not_touch_wsl_for_another_engine(tmp_path, monkeypatch):
    config, state = _reclaimer(tmp_path, monkeypatch, engine="linux|Ubuntu 24.04")
    resources.recover_wsl_memory(config, wait_id="remote")
    assert len(state.commands) == 2
    assert read_json(tmp_path / "wsl-reclaim.json")["status"] == "not_local_desktop_linux"


def test_workspace_commands_are_serial_and_publish_terminal_result(tmp_path, monkeypatch):
    monkeypatch.setenv("HARBOR_AUTHOR_SESSION_RUN", "session-token")
    ctx = SimpleNamespace(workspace=tmp_path)
    with author_tool._helper_operation(ctx, "build") as complete:
        with pytest.raises(PipelineError, match="still running"):
            with author_tool._helper_operation(ctx, "probe"):
                pytest.fail("second command must not run")
        complete(0)
    record = authoring.helper_status(tmp_path)
    assert record["status"] == "succeeded"
    assert record["session_token"] == "session-token"
    with author_tool._helper_operation(ctx, "probe") as complete:
        complete(1)
    assert authoring.helper_status(tmp_path)["status"] == "failed"


def test_helper_state_failure_still_releases_workspace_lock(tmp_path, monkeypatch):
    real_write = author_tool.write_json
    calls = 0

    def write(path, value):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk failure on completion")
        real_write(path, value)

    monkeypatch.setattr(author_tool, "write_json", write)
    ctx = SimpleNamespace(workspace=tmp_path)
    with pytest.raises(OSError):
        with author_tool._helper_operation(ctx, "build") as complete:
            complete(0)
    with author_tool._helper_operation(ctx, "build") as complete:
        complete(0)


def test_owned_runner_reaps_orphans_but_not_an_unrelated_process(tmp_path):
    sentinel = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"], **no_window_kwargs())
    code = ("import subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
            "print(p.pid,flush=True);time.sleep(0.5)")
    try:
        result = processes.run_owned([sys.executable, "-u", "-c", code], timeout=10,
                                     log_path=tmp_path / "owned.log", **no_window_kwargs())
        child = int(result.stdout.strip())
        assert result.returncode == 0
        assert not psutil.pid_exists(child)
        assert sentinel.poll() is None
    finally:
        sentinel.kill()
        sentinel.wait(timeout=5)


def test_owned_runner_timeout_keeps_log_and_kills_child(tmp_path):
    code = "import os,time;print(os.getpid(),flush=True);time.sleep(60)"
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        processes.run_owned([sys.executable, "-u", "-c", code], timeout=0.5,
                            log_path=tmp_path / "timeout.log", **no_window_kwargs())
    pid = int(caught.value.output.splitlines()[0])
    assert not psutil.pid_exists(pid)
    assert "TIMEOUT" in (tmp_path / "timeout.log").read_text()


def test_tracker_does_not_kill_a_reused_pid(monkeypatch):
    monkeypatch.setattr(processes, "identity", lambda pid: 10.0)
    fake = SimpleNamespace(pid=12345678, poll=lambda: None)
    tree = processes.ProcessTree(fake)
    other = SimpleNamespace(create_time=lambda: 11.0, kill=lambda: pytest.fail("unrelated PID reuse must be protected"))
    monkeypatch.setattr(processes.psutil, "Process", lambda pid: other)
    monkeypatch.setattr(processes.psutil, "wait_procs", lambda victims, **kwargs: None)
    tree.kill()
    assert not tree.owned


def test_helper_budget_exhaustion_is_preserved_for_pipeline(tmp_path):
    ctx = SimpleNamespace(workspace=tmp_path)
    with pytest.raises(PipelineError):
        with author_tool._helper_operation(ctx, "build"):
            raise PipelineError("builds budget exhausted (8/8)")
    assert authoring.helper_status(tmp_path)["error_category"] == "budget_exhausted"


def test_author_waits_for_background_helper_without_spending_reasoning_timeout(tmp_path, monkeypatch):
    helper = tmp_path / "helper.py"
    helper.write_text('''import json,os,time,psutil
from pathlib import Path
p=Path('.harbor/job.json');p.parent.mkdir(exist_ok=True)
h={'pid':os.getpid(),'created':psutil.Process().create_time(),'session_token':os.environ['HARBOR_AUTHOR_SESSION_RUN'],'command':'build','status':'waiting'}
def save():
    q=p.with_suffix('.tmp');q.write_text(json.dumps({'helper':h}));q.replace(p)
save();time.sleep(2)
h['status']='succeeded';h['exit_code']=0;save()
''')
    cli = tmp_path / "fake_cli.py"
    cli.write_text('''import json,subprocess,sys,time
subprocess.Popen([sys.executable,'helper.py'])
time.sleep(.3)
print(json.dumps({'type':'result','subtype':'success','session_id':'same-session','num_turns':1,'result':'helper pending'}),flush=True)
''')
    runner = agent.ClaudeCodeAgent.__new__(agent.ClaudeCodeAgent)
    runner.profile = SimpleNamespace(role="author", trace_name="trace.jsonl")
    runner.settings = SimpleNamespace(timeout_sec=1)
    runner.config = SimpleNamespace(pipeline=SimpleNamespace(resource_wait_sec=5, command_timeout_sec=3))
    runner.command = lambda **kwargs: [sys.executable, "-u", str(cli)]
    monkeypatch.setattr(agent, "agent_environment", lambda **kwargs: dict(os.environ))
    monkeypatch.setattr(author_debug, "cleanup", lambda _: None)
    outcome = runner._run_once(prompt="test", workspace=tmp_path, settings_path=tmp_path / "settings.json",
                             contract="test", resume=None, extra_env=None, bare=True)
    assert outcome.status == "completed" and not outcome.timed_out
    assert outcome.helper_result["status"] == "succeeded"
    assert outcome.helper_result["pending_at_exit"] is True
    assert not processes.alive(outcome.helper_result["pid"], outcome.helper_result["created"])
