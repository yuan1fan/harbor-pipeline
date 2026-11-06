"""Host preflight parsing and the user-network safety rule."""

import os
from types import SimpleNamespace

from harbor_pipeline import preflight


def test_parse_size_and_excluded_ranges():
    assert preflight.parse_size("1.5GB") == 1.5e9
    assert preflight.parse_size("512MB") == 512e6
    assert preflight.parse_size("n/a") == 0.0

    output = """协议 tcp 端口排除范围

开始端口    结束端口
----------    --------
      1514        1515     *
     50000       50059     *
"""
    ranges = preflight.parse_excluded_ranges(output)
    assert ranges == [(1514, 1515), (50000, 50059)]
    assert preflight.port_excluded(1515, ranges) is True
    assert preflight.port_excluded(55000, ranges) is False


def _fake_run(command, timeout=30):
    joined = " ".join(command)
    if "info" in command and "--format" in joined:
        return SimpleNamespace(returncode=0, stdout="28.3.2|21000000000|32\n", stderr="")
    if "system df" in joined:
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE\n"
                "Images          10        1         10GB      5GB (50%)\n"
                "Build Cache     2         0         1GB       1GB\n"
            ),
            stderr="",
        )
    if "ps -a" in joined:
        return SimpleNamespace(
            returncode=0, stdout="abc123 task__dead_env-target-1\n", stderr=""
        )
    if "images" in command:
        return SimpleNamespace(returncode=0, stdout="486MB\n1.7GB\n", stderr="")
    if "network ls" in joined:
        return SimpleNamespace(
            returncode=0,
            stdout="iris_backend\nsingle-node_default\ntask__dead_env_default\n",
            stderr="",
        )
    if command[0] == "netsh":
        return SimpleNamespace(returncode=0, stdout="1514 1515 *\n50000 50059 *\n", stderr="")
    return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")


def test_preflight_warns_about_user_networks_without_removing_them(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(preflight, "_run", _fake_run)

    result = preflight.run_preflight(
        output_dir=tmp_path,
        workers=2,
        trial_workers=2,
        required_ports=(1514, 1515),
        clean=False,
    )

    checks = {check["id"]: check for check in result["checks"]}
    assert checks["docker-daemon"]["status"] == "pass"
    assert checks["user-networks-dangling"]["status"] == "warn"
    assert "iris_backend" in checks["user-networks-dangling"]["detail"]
    assert checks["task-leftovers"]["status"] == "warn"
    # Port reservation is a Windows/WinNAT concern; Linux hosts have no netsh
    # check at all.
    if os.name == "nt":
        assert checks["port-exclusions"]["status"] == "pass"
    else:
        assert "port-exclusions" not in checks
    # A preflight without --clean must not delete anything.
    assert result["cleaned"] == {"containers": [], "networks": [], "images": []}


def test_preflight_fails_when_docker_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda _name: None)
    result = preflight.run_preflight(
        output_dir=tmp_path, workers=1, trial_workers=1
    )
    assert result["ok"] is False
    assert result["checks"][0]["id"] == "docker-daemon"
    assert result["checks"][0]["status"] == "fail"


def test_preflight_clean_calls_the_task_scoped_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(preflight, "_run", _fake_run)
    calls: list[bool] = []

    def fake_cleanup(*, images=False):
        calls.append(images)
        return {"containers": ["c"], "networks": ["n"], "images": []}

    monkeypatch.setattr(preflight, "prune_orphan_task_resources", fake_cleanup)
    result = preflight.run_preflight(
        output_dir=tmp_path,
        workers=1,
        trial_workers=1,
        required_ports=(1514, 1515),
        clean=True,
    )
    assert calls == [False]
    assert result["cleaned"]["containers"] == ["c"]
