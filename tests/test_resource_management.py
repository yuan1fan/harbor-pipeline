import json
import multiprocessing
import os
import time
from types import SimpleNamespace

import pytest

from harbor_pipeline import resources, storage
from harbor_pipeline.config import Settings, load_config
from harbor_pipeline.errors import TaskError
from harbor_pipeline.util import digest, write_json


@pytest.fixture(autouse=True)
def reset_policy():
    token = resources._POLICY.set({"slots": 0})
    yield
    resources._POLICY.reset(token)


def _policy(root, slots=2):
    return {"slots": slots, "directory": str(root), "min_memory_mb": 0,
            "min_disk_gb": 0, "wait_sec": 10, "disk_paths": [str(root)]}


def _parallel_work(root, events):
    resources._POLICY.set(_policy(root))
    with resources.docker_work("test", poll_sec=0.02):
        events.put((time.monotonic(), 1))
        time.sleep(0.2)
        events.put((time.monotonic(), -1))


def test_processes_share_two_slots(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    events = ctx.Queue()
    processes = [ctx.Process(target=_parallel_work, args=(str(tmp_path), events)) for _ in range(6)]
    for process in processes:
        process.start()
    try:
        for process in processes:
            process.join(20)
            assert process.exitcode == 0
        records = sorted(events.get(timeout=2) for _ in range(12))
        active = peak = 0
        for _, change in records:
            active += change
            peak = max(peak, active)
        assert peak == 2
        assert active == 0
        assert json.loads((tmp_path / "docker-queue.json").read_text())["entries"] == []
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)


def test_pressure_wait_is_infra_error_and_releases_queue(tmp_path, monkeypatch):
    policy = _policy(tmp_path)
    policy["wait_sec"] = 0.02
    resources._POLICY.set(policy)
    monkeypatch.setattr(resources, "pressure_reason", lambda _p: "disk below reserve")
    with pytest.raises(TaskError, match="disk below reserve"):
        with resources.docker_work("build", poll_sec=0.01):
            pytest.fail("work must not start")
    assert json.loads((tmp_path / "docker-queue.json").read_text())["entries"] == []


def test_dead_owner_reclaimed_nested_work_and_exception_release(tmp_path, monkeypatch):
    resources._POLICY.set(_policy(tmp_path, 1))
    write_json(tmp_path / "docker-queue.json", {"entries": [
        {"id": "stale", "pid": 123456789, "capacity": 1, "units": 1, "status": "running"}
    ]})
    monkeypatch.setattr(resources, "_pid_alive", lambda pid: pid == os.getpid())
    with pytest.raises(RuntimeError):
        with resources.docker_work("build"):
            with resources.docker_work("inspect"):
                raise RuntimeError("build failed")
    assert json.loads((tmp_path / "docker-queue.json").read_text())["entries"] == []


def test_harbor_concurrency_and_extra_override_are_bounded(tmp_path):
    resources._POLICY.set(_policy(tmp_path))

    @resources.limited("harbor", concurrency_arg="n_concurrent")
    def run(**kwargs):
        return kwargs

    actual = run(n_concurrent=10, extra={"n_concurrent_trials": 8})
    assert actual["n_concurrent"] == actual["extra"]["n_concurrent_trials"] == 2


def test_author_helper_inherits_absolute_policy(tmp_path, monkeypatch):
    from harbor_pipeline.agent import agent_environment
    resources._POLICY.set(_policy(tmp_path))
    child = agent_environment(workspace=tmp_path / "author", repo_root=tmp_path)
    monkeypatch.setenv(resources.ENV_NAME, child[resources.ENV_NAME])
    resources.configure(Settings(), inherit=True)
    assert resources.policy()["directory"] == str(tmp_path)
    assert resources.policy()["slots"] == 2


def test_resource_settings_reject_invalid_values(tmp_path):
    path = tmp_path / "config.toml"
    for value in ('docker_slots = -1', 'docker_slots = true', 'resource_wait_sec = 0', 'build_cache_keep_gb = -1'):
        path.write_text('[pipeline]\n' + value)
        with pytest.raises(Exception, match="must be"):
            load_config(path)


def _candidate(root, name="CVE-2026-12345", state="QUARANTINED"):
    path = root / name
    write_json(path / "state.json", {"state": state})
    return path


def _image(tag, identity="sha256:old", labels=None):
    return {"Id": identity, "RepoTags": [tag] if tag else [], "Config": {"Labels": labels or {}}}


def test_failed_build_without_manifest_and_old_revisions_are_collected(tmp_path):
    root = tmp_path / "runs" / "run1"
    _candidate(root)
    tags = [f"harbor-pipeline/cve-2026-12345-vulnerable-r{r}-target:latest" for r in (1, 2, 3)]
    images = [_image(t, f"sha256:{i}") for i, t in enumerate(tags)]
    images += [_image("harbor-pipeline/base-environment:shared"), _image("another-project:latest")]
    plan = storage.plan_cleanup(root, images, set())
    assert [item["ref"] for item in plan["remove"]] == tags


def test_protect_release_and_all_containers_and_live_peer(tmp_path):
    root = tmp_path / "runs" / "run1"
    candidate = _candidate(root, state="RELEASED")
    write_json(candidate / "image-set.json", {"images": {"target": {"image_digest": "sha256:release"}}})
    images = [_image(f"harbor-pipeline/cve-2026-12345-vulnerable-r{i}-target:latest", identity)
              for i, identity in enumerate(("sha256:release", "sha256:used", "sha256:old"), 1)]
    plan = storage.plan_cleanup(root, images, {"sha256:used"})
    assert [item["image_id"] for item in plan["remove"]] == ["sha256:old"]
    _candidate(root.parent / "run2", state="GENERATED")
    assert storage.plan_cleanup(root, images, set())["remove"] == []


def test_dangling_owned_builds_and_other_run_ownership(tmp_path):
    root = tmp_path / "runs" / "run1"
    candidate = _candidate(root)
    own = {storage.OWNER: digest(str(candidate.resolve()))}
    images = [_image(None, "sha256:dangling", own),
              _image("harbor-pipeline/rebuild-test-0-fixed-target:latest", "sha256:rebuild", own),
              _image("harbor-pipeline/cve-2026-12345-vulnerable-r1-target:latest", "sha256:foreign", {storage.OWNER: "other"})]
    plan = storage.plan_cleanup(root, images, set())
    assert {i["image_id"] for i in plan["remove"]} == {"sha256:dangling", "sha256:rebuild"}
    assert plan["skip"][0]["reason"] == "owned by another run"


def test_cleanup_refuses_retagged_image(tmp_path, monkeypatch):
    root = tmp_path / "runs" / "run1"
    _candidate(root)
    img = _image("harbor-pipeline/cve-2026-12345-vulnerable-r1-target:latest")
    monkeypatch.setattr(storage, "inventory", lambda: ([img], set()))
    monkeypatch.setattr(storage, "_json_command", lambda args: [{"Id": "sha256:new"}])
    monkeypatch.setattr(storage, "_docker", lambda args: pytest.fail("no deletion authorized"))
    result = storage.cleanup_run(root, apply=True)
    assert not result["removed"]
    assert result["errors"][0]["reason"] == "identity changed"


def test_default_cleanup_is_preview_only(tmp_path, monkeypatch):
    root = tmp_path / "runs" / "run1"
    _candidate(root)
    monkeypatch.setattr(storage, "inventory", lambda: ([_image("harbor-pipeline/cve-2026-12345-fixed-r1-target:latest")], set()))
    monkeypatch.setattr(storage, "_docker", lambda args: pytest.fail("preview cannot delete"))
    assert len(storage.cleanup_run(root)["remove"]) == 1
    assert not (root / "storage-cleanup.json").exists()


def test_replaced_build_cleanup_preserves_named_used_and_released(tmp_path, monkeypatch):
    root = tmp_path / "runs" / "run1"
    candidate = _candidate(root, state="GENERATED")
    owner = digest(str(candidate.resolve()))
    write_json(candidate / "release" / "build-manifest.json", {"image_digest": "sha256:released"})
    removed = []

    def docker(args, **kwargs):
        if args[:2] == ["image", "ls"]:
            assert f"label={storage.OWNER}={owner}" in args
            return SimpleNamespace(returncode=0, stdout="sha256:old sha256:named sha256:used sha256:released")
        if args[:2] == ["ps", "-aq"]:
            return SimpleNamespace(returncode=0, stdout="container" if args[-1].endswith(":used") else "")
        assert args[:2] == ["image", "rm"]
        removed.append(args[-1])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(storage, "_docker", docker)
    monkeypatch.setattr(storage, "_json_command", lambda args: [_image(
        "keep:latest" if args[-1].endswith(":named") else None, args[-1], {storage.OWNER: owner})])
    assert storage.cleanup_replaced_images(candidate) == ["sha256:old"]
    assert removed == ["sha256:old"]
