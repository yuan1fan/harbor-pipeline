"""Network wiring for the author scratch container and debug targets."""
import json
import subprocess

import pytest

from harbor_pipeline import author_debug
from harbor_pipeline.config import Settings


def _result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class FakeDocker:
    def __init__(self, workspace, *, networks=(), container=None):
        self.calls = []
        self.owner = author_debug._owner(workspace)
        self.networks = {name: self.owner for name in networks}
        self.container = container

    def run(self, args, *, timeout=30):
        self.calls.append(list(args))
        if args[:2] == ["network", "inspect"]:
            name = args[2]
            if name not in self.networks:
                return _result(1, stderr="not found")
            return _result(0, stdout=json.dumps([{
                "Name": name,
                "Labels": {author_debug.NETWORK_OWNER_LABEL: self.networks[name]},
            }]))
        if args[:2] == ["network", "create"]:
            self.networks[args[-1]] = self.owner
            return _result()
        if args[:2] == ["network", "connect"]:
            return _result()
        if args[:2] == ["network", "rm"]:
            self.networks.pop(args[2], None)
            return _result()
        if args[0] in {"run", "start", "stop", "rm"}:
            return _result()
        raise AssertionError(f"unexpected docker call: {args}")

    def calls_for(self, *prefix):
        return [call for call in self.calls if call[:len(prefix)] == list(prefix)]


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fake = FakeDocker(tmp_path)
    monkeypatch.setattr(author_debug, "_run", fake.run)
    monkeypatch.setattr(author_debug, "inspect", lambda _workspace, _kind: None)
    return tmp_path, fake


def test_author_sandbox_defaults_to_public_network_and_dev_image():
    settings = Settings()
    assert settings.author_sandbox_network == "bridge"
    assert settings.author_sandbox_image.endswith("-bookworm")


def test_scratch_gets_public_egress_and_candidate_debug_network(workspace):
    workspace_dir, fake = workspace
    author_debug.start(workspace_dir, kind="scratch", image="author:test", network="bridge")

    debug = author_debug._network_name(workspace_dir, author_debug.DEBUG_NETWORK)
    egress = author_debug._network_name(workspace_dir, author_debug.EGRESS_NETWORK)
    create = fake.calls_for("network", "create")
    assert any("--internal" in call and debug in call for call in create)
    assert any("--internal" not in call and egress in call for call in create)

    run = fake.calls_for("run", "-d")[0]
    assert run[run.index("--network") + 1] == egress
    assert run[run.index("--network-alias") + 1] == "author"
    connect = fake.calls_for("network", "connect")[0]
    assert debug in connect and "author" in connect and "--alias" in connect

    mounts = " ".join(run)
    assert "/workspace/research" in mounts
    assert "/workspace/tools" in mounts
    assert "/workspace/inputs" in mounts
    readonly = [r for r in run if "/workspace/inputs" in r]
    assert readonly and "readonly" in readonly[0]


def test_debug_target_joins_only_the_internal_debug_network(workspace):
    workspace_dir, fake = workspace
    author_debug.start(workspace_dir, kind="vulnerable", image="target:test")

    debug = author_debug._network_name(workspace_dir, author_debug.DEBUG_NETWORK)
    egress = author_debug._network_name(workspace_dir, author_debug.EGRESS_NETWORK)
    run = fake.calls_for("run", "-d")[0]
    assert run[run.index("--network") + 1] == debug
    assert run[run.index("--network-alias") + 1] == "target-vulnerable"
    assert not fake.calls_for("network", "connect")
    assert egress not in fake.networks


def test_stopped_container_is_resumed_without_losing_installed_tools(workspace, monkeypatch):
    workspace_dir, fake = workspace
    owner = author_debug._owner(workspace_dir)
    debug = author_debug._network_name(workspace_dir, author_debug.DEBUG_NETWORK)
    egress = author_debug._network_name(workspace_dir, author_debug.EGRESS_NETWORK)
    fake.networks[debug] = owner
    fake.networks[egress] = owner
    data = {
        "Config": {"Labels": {
            author_debug.OWNER_LABEL: owner,
            "harbor-pipeline.requested-image": "author:test",
        }},
        "State": {"Running": False},
        "HostConfig": {"NetworkMode": egress},
        "NetworkSettings": {"Networks": {egress: {}}},
    }
    monkeypatch.setattr(author_debug, "inspect", lambda _workspace, _kind: data)

    result = author_debug.start(workspace_dir, kind="scratch", image="author:test", network="bridge")

    assert result["reused"] is True and result["status"] == "resumed"
    assert fake.calls_for("start", author_debug._name(workspace_dir, "scratch"))
    assert not fake.calls_for("rm", "-f")
    assert not fake.calls_for("run", "-d")
    connect = fake.calls_for("network", "connect")[0]
    assert debug in connect


def test_legacy_network_none_container_is_recreated(workspace, monkeypatch):
    workspace_dir, fake = workspace
    owner = author_debug._owner(workspace_dir)
    data = {
        "Config": {"Labels": {
            author_debug.OWNER_LABEL: owner,
            "harbor-pipeline.requested-image": "target:test",
        }},
        "State": {"Running": True},
        "HostConfig": {"NetworkMode": "none"},
        "NetworkSettings": {"Networks": {}},
    }
    monkeypatch.setattr(author_debug, "inspect", lambda _workspace, _kind: data)

    author_debug.start(workspace_dir, kind="vulnerable", image="target:test")

    assert fake.calls_for("rm", "-f")
    run = fake.calls_for("run", "-d")[0]
    assert run[run.index("--network-alias") + 1] == "target-vulnerable"


def test_cleanup_removes_candidate_networks(workspace):
    workspace_dir, fake = workspace
    owner = author_debug._owner(workspace_dir)
    for suffix in (author_debug.DEBUG_NETWORK, author_debug.EGRESS_NETWORK):
        fake.networks[author_debug._network_name(workspace_dir, suffix)] = owner

    author_debug.cleanup(workspace_dir)

    removed = {call[2] for call in fake.calls_for("network", "rm")}
    assert removed == {
        author_debug._network_name(workspace_dir, author_debug.DEBUG_NETWORK),
        author_debug._network_name(workspace_dir, author_debug.EGRESS_NETWORK),
    }
    assert not fake.networks
