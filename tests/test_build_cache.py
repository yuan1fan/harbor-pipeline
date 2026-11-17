"""Image reuse compares actual inputs and immutable IDs; no Docker is started."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from harbor_pipeline import backend, build_cache, resources, runtime_identity
from harbor_pipeline.util import read_json, write_json


@pytest.fixture
def builds(tmp_path, monkeypatch):
    token = resources._POLICY.set({"slots": 0})
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM python:3.11-slim\nCOPY app.py /app.py\n")
    (context / "app.py").write_text("print('one')\n")
    images = {"python:3.11-slim": "sha256:" + "e" * 64}
    commands, tags, charges = [], [], []

    def run(command, **kwargs):
        commands.append(command)
        identity = f"sha256:{len(commands):064x}"
        images[identity] = identity
        images[command[command.index("-t") + 1]] = identity
        Path(command[command.index("--iidfile") + 1]).write_text(identity)
        kwargs["log_path"].write_text("successful build\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    def docker(command, **kwargs):
        if command[1:3] == ["image", "inspect"]:
            identity = images.get(command[-1], "")
            return subprocess.CompletedProcess(command, 0 if identity else 1, identity, "")
        if command[1:3] == ["image", "tag"]:
            assert command[3] in images
            images[command[4]] = command[3]
            tags.append(command[4])
            return subprocess.CompletedProcess(command, 0, "", "")
        pytest.fail(f"unexpected Docker call: {command}")

    monkeypatch.setattr(backend, "docker_binary", lambda: "docker")
    monkeypatch.setattr(backend, "daemon_available", lambda _: True)
    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr(backend, "inspect_image", lambda identity, **k: (images.get(identity, identity), "amd64"))
    monkeypatch.setattr(backend, "dependency_lock", lambda _: {})
    monkeypatch.setattr(backend, "image_label", lambda *a: "v1")
    monkeypatch.setattr(runtime_identity, "inspect_runtime", lambda *a, **k: {"verified": True, "dependencies": {}})
    monkeypatch.setattr(build_cache.subprocess, "run", docker)
    kwargs = dict(name="target", context=context, image_ref="demo:r1",
                  log_path=tmp_path / "logs" / "target.log", reuse=True,
                  on_build=lambda: charges.append(1))
    yield SimpleNamespace(kwargs=kwargs, context=context, images=images,
                          commands=commands, tags=tags, charges=charges)
    resources._POLICY.reset(token)


def test_same_inputs_retag_the_measured_image_without_build_budget(builds):
    first = backend.build_image(**builds.kwargs)
    again = backend.build_image(**{**builds.kwargs, "image_ref": "demo:r2"})
    assert again.reused and again.cached
    assert first.image_digest == again.image_digest
    assert builds.tags == ["demo:r2"]
    assert len(builds.commands) == len(builds.charges) == 1


@pytest.mark.parametrize("change", ["source", "dockerfile", "args", "ref", "base", "platform"])
def test_changed_build_input_invalidates_cached_image(builds, monkeypatch, change):
    first = backend.build_image(**builds.kwargs)
    kwargs = dict(builds.kwargs)
    if change == "source":
        (builds.context / "app.py").write_text("print('two')\n")
    elif change == "dockerfile":
        with (builds.context / "Dockerfile").open("a") as handle:
            handle.write("ENV OTHER=1\n")
    elif change == "args":
        kwargs["build_args"] = {"VERSION": "2"}
    elif change == "ref":
        kwargs["product_ref"] = "v2"
    elif change == "base":
        builds.images["python:3.11-slim"] = "sha256:" + "f" * 64
    else:
        monkeypatch.setenv("DOCKER_DEFAULT_PLATFORM", "linux/arm64")
    second = backend.build_image(**kwargs)
    assert not second.reused
    assert second.image_digest != first.image_digest
    assert len(builds.charges) == 2


def test_missing_image_and_corrupt_manifest_fall_back_to_build(builds):
    first = backend.build_image(**builds.kwargs)
    builds.images.pop(first.image_digest)
    second = backend.build_image(**builds.kwargs)
    assert second.image_digest != first.image_digest
    path = builds.kwargs["log_path"].with_name("target.log.image.json")
    entry = read_json(path)
    del entry["image"]["architecture"]
    write_json(path, entry)
    assert not backend.build_image(**builds.kwargs).reused
    path.write_text("{partial")
    assert not backend.build_image(**builds.kwargs).reused
    assert len(builds.commands) == 4


def test_cold_rebuild_never_reuses_images(builds):
    backend.build_image(**builds.kwargs)
    cold = backend.build_image(**builds.kwargs, no_cache=True)
    assert not cold.reused
    assert "--no-cache" in builds.commands[-1]
    assert len(builds.charges) == 2


def test_context_changed_during_build_is_not_checkpointed(builds, monkeypatch):
    original = backend._run

    def run(*args, **kwargs):
        result = original(*args, **kwargs)
        (builds.context / "app.py").write_text("changed while building")
        return result

    monkeypatch.setattr(backend, "_run", run)
    backend.build_image(**builds.kwargs)
    assert not builds.kwargs["log_path"].with_name("target.log.image.json").exists()


def test_author_state_with_removed_images_is_not_reused(builds, tmp_path):
    from harbor_pipeline import author_tool
    from harbor_pipeline.authoring import BUILD_STATE_FILE
    from harbor_pipeline.util import digest
    image = backend.build_image(**builds.kwargs)
    state = {"bundle_digest": digest({"task": "demo"}),
             "variants": {name: image.to_json() for name in ("vulnerable", "fixed")}}
    write_json(tmp_path / BUILD_STATE_FILE, state)
    ctx = SimpleNamespace(workspace=tmp_path)
    assert author_tool._load_build_state(ctx, {"task": "demo"})
    builds.images.pop(image.image_digest)
    assert not author_tool._load_build_state(ctx, {"task": "demo"})


@pytest.mark.parametrize("body", [
    "FROM ${UNKNOWN}\n", "# syntax=docker/dockerfile:1\nFROM scratch\n",
    "FROM scratch\nCOPY --from=untracked:latest /a /a\n",
    "FROM scratch\nRUN --mount=from=untracked:latest,target=/a cp /a/file /file\n",
])
def test_unresolved_build_inputs_disable_reuse(builds, body):
    (builds.context / "Dockerfile").write_text(body)
    backend.build_image(**builds.kwargs)
    assert not backend.build_image(**builds.kwargs).reused


def test_pipeline_repair_preserves_images_at_an_exhausted_build_budget(builds, tmp_path, monkeypatch):
    from harbor_pipeline import fixtures, pipeline as pipeline_mod
    from harbor_pipeline.config import Config, Settings
    from harbor_pipeline.generator import render_task
    pipeline = pipeline_mod.CvePipeline(
        config=Config(pipeline=Settings(docker_slots=0)), cve_id="CVE-2024-23334",
        scenario="fixture", run_id="cache", output_root=tmp_path,
    )
    pipeline._capabilities = SimpleNamespace(network_mode="public", harbor_version="0.23.0")
    pipeline.store.create()
    job = pipeline.store.load()
    job.state = "GENERATED"
    pipeline.store.save(job)
    spec = fixtures.cve_spec()
    task = render_task(spec, scenario_name="fixture", variant="vulnerable")
    task.write(pipeline.store.root)
    base_id = "sha256:" + "e" * 64
    builds.images["base-environment"] = base_id
    monkeypatch.setattr(pipeline_mod.author_probe, "ensure_base_images", lambda **k: {
        "environment": {"image_ref": "base-environment", "image_digest": base_id}})
    first = pipeline.build(spec, task)
    assert len(builds.commands) == 4
    ledger = pipeline._ledger()
    data = read_json(ledger.path)
    assert data["used"]["builds"] == 4
    data["limits"]["builds"] = 4
    write_json(ledger.path, data)
    job = pipeline.store.load()
    job.state, job.revision = "GENERATED", 2
    pipeline.store.save(job)
    pipeline._clear_derived()
    task.files["instruction.md"] += "\nClarified wording.\n"
    task.write(pipeline.store.root)
    second = pipeline.build(spec, task)
    assert len(builds.commands) == 4
    assert ledger.snapshot()["used"]["builds"] == 4
    for variant in ("vulnerable", "fixed"):
        assert first["variants"][variant]["target_digest"] == second["variants"][variant]["target_digest"]
        assert all(second["variants"][variant]["images"][name]["reused"] for name in ("target", "verifier"))


def test_changed_verifier_rebuilds_only_its_own_image(builds, tmp_path):
    from harbor_pipeline import fixtures
    from harbor_pipeline.generator import render_task
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    root = task.write(tmp_path / "probe")
    builds.images["base-environment"] = "sha256:" + "e" * 64
    kwargs = dict(task_dir=root, variant="vulnerable", revision=1, log_dir=tmp_path / "probe-logs",
                  tag_base="probe-r1", reuse=True, target_only=True, environment_image="base-environment")
    first = backend.build_task_images(**kwargs)
    assert len(builds.commands) == 2
    with (root / "tests" / "reference_poc.py").open("a") as handle:
        handle.write("\n# changed PoC\n")
    second = backend.build_task_images(**{**kwargs, "revision": 2, "tag_base": "probe-r2"})
    assert len(builds.commands) == 3
    assert second["images"]["target"]["reused"] is True
    assert second["images"]["verifier"]["reused"] is False
    assert first["target_digest"] == second["target_digest"]


def test_author_presentation_revision_reuses_both_target_images(builds, tmp_path, monkeypatch):
    from harbor_pipeline import author_tool, fixtures
    from harbor_pipeline.authoring import BUILD_STATE_FILE
    from harbor_pipeline.config import Config
    ctx = SimpleNamespace(workspace=tmp_path / "author", run_dir=tmp_path / "run",
                          cve_id="CVE-2024-23334", revision=1, config=Config(), evidence={}, discovery=None)
    bundle = {"presentation": {"hints": ["one"]}}
    charges = []
    monkeypatch.setattr(author_tool, "validate_workspace", lambda **k: (bundle, [], []))
    monkeypatch.setattr(author_tool, "_spec_for", lambda *a: fixtures.cve_spec())
    monkeypatch.setattr(author_tool, "_charge", lambda *a: charges.append(1))
    monkeypatch.setattr(author_tool.author_probe, "ensure_base_images", lambda **k: {})

    def render(ctx, *args, **kwargs):
        tasks = {}
        for variant in ("vulnerable", "fixed"):
            task = ctx.run_dir / f"r{ctx.revision}" / variant / "task"
            context = task / "environment" / "target"
            context.mkdir(parents=True, exist_ok=True)
            for name in ("Dockerfile", "app.py"):
                (context / name).write_text((builds.context / name).read_text())
            tasks[variant] = task
        return tasks

    monkeypatch.setattr(author_tool, "_render_variants", render)
    assert author_tool.cmd_build(ctx, quiet=True) == 0
    ctx.revision = 2
    bundle["presentation"]["hints"] = ["clearer wording"]
    assert author_tool.cmd_build(ctx, quiet=True) == 0
    assert len(builds.commands) == 2
    assert len(charges) == 1
    state = read_json(ctx.workspace / BUILD_STATE_FILE)
    assert all(image["reused"] for image in state["variants"].values())


def test_base_tracking_respects_global_arg_scope_and_cli_overrides():
    body = "ARG BASE=python:3.11\nFROM scratch AS builder\nARG BASE=wrong:latest\nFROM ${BASE}\n"
    assert build_cache._base_refs(body, {}) == ["python:3.11"]
    assert build_cache._base_refs(body, {"BASE": "python:3.12"}) == ["python:3.12"]
