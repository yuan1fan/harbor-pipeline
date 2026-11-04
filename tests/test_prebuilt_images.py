"""Validation probes pin prebuilt images; the release task stays portable."""

import tomllib
from pathlib import Path

from harbor_pipeline import fixtures
from harbor_pipeline.differential import MatrixStep, build_step_cases
from harbor_pipeline.generator import render_task
from harbor_pipeline.repair import POC_PATH


def _config(task) -> dict:
    return tomllib.loads(task.files["task.toml"])


def test_portable_task_has_no_image_pins():
    task = render_task(
        fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable"
    )
    config = _config(task)
    assert "docker_image" not in config["environment"]
    assert "environment" not in config["verifier"]
    compose = task.files["environment/docker-compose.yaml"]
    assert "image:" not in compose


def test_prebuilt_task_pins_agent_target_and_verifier():
    task = render_task(
        fixtures.cve_spec(),
        scenario_name="fixture",
        variant="vulnerable",
        prebuilt=True,
        revision=4,
    )
    config = _config(task)
    base = "harbor-pipeline/cve-2024-0001-vulnerable-r4"
    assert config["environment"]["docker_image"] == f"{base}-agent"
    assert config["verifier"]["environment"]["docker_image"] == f"{base}-verifier"
    assert f"image: {base}-target" in task.files["environment/docker-compose.yaml"]
    assert f"image: {base}-target" in task.files["tests/docker-compose.yaml"]


def test_fixed_variant_uses_its_own_image_tags():
    task = render_task(
        fixtures.cve_spec(),
        scenario_name="fixture",
        variant="fixed",
        prebuilt=True,
        revision=2,
    )
    config = _config(task)
    base = "harbor-pipeline/cve-2024-0001-fixed-r2"
    assert config["environment"]["docker_image"] == f"{base}-agent"
    assert config["verifier"]["environment"]["docker_image"] == f"{base}-verifier"
    assert f"image: {base}-target" in task.files["environment/docker-compose.yaml"]


def test_repaired_reference_propagates_to_solve_sh():
    repaired = "#!/bin/sh\necho REPAIRED\n"
    task = render_task(
        fixtures.cve_spec(),
        scenario_name="fixture",
        variant="vulnerable",
        probe="reference",
        overrides={POC_PATH: repaired},
    )
    assert task.files[POC_PATH] == repaired
    # The submitted artifact must use the repaired PoC, otherwise T03 can
    # never pass: the verifier's reference run and the artifact would diverge.
    assert "echo REPAIRED" in task.files["solution/solve.sh"]

    # The alternate probe keeps its own payload.
    alternate = render_task(
        fixtures.cve_spec(),
        scenario_name="fixture",
        variant="vulnerable",
        probe="alternate",
        overrides={POC_PATH: repaired},
    )
    assert "echo REPAIRED" not in alternate.files["solution/solve.sh"]


def test_step_cases_render_prebuilt_probes(tmp_path: Path):
    spec = fixtures.cve_spec()
    step = MatrixStep("t03-first", ("T03",), 1, True)
    cases = build_step_cases(
        spec,
        step=step,
        scenario_name="fixture",
        root=tmp_path / "matrix",
        network_mode="public",
        allowed_hosts=("target",),
        revision=5,
    )
    assert len(cases) == 1
    config = tomllib.loads(cases[0].task.files["task.toml"])
    assert config["environment"]["docker_image"].endswith("vulnerable-r5-agent")
    assert "vulnerable-r5-target" in cases[0].task.files["environment/docker-compose.yaml"]
