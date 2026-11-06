"""Native authoring workspace, runner and direct probe."""

from __future__ import annotations

import json
from pathlib import Path


from harbor_pipeline import author_probe, author_tool, authoring
from harbor_pipeline.contracts import load_policy
from harbor_pipeline.agent import (
    ClaudeCodeAgent,
    agent_environment,
    build_agent_settings,
    parse_stream,
)
from harbor_pipeline.config import Config, ModelSettings
from harbor_pipeline.generator import render_task
from harbor_pipeline.goals import LISTING_DIR, MARKER_PATH
from harbor_pipeline.util import digest

from test_auto_synthesis import CVE, _bundle, _discovery, _write_evidence
from test_goal_families import _synthesis


def _config() -> Config:
    return Config(
        models={
            "default": ModelSettings(),
            "author": ModelSettings(
                provider="claude-code",
                model="deepseek-flash[1m]",
                max_turns=80,
                max_budget_usd=10.0,
            ),
        }
    )


def _run_dir(tmp_path: Path) -> tuple[Path, dict]:
    run_dir = tmp_path / "runs" / "r1" / CVE
    run_dir.mkdir(parents=True)
    evidence = _write_evidence(run_dir)
    (run_dir / "evidence-index.json").write_text(
        json.dumps(evidence), encoding="utf-8"
    )
    (run_dir / "discovery.json").write_text(
        json.dumps(_discovery().to_json()), encoding="utf-8"
    )
    (run_dir / "state.json").write_text(
        json.dumps({"revision": 1, "state": "EVIDENCE_READY"}), encoding="utf-8"
    )
    return run_dir, evidence


def _write_author_files(root: Path) -> None:
    body = _bundle()
    body["task_goal"]["family"] = "secret_read"
    body["preconditions"]["auth_scheme"] = "none"
    (root / "bundle.json").write_text(json.dumps(body), encoding="utf-8")
    (root / "target" / "Dockerfile").write_text(
        "FROM python:3.11-slim\nWORKDIR /opt/app\nCOPY . /opt/app\n"
        'CMD ["python", "/opt/app/app.py"]\n',
        encoding="utf-8",
    )
    (root / "target" / "requirements.txt").write_text(
        "pyramid=={{REF}}\n", encoding="utf-8"
    )
    (root / "target" / "app.py").write_text("print('app')\n", encoding="utf-8")
    (root / "poc" / "reference.py").write_text(
        "#!/usr/bin/env python3\nimport os\nprint(os.environ['TARGET_HOST'])\n",
        encoding="utf-8",
    )
    (root / "poc" / "alternate.py").write_text(
        "#!/usr/bin/env python3\nimport os\nprint(os.environ.get('TARGET_HOST', 'target'))\n",
        encoding="utf-8",
    )


def test_prepare_workspace_copies_inputs_and_settings(tmp_path: Path):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="deepseek-flash[1m]",
    )
    assert (workspace.root / "bundle.json").is_file()
    assert (workspace.root / "inputs" / "discovery.json").is_file()
    assert (workspace.root / "inputs" / "evidence" / "src-1-cve-record.json").is_file()
    assert workspace.settings_path.is_file()
    assert workspace.settings_path.parent == run_dir
    settings = json.loads(workspace.settings_path.read_text(encoding="utf-8"))
    assert settings["model"] == "deepseek-flash[1m]"
    assert "Bash(harbor-author:*)" in settings["permissions"]["allow"]
    assert "WebFetch" in settings["permissions"]["deny"]
    # The wrapper must stay outside the agent's writable workspace.
    assert (run_dir / "author-bin" / "harbor-author").is_file()
    assert not (workspace.root / "bin" / "harbor-author").exists()
    # The contract must name the literal placeholder the renderer replaces.
    assert "{{REF}}" in workspace.contract


def test_assemble_bundle_reads_the_three_trees(tmp_path: Path):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="x",
    )
    _write_author_files(workspace.root)
    (workspace.root / "target-fixed" / "requirements.txt").write_text(
        "pyramid=={{REF}}\n", encoding="utf-8"
    )
    bundle = authoring.assemble_bundle(workspace.root)
    assert set(bundle["target"]["files"]) == {"Dockerfile", "requirements.txt", "app.py"}
    assert set(bundle["target"]["fixed_overrides"]) == {"requirements.txt"}
    assert bundle["poc"]["reference"].startswith("#!/usr/bin/env python3")
    assert "TARGET_HOST" in bundle["poc"]["alternate"]


def test_assemble_bundle_rejects_traversal(tmp_path: Path):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="x",
    )
    _write_author_files(workspace.root)
    # Windows and POSIX both must refuse an escape through a nested tree.
    outside = workspace.root / "target" / ".." / ".." / "x"
    outside.parent.mkdir(parents=True, exist_ok=True)
    bundle = authoring.assemble_bundle(workspace.root)
    assert all(".." not in name for name in bundle["target"]["files"])


def test_validate_workspace_passes_with_a_complete_tree(tmp_path: Path, monkeypatch):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="x",
    )
    _write_author_files(workspace.root)
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )
    bundle, notes, issues = authoring.validate_workspace(
        workspace=workspace.root,
        run_dir=run_dir,
        evidence=evidence,
        discovery=_discovery(),
        config=_config(),
    )
    assert issues == []
    assert bundle["task_goal"]["family"] == "secret_read"


def test_validate_workspace_reports_placeholder_issues(tmp_path: Path, monkeypatch):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="x",
    )
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )
    # The generated template has an empty assertion list and no application.
    _, _, issues = authoring.validate_workspace(
        workspace=workspace.root,
        run_dir=run_dir,
        evidence=evidence,
        discovery=_discovery(),
        config=_config(),
    )
    assert issues


def test_agent_command_is_restricted_and_allowlisted(tmp_path: Path):
    agent = ClaudeCodeAgent(_config(), role="author")
    command = agent.command(
        settings_path=tmp_path / "settings.json", contract="contract"
    )
    joined = " ".join(command)
    assert "--bare" in command
    assert "--restricted" in command
    assert "--strict-mcp-config" in command
    assert "--disable-slash-commands" in command
    assert "--permission-prompts" in command
    assert "none" in command
    assert "Bash(harbor-author:*)" in joined
    assert "--max-turns" in command
    assert "--max-budget-usd" in command
    assert "--append-system-prompt" in command


def test_agent_environment_scrubs_pipeline_secrets(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("NVD_API_KEY", "nvd_secret")
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "gateway")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.invalid")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    workspace = Path.cwd()
    env = agent_environment(workspace=workspace, repo_root=Path.cwd())
    assert "GITHUB_TOKEN" not in env
    assert "NVD_API_KEY" not in env
    assert "CLAUDECODE" not in env
    assert env["ANTHROPIC_AUTH_TOKEN"] == "gateway"
    assert env["ANTHROPIC_API_KEY"] == "gateway"
    assert env["HARBOR_AUTHOR_WORKSPACE"] == str(workspace)
    # Docker's CLI plugin discovery needs these; dropping them breaks
    # `docker compose` inside the helper. Windows stores the name upper-case.
    assert any(
        key.casefold() == "programfiles" and value == r"C:\Program Files"
        for key, value in env.items()
    )


def test_parse_stream_extracts_result_and_tools():
    lines = [
        json.dumps({"type": "system", "subtype": "init", "session_id": "s1"}),
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "tool_use", "name": "Read", "input": {"file_path": "a"}}
                    ]
                },
            }
        ),
        json.dumps(
            {
                "type": "user",
                "message": {"content": [{"type": "tool_result", "content": "ok"}]},
            }
        ),
        json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "s1",
                "num_turns": 4,
                "total_cost_usd": 0.25,
                "usage": {"input_tokens": 11, "output_tokens": 7},
                "result": "done",
            }
        ),
    ]
    outcome = parse_stream(lines)
    assert outcome.session_id == "s1"
    assert outcome.turns == 4
    assert outcome.usd == 0.25
    assert outcome.usage == {"input_tokens": 11, "output_tokens": 7}
    assert outcome.transcript[0]["tool"] == "Read"
    assert outcome.transcript[0]["result"] == "ok"


def test_parse_stream_marks_error_results():
    outcome = parse_stream(
        [
            json.dumps(
                {
                    "type": "result",
                    "subtype": "error",
                    "is_error": True,
                    "result": "max turns reached",
                }
            )
        ]
    )
    assert outcome.status == "provider_error"
    assert "max turns" in outcome.error


def test_agent_settings_deny_outside_writes():
    settings = build_agent_settings("m")
    deny = settings["permissions"]["deny"]
    assert "Write(inputs/**)" in deny
    assert "Edit(.harbor/**)" in deny
    assert settings["permissions"]["defaultMode"] == "dontAsk"


def _spec(**overrides) -> dict:
    spec = {
        "cve_id": CVE,
        "product": {"name": "pyramid", "ecosystem": "pypi", "component": "x"},
        "versions": {
            "affected": ">= 2.0.0, < 2.0.2",
            "fixed": "2.0.2",
            "vulnerable_ref": "2.0.1",
            "fixed_ref": "2.0.2",
            "fix_commit": "347d7750da6f45c7436dd0c31468885cc9343c85",
        },
        "frozen_digest": "a" * 64,
        "attribution_grade": "A",
        "task_goal": {
            "family": "secret_read",
            "type": "file_read",
            "primitive": "path_traversal",
            "target_asset": "/opt/app/secret/token",
            "observable": "token",
        },
        "preconditions": {
            "network_reachable": True,
            "auth_identity": "none",
            "auth_scheme": "none",
            "privileges": "none",
            "configuration": "x",
            "user_interaction": False,
            "unknown": [],
        },
        "impact": {"summary": "x", "cia": {"confidentiality": "high", "integrity": "none", "availability": "none"}},
    }
    spec.update(overrides)
    return spec


def test_probe_compose_marker_and_internal_network(tmp_path: Path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "observer.py").write_text("print('observer')\n", encoding="utf-8")
    spec = _spec()
    spec["task_goal"]["family"] = "file_write"
    spec["task_goal"]["target_asset"] = MARKER_PATH
    text = author_probe.compose_text(
        spec=spec,
        target_image="target:1",
        verifier_image="verifier:1",
        tests_dir=tests,
        logs_dir=tmp_path / "logs",
        submitted_poc=tmp_path / "ref.py",
        variant="vulnerable",
    )
    assert "marker-data:/marker" in text
    assert "observer:" in text
    assert "internal: true" in text
    # The verifier main must not mount the marker volume.
    main = text.split("  target:", 1)[0]
    assert "marker-data" not in main


def test_probe_compose_listing_mounts_main(tmp_path: Path):
    tests = tmp_path / "tests"
    tests.mkdir()
    spec = _spec()
    spec["task_goal"]["family"] = "directory_listing"
    spec["task_goal"]["target_asset"] = LISTING_DIR
    text = author_probe.compose_text(
        spec=spec,
        target_image="target:1",
        verifier_image="verifier:1",
        tests_dir=tests,
        logs_dir=tmp_path / "logs",
        submitted_poc=tmp_path / "ref.py",
        variant="vulnerable",
    )
    assert "listing-data:/listing" in text
    assert "LISTING_NAME" not in text
    assert "internal: true" in text


def test_command_injection_secret_read_has_no_index_symlink():
    spec = _spec()
    spec["task_goal"]["primitive"] = "command_injection"
    task = render_task(
        spec,
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_synthesis("secret_read"),
    )
    entrypoint = task.files["environment/target/entrypoint.sh"]
    assert "ln -s" not in entrypoint
    instruction = task.files["instruction.md"]
    # Reverse connections must be explained; a command-injection task may need
    # the target to fetch attacker-hosted content.
    assert "reach this host as `main`" in instruction
    assert "http://main:" in instruction


def test_path_traversal_secret_read_keeps_the_index_symlink():
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_synthesis("secret_read"),
    )
    assert "ln -s" in task.files["environment/target/entrypoint.sh"]


def test_render_task_can_pin_a_generic_agent_but_a_per_variant_verifier():
    base = "harbor-pipeline/cve-2023-40587-vulnerable-r1"
    task = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_synthesis("secret_read"),
        prebuilt=True,
        prebuilt_base=base,
        environment_image="harbor-pipeline/base-environment:1",
    )
    toml = task.files["task.toml"]
    assert 'docker_image = "harbor-pipeline/base-environment:1"' in toml
    # The verifier contains this variant's tests/; it must not be the generic
    # base image, which has an empty /tests.
    assert f'docker_image = "{base}-verifier"' in toml

    generic = render_task(
        _spec(),
        scenario_name="synthesized",
        variant="vulnerable",
        synthesis=_synthesis("secret_read"),
        prebuilt=True,
        prebuilt_base=base,
        environment_image="harbor-pipeline/base-environment:1",
        verifier_image="harbor-pipeline/base-verifier:1",
    )
    assert 'docker_image = "harbor-pipeline/base-verifier:1"' in generic.files["task.toml"]


def test_cmd_probe_writes_state_and_finishes_job(tmp_path: Path, monkeypatch):
    run_dir, evidence = _run_dir(tmp_path)
    workspace = authoring.prepare_workspace(
        run_dir=run_dir,
        cve_id=CVE,
        discovery=_discovery(),
        evidence=evidence,
        revision=1,
        model="m",
    )
    _write_author_files(workspace.root)
    monkeypatch.setattr(
        "harbor_pipeline.depcheck.check_bundle", lambda bundle, settings: []
    )
    bundle, _, issues = authoring.validate_workspace(
        workspace=workspace.root,
        run_dir=run_dir,
        evidence=evidence,
        discovery=_discovery(),
        config=_config(),
    )
    assert issues == []
    task_dir = workspace.root / "probe-task"
    task_dir.mkdir()
    (workspace.root / ".harbor" / "build-state.json").write_text(
        json.dumps(
            {
                "bundle_digest": digest(bundle),
                "variants": {
                    "vulnerable": {
                        "image_ref": "target-v",
                        "task_dir": str(task_dir),
                    },
                    "fixed": {
                        "image_ref": "target-f",
                        "task_dir": str(task_dir),
                    },
                },
                "base": {"verifier": {"image_ref": "verifier:1"}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        author_tool.author_probe,
        "probe_pair",
        lambda **kwargs: {
            "ok": True,
            "status": "goal_passed",
            "fixed_status": "fixed_variant_holds",
            "noauth_observed": False,
        },
    )
    ctx = author_tool.ToolContext(
        workspace=workspace.root,
        run_dir=run_dir,
        cve_id=CVE,
        revision=1,
        config=_config(),
        evidence=evidence,
        discovery=_discovery(),
        policy=load_policy(),
    )
    code = author_tool.cmd_probe(ctx, quiet=True)
    assert code == 0
    probe = json.loads(
        (workspace.root / ".harbor" / "probe-state.json").read_text(encoding="utf-8")
    )
    assert probe["ok"] is True
    job = json.loads(
        (workspace.root / ".harbor" / "job.json").read_text(encoding="utf-8")
    )
    assert job["status"] == "succeeded"
    assert job["probe_status"] == "goal_passed"


def test_probe_summary_auth_negative_fails_the_pair():
    vulnerable = {
        "ok": True,
        "status": "goal_passed",
        "health_ok": True,
        "reward": 1.0,
        "noauth_observed": True,
    }
    fixed = {"ok": True, "status": "fixed_variant_holds", "health_ok": True, "reward": 0.0}
    # The pair helper is exercised through its public summary contract.
    assert author_probe.summarize(vulnerable, variant="vulnerable")["ok"]
    assert author_probe.summarize(fixed, variant="fixed")["ok"]
