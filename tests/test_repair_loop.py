"""The repair agent's tool loop, gates and authoring state."""

import json

from harbor_pipeline.budget import DEFAULT_LIMITS, Ledger
from harbor_pipeline.config import Config
from harbor_pipeline.errors import TaskError
from harbor_pipeline.providers.base import ModelResponse
from harbor_pipeline.repair import (
    MAX_VERIFIER_RUNS,
    POC_PATH,
    RepairEngine,
    RepairTools,
)


class FakeProvider:
    name = "fake"

    def __init__(self, bodies):
        self.bodies = list(bodies)
        self.prompts: list[str] = []

    def generate(self, request):
        self.prompts.append(request.prompt)
        body = self.bodies.pop(0)
        return ModelResponse(
            text=json.dumps(body),
            structured=body,
            usage={"input_tokens": 10, "output_tokens": 10},
            model_identity="fake",
        )


class Tools:
    def __init__(self, *, builds=None, verifies=None, registry=None):
        self.builds = list(builds or [])
        self.verifies = list(verifies or [])
        self.registry_result = registry or {"versions": ["1.2.3"], "total": 1}
        self.build_calls = 0
        self.verify_calls = 0
        self.registry_calls: list[tuple[str, str]] = []

    def build(self, state):
        self.build_calls += 1
        if self.builds:
            return self.builds.pop(0)
        return {"ok": True, "status": "built"}

    def debug(self, state):
        self.verify_calls += 1
        if self.verifies:
            return self.verifies.pop(0)
        return _pass()

    def registry(self, ecosystem, name):
        self.registry_calls.append((ecosystem, name))
        return self.registry_result


def _pass():
    return {
        "ok": True,
        "status": "goal_passed",
        "fixed_status": "fixed_variant_holds",
        "fixed_health_ok": True,
    }


def _fail(error="HTTP Error 404"):
    return {
        "ok": False,
        "status": "oracle_failure",
        "reference_exit": 1,
        "reference_error": error,
        "submitted_exit": 1,
        "submitted_observed": False,
        "fixed_status": "fixed_variant_holds",
        "fixed_health_ok": True,
    }


def _engine(tmp_path, bodies, *, spec=None, bundle=None):
    engine = object.__new__(RepairEngine)
    engine.config = Config()
    engine.ledger = Ledger(
        tmp_path / "ledger.json",
        limits={**DEFAULT_LIMITS, "calls": 80, "tokens": 2_000_000},
    )
    engine.role = "repairer"
    engine.settings = engine.config.model_for("repairer")
    engine.provider = FakeProvider(bodies)
    return engine


def _error():
    return TaskError(
        "validation_error",
        "reference_poc_all_success: 0/1; the reference exploit reached no secret",
    )


def _files():
    return {
        "environment/target/app.py": "print('app')\n",
        "environment/target/requirements.txt": "foo=={{REF}}\n",
        "instruction.md": "# task\n",
        POC_PATH: "#!/bin/sh\necho ORIGINAL\n",
    }


def _spec():
    return {"versions": {"vulnerable_ref": "1.0.0", "fixed_ref": "1.0.1"}}


def _bundle():
    return {
        "product": {"name": "demo"},
        "versions": {"vulnerable_ref": "1.0.0", "fixed_ref": "1.0.1"},
        "root_cause": {"summary": "the parser resolves ../ in a filename"},
        "preconditions": {"configuration": "a /load endpoint"},
        "target": {
            "files": {"app.py": "print('app')\n"},
            "start_command": "python app.py",
            "port": 8080,
        },
        "poc": {"reference": "print('probe')"},
    }


def test_agent_reads_builds_writes_and_verifies(tmp_path):
    tools = Tools(
        builds=[
            {
                "ok": False,
                "status": "build_error",
                "log_tail": "ModuleNotFoundError: No module named 'foo'",
            },
            {"ok": True, "status": "built"},
        ],
    )
    engine = _engine(tmp_path, [
        {"action": "read_file", "path": "environment/target/app.py"},
        {"action": "write_file", "path": "environment/target/app.py",
         "content": "print('repaired')\n"},
        {"action": "build"},
        {"action": "write_file", "path": "environment/target/requirements.txt",
         "content": "foo=={{REF}}\n# added\n"},
        {"action": "build"},
        {"action": "run_verifier"},
        {"action": "submit", "reason": "the pair passes"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=TaskError("build_error", "docker build failed"),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(
            build=tools.build, debug=tools.debug, registry=tools.registry
        ),
    )

    assert result.error is None
    assert result.files["environment/target/app.py"].endswith("print('repaired')\n")
    assert result.files["environment/target/requirements.txt"].endswith("# added\n")
    # The build log is evidence, not prose the model has to guess from.
    assert "ModuleNotFoundError" in engine.provider.prompts[3]
    assert tools.build_calls == 2
    assert tools.verify_calls == 1
    # The passing pair finalizes the repair; the observation is auditable.
    assert "PAIR PASSED" in result.trace[-1]["observation"]


def test_agent_uses_the_registry_and_changes_the_pinned_release(tmp_path):
    tools = Tools(registry={"versions": ["1.2.3", "1.2.2"], "total": 2})
    seen_versions: list[str] = []

    def debug(state):
        tools.verify_calls += 1
        seen_versions.append(state.spec["versions"]["vulnerable_ref"])
        return _pass()

    engine = _engine(tmp_path, [
        {"action": "registry", "ecosystem": "pypi", "name": "foo"},
        {"action": "set_version", "role": "vulnerable", "ref": "1.2.2"},
        {"action": "submit", "reason": "version exists and the pair passes"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=2,
        error=TaskError("build_error", "foo==1.0.0 is not a published release"),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(
            build=tools.build, debug=debug, registry=tools.registry
        ),
    )

    assert result.error is None
    assert result.spec_changed is True
    assert result.spec["versions"]["vulnerable_ref"] == "1.2.2"
    assert result.bundle["versions"]["vulnerable_ref"] == "1.2.2"
    assert tools.registry_calls == [("pypi", "foo")]
    assert seen_versions == ["1.2.2"]


def test_the_paired_verifier_rejects_a_fixed_variant_leak(tmp_path):
    tools = Tools(verifies=[
        {
            "ok": False,
            "status": "goal_passed",
            "fixed_status": "fixed_variant_leaks",
            "fixed_health_ok": True,
        },
        _pass(),
    ])
    engine = _engine(tmp_path, [
        {"action": "write_file", "path": "environment/target/app.py",
         "content": "print('one')\n"},
        {"action": "run_verifier"},
        {"action": "write_file", "path": "environment/target/app.py",
         "content": "print('two')\n"},
        {"action": "submit", "reason": "the read-back is gone"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=TaskError(
            "validation_error", "zero_fixed_success: 20 fixed trials leaked"
        ),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.error is None
    assert result.files["environment/target/app.py"].endswith("print('two')\n")
    assert tools.verify_calls == 2
    # A T03 pass alone is not enough; the fixed build must hold.
    assert "fixed_variant_leaks" in engine.provider.prompts[2]


def test_agent_may_add_and_read_a_new_environment_file(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {"action": "write_file", "path": "environment/target/lib.py",
         "content": "VALUE = 1\n"},
        {"action": "list_files"},
        {"action": "read_file", "path": "environment/target/lib.py"},
        {"action": "submit", "reason": "new helper"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.files["environment/target/lib.py"] == "VALUE = 1\n"
    assert "environment/target/lib.py" in engine.provider.prompts[1]
    assert "VALUE = 1" in engine.provider.prompts[2]


def test_the_verifier_and_instruction_are_not_writable(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {"action": "write_file", "path": "tests/verify.py",
         "content": "print(1.0)\n"},
        {"action": "write_file", "path": "instruction.md", "content": "weaken\n"},
        {"action": "abort", "reason": "nothing useful"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.files == {}
    assert "Refusing to write" in engine.provider.prompts[1]


def test_submit_reuses_the_last_verified_state(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {"action": "write_file", "path": "environment/target/app.py",
         "content": "print('fixed')\n"},
        {"action": "run_verifier"},
        {"action": "submit", "reason": "unchanged since the pass"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.error is None
    assert tools.verify_calls == 1


def test_changes_are_not_applied_without_a_verified_submit(tmp_path):
    tools = Tools(verifies=[_fail() for _ in range(MAX_VERIFIER_RUNS + 2)])
    bodies = [
        {"action": "write_file", "path": "environment/target/app.py",
         "content": "print('unverified')\n"},
    ] + [
        {"action": "run_verifier"} for _ in range(MAX_VERIFIER_RUNS + 2)
    ] + [{"action": "abort", "reason": "exhausted"}]
    engine = _engine(tmp_path, bodies, spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    # An unverified rewrite must not reach the full matrix.
    assert result.files == {}
    assert result.error


def test_agent_can_change_the_start_command_and_fixed_override(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {"action": "set_start_command", "command": "cd /opt/app && node app.js"},
        {"action": "set_fixed_override", "name": "requirements.txt",
         "content": "foo=={{REF}} # fixed\n"},
        {"action": "submit", "reason": "start command and fixed pin"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=TaskError("build_error", "the app starts in the wrong directory"),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.error is None
    assert result.bundle_changed is True
    assert result.bundle["target"]["start_command"] == "cd /opt/app && node app.js"
    assert (
        result.bundle["target"]["fixed_overrides"]["requirements.txt"]
        == "foo=={{REF}} # fixed\n"
    )


def test_prompt_contains_the_bundle_semantics_and_the_harness_context(tmp_path):
    engine = _engine(tmp_path, [
        {"action": "abort", "reason": "read-only inspection"},
    ], spec=_spec(), bundle=_bundle())

    engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=TaskError("build_error", "docker build failed"),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        context="## Build failure log (tail)\n```\nboom\n```",
    )

    prompt = engine.provider.prompts[0]
    assert "the parser resolves ../ in a filename" in prompt
    assert "a /load endpoint" in prompt
    assert "boom" in prompt
    assert "instruction.md" in prompt
    # The verifier is not put in front of the author as a file to edit.
    assert "tests/verify.py" not in prompt


def test_a_legacy_patch_shape_is_still_accepted(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {
            "reason": "keep the old shape",
            "files": [
                {"path": POC_PATH, "content": "#!/bin/sh\necho NEW\n"}
            ],
        },
        {"action": "submit", "reason": "legacy patch"},
    ], spec=_spec(), bundle=_bundle())

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert result.error is None
    assert result.files[POC_PATH].endswith("echo NEW\n")


def test_repeated_read_bundle_is_short_circuited(tmp_path):
    tools = Tools()
    engine = _engine(tmp_path, [
        {"action": "read_bundle"},
        {"action": "read_bundle"},
        {"action": "abort", "reason": "no more context needed"},
    ], spec=_spec(), bundle=_bundle())

    engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=tools.debug),
    )

    assert "unchanged since your last read" in engine.provider.prompts[2]


def test_registry_failure_allows_one_transient_retry(tmp_path):
    class Flaky:
        def __init__(self):
            self.calls = 0

        def __call__(self, ecosystem, name):
            self.calls += 1
            if self.calls < 3:
                return {"error": "SSL EOF"}
            return {"versions": ["1.2.3"], "total": 1}

    registry = Flaky()
    engine = _engine(tmp_path, [
        {"action": "registry", "ecosystem": "npm", "name": "foo"},
        {"action": "registry", "ecosystem": "npm", "name": "foo"},
        {"action": "registry", "ecosystem": "npm", "name": "foo"},
        {"action": "abort", "reason": "done"},
    ], spec=_spec(), bundle=_bundle())

    engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
        tools=RepairTools(debug=lambda _state: _pass(), registry=registry),
    )

    assert registry.calls == 3
    assert "1.2.3" in engine.provider.prompts[3]


def test_a_malformed_reply_is_retried_with_feedback(tmp_path):
    class Unstructured(FakeProvider):
        def generate(self, request):
            self.prompts.append(request.prompt)
            if len(self.prompts) == 1:
                return ModelResponse(
                    text="not json",
                    structured=None,
                    usage={"input_tokens": 1, "output_tokens": 1},
                    model_identity="fake",
                )
            body = {"action": "abort", "reason": "cannot fix"}
            return ModelResponse(
                text=json.dumps(body),
                structured=body,
                usage={"input_tokens": 1, "output_tokens": 1},
                model_identity="fake",
            )

    engine = _engine(tmp_path, [], spec=_spec(), bundle=_bundle())
    engine.provider = Unstructured([])

    result = engine.repair(
        cve_id="CVE-2024-0001",
        revision=1,
        error=_error(),
        files=_files(),
        spec=_spec(),
        bundle=_bundle(),
    )

    assert result.files == {}
    assert len(engine.provider.prompts) == 2
    assert "not structured JSON" in engine.provider.prompts[1]
