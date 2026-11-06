"""Goal families and authentication as first-class task preconditions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from harbor_pipeline import evaluator
from harbor_pipeline import synthesis as synthesis_mod
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.generator import render_task
from harbor_pipeline.goals import LISTING_DIR, MARKER_PATH, auth_material
from harbor_pipeline.verifier_check import verifier_regression_checks
from harbor_pipeline.trials import Expectation

from test_auto_synthesis import CVE, _bundle, _discovery, _write_evidence

COMMIT = "347d7750da6f45c7436dd0c31468885cc9343c85"


def _normalize(tmp_path: Path, body: dict):
    evidence = _write_evidence(tmp_path)
    return synthesis_mod.normalize_bundle(
        body, evidence=evidence, discovery=_discovery(), run_dir=tmp_path
    )


def _spec(goal: dict, pre: dict) -> dict:
    return {
        "cve_id": CVE,
        "product": {"name": "pyramid", "ecosystem": "pypi", "component": "x"},
        "versions": {
            "affected": ">= 2.0.0, < 2.0.2",
            "fixed": "2.0.2",
            "vulnerable_ref": "2.0.1",
            "fixed_ref": "2.0.2",
            "fix_commit": COMMIT,
        },
        "frozen_digest": "a" * 64,
        "attribution_grade": "A",
        "task_goal": goal,
        "preconditions": pre,
        "impact": {"summary": "x", "cia": {"confidentiality": "none", "integrity": "none", "availability": "none"}},
    }


def _synthesis(family: str) -> SimpleNamespace:
    return SimpleNamespace(
        digest="deadbeef",
        target={
            "base_image": "python:3.11-slim",
            "port": 8080,
            "health_path": "/health",
            "business_path": "/business",
            "business_body": "ok",
            "start_command": "python /opt/app/app.py",
            "files": {
                "Dockerfile": (
                    "FROM python:3.11-slim\n"
                    "WORKDIR /opt/app\n"
                    "COPY app.py app.py\n"
                    'CMD ["python", "/opt/app/app.py"]\n'
                ),
                "app.py": "print('app')\n",
            },
            "fixed_overrides": {},
        },
        poc={"reference": "#!/usr/bin/env python3\nprint('x')\n",
             "alternate": "#!/usr/bin/env python3\nprint('y')\n"},
    )


def test_normalize_file_write_forces_marker_and_integrity(tmp_path: Path):
    body = _bundle()
    body["task_goal"] = {
        "family": "file_write",
        "primitive": "path_traversal",
        "observable": "The target writes the marker through the vulnerability.",
    }
    bundle, _, issues = _normalize(tmp_path, body)
    assert issues == []
    assert bundle["task_goal"]["type"] == "file_write"
    assert bundle["task_goal"]["target_asset"] == MARKER_PATH
    assert bundle["impact"]["cia"]["integrity"] == "high"


def test_normalize_directory_listing_forces_type_and_asset(tmp_path: Path):
    body = _bundle()
    body["task_goal"] = {
        "family": "directory_listing",
        "primitive": "path_traversal",
        "observable": "The random filename appears in the PoC output.",
    }
    body["impact"]["cia"] = {
        "confidentiality": "none", "integrity": "none", "availability": "none",
    }
    bundle, _, issues = _normalize(tmp_path, body)
    assert issues == []
    assert bundle["task_goal"]["type"] == "directory_listing"
    assert bundle["task_goal"]["target_asset"] == LISTING_DIR
    assert bundle["impact"]["cia"]["confidentiality"] == "low"


def test_normalize_accepts_authenticated_precondition(tmp_path: Path):
    body = _bundle()
    body["preconditions"]["auth_identity"] = "low_privilege"
    body["preconditions"]["auth_scheme"] = "http_basic"
    bundle, _, issues = _normalize(tmp_path, body)
    assert issues == []
    assert bundle["preconditions"]["auth_identity"] == "low_privilege"
    assert bundle["preconditions"]["auth_scheme"] == "http_basic"
    assert bundle["preconditions"]["privileges"] == "low"


def test_normalize_rejects_identity_without_scheme(tmp_path: Path):
    body = _bundle()
    body["preconditions"]["auth_identity"] = "low_privilege"
    body["preconditions"]["auth_scheme"] = "none"
    _, _, issues = _normalize(tmp_path, body)
    assert any("auth_scheme" in issue for issue in issues)


def test_auth_material_is_deterministic_and_framework_owned():
    spec = _spec(
        {"family": "secret_read", "type": "secret_disclosure", "primitive": "ssrf",
         "target_asset": "/opt/app/secret/token", "observable": "token"},
        {"auth_identity": "low_privilege", "auth_scheme": "http_basic"},
    )
    first = auth_material(spec)
    second = auth_material(dict(spec))
    assert first == second
    assert first["user"] and first["password"]
    assert first["password"] not in spec["frozen_digest"]


def test_render_file_write_ships_observer_and_marker_volume():
    goal = {
        "family": "file_write",
        "type": "file_write",
        "primitive": "path_traversal",
        "target_asset": MARKER_PATH,
        "observable": "The target writes the marker and the PoC prints the nonce.",
    }
    pre = {
        "network_reachable": True,
        "auth_identity": "none",
        "auth_scheme": "none",
        "privileges": "none",
        "configuration": "static root",
        "user_interaction": False,
        "unknown": [],
    }
    task = render_task(
        _spec(goal, pre), scenario_name="synthesized", variant="vulnerable",
        synthesis=_synthesis("file_write"),
    )
    assert "tests/observer.py" in task.files
    assert "marker-data" in task.files["environment/docker-compose.yaml"]
    assert "marker-data" in task.files["tests/docker-compose.yaml"]
    # The verifier main must never mount the marker volume itself.
    main_block = task.files["tests/docker-compose.yaml"].split("main:", 1)[1].split("target:", 1)[0]
    assert "marker-data" not in main_block
    # The agent must know which marker the observation checks, but the token
    # is irrelevant to this family and must not be advertised.
    assert MARKER_PATH in task.files["instruction.md"]
    assert "/opt/app/secret/token" not in task.files["instruction.md"]
    assert "goal_family = \"file_write\"" in task.files["task.toml"]


def test_render_auth_puts_credentials_in_instruction_and_target_env():
    goal = {
        "family": "secret_read",
        "type": "secret_disclosure",
        "primitive": "sql_injection",
        "target_asset": "/opt/app/secret/token",
        "observable": "The secret token appears in the PoC output.",
    }
    pre = {
        "network_reachable": True,
        "auth_identity": "low_privilege",
        "auth_scheme": "http_basic",
        "privileges": "low",
        "configuration": "login required",
        "user_interaction": False,
        "unknown": [],
    }
    spec = _spec(goal, pre)
    material = auth_material(spec)
    task = render_task(
        spec, scenario_name="synthesized", variant="vulnerable",
        synthesis=_synthesis("secret_read"),
    )
    instruction = task.files["instruction.md"]
    assert material["user"] in instruction
    assert material["password"] in instruction
    assert "APP_USER" in task.files["environment/docker-compose.yaml"]
    verify = task.files["tests/verify.py"]
    assert "TARGET_USER" in verify
    assert "noauth_observed" in verify


def test_render_listing_publishes_name_and_mounts_it_only_for_the_verifier():
    goal = {
        "family": "directory_listing",
        "type": "directory_listing",
        "primitive": "path_traversal",
        "target_asset": LISTING_DIR,
        "observable": "The random filename appears in the PoC output.",
    }
    pre = {
        "network_reachable": True,
        "auth_identity": "none",
        "auth_scheme": "none",
        "privileges": "none",
        "configuration": "static root",
        "user_interaction": False,
        "unknown": [],
    }
    task = render_task(
        _spec(goal, pre), scenario_name="synthesized", variant="vulnerable",
        synthesis=_synthesis("directory_listing"),
    )
    entrypoint = task.files["environment/target/entrypoint.sh"]
    assert "/listing/expected" in entrypoint
    compose = task.files["tests/docker-compose.yaml"]
    assert "listing-data:/listing" in compose
    # The expected filename must not be embedded in the verifier source.
    assert "0123456789abcdef" not in task.files["tests/verify.py"]


def test_verifier_negatives_hold_for_write_and_listing_families(tmp_path: Path):
    pre = {
        "network_reachable": True,
        "auth_identity": "none",
        "auth_scheme": "none",
        "privileges": "none",
        "configuration": "static root",
        "user_interaction": False,
        "unknown": [],
    }
    write_spec = _spec(
        {"family": "file_write", "type": "file_write", "primitive": "path_traversal",
         "target_asset": MARKER_PATH, "observable": "marker write"},
        pre,
    )
    listing_spec = _spec(
        {"family": "directory_listing", "type": "directory_listing",
         "primitive": "path_traversal", "target_asset": LISTING_DIR,
         "observable": "random filename listing"},
        pre,
    )
    for spec in (write_spec, listing_spec):
        results = verifier_regression_checks(spec, synthetic=True)
        assert results["T05"]["status"] == "artifact_missing"
        assert results["T06"]["status"] == "goal_failed"
        assert results["T07"]["status"] == "goal_failed"
        assert results["T10"]["status"] == "goal_failed"


def _p2_status(pre: dict, auth: dict | None) -> str:
    spec = {"preconditions": pre}
    records = []
    if auth is not None:
        records.append({"experiment_id": "T03", "auth": auth})
    matrix = MatrixResult(
        job=None,
        records=records,
        expectations={"T01": Expectation("T01", True, "healthy", "healthy")},
    )
    dimension = evaluator._dimension_p(spec, matrix, {})
    return next(item for item in dimension.items if item.id == "P2-auth-precondition").status


def test_p2_accepts_authentication_when_the_reference_needs_it():
    pre = {
        "network_reachable": True,
        "auth_identity": "low_privilege",
        "auth_scheme": "http_basic",
        "privileges": "low",
        "configuration": "login",
        "user_interaction": False,
        "unknown": [],
    }
    assert _p2_status(pre, {"required": True, "noauth_observed": False}) == "pass"
    assert _p2_status(pre, {"required": True, "noauth_observed": True}) == "fail"


def test_p2_still_rejects_an_authenticated_claim_without_a_scheme():
    pre = {
        "network_reachable": True,
        "auth_identity": "low_privilege",
        "auth_scheme": "",
        "privileges": "low",
        "configuration": "login",
        "user_interaction": False,
        "unknown": [],
    }
    assert _p2_status(pre, {"required": True, "noauth_observed": False}) == "fail"


def _i1_status(goal: dict, cia: dict) -> str:
    spec = {"task_goal": goal, "impact": {"cia": cia}}
    matrix = MatrixResult(job=None, records=[], expectations={})
    dimension = evaluator._dimension_i(spec, {}, matrix, [], "public")
    return next(item for item in dimension.items if item.id == "I1-goal-impact").status


def test_i1_is_family_aware():
    assert _i1_status(
        {"family": "file_write", "type": "file_write",
         "observable": "The marker is written with the nonce."},
        {"confidentiality": "none", "integrity": "high", "availability": "none"},
    ) == "pass"
    assert _i1_status(
        {"family": "directory_listing", "type": "directory_listing",
         "observable": "The listing reveals the random filename."},
        {"confidentiality": "low", "integrity": "none", "availability": "none"},
    ) == "pass"
    # A listing goal claiming high confidentiality without disclosing content is
    # still coherent; a write goal without integrity is not.
    assert _i1_status(
        {"family": "file_write", "type": "file_write",
         "observable": "The marker is written with the nonce."},
        {"confidentiality": "high", "integrity": "none", "availability": "none"},
    ) == "fail"


def test_version_ref_prefix_is_stripped_before_the_build(tmp_path):
    body = _bundle()
    body["versions"]["vulnerable_ref"] = "pyramid==2.0.1"
    evidence = _write_evidence(tmp_path)
    bundle, _, issues = synthesis_mod.normalize_bundle(
        body,
        evidence=evidence,
        discovery=_discovery(vulnerable_ref=""),
        run_dir=tmp_path,
    )
    assert issues == []
    assert bundle["versions"]["vulnerable_ref"] == "2.0.1"


def test_scoped_npm_ref_prefix_is_stripped():
    assert synthesis_mod._clean_version_ref(
        "npm",
        "@apostrophecms/import-export",
        "@apostrophecms/import-export@3.6.2",
    ) == "3.6.2"
    assert synthesis_mod._clean_version_ref("pypi", "demo", "demo==1.2.3") == "1.2.3"
    assert synthesis_mod._clean_version_ref("maven", "g:a", "g:a:1.2.3") == "1.2.3"


def test_an_advisory_without_an_end_to_end_exploit_is_unsupported():
    corpus = (
        "The source establishes this static primitive but not an end-to-end "
        "exploit or controlled arbitrary file read or write."
    )
    reason = synthesis_mod._negated_exploit(corpus)
    assert reason is not None
    assert "no end-to-end exploit" in reason
    assert synthesis_mod._negated_exploit(
        "An unauthenticated request reads the secret token."
    ) is None
