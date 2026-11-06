"""Regression cases for false rewards, unsupported evidence and data leakage."""
import json
import socket
import urllib.request

from harbor_pipeline import fixtures
from harbor_pipeline.author_tool import build_parser
from harbor_pipeline.backend import dependency_lock
from harbor_pipeline.dataset import assign_splits, split_conflicts
from harbor_pipeline.generator import render_task
from harbor_pipeline.provenance import version_pair_issues
from harbor_pipeline.quality_report import build_quality_report
from harbor_pipeline.runtime_identity import jar_metadata, parse_go_metadata
from harbor_pipeline.scenario import ScenarioContext, _verifier_compose, _verify_script
from harbor_pipeline.synthesis import normalize_bundle
from harbor_pipeline.validation_evidence import validation_signature

from test_auto_synthesis import _bundle, _discovery, _write_evidence
from test_goal_families import _synthesis


def verifier(tmp_path, *, family="secret_read", paired=False):
    ctx = ScenarioContext(cve_id="CVE-0000-0000", product="demo", variant="vulnerable",
        probe="reference", version="1.0", secret_path="/opt/app/secret/token",
        spec_digest="a" * 64, attribution_grade="A", goal_family=family,
        paired_verification=paired)
    namespace = {"__name__": "test_verifier"}
    exec(compile(_verify_script(ctx), "verify.py", "exec"), namespace)
    artifact = tmp_path / "poc"
    artifact.write_text("submitted")
    namespace.update(
        TARGET_HOST="target", REFERENCE_TARGET_HOST="target-reference",
        ARTIFACT_PATH=str(artifact),
        REWARD_PATH=str(tmp_path / "reward.txt"), EVIDENCE_PATH=str(tmp_path / "evidence.json"),
        wait_healthy=lambda *args, **kwargs: True, business_ok=lambda: True,
    )
    # The reference instance has its own token; never reuse the submitted one.
    namespace["expected_secret"] = (
        lambda reference=False: ("c" if reference else "a") * 48
    )
    def fixed_check():
        namespace["TARGET_HOST"] = "target-fixed"
        namespace["REFERENCE_TARGET_HOST"] = "target-fixed"
        namespace["EXPECT_VARIANT"] = "fixed"
        namespace["EXPECT_VULNERABLE"] = False
        return namespace["verify_one"]()
    namespace["check_fixed_submission"] = fixed_check
    return namespace


def test_reference_output_is_not_the_source_of_truth(tmp_path):
    ns = verifier(tmp_path)
    ns["run_restricted"] = lambda *a, **k: ("f" * 48, "", 0)
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 0
    assert evidence["status"] == "oracle_failure"


def test_submission_that_also_works_on_fixed_gets_zero(tmp_path):
    ns = verifier(tmp_path, paired=True)
    calls = []

    def replay(path, **kwargs):
        host = kwargs.get("host") or ns["TARGET_HOST"]
        calls.append((host, path))
        # This PoC also works against the fixed build; the fixed replay must
        # catch it and zero the reward.
        if path == ns["REFERENCE_PATH"]:
            return ns["expected_secret"](reference=True), "", 0
        return ns["expected_secret"](), "", 0

    ns["run_restricted"] = replay
    ns["main"]()
    evidence = json.loads((tmp_path / "evidence.json").read_text())
    assert evidence["reward"] == 0
    assert evidence["fixed_replay"]["submitted_observed"]
    assert ("target-fixed", ns["ARTIFACT_PATH"]) in calls


def test_valid_differential_submission_is_accepted(tmp_path):
    ns = verifier(tmp_path, paired=True)
    def replay(path, **kwargs):
        host = kwargs.get("host") or ns["TARGET_HOST"]
        if host == "target-fixed":
            return "", "rejected", 1
        if path == ns["REFERENCE_PATH"]:
            return ns["expected_secret"](reference=True), "", 0
        return ns["expected_secret"](), "", 0
    ns["run_restricted"] = replay
    ns["main"]()
    evidence = json.loads((tmp_path / "evidence.json").read_text())
    assert evidence["reward"] == 1
    assert evidence["fixed_replay"]["status"] == "fixed_variant_holds"


def test_crashing_submission_cannot_win_by_printing_the_token(tmp_path):
    ns = verifier(tmp_path)
    ns["run_restricted"] = lambda path, **kw: (
        ("c" if path == ns["REFERENCE_PATH"] else "a") * 48,
        "",
        0 if path == ns["REFERENCE_PATH"] else 1,
    )
    assert ns["verify_one"]()["reward"] == 0


def test_reference_state_cannot_satisfy_the_submission(tmp_path):
    """A reference that writes state must not make a later submitted PoC pass.

    The fake target keeps state per hostname. The reference runs against
    target-reference; the submission runs against target and must still fail
    because it never saw the reference's state.
    """
    ns = verifier(tmp_path)
    state = {"target": False, "target-reference": False}

    def replay(path, **kwargs):
        host = kwargs.get("host") or ns["TARGET_HOST"]
        if path == ns["REFERENCE_PATH"]:
            state[host] = True
            return ns["expected_secret"](reference=True), "", 0
        if state.get(host):
            return ns["expected_secret"](), "", 0
        return "", "no state left by a reference run", 1

    ns["run_restricted"] = replay
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 0
    assert evidence["status"] == "goal_failed"
    assert state == {"target": False, "target-reference": True}


def test_compose_gives_reference_and_submission_separate_targets():
    compose = _verifier_compose({"A": "1"})
    assert "  target-reference:\n" in compose
    # Each instance owns its answer volume; the main only reads both.
    assert "ref-oracle-data:/oracle" in compose
    assert "ref-oracle-data:/oracle-ref" in compose
    assert 'VERIFY_REFERENCE_HOST: "target-reference"' in compose
    paired = _verifier_compose(
        {"A": "1"},
        image="harbor-pipeline/demo-vulnerable-r1-target",
        paired=True,
    )
    # The fixed side does not need its own reference copy; target-fixed already
    # runs the submitted PoC on a separate instance.
    assert paired.count("\n  target-reference:\n") == 1
    assert "  target-fixed:\n" in paired


def test_old_listing_answer_is_rejected_on_a_new_instance(tmp_path):
    ns = verifier(tmp_path, family="directory_listing")
    ns["_EXPECTED_LISTING"] = "new-instance.txt"
    ns["_EXPECTED_LISTING_REF"] = "new-instance.txt"
    ns["run_restricted"] = lambda path, **kw: ("new-instance.txt" if path == ns["REFERENCE_PATH"] else "previous-instance.txt", "", 0)
    assert ns["verify_one"]()["reward"] == 0


def test_white_box_does_not_contain_a_listing_answer_or_entrypoint():
    spec = fixtures.cve_spec()
    spec["task_goal"].update(family="directory_listing", type="directory_listing")
    synthesis = _synthesis("directory_listing")
    synthesis.bundle = {"presentation": {"mode": "white_box", "source_paths": ["app.py"]}}
    task = render_task(spec, scenario_name="synthesized", variant="vulnerable", synthesis=synthesis)
    exposed = {k: v for k, v in task.files.items() if k.startswith("environment/source/")}
    assert list(exposed) == ["environment/source/app.py"]
    assert "LISTING_NAME:-" not in task.files["environment/target/entrypoint.sh"]
    assert "LISTING_NAME:" not in task.files["environment/docker-compose.yaml"]
    assert "tests/fixed-target/entrypoint.sh" in task.files


def test_downloaded_source_does_not_confirm_an_arbitrary_claim(tmp_path):
    evidence = _write_evidence(tmp_path)
    body = _bundle()
    body["assertions"][0]["text"] = "Two plus two is five, and this is independently confirmed."
    normalized, _, issues = normalize_bundle(body, evidence=evidence, discovery=_discovery(), run_dir=tmp_path)
    assert normalized["assertions"][0]["status"] == "unknown"
    assert any("exact excerpt" in issue for issue in issues)


def test_edited_source_cannot_satisfy_its_old_checksum(tmp_path):
    evidence = _write_evidence(tmp_path)
    (tmp_path / "evidence/cve.json").write_text(_bundle()["assertions"][0]["text"])
    _, _, issues = normalize_bundle(_bundle(), evidence=evidence, discovery=_discovery(), run_dir=tmp_path)
    assert any("checksum" in issue for issue in issues)


def test_fixed_application_rewrite_is_not_an_upstream_version_change():
    bundle = _bundle()
    bundle["target"]["fixed_overrides"] = {"app.py": "print('reject every request')\n"}
    assert version_pair_issues(bundle["target"], bundle["versions"])


def test_version_placeholder_cannot_switch_application_behavior():
    bundle = _bundle()
    bundle["target"]["files"]["app.py"] = 'VERSION="{{REF}}"\n'
    assert version_pair_issues(bundle["target"], bundle["versions"])


def test_regeneration_removes_previously_exposed_source_files(tmp_path):
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    task.files["environment/source/old-answer.txt"] = "old answer"
    root = task.write(tmp_path)
    del task.files["environment/source/old-answer.txt"]
    task.write(tmp_path)
    assert not (root / "environment/source/old-answer.txt").exists()


def test_execution_copy_pins_both_variants_and_fixed_runner():
    from harbor_pipeline.generator import pin_task_images
    task = render_task(fixtures.cve_spec(), scenario_name="synthesized", variant="vulnerable", synthesis=_synthesis("secret_read"), prebuilt=True)
    base = "harbor-pipeline/cve-2024-0001"
    images = {"vulnerable": {"images": {
        "target": {"image_ref": base + "-vulnerable-r1-target", "image_digest": "sha256:" + "1" * 64},
        "verifier": {"image_ref": base + "-vulnerable-r1-verifier", "image_digest": "sha256:" + "2" * 64},
    }}, "fixed": {"images": {
        "target": {"image_ref": base + "-fixed-r1-target", "image_digest": "sha256:" + "3" * 64},
    }}}
    old = task.task_digest
    pin_task_images(task, {"variants": images})
    compose = task.files["tests/docker-compose.yaml"]
    assert all("sha256:" + digit * 64 in compose for digit in "123")
    assert old != task.task_digest


def test_dockerfile_comments_cannot_attest_installed_dependencies(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n# example-webapp v1.2.3\n")
    assert dependency_lock(tmp_path, product="example-webapp", ref="v1.2.3") == {}


def test_aliases_and_shared_patches_cannot_cross_splits():
    entries = [
        {"cve_id": "CVE-2026-0001", "project": "scikit-learn", "patch_group": "patch-a", "split": "train"},
        {"cve_id": "CVE-2026-0002", "project": "scikit_learn", "patch_group": "patch-b", "split": "test"},
        {"cve_id": "CVE-2026-0003", "project": "another-project", "patch_group": "patch-b", "split": "validation"},
        {"cve_id": "CVE-2026-0004", "aliases": ["CVE-2026-0003"], "project": "fork", "patch_group": "patch-c", "split": "train"},
    ]
    assert split_conflicts(entries)
    assigned = assign_splits(entries)
    assert len({e["split"] for e in assigned}) == 1
    assert split_conflicts(assigned) == []
    assert assign_splits(list(reversed(entries))) == list(reversed(assigned))


def test_changed_grader_invalidates_stored_execution_signature():
    task = render_task(fixtures.cve_spec(), scenario_name="fixture", variant="vulnerable")
    initial = validation_signature(fixtures.cve_spec(), task, {})
    task.files["tests/verify.py"] += "\n# changed grader protocol\n"
    assert validation_signature(fixtures.cve_spec(), task, {}) != initial


def test_author_has_fixed_and_persistent_debug_commands():
    parser = build_parser()
    assert parser.parse_args(["exec", "--variant", "fixed", "--", "python", "-V"]).variant == "fixed"
    parsed = parser.parse_args(["debug", "--variant", "fixed", "exec", "--", "sh", "-lc", "ps; ls"])
    assert parsed.variant == "fixed" and parsed.action == "exec"
    assert parsed.command[-1] == "ps; ls"
    assert parser.parse_args(["shell", "--", "python", "-V"]).subcommand == "shell"
    assert parser.parse_args(["shell", "--runtime", "node", "--", "node", "-v"]).runtime == "node"


def test_debug_dependency_caches_do_not_enter_task_bundles(tmp_path):
    from harbor_pipeline.authoring import _read_tree
    (tmp_path / "app.py").write_text("import math\n")
    for folder in ("node_modules", "__pycache__", ".venv"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "cache.bin").write_bytes(b"\xff\x00")
    assert _read_tree(tmp_path, label="target") == {"app.py": "import math\n"}


def test_go_and_maven_identity_comes_from_built_metadata(tmp_path):
    assert parse_go_metadata("\tdep\texample.com/lib\tv1.2.3\th1:abc\n\tmod\texample.com/app\t(devel)\n") == {"example.com/lib": "1.2.3"}
    import zipfile
    jar = tmp_path / "app.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.writestr("META-INF/maven/org.example/lib/pom.properties", "groupId=org.example\nartifactId=lib\nversion=1.2.3\n")
    assert jar_metadata(jar) == {"org.example:lib": "1.2.3"}


def test_quality_report_does_not_invent_accuracy_or_training_gains(tmp_path):
    report = build_quality_report(tmp_path)
    assert report["independent_correctness"]["accuracy"] is None
    assert report["training_effect"] is None
    assert report["release_rate"] is None


def test_clean_rebuilds_build_and_execute_both_variants(tmp_path, monkeypatch):
    import inspect
    from types import SimpleNamespace
    from harbor_pipeline import backend
    from harbor_pipeline.differential import run_seed_repeats
    from harbor_pipeline.harbor_adapter import TrialOutcome
    signature = inspect.signature(backend.build_task_images)
    calls, cleaned = [], []

    def build(**kwargs):
        signature.bind(**kwargs)  # Reject unsupported arguments at the call boundary.
        calls.append(kwargs)
        base = kwargs["tag_base"]
        images = {name: {"image_ref": base + "-" + name, "image_digest": "sha256:" + str(i) * 64}
                  for i, name in enumerate(("target", "verifier", "agent"), 1)}
        return {"images": images, "target_digest": images["target"]["image_digest"]}

    class Adapter:
        def run(self, task_paths, **kwargs):
            files = {p.relative_to(task_paths[0]).as_posix(): p.read_text(encoding="utf-8")
                     for p in task_paths[0].rglob("*") if p.is_file()}
            assert 'PAIRED_VERIFICATION = "false"' in files["tests/verify.py"]
            fixed = kwargs["job_name"].endswith("fixed")
            trial = TrialOutcome(trial_name=kwargs["job_name"], task_path=str(task_paths[0]), task_name="rebuild",
                trial_dir=tmp_path, reward=0.0 if fixed else 1.0, exception=None,
                evidence={"status": "fixed_variant_holds" if fixed else "goal_passed", "health_ok": True, "business_ok": True,
                          "submitted_observed": not fixed, "reference_observed": not fixed},
                started_at=fixtures.NOW, finished_at=fixtures.NOW, duration_sec=0.0)
            return SimpleNamespace(trials=[trial], result={"started_at": fixtures.NOW})

    monkeypatch.setattr(backend, "build_task_images", build)
    monkeypatch.setattr(backend, "prune_task_images", lambda tag: cleaned.append(tag))
    records, errors = run_seed_repeats(Adapter(), fixtures.cve_spec(), scenario_name="synthesized", root=tmp_path,
        network_mode="public", allowed_hosts=("target",), run_id="test", candidate_revision=1,
        artifact_digest="sha256:" + "0" * 64, synthesis=_synthesis("secret_read"), environment_image="agent")
    assert not errors
    assert len(records) == len(calls) == len(cleaned) == 6
    assert all(call["no_cache"] for call in calls)
    assert [call["variant"] for call in calls] == ["vulnerable", "fixed"] * 3


def test_legacy_dataset_is_archived_and_not_silently_reused(tmp_path):
    from harbor_pipeline.batch import _write_dataset
    from harbor_pipeline.util import write_json, read_json
    old = fixtures.dataset_manifest()
    write_json(tmp_path / "dataset-manifest.json", old)
    summary = {}
    _write_dataset(None, {}, tmp_path, summary)
    assert read_json(tmp_path / "dataset-manifest.json")["tasks"] == []
    archived = list((tmp_path / "dataset-history").glob("*.json"))
    assert len(archived) == 1 and read_json(archived[0]) == old
    assert summary["dataset"]["excluded_legacy"] == [old["tasks"][0]["cve_id"]]


def test_offline_execution_task_pins_every_grading_image(tmp_path):
    import tomllib
    from harbor_pipeline.image_archive import pinned_release_task
    task = render_task(fixtures.cve_spec(), scenario_name="synthesized", variant="vulnerable", synthesis=_synthesis("secret_read"))
    task.write(tmp_path)
    images = {}
    for variant, offset in (("vulnerable", 1), ("fixed", 4)):
        images[variant] = {"images": {name: {"image_ref": variant + "-" + name, "image_digest": "sha256:" + str(index + offset) * 64}
                                      for index, name in enumerate(("target", "verifier", "agent"))}}
    pinned = pinned_release_task(tmp_path, {"image_set": {"variants": images}})
    config = tomllib.loads(pinned.files["task.toml"])
    assert config["environment"]["docker_image"] == "sha256:" + "3" * 64
    assert config["verifier"]["environment"]["docker_image"] == "sha256:" + "2" * 64
    compose = pinned.files["tests/docker-compose.yaml"]
    assert all("sha256:" + digit * 64 in compose for digit in "124")


def test_server_request_family_normalizes_callback_goal(tmp_path):
    from harbor_pipeline.goals import CALLBACK_PATH
    from harbor_pipeline.synthesis import normalize_bundle
    evidence = _write_evidence(tmp_path)
    body = _bundle()
    body["task_goal"].update(
        family="server_request",
        type="server_request",
        primitive="ssrf",
        target_asset=CALLBACK_PATH,
        observable="The target issues an HTTP request to the verifier callback URL.",
    )
    body["impact"]["cia"] = {
        "confidentiality": "none", "integrity": "none", "availability": "none"
    }
    normalized, _, issues = normalize_bundle(
        body, evidence=evidence, discovery=_discovery(), run_dir=tmp_path
    )
    assert not issues, issues
    assert normalized["task_goal"]["family"] == "server_request"
    assert normalized["task_goal"]["type"] == "server_request"
    assert normalized["task_goal"]["target_asset"] == CALLBACK_PATH
    # A blind request still performs an unintended action even without data.
    assert normalized["impact"]["cia"]["integrity"] == "low"


def test_server_request_verifier_accepts_only_target_callback(tmp_path):
    ns = verifier(tmp_path, family="server_request")
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    callback_port = probe.getsockname()[1]
    probe.close()
    ns.update(
        TARGET_HOST="127.0.0.1",
        REFERENCE_TARGET_HOST="127.0.0.1",
        CALLBACK_PORT=callback_port,
        CALLBACK_PUBLIC_HOST="127.0.0.1",
    )

    def replay(path, **kwargs):
        url = kwargs.get("callback_url_value")
        if url:
            urllib.request.urlopen(url, timeout=5).read()
        return "", "", 0

    ns["run_restricted"] = replay
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 1
    assert evidence["reference_observed"] and evidence["submitted_observed"]


def test_server_request_ignores_a_callback_from_the_wrong_source(tmp_path):
    ns = verifier(tmp_path, family="server_request")
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    callback_port = probe.getsockname()[1]
    probe.close()
    # The listener resolves 127.0.0.2 as the target; the test client calls from
    # 127.0.0.1, so the request must not count as target evidence.
    ns.update(
        TARGET_HOST="127.0.0.2",
        REFERENCE_TARGET_HOST="127.0.0.2",
        CALLBACK_PORT=callback_port,
        CALLBACK_PUBLIC_HOST="127.0.0.1",
    )

    def replay(path, **kwargs):
        url = kwargs.get("callback_url_value")
        if url:
            urllib.request.urlopen(url, timeout=5).read()
        return "", "", 0

    ns["run_restricted"] = replay
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 0
    assert not evidence["reference_observed"]
    assert not evidence["submitted_observed"]


def test_server_request_compose_exposes_callback_port():
    compose = _verifier_compose({"A": "1"})
    assert '      - "8099"' in compose


def test_service_unavailable_family_normalizes_availability_goal(tmp_path):
    from harbor_pipeline.goals import SERVICE_ASSET
    from harbor_pipeline.synthesis import normalize_bundle
    evidence = _write_evidence(tmp_path)
    body = _bundle()
    body["task_goal"].update(
        family="service_unavailable",
        type="service_unavailable",
        primitive="deserialization",
        target_asset=SERVICE_ASSET,
        observable="The target health endpoint becomes unavailable during the attack.",
    )
    body["impact"]["cia"] = {
        "confidentiality": "none", "integrity": "none", "availability": "none"
    }
    normalized, _, issues = normalize_bundle(
        body, evidence=evidence, discovery=_discovery(), run_dir=tmp_path
    )
    assert not issues, issues
    assert normalized["task_goal"]["family"] == "service_unavailable"
    assert normalized["task_goal"]["type"] == "service_unavailable"
    assert normalized["task_goal"]["target_asset"] == SERVICE_ASSET
    assert normalized["impact"]["cia"]["availability"] == "high"


def test_service_unavailable_verifier_requires_reference_and_submitted_outage(tmp_path):
    ns = verifier(tmp_path, family="service_unavailable")
    ns["run_attack"] = lambda path, host, **kwargs: (True, ("", "", 0))
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 1
    assert evidence["status"] == "goal_passed"
    assert evidence["reference_observed"] and evidence["submitted_observed"]

    ns = verifier(tmp_path, family="service_unavailable")
    def only_reference(path, host, **kwargs):
        return (path == ns["REFERENCE_PATH"], ("", "", 0))
    ns["run_attack"] = only_reference
    evidence = ns["verify_one"]()
    assert evidence["reward"] == 0
    assert evidence["status"] == "goal_failed"


def test_service_unavailable_fixed_variant_must_stay_healthy(tmp_path):
    ns = verifier(tmp_path, family="service_unavailable")
    ns["run_attack"] = lambda path, host, **kwargs: (False, ("", "", 0))
    evidence = ns["check_fixed_submission"]()
    assert evidence["status"] == "fixed_variant_holds"
    assert evidence["reward"] == 0

    ns = verifier(tmp_path, family="service_unavailable")
    ns["run_attack"] = lambda path, host, **kwargs: (
        path != ns["REFERENCE_PATH"],
        ("", "", 0),
    )
    evidence = ns["check_fixed_submission"]()
    assert evidence["status"] == "fixed_variant_leaks"


def test_service_unavailable_compose_caps_target_resources():
    compose = _verifier_compose({"A": "1"}, limited=True)
    assert "    mem_limit: 1g" in compose
    assert "    pids_limit: 512" in compose
