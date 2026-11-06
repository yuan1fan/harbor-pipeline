"""Admission must fail on incomplete execution or unsupported provenance."""

from harbor_pipeline import fixtures
from harbor_pipeline.contracts import load_policy
from harbor_pipeline.differential import MatrixResult
from harbor_pipeline.evaluator import evaluate
from harbor_pipeline.trials import Expectation


def candidate():
    spec = fixtures.cve_spec()
    evidence = fixtures.evidence_index()
    sources = {source["id"]: source for source in evidence["sources"]}
    for assertion in spec["assertions"]:
        assertion["evidence_quote"] = assertion["text"]
        assertion["evidence_sha256"] = sources[assertion["source_id"]]["content_sha256"]
    spec["business_probes"] = [{"path": "/static/hello.txt", "status": 200, "contains": "hello"}]
    image = "sha256:" + "a" * 64
    images = {"target_digest": image, "dependencies": {"example-webapp": "1.2.3"}, "variants": {}}
    for variant, version, identity in (("vulnerable", "1.2.3", image), ("fixed", "1.2.4", "sha256:" + "b" * 64)):
        images["variants"][variant] = {
            "target_digest": identity,
            "runtime_identity": {"verified": True, "image": identity, "dependencies": {"example-webapp": version}},
        }
    matrix = MatrixResult(matrix_repeats=3)
    for experiment_id in ("T01", "T02", "T03", "T04", "T05", "T06", "T07", "T10", "T11", "T12"):
        matrix.expectations[experiment_id] = Expectation(experiment_id, True, "observed", "healthy")
    for experiment_id, variant, status, count in (
        ("T03", "vulnerable", "goal_passed", 3), ("T04", "fixed", "fixed_variant_holds", 3),
        ("T05", "vulnerable", "artifact_missing", 1), ("T06", "vulnerable", "goal_failed", 1),
        ("T07", "vulnerable", "goal_failed", 1), ("T10", "vulnerable", "goal_failed", 1),
        ("T09", "vulnerable", "goal_passed", 3), ("T09", "fixed", "fixed_variant_holds", 3),
    ):
        for index in range(count):
            success = status == "goal_passed"
            record = fixtures.trial_record(experiment_id, variant, "passed" if success else "failed", observed=success)
            record.update(artifact_digest=image, seed=index)
            record["trigger_evidence"]["detail"] = status
            if experiment_id == "T09":
                record["_audit"] = {"mode": "clean-rebuild", "actual_image_digest": image, "no_cache": True}
            matrix.records.append(record)
    return dict(spec=spec, evidence=evidence, matrix=matrix, image_set=images,
                policy=load_policy(), profile_name="qualification", skipped_experiments={"T08": "not applicable"})


def test_complete_execution_evidence_is_admitted():
    result = evaluate(**candidate())
    assert result.admitted, result.evaluation["failure_reasons"]


def test_partial_pair_matrix_is_rejected():
    kwargs = candidate()
    records = kwargs["matrix"].records
    records.remove(next(record for record in records if record["experiment_id"] == "T04"))
    result = evaluate(**kwargs)
    assert not result.admitted
    assert any("paired_samples" in reason for reason in result.evaluation["failure_reasons"])


def test_reusing_prebuilt_images_does_not_count_as_clean_rebuilds():
    kwargs = candidate()
    for record in kwargs["matrix"].records:
        if record["experiment_id"] == "T09":
            record["_audit"] = {"mode": "prebuilt-replay"}
    assert not evaluate(**kwargs).admitted


def test_metadata_from_a_different_image_does_not_attest_the_target():
    kwargs = candidate()
    kwargs["image_set"]["variants"]["fixed"]["runtime_identity"]["image"] = "unrelated-image"
    assert not evaluate(**kwargs).admitted


def test_framework_negatives_cannot_replace_candidate_negatives():
    kwargs = candidate()
    for record in kwargs["matrix"].records:
        if record["experiment_id"] == "T07":
            record["_audit"] = {"mode": "framework-verifier"}
    assert not evaluate(**kwargs).admitted


def test_legacy_assertions_without_source_excerpts_do_not_get_grandfathered():
    kwargs = candidate()
    for assertion in kwargs["spec"]["assertions"]:
        assertion.pop("evidence_quote")
        assertion.pop("evidence_sha256")
    assert not evaluate(**kwargs).admitted
