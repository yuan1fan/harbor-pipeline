"""The framework-owned verifier checks run without Docker."""

from harbor_pipeline import fixtures
from harbor_pipeline.verifier_check import verifier_regression_checks


def test_framework_checks_reject_every_negative_without_a_target():
    results = verifier_regression_checks(fixtures.cve_spec(), synthetic=False)

    # Each probe reaches a distinct verifier branch: a missing artifact, a
    # forged success report, a default-looking secret, and a malformed PoC.
    assert results["T05"]["status"] == "artifact_missing"
    assert results["T05"]["artifact_present"] is False
    assert results["T06"]["status"] == "goal_failed"
    assert results["T07"]["status"] == "goal_failed"
    assert results["T10"]["status"] == "goal_failed"

    for experiment_id in ("T05", "T06", "T07", "T10"):
        evidence = results[experiment_id]
        assert evidence["reward"] == 0.0
        assert evidence["health_ok"] is True
        assert evidence["business_ok"] is True
        assert evidence["reference_observed"] is True
        assert evidence["submitted_observed"] is False

    # The forged and bypass payloads exit cleanly; the invalid PoC does not.
    # If they behaved the same, one check would be testing one shape twice.
    assert results["T06"]["submitted_exit"] == 0
    assert results["T07"]["submitted_exit"] == 0
    assert results["T10"]["submitted_exit"] != 0


def test_framework_checks_are_cached_per_verifier_template():
    spec = fixtures.cve_spec()
    first = verifier_regression_checks(spec, synthetic=False)
    second = verifier_regression_checks(spec, synthetic=False)
    assert first is second
