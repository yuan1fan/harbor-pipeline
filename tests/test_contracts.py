import copy

import pytest

from harbor_pipeline import contracts, fixtures
from harbor_pipeline.contracts import ContractError
from harbor_pipeline.util import PipelineError


CASES = {
    "evidence-index": fixtures.evidence_index,
    "cve-spec": fixtures.cve_spec,
    "build-manifest": fixtures.build_manifest,
    "trial-record": fixtures.trial_record,
    "evaluation": fixtures.evaluation,
    "dataset-manifest": fixtures.dataset_manifest,
}


@pytest.mark.parametrize("name,builder", CASES.items())
def test_all_contracts_accept_canonical_examples(name, builder):
    contracts.validate(name, builder())


@pytest.mark.parametrize("name,builder", CASES.items())
def test_contracts_reject_unknown_fields(name, builder):
    data = builder()
    data["unexpected"] = True
    with pytest.raises(ContractError):
        contracts.validate(name, data)


def test_missing_required_field_is_rejected():
    data = fixtures.cve_spec()
    del data["root_cause"]
    with pytest.raises(ContractError, match="root_cause"):
        contracts.validate("cve-spec", data)


def test_unknown_assertion_status_is_rejected():
    data = fixtures.cve_spec()
    data["assertions"][0]["status"] = "maybe"
    with pytest.raises(ContractError):
        contracts.validate("cve-spec", data)


def test_unknown_error_category_is_rejected():
    data = fixtures.trial_record(error_category="made_up")
    with pytest.raises(ContractError):
        contracts.validate("trial-record", data)


def test_policy_weights_total_one_hundred():
    policy = contracts.load_policy()
    assert policy.weight_total() == 100.0
    assert policy.profile("qualification").min_valid_trials == 3


def test_matrix_repeats_uses_the_profile_as_a_floor():
    policy = contracts.load_policy()
    qualification = policy.profile("qualification")
    assert qualification.trials == 3
    assert contracts.matrix_repeats(qualification) == 3
    # A task author can raise the count for a nondeterministic exploit.
    assert contracts.matrix_repeats(qualification, 8) == 8
    assert contracts.matrix_repeats(qualification, "12") == 12


def test_matrix_repeats_is_bounded_and_ignores_junk():
    policy = contracts.load_policy()
    qualification = policy.profile("qualification")
    assert contracts.matrix_repeats(qualification, 2) == 3
    assert contracts.matrix_repeats(qualification, 10_000) == contracts.MAX_MATRIX_REPEATS
    assert contracts.matrix_repeats(qualification, None) == 3
    assert contracts.matrix_repeats(qualification, "lots") == 3


def test_mandatory_experiments_are_declared():
    ids = contracts.mandatory_experiment_ids()
    assert {"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T10"} <= set(ids)


def test_fixture_spec_digest_is_stable():
    first = fixtures.cve_spec()
    second = fixtures.cve_spec()
    assert first["frozen_digest"] == second["frozen_digest"]
    tampered = copy.deepcopy(first)
    tampered["root_cause"]["summary"] = "changed"
    assert contracts.freeze_digest(tampered) != fixtures.cve_spec()["frozen_digest"]


def test_fixtures_are_synthetic():
    assert fixtures.FIXTURE_CVE.endswith("0001")


def test_unknown_schema_name_is_rejected():
    with pytest.raises(PipelineError):
        contracts.load_schema("not-a-contract")
