"""The optional cold-build check must be an explicit boolean choice."""
import pytest

from harbor_pipeline.config import load_config
from harbor_pipeline.contracts import load_experiments
from harbor_pipeline.util import PipelineError


def test_default_config_disables_cold_rebuild_and_retires_old_probes():
    assert load_config().pipeline.cold_rebuild is False
    ids = {experiment.id for experiment in load_experiments()}
    assert {"T03", "T04", "T09", "T12"} <= ids
    assert not {"T08", "T11"} & ids


@pytest.mark.parametrize("value,expected", [("true", True), ("false", False)])
def test_config_can_enable_or_disable_cold_rebuild(tmp_path, value, expected):
    path = tmp_path / "pipeline.toml"
    path.write_text(f"[pipeline]\ncold_rebuild = {value}\n", encoding="utf-8")
    assert load_config(path).pipeline.cold_rebuild is expected


@pytest.mark.parametrize("value", ['"false"', "1"])
def test_cold_rebuild_rejects_non_boolean_config(tmp_path, value):
    path = tmp_path / "pipeline.toml"
    path.write_text(f"[pipeline]\ncold_rebuild = {value}\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="cold_rebuild must be a boolean"):
        load_config(path)


def test_batch_budget_only_includes_cold_builds_when_enabled(tmp_path):
    from harbor_pipeline.batch import Candidate, plan_batch, _difficulty_baseline
    options = dict(run_id="test-plan", profile="qualification", workers=1,
                   output_root=tmp_path, max_repairs=0)
    normal = plan_batch([Candidate("CVE-2024-23334")], **options)
    cold = plan_batch([Candidate("CVE-2024-23334")], **options, cold_rebuild=True)
    assert cold.limits["trials"] - normal.limits["trials"] == 6
    assert cold.limits["builds"] - normal.limits["builds"] == 12
    assert _difficulty_baseline({}, tmp_path)["seed_consistent"] is None
