"""Local .env loading: convenience without overriding real environment values."""

import os

import pytest

from harbor_pipeline.config import load_config, load_env_file
from harbor_pipeline.util import PipelineError


def test_env_file_parses_export_quotes_and_comments(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "# local credentials\n"
        "export GITHUB_TOKEN=\"file-token\"\n"
        "NVD_API_KEY='nvd-token'\n"
        "INVALID LINE\n"
        "EMPTY=\n",
        encoding="utf-8",
    )
    environ: dict[str, str] = {}
    load_env_file(path, environ=environ)
    assert environ == {"GITHUB_TOKEN": "file-token", "NVD_API_KEY": "nvd-token", "EMPTY": ""}


def test_env_file_does_not_override_process_environment(tmp_path):
    path = tmp_path / ".env"
    path.write_text("GITHUB_TOKEN=file-token\n", encoding="utf-8")
    environ = {"GITHUB_TOKEN": "process-token"}
    load_env_file(path, environ=environ)
    assert environ["GITHUB_TOKEN"] == "process-token"


def test_load_config_reads_dotenv_next_to_the_profile(tmp_path, monkeypatch):
    (tmp_path / "pipeline.toml").write_text("[pipeline]\n", encoding="utf-8")
    (tmp_path / ".env").write_text("GITHUB_TOKEN=file-token\n", encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("HARBOR_ENV_FILE", raising=False)
    try:
        config = load_config(tmp_path / "pipeline.toml")
        assert config.sources.github_token == "file-token"
    finally:
        # load_env_file writes the process environment on purpose; keep later
        # tests from inheriting this fixture token.
        os.environ.pop("GITHUB_TOKEN", None)


def test_process_environment_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / "pipeline.toml").write_text("[pipeline]\n", encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("GITHUB_TOKEN=file-token\n", encoding="utf-8")
    monkeypatch.setenv("HARBOR_ENV_FILE", str(env_file))
    monkeypatch.setenv("GITHUB_TOKEN", "process-token")
    config = load_config(tmp_path / "pipeline.toml")
    assert config.sources.github_token == "process-token"


def test_author_helper_can_skip_model_placeholder_expansion(tmp_path, monkeypatch):
    # The author environment strips ANTHROPIC_*; helper config loading must
    # still preserve pipeline settings such as the evidence resolver.
    profile = tmp_path / "pipeline.toml"
    profile.write_text(
        "[pipeline]\n"
        "evidence_resolver = true\n"
        "max_evidence_reviews = 2\n"
        "[models.repairer]\n"
        'api_base = "${ANTHROPIC_BASE_URL}"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    with pytest.raises(PipelineError, match="ANTHROPIC_BASE_URL"):
        load_config(profile)
    config = load_config(profile, expand_env=False)
    assert config.pipeline.evidence_resolver is True
    assert config.pipeline.max_evidence_reviews == 2
    assert config.models["repairer"].api_base == "${ANTHROPIC_BASE_URL}"
