"""Registry lookups that replace the repairer's version guessing."""

import json
from types import SimpleNamespace

from harbor_pipeline import registry
from harbor_pipeline.config import SourceSettings
from harbor_pipeline.errors import TaskError


def _fake(body: bytes):
    def fetch(_url, _settings, max_redirects=3):
        return SimpleNamespace(body=body)

    return fetch


def test_lookup_parses_each_supported_registry(monkeypatch):
    settings = SourceSettings()

    monkeypatch.setattr(
        registry, "fetch",
        _fake(json.dumps({"releases": {"1.0.0": [], "1.2.0": []}}).encode()),
    )
    result = registry.lookup("pypi", "foo", settings)
    assert result["versions"][:2] == ["1.2.0", "1.0.0"]

    monkeypatch.setattr(
        registry, "fetch",
        _fake(json.dumps({"versions": {"1.0.0": {}, "2.0.0": {}}}).encode()),
    )
    assert registry.lookup("npm", "@scope/pkg", settings)["versions"][0] == "2.0.0"

    monkeypatch.setattr(registry, "fetch", _fake(b"v1.0.0\nv1.1.0\n"))
    assert "v1.1.0" in registry.lookup("go", "example.com/mod", settings)["versions"]

    monkeypatch.setattr(
        registry, "fetch",
        _fake(b"<metadata><versioning><versions>"
              b"<version>1.0</version><version>2.0</version>"
              b"</versions></versioning></metadata>"),
    )
    assert registry.lookup("maven", "com.example:lib", settings)["versions"][0] == "2.0"


def test_lookup_rejects_unsafe_names_and_reports_fetch_failure(monkeypatch):
    settings = SourceSettings()
    assert "error" in registry.lookup("pypi", "../evil", settings)

    def failing(_url, _settings, max_redirects=3):
        raise TaskError("source_error", "HTTP 404 not found")

    monkeypatch.setattr(registry, "fetch", failing)
    result = registry.lookup("npm", "missing", settings)
    assert "error" in result


def test_build_context_includes_log_and_real_versions(tmp_path, monkeypatch):
    target = tmp_path / "environment" / "target"
    target.mkdir(parents=True)
    (target / "requirements.txt").write_text("foo==9.9.9\n", encoding="utf-8")

    monkeypatch.setattr(
        registry, "fetch",
        _fake(json.dumps({"releases": {"1.0.0": [], "1.2.0": []}}).encode()),
    )
    context = registry.build_context(
        spec={"product": {"ecosystem": "pypi"}},
        task_dir=tmp_path,
        settings=SourceSettings(),
        log_tail="ERROR: No matching distribution found for foo==9.9.9",
    )
    assert "No matching distribution" in context
    assert "foo" in context and "9.9.9" in context
    assert "1.2.0" in context
    assert "do not guess" in context
