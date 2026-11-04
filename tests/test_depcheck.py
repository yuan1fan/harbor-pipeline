"""Draft-time dependency reality checks and repair-side static hints."""

from __future__ import annotations

from harbor_pipeline import depcheck, repair
from harbor_pipeline.config import SourceSettings


def _bundle(ecosystem="pypi", name="demo", base="python:3.12-slim", files=None):
    return {
        "product": {"ecosystem": ecosystem, "name": name},
        "versions": {"vulnerable_ref": "1.0.0", "fixed_ref": "1.2.0"},
        "target": {"base_image": base, "files": files or {}},
    }


def test_missing_release_is_a_draft_issue(monkeypatch):
    monkeypatch.setattr(
        depcheck, "lookup", lambda ecosystem, name, settings: {"versions": ["1.0.0", "1.1.0"]}
    )
    monkeypatch.setattr(
        depcheck, "version_exists", lambda ecosystem, name, ref, settings: ref == "1.0.0"
    )
    monkeypatch.setattr(depcheck, "_release_metadata", lambda *args: {})
    issues = depcheck.check_bundle(_bundle(), SourceSettings())
    assert any("1.2.0" in issue and "does not exist" in issue for issue in issues)


def test_missing_package_is_a_draft_issue(monkeypatch):
    monkeypatch.setattr(
        depcheck, "lookup", lambda *args: {"error": "HTTP 404 Not Found"}
    )
    issues = depcheck.check_bundle(_bundle(), SourceSettings())
    assert any("not published" in issue for issue in issues)


def test_registry_transport_failure_is_not_a_draft_issue(monkeypatch):
    monkeypatch.setattr(depcheck, "lookup", lambda *args: {"error": "timed out"})
    assert depcheck.check_bundle(_bundle(), SourceSettings()) == []


def test_python_requires_python_incompatibility(monkeypatch):
    monkeypatch.setattr(
        depcheck, "lookup", lambda *args: {"versions": ["1.0.0", "1.2.0"]}
    )
    monkeypatch.setattr(depcheck, "version_exists", lambda *args: True)
    monkeypatch.setattr(
        depcheck, "_release_metadata", lambda *args: {"requires_python": ">=3.6,<3.9"}
    )
    issues = depcheck.check_bundle(_bundle(), SourceSettings())
    assert any("requires Python" in issue for issue in issues)


def test_node_engines_incompatibility(monkeypatch):
    monkeypatch.setattr(
        depcheck, "lookup", lambda *args: {"versions": ["1.0.0", "1.2.0"]}
    )
    monkeypatch.setattr(depcheck, "version_exists", lambda *args: True)
    monkeypatch.setattr(
        depcheck, "_release_metadata", lambda *args: {"engines": {"node": ">=20"}}
    )
    bundle = _bundle(ecosystem="npm", name="demo", base="node:18-bookworm")
    issues = depcheck.check_bundle(bundle, SourceSettings())
    assert any("requires Node" in issue for issue in issues)


def test_go_toolchain_incompatibility(monkeypatch):
    monkeypatch.setattr(
        depcheck, "lookup", lambda *args: {"versions": ["1.0.0", "1.2.0"]}
    )
    monkeypatch.setattr(depcheck, "version_exists", lambda *args: True)
    bundle = _bundle(
        ecosystem="go",
        name="example.com/demo",
        base="golang:1.21-bookworm",
        files={"go.mod": "module x\n\ngo 1.25\n\nrequire example.com/demo v1.0.0\n"},
    )
    issues = depcheck.check_bundle(bundle, SourceSettings())
    assert any("requires Go 1.25" in issue for issue in issues)


def test_set_version_rejects_a_release_outside_the_affected_range():
    spec = {"versions": {"vulnerable_ref": "1.0.0", "fixed_ref": "1.2.0"}}
    bundle = {"versions": {"affected": ">=1.0.0,<1.2.0"}}
    message = repair._set_version(
        {"role": "vulnerable", "ref": "1.3.0"}, spec, bundle
    )
    assert "outside the recorded affected range" in message
    assert spec["versions"]["vulnerable_ref"] == "1.0.0"


def test_set_version_accepts_an_affected_release_and_keeps_the_order():
    spec = {"versions": {"vulnerable_ref": "1.0.0", "fixed_ref": "1.2.0"}}
    bundle = {"versions": {"affected": ">=1.0.0,<1.2.0"}}
    message = repair._set_version(
        {"role": "vulnerable", "ref": "1.1.0"}, spec, bundle
    )
    assert message.startswith("Set vulnerable_ref")
    assert spec["versions"]["vulnerable_ref"] == "1.1.0"
    reverse = repair._set_version(
        {"role": "fixed", "ref": "1.0.5"}, spec, bundle
    )
    assert "must be older" in reverse


def test_readback_scan_points_at_direct_reads_next_to_the_product_import():
    files = {
        "environment/target/server.js": (
            "const demo = require('demopkg');\n"
            "const body = fs.readFileSync(path.join(root, req.query.p));\n"
        ),
        "environment/target/unrelated.js": "fs.readFileSync('config.json');\n",
    }
    scan = repair._readback_scan(files, {"product": {"name": "demopkg"}})
    assert "server.js:2" in scan
    assert "unrelated.js" not in scan


def test_exec_action_is_part_of_the_agent_protocol():
    actions = repair.ACTION_SCHEMA["properties"]["action"]["enum"]
    assert "exec" in actions
    assert "inspect_package" in actions
    assert "exec_image" in repair.RepairTools.__dataclass_fields__
    assert "inspect_package" in repair.RepairTools.__dataclass_fields__
