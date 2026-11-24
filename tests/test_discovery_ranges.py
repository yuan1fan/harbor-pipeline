"""Structured affected-branch output for multi-branch advisories."""
import json

from harbor_pipeline.discovery import Discovery, _affected_ranges


def _cve_record():
    return {
        "containers": {
            "cna": {
                "affected": [{
                    "vendor": "PHP Group",
                    "product": "PHP",
                    "versions": [
                        {"status": "affected", "version": "8.2.*", "lessThan": "8.2.35", "versionType": "semver"},
                        {"status": "affected", "version": "8.3.*", "lessThan": "8.3.36", "versionType": "semver"},
                        {"status": "affected", "version": "8.4.*", "lessThan": "8.4.27", "versionType": "semver"},
                        {"status": "affected", "version": "8.5.*", "lessThan": "8.5.12", "versionType": "semver"},
                    ],
                }]
            }
        }
    }


def _osv_record():
    return {
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "database_specific": {
                    "extracted_events": [
                        {"range": [{"introduced": "8.2.0"}, {"fixed": "8.2.35"}]},
                        {"range": [{"introduced": "8.3.0"}, {"fixed": "8.3.36"}]},
                        {"range": [{"introduced": "8.4.0"}, {"fixed": "8.4.27"}]},
                        {"range": [{"introduced": "8.5.0"}, {"fixed": "8.5.12"}]},
                    ]
                },
            }]
        }]
    }


def test_all_affected_branches_are_kept_and_sources_merged():
    rows = _affected_ranges(
        _cve_record(),
        _osv_record(),
        cve_source_id="src-1-cve-record",
        osv_source_id="src-2-other",
    )
    assert [(row["series"], row["introduced"], row["fixed"]) for row in rows] == [
        ("8.2", "8.2.0", "8.2.35"),
        ("8.3", "8.3.0", "8.3.36"),
        ("8.4", "8.4.0", "8.4.27"),
        ("8.5", "8.5.0", "8.5.12"),
    ]
    for row in rows:
        assert row["source_ids"] == ["src-1-cve-record", "src-2-other"]


def test_discovery_json_round_trips_affected_ranges():
    rows = _affected_ranges(
        _cve_record(), _osv_record(),
        cve_source_id="src-1", osv_source_id="src-2",
    )
    discovery = Discovery(
        cve_id="CVE-2026-109618",
        package="php/php-src",
        ecosystem="generic",
        affected_range=">= 8.5.0, < 8.5.12",
        affected_ranges=rows,
    )
    payload = json.loads(json.dumps(discovery.to_json()))
    assert len(payload["affected_ranges"]) == 4
    restored = Discovery.from_json(payload)
    assert restored.affected_range == ">= 8.5.0, < 8.5.12"
    assert restored.affected_ranges == rows


def test_selected_pair_is_still_the_latest_branch():
    rows = _affected_ranges(_cve_record(), _osv_record())
    # Discovery keeps the selector's chosen range separate from the complete
    # branch list; the author can request an earlier branch without changing
    # the default.
    assert rows[-1] == {
        "series": "8.5",
        "introduced": "8.5.0",
        "fixed": "8.5.12",
        "source_ids": [],
    }
