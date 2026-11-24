"""The selected affected range must describe the selected commit pair's branch."""

from types import SimpleNamespace

from harbor_pipeline.discovery import Discovery, DiscoveryRef
from harbor_pipeline.discovery_refs import (
    _align_affected_range,
    _candidate_for_branch,
    _search_branch_pair,
)

REPO = "php/php-src"
VULN = "1" * 40
FIX = "2" * 40


def _rows():
    return (
        {"series": "8.2", "introduced": "8.2.0", "fixed": "8.2.35", "source_ids": ["cve"]},
        {"series": "8.3", "introduced": "8.3.0", "fixed": "8.3.36", "source_ids": ["cve"]},
        {"series": "8.4", "introduced": "8.4.0", "fixed": "8.4.27", "source_ids": ["cve"]},
        {"series": "8.5", "introduced": "8.5.0", "fixed": "8.5.12", "source_ids": ["cve"]},
    )


class FakeMetadata:
    """Only the branch/ancestry surface used by range alignment."""

    def __init__(self, *, containing=(), branches=()):
        self.containing = set(containing)
        self.branches = dict(branches)
        self.notes = []
        self.decisions = []

    def release_tag(self, repo, value):
        return SimpleNamespace(resolved_commit=f"tag:{value}")

    def precedes(self, repo, base, head, **_kwargs):
        if head.startswith(("tag:", "branch:")):
            head = head.split(":", 1)[1]
        return (base, head) in self.containing

    def branch(self, repo, series):
        return self.branches.get(series)

    def decision(self, rule, outcome, reason, **details):
        self.decisions.append({"rule": rule, "outcome": outcome, **details})


def _discovery(**overrides):
    values = {
        "cve_id": "CVE-2026-109618",
        "package": REPO,
        "ecosystem": "generic",
        "affected_range": ">= 8.5.0, < 8.5.12",
        "affected_ranges": _rows(),
        "vulnerable": DiscoveryRef("commit", VULN, repository=REPO, resolved_commit=VULN),
        "fixed": DiscoveryRef("commit", FIX, repository=REPO, resolved_commit=FIX),
        "fix_commit": FIX,
    }
    values.update(overrides)
    return Discovery(**values)


def test_declared_fixed_tag_lag_selects_latest_actual_fixed_release():
    # Every branch gets the shared fix in the next patch release. The latest
    # affected branch is the default, and its range must name 8.5.13, not the
    # advisory's 8.5.12 which does not contain the patch.
    metadata = FakeMetadata(
        containing={(FIX, "8.5.13"), (FIX, "8.5")},
        branches={"8.5": "branch:8.5"},
    )
    aligned = _align_affected_range(metadata, _discovery(), REPO)
    assert aligned.affected_range == ">= 8.5.0, < 8.5.13"
    assert aligned.affected_ranges == _rows()


def test_fix_only_in_older_branch_records_that_older_branch():
    # CVE-2026-109619's 01a40e89 is contained in php-8.2.35 but not in the
    # declared 8.5.12 release; the range must follow the commit, not the
    # advisory's newest branch.
    metadata = FakeMetadata(containing={(FIX, "8.2.35")})
    aligned = _align_affected_range(metadata, _discovery(), REPO)
    assert aligned.affected_range == ">= 8.2.0, < 8.2.35"


def test_shared_fix_uses_the_vulnerable_commits_branch():
    # 512c04e is the 8.2.34-dev vulnerable state. The shared fix 3584a98 also
    # appears in 8.5.13, but that must not relabel the build as 8.5.
    metadata = FakeMetadata(
        containing={(VULN, "8.2.35"), (VULN, "8.3.36"), (FIX, "8.5.13"),
                    (FIX, "8.2"), (FIX, "8.2.36")},
        branches={"8.2": "branch:8.2"},
    )
    aligned = _align_affected_range(metadata, _discovery(), REPO)
    assert aligned.affected_range == ">= 8.2.0, < 8.2.36"


def test_branch_specific_fix_keeps_its_own_series():
    metadata = FakeMetadata(
        containing={(VULN, "8.5.12"), (FIX, "8.5.12")},
    )
    aligned = _align_affected_range(metadata, _discovery(), REPO)
    assert aligned.affected_range == ">= 8.5.0, < 8.5.12"


def test_tag_pair_selects_its_own_release_branch_without_network():
    discovery = _discovery(
        vulnerable=DiscoveryRef("tag", "8.2.34", repository=REPO, resolved_commit=VULN),
        fixed=DiscoveryRef("tag", "8.2.35", repository=REPO, resolved_commit=FIX),
    )
    aligned = _align_affected_range(FakeMetadata(), discovery, REPO)
    assert aligned.affected_range == ">= 8.2.0, < 8.2.35"


def test_prefixed_release_tag_keeps_the_numeric_range():
    # php-src tags are named php-8.2.35; the range still needs a version.
    discovery = _discovery(
        vulnerable=DiscoveryRef("tag", "php-8.2.34", repository=REPO, resolved_commit=VULN),
        fixed=DiscoveryRef("tag", "php-8.2.35", repository=REPO, resolved_commit=FIX),
    )
    aligned = _align_affected_range(FakeMetadata(), discovery, REPO)
    assert aligned.affected_range == ">= 8.2.0, < 8.2.35"


def test_branch_candidate_narrows_multiple_fixes_by_affected_branch():
    metadata = FakeMetadata(containing={(FIX, "8.2.35")})
    candidates = [(FIX, VULN, "src-1"), ("3" * 40, VULN, "src-2")]
    chosen = _candidate_for_branch(metadata, _discovery(), REPO, candidates)
    assert chosen is not None
    candidate, row, actual_fixed = chosen
    assert candidate[0] == FIX
    assert row["series"] == "8.2" and actual_fixed == "8.2.35"


class BranchMetadata:
    def __init__(self):
        self.notes = []
        self.decisions = []
        self.collector = SimpleNamespace(
            sources=[{"id": "src-1", "source_type": "release_notes"}]
        )

    def release_tag(self, repo, value):
        if value == "8.5.12":
            return SimpleNamespace(value="php-8.5.12", resolved_commit="tag:8.5.12")
        return None

    def commits(self, repo, ref, per_page=100):
        return ([{
            "sha": FIX,
            "commit": {"message": "Avoid state corruption via bailout\n\n"
                                 "Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)"},
        }], "src-list")

    def commit(self, repo, sha):
        return ({
            "sha": sha,
            "html_url": f"https://github.com/{repo}/commit/{sha}",
            "commit": {"message": "Avoid state corruption via bailout\n\n"
                                 "Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)"},
            "parents": [{"sha": VULN}],
            "files": [{"filename": "ext/session/session.c", "patch": "@@ -1 +1 @@\n-old\n+new"}],
        }, "src-1")

    def precedes(self, repo, base, head, **_kwargs):
        return True

    def decision(self, rule, outcome, reason, **details):
        self.decisions.append({"rule": rule, "outcome": outcome, **details})


def test_branch_pair_prefers_a_branch_specific_fix_over_global_search():
    metadata = BranchMetadata()
    selected = _search_branch_pair(_discovery(), metadata, REPO)
    assert selected is not None
    assert selected.vulnerable.value == VULN
    assert selected.fixed.value == "php-8.5.12"
    assert selected.fix_commit == FIX
    assert selected.affected_range == ">= 8.5.0, < 8.5.12"
