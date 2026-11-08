#!/usr/bin/env python3
"""Sample open-source, web-reachable CVE-2026 candidates for Harbor authoring.

The earlier sample was stratified only by primitive/ecosystem/month and let in
proprietary appliances and products with no public fix. This sampler applies
the hard requirements first:

* a public GitHub repository (or a package ecosystem) is referenced;
* the description is a remote/web-facing issue, not local/physical;
* a fix commit or a GHSA advisory is present;
* the product looks like a package rather than a vendor appliance name;
* candidates already used by previous runs are excluded.

Within the surviving pool it stratifies by a goal-family hint and spreads the
selection across publication months and repositories.
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO_RE = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
BAD_OWNERS = {
    "advisories",
    "cveproject",
    "nomi-sec",
    "trickest",
    "cxsecurity",
    "exploitdb",
    "packetstorm",
}
BAD_REPO = re.compile(r"(?i)(^|[-_])(poc|exploit|advisory|cve-\d+|vuln)([-_]|$)")
WEB = re.compile(
    r"http|web|server|api|endpoint|request|remote|unauthenticated|"
    r"authenticated|service|application",
    re.I,
)
LOCAL = re.compile(
    r"local attack|physical|adjacent|bluetooth|usb|firmware|desktop application|"
    r"mobile app|android|ios app|windows driver|kernel module|browser extension|"
    r"proprietary",
    re.I,
)
VENDOR = re.compile(
    r"\b(juniper|junos|cisco|fortinet|palo alto|citrix adc|f5|checkpoint|"
    r"sonicwall|ivanti|pulse secure|oracle|sap|ibm|vmware|broadcom|dell|hp|arista)\b",
    re.I,
)
VERSION_HINT = re.compile(
    r"before|prior to|fixed in|patched in|through|up to|versions? .* to |"
    r"affects? .* (?:version|release)",
    re.I,
)
DOS = re.compile(
    r"denial of service|\bdos\b|crash|hang|exhaust|unbounded|resource consumption|"
    r"memory exhaustion|cpu exhaustion|infinite loop",
    re.I,
)
SSRF = re.compile(r"server-side request|outbound request|callback url", re.I)
WRITE = re.compile(
    r"arbitrary file write|zip slip|zip-slip|write arbitrary|write files?|"
    r"file write|extract.*outside|path traversal.*write",
    re.I,
)
LISTING = re.compile(
    r"directory listing|list files|file listing|filename|list the contents|"
    r"directory traversal",
    re.I,
)
READ = re.compile(
    r"file read|arbitrary file read|information disclosure|sensitive information|"
    r"read files?|path traversal|secret|credential|token",
    re.I,
)
OTHER = re.compile(
    r"code execution|remote code|command injection|deserialization|sql injection|"
    r"xxe|template injection|auth(?:entication)? bypass",
    re.I,
)

DEFAULT_QUOTAS = {
    "server_request": 25,
    "service_unavailable": 15,
    "secret_read": 30,
    "file_write": 15,
    "directory_listing": 10,
    "other": 5,
}


def repos(item: dict) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for ref in item.get("references", []):
        match = REPO_RE.match(str(ref))
        if not match:
            continue
        owner, repo = match.group(1), match.group(2)
        if owner.lower() in BAD_OWNERS or BAD_REPO.search(repo):
            continue
        found.add((owner, repo))
    return found


def family_hint(item: dict) -> str:
    text = (item.get("description", "") + " " + " ".join(item.get("primitives") or [])).lower()
    if DOS.search(text):
        return "service_unavailable"
    if "ssrf" in (item.get("primitives") or []) or SSRF.search(text):
        return "server_request"
    if WRITE.search(text):
        return "file_write"
    if LISTING.search(text):
        return "directory_listing"
    if READ.search(text):
        return "secret_read"
    if OTHER.search(text):
        return "other"
    return "other"


def repo_matches_product(item: dict) -> bool:
    product = re.sub(r"[^a-z0-9]", "", str(item.get("product") or "").lower())
    for _, repo in repos(item):
        token = re.sub(r"[^a-z0-9]", "", repo.lower())
        if not token:
            continue
        if token in product or product in token:
            return True
    return False


def eligible(item: dict, excluded: set[str]) -> bool:
    cve = item.get("cve_id", "")
    product = str(item.get("product") or "")
    published = str(item.get("published") or "")
    description = str(item.get("description") or "")
    if cve in excluded or not cve.startswith("CVE-2026-"):
        return False
    if published[:7] not in {f"2026-{month:02d}" for month in range(1, 11)}:
        return False
    if not product or " " in product or len(product) > 60 or VENDOR.search(product):
        return False
    if not WEB.search(description) or LOCAL.search(description):
        return False
    if not repos(item) and not item.get("ecosystem_hint"):
        return False
    if not item.get("commit_refs") and not any(
        "GHSA" in str(ref)
        for ref in item.get("references", []) + item.get("advisory_refs", [])
    ):
        return False
    if not VERSION_HINT.search(description) and not item.get("commit_refs"):
        return False
    return True


def score(item: dict) -> tuple:
    return (
        1 if repo_matches_product(item) else 0,
        1 if item.get("commit_refs") else 0,
        1 if item.get("ecosystem_hint") else 0,
        int(item.get("priority") or 0),
    )


def pick(
    pool: list[dict],
    quota: int,
    rng: random.Random,
    repo_counts: Counter,
    month_counts: Counter,
) -> list[dict]:
    # Prefer month diversity, then repo diversity, then the quality score.
    ordered = sorted(pool, key=lambda item: (score(item), rng.random()), reverse=True)
    picked: list[dict] = []
    remaining = list(ordered)
    while remaining and len(picked) < quota:
        month = min(
            (item.get("published", "")[:7] for item in remaining),
            key=lambda value: (month_counts[value], value),
        )
        candidates = [item for item in remaining if item.get("published", "")[:7] == month]
        candidates.sort(key=lambda item: score(item), reverse=True)
        chosen = None
        for item in candidates:
            repo = next(iter(repos(item)), ("", ""))
            if repo_counts[repo] < 2:
                chosen = item
                break
        if chosen is None:
            chosen = candidates[0]
        remaining.remove(chosen)
        picked.append(chosen)
        repo_counts[next(iter(repos(chosen)), ("", ""))] += 1
        month_counts[chosen.get("published", "")[:7]] += 1
    return picked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=Path, default=Path("candidates/cve-2026.json"))
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261108)
    args = parser.parse_args()

    raw = json.loads(args.pool.read_text(encoding="utf-8"))
    items = raw["candidates"] if isinstance(raw, dict) else raw
    excluded: set[str] = set()
    for path in args.exclude:
        data = json.loads(path.read_text(encoding="utf-8"))
        candidates = data["candidates"] if isinstance(data, dict) else data
        excluded.update(str(item["cve_id"]) for item in candidates)

    surviving = [item for item in items if eligible(item, excluded)]
    groups: dict[str, list[dict]] = defaultdict(list)
    for item in surviving:
        groups[family_hint(item)].append(item)

    rng = random.Random(args.seed)
    repo_counts: Counter = Counter()
    month_counts: Counter = Counter()
    quotas = dict(DEFAULT_QUOTAS)
    total_quota = sum(quotas.values())
    if total_quota != args.count:
        quotas = {key: max(0, round(value * args.count / total_quota)) for key, value in quotas.items()}

    chosen: list[dict] = []
    for family, quota in quotas.items():
        chosen.extend(pick(groups.get(family, []), quota, rng, repo_counts, month_counts))

    # Fill any shortfall from the largest remaining groups without duplicates.
    seen = {item["cve_id"] for item in chosen}
    leftovers = [
        item
        for item in sorted(surviving, key=lambda item: score(item), reverse=True)
        if item["cve_id"] not in seen
    ]
    for item in leftovers:
        if len(chosen) >= args.count:
            break
        chosen.append(item)

    chosen = chosen[: args.count]
    chosen.sort(key=lambda item: item["cve_id"])
    args.output.write_text(json.dumps(chosen, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    print(f"pool={len(items)} eligible={len(surviving)} selected={len(chosen)}")
    print("families", dict(Counter(family_hint(item) for item in chosen)))
    print("months", dict(sorted(Counter(item["published"][:7] for item in chosen).items())))
    print("repos", len({next(iter(repos(item)), ("", "")) for item in chosen}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
