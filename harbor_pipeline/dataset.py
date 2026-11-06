"""Group related tasks before splitting; audit every relationship, not just CWE."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .util import digest


def canonical_project(value: str) -> str:
    value = str(value).strip().lower().rstrip("/").removesuffix(".git")
    # PEP 503 equivalences also conservatively group alternative spellings of
    # projects from other ecosystems; over-grouping is safer than leakage.
    return re.sub(r"[-_.]+", "-", value)


def identity_keys(entry: dict) -> set[str]:
    keys = {"project:" + canonical_project(entry["project"])}
    repository = str(entry.get("repository") or "").strip()
    if repository:
        parts = urlsplit(repository)
        keys.add("repo:" + canonical_project(parts.netloc + parts.path if parts.netloc else repository))
    patch = str(entry.get("patch_group") or "").strip().lower()
    if patch and patch not in {"unknown", "none", "unverified"}:
        if re.fullmatch(r"[0-9a-f]{7,40}", patch):
            # Conservative grouping accommodates legacy abbreviated SHAs.
            patch = patch[:7]
        keys.add("patch:" + patch)
    for alias in [entry.get("cve_id"), *(entry.get("aliases") or [])]:
        if alias:
            keys.add("alias:" + str(alias).strip().upper())
    if entry.get("task_digest"):
        keys.add("task:" + entry["task_digest"])
    return keys


def _components(entries: list[dict]) -> list[list[int]]:
    parents = list(range(len(entries)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    seen = {}
    for index, entry in enumerate(entries):
        for key in identity_keys(entry):
            if key in seen:
                parents[root(index)] = root(seen[key])
            else:
                seen[key] = index
    groups = {}
    for index in range(len(entries)):
        groups.setdefault(root(index), []).append(index)
    return list(groups.values())


def split_for_key(key: str) -> str:
    bucket = int(digest(key)[:8], 16) % 100
    return "train" if bucket < 80 else "validation" if bucket < 90 else "test"


def assign_splits(entries: list[dict]) -> list[dict]:
    result = [dict(entry) for entry in entries]
    for group in _components(entries):
        projects = sorted({canonical_project(entries[i]["project"]) for i in group})
        group_id = digest(projects)
        split = split_for_key(projects[0])
        for index in group:
            result[index].update(split=split, split_group=group_id)
    return result


def split_conflicts(entries: list[dict]) -> list[dict]:
    conflicts = []
    for group in _components(entries):
        splits = sorted({entries[i]["split"] for i in group})
        if len(splits) > 1:
            conflicts.append({
                "projects": sorted({entries[i]["project"] for i in group}),
                "cve_ids": sorted({entries[i].get("cve_id", "") for i in group}),
                "splits": splits,
            })
    return conflicts


def merge_manifests(paths, output):
    from .contracts import validate
    from .release import write_dataset_manifest
    from .util import PipelineError, read_json
    by_cve = {}
    for path in paths:
        manifest = read_json(path)
        validate("dataset-manifest", manifest)
        for entry in manifest["tasks"]:
            if entry.get("validation_protocol") != 2:
                raise PipelineError(f"Legacy task {entry['cve_id']} needs protocol-2 revalidation before dataset merging")
            old = by_cve.get(entry["cve_id"])
            if old and (old.get("task_digest"), old["artifact_digest"]) != (entry.get("task_digest"), entry["artifact_digest"]):
                raise PipelineError(f"Different task versions for {entry['cve_id']}; select one before merging")
            by_cve[entry["cve_id"]] = entry
    entries = assign_splits([by_cve[key] for key in sorted(by_cve)])
    write_dataset_manifest(entries, output)
    return {"tasks": len(entries), "output": str(output), "split_conflicts": split_conflicts(entries)}
