"""Scoped image lifecycle: all revisions, including partially failed builds.

Never remove experiment files, base images, images used by any container, or
the measured images of a released task. Legacy tags have no run ownership, so
any unfinished peer candidate protects the entire CVE namespace.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .state import _pid_alive
from .util import PipelineError, digest, no_window_kwargs, read_json, write_json

MANAGED = "harbor-pipeline.managed"
OWNER = "harbor-pipeline.owner"
TERMINAL = {"RELEASED", "QUARANTINED", "UNSUPPORTED"}
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


def candidate_root(path: Path) -> Path | None:
    for parent in (path.resolve(), *path.resolve().parents):
        if CVE.fullmatch(parent.name) and (parent / "state.json").is_file():
            return parent
    return None


def image_labels(context: Path) -> dict[str, str]:
    root = candidate_root(context)
    return {MANAGED: "true", **({OWNER: digest(str(root)), "harbor-pipeline.cve": root.name} if root else {})}


def _docker(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    docker = shutil.which("docker")
    if not docker:
        raise PipelineError("Docker CLI is not available")
    return subprocess.run([docker, *args], capture_output=True, text=True,
                          timeout=timeout, **no_window_kwargs())


def _json_command(args: list[str]) -> list[dict]:
    result = _docker(args)
    if result.returncode:
        raise PipelineError(f"Docker inventory failed: {result.stderr[-1000:]}")
    return json.loads(result.stdout)


def inventory() -> tuple[list[dict], set[str]]:
    result = _docker(["image", "ls", "-q", "--no-trunc"])
    if result.returncode:
        raise PipelineError("Cannot list Docker images")
    ids = sorted(set(result.stdout.split()))
    images = []
    for offset in range(0, len(ids), 50):
        images.extend(_json_command(["image", "inspect", *ids[offset:offset + 50]]))
    result = _docker(["ps", "-aq"])
    if result.returncode:
        raise PipelineError("Cannot list Docker containers")
    used: set[str] = set()
    ids = result.stdout.split()
    for offset in range(0, len(ids), 50):
        used.update(item["Image"] for item in _json_command(["inspect", *ids[offset:offset + 50]]))
    return images, used


def _digests(value) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "image_digest" and isinstance(item, str):
                result.add(item)
            result.update(_digests(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_digests(item))
    return result


def protection(root: Path) -> tuple[set[str], set[str]]:
    """Protect active candidates and released digests across sibling runs."""
    active, protected = set(), set()
    # root is runs/<run-id>; sibling runs can use the same historical tags.
    for path in root.parent.glob("*/CVE-*/state.json"):
        try:
            state = read_json(path)
            name = path.parent.name
            lease = path.parent / ".lease"
            busy = lease.exists() and _pid_alive(int(read_json(lease).get("pid", 0)))
            if busy or state.get("state") not in TERMINAL:
                active.add(name)
            # Protect releases even when a recheck has since quarantined them.
            manifests = list((path.parent / "release").rglob("build-manifest.json"))
            if state.get("state") == "RELEASED":
                manifests.append(path.parent / "image-set.json")
            for manifest in manifests:
                if manifest.is_file():
                    protected.update(_digests(read_json(manifest)))
        except (OSError, ValueError, TypeError, PipelineError):
            # A malformed record cannot authorize deletion.
            active.add(path.parent.name)
    return active, protected


def plan_cleanup(root: Path, images: list[dict], used: set[str], *, only_cve: str | None = None) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise PipelineError(f"Run directory does not exist: {root}")
    active, protected = protection(root)
    owners: dict[str, str] = {}
    candidates = set()
    for path in root.glob("CVE-*/state.json"):
        name = path.parent.name
        if not CVE.fullmatch(name) or (only_cve and name != only_cve) or path.parent.is_symlink():
            continue
        try:
            if read_json(path).get("state") in TERMINAL:
                candidates.add(name)
                owners[digest(str(path.parent.resolve()))] = name
        except (OSError, ValueError, PipelineError):
            continue
    removable, skipped = [], []
    for item in images:
        labels = item.get("Config", {}).get("Labels") or {}
        tags = item.get("RepoTags") or []
        tagged_candidates = set()
        owned_tags = []
        for tag in tags:
            match = re.fullmatch(r"harbor-pipeline/(cve-[0-9]{4}-[0-9]{4,})-(?:vulnerable|fixed)-r[0-9]+(?:-[a-z0-9-]+)?-?(?:target|verifier|agent):[^:]+", tag)
            if match and match[1].upper() in candidates:
                tagged_candidates.add(match[1].upper())
                owned_tags.append(tag)
        owner_cve = owners.get(labels.get(OWNER))
        if not tagged_candidates and not owner_cve:
            continue
        names = tagged_candidates | ({owner_cve} if owner_cve else set())
        reason = ""
        if names & active:
            reason = "unfinished or leased candidate in this or a sibling run"
        elif item["Id"] in used:
            reason = "referenced by a container (including stopped containers)"
        elif item["Id"] in protected:
            reason = "measured release image"
        elif labels.get(OWNER) and not owner_cve:
            reason = "owned by another run"
        elif any(tag not in owned_tags for tag in tags) and not owner_cve:
            reason = "additional non-candidate tags"
        refs = owned_tags or ([item["Id"]] if not tags and owner_cve else [])
        # Owner labels also cover T09 and debug tags outside the legacy prefix.
        if owner_cve and not owned_tags:
            refs = [tag for tag in tags if tag.startswith("harbor-pipeline/rebuild-")] or refs
        for ref in refs:
            record = {"ref": ref, "image_id": item["Id"], "cves": sorted(names)}
            if reason:
                skipped.append({**record, "reason": reason})
            else:
                removable.append(record)
    return {"run_dir": str(root), "remove": removable, "skip": skipped,
            "protected_cves": sorted(active & candidates)}


def cleanup_run(root: Path, *, apply: bool = False, only_cve: str | None = None) -> dict:
    images, used = inventory()
    plan = plan_cleanup(root, images, used, only_cve=only_cve)
    plan.update(applied=apply, removed=[], errors=[])
    if apply:
        for item in plan["remove"]:
            # A tag can have been rebuilt since inventory; never delete its replacement.
            inspected = _json_command(["image", "inspect", item["ref"]])
            if inspected[0]["Id"] != item["image_id"]:
                plan["errors"].append({"ref": item["ref"], "reason": "identity changed"})
                continue
            active, protected = protection(root.resolve())
            if active.intersection(item["cves"]):
                plan["errors"].append({"ref": item["ref"], "reason": "candidate became active"})
                continue
            if item["image_id"] in protected:
                plan["errors"].append({"ref": item["ref"], "reason": "newly protected release image"})
                continue
            containers = _docker(["ps", "-aq", "--filter", f"ancestor={item['image_id']}"])
            if containers.returncode or containers.stdout.strip():
                plan["errors"].append({"ref": item["ref"], "reason": "container reference present or unreadable"})
                continue
            result = _docker(["image", "rm", item["ref"]])  # never --force
            if result.returncode == 0:
                plan["removed"].append(item["ref"])
            else:
                plan["errors"].append({"ref": item["ref"], "reason": result.stderr[-500:]})
        output = root / only_cve if only_cve else root
        write_json(output / "storage-cleanup.json", plan)
    return plan


def cleanup_replaced_images(context: Path) -> list[str]:
    """Reap superseded builds during a long author session, before it ends.

    Only untagged images labelled with this exact candidate owner are eligible.
    Named versions, release identities and running/debug targets are retained.
    """
    root = candidate_root(context)
    if root is None:
        return []
    result = _docker(["image", "ls", "-q", "--no-trunc", "--filter", "dangling=true",
                      "--filter", f"label={OWNER}={digest(str(root))}"])
    if result.returncode:
        return []
    identities = sorted(set(result.stdout.split()))
    if not identities:
        return []
    _, protected = protection(root.parent)
    removed = []
    for identity in identities:
        if identity in protected:
            continue
        image = _json_command(["image", "inspect", identity])[0]
        if image.get("RepoTags") or (image.get("Config", {}).get("Labels") or {}).get(OWNER) != digest(str(root)):
            continue
        containers = _docker(["ps", "-aq", "--filter", f"ancestor={identity}"])
        if containers.returncode or containers.stdout.strip():
            continue
        if _docker(["image", "rm", identity]).returncode == 0:
            removed.append(identity)
    return removed
