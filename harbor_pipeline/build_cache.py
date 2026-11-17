"""Bounded, local reuse of a measured image for an unchanged build context.

One entry per build log is retained. Missing images or unfamiliar Dockerfile
syntax cause a normal build; this is not a registry or a source-identity gate.
"""
from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
from pathlib import Path
from string import Template

from .util import PipelineError, digest, no_window_kwargs, read_json, tree_hashes
from .storage import image_labels


def image_identity(docker: str, ref: str) -> str | None:
    try:
        result = subprocess.run(
            [docker, "image", "inspect", "--format", "{{.Id}}", ref],
            capture_output=True, text=True, errors="replace", timeout=5,
            **no_window_kwargs(),
        )
        value = result.stdout.strip()
        if result.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _base_refs(body: str, build_args: dict) -> list[str] | None:
    args, stages, refs = {}, set(), []
    saw_from = False
    # Unsupported constructs disable reuse rather than guessing their inputs.
    if "<<" in body or re.search(r"(?im)^\s*#\s*(?:syntax|escape)\s*=", body):
        return None
    for line in re.sub(r"\\\r?\n", " ", body).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if any(word.startswith("--mount") for word in words[1:]):
            return None  # Mount/secret inputs are not part of this context hash.
        instruction = words[0].upper()
        if instruction == "ARG" and len(words) == 2 and not saw_from:
            key, _, value = words[1].partition("=")
            args[key] = str(build_args.get(key, value))
        if instruction == "FROM":
            saw_from = True
            tokens = [word for word in words[1:] if not word.startswith("--")]
            if len(tokens) not in {1, 3}:
                return None
            ref = Template(tokens[0]).safe_substitute(args)
            if "$" in ref:
                return None
            if ref.lower() not in stages and ref.lower() != "scratch":
                refs.append(ref)
            if len(tokens) == 3:
                if tokens[1].upper() != "AS":
                    return None
                stages.add(tokens[2].lower())
        for word in words[1:]:
            if word.startswith("--from="):
                source = word.partition("=")[2]
                if source.lower() not in stages and not source.isdigit():
                    # External COPY/RUN mounts need a richer Dockerfile parser.
                    return None
    return sorted(set(refs)) if saw_from else None


def build_signature(docker: str, context: Path, dockerfile: Path, *, build_args: dict,
                    product: str | None, product_ref: str | None) -> str | None:
    try:
        body = dockerfile.read_text(encoding="utf-8")
        refs = _base_refs(body, build_args)
        if refs is None:
            return None
        files = tree_hashes(context)
        modes = {name: stat.S_IMODE((context / name).stat().st_mode) for name in files}
        root = Path(__file__).parent
        return digest({
            "protocol": 1, "files": files, "modes": modes, "dockerfile": body,
            "labels": image_labels(context),
            "build_args": build_args, "product": product, "product_ref": product_ref,
            # No --pull is requested. Track locally resolved base tags; a tag
            # becoming available or changing locally invalidates the entry.
            "bases": {ref: image_identity(docker, ref) for ref in refs},
            "environment": {key: os.environ.get(key) for key in (
                "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_DEFAULT_PLATFORM",
                "DOCKER_BUILDKIT", "BUILDX_BUILDER", "BUILDX_CONFIG",
            )},
            "builder": {name: digest((root / name).read_bytes()) for name in (
                "backend.py", "build_cache.py", "runtime_identity.py",
            )},
        })
    except (OSError, ValueError, PipelineError):
        return None


def reuse_image(docker: str, path: Path, signature: str, image_ref: str) -> dict | None:
    try:
        entry = read_json(path)
        record = entry["image"]
        if (not isinstance(record, dict) or not isinstance(record.get("architecture"), str)
                or not isinstance(record.get("dependencies", {}), dict)
                or not isinstance(record.get("runtime_identity", {}), dict)):
            return None
        identity = record["image_digest"]
        if entry["signature"] != signature or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
            return None
        if image_identity(docker, identity) != identity:
            return None
        # Probes render the new revision's tag, then pin it to this immutable ID.
        result = subprocess.run(
            [docker, "image", "tag", identity, image_ref], capture_output=True,
            text=True, errors="replace", timeout=10, **no_window_kwargs(),
        )
        if result.returncode == 0:
            return record
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    return None
