"""Docker build execution and immutable artifact identity.

Harbor rebuilds images itself during a trial. This module builds the same
contexts first so their digests can be frozen into the BuildManifest, and so a
build failure is attributed to the candidate rather than to a later trial.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .errors import TaskError
from .util import PipelineError, read_json, write_json

_CACHE_RE = re.compile(r"(?im)^\s*(?:=>\s*)?CACHED\s*$")


@dataclass
class ImageBuild:
    name: str
    context: Path
    dockerfile: Path
    image_ref: str
    image_digest: str
    architecture: str
    duration_sec: float
    log_path: Path
    cached: bool = False
    dependencies: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "image_ref": self.image_ref,
            "image_digest": self.image_digest,
            "architecture": self.architecture,
            "duration_sec": round(self.duration_sec, 2),
            "log": str(self.log_path),
            "cached": self.cached,
            "dependencies": dict(self.dependencies),
        }


def docker_binary() -> str:
    resolved = shutil.which("docker")
    if not resolved:
        raise TaskError("infra_error", "docker is not on PATH; a Docker daemon is required")
    return resolved


def _run(command: list[str], *, timeout: int, log_path: Path) -> subprocess.CompletedProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        text = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        log_path.write_text(text + "\nTIMEOUT\n", encoding="utf-8")
        raise TaskError("build_error", f"Build exceeded {timeout}s: {' '.join(command[:4])}") from exc
    log_path.write_text(
        f"$ {' '.join(command)}\n\n{completed.stdout}\n{completed.stderr}\n",
        encoding="utf-8",
    )
    return completed


def inspect_image(image_ref: str, *, dockerfile: Path) -> tuple[str, str]:
    docker = docker_binary()
    completed = subprocess.run(
        [docker, "image", "inspect", image_ref, "--format", "{{.Id}} {{.Architecture}}"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise TaskError("build_error", f"Cannot inspect built image {image_ref}")
    parts = completed.stdout.strip().split()
    if not parts:
        raise TaskError("build_error", f"Image inspect returned no identity for {image_ref}")
    return parts[0], (parts[1] if len(parts) > 1 else "unknown")


def dependency_lock(context: Path) -> dict[str, str]:
    """Best-effort pinned dependency list for the target image."""
    lock: dict[str, str] = {}
    requirements = context / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                lock[name.strip()] = version.strip()
            else:
                lock[line] = "unpinned"
    package_json = context / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        for name, version in (data.get("dependencies") or {}).items():
            lock[name] = str(version)
    return lock


def build_image(
    *,
    name: str,
    context: Path,
    image_ref: str,
    log_path: Path,
    timeout_sec: int = 900,
    dockerfile: Path | None = None,
    no_cache: bool = False,
    build_args: dict[str, str] | None = None,
) -> ImageBuild:
    if not context.is_dir():
        raise TaskError("build_error", f"Missing build context {context}")
    dockerfile = dockerfile or (context / "Dockerfile")
    if not dockerfile.is_file():
        raise TaskError("build_error", f"Missing Dockerfile {dockerfile}")
    docker = docker_binary()
    command = [
        docker,
        "build",
        "-t",
        image_ref,
        "-f",
        str(dockerfile),
    ]
    if no_cache:
        command.append("--no-cache")
    for key, value in (build_args or {}).items():
        command.extend(["--build-arg", f"{key}={value}"])
    command.append(str(context))
    started = time.monotonic()
    completed = _run(command, timeout=timeout_sec, log_path=log_path)
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-8:]
        raise TaskError(
            "build_error",
            f"docker build failed for {name}: " + " | ".join(tail),
            detail={"log": str(log_path)},
        )
    duration = time.monotonic() - started
    digest, architecture = inspect_image(image_ref, dockerfile=dockerfile)
    return ImageBuild(
        name=name,
        context=context,
        dockerfile=dockerfile,
        image_ref=image_ref,
        image_digest=digest,
        architecture=architecture,
        duration_sec=duration,
        log_path=log_path,
        cached=bool(_CACHE_RE.search(completed.stdout or "")),
        dependencies=dependency_lock(context),
    )


def build_task_images(
    *,
    task_dir: Path,
    variant: str,
    revision: int,
    log_dir: Path,
    timeout_sec: int = 900,
    no_cache: bool = False,
    harbor_version: str = "0.23.0",
) -> dict:
    """Build agent, target, and verifier images and return an image set."""
    tag_base = f"harbor-pipeline/{task_dir.parent.name}-{variant}-r{revision}".lower()
    builds = {}
    plans = {
        "agent": (task_dir / "environment", f"{tag_base}-agent"),
        "target": (task_dir / "environment" / "target", f"{tag_base}-target"),
        "verifier": (task_dir / "tests", f"{tag_base}-verifier"),
    }
    for name, (context, ref) in plans.items():
        if not context.is_dir():
            raise TaskError("build_error", f"Task is missing the {name} build context {context}")
        builds[name] = build_image(
            name=name,
            context=context,
            image_ref=ref,
            log_path=log_dir / f"build-{name}.log",
            timeout_sec=timeout_sec,
            no_cache=no_cache,
        )
    return {
        "tag_base": tag_base,
        "harbor_version": harbor_version,
        "images": {name: build.to_json() for name, build in builds.items()},
        "target_digest": builds["target"].image_digest,
        "architecture": builds["target"].architecture,
        "dependencies": builds["target"].dependencies,
    }


def write_image_set(path: Path, image_set: dict) -> Path:
    write_json(path, image_set)
    return path


def read_image_set(path: Path) -> dict:
    if not path.is_file():
        raise PipelineError(f"Missing image set {path}")
    return read_json(path)
