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
import uuid
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path

from .errors import TaskError
from .util import PipelineError, no_window_kwargs, read_json, write_json

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
            command, capture_output=True, text=True, timeout=timeout,
            **no_window_kwargs(),
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
        **no_window_kwargs(),
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
    go_mod = context / "go.mod"
    if go_mod.is_file():
        lock.update(_go_mod_dependencies(go_mod))
    pom = context / "pom.xml"
    if pom.is_file():
        lock.update(_pom_dependencies(pom))
    return lock


def _go_mod_dependencies(path: Path) -> dict[str, str]:
    """Read pinned module versions from a go.mod, single or block require.

    Go writes the mandatory ``v`` prefix on module versions, while the spec
    stores registry versions without it; normalize so the build lock compares
    equal to ``versions.vulnerable_ref``.
    """
    lock: dict[str, str] = {}
    in_block = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return lock
    for line in lines:
        text = line.split("//", 1)[0].strip()
        if not text:
            continue
        if text.startswith("require ("):
            in_block = True
            continue
        if in_block and text == ")":
            in_block = False
            continue
        if text.startswith("require "):
            text = text[len("require "):].strip()
        elif not in_block:
            continue
        parts = text.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        lock[parts[0]] = parts[1].removeprefix("v").removesuffix("+incompatible")
    return lock


def _pom_dependencies(path: Path) -> dict[str, str]:
    """Read ``group:artifact -> version`` from a pom.xml dependency list."""
    lock: dict[str, str] = {}
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return lock
    for element in root.iter():
        if not element.tag.endswith("dependency"):
            continue
        values: dict[str, str] = {}
        for child in list(element):
            name = child.tag.rsplit("}", 1)[-1]
            values[name] = (child.text or "").strip()
        group = values.get("groupId")
        artifact = values.get("artifactId")
        version = values.get("version")
        if group and artifact and version:
            lock[f"{group}:{artifact}"] = version
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
    tag_base: str | None = None,
) -> dict:
    """Build agent, target, and verifier images and return an image set.

    ``tag_base`` defaults to the legacy task-directory-derived name; the
    pipeline passes an explicit CVE-based base so the fixed variant (rendered
    into a scratch directory) still gets the same prefix the probes pin.
    """
    tag_base = (
        tag_base
        or f"harbor-pipeline/{task_dir.parent.name}-{variant}-r{revision}"
    ).lower()
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


def _container_logs(docker: str, name: str) -> str:
    try:
        completed = subprocess.run(
            [docker, "logs", "--tail", "60", name],
            capture_output=True, text=True, timeout=60,
            **no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return "<no container log>"
    text = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return text or "<empty container log>"


def preflight_target(
    image_ref: str,
    *,
    log_path: Path,
    timeout_sec: int = 60,
    port: int = 8080,
    health_path: str = "/health",
) -> None:
    """Start the built target once and require its health endpoint.

    ``docker build`` proves the image assembles, not that the application
    starts: ``pip install`` and ``npm install`` never import the app. A
    missing runtime dependency or a bad entrypoint then surfaces only inside
    the matrix, where every trial fails before scoring and is filed as an
    infrastructure error, so the repairer never sees a defect it could fix.
    Failing here instead raises ``build_error`` with the container log.
    """
    docker = docker_binary()
    name = f"harbor-preflight-{uuid.uuid4().hex[:10]}"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    started = time.monotonic()

    def record(text: str) -> None:
        lines.append(f"[{time.monotonic() - started:6.1f}s] {text}")
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        created = subprocess.run(
            [docker, "run", "--detach", "--name", name, image_ref],
            capture_output=True,
            text=True,
            timeout=180,
            **no_window_kwargs(),
        )
        record(f"$ docker run --detach --name {name} {image_ref}")
        record((created.stdout or "").strip())
        if created.returncode != 0:
            tail = (created.stderr or created.stdout or "").strip().splitlines()[-6:]
            raise TaskError(
                "build_error",
                f"Target image {image_ref} could not start: " + " | ".join(tail),
                detail={"log": str(log_path), "image": image_ref},
            )
        deadline = started + timeout_sec
        while time.monotonic() < deadline:
            state = subprocess.run(
                [docker, "inspect", "--format", "{{.State.Status}}", name],
                capture_output=True,
                text=True,
                timeout=60,
                **no_window_kwargs(),
            )
            # ``created`` is a normal transient state right after ``run -d``;
            # only an exited or dead container is a startup failure.
            if state.stdout.strip() in {"exited", "dead"}:
                logs = _container_logs(docker, name)
                record("container exited before becoming healthy\n" + logs)
                raise TaskError(
                    "build_error",
                    "Target container exited before it became healthy; the "
                    "synthesized application does not start. Container log: "
                    + logs[-900:],
                    detail={"log": str(log_path), "image": image_ref},
                )
            probe = subprocess.run(
                [
                    docker, "exec", name, "curl", "-fsS", "-o", "/dev/null",
                    f"http://127.0.0.1:{port}{health_path}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                **no_window_kwargs(),
            )
            if probe.returncode == 0:
                record(f"health {health_path} answered")
                return
            time.sleep(1)
        logs = _container_logs(docker, name)
        record(f"health {health_path} did not answer within {timeout_sec}s\n" + logs)
        raise TaskError(
            "build_error",
            f"Target did not answer {health_path} within {timeout_sec}s. "
            "Container log: " + logs[-900:],
            detail={"log": str(log_path), "image": image_ref},
        )
    finally:
        subprocess.run(
            [docker, "rm", "--force", name],
            capture_output=True,
            text=True,
            timeout=120,
            **no_window_kwargs(),
        )


def prune_orphan_networks() -> list[str]:
    """Remove unused Harbor trial networks left behind by killed runs.

    Harbor creates one compose network per trial. When the orchestrator is
    killed the network survives, and enough orphans exhaust Docker's predefined
    address pools ("all predefined address pools have been fully subnetted"),
    which fails every later trial before it starts. Only unused networks named
    ``task__*`` are removed: an active trial keeps its containers attached and
    is never listed by the dangling filter.
    """
    docker = shutil.which("docker")
    if not docker:
        return []
    try:
        listed = subprocess.run(
            [docker, "network", "ls", "--filter", "dangling=true",
             "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            timeout=30,
            **no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        # Docker Desktop can spend minutes initializing. Cleanup is best
        # effort; the first trial will surface a real daemon error.
        return []
    if listed.returncode != 0:
        return []
    removed: list[str] = []
    for name in listed.stdout.split():
        if not name.startswith("task__"):
            continue
        try:
            result = subprocess.run(
                [docker, "network", "rm", name],
                capture_output=True,
                text=True,
                timeout=60,
                **no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            removed.append(name)
    return removed


def prune_orphan_task_resources(*, images: bool = False) -> dict[str, list[str]]:
    """Remove Harbor trial leftovers without touching user stacks.

    A killed matrix leaves exited ``task__*`` containers attached to their
    networks, project-scoped ``task__*`` images, and dangling networks. The
    containers keep the networks from being reported as removable, and the
    images accumulate by hundreds of gigabytes. Only names starting with
    ``task__`` are touched; stopped user containers and their networks are
    never removed by this function.
    """
    docker = shutil.which("docker")
    report: dict[str, list[str]] = {"containers": [], "networks": [], "images": []}
    if not docker:
        return report

    def run(command: list[str], timeout: float) -> subprocess.CompletedProcess | None:
        try:
            return subprocess.run(
                command, capture_output=True, text=True, timeout=timeout,
                **no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            return None

    listed = run(
        [docker, "ps", "-a", "--filter", "name=task__",
         "--filter", "status=exited", "--format", "{{.ID}} {{.Names}}"],
        timeout=30,
    )
    if listed is not None and listed.returncode == 0:
        for line in listed.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            container_id, name = parts
            if not name.startswith("task__"):
                continue
            removed = run([docker, "rm", container_id], timeout=60)
            if removed is not None and removed.returncode == 0:
                report["containers"].append(name)

    report["networks"] = prune_orphan_networks()

    if images:
        listed = run(
            [docker, "images", "--filter", "reference=task__*",
             "--format", "{{.ID}}"],
            timeout=120,
        )
        if listed is not None and listed.returncode == 0:
            for image_id in sorted(set(listed.stdout.split())):
                removed = run([docker, "rmi", image_id], timeout=120)
                if removed is not None and removed.returncode == 0:
                    report["images"].append(image_id)
    return report


def prune_task_images(tag_base: str) -> list[str]:
    """Remove the three per-candidate images after a terminal state.

    A 10k campaign would otherwise keep roughly 1-2 GB of images per candidate
    on disk forever. The release package carries the task source, not the
    images, and a resumed run rebuilds from the cached layers. Failures are
    logged and ignored: storage cleanup must never fail a candidate.
    """
    docker = shutil.which("docker")
    if not docker:
        return []
    prefixes = (f"{tag_base}-",)
    listed = subprocess.run(
        [docker, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True,
        text=True,
        timeout=120,
        **no_window_kwargs(),
    )
    if listed.returncode != 0:
        return []
    removable = [
        ref for ref in listed.stdout.split()
        if any(ref.startswith(prefix) for prefix in prefixes)
    ]
    removed: list[str] = []
    for ref in removable:
        result = subprocess.run(
            [docker, "image", "rm", "-f", ref],
            capture_output=True,
            text=True,
            timeout=300,
            **no_window_kwargs(),
        )
        if result.returncode == 0:
            removed.append(ref)
    return removed


def write_image_set(path: Path, image_set: dict) -> Path:
    write_json(path, image_set)
    return path


def read_image_set(path: Path) -> dict:
    if not path.is_file():
        raise PipelineError(f"Missing image set {path}")
    return read_json(path)
