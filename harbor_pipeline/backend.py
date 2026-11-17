"""Docker build execution and immutable artifact identity.

Harbor rebuilds images itself during a trial. This module builds the same
contexts first so their digests can be frozen into the BuildManifest, and so a
build failure is attributed to the candidate rather than to a later trial.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .errors import TaskError
from .resources import limited
from .retries import TRANSIENT_BUILD
from .util import PipelineError, no_window_kwargs, read_json, write_json

_CACHE_RE = re.compile(r"(?im)^\s*(?:=>\s*)?CACHED\s*$")
# Package registries and mirrors fail transiently under load. Retrying these
# once inside the build is cheaper than handing the author a network blip and
# making it change a correct Dockerfile.
_TRANSIENT_BUILD = re.compile(
    r"(?i)ECONNRESET|ETIMEDOUT|EAI_AGAIN|socket disconnected|"
    r"Temporary failure|502 Bad Gateway|503 Service Unavailable|"
    r"Could not resolve host|Connection reset by peer|"
    r"failed to fetch|network is unreachable"
)
_DOCKER_CONNECTION_ERROR = re.compile(
    r"(?i)error during connect|cannot connect to the docker daemon|"
    r"is the docker daemon running|"
    r"failed to receive status: rpc error: code = Unavailable"
)
# Docker Desktop occasionally leaves the builder session open after BuildKit
# has already exported and tagged the image. These markers trigger an identity
# check; the log alone does not prove that the tag belongs to this build.
_COMPLETED_EXPORT = re.compile(
    r"(?im)^#(?P<vertex>\d+)[ \t]+(?P<action>naming to|unpacking to)\b[^\r\n]*\bdone[ \t]*\r?$"
)
_BUILD_FATAL_AFTER_EXPORT = re.compile(
    r"(?i)ERROR:|failed to solve|failed to build|did not complete successfully"
)
_BUILD_ATTEMPT_LABEL = "harbor-pipeline.build-attempt"
_EXPORT_POLL_SEC = 2.0
_EXPORT_GRACE_SEC = 15.0
_EXPORT_RETRY_SEC = 10.0
_EXPORT_INSPECT_TIMEOUT_SEC = 5.0


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
    reused: bool = False
    dependencies: dict[str, str] = field(default_factory=dict)
    runtime_identity: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "image_ref": self.image_ref,
            "image_digest": self.image_digest,
            "architecture": self.architecture,
            "duration_sec": round(self.duration_sec, 2),
            "log": str(self.log_path),
            "cached": self.cached,
            "reused": self.reused,
            "dependencies": dict(self.dependencies),
            "runtime_identity": dict(self.runtime_identity),
        }


def docker_binary() -> str:
    resolved = shutil.which("docker")
    if not resolved:
        raise TaskError("infra_error", "docker is not on PATH; a Docker daemon is required")
    return resolved


def daemon_available(docker: str) -> bool:
    """Distinguish a stalled/offline engine from a slow candidate build."""
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, errors="replace", timeout=10,
            **no_window_kwargs(),
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the docker CLI and every child that inherited its pipes.

    ``subprocess.run(timeout=...)`` only kills the direct child. A docker build
    spawns a buildx child that keeps the stdout/stderr pipes open, so the
    reader threads in ``communicate()`` stay blocked even after the CLI dies.
    On Windows that turned a 600 s build timeout into an hours-long hang.
    """
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True, text=True, errors="replace", timeout=30,
                **no_window_kwargs(),
            )
        else:
            try:
                # Only a group created for this child is ours to terminate.
                if os.getpgid(proc.pid) == proc.pid:
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception:  # noqa: BLE001 - best-effort teardown
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _wait_for_build(
    proc: subprocess.Popen, *, timeout: int, log_path: Path,
    recover_export: Callable[[float], str | None] | None,
) -> str | None:
    """Allow normal work its full budget, but probe a completed export early."""
    if recover_export is None:
        proc.wait(timeout=timeout)
        return None
    deadline = time.monotonic() + timeout
    exported_at = None
    next_probe = 0.0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(proc.args, timeout)
        try:
            proc.wait(timeout=min(_EXPORT_POLL_SEC, remaining))
            return None
        except subprocess.TimeoutExpired:
            pass
        now = time.monotonic()
        if now >= deadline:
            raise subprocess.TimeoutExpired(proc.args, timeout)
        if not _log_shows_completed_export(log_path):
            exported_at = None
            continue
        if exported_at is None:
            exported_at = now
        if now - exported_at < _EXPORT_GRACE_SEC or now < next_probe:
            continue
        recovered = recover_export(deadline - now)
        next_probe = time.monotonic() + _EXPORT_RETRY_SEC
        # A real exit (especially a failure) takes precedence over recovery.
        # Also recheck the log for errors arriving during image inspection.
        if proc.poll() is not None:
            return None
        if recovered and _log_shows_completed_export(log_path):
            return recovered


def _run(
    command: list[str], *, timeout: int, log_path: Path,
    recover_export: Callable[[float], str | None] | None = None,
) -> subprocess.CompletedProcess:
    """Stream build output to disk; keep only a bounded diagnostic tail in RAM."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    recovered = None
    with log_path.open("wb") as handle:
        handle.write((f"$ {' '.join(command)}\n\n").encode("utf-8"))
        handle.flush()
        proc = subprocess.Popen(
            command, stdout=handle, stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt", **no_window_kwargs(),
        )
        from .processes import ProcessTree
        with ProcessTree(proc):
            try:
                recovered = _wait_for_build(
                    proc, timeout=timeout, log_path=log_path, recover_export=recover_export,
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_tree(proc)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    pass
                handle.write(b"\nTIMEOUT\n")
                handle.flush()
            finally:
                if proc.poll() is None:
                    _kill_tree(proc)
                    try:
                        proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        pass
                elif recovered:
                    # Preserve an exit code arriving just after the recovery probe.
                    recovered = None
        if recovered and proc.poll() is None:
            raise TaskError(
                "infra_error", "Image exported but the stalled Docker CLI could not be stopped",
                detail={"log": str(log_path), "post_export_hang": True},
            )
        if recovered and not _log_shows_completed_export(log_path):
            recovered = None
        if recovered:
            handle.write((
                f"\nRECOVERED_POST_EXPORT {recovered}: verified this build's image; "
                "stopped stalled Docker CLI\n"
            ).encode("utf-8"))
            handle.flush()
    if timed_out:
        available = daemon_available(command[0])
        raise TaskError(
            "build_error" if available else "infra_error",
            f"Build exceeded {timeout}s: {' '.join(command[:4])}"
            + ("; Docker daemon is unavailable" if not available else ""),
            detail={"log": str(log_path), "daemon_available": available, "build_timeout": True},
        )
    with log_path.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - 100_000))
        tail = handle.read().decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(command, 0 if recovered else proc.returncode, tail, "")


@limited("inspect")
def run_in_image(
    image_ref: str,
    command: str,
    *,
    timeout: int = 60,
    log_path: Path | None = None,
    max_output: int = 8000,
) -> dict:
    """Run a bounded shell command in a throwaway container of a built image.

    Used by the repair agent to inspect the installed dependency (exports,
    package metadata, import errors) instead of guessing from the build log.
    The container has no network, a memory/CPU cap and a hard timeout; it
    cannot modify the image or the host.
    """
    docker = docker_binary()
    container_name = "harbor-inspect-" + uuid.uuid4().hex[:16]
    argv = [
        docker, "run", "--rm", "--network", "none",
        "--name", container_name, "--pids-limit", "256",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "512m", "--cpus", "1",
        "--entrypoint", "sh", image_ref, "-c", command,
    ]
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            errors="replace", **no_window_kwargs(),
        )
    except OSError as exc:
        return {"exit": -1, "output": f"docker run failed: {exc}"}
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        subprocess.run([docker, "rm", "-f", container_name], capture_output=True, timeout=30, **no_window_kwargs())
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        output = (stdout or "") + (stderr or "") + "\nTIMEOUT"
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(output[-20000:], encoding="utf-8")
        return {"exit": 124, "output": output[-8000:]}
    combined = (stdout or "") + (stderr or "")
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(combined[-20000:], encoding="utf-8")
    return {"exit": proc.returncode, "output": combined[-max_output:]}


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


def image_label(image_ref: str, key: str) -> str:
    """Read a framework-owned label from a built image, empty when absent."""
    docker = docker_binary()
    completed = subprocess.run(
        [
            docker,
            "image",
            "inspect",
            image_ref,
            "--format",
            '{{index .Config.Labels "' + key + '"}}',
        ],
        capture_output=True,
        text=True,
        timeout=60,
        **no_window_kwargs(),
    )
    if completed.returncode != 0:
        return ""
    value = completed.stdout.strip()
    return "" if value in {"<no value>", "null"} else value


def dependency_lock(
    context: Path,
    *,
    product: str | None = None,
    ref: str | None = None,
) -> dict[str, str]:
    """Best-effort pinned dependency list for the target image.

    A synthesized target may vendor the component's upstream source instead of
    installing it from a package registry (for example a Go service built from
    a pinned tarball). In that case there is no package lock entry to read, but
    the target Dockerfile names the pinned ref directly. Recording it keeps the
    V4 build-lock gate meaning "the built target is the vulnerable version"
    rather than "the component must be a registry dependency".
    """
    lock: dict[str, str] = {}
    requirements = context / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            # Drop environment markers and extras so the lock key is the
            # distribution name, not `name[extra]` or `version; python_...`.
            line = line.split(";", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if not match:
                continue
            name = match.group(1)
            if "==" in line:
                lock[name] = line.split("==", 1)[1].strip()
            else:
                lock[name] = "unpinned"
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


def _read_log_tail(path: Path, limit: int = 100_000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - limit))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _log_shows_completed_export(path: Path) -> bool:
    """Return true when BuildKit finished tagging and unpacking the image."""
    text = _read_log_tail(path)
    named = {}
    for match in _COMPLETED_EXPORT.finditer(text):
        vertex = match["vertex"]
        if match["action"].lower() == "naming to":
            named[vertex] = match.start()
        elif vertex in named:
            # Require completion of the same export vertex, not just a tag
            # followed by an unpack still in progress (or another stage).
            finished = re.search(rf"(?m)^#{vertex}[ \t]+DONE\b", text[match.end():])
            if finished and not _BUILD_FATAL_AFTER_EXPORT.search(text[named[vertex]:]):
                return True
    return False


def _recover_image_after_export(
    docker: str, image_ref: str, iid_file: Path, log_path: Path, *,
    attempt_id: str, timeout_sec: float = _EXPORT_INSPECT_TIMEOUT_SEC,
) -> str | None:
    """Recover only an image labeled by this exact build attempt."""
    if not _log_shows_completed_export(log_path):
        return None
    try:
        result = subprocess.run(
            [docker, "image", "inspect", "--format",
             '{{.Id}} {{index .Config.Labels "' + _BUILD_ATTEMPT_LABEL + '"}}', image_ref],
            capture_output=True, text=True, errors="replace",
            timeout=min(timeout_sec, _EXPORT_INSPECT_TIMEOUT_SEC),
            **no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    parts = (result.stdout or "").split()
    if (result.returncode != 0 or len(parts) != 2 or parts[1] != attempt_id
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", parts[0])):
        return None
    image_id = parts[0]
    if not _log_shows_completed_export(log_path):
        return None
    try:
        iid_file.write_text(image_id + "\n", encoding="ascii")
    except OSError:
        return None
    return image_id


@limited("build")
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
    product: str | None = None,
    product_ref: str | None = None,
    reuse: bool = False,
    on_build: Callable[[], None] | None = None,
) -> ImageBuild:
    if not context.is_dir():
        raise TaskError("build_error", f"Missing build context {context}")
    dockerfile = dockerfile or (context / "Dockerfile")
    if not dockerfile.is_file():
        raise TaskError("build_error", f"Missing Dockerfile {dockerfile}")
    docker = docker_binary()
    if not daemon_available(docker):
        raise TaskError(
            "infra_error", f"Docker daemon is unavailable before building {name}",
            detail={"log": str(log_path), "daemon_available": False},
        )
    iid_file = log_path.with_name(log_path.name + ".iid")
    iid_file.parent.mkdir(parents=True, exist_ok=True)
    command = [
        docker,
        "build",
        "--progress=plain",
        "--iidfile",
        str(iid_file),
        "-t",
        image_ref,
        "-f",
        str(dockerfile),
    ]
    from .storage import image_labels
    for key, value in image_labels(context).items():
        command.extend(["--label", f"{key}={value}"])
    if name == "target" and product_ref:
        # The framework appends this label to every synthesized target. It is
        # the only identity evidence for a Go/Rust binary whose main module is
        # reported as "(devel)" in build info and therefore never appears in
        # the dependency list.
        build_args = {**(build_args or {}), "HARBOR_SOURCE_REF": product_ref}
    from .build_cache import build_signature, reuse_image
    cache_path = log_path.with_name(log_path.name + ".image.json")
    signature = None
    if reuse and not no_cache:
        signature = build_signature(
            docker, context, dockerfile, build_args=build_args or {},
            product=product, product_ref=product_ref,
        )
        cached = reuse_image(docker, cache_path, signature, image_ref) if signature else None
        if cached:
            iid_file.write_text(cached["image_digest"] + "\n", encoding="ascii")
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"\nREUSED_IMAGE {cached['image_digest']} inputs={signature}\n")
            return ImageBuild(
                name=name, context=context, dockerfile=dockerfile, image_ref=image_ref,
                image_digest=cached["image_digest"], architecture=cached["architecture"],
                duration_sec=0.0, log_path=log_path, cached=True, reused=True,
                dependencies=dict(cached.get("dependencies") or {}),
                runtime_identity=dict(cached.get("runtime_identity") or {}),
            )
    if on_build is not None:
        on_build()
    if no_cache:
        command.append("--no-cache")
    for key, value in (build_args or {}).items():
        command.extend(["--build-arg", f"{key}={value}"])
    started = time.monotonic()
    completed = None
    for attempt in range(2):
        # A reused tag/iidfile must never turn a failed new build into success,
        # including when retrying after a transient registry failure.
        iid_file.unlink(missing_ok=True)
        attempt_id = uuid.uuid4().hex
        attempt_command = [
            *command, "--label", f"{_BUILD_ATTEMPT_LABEL}={attempt_id}", str(context),
        ]

        def recover_export(remaining: float) -> str | None:
            return _recover_image_after_export(
                docker, image_ref, iid_file, log_path,
                attempt_id=attempt_id, timeout_sec=remaining,
            )

        try:
            completed = _run(
                attempt_command, timeout=timeout_sec, log_path=log_path,
                recover_export=recover_export,
            )
        except TaskError as exc:
            if exc.category.code != "build_error":
                raise
            recovered = recover_export(_EXPORT_INSPECT_TIMEOUT_SEC)
            if recovered:
                completed = subprocess.CompletedProcess(
                    attempt_command, 0, _read_log_tail(log_path), ""
                )
                break
            if _log_shows_completed_export(log_path):
                raise TaskError(
                    "infra_error",
                    f"Docker build exported {name} but the CLI did not return; "
                    "restart Docker Desktop before retrying",
                    detail={
                        "log": str(log_path),
                        "daemon_available": True,
                        "post_export_hang": True,
                    },
                ) from exc
            if (exc.detail or {}).get("build_timeout"):
                tail = _read_log_tail(log_path)
                if TRANSIENT_BUILD.search(tail) or not _BUILD_FATAL_AFTER_EXPORT.search(tail):
                    raise TaskError("infra_error", str(exc), detail={**(exc.detail or {}), "stage": "build"}) from exc
            raise
        if completed.returncode == 0:
            break
        output = (completed.stderr or "") + (completed.stdout or "")
        if _DOCKER_CONNECTION_ERROR.search(output):
            raise TaskError(
                "infra_error", f"Docker engine connection failed while building {name}",
                detail={"log": str(log_path)},
            )
        if attempt == 0 and (_TRANSIENT_BUILD.search(output) or TRANSIENT_BUILD.search(output)):
            time.sleep(5)
            continue
        tail = output.strip().splitlines()[-8:]
        raise TaskError(
            "infra_error" if TRANSIENT_BUILD.search(output) else "build_error",
            f"docker build failed for {name}: " + " | ".join(tail),
            detail={"log": str(log_path)},
        )
    duration = time.monotonic() - started
    try:
        built_id = iid_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise TaskError("build_error", "Docker did not write a valid immutable image ID",
                        detail={"log": str(log_path)}) from exc
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", built_id):
        raise TaskError("build_error", "Docker did not write a valid immutable image ID")
    digest, architecture = inspect_image(built_id, dockerfile=dockerfile)
    identity = {}
    if name == "target" and product:
        from .runtime_identity import inspect_runtime
        identity = inspect_runtime(
            digest, runner=run_in_image, product=product,
            product_ref=product_ref,
            log_path=log_path.with_suffix(".identity.json"),
        )
        identity["source_ref"] = image_label(digest, "org.harbor.source-ref")
    from .resources import policy as resource_policy
    if resource_policy().get("prune_images"):
        from .storage import cleanup_replaced_images
        try:
            cleanup_replaced_images(context)
        except (OSError, ValueError, PipelineError, subprocess.SubprocessError):
            pass  # Terminal cleanup retries; never invalidate a successful build.
    built = ImageBuild(
        name=name,
        context=context,
        dockerfile=dockerfile,
        image_ref=image_ref,
        image_digest=digest,
        architecture=architecture,
        duration_sec=duration,
        log_path=log_path,
        cached=bool(_CACHE_RE.search(completed.stdout or "")),
        dependencies=identity.get("dependencies", {}) if product else dependency_lock(context),
        runtime_identity=identity,
    )
    if signature and signature == build_signature(
        docker, context, dockerfile, build_args=build_args or {},
        product=product, product_ref=product_ref,
    ):
        try:
            write_json(cache_path, {"signature": signature, "image": built.to_json()})
        except OSError:
            pass  # A cache write failure must not invalidate a measured build.
    return built


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
    target_only: bool = False,
    environment_image: str | None = None,
    product: str | None = None,
    product_ref: str | None = None,
    reuse: bool = False,
    on_build: Callable[[], None] | None = None,
) -> dict:
    """Build the target and verifier images and return an image set.

    ``tag_base`` defaults to the legacy task-directory-derived name; the
    pipeline passes an explicit CVE-based base so the fixed variant (rendered
    into a scratch directory) still gets the same prefix the probes pin.

    The agent image is byte-identical for every synthesized task, so
    ``target_only`` takes a globally prebuilt ``environment_image`` and
    inspects it instead of rebuilding it. The verifier image is *not* generic:
    Harbor bakes the task's ``tests/`` into it, and a pinned generic verifier
    would run an empty ``/tests``. It stays a per-variant build, but it is a
    thin ``COPY tests`` layer.
    """
    tag_base = (
        tag_base
        or f"harbor-pipeline/{task_dir.parent.name}-{variant}-r{revision}"
    ).lower()
    builds: dict[str, ImageBuild] = {}
    target_context = task_dir / "environment" / "target"
    if not target_context.is_dir():
        raise TaskError(
            "build_error", f"Task is missing the target build context {target_context}"
        )
    builds["target"] = build_image(
        name="target",
        context=target_context,
        image_ref=f"{tag_base}-target",
        log_path=log_dir / "build-target.log",
        timeout_sec=timeout_sec,
        no_cache=no_cache,
        product=product,
        product_ref=product_ref,
        reuse=reuse, on_build=on_build,
    )
    tests_context = task_dir / "tests"
    if not tests_context.is_dir():
        raise TaskError(
            "build_error", f"Task is missing the verifier context {tests_context}"
        )
    builds["verifier"] = build_image(
        name="verifier",
        context=tests_context,
        image_ref=f"{tag_base}-verifier",
        log_path=log_dir / "build-verifier.log",
        timeout_sec=timeout_sec,
        no_cache=no_cache,
        reuse=reuse, on_build=on_build,
    )
    if target_only:
        if not environment_image:
            raise TaskError(
                "build_error",
                "target_only build needs a prebuilt agent environment image",
            )
        dockerfile = task_dir / "environment" / "Dockerfile"
        image_digest, architecture = inspect_image(environment_image, dockerfile=dockerfile)
        builds["agent"] = ImageBuild(
            name="agent",
            context=task_dir / "environment",
            dockerfile=dockerfile,
            image_ref=environment_image,
            image_digest=image_digest,
            architecture=architecture,
            duration_sec=0.0,
            log_path=log_dir / "build-agent.log",
            cached=True,
        )
    else:
        context = task_dir / "environment"
        if not context.is_dir():
            raise TaskError(
                "build_error", f"Task is missing the agent build context {context}"
            )
        builds["agent"] = build_image(
            name="agent",
            context=context,
            image_ref=f"{tag_base}-agent",
            log_path=log_dir / "build-agent.log",
            timeout_sec=timeout_sec,
            no_cache=no_cache,
            reuse=reuse, on_build=on_build,
        )
    bot_context = task_dir / "tests" / "bot"
    if (bot_context / "Dockerfile").is_file():
        from .author_probe import ensure_bot_image
        from .goals import BOT_IMAGE
        ensure_bot_image(probe_root=log_dir / "base-images", log_dir=log_dir, timeout_sec=timeout_sec)
        identity, architecture = inspect_image(BOT_IMAGE, dockerfile=bot_context / "Dockerfile")
        builds["bot"] = ImageBuild(
            name="bot", context=bot_context, dockerfile=bot_context / "Dockerfile",
            image_ref=BOT_IMAGE, image_digest=identity, architecture=architecture,
            duration_sec=0.0, log_path=log_dir / "base-bot.log", cached=True,
        )
    return {
        "tag_base": tag_base,
        "harbor_version": harbor_version,
        "images": {name: build.to_json() for name, build in builds.items()},
        "target_digest": builds["target"].image_digest,
        "architecture": builds["target"].architecture,
        "dependencies": builds["target"].dependencies,
        "runtime_identity": builds["target"].runtime_identity,
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


@limited("target-health")
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
            [docker, "image", "rm", ref],
            capture_output=True,
            text=True,
            timeout=300,
            **no_window_kwargs(),
        )
        if result.returncode == 0:
            removed.append(ref)
    return removed


def prune_build_cache(keep_gb: int = 20) -> dict:
    """Cap BuildKit cache after a finished task.

    Removing per-candidate tags alone leaves the shared build cache and old
    layers behind; a long campaign can fill the Docker VHDX even though each
    candidate's images were pruned. This is best effort and never fails a
    candidate.
    """
    docker = shutil.which("docker")
    if not docker:
        return {}
    result = {}
    for name, command in (
        ("builder", [docker, "builder", "prune", "-f", "--keep-storage", f"{max(1, keep_gb)}GB"]),
    ):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                **no_window_kwargs(),
            )
            result[name] = completed.returncode
        except (OSError, subprocess.SubprocessError):
            result[name] = -1
    return result


def write_image_set(path: Path, image_set: dict) -> Path:
    write_json(path, image_set)
    return path


def read_image_set(path: Path) -> dict:
    if not path.is_file():
        raise PipelineError(f"Missing image set {path}")
    return read_json(path)
