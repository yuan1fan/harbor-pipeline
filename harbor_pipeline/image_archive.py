"""Optional exact-image delivery; source rebuilds alone are not binary recovery."""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

from .backend import docker_binary
from .generator import GeneratedTask, pin_task_images
from .util import PipelineError, no_window_kwargs, read_json, write_json


def _table_image(text: str, section: str, image: str) -> str:
    pattern = r"(?ms)(^\[" + re.escape(section) + r"\]\n)(.*?)(?=^\[|\Z)"
    def replace(match):
        body = re.sub(r"(?m)^docker_image\s*=.*\n?", "", match[2])
        return match[1] + f'docker_image = "{image}"\n' + body
    result, count = re.subn(pattern, replace, text)
    if count == 0:
        return text.rstrip() + f'\n\n[{section}]\ndocker_image = "{image}"\n'
    if count != 1:
        raise PipelineError(f"Missing task section {section}")
    return result


def pinned_release_task(release: Path, manifest: dict) -> GeneratedTask:
    files = {p.relative_to(release / "task").as_posix(): p.read_text(encoding="utf-8")
             for p in (release / "task").rglob("*") if p.is_file()}
    metadata = tomllib.loads(files["task.toml"])["metadata"]
    images = manifest["image_set"]
    variants = images.get("variants") or {}
    vulnerable = variants.get("vulnerable", images)["images"]
    fixed = variants["fixed"]["images"]
    for name in ("environment/docker-compose.yaml", "tests/docker-compose.yaml"):
        services = {"target": vulnerable["target"]["image_digest"]}
        if name.startswith("tests/"):
            services.update({"target-fixed": fixed["target"]["image_digest"], "fixed-runner": vulnerable["verifier"]["image_digest"]})
        for service, identity in services.items():
            pattern = r"(?m)(^  " + re.escape(service) + r":\n)(?:    image:.*\n)?"
            files[name] = re.sub(pattern, lambda match: match[1] + f"    image: {identity}\n", files[name])
    files["task.toml"] = _table_image(files["task.toml"], "environment", vulnerable["agent"]["image_digest"])
    files["task.toml"] = _table_image(files["task.toml"], "verifier.environment", vulnerable["verifier"]["image_digest"])
    task = GeneratedTask(cve_id=metadata["cve_id"], variant=metadata["variant"], probe=metadata["probe"],
        scenario=metadata["scenario"], spec_digest=metadata["spec_digest"], task_digest=metadata["task_digest"],
        files=files, synthesis_digest=metadata.get("synthesis_digest", ""))
    return pin_task_images(task, images)


def archive_release_images(release: Path, output: Path) -> dict:
    from .release import verify_release
    issues = verify_release(release)
    if issues:
        raise PipelineError("Release is not valid: " + "; ".join(issues[:5]))
    manifest = read_json(release / "build-manifest.json")
    images = manifest.get("image_set") or {}
    ids = sorted({image["image_digest"] for variant in images.get("variants", {}).values()
                  for image in variant.get("images", {}).values()})
    if not ids or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", identity) for identity in ids):
        raise PipelineError("Release has no complete measured image set")
    docker = docker_binary()
    present = subprocess.run([docker, "image", "inspect", *ids], capture_output=True, timeout=60, **no_window_kwargs())
    if present.returncode:
        raise PipelineError("Measured images are no longer present; rebuild and revalidate instead of exporting a mutable tag")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output, prefix="images-", suffix=".tmp", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        result = subprocess.run([docker, "save", "--output", str(temporary), *ids], capture_output=True, text=True, timeout=1800, **no_window_kwargs())
        if result.returncode:
            raise PipelineError("docker save failed: " + result.stderr[-1000:])
        archive = output / "images.tar"
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    with archive.open("rb") as handle:
        checksum = hashlib.file_digest(handle, "sha256").hexdigest()
    task = pinned_release_task(release, manifest)
    task.write(output)
    record = {"source_task_digest": manifest["task_digest"], "execution_task_digest": task.task_digest,
              "image_ids": ids, "archive_sha256": checksum, "archive_bytes": archive.stat().st_size,
              "restore": "docker load -i images.tar; then run Harbor against task/"}
    write_json(output / "image-lock.json", record)
    return record
