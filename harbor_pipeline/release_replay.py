"""Build the portable release with the monitored builder, then run pinned copies.

The distributed task stays portable. Only this private execution copy removes
Compose build directives, so Harbor cannot start an unmonitored second build.
"""
from __future__ import annotations

import copy
import re
import shutil
import tomllib
from pathlib import Path

import yaml

from .backend import build_image
from .errors import TaskError
from .util import PipelineError, digest, read_json, tree_hashes, write_json


def _pin_toml(body: str, section: str, image: str) -> str:
    heading = f"[{section}]"
    pattern = re.compile(r"(?ms)^" + re.escape(heading) + r"\r?\n(.*?)(?=^\[|\Z)")
    found = pattern.search(body)
    if found:
        content = re.sub(r'(?m)^docker_image\s*=.*\n?', '', found[1])
        return body[:found.start()] + f'{heading}\ndocker_image = "{image}"\n' + content + body[found.end():]
    return body.rstrip() + f'\n\n{heading}\ndocker_image = "{image}"\n'


def prepare_release_replay(release_dir: Path, *, timeout_sec: int = 900, on_build=None) -> tuple[Path, dict]:
    """Build every packaged context, including the paired fixed target.

    Sources come from the verified release copy. Contexts with identical build
    parameters share one image; retries can reuse only matching context hashes.
    A fresh ID is measured for the replay, independent of the matrix image ID.
    """
    task_dir = release_dir / "task"
    manifest = read_json(release_dir / "build-manifest.json")
    expected = manifest["file_digests"]
    if tree_hashes(task_dir) != expected:
        raise TaskError("grader_failure", "Release source files changed before replay")
    root = release_dir.parent / (release_dir.name + "-replay")
    root.mkdir(parents=True, exist_ok=True)
    source_files = {name: (task_dir / name).read_bytes() for name in expected}
    configs = {name: yaml.safe_load(source_files[name]) for name in (
        "environment/docker-compose.yaml", "tests/docker-compose.yaml",
    )}
    built, image_records = {}, {}

    def build(context: Path, *, dockerfile="Dockerfile", args=None):
        context = context.resolve()
        file = (context / dockerfile).resolve()
        if (not context.is_relative_to(task_dir.resolve()) or not file.is_relative_to(task_dir.resolve())
                or not file.is_file()):
            raise PipelineError("Replay build context or Dockerfile escapes the release task")
        key = digest({"context": str(context), "dockerfile": str(file), "args": args or {}})
        if key not in built:
            name = "release-" + key[:12]
            image = build_image(name=name, context=context, dockerfile=file,
                image_ref=f"harbor-pipeline/replay-{digest(str(release_dir.resolve()))[:12]}-{key[:12]}",
                log_path=root / "build-logs" / (name + ".log"), timeout_sec=timeout_sec,
                build_args=args, reuse=True, on_build=on_build)
            built[key] = image.image_digest
            image_records[key] = {**image.to_json(), "source_context": context.relative_to(task_dir.resolve()).as_posix(),
                                  "source_files": tree_hashes(context)}
        return built[key]

    agent = build(task_dir / "environment")
    verifier = build(task_dir / "tests")
    for name, config in configs.items():
        if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
            raise PipelineError(f"Invalid release compose file: {name}")
        for service, fields in config["services"].items():
            definition = fields.pop("build", None)
            if definition is not None:
                definition = {"context": definition} if isinstance(definition, str) else definition
                if (not isinstance(definition, dict) or set(definition) - {"context", "dockerfile", "args"}
                        or not isinstance(definition.get("args", {}), dict)):
                    raise PipelineError("Unsupported release build settings; refusing an unmonitored Compose build")
                fields["image"] = build(task_dir / Path(name).parent / definition.get("context", "."),
                    dockerfile=definition.get("dockerfile", "Dockerfile"), args=definition.get("args"))
        config["services"]["main"]["image"] = agent if name.startswith("environment/") else verifier
    # Building can run long enough for a caller to edit files: do not combine
    # changed files and measured images into a successful replay.
    if tree_hashes(task_dir) != expected:
        raise TaskError("grader_failure", "Release source files changed while building replay images")
    execution = root / "task"
    # Rebuild the execution tree from scratch: a prior replay may have had
    # files that are no longer part of the signed release. Leaving them behind
    # would let Harbor execute stale code or stale test fixtures.
    if execution.exists():
        shutil.rmtree(execution)
    for name, body in source_files.items():
        path = execution / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    for name, config in configs.items():
        for fields in config["services"].values():
            if "build" in fields:
                raise PipelineError(f"Replay left an unmonitored Compose build in {name}")
        (execution / name).write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding="utf-8")
    body = source_files["task.toml"].decode("utf-8")
    body = _pin_toml(_pin_toml(body, "environment", agent), "verifier.environment", verifier)
    (execution / "task.toml").write_text(body, encoding="utf-8")
    parsed = tomllib.loads(body)
    if parsed.get("environment", {}).get("docker_image") != agent:
        raise PipelineError("Replay did not pin the environment image")
    if parsed.get("verifier", {}).get("environment", {}).get("docker_image") != verifier:
        raise PipelineError("Replay did not pin the verifier image")
    audit = {"source_task": str(task_dir.resolve()), "source_file_digests": expected,
             "execution_task": str(execution.resolve()), "execution_file_digests": tree_hashes(execution),
             "images": image_records, "mode": "build-portable-source-then-pin", "protocol": 1}
    write_json(root / "replay-inputs.json", audit)
    return execution, audit
