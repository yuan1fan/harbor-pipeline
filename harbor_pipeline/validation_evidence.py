"""Bind stored trial evidence to the code and artifacts that produced it."""
from pathlib import Path
import tomllib

from .util import digest


def _executors():
    root = Path(__file__).parent
    return {name: digest((root / name).read_bytes()) for name in (
        "scenario.py", "generator.py", "differential.py", "verifier_check.py",
        "harbor_adapter.py", "backend.py", "goals.py", "trials.py",
        "pipeline.py", "runtime_identity.py", "provenance.py",
        "validation_evidence.py", "execution_progress.py", "build_cache.py", "author_probe.py",
        "assets/browser_bot.py",
    )}


def _images(image_set):
    return {
        variant: {name: image.get("image_digest") for name, image in data.get("images", {}).items()}
        for variant, data in (image_set.get("variants") or {"vulnerable": image_set}).items()
    }


def execution_files(task):
    """Oracle execution inputs; solver/reviewer still bind the entire task."""
    files = {name: body for name, body in task.files.items()
             if name not in {"instruction.md", "README.md", ".gitignore", "task.toml"}}
    config = tomllib.loads(task.files["task.toml"])
    metadata = config.get("metadata", {})
    for name in ("synthesis_digest", "spec_digest", "task_digest", "presentation_mode"):
        metadata.pop(name, None)
    files["task.toml"] = config
    return files


def execution_signature(spec, task, image_set, *, synthesis=None, overrides=None, parameters=None):
    return digest({
        "protocol": 1,
        "spec": {key: value for key, value in spec.items() if key not in {"frozen_at", "frozen_digest"}},
        "files": execution_files(task), "images": _images(image_set),
        "target_digest": image_set.get("target_digest"),
        "synthesis": {"target": synthesis.target, "poc": {"reference": synthesis.poc["reference"]}} if synthesis else None,
        "overrides": {key: value for key, value in (overrides or {}).items()
                      if key not in {"instruction.md", "README.md", ".gitignore"}},
        "parameters": parameters, "executors": _executors(),
    })


def validation_signature(spec, task, image_set, *, cold_rebuild=False):
    return digest({
        "protocol": 3,
        "cold_rebuild": cold_rebuild,
        "spec": spec,
        "files": task.files,
        "images": _images(image_set),
        "executors": _executors(),
    })
