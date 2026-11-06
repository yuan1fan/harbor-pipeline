"""Bind stored trial evidence to the code and artifacts that produced it."""
from pathlib import Path

from .util import digest


def validation_signature(spec, task, image_set):
    root = Path(__file__).parent
    executors = {name: digest((root / name).read_bytes()) for name in (
        "scenario.py", "generator.py", "differential.py", "verifier_check.py",
        "harbor_adapter.py", "backend.py", "goals.py", "trials.py",
        "pipeline.py", "runtime_identity.py", "provenance.py",
    )}
    return digest({
        "protocol": 2,
        "spec": spec,
        "files": task.files,
        "images": {
            variant: {name: image.get("image_digest") for name, image in data.get("images", {}).items()}
            for variant, data in (image_set.get("variants") or {"vulnerable": image_set}).items()
        },
        "executors": executors,
    })
