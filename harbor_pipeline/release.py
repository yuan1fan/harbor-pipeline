"""Local release packages, audit bundles, and immutable-artifact rechecks."""

from __future__ import annotations

import json
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import GENERATOR_VERSION, PROMPT_VERSION, SCHEMA_VERSION
from .contracts import freeze_digest, validate
from .errors import TaskError
from .generator import GeneratedTask, inspect_task
from .harbor_adapter import HarborAdapter
from .util import PipelineError, digest, read_json, tree_hashes, write_json

DATASET_VERSION = "2026.11.1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ReleaseResult:
    root: Path
    task_dir: Path
    evaluation_path: Path
    manifest_path: Path
    audit_path: Path
    dataset_entry: dict

    def to_json(self) -> dict:
        return {
            "root": str(self.root),
            "task_dir": str(self.task_dir),
            "evaluation": str(self.evaluation_path),
            "build_manifest": str(self.manifest_path),
            "audit": str(self.audit_path),
            "dataset_entry": self.dataset_entry,
        }


def build_manifest(
    *,
    spec: dict,
    task: GeneratedTask,
    task_dir: Path,
    image_set: dict,
    revision: int,
    harbor_version: str,
    seed: int | None,
    control_plan: dict,
) -> dict:
    target = image_set.get("images", {}).get("target", {})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": spec["cve_id"],
        "candidate_revision": revision,
        "variant": "vulnerable",
        "source_commit": spec["versions"]["vulnerable_ref"],
        "image_ref": target.get("image_ref", "unknown"),
        "image_digest": target.get("image_digest") or image_set.get("target_digest", "unknown"),
        "dependency_lock": dict(image_set.get("dependencies", {})),
        "cpu_arch": image_set.get("architecture", "unknown"),
        "harbor_version": harbor_version,
        "generator_version": GENERATOR_VERSION,
        "prompt_version": PROMPT_VERSION,
        "file_digests": tree_hashes(task_dir),
        "control_plan": control_plan,
        "seed": seed,
        "task_digest": task.task_digest,
        "built_at": utc_now(),
    }
    validate("build-manifest", manifest)
    return manifest


def build_release(
    *,
    spec: dict,
    evidence: dict,
    evaluation: dict,
    matrix_result: dict,
    task: GeneratedTask,
    task_dir: Path,
    image_set: dict,
    run_dir: Path,
    revision: int = 1,
    harbor_version: str = "0.23.0",
    seed: int | None = 0,
) -> ReleaseResult:
    """Copy the immutable vulnerable task and write contracts plus an audit zip."""
    root = run_dir / "release"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    released_task = root / "task"
    _copy_tree(task_dir, released_task)

    issues = inspect_task(task.files, spec)
    if issues:
        raise TaskError("generation_error", "Release copy failed inspection: " + "; ".join(issues))

    control_plan = {
        "experiments": [
            {
                "id": item["experiment_id"],
                "goal_result": item["goal_result"],
                "reward": item["reward"],
                "error_category": item["error_category"],
            }
            for item in matrix_result.get("records", [])
        ],
        "matrix": matrix_result.get("job_name"),
    }
    manifest = build_manifest(
        spec=spec,
        task=task,
        task_dir=released_task,
        image_set=image_set,
        revision=revision,
        harbor_version=harbor_version,
        seed=seed,
        control_plan=control_plan,
    )
    target_digest = manifest["image_digest"]
    evaluation = dict(evaluation)
    evaluation["candidate_revision"] = revision
    evaluation["artifact_digest"] = target_digest
    validate("evaluation", evaluation)

    write_json(root / "spec.json", spec)
    write_json(root / "evidence-index.json", evidence)
    write_json(root / "evaluation.json", evaluation)
    write_json(root / "build-manifest.json", manifest)
    write_json(root / "matrix.json", matrix_result)
    _write_readme(root, spec, evaluation, manifest, task)

    entry = {
        "cve_id": spec["cve_id"],
        "task_version": "1.0.0",
        "artifact_digest": target_digest,
        "project": spec["product"]["name"],
        "root_cause_group": root_cause_group(spec),
        "patch_group": spec["versions"]["fix_commit"][:12],
        "split": dataset_split(spec["cve_id"], spec["product"]["name"], root_cause_group(spec)),
        "location": released_task.as_posix(),
    }
    validate("dataset-manifest", {
        "schema_version": SCHEMA_VERSION,
        "dataset_version": DATASET_VERSION,
        "created_at": utc_now(),
        "tasks": [entry],
    })

    audit_path = root / "audit.zip"
    _write_audit(audit_path, spec, evidence, evaluation, manifest, matrix_result, root)
    return ReleaseResult(
        root=root,
        task_dir=released_task,
        evaluation_path=root / "evaluation.json",
        manifest_path=root / "build-manifest.json",
        audit_path=audit_path,
        dataset_entry={**entry, "location": str(released_task)},
    )


def root_cause_group(spec: dict) -> str:
    summary = str(spec.get("root_cause", {}).get("summary", "")).lower()
    if "traversal" in summary or ".." in summary or "path" in summary:
        return "path-traversal"
    if "deserial" in summary:
        return "deserialization"
    if "injection" in summary:
        return "injection"
    if "ssrf" in summary:
        return "ssrf"
    return "root-cause-" + digest(summary)[:8]


def dataset_split(cve_id: str, project: str, group: str) -> str:
    """Stable project/alias grouping: near-duplicates never span splits."""
    bucket = int(digest({"project": project, "group": group})[:8], 16) % 100
    if bucket < 80:
        return "train"
    if bucket < 90:
        return "validation"
    return "test"


def verify_release(release_dir: Path, *, expected_digest: str | None = None) -> list[str]:
    """Re-check a release package against its recorded digests."""
    issues: list[str] = []
    required = [
        "task/task.toml",
        "task/instruction.md",
        "task/environment/Dockerfile",
        "task/solution/solve.sh",
        "task/tests/test.sh",
        "spec.json",
        "evaluation.json",
        "build-manifest.json",
        "audit.zip",
    ]
    for name in required:
        if not (release_dir / name).is_file():
            issues.append(f"missing {name}")
    if issues:
        return issues
    spec = read_json(release_dir / "spec.json")
    if spec.get("frozen_digest") != freeze_digest(spec):
        issues.append("spec frozen_digest does not match its body")
    manifest = read_json(release_dir / "build-manifest.json")
    validate("build-manifest", manifest)
    evaluation = read_json(release_dir / "evaluation.json")
    validate("evaluation", evaluation)
    if evaluation["artifact_digest"] != manifest["image_digest"]:
        issues.append("evaluation artifact digest differs from the build manifest")
    actual = tree_hashes(release_dir / "task")
    if actual != manifest["file_digests"]:
        changed = sorted(
            set(actual) ^ set(manifest["file_digests"])
            | {k for k in actual.keys() & manifest["file_digests"].keys()
               if actual[k] != manifest["file_digests"][k]}
        )
        issues.append("release task files changed: " + ", ".join(changed[:5]))
    if expected_digest and manifest["image_digest"] != expected_digest:
        issues.append(
            f"image digest {manifest['image_digest']} != expected {expected_digest}"
        )
    with zipfile.ZipFile(release_dir / "audit.zip") as archive:
        names = set(archive.namelist())
        for name in ("spec.json", "evidence-index.json", "evaluation.json", "build-manifest.json"):
            if name not in names:
                issues.append(f"audit bundle is missing {name}")
    return issues


def recheck_from_release(
    adapter: HarborAdapter,
    release_dir: Path,
    *,
    n_concurrent: int = 2,
) -> dict:
    """Re-run health plus the reference PoC from the immutable release copy."""
    task_dir = release_dir / "task"
    if not task_dir.is_dir():
        raise PipelineError(f"No task directory in {release_dir}")
    outcome = adapter.run(
        [task_dir],
        agent="oracle",
        job_name="release-recheck",
        n_concurrent=n_concurrent,
    )
    if not outcome.trials:
        raise TaskError("infra_error", "Release recheck produced no trial")
    trial = outcome.trials[0]
    return {
        "job_name": outcome.job_name,
        "reward": trial.reward,
        "status": trial.evidence_status,
        "health_ok": bool((trial.evidence or {}).get("health_ok")),
        "reference_observed": bool((trial.evidence or {}).get("reference_observed")),
        "trial_dir": str(trial.trial_dir),
    }


def write_dataset_manifest(entries: list[dict], path: Path) -> Path:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "dataset_version": DATASET_VERSION,
        "created_at": utc_now(),
        "tasks": entries,
    }
    validate("dataset-manifest", manifest)
    write_json(path, manifest)
    return path


def _copy_tree(source: Path, target: Path) -> None:
    if not source.is_dir():
        raise PipelineError(f"Missing source tree {source}")
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise PipelineError(f"Symlink in task package: {path}")
        destination = target / path.relative_to(source)
        if path.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)


def _write_readme(root: Path, spec: dict, evaluation: dict, manifest: dict, task: GeneratedTask) -> None:
    lines = [
        f"# {spec['cve_id']} Harbor task release",
        "",
        f"- Product: {spec['product']['name']}",
        f"- Vulnerable: {spec['versions']['vulnerable_ref']}",
        f"- Fixed: {spec['versions']['fixed_ref']}",
        f"- Fix commit: {spec['versions']['fix_commit']}",
        f"- Attribution grade: {spec['attribution_grade']}",
        f"- Quality score: {evaluation['quality_score']}",
        f"- Admission: {evaluation['admission_status']}",
        f"- Task digest: {task.task_digest}",
        f"- Image digest: {manifest['image_digest']}",
        "",
        "The agent-visible `instruction.md` intentionally omits the CVE id, product",
        "name, fixed version, and fix commit. Deployment metadata must not mount",
        "README.md, spec.json, or evaluation.json into the agent environment.",
    ]
    (root / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _write_audit(
    path: Path,
    spec: dict,
    evidence: dict,
    evaluation: dict,
    manifest: dict,
    matrix_result: dict,
    root: Path,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        payloads = {
            "spec.json": spec,
            "evidence-index.json": evidence,
            "evaluation.json": evaluation,
            "build-manifest.json": manifest,
            "matrix.json": matrix_result,
        }
        for name, value in payloads.items():
            archive.writestr(name, json.dumps(value, indent=2, sort_keys=True) + "\n")
        evidence_dir = root.parent / "evidence"
        if evidence_dir.is_dir():
            for item in sorted(evidence_dir.rglob("*")):
                if item.is_file():
                    archive.write(item, f"evidence/{item.relative_to(evidence_dir).as_posix()}")
        for trial in matrix_result.get("records", []):
            audit = trial.get("_audit", {})
            evidence_path = Path(str(audit.get("evidence", "")))
            if evidence_path.is_file():
                trial_name = str(audit.get("trial_name", evidence_path.parent.name))
                archive.write(
                    evidence_path,
                    f"trials/{trial['experiment_id']}/{trial_name}/{evidence_path.name}",
                )
