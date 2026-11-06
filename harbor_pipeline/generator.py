"""Render, inspect, and write Harbor task bundles from a frozen CveSpec."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from . import GENERATOR_VERSION, PROMPT_VERSION
from .goals import (
    SECRET_PATH,
    auth_identity,
    auth_material,
    auth_scheme,
    goal_family,
    target_asset,
)
from .repair import FRAMEWORK_PATHS, POC_PATH
from .scenario import (
    _SYNTHESIS_LAYER,
    ScenarioContext,
    get_scenario,
    render_synthesis,
    wrap_solution,
)
from .util import PipelineError, digest, image_base as image_tag_base, read_json, write_files, tree_hashes, child_path

ALLOWED_PREFIXES: tuple[str, ...] = (
    "instruction.md",
    "task.toml",
    "README.md",
    ".gitignore",
    "environment/",
    "solution/",
    "tests/",
)

REQUIRED_FILES: tuple[str, ...] = (
    "instruction.md",
    "task.toml",
    "environment/Dockerfile",
    "environment/docker-compose.yaml",
    "solution/solve.sh",
    "tests/Dockerfile",
    "tests/docker-compose.yaml",
    "tests/test.sh",
    "tests/verify.py",
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def harbor_task_schema() -> dict:
    candidates = [
        _REPO_ROOT / "docs" / "reference" / "harbor-task-schema.json",
        Path(__file__).resolve().parent / "reference" / "harbor-task-schema.json",
        Path(__file__).resolve().parent / "resources" / "reference" / "harbor-task-schema.json",
    ]
    for path in candidates:
        if path.is_file():
            return read_json(path)
    raise PipelineError("Harbor task schema snapshot is missing")


@dataclass
class GeneratedTask:
    cve_id: str
    variant: str
    probe: str
    scenario: str
    spec_digest: str
    task_digest: str
    files: dict[str, str]
    synthesis_digest: str = ""

    def write(self, root: Path) -> Path:
        task_root = root / "task"
        if task_root.is_symlink():
            raise PipelineError("Task directory must not be a symlink")
        old_files = set(tree_hashes(task_root)) if task_root.exists() else set()
        items = [{"path": name, "content": body} for name, body in self.files.items()]
        write_files(task_root, items, ALLOWED_PREFIXES)
        for stale in old_files - self.files.keys():
            child_path(task_root, stale).unlink()
        return task_root


def render_task(
    spec: dict,
    *,
    scenario_name: str,
    variant: str,
    probe: str = "reference",
    synthetic: bool = False,
    network_mode: str = "public",
    allowed_hosts: tuple[str, ...] = ("target",),
    controlled: bool = False,
    fault: bool = False,
    overrides: dict[str, str] | None = None,
    synthesis=None,
    revision: int = 1,
    prebuilt: bool = False,
    prebuilt_base: str | None = None,
    environment_image: str | None = None,
    verifier_image: str | None = None,
    agent_timeout_sec: float | None = None,
    paired_verification: bool = True,
) -> GeneratedTask:
    if variant not in {"vulnerable", "fixed"}:
        raise PipelineError(f"Unknown variant {variant!r}")
    version = spec["versions"]["vulnerable_ref"] if variant == "vulnerable" else spec["versions"]["fixed_ref"]
    synthesis_digest = synthesis.digest if synthesis is not None else ""
    # Validation probes use the images the pipeline just built; the release
    # copy is rendered without this so it can be rebuilt anywhere. A repair
    # debug run passes its own base so it never clobbers the validation tags.
    tag_base = prebuilt_base or (
        image_tag_base(spec["cve_id"], variant, revision) if prebuilt else None
    )
    family = goal_family(spec)
    allowed_hosts = tuple(dict.fromkeys((*allowed_hosts, "target-fixed", "observer", "observer-fixed")))
    material = auth_material(spec)
    bundle = getattr(synthesis, "bundle", None) if synthesis is not None else None
    presentation = (bundle or {}).get("presentation") or {}
    presentation_mode = str(presentation.get("mode") or "black_box")
    ctx = ScenarioContext(
        cve_id=spec["cve_id"],
        product=spec["product"]["name"],
        variant=variant,
        probe=probe,
        version=version,
        # The framework always creates the token at SECRET_PATH, whichever
        # family the goal belongs to; the family picks the observable.
        secret_path=SECRET_PATH,
        spec_digest=spec["frozen_digest"],
        attribution_grade=spec["attribution_grade"],
        synthetic=synthetic or synthesis is not None,
        controlled=controlled,
        fault=fault,
        business_path="/business" if synthesis is not None else "/static/hello.txt",
        business_body="ok" if synthesis is not None else "hello",
        synthesis_digest=synthesis_digest,
        revision=revision,
        image_base=tag_base,
        paired_verification=paired_verification and variant == "vulnerable" and scenario_name != "fixture",
        business_probes=tuple((getattr(synthesis, "target", {}) or {}).get("business_probes") or []),
        goal_family=family,
        goal_primitive=str((spec.get("task_goal") or {}).get("primitive") or ""),
        auth_identity=auth_identity(spec),
        auth_scheme=auth_scheme(spec),
        auth_user=material["user"],
        auth_password=material["password"],
        auth_token=material["token"],
        listing_name="",  # Answers are generated at target startup, never from the spec.
        target_asset=target_asset(spec, family),
        presentation_mode=presentation_mode,
        presentation_hints=tuple(str(x) for x in (presentation.get("hints") or ())),
        presentation_sources=tuple(str(x) for x in (presentation.get("source_paths") or ())),
    )
    if synthesis is not None:
        files = render_synthesis(ctx, synthesis)
    else:
        files = get_scenario(scenario_name).render(ctx)
    files = _apply_overrides(files, overrides, version=version)
    if variant == "fixed" and synthesis is not None:
        # A repair overlay is variant-agnostic. When the bundle defines a
        # fixed-only file (typically the fixed package pin), it must win over
        # a vulnerable-side repair to that file, or the fixed build silently
        # reverts to the vulnerable release.
        for name, body in (synthesis.target.get("fixed_overrides") or {}).items():
            files[f"environment/target/{name}"] = body.replace("{{REF}}", version)
    if synthesis is not None and "environment/target/Dockerfile" in files:
        # The framework layer owns the secret lifecycle, the entrypoint and the
        # curl health tooling. A repair overlay may rewrite the target
        # Dockerfile, but it must not be able to drop this layer: T12's fault
        # switch and the verifier's health path live there.
        layer = _SYNTHESIS_LAYER.strip()
        if layer not in files["environment/target/Dockerfile"]:
            files["environment/target/Dockerfile"] = (
                files["environment/target/Dockerfile"].rstrip()
                + "\n\n"
                + _SYNTHESIS_LAYER
            )
    if ctx.paired_verification:
        fixed_task = render_task(
            spec, scenario_name=scenario_name, variant="fixed", probe="reference",
            synthetic=synthetic, network_mode=network_mode, allowed_hosts=allowed_hosts,
            overrides=overrides, synthesis=synthesis, revision=revision,
            paired_verification=False,
        )
        for name, body in fixed_task.files.items():
            prefix = "environment/target/"
            if name.startswith(prefix):
                files["tests/fixed-target/" + name[len(prefix):]] = body
        files["tests/fixed/verify.py"] = fixed_task.files["tests/verify.py"]
        files["tests/fixed/reference_poc.py"] = fixed_task.files["tests/reference_poc.py"]
        files["tests/fixed_runner.py"] = (Path(__file__).parent / "assets" / "fixed_runner.py").read_text(encoding="utf-8")
    if presentation_mode == "white_box":
        # Publish only authored application context. Framework entrypoints and
        # deployment/patch files are not solver source, even when source_paths
        # is omitted. Explicit selections are checked against this boundary.
        authored = (getattr(synthesis, "target", {}) or {}).get("files", {})
        selected = presentation.get("source_paths") or list(authored)
        for name in selected:
            path = Path(name)
            forbidden = (
                path.name.lower() in {"dockerfile", "entrypoint.sh", "docker-compose.yaml", "docker-compose.yml"}
                or path.suffix.lower() in {".patch", ".diff"}
                or any(part.startswith(".") for part in path.parts)
            )
            if forbidden:
                if name in (presentation.get("source_paths") or []):
                    raise PipelineError(f"White-box source cannot expose deployment/patch file {name}")
                continue
            key = f"environment/target/{name}"
            if key in files:
                files[f"environment/source/{name}"] = files[key]
    # A repaired reference PoC must also replace the payload the oracle agent
    # submits. Otherwise the verifier's reference run uses the fix while the
    # submitted artifact still contains the broken PoC, so T03 can never pass.
    if probe == "reference" and POC_PATH in files:
        files["solution/solve.sh"] = wrap_solution(files[POC_PATH])
    task_digest = compute_task_digest(
        files,
        spec=spec,
        variant=variant,
        probe=probe,
        controlled=controlled,
        fault=fault,
        synthesis_digest=synthesis_digest,
    )
    files["task.toml"] = _task_toml(
        spec=spec,
        variant=variant,
        probe=probe,
        scenario_name=scenario_name,
        task_digest=task_digest,
        synthetic=synthetic or synthesis is not None,
        network_mode=network_mode,
        allowed_hosts=allowed_hosts,
        controlled=controlled,
        fault=fault,
        synthesis_digest=synthesis_digest,
        image_base=tag_base,
        environment_image=environment_image,
        verifier_image=verifier_image,
        presentation_mode=presentation_mode,
        agent_timeout_sec=agent_timeout_sec,
    )
    generated = GeneratedTask(
        cve_id=spec["cve_id"],
        variant=variant,
        probe=probe,
        scenario=scenario_name,
        spec_digest=spec["frozen_digest"],
        task_digest=task_digest,
        files=files,
        synthesis_digest=synthesis_digest,
    )
    check_task(generated, spec)
    return generated


def _apply_overrides(
    files: dict[str, str],
    overrides: dict[str, str] | None,
    *,
    version: str | None = None,
) -> dict[str, str]:
    """Apply the authoring agent's file edits before the task digest.

    The agent may rewrite or add files under ``environment/`` and the reference
    exploit. The instruction, verifier and frozen spec are not in this map and
    cannot be reached here, so the grading gate stays outside the write scope.
    ``{{REF}}`` in an override is substituted per variant, which lets a repair
    keep the vulnerable and fixed pins distinct.
    """
    if not overrides:
        return files
    patched = dict(files)
    for name, body in overrides.items():
        if not isinstance(name, str) or not isinstance(body, str):
            raise PipelineError("Repair overrides must map paths to text")
        if ".." in name.split("/") or name.startswith("/") or "\\" in name:
            raise PipelineError(f"Repair may not modify {name!r}")
        if name in FRAMEWORK_PATHS:
            raise PipelineError(
                f"Repair may not modify framework-owned file {name!r}; "
                "use set_start_command for the launch command"
            )
        allowed = (
            name == POC_PATH
            or (name.startswith("environment/") and "/" in name)
        )
        if not allowed:
            raise PipelineError(f"Repair may not modify {name!r}")
        if len(body.encode("utf-8")) > 256_000:
            raise PipelineError(f"Repair for {name} exceeds 256 KB")
        if version is not None:
            body = body.replace("{{REF}}", version)
        patched[name] = body
    return patched


def compute_task_digest(
    files: dict[str, str],
    *,
    spec: dict,
    variant: str,
    probe: str,
    controlled: bool = False,
    fault: bool = False,
    synthesis_digest: str = "",
) -> str:
    body = {
        "files": {name: digest(content.encode("utf-8")) for name, content in sorted(files.items()) if name != "task.toml"},
        "spec_digest": spec["frozen_digest"],
        "variant": variant,
        "probe": probe,
        "controlled": controlled,
        "fault": fault,
        "synthesis_digest": synthesis_digest,
        "generator_version": GENERATOR_VERSION,
    }
    return digest(body)


def pin_task_images(task: GeneratedTask, *image_sets: dict) -> GeneratedTask:
    """Pin execution copies to measured image IDs, including the fixed runner."""
    identities: dict[str, str] = {}

    def visit(value):
        if not isinstance(value, dict):
            return
        ref, identity = value.get("image_ref"), value.get("image_digest")
        if ref and identity:
            if ref in identities and identities[ref] != identity:
                raise PipelineError(f"Conflicting measured image identities for {ref}")
            identities[ref] = identity
        for child in value.values():
            visit(child)

    for image_set in image_sets:
        visit(image_set)
    old_digest = task.task_digest
    metadata = tomllib.loads(task.files["task.toml"])["metadata"]
    for name in ("task.toml", "environment/docker-compose.yaml", "tests/docker-compose.yaml"):
        body = task.files[name]
        for ref, identity in identities.items():
            body = body.replace(f"image: {ref}\n", f"image: {identity}\n")
            body = body.replace(f'docker_image = "{ref}"', f'docker_image = "{identity}"')
        task.files[name] = body
    task.task_digest = compute_task_digest(task.files, spec={"frozen_digest": task.spec_digest},
        variant=task.variant, probe=task.probe, controlled=metadata.get("controlled", False),
        fault=metadata.get("fault_injected", False), synthesis_digest=task.synthesis_digest)
    task.files["task.toml"] = task.files["task.toml"].replace(f'task_digest = "{old_digest}"', f'task_digest = "{task.task_digest}"')
    return task


def _task_toml(
    *,
    spec: dict,
    variant: str,
    probe: str,
    scenario_name: str,
    task_digest: str,
    synthetic: bool,
    network_mode: str,
    allowed_hosts: tuple[str, ...],
    controlled: bool,
    fault: bool,
    synthesis_digest: str = "",
    image_base: str | None = None,
    environment_image: str | None = None,
    verifier_image: str | None = None,
    presentation_mode: str = "black_box",
    agent_timeout_sec: float | None = None,
) -> str:
    suffix = "-control" if controlled else ("-fault" if fault else "")
    # Task validation probes reuse two task-independent images so every
    # candidate does not rebuild an agent and a verifier that are byte-identical
    # for all tasks. The target image stays per-candidate.
    verifier_ref = verifier_image or (image_base + "-verifier" if image_base else None)
    environment_ref = environment_image or (image_base + "-agent" if image_base else None)
    verifier_block = (
        "[verifier.environment]\n"
        f"docker_image = {_q(verifier_ref)}\n"
        if verifier_ref else ""
    )
    environment_line = (
        f"docker_image = {_q(environment_ref)}\n"
        if environment_ref else ""
    )
    primitive = str(spec["task_goal"].get("primitive") or "file_read")
    primitive_keyword = primitive.replace("_", "-")
    name = f"harbor-cve/{spec['cve_id'].lower()}-{variant}{suffix}"
    description = (
        f"Replayable web security task derived from {spec['cve_id']} "
        f"({spec['product']['name']}, {variant}{suffix})."
    )
    if network_mode == "allowlist":
        allow = "allowed_hosts = [" + ", ".join(_q(h) for h in allowed_hosts) + "]\n"
    else:
        allow = ""
    return f"""\
schema_version = "1.4"

[task]
name = {_q(name)}
version = "1.0.0"
description = {_q(description)}
keywords = ["web", {_q(primitive_keyword)}, "cve"]
[[task.authors]]
name = "harbor-cve-pipeline"

[metadata]
cve_id = {_q(spec['cve_id'])}
product = {_q(spec['product']['name'])}
variant = {_q(variant)}
probe = {_q(probe)}
scenario = {_q(scenario_name)}
synthetic = {str(synthetic).lower()}
generation_mode = {_q("synthesized" if synthesis_digest else "template")}
synthesis_digest = {_q(synthesis_digest)}
controlled = {str(controlled).lower()}
fault_injected = {str(fault).lower()}
attribution_grade = {_q(spec['attribution_grade'])}
spec_digest = {_q(spec['frozen_digest'])}
task_digest = {_q(task_digest)}
generator_version = {_q(GENERATOR_VERSION)}
prompt_version = {_q(PROMPT_VERSION)}
prompt_policy = "service-only"
network_isolation = {_q(network_mode)}
goal_type = {_q(spec['task_goal']['type'])}
goal_family = {_q(str(spec['task_goal'].get('family') or 'secret_read'))}
goal_primitive = {_q(primitive)}
target_secret_path = {_q(SECRET_PATH)}
goal_target_asset = {_q(spec['task_goal']['target_asset'])}
auth_identity = {_q(str(spec.get('preconditions', {}).get('auth_identity') or 'none'))}
auth_scheme = {_q(str(spec.get('preconditions', {}).get('auth_scheme') or 'none'))}
presentation_mode = {_q(presentation_mode)}

[verifier]
environment_mode = "separate"
timeout_sec = 600.0
network_mode = {_q(network_mode)}
{allow}{verifier_block}
[agent]
timeout_sec = {float(agent_timeout_sec or 900.0)}
network_mode = {_q(network_mode)}
{allow}
[environment]
network_mode = {_q(network_mode)}
{allow}{environment_line}build_timeout_sec = 900.0
os = "linux"
cpus = 2
memory_mb = 2048
"""


def _q(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def check_task(generated: GeneratedTask, spec: dict) -> None:
    issues = inspect_task(generated.files, spec)
    if issues:
        raise PipelineError("Generated task failed checks: " + "; ".join(issues))


def inspect_task(files: dict[str, str], spec: dict) -> list[str]:
    issues: list[str] = []
    for required in REQUIRED_FILES:
        if required not in files:
            issues.append(f"missing {required}")
    if len(files) > 160:
        issues.append("more than 160 files")
    total = sum(len(content.encode("utf-8")) for content in files.values())
    if total > 8_000_000:
        issues.append("bundle exceeds 8 MB")
    for name in files:
        if name.startswith("/") or ".." in Path(name).parts or "\\" in name:
            issues.append(f"unsafe path {name}")

    instruction = files.get("instruction.md", "")
    issues.extend(_instruction_policy_issues(instruction, spec))

    task_toml = files.get("task.toml")
    if task_toml:
        try:
            parsed = tomllib.loads(task_toml)
        except tomllib.TOMLDecodeError as exc:
            issues.append(f"task.toml is not valid TOML: {exc}")
        else:
            try:
                Draft202012Validator(harbor_task_schema()).validate(parsed)
            except Exception as exc:  # jsonschema.ValidationError
                issues.append(f"task.toml violates the Harbor schema: {getattr(exc, 'message', exc)}")
            verifier = parsed.get("verifier") or {}
            if verifier.get("environment_mode") != "separate":
                issues.append("verifier must build its own environment (environment_mode = 'separate')")
    return issues


def _instruction_policy_issues(instruction: str, spec: dict) -> list[str]:
    issues: list[str] = []
    lowered = instruction.lower()
    forbidden = {
        "cve id": spec["cve_id"].lower(),
        "product name": spec["product"]["name"].lower(),
        "fix commit": spec["versions"]["fix_commit"].lower(),
        "fixed version": spec["versions"]["fixed_ref"].lower(),
    }
    for label, value in forbidden.items():
        if value and value in lowered:
            issues.append(f"instruction leaks the {label} ({value})")
    for phrase in ("official patch", "reference solution", "the vulnerability is"):
        if phrase in lowered:
            issues.append(f"instruction contains forbidden phrase {phrase!r}")
    if "/logs/artifacts/poc" not in instruction:
        issues.append("instruction must tell the agent where to publish the PoC")
    if "shebang" not in lowered:
        issues.append("instruction must require a self-contained executable script")
    return issues
