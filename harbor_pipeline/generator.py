"""Render, inspect, and write Harbor task bundles from a frozen CveSpec."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from . import GENERATOR_VERSION, PROMPT_VERSION
from .scenario import ScenarioContext, get_scenario
from .util import PipelineError, digest, read_json, write_files

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

    def write(self, root: Path) -> Path:
        task_root = root / "task"
        items = [{"path": name, "content": body} for name, body in self.files.items()]
        write_files(task_root, items, ALLOWED_PREFIXES)
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
) -> GeneratedTask:
    if variant not in {"vulnerable", "fixed"}:
        raise PipelineError(f"Unknown variant {variant!r}")
    scenario = get_scenario(scenario_name)
    version = spec["versions"]["vulnerable_ref"] if variant == "vulnerable" else spec["versions"]["fixed_ref"]
    ctx = ScenarioContext(
        cve_id=spec["cve_id"],
        product=spec["product"]["name"],
        variant=variant,
        probe=probe,
        version=version,
        secret_path=spec["task_goal"]["target_asset"],
        spec_digest=spec["frozen_digest"],
        attribution_grade=spec["attribution_grade"],
        synthetic=synthetic,
        controlled=controlled,
        fault=fault,
    )
    files = scenario.render(ctx)
    files = _apply_overrides(files, overrides)
    task_digest = compute_task_digest(
        files, spec=spec, variant=variant, probe=probe, controlled=controlled, fault=fault
    )
    files["task.toml"] = _task_toml(
        spec=spec,
        variant=variant,
        probe=probe,
        scenario_name=scenario_name,
        task_digest=task_digest,
        synthetic=synthetic,
        network_mode=network_mode,
        allowed_hosts=allowed_hosts,
        controlled=controlled,
        fault=fault,
    )
    generated = GeneratedTask(
        cve_id=spec["cve_id"],
        variant=variant,
        probe=probe,
        scenario=scenario_name,
        spec_digest=spec["frozen_digest"],
        task_digest=task_digest,
        files=files,
    )
    check_task(generated, spec)
    return generated


def _apply_overrides(files: dict[str, str], overrides: dict[str, str] | None) -> dict[str, str]:
    """Apply reviewed repair edits before the task digest is computed.

    Repairs are restricted to existing files under `environment/`: the
    instruction, verifier, and reference solution are never model-editable.
    """
    if not overrides:
        return files
    patched = dict(files)
    for name, body in overrides.items():
        if not isinstance(name, str) or not isinstance(body, str):
            raise PipelineError("Repair overrides must map paths to text")
        if not name.startswith("environment/") or "/" not in name or ".." in name.split("/"):
            raise PipelineError(f"Repair may not modify {name!r}")
        if name not in patched:
            raise PipelineError(f"Repair may not create new file {name!r}")
        if len(body.encode("utf-8")) > 256_000:
            raise PipelineError(f"Repair for {name} exceeds 256 KB")
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
) -> str:
    body = {
        "files": {name: digest(content.encode("utf-8")) for name, content in sorted(files.items()) if name != "task.toml"},
        "spec_digest": spec["frozen_digest"],
        "variant": variant,
        "probe": probe,
        "controlled": controlled,
        "fault": fault,
        "generator_version": GENERATOR_VERSION,
    }
    return digest(body)


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
) -> str:
    suffix = "-control" if controlled else ("-fault" if fault else "")
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
keywords = ["web", "file-read", "cve"]
[[task.authors]]
name = "harbor-cve-pipeline"

[metadata]
cve_id = {_q(spec['cve_id'])}
product = {_q(spec['product']['name'])}
variant = {_q(variant)}
probe = {_q(probe)}
scenario = {_q(scenario_name)}
synthetic = {str(synthetic).lower()}
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
target_secret_path = {_q(spec['task_goal']['target_asset'])}

[verifier]
environment_mode = "separate"
timeout_sec = 600.0
network_mode = {_q(network_mode)}
{allow}
[agent]
timeout_sec = 900.0
network_mode = {_q(network_mode)}
{allow}
[environment]
network_mode = {_q(network_mode)}
{allow}build_timeout_sec = 900.0
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
    if len(files) > 80:
        issues.append("more than 80 files")
    total = sum(len(content.encode("utf-8")) for content in files.values())
    if total > 4_000_000:
        issues.append("bundle exceeds 4 MB")
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
