"""Load and validate the frozen data contracts and policy files."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .util import PipelineError, digest, read_json

SCHEMA_NAMES: tuple[str, ...] = (
    "evidence-index",
    "cve-spec",
    "build-manifest",
    "trial-record",
    "evaluation",
    "dataset-manifest",
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _search_dir(env_var: str, name: str) -> Path:
    override = os.environ.get(env_var)
    candidates = []
    if override:
        candidates.append(Path(override))
    candidates.append(_REPO_ROOT / name)
    candidates.append(Path(__file__).resolve().parent / name)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise PipelineError(f"Cannot locate {name}/ directory for the pipeline")


def schemas_dir() -> Path:
    return _search_dir("HARBOR_PIPELINE_SCHEMAS", "schemas")


def policies_dir() -> Path:
    return _search_dir("HARBOR_PIPELINE_POLICIES", "policies")


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    if name not in SCHEMA_NAMES:
        raise PipelineError(f"Unknown schema: {name!r}")
    path = schemas_dir() / f"{name}.schema.json"
    if not path.is_file():
        raise PipelineError(f"Missing schema file: {path}")
    return read_json(path)


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    Draft202012Validator.check_schema(load_schema(name))
    return Draft202012Validator(load_schema(name))


class ContractError(PipelineError):
    def __init__(self, name: str, errors: Iterable[str]):
        self.name = name
        self.errors = list(errors)
        super().__init__(f"{name} contract violation: " + "; ".join(self.errors))


def validate(name: str, data: Any) -> dict:
    """Validate data against a named contract and return it unchanged."""
    errors = sorted(
        (e for e in _validator(name).iter_errors(data)),
        key=lambda e: list(e.absolute_path),
    )
    if errors:
        raise ContractError(name, (_format_error(e) for e in errors))
    return data


def _format_error(error: ValidationError) -> str:
    location = "/".join(str(p) for p in error.absolute_path) or "<root>"
    return f"{location}: {error.message}"


def freeze_digest(spec: dict) -> str:
    """Canonical digest of a spec body, excluding the frozen digest field itself."""
    body = {k: v for k, v in spec.items() if k != "frozen_digest"}
    return digest(body)


# ---------------------------------------------------------------------------
# Policy files
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Profile:
    name: str
    trials: int
    min_valid_trials: int
    require_paired: bool
    min_quality_score: float
    allow_attribution_grade: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    schema_version: str
    policy_version: str
    weights: dict[str, float]
    min_quality_score: float
    min_attribution_grade: str
    hard_conditions: dict[str, Any]
    profiles: dict[str, Profile]
    grades: dict[str, dict[str, Any]] = field(default_factory=dict)

    def profile(self, name: str) -> Profile:
        try:
            return self.profiles[name]
        except KeyError as exc:
            raise PipelineError(f"Unknown profile: {name!r}") from exc

    def weight_total(self) -> float:
        return sum(self.weights.values())


@lru_cache(maxsize=None)
def load_policy() -> Policy:
    path = policies_dir() / "acceptance.toml"
    if not path.is_file():
        raise PipelineError(f"Missing policy file: {path}")
    raw = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    try:
        profiles = {
            name: Profile(name=name, **values)
            for name, values in raw.get("profiles", {}).items()
        }
        policy = Policy(
            schema_version=raw["schema_version"],
            policy_version=raw["policy_version"],
            weights={k: float(v) for k, v in raw["weights"].items()},
            min_quality_score=float(raw["thresholds"]["min_quality_score"]),
            min_attribution_grade=raw["thresholds"]["min_attribution_grade"],
            hard_conditions=dict(raw.get("hard_conditions", {})),
            profiles=profiles,
            grades=dict(raw.get("grades", {})),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PipelineError(f"Invalid acceptance policy: {exc}") from exc
    missing = {"V", "P", "M", "D", "I"} - set(policy.weights)
    if missing:
        raise PipelineError(f"Policy weights missing dimensions: {sorted(missing)}")
    if abs(policy.weight_total() - 100.0) > 1e-9:
        raise PipelineError(f"Policy weights must total 100, got {policy.weight_total()}")
    return policy


@dataclass(frozen=True)
class Experiment:
    id: str
    name: str
    variant: str
    probe: str
    expect: str
    mandatory_for_release: bool
    description: str


@lru_cache(maxsize=None)
def load_experiments() -> tuple[Experiment, ...]:
    path = policies_dir() / "experiments.toml"
    if not path.is_file():
        raise PipelineError(f"Missing experiments policy: {path}")
    raw = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    experiments = []
    for item in raw.get("experiments", []):
        try:
            experiments.append(
                Experiment(
                    id=item["id"],
                    name=item["name"],
                    variant=item["variant"],
                    probe=item["probe"],
                    expect=item["expect"],
                    mandatory_for_release=bool(item["mandatory_for_release"]),
                    description=item["description"],
                )
            )
        except KeyError as exc:
            raise PipelineError(f"Invalid experiment entry: missing {exc}") from exc
    if not experiments:
        raise PipelineError("No experiments defined in policies/experiments.toml")
    ids = [e.id for e in experiments]
    if len(ids) != len(set(ids)):
        raise PipelineError("Duplicate experiment ids in policy")
    return tuple(experiments)


def mandatory_experiment_ids() -> list[str]:
    return [e.id for e in load_experiments() if e.mandatory_for_release]
