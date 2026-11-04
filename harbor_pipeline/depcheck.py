"""Deterministic dependency reality checks for a synthesized bundle.

The draft model sometimes pins a release that does not exist, a Go module path
that was never published, or a release that cannot run on the base image. Those
fail as build errors and then cost a repair cycle to diagnose. This module
queries the same public registries the repair agent uses, but at draft time,
and returns concrete issues that are fed back to the model before a build is
ever attempted.

The checks are advisory when the registry itself is unreachable: a network
outage must not turn a valid task into a generation error. A definitive answer
from the registry (no such version, incompatible ``requires_python``) is an
issue.
"""

from __future__ import annotations

import json
import re

from .config import SourceSettings
from .registry import lookup, version_exists
from .sources import fetch

_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[+-][A-Za-z0-9.-]+)?$")
_PY_IMAGE = re.compile(r"^python:(\d+)\.(\d+)")
_NODE_IMAGE = re.compile(r"^node:(\d+)")
_GO_IMAGE = re.compile(r"^golang:(\d+)(?:\.(\d+))?")
_GO_MOD_GO = re.compile(r"^\s*go\s+(\d+\.\d+)", re.MULTILINE)


def _base_runtime(base_image: str) -> tuple[str, str]:
    """Return ``(language, major[.minor])`` for the common official images."""
    image = str(base_image or "").strip()
    if match := _PY_IMAGE.match(image):
        return "python", f"{match.group(1)}.{match.group(2)}"
    if match := _NODE_IMAGE.match(image):
        return "node", match.group(1)
    if match := _GO_IMAGE.match(image):
        minor = f".{match.group(2)}" if match.group(2) else ""
        return "go", f"{match.group(1)}{minor}"
    return "", ""


def _normalize_ref(ecosystem: str, ref: str) -> str:
    ref = str(ref or "").strip()
    if ecosystem == "go":
        return ref.lstrip("v")
    return ref


def _release_metadata(
    ecosystem: str, name: str, version: str, settings: SourceSettings
) -> dict:
    try:
        if ecosystem == "pypi":
            result = fetch(f"https://pypi.org/pypi/{name}/{version}/json", settings)
            return json.loads(result.body.decode("utf-8")).get("info") or {}
        if ecosystem == "npm":
            result = fetch(
                f"https://registry.npmjs.org/{name}/{version}", settings
            )
            return json.loads(result.body.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a metadata miss must not block a task
        return {}
    return {}


def _python_compatible(requires_python: str, runtime: str) -> bool | None:
    if not requires_python:
        return None
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        return SpecifierSet(requires_python).contains(Version(runtime))
    except Exception:  # noqa: BLE001 - malformed metadata is not a verdict
        return None


def _node_compatible(engines: str, runtime: str) -> bool | None:
    """Conservative check of the common ``engines.node`` range forms."""
    if not engines:
        return None
    try:
        major = int(runtime)
    except ValueError:
        return None
    lower = re.search(r">=\s*(\d+)", engines)
    upper = re.search(r"<\s*(\d+)", engines)
    caret = re.search(r"\^\s*(\d+)", engines)
    if caret:
        return major == int(caret.group(1))
    if lower and major < int(lower.group(1)):
        return False
    if upper and major >= int(upper.group(1)):
        return False
    return True


def check_bundle(bundle: dict, settings: SourceSettings) -> list[str]:
    """Return concrete dependency issues; an empty list means "try the build"."""
    product = bundle.get("product") or {}
    ecosystem = str(product.get("ecosystem") or "")
    name = str(product.get("name") or "")
    versions = bundle.get("versions") or {}
    issues: list[str] = []
    if ecosystem not in {"pypi", "npm", "go", "maven"} or not name:
        return issues

    result = lookup(ecosystem, name, settings)
    if "error" in result:
        # A real "not found" is definitive; transport failures are not.
        error = str(result["error"]).lower()
        if "404" in error or "no published versions" in error:
            issues.append(
                f"The pinned {ecosystem} package {name!r} is not published in its "
                "registry. Use the real package named by the evidence."
            )
        return issues

    for key in ("vulnerable_ref", "fixed_ref"):
        ref = _normalize_ref(ecosystem, str(versions.get(key) or ""))
        if not ref:
            continue
        # Ask for the exact release: the version list is a page of the newest
        # entries, so membership in it would reject every older, valid pin.
        exists = version_exists(ecosystem, name, ref, settings)
        if exists is False:
            sample = ", ".join(result["versions"][:10])
            issues.append(
                f"versions.{key} {ref!r} does not exist for {ecosystem} "
                f"{name!r}. Newest published versions include: {sample}."
            )

    base_image = str((bundle.get("target") or {}).get("base_image") or "")
    language, runtime = _base_runtime(base_image)
    if language == "python" and ecosystem == "pypi":
        for key in ("vulnerable_ref", "fixed_ref"):
            ref = _normalize_ref(ecosystem, str(versions.get(key) or ""))
            info = _release_metadata(ecosystem, name, ref, settings)
            requires = str(info.get("requires_python") or "")
            compatible = _python_compatible(requires, runtime)
            if compatible is False:
                issues.append(
                    f"{name} {ref} requires Python {requires}, but the base image "
                    f"{base_image} provides Python {runtime}. Choose a release "
                    "compatible with the image or a matching base image."
                )
    elif language == "node" and ecosystem == "npm":
        for key in ("vulnerable_ref", "fixed_ref"):
            ref = _normalize_ref(ecosystem, str(versions.get(key) or ""))
            info = _release_metadata(ecosystem, name, ref, settings)
            engines = str((info.get("engines") or {}).get("node") or "")
            compatible = _node_compatible(engines, runtime)
            if compatible is False:
                issues.append(
                    f"{name} {ref} requires Node {engines}, but the base image "
                    f"{base_image} provides Node {runtime}. Choose a matching "
                    "release or base image."
                )
    elif language == "go":
        go_mod = ""
        for filename, body in ((bundle.get("target") or {}).get("files") or {}).items():
            if str(filename).endswith("go.mod"):
                go_mod = str(body)
                break
        match = _GO_MOD_GO.search(go_mod)
        if match:
            required = match.group(1)
            try:
                if tuple(int(x) for x in required.split(".")) > tuple(
                    int(x) for x in runtime.split(".")
                ):
                    issues.append(
                        f"go.mod requires Go {required}, but the base image "
                        f"{base_image} provides Go {runtime}. Use a newer "
                        "golang image tag."
                    )
            except ValueError:
                pass
    return issues
