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
            return json.loads(result.body.decode("utf-8"))
        if ecosystem == "npm":
            result = fetch(
                f"https://registry.npmjs.org/{name}/{version}", settings
            )
            return json.loads(result.body.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a metadata miss must not block a task
        return {}
    return {}


def _wheel_mismatch(files: list[str], runtime: str) -> bool:
    """True when the release publishes wheels, but none for this interpreter.

    ``requires_python`` is metadata the publisher may leave empty; an old
    release with only cp36 wheels then looks installable on Python 3.12 and
    fails at build time. Pure-python and abi3 wheels are usable everywhere
    they claim to be.
    """
    wheels = [name for name in files if name.endswith(".whl")]
    if not wheels:
        return False
    if any("none-any.whl" in name or "abi3" in name for name in wheels):
        return False
    major, _, minor = runtime.partition(".")
    tag = f"cp{major}{minor}"
    return not any(tag in name for name in wheels)


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
            doc = _release_metadata(ecosystem, name, ref, settings)
            info = doc.get("info") or {}
            requires = str(info.get("requires_python") or "")
            compatible = _python_compatible(requires, runtime)
            if compatible is False:
                issues.append(
                    f"{name} {ref} requires Python {requires}, but the base image "
                    f"{base_image} provides Python {runtime}. Choose a release "
                    "compatible with the image or a matching base image."
                )
            filenames = [
                str(item.get("filename") or "")
                for item in (doc.get("urls") or [])
                if isinstance(item, dict)
            ]
            if _wheel_mismatch(filenames, runtime):
                issues.append(
                    f"{name} {ref} publishes binary wheels, but none for Python "
                    f"{runtime} (base image {base_image}). Building from source is "
                    "likely to fail; choose a release with a matching wheel or a "
                    "compatible base image."
                )
    elif language == "node" and ecosystem == "npm":
        for key in ("vulnerable_ref", "fixed_ref"):
            ref = _normalize_ref(ecosystem, str(versions.get(key) or ""))
            doc = _release_metadata(ecosystem, name, ref, settings)
            engines = str((doc.get("engines") or {}).get("node") or "")
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
    issues.extend(_manifest_issues(bundle, settings))
    return issues


_GO_REQUIRE_BLOCK = re.compile(r"require\s*\(([^)]*)\)", re.DOTALL)
_GO_REQUIRE_LINE = re.compile(r"^\s*require\s+(\S+)\s+(\S+)\s*$", re.MULTILINE)


def _go_requires(go_mod: str) -> list[tuple[str, str]]:
    requires: list[tuple[str, str]] = []
    for block in _GO_REQUIRE_BLOCK.findall(go_mod):
        for line in block.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                requires.append((parts[0], parts[1]))
    for match in _GO_REQUIRE_LINE.finditer(go_mod):
        requires.append((match.group(1), match.group(2)))
    return requires


def _manifest_issues(bundle: dict, settings: SourceSettings) -> list[str]:
    """Check the dependencies the target actually declares.

    The product's ecosystem is a hint from the advisory; the build follows the
    target's ``go.mod`` / ``package.json`` / ``requirements.txt``. A model can
    therefore pin a real product and a nonexistent helper, or use a Go module
    path that was never published. A template ``{{REF}}`` version is checked
    for the package/module name only.
    """
    files = (bundle.get("target") or {}).get("files") or {}
    issues: list[str] = []
    budget = 8

    def exists(ecosystem: str, name: str, version: str | None) -> bool | None:
        nonlocal budget
        if budget <= 0:
            return None
        budget -= 1
        if version is None:
            result = lookup(ecosystem, name, settings)
            if "error" not in result:
                return True
            error = str(result["error"]).lower()
            return False if ("404" in error or "no published" in error) else None
        return version_exists(ecosystem, name, version, settings)

    for filename, body in files.items():
        name = str(filename)
        text = str(body)
        if name.endswith("go.mod"):
            for path, version in _go_requires(text):
                if path.startswith(("//", ")")):
                    continue
                if "{{REF}}" in version:
                    if exists("go", path, None) is False:
                        issues.append(
                            f"go.mod requires module {path!r}, which is not "
                            "published; use the real module path from the evidence."
                        )
                elif exists("go", path, version) is False:
                    issues.append(
                        f"go.mod requires {path} {version}, but that module "
                        "version is not published."
                    )
        elif name.endswith("package.json"):
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for dep, spec in (data.get("dependencies") or {}).items():
                spec = str(spec)
                if "{{REF}}" in spec:
                    if exists("npm", dep, None) is False:
                        issues.append(
                            f"package.json depends on {dep!r}, which is not "
                            "published on npm."
                        )
                elif re.fullmatch(r"v?\d+(?:\.\d+)*", spec):
                    if exists("npm", dep, spec.lstrip("v")) is False:
                        issues.append(
                            f"package.json pins {dep} {spec}, which is not "
                            "published on npm."
                        )
        elif name.endswith("requirements.txt"):
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if "==" not in line:
                    continue
                dep, version = line.split("==", 1)
                dep = dep.split("[", 1)[0].strip()
                version = version.strip()
                if not dep:
                    continue
                if "{{REF}}" in version:
                    if exists("pypi", dep, None) is False:
                        issues.append(
                            f"requirements.txt names {dep!r}, which is not "
                            "published on PyPI."
                        )
                elif re.fullmatch(r"\d+(?:\.\d+)*(?:[a-zA-Z0-9.+-]*)", version):
                    if exists("pypi", dep, version) is False:
                        issues.append(
                            f"requirements.txt pins {dep}=={version}, which is "
                            "not published on PyPI."
                        )
    return issues
