"""Public registry lookups for the repairer.

The repairer is a completion model without a shell. When a build fails because
a pinned dependency version does not exist, guessing another version wastes a
repair attempt. The harness therefore queries the public registry on the
model's behalf and puts the available versions into the repair prompt. Only the
configured source allowlist is used (https, public address, DNS pinned); the
model itself never gets network access.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .backend import dependency_lock
from .config import SourceSettings
from .errors import TaskError
from .sources import fetch

MAX_VERSIONS = 30
MAX_PACKAGES = 6

# Registry names may contain scopes (@scope/pkg), Go module paths (a/b/c) and
# Maven coordinates (group:artifact). Reject anything else before it becomes a
# URL path.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._@/+:-]+$")


def _sort_versions(versions: list[str]) -> list[str]:
    try:
        from packaging.version import InvalidVersion, Version

        return sorted(versions, key=Version, reverse=True)
    except Exception:  # noqa: BLE001 - registry versions are not all PEP 440
        return sorted(set(versions), reverse=True)


def _parse(ecosystem: str, name: str, settings: SourceSettings) -> list[str]:
    if ecosystem == "pypi":
        result = fetch(f"https://pypi.org/pypi/{name}/json", settings)
        data = json.loads(result.body.decode("utf-8"))
        return list((data.get("releases") or {}).keys())
    if ecosystem == "npm":
        result = fetch(f"https://registry.npmjs.org/{name}", settings)
        data = json.loads(result.body.decode("utf-8"))
        return list((data.get("versions") or {}).keys())
    if ecosystem == "go":
        result = fetch(f"https://proxy.golang.org/{name}/@v/list", settings)
        return [line.strip() for line in result.body.decode().splitlines() if line.strip()]
    if ecosystem == "maven":
        group, _, artifact = name.partition(":")
        if not group or not artifact:
            raise TaskError("source_error", f"Maven coordinate {name!r} is not group:artifact")
        url = (
            "https://repo1.maven.org/maven2/"
            f"{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        )
        result = fetch(url, settings)
        return re.findall(r"<version>([^<]+)</version>", result.body.decode("utf-8"))
    raise TaskError("source_error", f"Unsupported ecosystem {ecosystem!r}")


def lookup(ecosystem: str, name: str, settings: SourceSettings) -> dict:
    """Return ``{"versions": [...]}`` or ``{"error": "..."}`` never raise."""
    if not _SAFE_NAME.fullmatch(name):
        return {"error": "unsafe registry name"}
    try:
        versions = _sort_versions(_parse(ecosystem, name, settings))
    except (TaskError, ValueError, OSError) as exc:
        return {"error": str(exc)[:300]}
    if not versions:
        return {"error": "no published versions"}
    return {"versions": versions[:MAX_VERSIONS], "total": len(versions)}


def build_context(
    *,
    spec: dict,
    task_dir: Path,
    settings: SourceSettings,
    log_tail: str = "",
) -> str:
    """Describe the failed build and the real versions of its pinned deps."""
    chunks: list[str] = []
    if log_tail.strip():
        chunks.append(
            "## Build failure log (tail)\n"
            "```\n" + log_tail.strip()[-4000:] + "\n```"
        )
    ecosystem = str((spec.get("product") or {}).get("ecosystem") or "")
    target = task_dir / "environment" / "target"
    lock = dependency_lock(target) if target.is_dir() else {}
    lines: list[str] = []
    for name, version in list(lock.items())[:MAX_PACKAGES]:
        result = lookup(ecosystem, name, settings)
        if "error" in result:
            lines.append(
                f"- {ecosystem or 'package'} `{name}` pinned `{version}`: "
                f"registry lookup failed ({result['error']})"
            )
            continue
        latest = ", ".join(result["versions"][:12])
        lines.append(
            f"- {ecosystem or 'package'} `{name}` pinned `{version}`: "
            f"{result.get('total', len(result['versions']))} versions exist; "
            f"latest: {latest}"
        )
    if lines:
        chunks.append(
            "## Registry versions (queried by the harness; do not guess)\n"
            + "\n".join(lines)
            + "\nUse only a version that exists in the registry and still "
            "contains the vulnerable release. If the package name itself does "
            "not exist, choose a real dependency from the evidence."
        )
    return "\n\n".join(chunks)
