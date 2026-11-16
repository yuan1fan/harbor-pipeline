"""Opt-in reuse of a user's Claude connection settings for pipeline children.

Only the endpoint/authentication group is imported. Never import permissions,
hooks, arbitrary environment variables or model overrides from that file.
"""
from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from typing import Mapping

from .util import PipelineError

CONNECTION_KEYS = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")


def inherited_connection(
    config_path: Path | None,
    *,
    environ: Mapping[str, str] | None = None,
    settings_path: Path | None = None,
) -> dict[str, str]:
    """Return missing connection settings without mutating the caller's env.

    An explicit environment override, even a partial one, wins as a group.
    Combining a saved credential with another endpoint could send it to the
    wrong server, so never complete a partially overridden group implicitly.
    """
    if config_path is None:
        return {}
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise PipelineError(f"Cannot read configuration {config_path}") from exc
    if raw.get("pipeline", {}).get("inherit_claude_settings") is not True:
        return {}
    environ = os.environ if environ is None else environ
    if any(environ.get(name) for name in (*CONNECTION_KEYS, "CLAUDE_CODE_OAUTH_TOKEN")):
        return {}
    if settings_path is None:
        directory = Path(environ["CLAUDE_CONFIG_DIR"]) if environ.get("CLAUDE_CONFIG_DIR") else Path.home() / ".claude"
        settings_path = directory / "settings.json"
    try:
        saved = json.loads(settings_path.read_text(encoding="utf-8-sig"))
        saved_env = saved.get("env", {}) if isinstance(saved, dict) else {}
        if not isinstance(saved_env, dict):
            raise ValueError("env must be an object")
    except (OSError, ValueError) as exc:
        raise PipelineError(
            f"Cannot read Claude connection settings from {settings_path}; "
            "set ANTHROPIC_BASE_URL and the matching ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY in this shell"
        ) from exc
    values = {name: saved_env[name] for name in CONNECTION_KEYS
              if isinstance(saved_env.get(name), str) and saved_env[name].strip()}
    if not values.get("ANTHROPIC_BASE_URL") or not any(values.get(name) for name in CONNECTION_KEYS[1:]):
        raise PipelineError(
            "Claude settings do not contain a complete endpoint/authentication pair; "
            "set ANTHROPIC_BASE_URL and its matching credential in this shell"
        )
    if any(any(char in value for char in ("\0", "\r", "\n")) for value in values.values()):
        raise PipelineError("Invalid control character in Claude connection settings")
    return values
