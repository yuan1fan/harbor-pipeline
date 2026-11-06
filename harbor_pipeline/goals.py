"""Goal-family and authentication primitives shared by every pipeline stage.

A task used to have exactly one observable: the per-instance secret token. That
made every authenticated CVE unsupported and forced write-side, listing and
blind-request bugs into the wrong shape. This module names the families the
framework can actually verify and derives the framework-owned material
(credentials, marker name, callback path) from the frozen spec, so the rendered
task, the instruction and the verifier always agree.
"""

from __future__ import annotations

import hashlib

# The framework-owned token. It is always created, even when the goal is not a
# token read, so the target contract stays uniform and a PoC cannot satisfy a
# write/listing goal by reading it.
SECRET_PATH = "/opt/app/secret/token"
SECRET_MOUNT = "/oracle"
SECRET_NAME_FILE = "/oracle/expected-token"

# Shared marker volume for the file-write family. Only the target and the
# independent observer mount it; the verifier main (where the PoC runs) does
# not, so a PoC cannot satisfy the goal by writing the marker itself.
MARKER_PATH = "/marker/pwned"
MARKER_DIR = "/marker"

# Directory whose randomly named child is the directory-listing observable.
LISTING_DIR = "/opt/app/secret"
# Shared volume where the target publishes the expected filename. The verifier
# reads and deletes it before running any PoC, so the untrusted PoC cannot
# learn the answer from the verifier container.
LISTING_MOUNT = "/listing"
LISTING_NAME_FILE = "/listing/expected"

# Shared marker for the server-request family.
CALLBACK_PATH = "/callback"
CALLBACK_PORT = 8099

GOAL_FAMILIES: tuple[str, ...] = (
    "secret_read",
    "file_write",
    "directory_listing",
    "server_request",
)

AUTH_IDENTITIES: tuple[str, ...] = ("none", "low_privilege", "high_privilege")
AUTH_SCHEMES: tuple[str, ...] = ("none", "http_basic", "bearer_token")


def goal_family(spec: dict) -> str:
    goal = spec.get("task_goal") or {}
    family = str(goal.get("family") or "secret_read").strip()
    return family if family in GOAL_FAMILIES else "secret_read"


def auth_identity(spec: dict) -> str:
    pre = spec.get("preconditions") or {}
    identity = str(pre.get("auth_identity") or "none").strip()
    return identity if identity in AUTH_IDENTITIES else "none"


def auth_scheme(spec: dict) -> str:
    pre = spec.get("preconditions") or {}
    scheme = str(pre.get("auth_scheme") or "").strip()
    if not scheme:
        # Older specs only carry auth_identity. An authenticated identity
        # without a scheme is rendered as HTTP Basic.
        return "none" if auth_identity(spec) == "none" else "http_basic"
    return scheme if scheme in AUTH_SCHEMES else "none"


def auth_material(spec: dict) -> dict[str, str]:
    """Framework-owned credentials for the declared auth scheme.

    The values are deterministic from the frozen spec: the instruction, the
    target environment and the verifier must agree, and a repair must not
    rotate a credential out from under a task that already shipped. They are
    preconditions, not the answer; the per-instance secret and the marker
    content stay random.
    """
    scheme = auth_scheme(spec)
    if scheme == "none":
        return {"scheme": "none", "user": "", "password": "", "token": ""}
    digest = hashlib.sha256(
        f"{spec.get('frozen_digest', '')}:auth:v1".encode("utf-8")
    ).hexdigest()
    return {
        "scheme": scheme,
        "user": "analyst",
        "password": digest[:24],
        "token": digest[:32],
    }


def listing_name(spec: dict) -> str:
    """Framework-owned random filename that only a directory listing reveals."""
    digest = hashlib.sha256(
        f"{spec.get('frozen_digest', '')}:listing:v1".encode("utf-8")
    ).hexdigest()
    return f"{digest[:32]}.txt"


def target_asset(spec: dict, family: str | None = None) -> str:
    family = family or goal_family(spec)
    if family == "file_write":
        return MARKER_PATH
    if family == "directory_listing":
        return LISTING_DIR
    if family == "server_request":
        return CALLBACK_PATH
    return SECRET_PATH


def auth_env_target(spec: dict) -> dict[str, str]:
    """Environment the target application reads to enforce authentication."""
    material = auth_material(spec)
    if material["scheme"] == "http_basic":
        return {"APP_USER": material["user"], "APP_PASS": material["password"]}
    if material["scheme"] == "bearer_token":
        return {"APP_TOKEN": material["token"]}
    return {}


def auth_env_verifier(spec: dict) -> dict[str, str]:
    """Environment passed to the reference and submitted PoCs."""
    material = auth_material(spec)
    if material["scheme"] == "http_basic":
        return {"TARGET_USER": material["user"], "TARGET_PASSWORD": material["password"]}
    if material["scheme"] == "bearer_token":
        return {"TARGET_TOKEN": material["token"]}
    return {}
