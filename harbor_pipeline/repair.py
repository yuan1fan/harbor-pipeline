"""Tool-using repair agent for task authoring.

The repairer is the author of the vulnerable application, its packaging and the
reference exploit. It gets a real tool loop: it can list and read files, write
them, change the pinned release, change the start command, query public
registries, build both variants, and run the real paired verifier. The fixed
acceptance gates are outside its write scope: the verifier, the instruction,
``task.toml`` and the differential matrix are rendered by the framework on
every run. Giving the author tools instead of a one-shot patch is what makes a
failure observable ("the build log says X", "the server returned 403") rather
than something the model has to guess from a prose error.

Static pre-checks are deliberately absent on this path. The old repairer
rejected legal multi-stage Dockerfiles and dotted Python distributions because
a checker predicted what the build would do. The build and the verifier are the
ground truth; a wrong prediction here only blocks a correct fix.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .budget import Ledger
from .config import Config, ModelSettings
from .errors import TaskError
from .providers import build_provider
from .providers.base import ModelRequest, ModelResponse, ensure_structured
from .util import PipelineError, digest

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 1_000_000
# The reference exploit is an authoring artifact. It is always editable: the
# paired T03+T04 run is the gate that keeps it honest, not a static rule about
# which error category permits touching it.
POC_PATH = "tests/reference_poc.py"
# Framework-owned files. The target entrypoint owns the secret lifecycle and
# the T12 fault switch; the main Dockerfile/compose are thin framework wrappers.
# A task author edits the target application, its Dockerfile, the PoC and the
# launch command instead of reimplementing these.
FRAMEWORK_PATHS = frozenset({
    "environment/target/entrypoint.sh",
    "environment/Dockerfile",
    "environment/docker-compose.yaml",
})
MAX_AGENT_STEPS = 50
MAX_VERIFIER_RUNS = 8
MAX_BUILD_RUNS = 6
MAX_REGISTRY_LOOKUPS = 12
MAX_EXEC_RUNS = 16
MAX_INSPECT_RUNS = 4
MAX_REPLY_ATTEMPTS = 3
# One observation can carry a build log or a verifier trace. Keep it bounded so
# a long agent run does not grow the prompt without limit.
OUTPUT_LIMIT = 12_000
TRANSCRIPT_LIMIT = 60_000

ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["action"],
    "properties": {
        "action": {
            "type": "string",
            "enum": [
                "list_files",
                "read_file",
                "read_bundle",
                "read_spec",
                "write_file",
                "write_files",
                "set_version",
                "set_start_command",
                "set_fixed_override",
                "registry",
                "exec",
                "inspect_package",
                "build",
                "run_verifier",
                "submit",
                "abort",
            ],
        },
        "path": {"type": "string"},
        "content": {"type": "string"},
        "timeout": {"type": "integer", "minimum": 5, "maximum": 180},
        "files": {
            "type": "array",
            "maxItems": 16,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
        "role": {"type": "string", "enum": ["vulnerable", "fixed"]},
        "ref": {"type": "string"},
        "command": {"type": "string"},
        "name": {"type": "string"},
        "ecosystem": {"type": "string"},
        "reason": {"type": "string"},
    },
}

TOOL_SYSTEM = """\
You are the authoring agent for a containerised security-training task. You
repair the vulnerable application, its packaging, and the reference exploit.
You have tools; use them instead of guessing. Return JSON only.

## What you control

You may read and write environment files and the reference exploit
`tests/reference_poc.py`, except for the framework-owned target entrypoint and
the main `environment/Dockerfile` / `environment/docker-compose.yaml`. You may
create new files under `environment/` (for example a missing module or
configuration file). You may change the pinned vulnerable and fixed releases,
the target start command, and per-variant fixed overrides. Use
`set_start_command` for the launch command instead of rewriting the entrypoint.

You cannot edit the instruction, `task.toml`, the verifier under `tests/`, or
the differential matrix. Those are the fixed acceptance gates and are rendered
by the framework on every run. Running them is expected; editing them is not
possible and would not change the verdict.

## Tools

Exactly one action per reply, as a JSON object:

- `{"action":"list_files"}`: paths and sizes of the editable files.
- `{"action":"read_file","path":"environment/target/app.py"}`: full file text.
- `{"action":"read_bundle"}`: the synthesis bundle (root cause, preconditions,
  target files, PoC). Use it to recover the CVE's intended interface.
- `{"action":"read_spec"}`: the frozen CVE spec (versions, assertions, goal).
- `{"action":"write_file","path":"...","content":"..."}`
- `{"action":"write_files","files":[{"path":"...","content":"..."}]}`
- `{"action":"set_version","role":"vulnerable","ref":"1.2.3"}`: change the
  pinned release used for `{{REF}}` substitution. `role` is `vulnerable` or
  `fixed`. Use the registry tool to find a release that exists.
- `{"action":"set_start_command","command":"cd /opt/app && node server.js"}`:
  change how the target process is started.
- `{"action":"set_fixed_override","name":"requirements.txt","content":"..."}`:
  write a file that differs in the fixed variant. The vulnerable variant keeps
  the `environment/target/` version.
- `{"action":"registry","ecosystem":"pypi","name":"onnx"}`: published
  versions. Ecosystems: `pypi`, `npm`, `go`, `maven`.
- `{"action":"exec","command":"node -e \\"console.log(Object.keys(require('pkg')))\\"","timeout":60}`:
  run a bounded command in a throwaway container of the last built vulnerable
  target image (no network). Use it to list a package's real exports, read its
  installed source, or check an import error. It shows the last build, so call
  `build` after changing files.
- `{"action":"inspect_package","name":"@scope/pkg"}`: resolve the installed
  dependency in that same image and print its real path, files, package.json
  and exported symbols. Prefer this over guessing an import path; node_modules
  entries are often symlinks, so use `readlink -f` and `find -L` when you do
  use `exec` yourself.
- `{"action":"build"}`: build both variants and return the build log tail.
- `{"action":"run_verifier"}`: run the real T03+T04 pair. Success requires the
  vulnerable build to reach the goal observable AND the fixed build to hold.
- `{"action":"submit","reason":"..."}`: finalize. If the files changed since
  the last verifier run, this runs the pair again.
- `{"action":"abort","reason":"..."}`: give up without applying changes.

## Rules

- Keep the real vulnerable package at a vulnerable release. Do not vendor it,
  do not reimplement its vulnerable logic, and do not bypass it. The fixed
  variant differs only by the upstream release.
- In target files, write `{{REF}}` where the vulnerable package version is
  pinned. The harness substitutes the vulnerable ref for the vulnerable
  variant and the fixed ref for the fixed variant. A concrete version in a
  target file applies to both variants and will usually make the fixed build
  leak.
- The exploit must obtain the goal observable from the running vulnerable
  server. Never hard-code it, never read it from a local path, and never use an
  intended feature that works on both builds. The observable depends on
  `task_goal.family` read from the bundle:
  - `secret_read`: print the per-instance 48-hex token.
  - `file_write`: choose a fresh 48-hex nonce, make the target write it to the
    marker path through the vulnerability, and print the same nonce. Do not add
    an intended route that writes the marker.
  - `directory_listing`: list the protected directory and print the randomly
    named `.txt` filename, never the file contents.
- If `preconditions.auth_identity` is not `none`, the target must enforce the
  declared scheme on every route except `/health` and `/business`. The
  framework supplies `APP_USER`/`APP_PASS` or `APP_TOKEN` to the target and
  `TARGET_USER`/`TARGET_PASSWORD` or `TARGET_TOKEN` to the PoC. Do not
  hard-code the credential and do not make the protected route work without it.
- The bundle's root cause names the vulnerable code path. Make the application
  call that exact API. A wrapper or helper that throws before reaching it is
  not the vulnerability, even if the route returns an error from it.
- The bundle's product ecosystem is authoritative. If the synthesized target
  uses a different language or a dependency that does not exist, replace it
  with an application that uses the real product package (for example an npm
  package must be exercised from Node, not from an invented Go module).
- The fixed build must not return the observable. For `secret_read`, a
  vulnerable listing is not enough: use the library's own download/get call and
  return its body; do not read the file from disk after the library call.
- Use `registry` before choosing a version. Never invent one. If a lookup
  fails, do not repeat the same name; use the build log and the bundle's
  recorded versions instead.
- Use `build` for packaging failures and `run_verifier` for behaviour. The
  build log tail and the verifier's stdout/stderr are in the observation; do
  not repeat a patch that failed for the same reason.
- When the exploit fails silently, temporarily write a diagnostic PoC that
  prints the URL, HTTP status and the first 200 characters of the response
  (never the token), run the verifier, then restore the exploit.
- The application must keep a health endpoint and the business endpoint the
  framework probes. Do not remove them.
- Spend the budget on observations, not on rewrites: read the failing log
  first, make one focused change, then build or verify.
- The prompt shows the current contents of every editable file. Do not read
  back a file you just wrote; spend the step on build or run_verifier.
"""

# Runtime-specific details are only useful for that runtime. Sending them with
# a Python repair wastes context and can steer the model toward APIs or build
# flags that do not exist there.
GO_SYSTEM = """\
For a Go target, the official ``golang`` image sets ``GOTOOLCHAIN=local``.
If the log says a module "requires go >= X (running go Y)", raise the
``FROM golang:Y...`` tag to X or newer. Do not change GOBIN, GOPATH, or the
module path to work around a toolchain-version error. Keep ``go build`` or
``go install`` at image-build time; never move compilation to container start,
where the module proxy may be unreachable."""

NODE_SYSTEM = """\
For a Node.js target, ``fs`` has no ``dup2``; do not attempt fd-level
redirection. Wrap ``node:child_process``'s ``spawn`` so the child's stdout and
stderr are piped into a per-request buffer, and return that buffer. Import the
CommonJS default (``import childProcess from 'node:child_process'``) and patch
that object: the namespace returned by ``await import()`` is read-only, so
assigning to ``spawn`` throws ``TypeError``. The wrapper must replace the
library's inherited stdio with pipes (for example
``stdio: ['ignore', 'pipe', 'pipe']``) before calling the real ``spawn``;
otherwise ``child.stdout`` and ``child.stderr`` are null and nothing is
captured. Keep the library call itself unchanged: the vulnerable argument
vector must still be constructed by the real package."""


@dataclass
class AuthoringState:
    """The mutable authoring view of one candidate.

    ``spec`` and ``bundle`` are copies while the agent works; the pipeline
    persists them only after a successful verified submit. ``files`` is the
    current editable file set (the prior repair overlay already applied).
    """

    spec: dict[str, Any]
    bundle: dict[str, Any]
    files: dict[str, str]


@dataclass
class RepairTools:
    """Harness tools injected by the pipeline.

    The engine never imports Docker, the network or the task renderer. The
    callables receive an :class:`AuthoringState` and return JSON-like evidence.
    """

    build: Callable[[AuthoringState], dict[str, Any]] | None = None
    debug: Callable[[AuthoringState], dict[str, Any]] | None = None
    registry: Callable[[str, str], dict[str, Any]] | None = None
    # Run a bounded command inside the last built vulnerable target image.
    exec_image: Callable[[AuthoringState, str, int], dict[str, Any]] | None = None
    # Resolve the installed package and print its real exports/files.
    inspect_package: Callable[[AuthoringState, str], dict[str, Any]] | None = None
    # Live audit hook: the pipeline appends each step to repair-trace.jsonl so
    # a long agent run is observable before it finishes.
    on_step: Callable[[dict[str, Any]], None] | None = None


# Backwards-compatible shorthand: old callers passed a callable that took the
# file map. It is wrapped below so the agent always sees the full state.
DebugRunner = Callable[[dict[str, str]], dict[str, Any]]


@dataclass
class RepairResult:
    files: dict[str, str]
    reason: str
    model_identity: str
    usage: dict[str, Any]
    error: str | None = None
    debug_rounds: int = 0
    debug_evidence: list[dict[str, Any]] = field(default_factory=list)
    spec: dict[str, Any] | None = None
    bundle: dict[str, Any] | None = None
    spec_changed: bool = False
    bundle_changed: bool = False
    trace: list[dict[str, Any]] = field(default_factory=list)


class RepairEngine:
    def __init__(self, config: Config, ledger: Ledger, *, role: str = "repairer"):
        self.config = config
        self.ledger = ledger
        self.role = role
        self.settings: ModelSettings = config.model_for(role)
        self.provider = build_provider(config, role)

    @property
    def identity(self) -> str:
        return getattr(self.provider, "name", "unknown")

    def repair(
        self,
        *,
        cve_id: str,
        revision: int,
        error: TaskError,
        files: dict[str, str],
        spec: dict[str, Any] | None = None,
        bundle: dict[str, Any] | None = None,
        previous: dict[str, str] | None = None,
        reference: str | None = None,
        pinned_ref: str | None = None,
        debug: DebugRunner | None = None,
        context: str | None = None,
        tools: RepairTools | None = None,
    ) -> RepairResult:
        """Run the authoring agent until it verifies a state or exhausts a budget.

        ``debug`` is kept as a shorthand for a pipeline that only has the
        verifier tool. ``tools`` is the full agent tool set. ``files`` is the
        current rendered task file set (editable files plus read-only files).
        """
        if tools is None:
            tools = RepairTools(
                debug=(lambda state: debug(state.files)) if debug else None
            )
        editable = {
            name: body
            for name, body in files.items()
            if _editable(name)
        }
        read_only = {
            name: body for name, body in files.items() if name not in editable
        }
        current = dict(editable)
        for name, body in (previous or {}).items():
            if _editable(name) and isinstance(body, str):
                current[name] = body
        original = dict(current)
        spec_state = copy.deepcopy(spec or {})
        bundle_state = copy.deepcopy(bundle or {})
        original_spec = copy.deepcopy(spec_state)
        original_bundle = copy.deepcopy(bundle_state)
        system = _system(editable)
        total = {"input_tokens": 0, "output_tokens": 0}
        total_usd: float | None = None
        identity = "unavailable"
        trace: list[dict[str, Any]] = []
        observations: list[str] = []
        verifier_runs = 0
        build_runs = 0
        registry_lookups = 0
        exec_runs = 0
        inspect_runs = 0
        registry_cache: dict[tuple[str, str], dict[str, Any]] = {}
        registry_failures: dict[tuple[str, str], int] = {}
        last_read: dict[str, str] = {}
        verified: tuple[str, dict[str, Any]] | None = None
        last_verifier: dict[str, Any] | None = None
        last_reason = ""
        last_error: str | None = None

        def state() -> AuthoringState:
            return AuthoringState(
                spec=spec_state, bundle=bundle_state, files=dict(current)
            )

        def done(reason: str, *, verified_pass: bool = False) -> RepairResult:
            apply = verified_pass or tools.debug is None
            patch = {
                name: body
                for name, body in current.items()
                if body != original.get(name)
            }
            spec_changed = spec_state != original_spec
            bundle_changed = bundle_state != original_bundle
            return RepairResult(
                files=patch if apply else {},
                reason=reason[:2000],
                model_identity=identity,
                usage=_usage_total(total, total_usd),
                error=None if apply else last_error,
                debug_rounds=verifier_runs,
                debug_evidence=[last_verifier] if last_verifier else [],
                spec=spec_state if spec_changed and apply else None,
                bundle=bundle_state if bundle_changed and apply else None,
                spec_changed=spec_changed and apply,
                bundle_changed=bundle_changed and apply,
                trace=trace,
            )

        for step in range(MAX_AGENT_STEPS):
            scan = _readback_scan(current, bundle_state)
            prompt = self._agent_prompt(
                error=error,
                current=current,
                read_only=read_only,
                spec=spec_state,
                bundle=bundle_state,
                observations=observations,
                context="\n\n".join(part for part in (context, scan) if part),
                limits={
                    "steps": MAX_AGENT_STEPS - step,
                    "verifier": MAX_VERIFIER_RUNS - verifier_runs,
                    "build": MAX_BUILD_RUNS - build_runs,
                    "registry": MAX_REGISTRY_LOOKUPS - registry_lookups,
                    "exec": MAX_EXEC_RUNS - exec_runs,
                    "inspect": MAX_INSPECT_RUNS - inspect_runs,
                },
                pinned_ref=pinned_ref,
            )
            try:
                body, usage, identity = self._ask(
                    system=system,
                    prompt=prompt,
                    reservation=(
                        f"{cve_id}-repair-{revision}-{step}"
                    ),
                    metadata={"cve_id": cve_id, "revision": revision, "step": step},
                )
            except PipelineError as exc:
                last_error = str(exc)
                return RepairResult(
                    {}, "", identity, _usage_total(total, total_usd),
                    error=last_error, debug_rounds=verifier_runs,
                    debug_evidence=[last_verifier] if last_verifier else [],
                    trace=trace,
                )
            except Exception as exc:  # noqa: BLE001 - provider fault
                return RepairResult(
                    {}, "", identity, _usage_total(total, total_usd),
                    error=str(exc), debug_rounds=verifier_runs,
                    debug_evidence=[last_verifier] if last_verifier else [],
                    trace=trace,
                )
            for key in total:
                total[key] += int(usage.get(key, 0) or 0)
            if isinstance(usage.get("usd"), (int, float)):
                total_usd = (total_usd or 0.0) + float(usage["usd"])

            legacy_reply = isinstance(body, dict) and "action" not in body
            action, problem = _parse_action(body)
            if problem:
                observation = f"Invalid action: {problem}. Reply with one JSON object as described."
                observations.append(_clip(observation))
                trace.append({"step": step, "action": "invalid", "ok": False,
                              "observation": _clip(observation, 1500)})
                _emit(tools, trace[-1])
                continue

            kind = action["action"]
            last_reason = str(action.get("reason") or "")[:2000]
            observation = ""
            ok = True
            if kind == "list_files":
                observation = _list_files(current, read_only)
            elif kind == "read_file":
                path = str(action.get("path") or "")
                observation = _read_file(path, current, read_only)
            elif kind == "read_bundle":
                current_digest = digest(bundle_state)
                if last_read.get("bundle") == current_digest:
                    observation = (
                        "The bundle is unchanged since your last read. Use the "
                        "earlier output or read_file for a specific target file."
                    )
                else:
                    last_read["bundle"] = current_digest
                    observation = _clip(json.dumps(bundle_state, indent=1), 60_000)
            elif kind == "read_spec":
                current_digest = digest(spec_state)
                if last_read.get("spec") == current_digest:
                    observation = (
                        "The spec is unchanged since your last read. Use the "
                        "earlier output."
                    )
                else:
                    last_read["spec"] = current_digest
                    observation = _clip(json.dumps(spec_state, indent=1), 60_000)
            elif kind in {"write_file", "write_files"}:
                changed, observation = _apply_writes(action, current, files)
                ok = bool(changed)
                if legacy_reply and not changed:
                    # The old one-shot protocol signalled "nothing to change"
                    # with an empty patch. Keep it a clean no-op instead of
                    # spending the whole step budget on the same reply.
                    return done("no change proposed", verified_pass=False)
            elif kind == "set_version":
                observation = _set_version(action, spec_state, bundle_state)
            elif kind == "set_start_command":
                observation = _set_start_command(action, bundle_state)
            elif kind == "set_fixed_override":
                observation = _set_fixed_override(action, bundle_state)
            elif kind == "registry":
                if registry_lookups >= MAX_REGISTRY_LOOKUPS:
                    observation = "Registry lookup budget is exhausted."
                    ok = False
                elif tools.registry is None:
                    observation = "The registry tool is unavailable."
                    ok = False
                else:
                    ecosystem = str(action.get("ecosystem") or "")
                    name = str(action.get("name") or "")
                    key = (ecosystem, name)
                    cached = registry_cache.get(key)
                    if cached is not None and "versions" in cached:
                        observation = _registry_observation(cached, ecosystem, name)
                    elif registry_failures.get(key, 0) >= 3:
                        observation = (
                            f"Registry lookup for {ecosystem} `{name}` already "
                            "failed three times; do not retry it. Use the build "
                            "log or the bundle's recorded versions."
                        )
                    else:
                        registry_lookups += 1
                        try:
                            result = tools.registry(ecosystem, name)
                        except Exception as exc:  # noqa: BLE001 - tool fault
                            result = {"error": str(exc)[:300]}
                            ok = False
                        if "error" in result:
                            registry_failures[key] = registry_failures.get(key, 0) + 1
                            registry_cache[key] = result
                            observation = _registry_observation(result, ecosystem, name)
                            observation += (
                                " The public registry can fail transiently; you "
                                "may retry this name, but after three failures "
                                "use the build log or the bundle's versions."
                            )
                        else:
                            registry_cache[key] = result
                            observation = _registry_observation(result, ecosystem, name)
            elif kind == "exec":
                if exec_runs >= MAX_EXEC_RUNS:
                    observation = "Exec budget is exhausted. Use run_verifier or submit."
                    ok = False
                elif tools.exec_image is None:
                    observation = "The exec tool is unavailable."
                    ok = False
                else:
                    command = str(action.get("command") or "")
                    if not command.strip():
                        observation = "`command` must be a non-empty string."
                        ok = False
                    else:
                        try:
                            timeout = int(action.get("timeout") or 60)
                        except (TypeError, ValueError):
                            timeout = 60
                        timeout = max(5, min(timeout, 180))
                        try:
                            result = tools.exec_image(state(), command, timeout)
                            if not result.get("no_image"):
                                # A missing build is a usage hint, not a spent
                                # inspection: do not charge the budget for it.
                                exec_runs += 1
                            observation = (
                                f"exit={result.get('exit')}\n"
                                + str(result.get("output") or "")[-8000:]
                            )
                            if result.get("note"):
                                observation += "\n" + str(result["note"])
                            ok = result.get("exit") == 0
                        except Exception as exc:  # noqa: BLE001 - tool fault
                            observation = f"Exec tool failed: {exc}"
                            ok = False
            elif kind == "inspect_package":
                if inspect_runs >= MAX_INSPECT_RUNS:
                    observation = "Package inspection budget is exhausted."
                    ok = False
                elif tools.inspect_package is None:
                    observation = "The package inspection tool is unavailable."
                    ok = False
                else:
                    name = str(action.get("name") or "").strip()
                    if not name:
                        observation = "`name` must be a package name."
                        ok = False
                    else:
                        try:
                            result = tools.inspect_package(state(), name)
                            if not result.get("no_image"):
                                inspect_runs += 1
                            observation = (
                                f"exit={result.get('exit')}\n"
                                + str(result.get("output") or "")[-10000:]
                            )
                            if result.get("note"):
                                observation += "\n" + str(result["note"])
                            ok = result.get("exit") == 0
                        except Exception as exc:  # noqa: BLE001 - tool fault
                            observation = f"Package inspection failed: {exc}"
                            ok = False
            elif kind == "build":
                if build_runs >= MAX_BUILD_RUNS:
                    observation = "Build budget is exhausted. Use run_verifier or submit."
                    ok = False
                elif tools.build is None:
                    observation = "The build tool is unavailable."
                    ok = False
                else:
                    build_runs += 1
                    try:
                        observation = _build_observation(tools.build(state()))
                    except Exception as exc:  # noqa: BLE001 - tool fault
                        observation = f"Build tool failed: {exc}"
                        ok = False
            elif kind == "run_verifier":
                if verifier_runs >= MAX_VERIFIER_RUNS:
                    observation = (
                        "Verifier budget is exhausted. Submit the current state "
                        "or abort."
                    )
                    ok = False
                elif tools.debug is None:
                    observation = (
                        "No verifier tool is configured. Submit to apply the patch."
                    )
                    ok = False
                else:
                    verifier_runs += 1
                    try:
                        last_verifier = tools.debug(state())
                        verified = (_state_digest(spec_state, bundle_state, current),
                                    last_verifier)
                        observation = _verifier_observation(last_verifier)
                        ok = bool(last_verifier.get("ok"))
                    except Exception as exc:  # noqa: BLE001 - infra, not a verdict
                        observation = f"Verifier tool failed: {exc}"
                        ok = False
            elif kind == "submit":
                if tools.debug is None:
                    return done(last_reason or "submitted without a verifier",
                                verified_pass=True)
                current_digest = _state_digest(spec_state, bundle_state, current)
                if verified is not None and verified[0] == current_digest:
                    evidence = verified[1]
                elif verifier_runs >= MAX_VERIFIER_RUNS:
                    observation = (
                        "Verifier budget is exhausted and the current files are "
                        "unverified. Abort or revert to the last verified state."
                    )
                    ok = False
                    evidence = None
                else:
                    verifier_runs += 1
                    try:
                        evidence = tools.debug(state())
                    except Exception as exc:  # noqa: BLE001 - infra, not a verdict
                        observation = f"Verifier tool failed: {exc}"
                        ok = False
                        evidence = None
                    if evidence is not None:
                        last_verifier = evidence
                        verified = (current_digest, evidence)
                if evidence is not None:
                    if _debug_passed(evidence):
                        return done(last_reason or "verified by the paired matrix",
                                    verified_pass=True)
                    observation = "submit failed.\n" + _verifier_observation(evidence)
                    ok = False
            elif kind == "abort":
                last_error = "agent aborted without a verified state"
                return done(last_reason or "agent aborted", verified_pass=False)
            else:
                observation = f"Unknown action {kind!r}."
                ok = False

            observations.append(f"[{kind}] {_clip(observation)}")
            trace.append({
                "step": step,
                "action": kind,
                "ok": ok,
                "observation": _clip(observation, 2000),
            })
            _emit(tools, trace[-1])
            # A verified state that is still current is a success even if the
            # agent runs out of steps before calling submit.
            if (
                verified is not None
                and verified[0] == _state_digest(spec_state, bundle_state, current)
                and _debug_passed(verified[1])
            ):
                return done(last_reason or "verified by the paired matrix",
                            verified_pass=True)

        last_error = "repair agent exhausted its step budget without a verified state"
        return done(last_reason or "step budget exhausted", verified_pass=False)

    def _ask(
        self,
        *,
        system: str,
        prompt: str,
        reservation: str,
        metadata: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Ask for one action, retrying a malformed reply a few times."""
        feedback = ""
        last_error = "Repair produced no usable reply"
        spent = {"input_tokens": 0, "output_tokens": 0}
        spent_usd = 0.0
        for attempt in range(1, MAX_REPLY_ATTEMPTS + 1):
            estimated = (
                max(1, len(prompt + feedback) // 4)
                + self.settings.max_output_tokens
            )
            key = f"{reservation}-{attempt}"
            try:
                self.ledger.reserve(key, {"calls": 1, "tokens": estimated})
            except PipelineError as exc:
                raise TaskError("budget_exhausted", str(exc)) from exc
            try:
                response = self.provider.generate(
                    ModelRequest(
                        role=self.role,
                        system=system,
                        prompt=prompt + feedback,
                        schema=ACTION_SCHEMA,
                        max_output_tokens=self.settings.max_output_tokens,
                        metadata={**metadata, "attempt": attempt},
                    )
                )
            except PipelineError as exc:
                self.ledger.refund(key)
                last_error = str(exc)
                feedback = (
                    "\n\nYour previous reply was not a usable JSON action: "
                    f"{last_error}\nReturn exactly one JSON object with an "
                    "`action` field."
                )
                continue
            except Exception:
                self.ledger.refund(key)
                raise
            usage = _usage(response)
            self.ledger.commit(key, {
                "calls": 1,
                "tokens": usage.get("input_tokens", 0)
                + usage.get("output_tokens", 0),
                **({"usd": float(usage["usd"])}
                   if isinstance(usage.get("usd"), (int, float)) else {}),
            })
            for name in spent:
                spent[name] += int(usage.get(name, 0) or 0)
            if isinstance(usage.get("usd"), (int, float)):
                spent_usd += float(usage["usd"])
            try:
                body = ensure_structured(response)
            except PipelineError as exc:
                last_error = str(exc)
                feedback = (
                    "\n\nYour previous reply was not structured JSON: "
                    f"{last_error}\nReturn exactly one JSON object with an "
                    "`action` field."
                )
                continue
            total_usage = dict(spent)
            if spent_usd:
                total_usage["usd"] = spent_usd
            return body, total_usage, response.model_identity
        raise PipelineError(last_error)

    def _agent_prompt(
        self,
        *,
        error: TaskError,
        current: dict[str, str],
        read_only: dict[str, str],
        spec: dict[str, Any],
        bundle: dict[str, Any],
        observations: list[str],
        context: str | None,
        limits: dict[str, int],
        pinned_ref: str | None,
    ) -> str:
        chunks = [
            f"The task failed with {error.category.code}: {error}",
        ]
        summary = _authoring_summary(spec, bundle)
        if summary:
            chunks.append(summary)
        if pinned_ref:
            chunks.append(
                f"The synthesis pinned vulnerable ref {pinned_ref!r}. Keep a "
                "vulnerable release; use set_version if the pinned release is "
                "not published."
            )
        chunks.append(
            "## Editable files (current contents)\n"
            "A write whose text already matches the file is rejected as a "
            "no-op; do not repeat it. Read the file or make a different change."
        )
        budget = max(4000, self.config.pipeline.max_context_bytes)
        used = 0
        for name, body in sorted(current.items()):
            block = f"--- {name} ---\n{body}\n"
            if used + len(block) > budget:
                chunks.append(
                    f"... ({len(current) - len(chunks)} more files omitted; "
                    "use read_file)"
                )
                break
            chunks.append(block)
            used += len(block)
        if read_only:
            chunks.append("## Read-only task files")
            for name, body in sorted(read_only.items()):
                chunks.append(f"--- {name} ---\n{_clip(body, 12_000)}\n")
        if context:
            chunks.append("## Harness context")
            chunks.append(_clip(context, 12_000))
        if observations:
            chunks.append("## Tool transcript (most recent last)")
            transcript: list[str] = []
            used = 0
            for line in reversed(observations):
                if used + len(line) > TRANSCRIPT_LIMIT:
                    transcript.append("... (earlier observations omitted)")
                    break
                transcript.append(line)
                used += len(line)
            chunks.extend(reversed(transcript))
        chunks.append(
            "## Budget remaining\n"
            f"steps={limits['steps']} verifier_runs={limits['verifier']} "
            f"builds={limits['build']} registry_lookups={limits['registry']}"
        )
        chunks.append(
            "Choose exactly one action. Use `build` for packaging failures and "
            "`run_verifier` for behaviour; `submit` when the pair passes."
        )
        return "\n\n".join(chunks)


def _editable(name: str) -> bool:
    if name in FRAMEWORK_PATHS:
        return False
    if name == POC_PATH:
        return True
    if not name.startswith("environment/"):
        return False
    return len(name) > len("environment/")


def _allowed_write(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return False
    if name.startswith("/") or "\\" in name:
        return False
    if ".." in name.split("/") or "." in name.split("/"):
        return False
    return _editable(name)


def _system(files: dict[str, str]) -> str:
    """Add runtime-specific guidance only when the editable set needs it."""
    chunks = [TOOL_SYSTEM]
    if any(name.endswith((".go", "go.mod")) for name in files):
        chunks.append(GO_SYSTEM)
    if any(
        name.endswith((".js", ".mjs", ".cjs")) or name.endswith("package.json")
        for name in files
    ):
        chunks.append(NODE_SYSTEM)
    return "\n\n".join(chunks)


def _parse_action(body: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    if not isinstance(body, dict):
        return {}, "reply is not a JSON object"
    if "action" not in body:
        # A completion model occasionally falls back to the old patch shape.
        if isinstance(body.get("files"), (list, dict)):
            return {"action": "write_files", "files": body["files"],
                    "reason": body.get("reason", "")}, None
        return {}, "reply has no `action` field"
    action = body.get("action")
    if not isinstance(action, str):
        return {}, "`action` must be a string"
    return body, None


def _list_files(
    current: dict[str, str], read_only: dict[str, str]
) -> str:
    lines = ["Editable files:"]
    for name, body in sorted(current.items()):
        lines.append(f"- {name} ({len(body.encode('utf-8'))} bytes)")
    if read_only:
        lines.append("Read-only files:")
        for name, body in sorted(read_only.items()):
            lines.append(f"- {name} ({len(body.encode('utf-8'))} bytes)")
    return "\n".join(lines)


def _read_file(
    path: str, current: dict[str, str], read_only: dict[str, str]
) -> str:
    if path in current:
        return _clip(current[path])
    if path in read_only:
        return _clip(read_only[path])
    return f"No such file {path!r}. Call list_files to see available paths."


def _apply_writes(
    action: dict[str, Any],
    current: dict[str, str],
    files: dict[str, str],
) -> tuple[list[str], str]:
    if action["action"] == "write_file":
        entries = [{"path": action.get("path"), "content": action.get("content")}]
    else:
        raw = action.get("files")
        if isinstance(raw, dict):
            entries = [
                {"path": name, "content": body}
                for name, body in raw.items()
            ]
        elif isinstance(raw, list):
            entries = raw
        else:
            return [], "`files` must be an array of {path, content} objects."
    changed: list[str] = []
    total = sum(len(body.encode("utf-8")) for body in current.values())
    for entry in entries:
        if not isinstance(entry, dict):
            return changed, "Each file entry must be an object."
        path = entry.get("path")
        content = entry.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            return changed, "Each file entry needs a string path and content."
        if not _allowed_write(path):
            return changed, (
                f"Refusing to write {path!r}: only environment/ files and "
                f"{POC_PATH} are editable."
            )
        size = len(content.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            return changed, f"{path} exceeds {MAX_FILE_BYTES} bytes."
        old = current.get(path)
        if old is not None:
            total -= len(old.encode("utf-8"))
        total += size
        if total > MAX_TOTAL_BYTES:
            return changed, "The editable files exceed the total size limit."
        if old != content:
            current[path] = content
            changed.append(path)
    if not changed:
        names = ", ".join(
            str(entry.get("path")) for entry in entries if isinstance(entry, dict)
        )
        return [], (
            f"No change to {names}: the current files already contain exactly "
            "that text. Do not repeat this action; inspect the file or make a "
            "different change."
        )
    return changed, "Updated: " + ", ".join(changed)


_READBACK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("node", re.compile(
        r"\b(?:fs\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync)"
        r"|res\.sendFile)\b"
    )),
    ("python", re.compile(
        r"(?:\bopen\s*\(|\bPath\([^)]*\)\.read_text\s*\(|\bsend_file\s*\()"
    )),
    ("go", re.compile(
        r"\b(?:os\.ReadFile|ioutil\.ReadFile|http\.ServeFile|os\.ReadDir)\b"
    )),
    ("java", re.compile(
        r"\b(?:Files\.readAllBytes|new\s+FileInputStream|Files\.list)\b"
    )),
)


def _readback_scan(files: dict[str, str], bundle: dict[str, Any]) -> str:
    """Point the author at direct reads that can survive the fixed build.

    A handler that assembles a path from the request and reads it itself still
    works after the upstream patch, so T04 sees a leak. This is a pointer for
    the author, not a gate: the paired verifier remains the verdict.
    """
    product = str((bundle.get("product") or {}).get("name") or "").strip()
    hits: list[str] = []
    for name, body in sorted(files.items()):
        if not name.startswith("environment/target/"):
            continue
        lowered = body.lower()
        if product and product.lower() not in lowered:
            continue
        for language, pattern in _READBACK_PATTERNS:
            for match in pattern.finditer(body):
                line = body.count("\n", 0, match.start()) + 1
                hits.append(f"{name}:{line}: {match.group(0)} ({language})")
    if not hits:
        return (
            "## Static read-back scan\n"
            "No direct file-read call was found in a file that also references "
            "the product package."
        )
    return (
        "## Static read-back scan\n"
        "These direct reads sit in the same file as the product import. If a "
        "handler returns content read this way, the fixed build may still "
        "leak and T04 will fail. Route the observable through the library call "
        "only:\n- " + "\n- ".join(hits[:20])
    )


def _version_tuple(value: str) -> tuple[int, ...] | None:
    text = str(value or "").strip().lstrip("v")
    if not text or not text[0].isdigit():
        return None
    parts = []
    for chunk in re.split(r"[.+-]", text):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts) if parts else None


def _set_version(
    action: dict[str, Any], spec: dict[str, Any], bundle: dict[str, Any]
) -> str:
    role = str(action.get("role") or "")
    ref = action.get("ref")
    if role not in {"vulnerable", "fixed"}:
        return "`role` must be `vulnerable` or `fixed`."
    if not isinstance(ref, str) or not ref.strip() or "\n" in ref:
        return "`ref` must be a non-empty single-line string."
    versions = spec.setdefault("versions", {})
    if not isinstance(versions, dict):
        return "The spec has no versions object; cannot set a release."
    key = f"{role}_ref"
    ref = ref.strip()
    other = versions.get("fixed_ref" if role == "vulnerable" else "vulnerable_ref")
    if role == "vulnerable" and other and ref == str(other):
        return "The vulnerable ref must differ from the fixed ref."
    if role == "vulnerable":
        # The new release must still be inside the recorded affected range.
        affected = str((bundle.get("versions") or {}).get("affected") or "").strip()
        if affected and affected[0] in "><=~!":
            try:
                from packaging.specifiers import SpecifierSet
                from packaging.version import Version

                if not SpecifierSet(affected).contains(Version(ref.lstrip("v"))):
                    return (
                        f"{ref!r} is outside the recorded affected range "
                        f"{affected!r}. Choose an affected release, or keep the "
                        "current pair."
                    )
            except Exception:  # noqa: BLE001 - non-PEP 440 ranges are advisory
                pass
    current = versions.get(key)
    if current and other:
        low, high = (
            (ref, other) if role == "vulnerable" else (other, ref)
        )
        low_tuple, high_tuple = _version_tuple(low), _version_tuple(high)
        if low_tuple and high_tuple and low_tuple >= high_tuple:
            return (
                f"{low!r} must be older than {high!r} "
                "(vulnerable < fixed)."
            )
    bundle_versions = bundle.setdefault("versions", {})
    if versions.get(key) == ref and (
        not isinstance(bundle_versions, dict)
        or bundle_versions.get(key) == ref
    ):
        return (
            f"No change: {key} is already {ref!r}. If the build still fails, "
            "query the registry and choose a different published release."
        )
    versions[key] = ref
    if isinstance(bundle_versions, dict):
        bundle_versions[key] = ref
    return (
        f"Set {role}_ref to {ref.strip()!r}. Target files that use {{{{REF}}}} "
        "will now substitute this release; build or verify to check it."
    )


def _set_start_command(action: dict[str, Any], bundle: dict[str, Any]) -> str:
    command = action.get("command")
    if not isinstance(command, str) or not command.strip():
        return "`command` must be a non-empty string."
    if "\n" in command or len(command) > 2000:
        return "`command` must be a single line of at most 2000 characters."
    target = bundle.setdefault("target", {})
    if not isinstance(target, dict):
        return "The bundle has no target object; cannot set a start command."
    command = command.strip()
    if target.get("start_command") == command:
        return f"No change: target.start_command is already {command!r}."
    target["start_command"] = command
    return f"Set target.start_command to {command!r}."


def _set_fixed_override(action: dict[str, Any], bundle: dict[str, Any]) -> str:
    name = action.get("name")
    content = action.get("content")
    if not isinstance(name, str) or not name or not _allowed_write(
        f"environment/target/{name}"
    ):
        return "`name` must be a relative target file name."
    if not isinstance(content, str):
        return "`content` must be a string."
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        return f"Fixed override for {name} exceeds {MAX_FILE_BYTES} bytes."
    target = bundle.setdefault("target", {})
    if not isinstance(target, dict):
        return "The bundle has no target object; cannot set an override."
    overrides = target.setdefault("fixed_overrides", {})
    if not isinstance(overrides, dict):
        return "target.fixed_overrides is not an object."
    if overrides.get(name) == content:
        return (
            f"No change: the fixed-only override for {name} already has that "
            "content. Do not repeat it."
        )
    overrides[name] = content
    return f"Set a fixed-only override for {name}."


def _registry_observation(
    result: dict[str, Any], ecosystem: str = "", name: str = ""
) -> str:
    if "error" in result:
        text = f"Registry lookup failed: {result['error']}"
        if ecosystem == "go" and any(
            segment in name for segment in ("/src/", "/lib/", "/internal/")
        ):
            text += (
                " For Go, query the module path from the go.mod require line "
                "(for example github.com/owner/repo), not a package "
                "subdirectory."
            )
        return text
    versions = list(result.get("versions") or [])
    return (
        f"{result.get('total', len(versions))} published versions; newest: "
        + ", ".join(str(version) for version in versions[:30])
    )


def _build_observation(result: dict[str, Any]) -> str:
    lines = [f"build_ok={bool(result.get('ok'))}",
             f"status={result.get('status', 'unknown')}"]
    if result.get("error"):
        lines.append(f"error={str(result['error'])[-4000:]}")
    if result.get("log_tail"):
        lines.append("log_tail:\n" + str(result["log_tail"])[-8000:])
    return "\n".join(lines)


def _verifier_observation(evidence: dict[str, Any]) -> str:
    lines = [
        f"vulnerable_status={evidence.get('status', 'unknown')}",
        f"reference_exit={evidence.get('reference_exit')}",
        f"reference_stderr={str(evidence.get('reference_error') or '')[-1200:]!r}",
        f"reference_stdout={str(evidence.get('reference_stdout') or '')[-1200:]!r}",
        f"submitted_exit={evidence.get('submitted_exit')}",
        f"submitted_observed={evidence.get('submitted_observed')}",
        f"marker_present={evidence.get('marker_present')}",
        f"marker_matches_reference={evidence.get('marker_matches_reference')}",
        f"fixed_status={evidence.get('fixed_status')}",
        f"fixed_health_ok={evidence.get('fixed_health_ok')}",
        f"fixed_reference_stderr={str(evidence.get('fixed_reference_error') or '')[-600:]!r}",
    ]
    if evidence.get("error"):
        lines.append(f"error={str(evidence['error'])[-4000:]}")
    if evidence.get("log_tail"):
        lines.append("log_tail:\n" + str(evidence["log_tail"])[-8000:])
    if evidence.get("target_log"):
        lines.append(f"target_log={str(evidence['target_log'])[-800:]!r}")
    if _debug_passed(evidence):
        lines.append(
            "PAIR PASSED: vulnerable reached the goal observable and the fixed build holds."
        )
    else:
        lines.append(
            "PAIR FAILED: success requires goal_passed on the vulnerable build "
            "AND fixed_variant_holds on the fixed build."
        )
    return "\n".join(lines)


def _authoring_summary(spec: dict[str, Any], bundle: dict[str, Any]) -> str:
    """The CVE semantics the author needs, without dumping the whole bundle."""
    parts: list[str] = []
    if spec:
        parts.append("## Frozen spec (read-only summary)")
        parts.append(json.dumps({
            key: spec.get(key)
            for key in (
                "cve_id", "product", "versions", "fix_basis",
                "attribution_grade", "task_goal",
            )
            if key in spec
        }, indent=1)[:12_000])
    if bundle:
        target = bundle.get("target") or {}
        parts.append("## Synthesis bundle (authoring summary)")
        summary = {
            "product": bundle.get("product"),
            "versions": bundle.get("versions"),
            "preconditions": bundle.get("preconditions"),
            "root_cause": bundle.get("root_cause"),
            "impact": bundle.get("impact"),
            "task_goal": bundle.get("task_goal"),
            "fix_basis": bundle.get("fix_basis"),
            "assertions": bundle.get("assertions"),
            "target": {
                "port": target.get("port"),
                "start_command": target.get("start_command"),
                "files": sorted((target.get("files") or {}).keys()),
                "fixed_overrides": sorted(
                    (target.get("fixed_overrides") or {}).keys()
                ),
            },
            "poc_files": sorted((bundle.get("poc") or {}).keys()),
        }
        parts.append(_clip(json.dumps(summary, indent=1), 24_000))
        parts.append(
            "Use `read_bundle` for the complete bundle and `read_spec` for the "
            "complete frozen spec."
        )
    return "\n\n".join(parts)


def _state_digest(
    spec: dict[str, Any], bundle: dict[str, Any], files: dict[str, str]
) -> str:
    return digest({"spec": spec, "bundle": bundle, "files": files})


def _emit(tools: RepairTools, entry: dict[str, Any]) -> None:
    if tools.on_step is None:
        return
    try:
        tools.on_step(dict(entry))
    except Exception:  # noqa: BLE001 - observability must not break a repair
        pass


def _clip(text: str, limit: int = OUTPUT_LIMIT) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... ({len(text) - limit} characters truncated)"


def _usage(response: ModelResponse) -> dict[str, Any]:
    usage = dict(response.usage or {})
    usage.setdefault("input_tokens", 0)
    usage.setdefault("output_tokens", 0)
    return usage


def _usage_total(total: dict[str, Any], total_usd: float | None) -> dict[str, Any]:
    usage = dict(total)
    if total_usd is not None:
        usage["usd"] = total_usd
    return usage


def _debug_passed(evidence: dict[str, Any]) -> bool:
    """Success means T03 passes and the fixed build still holds."""
    status = str(evidence.get("status"))
    fixed = evidence.get("fixed_status")
    if fixed is None:
        return status == "goal_passed"
    return (
        status == "goal_passed"
        and str(fixed) == "fixed_variant_holds"
        and bool(evidence.get("fixed_health_ok", True))
    )


def repair_log_entry(
    *,
    attempt: int,
    result: RepairResult,
    error: TaskError,
    files_before: dict[str, str],
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "error_category": error.category.code,
        "error_message": str(error),
        "model": result.model_identity,
        "reason": result.reason,
        "changed": sorted(result.files),
        "digests": {
            name: digest(body) for name, body in sorted(result.files.items())
        },
        "usage": result.usage,
        "failure": result.error,
        "files_before": sorted(files_before),
        "debug_rounds": result.debug_rounds,
        "debug_evidence": result.debug_evidence,
        # The authoring agent may change the pinned release or the start
        # command; keep the audit trail even when no file was rewritten.
        "spec_changed": result.spec_changed,
        "bundle_changed": result.bundle_changed,
        "spec_digest": digest(result.spec) if result.spec else None,
        "bundle_digest": digest(result.bundle) if result.bundle else None,
        "trace": result.trace[-40:],
    }
