"""Native Claude Code authoring sessions.

The draft and repair stages used to call a completion endpoint with one
message at a time. That protocol cannot read an evidence file, build an image
or run a PoC, and re-sending every file on every step made a bad draft
expensive to repair. This module runs the real Claude Code harness instead:
native Read/Write/Edit/Grep/Glob/Bash tools, native context management, and a
permission allowlist that leaves the fixed acceptance gates outside the
session.

The runner is deliberately small. It owns process lifecycle, the scrubbed
environment, the stream-json transcript and the result accounting. It never
decides whether a task is good: the helper in ``author_tool`` and the fixed
differential matrix do that.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .config import Config, ModelSettings
from .util import PipelineError, hidden_console_kwargs

# The CLI must not inherit the parent session's identity or the pipeline's
# source credentials. Keep only the OS essentials and the model gateway.
_KEEP_ENV = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "SystemRoot",
    "SYSTEMROOT",
    "SystemDrive",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "PROGRAMDATA",
    "ProgramData",
    "APPDATA",
    "LOCALAPPDATA",
    # Docker Desktop discovers its CLI plugins (docker compose, buildx) under
    # these directories. Scrubbing them makes `docker compose` fall back to
    # the bare CLI and fail with "unknown shorthand flag".
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
}
_DROP_PREFIXES = ("CLAUDE_CODE_", "CLAUDECODE", "CLAUDE_PID", "AWS_", "DEEPSEEK_")
_DROP_NAMES = {
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NVD_API_KEY",
    "ANTHROPIC_MODEL",
}

AUTHOR_TOOLS = "Read,Write,Edit,Grep,Glob,Bash"
AUTHOR_ALLOWED_TOOLS = (
    "Read,Write,Edit,Grep,Glob,"
    "Bash(harbor-author:*),Bash(./bin/harbor-author:*),Bash(bash bin/harbor-author:*)"
)
RESOLVER_TOOLS = "Read,Write,Edit,Grep,Glob,Bash"
RESOLVER_ALLOWED_TOOLS = (
    "Read,Write,Edit,Grep,Glob,"
    "Bash(harbor-evidence:*),Bash(./bin/harbor-evidence:*),"
    "Bash(bash bin/harbor-evidence:*)"
)

# Backward-compatible names used by the authoring path and its tests.
TOOL_LIST = AUTHOR_TOOLS
ALLOWED_TOOLS = AUTHOR_ALLOWED_TOOLS


@dataclass(frozen=True)
class AgentProfile:
    """The narrow surface a specific native session may use.

    The author needs Write/Edit and the Docker-aware ``harbor-author`` helper.
    The evidence resolver only needs to read evidence, query allowlisted
    sources and write one proposal; sharing the author profile would give it
    far more power than its job requires.
    """

    role: str
    tool_list: str
    allowed_tools: str
    helper_name: str
    helper_dir: str
    workspace_env: str
    trace_name: str


AUTHOR_PROFILE = AgentProfile(
    role="author",
    tool_list=AUTHOR_TOOLS,
    allowed_tools=AUTHOR_ALLOWED_TOOLS,
    helper_name="harbor-author",
    helper_dir="author-bin",
    workspace_env="HARBOR_AUTHOR_WORKSPACE",
    trace_name="author-trace.jsonl",
)
RESOLVER_PROFILE = AgentProfile(
    role="resolver",
    tool_list=RESOLVER_TOOLS,
    allowed_tools=RESOLVER_ALLOWED_TOOLS,
    helper_name="harbor-evidence",
    helper_dir="resolver-bin",
    workspace_env="HARBOR_EVIDENCE_WORKSPACE",
    trace_name="resolver-trace.jsonl",
)


@dataclass
class AgentOutcome:
    status: str
    session_id: str = ""
    turns: int = 0
    usage: dict[str, Any] = field(default_factory=dict)
    usd: float | None = None
    exit_code: int | None = None
    result_text: str = ""
    error: str = ""
    transcript: list[dict[str, Any]] = field(default_factory=list)
    timed_out: bool = False
    helper_result: dict[str, Any] | None = None

    def trace_tool(self, block: dict[str, Any]) -> None:
        name = str(block.get("name") or "")
        payload = block.get("input")
        summary = ""
        if isinstance(payload, dict):
            for key in ("command", "path", "file_path", "pattern", "query"):
                if payload.get(key):
                    summary = f"{key}={str(payload[key])[:240]}"
                    break
        self.transcript.append({"tool": name, "input": summary})

    def trace_result(self, block: dict[str, Any]) -> None:
        content = block.get("content")
        text = ""
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = " ".join(
                str(item.get("text") or "")
                for item in content
                if isinstance(item, dict)
            )
        if text and self.transcript:
            self.transcript[-1]["result"] = text[:400]

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "session_id": self.session_id,
            "turns": self.turns,
            "usage": dict(self.usage),
            "usd": self.usd,
            "exit_code": self.exit_code,
            "result": self.result_text[-4000:],
            "error": self.error[-4000:],
            "timed_out": self.timed_out,
            "helper_result": self.helper_result,
            "tools": list(self.transcript),
        }


class AgentRunner(Protocol):
    def run(
        self,
        *,
        prompt: str,
        workspace: Path,
        contract: str,
        settings_path: Path,
        extra_env: dict[str, str] | None = None,
        resume: str | None = None,
    ) -> AgentOutcome: ...


def build_agent_settings(
    model: str,
    *,
    profile: AgentProfile = AUTHOR_PROFILE,
) -> dict[str, Any]:
    """Permission set for a native session.

    The allowlist is intentionally narrow: the agent can use its native file
    tools and can call exactly one helper. Every other Bash command is denied
    automatically because the session runs with ``--permission-prompts none``.
    """
    helper = profile.helper_name
    return {
        "model": model,
        "permissions": {
            "allow": [
                "Read",
                "Write",
                "Edit",
                "Grep",
                "Glob",
                f"Bash({helper}:*)",
                f"Bash(./bin/{helper}:*)",
                f"Bash(bash bin/{helper}:*)",
            ],
            "deny": [
                "WebFetch",
                "WebSearch",
                "Task",
                "NotebookEdit",
                "Read(//**/.claude/**)",
                "Write(inputs/**)",
                "Edit(inputs/**)",
                "Write(.harbor/**)",
                "Edit(.harbor/**)",
                "Write(CLAUDE.md)",
                "Edit(CLAUDE.md)",
            ]
            + (
                [
                    # The resolver only needs its helper. Denying the common
                    # shell readers stops a pipeline such as
                    # ``harbor-evidence show ... | head`` from widening the
                    # surface; ``show --limit`` is the supported form.
                    "Bash(cd:*)",
                    "Bash(ls:*)",
                    "Bash(cat:*)",
                    "Bash(head:*)",
                    "Bash(tail:*)",
                    "Bash(echo:*)",
                    "Bash(python:*)",
                    "Bash(python3:*)",
                ]
                if profile.role == "resolver"
                else []
            ),
            "defaultMode": "dontAsk",
        },
    }


def agent_environment(
    *,
    workspace: Path,
    repo_root: Path,
    extra_env: dict[str, str] | None = None,
    profile: AgentProfile = AUTHOR_PROFILE,
) -> dict[str, str]:
    """A clean child environment for the nested Claude Code process.

    The parent session may be a Claude Code process itself. Its
    ``CLAUDECODE``/``CLAUDE_CODE_*`` variables, its messaging socket and the
    pipeline's source tokens must not leak into the agent.
    """
    # Windows environment names are case-insensitive and are usually stored
    # upper-case (PROGRAMFILES, SYSTEMROOT). Compare case-folded so Docker's
    # CLI plugin discovery still sees its directories.
    keep = {name.casefold() for name in _KEEP_ENV}
    drop_names = {name.casefold() for name in _DROP_NAMES}
    drop_prefixes = tuple(name.casefold() for name in _DROP_PREFIXES)
    env: dict[str, str] = {
        key: value for key, value in os.environ.items() if key.casefold() in keep
    }
    for key, value in os.environ.items():
        folded = key.casefold()
        if folded in drop_names or folded.startswith(drop_prefixes):
            continue
        if folded.startswith("anthropic_"):
            env[key] = value
    token = env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY")
    if token:
        # The child CLI accepts ANTHROPIC_API_KEY; the gateway also accepts
        # the auth-token form. Set both in the child process only.
        env["ANTHROPIC_API_KEY"] = token
        env["ANTHROPIC_AUTH_TOKEN"] = token
    env.setdefault("HOME", os.environ.get("USERPROFILE", str(Path.home())))
    path = env.get("PATH", "")
    # The wrapper lives beside the workspace, not inside it, so the agent
    # cannot rewrite the only command it is allowed to execute.
    local_bin = workspace.parent / profile.helper_dir
    env["PATH"] = str(local_bin) + (os.pathsep + path if path else "")
    env["PYTHONPATH"] = str(repo_root) + (
        os.pathsep + os.environ["PYTHONPATH"]
        if os.environ.get("PYTHONPATH")
        else ""
    )
    env[profile.workspace_env] = str(workspace)
    # Both helpers use the same interpreter discovery variable; keeping the
    # author name makes the existing author wrapper remain unchanged.
    python = os.environ.get("HARBOR_AUTHOR_PYTHON", _python_identity())
    env["HARBOR_AUTHOR_PYTHON"] = python
    env["HARBOR_EVIDENCE_PYTHON"] = python
    env.update(extra_env or {})
    from .resources import child_environment
    env.update(child_environment())
    return env


def _python_identity() -> str:
    import sys

    return sys.executable


class ClaudeCodeAgent:
    """Run one ``claude -p`` native session with a restricted profile."""

    name = "claude-code"

    def __init__(
        self,
        config: Config,
        *,
        role: str = "author",
        profile: AgentProfile | None = None,
    ):
        self.config = config
        self.settings: ModelSettings = config.model_for(role)
        self.role = role
        self.profile = profile or (
            RESOLVER_PROFILE if role == "resolver" else AUTHOR_PROFILE
        )
        self.binary = shutil.which("claude")
        if not self.binary:
            raise PipelineError("claude CLI is not on PATH")

    # -- command -----------------------------------------------------------

    def command(
        self,
        *,
        settings_path: Path,
        contract: str,
        resume: str | None = None,
        bare: bool = True,
        safe_mode: bool = False,
    ) -> list[str]:
        argv = [self.binary, "-p"]
        if bare:
            # ``--bare`` silently drops Write/Grep/Glob from the built-in tool
            # set (only Read/Edit/Bash survive), which makes it impossible to
            # create a new target file. Loading no setting sources gives the
            # same isolation without shrinking the tool set.
            argv.extend(["--setting-sources", ""])
        if safe_mode:
            argv.append("--safe-mode")
        argv.extend(
            [
                "--restricted",
                "--strict-mcp-config",
                "--disable-slash-commands",
                "--tools",
                self.profile.tool_list,
                "--allowedTools",
                self.profile.allowed_tools,
                "--permission-mode",
                "dontAsk",
                "--permission-prompts",
                "none",
                "--settings",
                str(settings_path),
                "--append-system-prompt",
                contract,
                "--output-format",
                "stream-json",
                "--verbose",
                "--max-turns",
                str(self.settings.max_turns),
                "--max-budget-usd",
                str(self.settings.max_budget_usd),
                "--autocompact",
                str(self.settings.autocompact),
            ]
        )
        if resume:
            # A resumed session otherwise reuses the system prompt recorded by
            # the first run. The contract is part of that prompt, so render it
            # fresh when the session continues.
            argv.extend(["--system-prompt-snapshot", "off", "--resume", resume])
        return argv

    # -- execution ---------------------------------------------------------

    def run(
        self,
        *,
        prompt: str,
        workspace: Path,
        contract: str,
        settings_path: Path,
        extra_env: dict[str, str] | None = None,
        resume: str | None = None,
    ) -> AgentOutcome:
        workspace = workspace.resolve()
        attempt = self._run_once(
            prompt=prompt,
            workspace=workspace,
            contract=contract,
            settings_path=settings_path,
            extra_env=extra_env,
            resume=resume,
            bare=True,
        )
        # Some gateways front the API with a token-only auth path rather than
        # an API key. ``--bare`` is stricter about that; retry once with the
        # user's normal settings sources if the first attempt could not
        # authenticate. The prompt and workspace are unchanged, so the retry
        # is safe.
        if attempt.status == "auth_error" and not resume:
            fallback = self._run_once(
                prompt=prompt,
                workspace=workspace,
                contract=contract,
                settings_path=settings_path,
                extra_env=extra_env,
                resume=None,
                bare=False,
                safe_mode=True,
            )
            if fallback.status != "auth_error":
                return fallback
        return attempt

    def _run_once(
        self,
        *,
        prompt: str,
        workspace: Path,
        contract: str,
        settings_path: Path,
        extra_env: dict[str, str] | None,
        resume: str | None,
        bare: bool,
        safe_mode: bool = False,
    ) -> AgentOutcome:
        argv = self.command(
            settings_path=settings_path,
            contract=contract,
            resume=resume,
            bare=bare,
            safe_mode=safe_mode,
        )
        env = agent_environment(
            workspace=workspace,
            repo_root=Path(__file__).resolve().parent.parent,
            extra_env=extra_env,
            profile=self.profile,
        )
        invocation = uuid.uuid4().hex
        if self.profile.role == "author":
            env["HARBOR_AUTHOR_SESSION_RUN"] = invocation
        stdout_lines: list[str] = []
        stderr_chunks: list[str] = []
        timed_out = threading.Event()

        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(workspace),
                env=env,
                **hidden_console_kwargs(),
            )
        except OSError as exc:
            return AgentOutcome(status="provider_error", error=f"claude CLI failed: {exc}")

        def feed() -> None:
            try:
                assert proc.stdin is not None
                proc.stdin.write(prompt)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

        def drain_err() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line)
                if len(stderr_chunks) > 4000:
                    del stderr_chunks[:1000]

        threading.Thread(target=feed, daemon=True).start()
        err_thread = threading.Thread(target=drain_err, daemon=True)
        err_thread.start()

        trace_path = workspace / ".harbor" / self.profile.trace_name
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        from .processes import ProcessTree, alive, wait_until_idle
        from .authoring import helper_status

        stopped = threading.Event()
        pending_at_exit = threading.Event()
        started = time.monotonic()
        author = self.profile.role == "author"
        wait_limit = self.config.pipeline.resource_wait_sec if author else 0
        wall_deadline = started + self.settings.timeout_sec + wait_limit + (2 * self.config.pipeline.command_timeout_sec if author else 0)
        with ProcessTree(proc) as tree:
            def watchdog():
                last, paused = time.monotonic(), 0.0
                while not stopped.wait(0.2):
                    now = time.monotonic()
                    helper = helper_status(workspace) if author else {}
                    ours = helper.get("session_token") == invocation and alive(int(helper.get("pid") or 0), helper.get("created"))
                    if ours:
                        tree.track(helper["pid"])
                        if proc.poll() is not None and helper.get("status") in {"waiting", "running"}:
                            pending_at_exit.set()
                    # Queue time and finishing an already-started helper do not
                    # spend model reasoning time. A separate wall cap still holds.
                    if ours and (helper.get("status") == "waiting" or proc.poll() is not None):
                        paused += now - last
                    last = now
                    if (now >= wall_deadline or paused > wait_limit + (2 * self.config.pipeline.command_timeout_sec if author else 0)
                            or now - started - paused >= self.settings.timeout_sec):
                        timed_out.set()
                        tree.kill()
                        return

            watcher = threading.Thread(target=watchdog, daemon=True)
            watcher.start()
            try:
                assert proc.stdout is not None
                with trace_path.open("a", encoding="utf-8", newline="\n") as trace:
                    for line in proc.stdout:
                        stdout_lines.append(line)
                        _append_live_trace(trace, line)
                proc.wait(timeout=30)
                if author and not timed_out.is_set():
                    waited = wait_until_idle(workspace, invocation, deadline=wall_deadline,
                                             on_tick=lambda helper: tree.track(helper["pid"]))
                    if waited:
                        pending_at_exit.set()
            except (subprocess.TimeoutExpired, TimeoutError):
                timed_out.set()
                tree.kill()
            finally:
                stopped.set()
                watcher.join(timeout=2)
            if self.profile.role == "author":
                from .author_debug import cleanup
                cleanup(workspace)

        err_thread.join(timeout=5)
        stderr = "".join(stderr_chunks)
        parsed = parse_stream(stdout_lines)
        helper = helper_status(workspace) if author else {}
        if helper.get("session_token") == invocation:
            parsed.helper_result = {**helper, "pending_at_exit": pending_at_exit.is_set()}
            if helper.get("status") in {"waiting", "running"} and not alive(int(helper.get("pid") or 0), helper.get("created")):
                parsed.helper_result.update(status="interrupted", error_category="infra_error",
                                            error="helper exited without a terminal result")
        parsed.exit_code = proc.returncode
        parsed.timed_out = timed_out.is_set()
        if parsed.timed_out:
            parsed.status = "timeout"
            parsed.error = "claude CLI exceeded its authoring timeout"
        elif parsed.status == "completed" and proc.returncode not in (0, None):
            parsed.status = "provider_error"
            parsed.error = f"claude CLI exited {proc.returncode}: {stderr[-4000:]}"
        elif not parsed.error and parsed.status != "completed":
            parsed.error = stderr[-4000:]
        if not parsed.session_id and _looks_like_auth_error(stderr):
            parsed.status = "auth_error"
            parsed.error = stderr[-2000:]
        return parsed

    def health(self) -> dict[str, Any]:
        return {
            "ok": bool(self.binary),
            "provider": self.name,
            "binary": self.binary,
            "model": self.settings.model,
        }


def _looks_like_auth_error(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(
        phrase in lowered
        for phrase in (
            "authentication",
            "invalid api key",
            "unauthorized",
            "api key",
            "401",
        )
    )


def _kill_process(proc: subprocess.Popen) -> None:
    from .backend import _kill_tree

    _kill_tree(proc)


def _append_live_trace(handle, line: str) -> None:
    """Append a compact live event so a long session is observable.

    The full stream is kept in memory for the final accounting; this file only
    needs the tool names and short inputs to tell a stuck build from a stuck
    model. Write failures must never kill the session.
    """
    text = line.strip()
    if not text:
        return
    try:
        event = json.loads(text)
    except ValueError:
        return
    if not isinstance(event, dict):
        return
    kind = event.get("type")
    record: dict[str, Any] = {"type": kind}
    if kind == "system" and event.get("subtype") == "init":
        record["session_id"] = event.get("session_id")
    elif kind == "assistant":
        for block in (event.get("message") or {}).get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                payload = block.get("input") or {}
                summary = ""
                if isinstance(payload, dict):
                    for key in ("command", "file_path", "path", "pattern"):
                        if payload.get(key):
                            summary = f"{key}={str(payload[key])[:240]}"
                            break
                record.setdefault("tools", []).append(
                    {"name": block.get("name"), "input": summary}
                )
    elif kind == "result":
        record.update(
            {
                "status": event.get("subtype"),
                "turns": event.get("num_turns"),
                "usd": event.get("total_cost_usd"),
                "is_error": event.get("is_error"),
                "session_id": event.get("session_id"),
            }
        )
    else:
        return
    try:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        handle.flush()
    except OSError:
        pass


def parse_stream(lines: list[str]) -> AgentOutcome:
    """Parse ``claude -p --output-format stream-json`` line by line.

    The final ``result`` event carries session id, turn count, token usage and
    cost. A line that is not JSON is kept in ``error`` only when no result
    event appears, so a stray progress line cannot mask a successful session.
    """
    outcome = AgentOutcome(status="completed")
    result_seen = False
    raw: list[str] = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            raw.append(text)
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            outcome.session_id = str(event.get("session_id") or outcome.session_id)
        elif kind == "assistant":
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    outcome.trace_tool(block)
        elif kind == "result":
            result_seen = True
            outcome.session_id = str(event.get("session_id") or outcome.session_id)
            outcome.turns = int(event.get("num_turns") or 0)
            outcome.result_text = str(event.get("result") or "")[:4000]
            usage = event.get("usage") or {}
            if isinstance(usage, dict):
                outcome.usage = dict(usage)
            cost = event.get("total_cost_usd")
            if isinstance(cost, (int, float)):
                outcome.usd = float(cost)
            if event.get("is_error"):
                outcome.status = "provider_error"
                outcome.error = outcome.result_text or "claude CLI reported an error"
        elif kind == "user":
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    outcome.trace_result(block)
    if not result_seen and raw:
        outcome.error = "\n".join(raw)[-2000:]
    return outcome
