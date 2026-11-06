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

TOOL_LIST = "Read,Write,Edit,Grep,Glob,Bash"
ALLOWED_TOOLS = (
    "Read,Write,Edit,Grep,Glob,"
    "Bash(harbor-author:*),Bash(./bin/harbor-author:*),Bash(bash bin/harbor-author:*)"
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


def build_agent_settings(model: str) -> dict[str, Any]:
    """Permission set for an authoring session.

    The allowlist is intentionally narrow: the agent can edit its workspace
    with the native file tools and can call only the ``harbor-author`` helper.
    Every other Bash command is denied automatically because the session runs
    with ``--permission-prompts none``.
    """
    return {
        "model": model,
        "permissions": {
            "allow": [
                "Read",
                "Write",
                "Edit",
                "Grep",
                "Glob",
                "Bash(harbor-author:*)",
                "Bash(./bin/harbor-author:*)",
                "Bash(bash bin/harbor-author:*)",
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
            ],
            "defaultMode": "dontAsk",
        },
    }


def agent_environment(
    *,
    workspace: Path,
    repo_root: Path,
    extra_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """A clean child environment for the nested Claude Code process.

    The parent session may be a Claude Code process itself. Its
    ``CLAUDECODE``/``CLAUDE_CODE_*`` variables, its messaging socket and the
    pipeline's source tokens must not leak into the authoring agent.
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
        # ``--bare`` accepts ANTHROPIC_API_KEY; the gateway also accepts the
        # auth-token form. Set both in the child process only.
        env["ANTHROPIC_API_KEY"] = token
        env["ANTHROPIC_AUTH_TOKEN"] = token
    env.setdefault("HOME", os.environ.get("USERPROFILE", str(Path.home())))
    path = env.get("PATH", "")
    # The wrapper lives beside the author workspace, not inside it, so the
    # agent cannot rewrite the only command it is allowed to execute.
    local_bin = workspace.parent / "author-bin"
    env["PATH"] = str(local_bin) + (os.pathsep + path if path else "")
    env["PYTHONPATH"] = str(repo_root) + (
        os.pathsep + os.environ["PYTHONPATH"]
        if os.environ.get("PYTHONPATH")
        else ""
    )
    env["HARBOR_AUTHOR_WORKSPACE"] = str(workspace)
    env["HARBOR_AUTHOR_PYTHON"] = os.environ.get(
        "HARBOR_AUTHOR_PYTHON", _python_identity()
    )
    env.update(extra_env or {})
    return env


def _python_identity() -> str:
    import sys

    return sys.executable


class ClaudeCodeAgent:
    """Run one ``claude -p`` authoring session with native tools."""

    name = "claude-code"

    def __init__(self, config: Config, *, role: str = "author"):
        self.config = config
        self.settings: ModelSettings = config.model_for(role)
        self.role = role
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
            argv.append("--bare")
        if safe_mode:
            argv.append("--safe-mode")
        argv.extend(
            [
                "--restricted",
                "--strict-mcp-config",
                "--disable-slash-commands",
                "--tools",
                TOOL_LIST,
                "--allowedTools",
                ALLOWED_TOOLS,
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
        )
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

        def watchdog() -> None:
            timed_out.set()
            _kill_process(proc)

        trace_path = workspace / ".harbor" / "author-trace.jsonl"
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        timer = threading.Timer(self.settings.timeout_sec, watchdog)
        timer.start()
        try:
            assert proc.stdout is not None
            with trace_path.open("a", encoding="utf-8", newline="\n") as trace:
                for line in proc.stdout:
                    stdout_lines.append(line)
                    _append_live_trace(trace, line)
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _kill_process(proc)
        finally:
            timer.cancel()
            from .author_debug import cleanup
            cleanup(workspace)

        err_thread.join(timeout=5)
        stderr = "".join(stderr_chunks)
        parsed = parse_stream(stdout_lines)
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
