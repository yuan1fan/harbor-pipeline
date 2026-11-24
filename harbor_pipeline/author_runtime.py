"""Persistent author container; host-owned helper and model service lifecycle."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import author_debug, authoring
from .backend import build_image, docker_binary
from .errors import TaskError
from .util import PipelineError, digest, file_lock, hidden_console_kwargs, read_json, write_json

RUNTIME_FILE = ".harbor/runtime.json"
ASSETS = Path(__file__).resolve().parent / "assets"


def _docker(args, *, timeout=60, check=True):
    try:
        result = subprocess.run([docker_binary(), *args], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                **hidden_console_kwargs())
    except (OSError, subprocess.SubprocessError) as exc:
        raise TaskError("infra_error", f"Author container operation failed: {exc}") from exc
    if check and result.returncode:
        raise TaskError("infra_error", "Author container operation failed: " + result.stderr[-2000:])
    return result


def _owned(kind, name, workspace):
    result = _docker([kind, "inspect", name], check=False)
    if result.returncode:
        return None
    data = json.loads(result.stdout)[0]
    labels = (data.get("Config", {}).get("Labels") if kind == "container" else data.get("Labels")) or {}
    if labels.get(author_debug.OWNER_LABEL) != author_debug._owner(workspace):
        raise PipelineError("Author resource ownership mismatch")
    return data


def ensure_image(workspace, config):
    names = ("base_author.Dockerfile", "author_client.py", "author_net.py", "author_capture.py")
    contents = {name: (ASSETS / name).read_text(encoding="utf-8") for name in names}
    tag = "harbor-pipeline/base-author:" + digest(contents)[:12]
    from .author_probe import image_exists
    lock = Path(config.pipeline.resource_dir).resolve() / "author-image"
    with file_lock(lock, timeout_sec=config.pipeline.author_build_timeout_sec + 60):
        if not image_exists(tag):
            context = workspace.parent / "author-runtime-build"
            context.mkdir(parents=True, exist_ok=True)
            for name, body in contents.items():
                (context / ("Dockerfile" if name.endswith("Dockerfile") else name)).write_text(body, encoding="utf-8", newline="\n")
            build_image(name="base-author", context=context, image_ref=tag,
                        log_path=workspace / ".harbor/base-author.log",
                        timeout_sec=config.pipeline.author_build_timeout_sec)
    return tag


def prepare_live(workspace):
    """The writable bind contains no authoritative pipeline files."""
    live = workspace.parent / "author-files"
    live.mkdir(exist_ok=True)
    if live.is_symlink() or getattr(live, "is_junction", lambda: False)():
        raise PipelineError("Author live workspace must not be linked")
    marker = workspace / ".harbor/live-seeded.json"
    if not marker.is_file():
        if any(live.iterdir()):
            raise PipelineError("Unrecognized author-files directory; refusing to overwrite it")
        for name in ("target", "target-fixed", "poc"):
            shutil.copytree(workspace / name, live / name, symlinks=True)
        shutil.copyfile(workspace / "bundle.json", live / "bundle.json")
        for name in ("inputs", ".harbor", "research", "tools"):
            (live / name).mkdir(exist_ok=True)
        (live / "CLAUDE.md").touch()
        # The Docker node user must be able to edit a bind created by a host
        # account with a different UID. Parent run-directory permissions remain.
        for directory, dirs, files in os.walk(live, followlinks=False):
            Path(directory).chmod(0o777)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o666)
        write_json(marker, {"live": str(live)})
    return live


class AuthorRuntime:
    def __init__(self, workspace, config, *, image=None):
        self.workspace, self.config = workspace.resolve(), config
        owner = author_debug._owner(self.workspace)
        self.owner = owner
        self.name = f"harbor-author-{owner}-agent"
        self.egress = f"harbor-author-{owner}-egress"
        self.lab = f"harbor-author-{owner}-lab"
        self.home = f"harbor-author-{owner}-home"
        self.image = image
        self.live = prepare_live(self.workspace)
        self.service_ip = ""
        self.service_port = 0

    def start(self, port):
        self.image = self.image or ensure_image(self.workspace, self.config)
        label = f"{author_debug.OWNER_LABEL}={self.owner}"
        for name, internal in ((self.egress, False), (self.lab, True)):
            if not _owned("network", name, self.workspace):
                _docker(["network", "create", "--label", label, *(["--internal"] if internal else []), name])
        if not _owned("volume", self.home, self.workspace):
            _docker(["volume", "create", "--label", label, self.home])
        previous = _owned("container", self.name, self.workspace)
        if previous and previous.get("State", {}).get("Running"):
            self.stop()
        if previous and previous["Config"]["Labels"].get("harbor-pipeline.runtime-image") != self.image:
            _docker(["rm", self.name])
            previous = None
        probe = self.workspace.parent / "author-probe"
        probe.mkdir(exist_ok=True)
        if not previous:
            mounts = [(self.live, "/workspace", False),
                      (self.workspace / "inputs", "/workspace/inputs", True),
                      (self.workspace / ".harbor", "/workspace/.harbor", True),
                      (self.workspace / "CLAUDE.md", "/workspace/CLAUDE.md", True),
                      (probe, "/artifacts/probe", True)]
            args = ["create", "--name", self.name, "--init", "--label", label,
                    "--label", "harbor-pipeline.runtime-image=" + self.image,
                    "--network", self.egress, "--add-host", "host.docker.internal:host-gateway",
                    "--memory", str(self.config.pipeline.author_memory_mb) + "m",
                    "--cpus", str(self.config.pipeline.author_cpus), "--pids-limit", "512",
                    # sudo is intentionally available; NET_ADMIN/SYS_ADMIN are
                    # absent from Docker's default bounding set. Remove raw sockets.
                    "--cap-drop", "NET_RAW", "--cap-drop", "MKNOD",
                    "--mount", f"type=volume,src={self.home},dst=/home/node"]
            for source, destination, readonly in mounts:
                if source.is_symlink() or getattr(source, "is_junction", lambda: False)():
                    raise PipelineError("Unsafe author runtime mount")
                args += ["--mount", f"type=bind,src={source.resolve()},dst={destination}" + (",readonly" if readonly else "")]
            _docker([*args, self.image])
            _docker(["network", "connect", "--alias", "author", self.lab, self.name])
        _docker(["start", self.name])
        # Resolve in the trusted firewall container, not using mutable binaries
        # or /etc/hosts in the retained author container.
        result = _docker(["run", "--rm", "--network", self.egress,
                          "--add-host", "host.docker.internal:host-gateway", "--entrypoint", "python3", self.image,
                          "-c", "import socket; print(socket.gethostbyname('host.docker.internal'))"])
        self.service_ip, self.service_port = result.stdout.strip(), port
        self.firewall()
        old = read_json(self.workspace / RUNTIME_FILE) if (self.workspace / RUNTIME_FILE).is_file() else {}
        write_json(self.workspace / RUNTIME_FILE, {**old, "container": self.name, "lab": self.lab,
                   "home": self.home, "image": self.image, "transport": "container"})

    def firewall(self):
        targets = []
        for kind in ("vulnerable", "fixed"):
            data = author_debug.inspect(self.workspace, kind)
            if data and data.get("State", {}).get("Running"):
                address = data.get("NetworkSettings", {}).get("Networks", {}).get(self.lab, {}).get("IPAddress")
                if address:
                    targets.append(address)
        payload = json.dumps({"service_ip": self.service_ip, "port": self.service_port, "targets": targets})
        # The setup container has no writable host mounts, secrets or socket.
        _docker(["run", "--rm", "--network", "container:" + self.name, "--user", "0",
                 "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", "python3",
                 self.image, "/opt/harbor/author_net.py", payload])

    def after_helper(self, args):
        if args[0] in {"debug", "cleanup", "build", "probe", "submit"}:
            self.firewall()

    def capture(self, request):
        result = _docker(["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--memory", "256m", "--cpus", "1", "--pids-limit", "32",
                          "--mount", f"type=bind,src={self.live.resolve()},dst=/workspace,readonly",
                          "--entrypoint", "python3", self.image, "/opt/harbor/author_capture.py",
                          json.dumps(request)], check=False)
        try:
            value = json.loads(result.stdout)
        except ValueError as exc:
            raise PipelineError("Source capture failed: " + result.stderr[-1000:]) from exc
        if result.returncode or value.get("error"):
            raise PipelineError(str(value.get("error") or "Source capture failed"))
        return value

    def command(self, argv, token):
        endpoint = f"http://{self.service_ip}:{self.service_port}"
        env = {"HOME": "/home/node", "CLAUDE_CONFIG_DIR": "/home/node/.claude",
               "ANTHROPIC_BASE_URL": endpoint + "/model", "ANTHROPIC_API_KEY": token,
               "ANTHROPIC_AUTH_TOKEN": token,
               "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.config.model_for("author").model,
               "HARBOR_AUTHOR_ENDPOINT": endpoint, "HARBOR_AUTHOR_TOKEN": token,
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}
        # env -i prevents a retained container's environment from changing routing
        # or loading credentials. Only this short-lived capability enters it.
        return [docker_binary(), "exec", "-i", "--workdir", "/workspace", self.name,
                "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                *[key + "=" + value for key, value in env.items()], *argv]

    def stop(self):
        if _owned("container", self.name, self.workspace):
            _docker(["stop", "--time", "2", self.name], timeout=30)


def dispose(workspace):
    """Remove only this candidate's retained runtime after a terminal result."""
    path = workspace / RUNTIME_FILE
    if not path.is_file():
        return
    owner = author_debug._owner(workspace)
    name = f"harbor-author-{owner}-agent"
    if _owned("container", name, workspace):
        _docker(["rm", "-f", name])
    for kind, suffix in (("network", "lab"), ("network", "egress"), ("volume", "home")):
        name = f"harbor-author-{owner}-{suffix}"
        if _owned(kind, name, workspace):
            _docker([kind, "rm", name])
    path.unlink(missing_ok=True)


def run_session(agent, *, prompt, workspace, contract, settings_path, extra_env, resume, **_):
    from .agent import AgentOutcome, _append_live_trace, build_agent_settings, parse_stream
    from .author_service import AuthorService
    from .processes import ProcessTree

    invocation = uuid.uuid4().hex
    runtime = AuthorRuntime(workspace, agent.config)
    runtime_settings = workspace / ".harbor/container-settings.json"
    write_json(runtime_settings, build_agent_settings(agent.settings.model, unrestricted_shell=True))
    previous = read_json(workspace / RUNTIME_FILE) if (workspace / RUNTIME_FILE).is_file() else {}
    if resume and previous.get("session_id") != resume:
        prompt = "This is a container session continuing an older workspace. Read the existing files and continue the task.\n" + prompt
        resume = None
    argv = agent.command(settings_path=Path("/workspace/.harbor/container-settings.json"), contract=contract, resume=resume)
    argv[0] = "claude"
    argv[argv.index("--allowedTools") + 1] = agent.profile.tool_list
    lines, stderr = [], []
    timed_out = threading.Event()
    stopped = threading.Event()
    pending = False
    outcome = AgentOutcome(status="provider_error")
    wait_limit = agent.config.pipeline.resource_wait_sec
    extra_wall = wait_limit + 2 * agent.config.pipeline.author_build_timeout_sec
    with file_lock(workspace / ".harbor/runtime-operation", timeout_sec=0):
        try:
            with AuthorService(config=agent.config, workspace=workspace, live=runtime.live, invocation=invocation,
                               extra_env=extra_env, after_helper=runtime.after_helper, capture=runtime.capture) as service:
                runtime.start(service.port)
                launch = runtime.command(argv, service.token)
                started = time.monotonic()
                deadline = started + agent.settings.timeout_sec + extra_wall
                proc = subprocess.Popen(launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, encoding="utf-8", errors="replace", **hidden_console_kwargs())

                def feed():
                    try:
                        proc.stdin.write(prompt)
                        proc.stdin.close()
                    except (OSError, BrokenPipeError):
                        pass

                def drain():
                    for line in proc.stderr:
                        stderr.append(line)
                        if len(stderr) > 4000:
                            del stderr[:1000]

                threading.Thread(target=feed, daemon=True).start()
                err_thread = threading.Thread(target=drain, daemon=True)
                err_thread.start()
                with ProcessTree(proc) as tree:
                    def watchdog():
                        last, paused = time.monotonic(), 0.0
                        while not stopped.wait(.2):
                            now = time.monotonic()
                            helper = authoring.helper_status(workspace)
                            if service.process is not None:
                                tree.track(service.process.pid)
                            if service.active.is_set() and (helper.get("status") == "waiting" or proc.poll() is not None):
                                paused += now - last
                            last = now
                            if now >= deadline or paused > extra_wall or now - started - paused >= agent.settings.timeout_sec:
                                timed_out.set()
                                service.cancel_helper()
                                # Terminating docker exec alone leaves children alive.
                                runtime.stop()
                                tree.kill()
                                return

                    watcher = threading.Thread(target=watchdog, daemon=True)
                    watcher.start()
                    try:
                        with (workspace / ".harbor/author-trace.jsonl").open("a", encoding="utf-8") as trace:
                            for line in proc.stdout:
                                lines.append(line)
                                _append_live_trace(trace, line)
                        proc.wait(timeout=30)
                        if not timed_out.is_set():
                            pending = service.wait(deadline)
                    except (TimeoutError, subprocess.TimeoutExpired):
                        timed_out.set()
                        service.cancel_helper()
                        tree.kill()
                    finally:
                        stopped.set()
                        watcher.join(5)
                err_thread.join(5)
                outcome = parse_stream(lines)
                outcome.exit_code, outcome.timed_out = proc.returncode, timed_out.is_set()
                helper = authoring.helper_status(workspace)
                if helper.get("session_token") == invocation:
                    outcome.helper_result = {**helper, "pending_at_exit": pending}
                if timed_out.is_set():
                    outcome.status, outcome.error = "timeout", "Container author exceeded its timeout"
                elif proc.returncode and outcome.status == "completed":
                    outcome.status = "provider_error"
                if not outcome.error and outcome.status != "completed":
                    outcome.error = "".join(stderr)[-4000:]
                if outcome.session_id:
                    state = read_json(workspace / RUNTIME_FILE)
                    write_json(workspace / RUNTIME_FILE, {**state, "session_id": outcome.session_id})
        except TaskError:
            raise
        except (PipelineError, OSError, subprocess.SubprocessError) as exc:
            outcome.status, outcome.error = "provider_error", str(exc)
        finally:
            # Keep debug targets stopped but reusable across --resume. The
            # pipeline removes them only when the candidate reaches a terminal
            # state.
            author_debug.suspend(workspace)
            runtime.stop()
    return outcome
