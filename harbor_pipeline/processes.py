"""Lifetime of a subprocess and the descendants it actually created."""
from __future__ import annotations

import threading
import time
import os
import subprocess
from pathlib import Path

import psutil


def identity(pid: int) -> float | None:
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


def alive(pid: int, created: float | None) -> bool:
    return created is not None and identity(pid) == created


class ProcessTree:
    """Remember descendants before their parents exit or are reparented.

    Checking creation times before terminating prevents PID reuse from making
    another worker's process part of this operation. Polling continues until
    close, including after the direct child has exited.
    """

    def __init__(self, process):
        self.process = process
        self.owned = {}
        self.lock = threading.Lock()
        self.kill_lock = threading.Lock()
        self.stopped = threading.Event()
        if getattr(process, "pid", None) is not None and process.poll() is None:
            self.track(process.pid)
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def track(self, pid):
        created = identity(pid)
        if created is not None:
            with self.lock:
                self.owned[pid] = created

    def _scan(self):
        with self.lock:
            owners = list(self.owned.items())
        for pid, created in owners:
            try:
                process = psutil.Process(pid)
                if process.create_time() != created:
                    with self.lock:
                        if self.owned.get(pid) == created:
                            self.owned.pop(pid, None)
                    continue
                for child in process.children(recursive=True):
                    try:
                        child_created = child.create_time()
                    except psutil.Error:
                        continue
                    with self.lock:
                        self.owned[child.pid] = child_created
            except psutil.NoSuchProcess:
                with self.lock:
                    if self.owned.get(pid) == created:
                        self.owned.pop(pid, None)
            except psutil.Error:
                pass

    def _watch(self):
        while not self.stopped.wait(0.1):
            self._scan()

    def kill(self):
        with self.kill_lock:
            self._kill()

    def _kill(self):
        self._scan()
        with self.lock:
            owners = list(self.owned.items())
        victims = []
        for pid, created in reversed(owners):
            try:
                process = psutil.Process(pid)
                if process.create_time() == created:
                    process.kill()
                    victims.append(process)
            except psutil.Error:
                pass
        psutil.wait_procs(victims, timeout=5)

    def __enter__(self):
        self._scan()
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.kill()
        self.stopped.set()
        self.thread.join(timeout=1)
        try:
            self.process.wait(timeout=5)
        except Exception:  # an already-reaped direct child is harmless
            pass


def wait_until_idle(workspace, token, *, deadline, on_tick=None):
    """Wait for the helper from this agent invocation, without an LLM call."""
    from .authoring import helper_status

    waited = False
    while True:
        helper = helper_status(workspace)
        if helper.get("session_token") != token or helper.get("status") not in {"running", "waiting"}:
            return waited
        if not alive(int(helper.get("pid") or 0), helper.get("created")):
            return waited
        waited = True
        if on_tick:
            on_tick(helper)
        if time.monotonic() >= deadline:
            raise TimeoutError("author helper exceeded its resource/execution wall limit")
        time.sleep(0.2)


def run_owned(command, *, timeout, log_path: Path, cwd=None, **kwargs):
    """Stream a CLI to disk and reap its observed descendants, even on success.

    A timed-out Harbor parent may exit while compose/buildx still hold its cwd
    and stdout pipes. File-backed output avoids inherited-pipe deadlocks, and
    the tracker retains ownership after those children become orphaned.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    expired = False
    with log_path.open("wb") as log:
        proc = subprocess.Popen(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=os.name != "nt", **kwargs)
        with ProcessTree(proc):
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                expired = True
        if expired:
            log.write(b"\nTIMEOUT\n")
    with log_path.open("rb") as log:
        log.seek(0, 2)
        log.seek(max(0, log.tell() - 100_000))
        tail = log.read().decode("utf-8", errors="replace")
    if expired:
        raise subprocess.TimeoutExpired(command, timeout, output=tail, stderr="")
    return subprocess.CompletedProcess(command, proc.returncode, tail, "")
