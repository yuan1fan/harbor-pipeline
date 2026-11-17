#!/usr/bin/env python3
"""Watch a resolved-candidate test run and alert on stalls or resource locks.

The watcher is read-only. It observes:

- per-candidate ``state.json``
- author trace / helper job / build logs / matrix logs
- the shared Docker admission queue
- host available memory
- whether the driver (``run_resolved_tests.py``) and candidate processes exist

It prints a warning (and optionally beeps) when:
- an active candidate has no observable file progress for ``--stall-sec``
- a helper job says ``running`` but its process disappeared or its logs stopped
- Docker has waiting entries older than ``--queue-wait-sec``
- host available memory is below ``--memory-mb``
- the driver exits while candidates are still non-terminal

Examples:

    python scripts/watch_resolved_tests.py --once
    python scripts/watch_resolved_tests.py --run-id resolved-20261116-all
    python scripts/watch_resolved_tests.py --run-id resolved-20261116-all --poll 20 --stall-sec 1800

Alerts are appended to ``work/resolved-tests/<run-id>/monitor-alerts.jsonl``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TERMINAL = {"RELEASED", "QUARANTINED", "UNSUPPORTED"}
FAILURE = {"QUARANTINED", "UNSUPPORTED"}

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a project dependency
    psutil = None


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _newest_mtime(paths: list[Path]) -> float:
    newest = 0.0
    for path in paths:
        try:
            if path.is_file():
                newest = max(newest, path.stat().st_mtime)
        except OSError:
            pass
    return newest


def _candidate_files(root: Path) -> list[Path]:
    """Relevant live files, without walking huge source trees."""
    files = [
        root / "state.json",
        root / "author" / ".harbor" / "author-trace.jsonl",
        root / "author" / ".harbor" / "job.json",
        root / "author" / ".harbor" / "probe-state.json",
        root / "author" / ".harbor" / "build-state.json",
    ]
    for pattern in (
        "author/.harbor/*.log",
        "build-logs/*.log",
        "matrix/**/*.log",
        "matrix/**/state.json",
        "release/**/*.json",
    ):
        files.extend(root.glob(pattern))
    return files


def _process_snapshot(cves: set[str], run_id: str) -> tuple[bool, set[str]]:
    """Return (driver_alive, active_cves) using command lines and cwd."""
    if psutil is None:
        return True, set()
    driver = False
    active: set[str] = set()
    for process in psutil.process_iter(["pid", "cmdline", "cwd"]):
        try:
            cmd = " ".join(process.info.get("cmdline") or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if "run_resolved_tests.py" in cmd and run_id in cmd:
            driver = True
        for cve in cves:
            if cve in cmd:
                active.add(cve)
        if "harbor_pipeline.author_tool" in cmd or "harbor_pipeline -c" in cmd:
            try:
                cwd = str(process.info.get("cwd") or "")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cwd = ""
            for cve in cves:
                if cve in cwd:
                    active.add(cve)
    return driver, active


def _queue_snapshot(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries = data.get("entries") if isinstance(data, dict) else None
    return [entry for entry in entries or [] if isinstance(entry, dict)]


def _memory_mb() -> float | None:
    if psutil is None:
        return None
    try:
        return psutil.virtual_memory().available / 1024 / 1024
    except Exception:  # noqa: BLE001
        return None


def _job_running(path: Path) -> dict[str, Any]:
    job = _read_json(path)
    return job if str(job.get("status") or "") == "running" else {}


def _age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    if seconds >= 60:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds}s"


class Watcher:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_dir = (
            args.run_dir.resolve()
            if args.run_dir
            else (Path(args.output_dir) / args.run_id).resolve()
        )
        self.log_root = (
            args.log_dir.resolve()
            if args.log_dir
            else ROOT / "work" / "resolved-tests" / args.run_id
        )
        self.alert_path = self.log_root / "monitor-alerts.jsonl"
        self.summary_path = self.log_root / "summary.json"
        self.queue_path = ROOT / "work" / "resources" / "docker-queue.json"
        self.cves = self._discover_cves()
        self.started = time.time()
        self.last_alert: dict[str, float] = {}
        self.first_seen: dict[str, float] = {}
        self.last_progress: dict[str, float] = {}
        self.last_heartbeat = 0.0

    def _discover_cves(self) -> set[str]:
        if not self.run_dir.is_dir():
            return set()
        return {
            child.name
            for child in self.run_dir.iterdir()
            if child.is_dir() and child.name.startswith("CVE-")
        }

    def _alert(self, key: str, level: str, message: str, detail: dict[str, Any] | None = None) -> None:
        now = time.time()
        previous = self.last_alert.get(key, 0.0)
        if now - previous < self.args.repeat_sec:
            return
        self.last_alert[key] = now
        record = {
            "at": _utc_now(),
            "level": level,
            "key": key,
            "message": message,
            "detail": detail or {},
        }
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
        with self.alert_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[{_now()}] {level} {message}", flush=True)
        if self.args.beep:
            try:
                import winsound

                winsound.Beep(1200 if level == "CRITICAL" else 900, 350)
            except Exception:  # noqa: BLE001
                print("\a", end="", flush=True)

    def _snapshot(self) -> dict[str, Any]:
        states: dict[str, dict[str, Any]] = {}
        progress: dict[str, float] = {}
        for cve in sorted(self.cves):
            root = self.run_dir / cve
            state = _read_json(root / "state.json")
            states[cve] = state
            progress[cve] = _newest_mtime(_candidate_files(root))
        driver, active = _process_snapshot(self.cves, self.args.run_id)
        queue = _queue_snapshot(self.queue_path)
        return {
            "at": _utc_now(),
            "states": states,
            "progress": progress,
            "driver": driver,
            "active": active,
            "queue": queue,
            "memory_mb": _memory_mb(),
            "summary_exists": self.summary_path.is_file(),
        }

    def _check(self, snap: dict[str, Any]) -> bool:
        """Return True when the run has reached a terminal end."""
        states = snap["states"]
        if not states:
            self._alert(
                "no-state",
                "WARN",
                f"没有找到候选 state：{self.run_dir}",
            )
            return False

        terminal = [
            cve for cve, state in states.items()
            if str(state.get("state") or "") in TERMINAL
        ]
        now = time.time()
        if self.args.once or now - self.last_heartbeat >= self.args.heartbeat_sec:
            self.last_heartbeat = now
            queue = snap["queue"]
            waiting = sum(1 for entry in queue if entry.get("status") == "waiting")
            running = sum(1 for entry in queue if entry.get("status") == "running")
            memory = snap["memory_mb"]
            memory_text = f"{memory:.0f}MiB" if memory is not None else "unknown"
            active = ",".join(sorted(snap["active"])) or "none"
            print(
                f"[{_now()}] INFO {len(states)} candidates | "
                f"terminal {len(terminal)} | active {active} | "
                f"docker {running}r/{waiting}w | mem {memory_text}"
            )
        if len(terminal) == len(states):
            if snap["summary_exists"]:
                print(f"[{_now()}] INFO 全部候选已终态，summary 已生成")
                return True
            self._alert(
                "driver-exited",
                "CRITICAL",
                "全部候选已终态，但 driver 没有生成 summary.json",
            )
            return True

        if not snap["driver"]:
            self._alert(
                "driver-missing",
                "CRITICAL",
                "run_resolved_tests.py 进程不存在，但仍有非终态候选",
            )

        memory = snap["memory_mb"]
        if memory is not None and memory < self.args.memory_mb:
            self._alert(
                "memory",
                "CRITICAL",
                f"host available memory {memory:.0f} MiB < {self.args.memory_mb} MiB",
                {"available_mb": round(memory, 1)},
            )

        queue = snap["queue"]
        waiting = [entry for entry in queue if entry.get("status") == "waiting"]
        if waiting:
            old = []
            now = time.time()
            for entry in waiting:
                try:
                    age = now - float(entry.get("queued_at") or now)
                except (TypeError, ValueError):
                    age = 0.0
                if age >= self.args.queue_wait_sec:
                    old.append((entry, age))
            if old:
                sample = old[0]
                reason = str(sample[0].get("reason") or "unknown")
                self._alert(
                    "docker-queue",
                    "CRITICAL",
                    f"Docker queue 有 {len(old)} 个等待超过 {self.args.queue_wait_sec}s；"
                    f"最老 {_age(sample[1])}，原因：{reason}",
                    {"waiting": len(old), "oldest_sec": round(sample[1], 1)},
                )

        active = snap["active"]
        now = time.time()
        for cve, state in states.items():
            name = str(state.get("state") or "")
            if name in TERMINAL:
                continue
            key = f"cve:{cve}"
            self.first_seen.setdefault(key, now)
            changed = snap["progress"].get(cve, 0.0)
            previous = self.last_progress.get(key, 0.0)
            if changed > previous:
                self.last_progress[key] = changed
                self.first_seen[key] = now
                continue
            last_change = max(changed, self.first_seen[key])
            stalled = now - last_change
            job_path = self.run_dir / cve / "author" / ".harbor" / "job.json"
            job = _job_running(job_path)
            if job and cve not in active:
                self._alert(
                    f"job:{cve}",
                    "WARN",
                    f"{cve} 的 helper job 标记 running，但没有对应进程",
                    {"job": job},
                )

            if cve not in active:
                # A candidate waiting for a worker is not a stall; the driver
                # and Docker queue checks cover the global deadlock cases.
                continue
            if stalled >= self.args.stall_sec:
                self._alert(
                    key,
                    "WARN",
                    f"{cve} 处于 {name}，但已 {_age(stalled)} 没有可见文件进展",
                    {"state": name, "stalled_sec": round(stalled, 1)},
                )

        # A completed-looking summary is the only safe exit signal.
        if snap["summary_exists"]:
            print(f"[{_now()}] INFO summary.json 已出现，结束监视")
            return True
        return False

    def run(self, once: bool = False) -> int:
        deadline = (
            self.started + self.args.max_minutes * 60
            if self.args.max_minutes > 0
            else None
        )
        print(f"watch: {self.run_dir}")
        print(
            f"poll={self.args.poll}s stall={self.args.stall_sec}s "
            f"queue_wait={self.args.queue_wait_sec}s memory={self.args.memory_mb}MiB"
        )
        try:
            while True:
                snap = self._snapshot()
                if self._check(snap):
                    return 0
                if once:
                    return 0
                if deadline is not None and time.time() >= deadline:
                    print(f"[{_now()}] INFO 达到 --max-minutes，结束监视")
                    return 0
                time.sleep(max(1.0, self.args.poll))
        except KeyboardInterrupt:
            print(f"\n[{_now()}] INFO 监视已停止")
            return 130


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="resolved-20261116-all")
    parser.add_argument("--run-dir", type=Path, help="direct runs/<run-id> path")
    parser.add_argument("--output-dir", type=Path, default=Path("runs"))
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--poll", type=float, default=15.0)
    parser.add_argument("--stall-sec", type=float, default=1800.0)
    parser.add_argument("--queue-wait-sec", type=float, default=300.0)
    parser.add_argument("--memory-mb", type=float, default=3072.0)
    parser.add_argument("--repeat-sec", type=float, default=600.0)
    parser.add_argument("--heartbeat-sec", type=float, default=60.0)
    parser.add_argument("--max-minutes", type=float, default=0.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-beep", action="store_true")
    args = parser.parse_args()
    args.beep = not args.no_beep
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    return Watcher(args).run(once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
