"""End-to-end per-CVE orchestration with resumable state and budget accounting."""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION
from .backend import build_task_images, preflight_target, prune_task_images, run_in_image
from .config import Config
from .contracts import (
    MAX_MATRIX_REPEATS,
    load_experiments,
    load_policy,
    matrix_repeats,
    validate,
)
from . import discovery as discovery_mod
from . import synthesis as synthesis_mod
from .cves import (
    artifact_identity_from_evidence,
    get_optional,
    raw_spec,
    source_plan,
)
from .differential import (
    MatrixCase,
    MatrixResult,
    build_step_cases,
    case_manifest,
    collate,
    plan_matrix_steps,
    run_ladder,
    run_seed_repeats,
)
from .errors import TaskError
from .evaluator import GOAL_PASSING, EvaluationOutcome, evaluate
from .generator import GeneratedTask, inspect_task, render_task
from .harbor_adapter import Capabilities, HarborAdapter, TrialOutcome
from .release import build_release, recheck_from_release, verify_release
from .trials import Expectation, build_trial_record
from .verifier_check import verifier_regression_checks
from . import registry as registry_mod
from .repair import (
    FRAMEWORK_PATHS,
    MAX_BUILD_RUNS,
    MAX_VERIFIER_RUNS,
    POC_PATH,
    AuthoringState,
    RepairEngine,
    RepairTools,
    repair_log_entry,
)
from .sources import EvidenceCollector
from .spec import check_evidence_links, check_spec_consistency, freeze
from .state import JobStore, new_run_id
from .util import PipelineError, digest, image_base as image_tag_base

# Categories the bounded repair loop may edit environment/ for. The same set
# gates a resume: re-running identical inputs reproduces the same verdict, so
# only a fresh repair can change the outcome of an auto-repairable quarantine.
REPAIRABLE_CATEGORIES = frozenset(
    {"build_error", "generation_error", "validation_error"}
)

STAGE_ORDER = (
    "DISCOVERED",
    "EVIDENCE_READY",
    "SPEC_FROZEN",
    "GENERATED",
    "BUILT",
    "VALIDATING",
    "VALIDATED",
    "RELEASED",
)


def _auto_evidence_complete(evidence: dict) -> bool:
    """A checkpoint is reusable only when the CVE record and fix patch are present."""
    sources = evidence.get("sources") or []
    return (
        any(
            s.get("source_type") == "cve_record" and s.get("status") == "ok"
            for s in sources
        )
        and any(
            s.get("source_type") == "upstream_commit" and s.get("status") == "ok"
            for s in sources
        )
    )


@dataclass
class PipelineReport:
    cve_id: str
    run_id: str
    state: str
    task_digest: str | None
    image_digest: str | None
    quality_score: float | None
    quality_tier: str | None
    admission_status: str | None
    release: dict | None
    evaluation: dict | None
    trials: list[dict]
    error: dict | None
    budget: dict

    def to_json(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "cve_id": self.cve_id,
            "run_id": self.run_id,
            "state": self.state,
            "task_digest": self.task_digest,
            "image_digest": self.image_digest,
            "quality_score": self.quality_score,
            "quality_tier": self.quality_tier,
            "admission_status": self.admission_status,
            "release": self.release,
            "evaluation": self.evaluation,
            "trials": self.trials,
            "error": self.error,
            "budget": self.budget,
        }


class CvePipeline:
    def __init__(
        self,
        *,
        config: Config,
        cve_id: str,
        run_id: str | None = None,
        adapter: HarborAdapter | None = None,
        profile: str = "smoke",
        scenario: str | None = None,
        workers: int = 1,
        ledger=None,
        output_root: Path | None = None,
    ):
        self.config = config
        self.cve_id = cve_id
        self.builtin = get_optional(cve_id)
        self.auto = scenario == "auto" or (scenario is None and self.builtin is None)
        if self.auto:
            self.scenario = "synthesized"
        elif self.builtin is None:
            raise PipelineError(
                f"No curated facts for {cve_id}; use --scenario auto for synthesis"
            )
        else:
            self.scenario = scenario or self.builtin.template
        self.discovery = None
        self.synthesis = None
        self.run_id = run_id or new_run_id("run")
        base = Path(output_root) if output_root else Path(config.pipeline.output_dir)
        self.root = base.resolve() / self.run_id
        self.store = JobStore(base, self.run_id, cve_id)
        self.adapter = adapter or HarborAdapter(
            jobs_dir=self.root / "jobs",
            run_root=self.root,
            timeout_sec=config.pipeline.command_timeout_sec,
        )
        self.profile = load_policy().profile(profile)
        self.policy = load_policy()
        self.workers = max(1, workers)
        self._capabilities: Capabilities | None = None
        self._ledger_obj = ledger
        self._repair = None
        self._repair_error: str | None = None
        # Images built during the current repair attempt are kept until the
        # attempt ends so the exec tool can inspect the real installed package.
        self._repair_images: dict[str, str] = {}
        self._repair_prune_bases: list[str] = []

    # -- facility ----------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        if self._capabilities is None:
            self._capabilities = self.adapter.capabilities()
        return self._capabilities

    @property
    def network_mode(self) -> str:
        return self.capabilities.network_mode

    def _matrix_repeats(self) -> int:
        """T03/T04 repetitions: the profile floor, raised by the task author.

        A synthesized bundle may declare `matrix_repeats` when its exploit path
        is genuinely nondeterministic. Curated (non-synthesized) targets have no
        bundle and always use the profile value.
        """
        requested = self.synthesis.bundle.get("matrix_repeats") if self.synthesis else None
        return matrix_repeats(self.profile, requested)

    def _fold_framework_checks(
        self,
        matrix: MatrixResult,
        spec: dict,
        job,
        artifact_digest: str,
        checks: dict[str, dict],
    ) -> None:
        """Record T05/T06/T07/T10 as framework trials, not per-candidate ones.

        The payloads are constants and the verifier is shared, so a real target
        adds no information. The synthetic record keeps the release audit and
        the evaluator's negative-case conditions intact while marking how the
        evidence was produced.
        """
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        experiments = {experiment.id: experiment for experiment in load_experiments()}
        for experiment_id in ("T05", "T06", "T07", "T10"):
            evidence = dict(checks[experiment_id])
            evidence["cve_id"] = spec["cve_id"]
            trial = TrialOutcome(
                trial_name=f"framework-{experiment_id}",
                task_path="<framework-verifier>",
                task_name=f"framework-{experiment_id}",
                trial_dir=Path("<framework-verifier>"),
                reward=0.0,
                exception=None,
                evidence=evidence,
                started_at=now,
                finished_at=now,
                duration_sec=0.0,
            )
            record = build_trial_record(
                experiment=experiments[experiment_id],
                trial=trial,
                run_id=self.run_id,
                cve_id=spec["cve_id"],
                candidate_revision=job.revision,
                artifact_digest=artifact_digest,
                seed=0,
                poc_path=None,
                started_at=now,
            )
            record["_audit"] = {
                "mode": "framework-verifier",
                "note": "runs once per verifier template; starts no target",
            }
            verdict = Expectation(
                experiment_id=experiment_id,
                met=True,
                detail=(
                    f"framework verifier check: status={evidence.get('status')} "
                    f"reward={evidence.get('reward')} exit={evidence.get('submitted_exit')}"
                ),
                observed_status=str(evidence.get("status")),
                error_category=None,
            )
            matrix.records.append(record)
            matrix.expectations[experiment_id] = verdict
            matrix.verdicts.append(verdict)

    def _derive_health_verdicts(
        self,
        matrix: MatrixResult,
        spec: dict,
        job,
        artifact_digest: str,
    ) -> None:
        """Derive T01/T02 from the health check inside T03/T04.

        The verifier always probes `/health` and `/business` before it runs any
        PoC, and the trial record stores that result. A separate T01/T02 trial
        therefore starts a second target to repeat a check the T03/T04 record
        already contains. The derived verdict keeps the hard conditions and the
        D1/D2 dimensions intact; a derived record is kept in the audit with
        ``_audit.mode = "derived"`` so the control plan remains complete.
        """
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        experiments = {experiment.id: experiment for experiment in load_experiments()}
        for experiment_id, source_id in (("T01", "T03"), ("T02", "T04")):
            sources = [
                record for record in matrix.records
                if record["experiment_id"] == source_id
            ]
            if sources:
                healthy_count = sum(
                    1 for record in sources
                    if bool((record.get("health") or {}).get("ok"))
                )
                healthy = healthy_count == len(sources)
                detail = (
                    f"derived from {len(sources)} {source_id} trial(s): "
                    f"{healthy_count}/{len(sources)} healthy"
                )
                observed_status = "healthy" if healthy else "target_unhealthy"
                error_category = None if healthy else "infra_error"
                matrix.derived_records.append(
                    self._derived_health_record(
                        experiment=experiments[experiment_id],
                        source_id=source_id,
                        sources=sources,
                        healthy=healthy,
                        spec=spec,
                        job=job,
                        artifact_digest=artifact_digest,
                        now=now,
                    )
                )
            else:
                # T04 never runs when T03 fails. The fixed build is unknown
                # rather than unhealthy; repair is still allowed based on T03.
                healthy = False
                detail = f"{source_id} did not run; health unknown"
                observed_status = "missing"
                error_category = "infra_error"
            verdict = Expectation(
                experiment_id=experiment_id,
                met=healthy,
                detail=detail,
                observed_status=observed_status,
                error_category=error_category,
            )
            matrix.expectations[experiment_id] = verdict
            matrix.verdicts.append(verdict)

    def _derived_health_record(
        self,
        *,
        experiment,
        source_id: str,
        sources: list[dict],
        healthy: bool,
        spec: dict,
        job,
        artifact_digest: str,
        now: str,
    ) -> dict:
        evidence = {
            "health_ok": healthy,
            "business_ok": healthy,
            "status": "healthy" if healthy else "target_unhealthy",
            "reference_observed": False,
            "submitted_observed": False,
            "derived_from": [record["trial_id"] for record in sources],
        }
        trial = TrialOutcome(
            trial_name=f"derived-{experiment.id.lower()}",
            task_path="<derived>",
            task_name=f"derived-{experiment.id.lower()}",
            trial_dir=Path("<derived>"),
            reward=1.0 if healthy else 0.0,
            exception=None,
            evidence=evidence,
            started_at=now,
            finished_at=now,
            duration_sec=0.0,
        )
        record = build_trial_record(
            experiment=experiment,
            trial=trial,
            run_id=self.run_id,
            cve_id=spec["cve_id"],
            candidate_revision=job.revision,
            artifact_digest=artifact_digest,
            seed=0,
            poc_path=None,
            started_at=now,
        )
        record["_audit"] = {
            "mode": "derived",
            "sources": [source["trial_id"] for source in sources],
            "note": f"health copied from {source_id}; no separate container ran",
        }
        return record

    def _debug_overrides(self, files: dict[str, str]) -> dict[str, str]:
        """Merge the current repair overlay with the engine's editable files."""
        merged = {**self._task_overlay(), **files}
        return {
            name: body
            for name, body in merged.items()
            if name not in FRAMEWORK_PATHS
            and (name == POC_PATH or name.startswith("environment/"))
        }

    def _ensure_synthesis(self) -> None:
        """Load the cached synthesis bundle before rendering a debug task.

        A repair resumed from QUARANTINED runs ``_attempt_repair`` before
        ``_advance`` calls ``synthesize``. Without this, the debug task is
        rendered with ``synthesis=None`` and the auto scenario has no template,
        so the second repair fails with "Unknown scenario template
        'synthesized'" instead of testing the patch.
        """
        if self.synthesis is not None or not self.auto:
            return
        try:
            self.synthesis = synthesis_mod.load(self.store.root, self.cve_id)
        except (PipelineError, TaskError, OSError):
            self.synthesis = None

    def _repair_part(self, state) -> tuple[dict, object | None, dict[str, str]]:
        """Resolve the agent's authoring state into spec, synthesis and files."""
        spec = getattr(state, "spec", None)
        bundle = getattr(state, "bundle", None)
        files = getattr(state, "files", None)
        if isinstance(state, dict):
            spec = state.get("spec") or spec
            bundle = state.get("bundle") or bundle
            files = state.get("files") or files
        if not spec:
            spec = self.store.read_artifact("cve-spec.json")
        if not files:
            files = self._task_files()
        self._ensure_synthesis()
        synthesis = self._synthesis_for_bundle(bundle)
        if synthesis is None and self.auto:
            raise TaskError(
                "generation_error",
                "synthesis bundle is unavailable; cannot render a debug task",
            )
        return spec, synthesis, self._debug_overrides(files)

    def _synthesis_for_bundle(self, bundle: dict | None):
        """Build a temporary Synthesis for the agent's patched bundle."""
        if not bundle:
            return self.synthesis
        if self.synthesis is not None and bundle == self.synthesis.bundle:
            return self.synthesis
        return synthesis_mod.Synthesis(
            cve_id=self.cve_id,
            bundle=bundle,
            model_identity="repair",
            usage={},
            prompt_sha256="",
            generated_at="",
            digest=digest(bundle),
        )

    def _render_repair_pair(self, spec, synthesis, overrides):
        """Render both variants with a private image tag and a scratch dir."""
        job = self.store.load()
        token = uuid.uuid4().hex[:8]
        vuln_base = (
            f"{image_tag_base(self.cve_id, 'vulnerable', job.revision)}-debug-{token}"
        )
        fixed_base = (
            f"{image_tag_base(self.cve_id, 'fixed', job.revision)}-debug-{token}"
        )
        debug_root = self.store.path("debug") / token
        common = {
            "scenario_name": self.scenario,
            "probe": "reference",
            "network_mode": self.network_mode,
            "allowed_hosts": ("target",),
            "overrides": overrides,
            "synthesis": synthesis,
            "revision": job.revision,
        }
        vuln_task = render_task(
            spec, variant="vulnerable", prebuilt_base=vuln_base, **common
        )
        fixed_task = render_task(
            spec, variant="fixed", prebuilt_base=fixed_base, **common
        )
        vuln_dir = vuln_task.write(debug_root / "vulnerable")
        fixed_dir = fixed_task.write(debug_root / "fixed")
        return token, debug_root, vuln_dir, fixed_dir, vuln_base, fixed_base

    def _build_log_tail(self, exc: TaskError, variant: str) -> str:
        """Read the failing build log so the agent sees the real error."""
        log_path = str((exc.detail or {}).get("log") or "")
        candidates = [Path(log_path)] if log_path else []
        log_dir = self.store.path("build-logs") / f"debug-{variant}"
        if log_dir.is_dir():
            candidates.extend(
                sorted(
                    log_dir.glob("build-*.log"),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )
            )
        for path in candidates:
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8", errors="replace")[-8000:]
            except OSError:
                continue
        return ""

    def _trial_log_tail(self, trial) -> str:
        """The Harbor trial log for a target that never became healthy."""
        trial_dir = Path(getattr(trial, "trial_dir", ""))
        for name in ("trial.log", "exception.txt"):
            path = trial_dir / name
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8", errors="replace")[-8000:]
            except OSError:
                continue
        return ""

    def _repair_build_run(self, state) -> dict:
        """Build both variants without running the verifier.

        This is the packaging tool. It is cheaper than a full verifier run and
        gives the author the exact Docker output instead of a prose summary.
        """
        spec, synthesis, overrides = self._repair_part(state)
        token, debug_root, vuln_dir, fixed_dir, vuln_base, fixed_base = (
            self._render_repair_pair(spec, synthesis, overrides)
        )
        ledger = self._ledger()
        reservation = f"{self.cve_id}-repair-build-{token}"
        try:
            ledger.reserve(reservation, {"builds": 6}, reuse=True)
        except PipelineError as exc:
            shutil.rmtree(debug_root, ignore_errors=True)
            raise TaskError("budget_exhausted", str(exc)) from exc
        builds: dict[str, dict] = {}
        try:
            for variant, task_dir, base in (
                ("vulnerable", vuln_dir, vuln_base),
                ("fixed", fixed_dir, fixed_base),
            ):
                try:
                    builds[variant] = build_task_images(
                        task_dir=task_dir,
                        variant=variant,
                        revision=self.store.load().revision,
                        tag_base=base,
                        log_dir=self.store.path("build-logs") / f"debug-{variant}",
                        timeout_sec=self.config.pipeline.command_timeout_sec,
                        harbor_version=self.capabilities.harbor_version,
                    )
                except TaskError as exc:
                    ledger.refund(reservation)
                    return {
                        "ok": False,
                        "status": "build_error",
                        "variant": variant,
                        "error": str(exc)[-2000:],
                        "log_tail": self._build_log_tail(exc, variant),
                    }
            # Building is not enough: the target must start. This turns a
            # missing runtime import or a bad start command into a build log
            # the agent can read, instead of an opaque "trial missing" error.
            for variant, build in builds.items():
                try:
                    preflight_target(
                        build["images"]["target"]["image_ref"],
                        log_path=self.store.path("build-logs")
                        / f"preflight-debug-{variant}.log",
                        timeout_sec=min(
                            120, self.config.pipeline.command_timeout_sec
                        ),
                    )
                except TaskError as exc:
                    ledger.refund(reservation)
                    return {
                        "ok": False,
                        "status": "target_error",
                        "variant": variant,
                        "error": str(exc)[-5000:],
                        "log_tail": self._build_log_tail(exc, variant),
                    }
            return {"ok": True, "status": "built_and_started"}
        except Exception:
            ledger.refund(reservation)
            raise
        else:
            ledger.commit(reservation, {"builds": 6})
        finally:
            shutil.rmtree(debug_root, ignore_errors=True)
            # Keep only this build's images: the exec tool inspects the last
            # built vulnerable target, and older sets are pruned immediately.
            self._replace_repair_images(
                [vuln_base, fixed_base],
                {
                    variant: build["images"]["target"]["image_ref"]
                    for variant, build in builds.items()
                    if build.get("images", {}).get("target", {}).get("image_ref")
                },
            )

    def _repair_registry_lookup(self, ecosystem: str, name: str) -> dict:
        """Query a public registry through the configured allowlisted fetcher."""
        return registry_mod.lookup(ecosystem, name, self.config.sources)

    def _repair_inspect_package(self, state, name: str) -> dict:
        """Resolve an installed dependency and print its real exports.

        Node modules are frequently symlinked (npm workspaces, pnpm), so a
        guessed ``lib/...`` path can miss the installed tree entirely. This
        runs the ecosystem's own resolver and lists what the package actually
        exports, which is what the author needs to call the right API.
        """
        import re

        if not re.fullmatch(r"[A-Za-z0-9._@/:-]+", name):
            return {"exit": 2, "output": "unsafe package name"}
        product = {}
        try:
            product = state.spec.get("product") or {}
        except AttributeError:
            product = {}
        ecosystem = str(product.get("ecosystem") or "")
        if not ecosystem:
            ecosystem = str(((state.bundle or {}).get("product") or {}).get("ecosystem") or "")
        if ecosystem == "npm":
            command = (
                "set +e; PKG='" + name + "'; "
                "echo '== resolve'; readlink -f \"/opt/app/node_modules/$PKG\" 2>/dev/null; "
                "echo '== files'; find -L \"/opt/app/node_modules/$PKG\" -maxdepth 3 "
                "-type f 2>/dev/null | head -60; "
                "echo '== package.json'; cat \"/opt/app/node_modules/$PKG/package.json\" "
                "2>/dev/null | head -60; "
                "echo '== exports'; cd /opt/app && node -e \"const m=require('$PKG'); "
                "console.log(Object.keys(m)); if (m && m.default) "
                "console.log('default:', Object.keys(m.default));\" 2>&1 | head -40"
            )
        elif ecosystem == "pypi":
            module = name.replace("-", "_")
            command = (
                "set +e; MOD='" + module + "'; "
                "echo '== module'; python -c \"import importlib;"
                "m=importlib.import_module('$MOD');"
                "print('file:', getattr(m,'__file__',None));"
                "print('exports:', [x for x in dir(m) if not x.startswith('_')])\" "
                "2>&1 | head -40; "
                "echo '== files'; find /usr/local/lib/python*/site-packages "
                f"-maxdepth 3 -iname '*{module}*' 2>/dev/null | head -40"
            )
        elif ecosystem == "go":
            command = (
                "set +e; cd /opt/app 2>/dev/null; "
                "echo '== go doc'; go doc '" + name + "' 2>&1 | head -60; "
                "echo '== module dirs'; find /go/pkg/mod -maxdepth 6 -type d "
                f"-path '*{name}*' 2>/dev/null | head -20"
            )
        elif ecosystem == "maven":
            artifact = name.split(":")[-1]
            command = (
                "set +e; echo '== jars'; find /root/.m2 /usr/share/maven-repo "
                f"-name '*.jar' 2>/dev/null | grep -i '{artifact}' | head -20"
            )
        else:
            return {"exit": 2, "output": f"unsupported ecosystem {ecosystem!r}"}
        image = self._repair_images.get("vulnerable")
        if not image:
            return {
                "exit": -1,
                "no_image": True,
                "output": "No vulnerable target image has been built yet. Call "
                          "`build` first, then retry the inspection.",
            }
        result = run_in_image(
            image, command, timeout=60, log_path=self.store.path("repair-inspect.log")
        )
        result["note"] = (
            "This ran in the last built vulnerable image. If you changed files "
            "after that build, call `build` before trusting these results."
        )
        return result

    def _cleanup_repair_images(self) -> None:
        """Drop the debug images kept alive for the exec tool."""
        for base in dict.fromkeys(self._repair_prune_bases):
            try:
                prune_task_images(base)
            except Exception:  # noqa: BLE001 - cleanup must not mask a verdict
                pass
        self._repair_prune_bases = []
        self._repair_images = {}

    def _replace_repair_images(
        self, bases: list[str], images: dict[str, str]
    ) -> None:
        """Swap in the newest debug image set and prune the previous one."""
        self._cleanup_repair_images()
        self._repair_prune_bases = list(bases)
        self._repair_images = dict(images)

    def _repair_exec_run(self, state, command: str, timeout: int) -> dict:
        """Run a bounded command in the last built vulnerable target image."""
        image = self._repair_images.get("vulnerable")
        if not image:
            return {
                "exit": -1,
                "no_image": True,
                "output": "No vulnerable target image has been built yet. Call "
                          "`build` first, then retry the inspection.",
            }
        result = run_in_image(
            image,
            command,
            timeout=timeout,
            log_path=self.store.path("repair-exec.log"),
        )
        result["note"] = (
            "This ran in the last built vulnerable image. If you changed files "
            "after that build, call `build` before trusting these results."
        )
        return result

    def _debug_repair_run(self, state) -> dict:
        """Execute one T03+T04 pair for the repairer's current authoring state.

        Both variants are rendered from the patched spec and bundle plus the
        file edits, and run with the same oracle and verifier as the real
        matrix. Success requires the vulnerable build to reach the secret AND
        the fixed build to hold. Nothing from this run enters the candidate's
        evidence; a passing pair is re-run by the full matrix at the new
        revision.
        """
        spec, synthesis, overrides = self._repair_part(state)
        token, debug_root, vuln_dir, fixed_dir, vuln_base, fixed_base = (
            self._render_repair_pair(spec, synthesis, overrides)
        )
        ledger = self._ledger()
        reservation = f"{self.cve_id}-debug-{token}"
        try:
            ledger.reserve(reservation, {"builds": 6, "trials": 2}, reuse=True)
        except PipelineError as exc:
            shutil.rmtree(debug_root, ignore_errors=True)
            raise TaskError("budget_exhausted", str(exc)) from exc
        built: dict[str, dict] = {}
        try:
            for variant, task_dir, base in (
                ("vulnerable", vuln_dir, vuln_base),
                ("fixed", fixed_dir, fixed_base),
            ):
                try:
                    built[variant] = build_task_images(
                        task_dir=task_dir,
                        variant=variant,
                        revision=self.store.load().revision,
                        tag_base=base,
                        log_dir=self.store.path("build-logs") / f"debug-{variant}",
                        timeout_sec=self.config.pipeline.command_timeout_sec,
                        harbor_version=self.capabilities.harbor_version,
                    )
                except TaskError as exc:
                    ledger.refund(reservation)
                    return {
                        "ok": False,
                        "status": "build_error",
                        "fixed_status": "build_error",
                        "variant": variant,
                        "error": str(exc)[-2000:],
                        "log_tail": self._build_log_tail(exc, variant),
                    }
            # Sequential on purpose: two debug trials at once plus the matrix
            # workers exhausted the host's memory on a 20 GB Docker VM.
            outcome = self.adapter.run(
                [vuln_dir, fixed_dir],
                agent="oracle",
                job_name=f"{self.cve_id.lower()}-debug",
                n_concurrent=1,
                timeout_sec=max(900, self.config.pipeline.command_timeout_sec * 3),
            )
            by_path = outcome.by_task_path()
            trials = {
                "vulnerable": by_path.get(str(vuln_dir.resolve()).casefold()),
                "fixed": by_path.get(str(fixed_dir.resolve()).casefold()),
            }
            if any(trial is None for trial in trials.values()):
                raise TaskError("infra_error", "Debug job did not return both variants")
            for label, trial in trials.items():
                if trial.evidence_status in {"target_unhealthy", "missing", "verifier_error"}:
                    # Do not turn a startup failure into an opaque infra
                    # exception. The trial log is the evidence the agent needs
                    # to fix the import, the start command or the app.
                    ledger.refund(reservation)
                    return {
                        "ok": False,
                        "status": (
                            "target_error"
                            if trial.evidence_status == "target_unhealthy"
                            else trial.evidence_status
                        ),
                        "variant": label,
                        "error": (
                            f"{label} trial failed before scoring: "
                            f"{trial.evidence_status}"
                        ),
                        "log_tail": self._trial_log_tail(trial),
                    }
            vuln = dict(trials["vulnerable"].evidence or {})
            fixed = dict(trials["fixed"].evidence or {})
            vulnerable_ok = vuln.get("status") == "goal_passed"
            fixed_ok = (
                fixed.get("status") == "fixed_variant_holds"
                and bool(fixed.get("health_ok"))
                and float(fixed.get("reward") or 0.0) == 0.0
            )
            return {
                "ok": vulnerable_ok and fixed_ok,
                "status": vuln.get("status"),
                "reference_exit": vuln.get("reference_exit"),
                "reference_error": vuln.get("reference_error"),
                "reference_stdout": vuln.get("reference_stdout"),
                "submitted_exit": vuln.get("submitted_exit"),
                "submitted_observed": vuln.get("submitted_observed"),
                "marker_present": vuln.get("marker_present"),
                "marker_matches_reference": vuln.get("marker_matches_reference"),
                "fixed_status": fixed.get("status"),
                "fixed_health_ok": fixed.get("health_ok"),
                "fixed_reference_error": fixed.get("reference_error"),
            }
        except Exception:
            ledger.refund(reservation)
            raise
        else:
            ledger.commit(reservation, {"builds": 6, "trials": 2})
        finally:
            shutil.rmtree(debug_root, ignore_errors=True)
            self._replace_repair_images(
                [vuln_base, fixed_base],
                {
                    variant: build["images"]["target"]["image_ref"]
                    for variant, build in built.items()
                    if build.get("images", {}).get("target", {}).get("image_ref")
                },
            )

    def _ledger(self):
        from .budget import Ledger

        if self._ledger_obj is not None:
            return self._ledger_obj
        # Every repair reruns the whole differential matrix at a new revision,
        # so the trial ceiling must cover one matrix per repair attempt plus the
        # original run. A flat multiplier here would quarantine a candidate for
        # a budget that the repair loop itself needs.
        mandatory = len([
            experiment
            for experiment in load_experiments()
            if experiment.id not in {"T03", "T04", "T09"}
        ])
        # A synthesized task may raise the repeat count above the profile floor,
        # and the reservation is taken before the bundle is visible here, so the
        # ceiling has to assume the largest count the schema permits.
        repeats = max(self.profile.trials, MAX_MATRIX_REPEATS)
        per_matrix = mandatory + 2 * repeats + 3
        repairs = max(0, self.config.pipeline.max_repairs)
        # ``max_calls`` and ``max_total_tokens`` are per-candidate ceilings, but
        # the ledger is per run: a repair launches another synthesis plus up to
        # three JSON retries, so the model budget must scale with the repair
        # loop instead of being spent once by the first candidate.
        limits = {
            # A repair agent may run the paired verifier up to
            # MAX_VERIFIER_RUNS times.
            "trials": float(
                max(
                    60,
                    per_matrix * (repairs + 1)
                    + 2 * MAX_VERIFIER_RUNS * repairs + 10,
                )
            ),
            # Both variants are built per revision (agent/target/verifier each).
            # Each build or verifier tool call builds six more images for the
            # pair; the ceiling covers both tool budgets.
            "builds": float(
                6 * (repairs + 1)
                + 6 * (MAX_VERIFIER_RUNS + MAX_BUILD_RUNS) * repairs
                + 4
            ),
            "wall_sec": 7200.0,
            "calls": float(self.config.pipeline.max_calls * (repairs + 2)),
            "tokens": float(self.config.pipeline.max_total_tokens * (repairs + 1)),
            "usd": float(self.config.models["default"].max_budget_usd * (repairs + 2)),
        }
        return Ledger.load_or_create(self.root / "budget.json", limits=limits)

    # -- stages ------------------------------------------------------------

    def collect(self, job=None) -> dict:
        job = job or self.store.create()
        if self.auto:
            return self._collect_auto(job)
        if self.store.state_path.exists():
            try:
                existing = self.store.read_artifact("evidence-index.json")
            except PipelineError:
                existing = None
            complete = existing and all(
                source.get("status") == "ok"
                for source in existing.get("sources", [])
            )
            if existing and existing.get("cve_id") == self.cve_id and complete:
                if job.state == "DISCOVERED":
                    self.store.transition(job, "EVIDENCE_READY", "evidence loaded from checkpoint")
                return existing
        collector = EvidenceCollector(self.config.sources, self.store.root)
        evidence = collector.collect(self.cve_id, source_plan(self.builtin))
        validate("evidence-index", evidence)
        self.store.write_artifact("evidence-index.json", evidence)
        failed = [
            source["id"] for source in evidence.get("sources", [])
            if source.get("status") != "ok"
        ]
        if failed:
            raise TaskError(
                "source_error",
                "Source fetch failed for " + ", ".join(failed),
                detail={"failed_sources": failed},
            )
        job = self.store.load()
        if job.state == "DISCOVERED":
            self.store.transition(job, "EVIDENCE_READY", "sources fetched")
        return evidence

    def _collect_auto(self, job) -> dict:
        """Discover sources for any CVE id and checkpoint the parsed facts."""
        existing = None
        if self.store.state_path.exists():
            try:
                existing = self.store.read_artifact("evidence-index.json")
            except PipelineError:
                existing = None
        if existing and existing.get("cve_id") == self.cve_id and _auto_evidence_complete(existing):
            try:
                self.discovery = discovery_mod.load(self.store.root, self.cve_id)
            except (PipelineError, OSError):
                self.discovery = None
            if self.discovery is not None:
                if job.state == "DISCOVERED":
                    self.store.transition(
                        job, "EVIDENCE_READY", "evidence loaded from checkpoint"
                    )
                return existing

        evidence, parsed = discovery_mod.collect(
            self.config.sources, self.store.root, self.cve_id
        )
        validate("evidence-index", evidence)
        self.store.write_artifact("evidence-index.json", evidence)
        self.store.write_artifact("discovery.json", parsed.to_json())
        self.discovery = parsed
        job = self.store.load()
        if job.state == "DISCOVERED":
            self.store.transition(job, "EVIDENCE_READY", "sources discovered")
        if not parsed.vulnerable_ref or not parsed.fixed_ref:
            raise TaskError(
                "unsupported",
                "No concrete vulnerable/fixed release pair could be derived from "
                "public records; a differential task cannot be built.",
                detail={"discovery": parsed.to_json()},
            )
        if not parsed.fix_commit or not parsed.fix_source_id:
            raise TaskError(
                "unsupported",
                "No public upstream fix commit could be fetched, so the root cause "
                "cannot be tied to a real fix.",
                detail={"discovery": parsed.to_json()},
            )
        return evidence

    def draft(self, evidence: dict):
        """Generate the initial task-bundle draft; resume from disk when possible.

        This is deliberately a completion-only draft generator, not the
        verified author. The fixed pipeline tests the draft immediately:
        ``build`` starts the target and the first T03/T04 pair is the draft
        gate. A failure there goes to the tool-using repair agent; only a
        passing pair proceeds to the rest of the matrix.
        """
        if not self.auto:
            return None
        if self.synthesis is not None:
            return self.synthesis
        try:
            self.synthesis = synthesis_mod.load(self.store.root, self.cve_id)
            return self.synthesis
        except TaskError:
            raise
        except (PipelineError, OSError):
            pass
        if self.discovery is None:
            self.discovery = discovery_mod.load(self.store.root, self.cve_id)
        engine = synthesis_mod.Synthesizer(
            self.config, self._ledger(), role="synthesizer"
        )
        result = engine.synthesize(
            cve_id=self.cve_id,
            evidence=evidence,
            discovery=self.discovery,
            run_dir=self.store.root,
        )
        self.synthesis = result
        self.store.write_artifact("synthesis.json", result.to_json())
        return result

    # Backwards-compatible alias for callers written before the step was
    # renamed to "draft generation".
    synthesize = draft

    def freeze(self, evidence: dict, job=None) -> dict:
        job = job or self.store.load()
        try:
            existing = self.store.read_artifact("cve-spec.json")
        except PipelineError:
            existing = None
        if existing and existing.get("frozen_digest"):
            job = self.store.load()
            if job.state == "EVIDENCE_READY":
                self.store.transition(job, "SPEC_FROZEN", "frozen spec resumed")
            return existing
        if self.auto:
            if self.synthesis is None:
                self.draft(evidence)
            raw = synthesis_mod.build_spec(
                self.synthesis,
                evidence=evidence,
                discovery=self.discovery,
                artifact_identity_value=discovery_mod.artifact_identity(
                    evidence,
                    self.store.root,
                    product=self.synthesis.product["name"],
                    vulnerable_ref=self.synthesis.versions["vulnerable_ref"],
                ),
                policy_version=self.policy.policy_version,
            )
        else:
            identity = artifact_identity_from_evidence(self.builtin, evidence, self.store.root)
            raw = raw_spec(self.builtin, evidence, identity)
        spec = freeze(raw, self.policy.policy_version)
        issues = check_evidence_links(spec, evidence) + check_spec_consistency(spec)
        if issues:
            raise TaskError("evidence_insufficient", "; ".join(issues), detail={"issues": issues})
        self.store.write_artifact("cve-spec.json", spec)
        job = self.store.load()
        if job.state == "EVIDENCE_READY":
            self.store.transition(job, "SPEC_FROZEN", "facts frozen")
        return spec

    def generate(self, spec: dict, job=None) -> tuple[GeneratedTask, Path]:
        job = job or self.store.load()
        task_dir = self.store.path("task")
        if job.state == "GENERATED" or (job.state in {"BUILT", "VALIDATING", "VALIDATED", "RELEASED"}):
            manifest = self.store.read_artifact("task-manifest.json")
            if task_dir.is_dir() and _tree_digest(task_dir) == manifest.get("tree_digest"):
                task = render_task(
                    spec,
                    scenario_name=self.scenario,
                    variant="vulnerable",
                    probe="reference",
                    network_mode=self.network_mode,
                    overrides=self._task_overlay(),
                    synthesis=self.synthesis,
                )
                if task.task_digest == manifest.get("task_digest"):
                    return task, task_dir
                raise TaskError(
                    "generation_error",
                    "Frozen spec no longer renders the recorded task; invalidate the candidate",
                )
        task = render_task(
            spec,
            scenario_name=self.scenario,
            variant="vulnerable",
            probe="reference",
            network_mode=self.network_mode,
            overrides=self._task_overlay(),
            synthesis=self.synthesis,
        )
        task.write(self.store.root)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "cve_id": spec["cve_id"],
            "task_digest": task.task_digest,
            "spec_digest": spec["frozen_digest"],
            "scenario": self.scenario,
            "generation_mode": "synthesized" if task.synthesis_digest else "template",
            "synthesis_digest": task.synthesis_digest,
            "tree_digest": _tree_digest(task_dir),
            "files": sorted(task.files),
        }
        self.store.write_artifact("task-manifest.json", manifest)
        job = self.store.load()
        if job.state in {"SPEC_FROZEN", "REPAIRING"}:
            self.store.transition(job, "GENERATED", "task rendered")
        return task, task_dir

    def build(self, spec: dict, task: GeneratedTask, job=None) -> dict:
        job = job or self.store.load()
        if job.state in {"BUILT", "VALIDATING", "VALIDATED", "RELEASED"}:
            try:
                image_set = self.store.read_artifact("image-set.json")
                if image_set.get("target_digest"):
                    return image_set
            except PipelineError:
                pass
        ledger = self._ledger()
        # Both variants are prebuilt: the matrix probes pin these tags, so
        # Harbor never runs `docker compose build` per trial.
        vulnerable_base = image_tag_base(self.cve_id, "vulnerable", job.revision)
        fixed_base = image_tag_base(self.cve_id, "fixed", job.revision)
        try:
            ledger.reserve(
                f"{self.cve_id}-build-{job.revision}", {"builds": 6}, reuse=True
            )
        except PipelineError as exc:
            raise TaskError("budget_exhausted", str(exc)) from exc
        try:
            vulnerable = build_task_images(
                task_dir=self.store.path("task"),
                variant="vulnerable",
                revision=job.revision,
                tag_base=vulnerable_base,
                log_dir=self.store.path("build-logs"),
                timeout_sec=self.config.pipeline.command_timeout_sec,
                harbor_version=self.capabilities.harbor_version,
            )
            try:
                fixed_task = render_task(
                    spec,
                    scenario_name=self.scenario,
                    variant="fixed",
                    probe="reference",
                    network_mode=self.network_mode,
                    allowed_hosts=("target",),
                    overrides=self._task_overlay(),
                    synthesis=self.synthesis,
                    revision=job.revision,
                )
            except PipelineError as exc:
                raise TaskError(
                    "generation_error",
                    f"Fixed variant could not be rendered: {exc}",
                ) from exc
            fixed_dir = self.store.path("fixed-build")
            if fixed_dir.exists():
                shutil.rmtree(fixed_dir)
            fixed_task.write(fixed_dir)
            fixed = build_task_images(
                task_dir=fixed_dir / "task",
                variant="fixed",
                revision=job.revision,
                tag_base=fixed_base,
                log_dir=self.store.path("build-logs") / "fixed",
                timeout_sec=self.config.pipeline.command_timeout_sec,
                harbor_version=self.capabilities.harbor_version,
            )
        except Exception:
            ledger.refund(f"{self.cve_id}-build-{job.revision}")
            raise
        ledger.commit(f"{self.cve_id}-build-{job.revision}", {"builds": 6})
        image_set = {
            **vulnerable,
            "tag_bases": [vulnerable_base, fixed_base],
            "variants": {"vulnerable": vulnerable, "fixed": fixed},
        }
        if self.auto:
            # The synthesized target must start before the matrix charges for
            # 40+ trials. A missing runtime import otherwise makes every trial
            # fail as an infrastructure error, which is not repairable; this
            # check turns it into a build_error the repair loop can act on.
            preflight_target(
                image_set["images"]["target"]["image_ref"],
                log_path=self.store.path("build-logs")
                / f"preflight-r{job.revision}.log",
                timeout_sec=min(120, self.config.pipeline.command_timeout_sec),
            )
        self.store.write_artifact("image-set.json", image_set)
        job = self.store.load()
        if job.state == "GENERATED":
            self.store.transition(job, "BUILT", "images built")
        return image_set

    def validate(
        self,
        spec: dict,
        evidence: dict,
        task: GeneratedTask,
        image_set: dict,
        job=None,
    ) -> tuple[MatrixResult, EvaluationOutcome]:
        job = job or self.store.load()
        if job.state in {"VALIDATING", "VALIDATED", "RELEASED"}:
            try:
                evaluation = self.store.read_artifact("evaluation.json")
                trials = self.store.read_artifact("trials.json")
                outcome = _reload_evaluation(evaluation)
                return _ReloadedMatrix(trials), outcome  # type: ignore[return-value]
            except PipelineError:
                pass
        job = self.store.load()
        if job.state == "BUILT":
            job = self.store.transition(job, "VALIDATING", "differential matrix started")
        artifact_digest = image_set["target_digest"]
        # T05/T06/T07/T10 feed fixed payloads to the shared verifier, so their
        # result does not depend on the candidate's application. Run them once
        # against a stub target on the host instead of starting a container
        # per candidate; a failure here means the grader itself is broken.
        framework_checks = verifier_regression_checks(
            spec, synthetic=self.synthesis is not None
        )
        # Framework health is not a task defect. A negative probe that is
        # accepted, or a verifier that crashes, means the grader is broken;
        # raise an infra error instead of asking the repair agent to rewrite a
        # task that the verifier cannot score.
        for experiment_id in ("T05", "T06", "T07", "T10"):
            check = framework_checks.get(experiment_id) or {}
            status = str(check.get("status") or "")
            reward = float(check.get("reward") or 0.0)
            if status not in {"goal_failed", "artifact_missing"} or reward != 0.0:
                raise TaskError(
                    "infra_error",
                    f"framework verifier health check {experiment_id} failed: "
                    f"status={status!r} reward={reward}",
                )
        # The author may raise the count when the exploit path is genuinely
        # nondeterministic; the profile value is the floor.
        repeats = self._matrix_repeats()
        # Each rung is its own Harbor job. Blocking rungs stop the ladder on
        # the first failure, so a candidate that cannot pass T03 never pays for
        # T04, the negative probes, the repeats, or the seed rebuilds.
        all_steps = plan_matrix_steps(repeats=repeats, include_optional=True)
        # The first two rungs (T03-first, T04-first) are the draft gate. They
        # test the synthesized draft before any repeats or negatives. A failure
        # here is a draft defect: _matrix_repair_error hands the evidence to
        # the tool-using repair agent. Only a passing pair proceeds to
        # confirm/seeds/T11/T12, which are the release gate.
        blocking_steps = [step for step in all_steps if step.blocking]
        advisory_steps = [step for step in all_steps if not step.blocking]
        matrix_root = self.store.path("matrix")
        if matrix_root.exists():
            shutil.rmtree(matrix_root)
        matrix_root.mkdir(parents=True, exist_ok=True)
        rendered: list[MatrixCase] = []
        ledger = self._ledger()

        def run_step(step):
            cases = build_step_cases(
                spec,
                step=step,
                scenario_name=self.scenario,
                root=matrix_root,
                network_mode=self.network_mode,
                allowed_hosts=("target",),
                overrides=self._task_overlay(),
                synthesis=self.synthesis,
                revision=job.revision,
            )
            rendered.extend(cases)
            reservation = f"{self.cve_id}-trials-{job.revision}-{step.key}"
            try:
                ledger.reserve(reservation, {"trials": len(cases)}, reuse=True)
            except PipelineError as exc:
                raise TaskError("budget_exhausted", str(exc)) from exc
            # A full batch makes each trial take four to five minutes of wall
            # clock; scale the ceiling with the real number of rounds.
            rounds = (len(cases) + max(1, self.workers) - 1) // max(1, self.workers)
            try:
                job_outcome = self.adapter.run(
                    [case.task_dir for case in cases],
                    agent="oracle",
                    job_name=f"{spec['cve_id'].lower()}-matrix-{step.key}",
                    n_concurrent=min(max(1, self.workers), len(cases)),
                    timeout_sec=max(
                        self.config.pipeline.command_timeout_sec,
                        360 * rounds + 1800,
                    ),
                )
            except Exception:
                ledger.refund(reservation)
                raise
            result = collate(
                job_outcome,
                cases,
                run_id=self.run_id,
                cve_id=spec["cve_id"],
                candidate_revision=job.revision,
                artifact_digest=artifact_digest,
            )
            ledger.commit(reservation, {"trials": len(result.records)})
            return result

        matrix = run_ladder(blocking_steps, run_step)
        seed_errors: list[str] = []
        if matrix.aborted_at is None:
            seed_records, seed_errors = run_seed_repeats(
                self.adapter,
                spec,
                scenario_name=self.scenario,
                root=matrix_root,
                network_mode=self.network_mode,
                allowed_hosts=("target",),
                run_id=self.run_id,
                candidate_revision=job.revision,
                artifact_digest=artifact_digest,
                repeats=3,
                n_concurrent=min(3, self.workers),
                overrides=self._task_overlay(),
                synthesis=self.synthesis,
                fail_fast=True,
            )
            matrix.records.extend(seed_records)
            if seed_errors:
                matrix.aborted_at = "t09-seeds"
                matrix.aborted_detail = "; ".join(seed_errors[:4])
                matrix.aborted_category = "infra_error"
        if matrix.aborted_at is None:
            # Advisory probes run only after every blocking rung passed. A
            # scored failure only lowers the quality score; a trial that never
            # produced a verdict is infrastructure and must be retried.
            for step in advisory_steps:
                result = run_step(step)
                if step.key == "t12":
                    # The fault-injected trial is *expected* to end in an
                    # infrastructure classification. Do not turn that expected
                    # error into a matrix abort; the T12 gate below decides
                    # whether it was classified correctly.
                    result.errors = []
                    matrix.merge(result)
                    continue
                matrix.merge(result)
                infra = [
                    verdict for verdict in result.verdicts
                    if not verdict.met
                    and verdict.error_category in {"infra_error", "build_error"}
                ]
                if result.errors or infra:
                    matrix.aborted_at = step.key
                    matrix.aborted_detail = "; ".join(
                        result.errors[:4]
                    ) or "; ".join(v.detail for v in infra[:4])
                    matrix.aborted_category = "infra_error"
                    break
        if matrix.aborted_at:
            # Surface the stop reason in the evaluation failures as well.
            matrix.errors.append(
                f"fail-fast: stopped at {matrix.aborted_at}: {matrix.aborted_detail}"
            )
        # T12 is a pipeline self-test: the fault-injected target must be
        # classified as an infrastructure failure. It is advisory in the
        # matrix ladder, but a failure here is a harness bug, not a task
        # quality signal; stop before evaluation and retry the pipeline.
        if matrix.aborted_at is None:
            fault = matrix.expectation("T12")
            if fault is None or not fault.met:
                raise TaskError(
                    "infra_error",
                    "framework fault-injection check T12 failed: "
                    + (fault.detail if fault else "missing"),
                )
        # Fold the framework-owned negative checks into the matrix so the
        # evaluator and the release audit keep the same shape as a trial.
        self._fold_framework_checks(
            matrix, spec, job, artifact_digest, framework_checks
        )
        # T01/T02 are the same health probe T03/T04 already performed.
        self._derive_health_verdicts(matrix, spec, job, artifact_digest)

        outcome = evaluate(
            spec=spec,
            evidence=evidence,
            matrix=matrix,
            image_set=image_set,
            policy=self.policy,
            profile_name=self.profile.name,
            package_issues=inspect_task(task.files, spec),
            network_isolation=self.network_mode,
            extra_seed_errors=seed_errors,
            skipped_experiments=(
                {"T08": "synthesized targets have no framework-owned controlled variant"}
                if self.auto else {}
            ),
        )
        # Record the effective count and the framework evidence on the result
        # itself so trials.json and the release audit agree.
        matrix.matrix_repeats = repeats
        matrix.framework_checks = {
            experiment_id: {
                "status": evidence.get("status"),
                "reward": evidence.get("reward"),
                "submitted_exit": evidence.get("submitted_exit"),
            }
            for experiment_id, evidence in framework_checks.items()
        }
        matrix_json = matrix.to_json()
        matrix_json["cases"] = case_manifest(rendered)
        if self.synthesis:
            reason = self.synthesis.bundle.get("matrix_repeats_reason")
            if reason:
                matrix_json["matrix_repeats_reason"] = reason
        self.store.write_artifact("trials.json", matrix_json)
        self.store.write_artifact("evaluation.json", outcome.evaluation)
        # Infrastructure and build failures are not task verdicts: classify
        # them before the candidate settles into a terminal state so the retry
        # and repair paths can still act.
        if matrix.aborted_category in {"infra_error", "build_error"}:
            raise TaskError(
                matrix.aborted_category,
                f"Differential matrix stopped at {matrix.aborted_at}: "
                f"{matrix.aborted_detail}",
            )
        job = self.store.load()
        if job.state == "VALIDATING":
            admission = outcome.evaluation["admission_status"]
            target_state = "QUARANTINED" if admission == "quarantined" else "VALIDATED"
            self.store.transition(
                job,
                target_state,
                f"quality={outcome.evaluation.get('quality_tier') or outcome.evaluation.get('quality_score')} admission={admission}",
            )
        return matrix, outcome

    def release(
        self,
        spec: dict,
        evidence: dict,
        task: GeneratedTask,
        image_set: dict,
        matrix: MatrixResult,
        outcome: EvaluationOutcome,
        job=None,
    ) -> dict:
        job = job or self.store.load()
        if job.state == "RELEASED":
            try:
                return self.store.read_artifact("release.json")
            except PipelineError:
                pass
        if outcome.evaluation["admission_status"] != "released":
            raise TaskError(
                "attribution_failure",
                "Release refused: " + "; ".join(outcome.evaluation["failure_reasons"][:5]),
                detail={"evaluation": outcome.evaluation},
            )
        result = build_release(
            spec=spec,
            evidence=evidence,
            evaluation=outcome.evaluation,
            matrix_result=matrix.to_json() if hasattr(matrix, "to_json") else matrix,
            task=task,
            task_dir=self.store.path("task"),
            image_set=image_set,
            run_dir=self.store.root,
            revision=job.revision,
            harbor_version=self.capabilities.harbor_version,
        )
        issues = verify_release(result.root, expected_digest=image_set["target_digest"])
        if issues:
            raise TaskError("grader_failure", "Release package failed recheck: " + "; ".join(issues))
        recheck = recheck_from_release(self.adapter, result.root, n_concurrent=self.workers)
        if recheck.get("reward") != 1.0:
            raise TaskError(
                "oracle_failure",
                f"Release recheck did not reproduce the goal: {recheck}",
                detail=recheck,
            )
        record = {**result.to_json(), "recheck": recheck}
        self.store.write_artifact("release.json", record)
        job = self.store.load()
        if job.state == "VALIDATED":
            self.store.transition(job, "RELEASED", "release package verified")
        return record

    # -- driver ------------------------------------------------------------

    def run(self, until: str = "release") -> PipelineReport:
        """Advance the candidate up to `until`; safe to call again to resume."""
        if until not in {"collect", "freeze", "generate", "build", "validate", "release"}:
            raise PipelineError(f"Unknown stage {until!r}")
        self.store.create()
        with self.store.lease:
            return self._run(until)

    def _run(self, until: str) -> PipelineReport:
        job = self.store.load()
        try:
            job = self._prepare_retry(job)
            if job.state in {"QUARANTINED", "UNSUPPORTED", "RELEASED"}:
                return self._stored_report(job)
            while True:
                try:
                    return self._advance(until)
                except TaskError as exc:
                    if not self._attempt_repair(exc):
                        raise
        except TaskError as exc:
            job = self.store.load()
            self.store.fail(job, exc)
            return self._stored_report(self.store.load())
        except PipelineError as exc:
            job = self.store.load()
            wrapped = TaskError("infra_error", str(exc))
            self.store.fail(job, wrapped)
            return self._stored_report(self.store.load())
        except Exception as exc:  # unexpected faults are infrastructure failures
            job = self.store.load()
            wrapped = TaskError("infra_error", f"{type(exc).__name__}: {exc}")
            self.store.fail(job, wrapped)
            return self._stored_report(self.store.load())

    def _advance(self, until: str) -> PipelineReport:
        job = self.store.load()
        evidence = self.collect(job)
        if until == "collect":
            return self._report(self.store.load(), None, None, None, None, None)
        if self.auto:
            self.draft(evidence)
        job = self.store.load()
        spec = self.freeze(evidence, job)
        if until == "freeze":
            return self._report(self.store.load(), None, None, None, None, None)
        job = self.store.load()
        task, _ = self.generate(spec, job)
        if until == "generate":
            return self._report(self.store.load(), task, None, None, None, None)
        job = self.store.load()
        image_set = self.build(spec, task, job)
        if until == "build":
            return self._report(self.store.load(), task, image_set, None, None, None)
        job = self.store.load()
        matrix, outcome = self.validate(spec, evidence, task, image_set, job)
        failure = self._matrix_repair_error(matrix, outcome)
        if failure is not None:
            # The target is up and the graders behave, but the reference exploit
            # reaches no secret. That is a defect in the synthesized application,
            # which lives under environment/ and is the repairer's to fix.
            raise failure
        if until == "validate":
            return self._report(
                self.store.load(), task, image_set, outcome, None, matrix
            )
        job = self.store.load()
        release = None
        if outcome.evaluation["admission_status"] == "released":
            release = self.release(spec, evidence, task, image_set, matrix, outcome, job)
            if until != "release":
                return self._report(
                    self.store.load(), task, image_set, outcome, release, matrix
                )
        job = self.store.load()
        return self._report(job, task, image_set, outcome, release, matrix)

    # -- bounded model repair ---------------------------------------------

    def _overlay(self) -> dict[str, str]:
        try:
            overlay = self.store.read_artifact("repair-overlay.json")
        except PipelineError:
            return {}
        if not isinstance(overlay, dict):
            raise PipelineError("repair-overlay.json is not an object")
        for name, body in overlay.items():
            if not isinstance(name, str) or not isinstance(body, str):
                raise PipelineError("repair overlay must map paths to text")
        return dict(overlay)

    def _task_overlay(self) -> dict[str, str]:
        """The overlay that may be applied to a rendered task.

        Older repair attempts were allowed to rewrite the framework-owned
        entrypoint and main compose files. Those edits are ignored: the
        entrypoint owns the secret lifecycle and the T12 fault switch, and the
        main Dockerfile/compose are framework wrappers.
        """
        return {
            name: body
            for name, body in self._overlay().items()
            if name not in FRAMEWORK_PATHS
        }

    def _repair_context(self, error: TaskError) -> str:
        """Harness-side facts for a build repair: log tail and real versions.

        The repairer cannot call tools or reach the network. This method gives
        it the failed build log and the published versions of the pinned
        dependencies, so it chooses a version that exists instead of guessing
        another nonexistent one.
        """
        if error.category.code != "build_error":
            return ""
        log_tail = ""
        log_path = str((error.detail or {}).get("log") or "")
        try:
            if log_path:
                log_tail = Path(log_path).read_text(
                    encoding="utf-8", errors="replace"
                )[-4000:]
            if not log_tail:
                logs = self.store.path("build-logs")
                candidates = [logs / "build-target.log"]
                if logs.is_dir():
                    candidates.extend(
                        sorted(
                            logs.glob("build-*.log"),
                            key=lambda path: path.stat().st_mtime,
                            reverse=True,
                        )
                    )
                for path in candidates:
                    if path.is_file():
                        log_tail = path.read_text(
                            encoding="utf-8", errors="replace"
                        )[-4000:]
                        break
        except OSError:
            log_tail = ""
        try:
            spec = self.store.read_artifact("cve-spec.json")
        except PipelineError:
            return (
                f"## Build failure log (tail)\n```\n{log_tail}\n```"
                if log_tail else ""
            )
        try:
            return registry_mod.build_context(
                spec=spec,
                task_dir=self.store.path("task"),
                settings=self.config.sources,
                log_tail=log_tail,
            )
        except Exception:  # noqa: BLE001 - registry lookup is best effort
            return (
                f"## Build failure log (tail)\n```\n{log_tail}\n```"
                if log_tail else ""
            )

    def _repair_engine(self):
        if self._repair is None:
            try:
                self._repair = RepairEngine(self.config, self._ledger(), role="repairer")
            except Exception as exc:  # noqa: BLE001 - repair is optional
                self._repair = False
                self._repair_error = str(exc)
        return self._repair or None

    def _task_files(self) -> dict[str, str]:
        """The authoring view of the task.

        Target files are shown as the bundle wrote them, so a package pin is
        still the ``{{REF}}`` placeholder rather than the vulnerable variant's
        substituted release. The harness substitutes the right ref per variant
        when it renders. Framework-owned files (the target Dockerfile, the
        secret entrypoint, the instruction) are shown as rendered. The verifier
        is not passed at all, so it cannot be edited and does not become a
        target the agent writes against.
        """
        root = self.store.path("task")
        if not root.is_dir():
            return {}
        overlay = self._task_overlay()
        try:
            self._ensure_synthesis()
        except (PipelineError, TaskError, OSError):
            pass
        rendered: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            if (
                name.startswith("environment/")
                or name == POC_PATH
                or name == "instruction.md"
            ):
                rendered[name] = path.read_text(encoding="utf-8")
        raw_target: dict[str, str] = {}
        if self.synthesis is not None:
            for name, body in (self.synthesis.target.get("files") or {}).items():
                # The Dockerfile is post-processed by the generator (apt retry
                # wrapper and the synthesis layer); editing the raw copy would
                # silently drop those. The entrypoint is generated from
                # start_command. Both stay rendered.
                if name in {"Dockerfile", "entrypoint.sh"}:
                    continue
                raw_target[f"environment/target/{name}"] = body
        files: dict[str, str] = {}
        for name, body in rendered.items():
            base = raw_target.get(name, body)
            files[name] = base if name in FRAMEWORK_PATHS else overlay.get(name, base)
        for name, body in raw_target.items():
            if name not in files:
                files[name] = overlay.get(name, body)
        for name, body in overlay.items():
            if (
                name not in files
                and name not in FRAMEWORK_PATHS
                and (name.startswith("environment/") or name == POC_PATH)
            ):
                files[name] = body
        return files

    def _reference_poc(self) -> str | None:
        """Read the trusted exploit as read-only repair context."""
        path = self.store.path("task", "tests", "reference_poc.py")
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _repair_log(self) -> list[dict]:
        try:
            log = self.store.read_artifact("repair-log.json")
        except PipelineError:
            return []
        return list(log) if isinstance(log, list) else []

    def _matrix_repair_error(
        self, matrix: MatrixResult, outcome: EvaluationOutcome
    ) -> TaskError | None:
        """Return a repairable error when only the app logic failed the matrix.

        The signature is narrow on purpose. Healthy vulnerable and fixed
        targets plus negatives that were scored and rejected mean packaging,
        verifier and oracle plumbing all work; if the reference exploit then
        reaches no secret, the defect is in the synthesized application.
        Everything else (missing trials, unhealthy targets, accepted negatives,
        sampling thresholds) is not the repairer's to fix: it may only edit
        ``environment/`` and never the tests or the instruction.

        A negative submission that never reaches scoring is different from an
        accepted one. When the app crashes every request, T05/T06/T07/T10 also
        end as ``oracle_failure`` with zero reward; that is the same broken
        interface that blocks T03, not evidence that the grader is too loose.
        """
        if outcome.evaluation["admission_status"] == "released":
            return None
        failed = {
            hc["id"]: hc["detail"]
            for hc in outcome.hard_conditions
            if not hc["passed"]
        }
        if not failed:
            return None
        finder = getattr(matrix, "expectation", None)
        t02 = finder("T02") if callable(finder) else None
        # T04 never runs when T03 fails, so a derived T02 is "missing", not
        # "unhealthy". That is not evidence against repair; only an observed
        # unhealthy fixed build rules it out.
        t02_unobserved = bool(
            t02 is not None and getattr(t02, "observed_status", "") == "missing"
        )
        if "t01_vulnerable_health" in failed or (
            "t02_fixed_health" in failed and not t02_unobserved
        ):
            return None
        negative_failures = [key for key in failed if key.startswith("negative_")]

        def observed(experiment_id: str) -> bool:
            finder = getattr(matrix, "record_for", None)
            if callable(finder):
                return finder(experiment_id) is not None
            return any(
                record.get("experiment_id") == experiment_id
                for record in matrix.records
            )

        # A fail-fast stop leaves later negatives unrun. Only a negative that
        # was actually observed can rule repair out; an unrun one is not
        # evidence that the grader accepts it.
        observed_negatives = [
            key for key in negative_failures
            if observed(key.removeprefix("negative_"))
        ]
        if observed_negatives and not all(
            self._negative_failed_to_execute(matrix, key)
            for key in observed_negatives
        ):
            return None
        if not {"reference_poc_all_success", "zero_fixed_success"} & failed.keys():
            return None
        lines = [f"{key}: {value}" for key, value in sorted(failed.items())]
        for record in matrix.records:
            if record["experiment_id"] not in {"T03", "T04"}:
                continue
            detail = self._trial_failure_detail(record)
            if detail:
                lines.append(f"{record['trial_id']}: {detail}")
        return TaskError(
            "validation_error",
            "Differential validation failed in the synthesized application. "
            + "; ".join(lines[:12]),
            detail={"failed_hard_conditions": failed},
        )

    @staticmethod
    def _negative_failed_to_execute(matrix: MatrixResult, condition_id: str) -> bool:
        """True when a negative submission crashed instead of being scored.

        ``oracle_failure`` with zero reward means the request produced no
        score at all; the app, not the grader, rejected it. A negative that
        reaches the goal has ``goal_result == "passed"`` and is a grader
        defect; one on an unhealthy target is a health defect. Neither is the
        repairer's to fix.
        """
        experiment_id = condition_id.removeprefix("negative_")
        records = [
            record for record in matrix.records
            if record["experiment_id"] == experiment_id
        ]
        return bool(records) and all(
            str(record["trigger_evidence"]["detail"]) == "oracle_failure"
            and (record.get("reward") or 0.0) == 0.0
            for record in records
        )

    def _trial_failure_detail(self, record: dict) -> str:
        """Describe a failed T03/T04 trial without echoing the secret."""
        if record["experiment_id"] == "T03" and record["goal_result"] == GOAL_PASSING:
            return ""
        status = str(record["trigger_evidence"]["detail"])
        held = (
            status == "fixed_variant_holds"
            and record["health"]["ok"]
            and (record.get("reward") or 0.0) == 0.0
        )
        if record["experiment_id"] == "T04" and held:
            return ""
        parts = [
            f"status={status}",
            f"healthy={record['health']['ok']}",
            f"goal={record['goal_result']}",
        ]
        evidence = self._read_trial_evidence(record)
        if evidence.get("status") == "oracle_failure":
            # The vulnerable reference run produced no token, so its stderr is
            # safe to quote: health passed and the exploit was rejected.
            message = str(evidence.get("reference_error") or "").strip()
            if message:
                parts.append(f"reference_stderr={message[-400:]!r}")
        return " ".join(parts)

    @staticmethod
    def _read_trial_evidence(record: dict) -> dict:
        path = str((record.get("_audit") or {}).get("evidence") or "")
        if not path:
            return {}
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _attempt_repair(self, error: TaskError) -> bool:
        """Try one bounded repair; return True when the pipeline may resume."""
        if error.category.code not in REPAIRABLE_CATEGORIES:
            return False
        job = self.store.load()
        used = int(job.attempts.get("repair", 0))
        if used >= self.config.pipeline.max_repairs:
            return False
        if not self.store.path("task").is_dir():
            return False
        try:
            self.store.read_artifact("cve-spec.json")
        except PipelineError:
            return False
        engine = self._repair_engine()
        if engine is None:
            return False
        files = self._task_files()
        overlay = self._overlay()
        self.store.fail(job, error)
        job = self.store.transition(
            self.store.load(), "REPAIRING", f"model repair {used + 1}"
        )
        job.revision += 1
        job.attempts["repair"] = used + 1
        self.store.save(job)
        self._repair_images = {}
        self._repair_prune_bases = []
        # A resume can enter repair before ``synthesize()`` has loaded the
        # bundle, so read the pinned release and the authoring bundle from disk
        # instead of assuming the in-memory attributes are populated.
        spec = self.store.read_artifact("cve-spec.json")
        pinned_ref = None
        try:
            self._ensure_synthesis()
            synthesis = self.synthesis or synthesis_mod.load(
                self.store.root, self.cve_id
            )
            pinned_ref = str(synthesis.versions.get("vulnerable_ref") or "") or None
            bundle = synthesis.bundle
        except (PipelineError, TaskError, OSError):
            synthesis = None
            bundle = {}
        try:
            result = engine.repair(
                cve_id=self.cve_id,
                revision=job.revision,
                error=error,
                spec=spec,
                bundle=bundle,
                files=files,
                previous=overlay,
                reference=self._reference_poc(),
                pinned_ref=pinned_ref,
                tools=RepairTools(
                    debug=self._debug_repair_run,
                    build=self._repair_build_run,
                    registry=self._repair_registry_lookup,
                    exec_image=self._repair_exec_run,
                    inspect_package=self._repair_inspect_package,
                    on_step=lambda entry: self._repair_trace_step(
                        used + 1, job.revision, entry
                    ),
                ),
                context=self._repair_context(error),
            )
        except TaskError as exc:
            self._append_repair_log(used + 1, error, files, model="unavailable", failure=str(exc))
            self.store.fail(self.store.load(), error)
            return False
        finally:
            self._cleanup_repair_images()
        self._append_repair_log(used + 1, error, files, result=result)
        if not (result.files or result.spec_changed or result.bundle_changed):
            # A provider outage or an unusable reply says nothing about the
            # candidate. Keep it retryable so a resume can try the repair
            # again; only a repair that ran and proposed nothing leaves the
            # original validation verdict in place.
            failure = (
                TaskError("infra_error", f"Repair provider failed: {result.error}")
                if result.error
                else error
            )
            self.store.fail(self.store.load(), failure)
            return False
        if result.spec_changed and result.spec:
            try:
                frozen = freeze(result.spec, self.policy.policy_version)
            except Exception as exc:  # noqa: BLE001 - schema or consistency
                failure = TaskError(
                    "generation_error",
                    f"Repair produced a spec that cannot be frozen: {exc}",
                )
                self.store.fail(self.store.load(), failure)
                return False
            self.store.write_artifact("cve-spec.json", frozen)
            spec = frozen
        if result.bundle_changed and result.bundle:
            base = synthesis or synthesis_mod.Synthesis(
                cve_id=self.cve_id,
                bundle=result.bundle,
                model_identity="repair",
                usage={},
                prompt_sha256="",
                generated_at="",
                digest=digest(result.bundle),
            )
            updated = synthesis_mod.Synthesis(
                cve_id=self.cve_id,
                bundle=result.bundle,
                model_identity=base.model_identity,
                usage=base.usage,
                prompt_sha256=base.prompt_sha256,
                generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                digest=digest(result.bundle),
            )
            self.store.write_artifact("synthesis.json", updated.to_json())
            self.synthesis = updated
        if result.files:
            overlay.update(result.files)
            self.store.write_artifact("repair-overlay.json", overlay)
        return True

    def _repair_trace_step(self, attempt: int, revision: int, entry: dict) -> None:
        """Append one live agent step so a long repair is observable."""
        path = self.store.path("repair-trace.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "attempt": attempt,
            "revision": revision,
            **entry,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")

    def _append_repair_log(self, attempt, error, files, *, result=None, model="", failure=None) -> None:
        from .repair import RepairResult

        entry = repair_log_entry(
            attempt=attempt,
            result=result or RepairResult({}, "", model or "unavailable", {}, failure),
            error=error,
            files_before=files,
        )
        log = self._repair_log()
        log.append(entry)
        self.store.write_artifact("repair-log.json", log)

    def _prepare_retry(self, job):
        """QUARANTINED jobs may only leave through REPAIRING.

        A transient failure is retried by resuming the stage that failed: the
        inputs are unchanged, so re-running them is the retry. A model-authored
        defect is different. Re-running the same files reproduces the same
        verdict, so a resume must first ask the repair model for another
        bounded change; otherwise a run that was interrupted just before its
        last allowed repair could never use it.
        """
        if job.state != "QUARANTINED":
            return job
        error = job.error or {}
        used = int(job.attempts.get("retry", 0))
        if used >= self.config.pipeline.max_repairs:
            return job
        category = str(error.get("category") or "")
        if not error.get("retryable") and category in REPAIRABLE_CATEGORIES:
            if int(job.attempts.get("repair", 0)) >= self.config.pipeline.max_repairs:
                return job
            job.attempts["retry"] = used + 1
            self.store.save(job)
            stored = TaskError(
                category,
                str(error.get("message") or "retry of an auto-repairable failure"),
                detail=dict(error.get("detail") or {}),
            )
            self._attempt_repair(stored)
            return self.store.load()
        if not error.get("retryable"):
            return job
        job.attempts["retry"] = used + 1
        self.store.save(job)
        return self.store.transition(
            job, "REPAIRING", f"retry {used + 1} after {error.get('category')}"
        )

    def _report(self, job, task, image_set, outcome, release, matrix) -> PipelineReport:
        evaluation = outcome.evaluation if outcome else None
        return PipelineReport(
            cve_id=self.cve_id,
            run_id=self.run_id,
            state=job.state,
            task_digest=task.task_digest if task else job.artifacts.get("task-manifest.json"),
            image_digest=(image_set or {}).get("target_digest"),
            quality_score=evaluation.get("quality_score") if evaluation else None,
            quality_tier=evaluation.get("quality_tier") if evaluation else None,
            admission_status=evaluation["admission_status"] if evaluation else None,
            release=release,
            evaluation=evaluation,
            trials=(matrix.records if matrix is not None and hasattr(matrix, "records") else []),
            error=job.error,
            budget=self._ledger().snapshot(),
        )

    def _stored_report(self, job) -> PipelineReport:
        """Report the best evidence available on disk without re-running stages."""

        def artifact(name: str):
            try:
                return self.store.read_artifact(name)
            except PipelineError:
                return None

        evaluation = artifact("evaluation.json")
        trials = artifact("trials.json") or {}
        manifest = artifact("task-manifest.json") or {}
        image_set = artifact("image-set.json") or {}
        release = artifact("release.json")
        return PipelineReport(
            cve_id=self.cve_id,
            run_id=self.run_id,
            state=job.state,
            task_digest=manifest.get("task_digest"),
            image_digest=image_set.get("target_digest"),
            quality_score=evaluation.get("quality_score") if evaluation else None,
            quality_tier=evaluation.get("quality_tier") if evaluation else None,
            admission_status=evaluation["admission_status"] if evaluation else None,
            release=release,
            evaluation=evaluation,
            trials=trials.get("records", []),
            error=None if job.state in {"VALIDATED", "RELEASED"} else job.error,
            budget=self._ledger().snapshot(),
        )


class _ReloadedMatrix:
    """Minimal MatrixResult stand-in when validation is resumed from disk."""

    def __init__(self, data: dict):
        self.payload = data
        self.records = data.get("records", [])

    def to_json(self) -> dict:
        return dict(self.payload)


def _reload_evaluation(data: dict) -> EvaluationOutcome:
    return EvaluationOutcome(evaluation=data, dimensions={}, hard_conditions=data.get("hard_conditions", []))


def _tree_digest(root: Path) -> str:
    from .util import tree_hashes

    return digest(tree_hashes(root))
