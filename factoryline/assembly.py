"""factoryline.assembly — line the Lego pieces up.

factoryline drives whichever modules are installed by shelling out to their CLIs.
It hard-depends on none of them. A missing module is simply a stud with nothing
plugged in — the chain reports it and continues with what's present. This is what
makes the factory portable: any IDE/agent/OS that can run a subprocess can drive it.
"""
from __future__ import annotations
import shutil
import subprocess
import json
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .contract import MODULES, STAGES, Meter, ensure_layout, Receipt
from .meter import MeterLog, StageTiming, stopwatch
from .attribution import Attribution, FailureClass
from .agent_contract import AgentContractError, validate_agent_contract
from .live_activity import LiveActivity


@dataclass
class ModuleStatus:
    name: str
    cli: str
    installed: bool
    role: str


def detect() -> list[ModuleStatus]:
    """Which Lego pieces are plugged in on this machine."""
    out = []
    for name, meta in MODULES.items():
        out.append(ModuleStatus(
            name=name, cli=meta["cli"],
            installed=shutil.which(meta["cli"]) is not None,
            role=meta["role"]))
    return out


def _run_cli(cli: str, args: list[str], cwd: Path, *, heartbeat: Callable[[], bool] | None = None) -> tuple[bool, str]:
    try:
        proc = subprocess.Popen([cli, *args], cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        started = time.monotonic()
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.25)
                # Parse structured evidence before truncating anything for the receipt.
                return proc.returncode == 0, stdout + stderr
            except subprocess.TimeoutExpired:
                if heartbeat is not None and heartbeat() is False:
                    proc.terminate()
                    try:
                        stdout, stderr = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        stdout, stderr = proc.communicate()
                    return False, "factory assembly stop requested through the local Studio\n" + stdout + stderr
                if time.monotonic() - started >= 300:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    return False, "factory stage timed out\n" + stdout + stderr
    except FileNotFoundError:
        return False, f"{cli} not installed"


def _attribution_from_output(output: str) -> dict | None:
    """Find a structured attribution block in a CLI's JSON output."""
    decoder = __import__("json").JSONDecoder()
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(output[offset:])
        except ValueError:
            continue
        if isinstance(payload, dict):
            raw = payload.get("attribution")
            if isinstance(raw, dict):
                Attribution.from_dict(raw)
                return raw
    return None


def _meter_from_output(output: str) -> tuple[Meter, bool]:
    """Read a module's standard meter block when its structured output supplies one.

    The wall-clock value remains FactoryLine's own local observation.  Model and
    token values are accepted only from a top-level ``meter`` block or a nested
    receipt envelope; otherwise they remain explicitly unreported.
    """
    decoder = json.JSONDecoder()
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(output[offset:])
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        raw = payload.get("meter")
        if raw is None and isinstance(payload.get("receipt"), dict):
            raw = payload["receipt"].get("meter")
        if not isinstance(raw, dict):
            continue
        try:
            values = {
                key: int(raw.get(key, 0))
                for key in ("model_calls", "tokens_in", "tokens_out")
            }
        except (TypeError, ValueError):
            continue
        if any(value < 0 for value in values.values()):
            continue
        return Meter(0, **values), True
    return Meter(), False


# The default pipeline: (module, cli-args-template). {f} = feature.
# Only stages whose module is installed run; UI stage runs only if smoke/<f>.ui exists.
DEFAULT_CHAIN = [
    ("specline",  ["strict", "{f}", "--json"]),
    ("specline",  ["verify-validators", "{f}", "--json"]),
    ("specline",  ["gate", "spec", "{f}"]),
    ("specline",  ["tasks", "{f}"]),
    ("specline",  ["gate", "plan", "{f}"]),
    ("forgeline", ["architect", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["review", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["arch-gate", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["verify-tests", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["smoke", "{f}"]),
    ("prestige",   ["score", "smoke/{f}.ui", "--json", "--strict"]),
    ("hsf",       ["compile", "specs/{f}.yaml"]),
    ("forgeline", ["ship", "{f}"]),
]


def _stage_order(module: str, stage: str) -> tuple[int, str, str]:
    """Return canonical pipeline order for a module stage.

    Receipt rollups can arrive in display order, filesystem timestamp order, or
    mixed legacy spellings. Failure diagnosis still follows pipeline order:
    instrument verification precedes trusting runtime smoke output.
    """
    normalized = stage.replace("_", "-")
    order = {
        (mod, args[0].replace("_", "-")): index
        for index, (mod, args) in enumerate(DEFAULT_CHAIN)
    }
    return (order.get((module, normalized), len(DEFAULT_CHAIN)), module, normalized)


def _ssat_contract(root: Path, feature: str) -> Path:
    """Resolve the supported SSAT locations without adopting a near match."""
    for path in (
        root / "specs" / f"{feature}.ssat.yaml",
        root / f"{feature}.ssat.yaml",
        root / f"{feature}.adoption.ssat.yaml",
    ):
        if path.is_file():
            return path
    return root / "specs" / f"{feature}.ssat.yaml"


def assemble(root: Path, feature: str, chain=None, dry_run: bool = False) -> dict:
    """Run the assembly line for a feature. Returns a per-stage report.
    Missing modules are skipped with a clear note (Lego stud left open)."""
    root = Path(root); ensure_layout(root)
    chain = chain or DEFAULT_CHAIN
    installed = {m.name: m for m in detect()}
    meterlog = MeterLog(root)
    run_id = uuid.uuid4().hex
    report = {"feature": feature, "root": str(root), "run_id": run_id, "stages": [], "dry_run": dry_run}
    activity = LiveActivity(root, run_id, feature, len(chain))
    activity.start()

    def finish_activity() -> None:
        terminal = "halted" if report.get("halted_at") else "waiting_for_human" if report.get("paused_at") else "completed"
        activity.finish(terminal, halted_at=report.get("halted_at"), paused_at=report.get("paused_at"))

    contract_path = root / ".factory" / "agent-contract.json"
    if contract_path.is_file():
        try:
            contract = validate_agent_contract(contract_path)
        except AgentContractError as exc:
            report["stages"].append({"module": "factoryline", "stage": "agent-contract", "status": "failed", "code": exc.code, "message": exc.message})
            activity.stage_finished("factoryline", "agent-contract", "failed")
            report["halted_at"] = "factoryline:agent-contract"
            finish_activity()
            return report
        report["agent_contract"] = {"path": str(contract_path), "digest": contract["contract_digest"], "marker": "AGENT_CONTRACT_BOUND"}
        report["stages"].append({"module": "factoryline", "stage": "agent-contract", "status": "ok", "marker": "AGENT_CONTRACT_BOUND"})
        activity.stage_finished("factoryline", "agent-contract", "ok")

    spec_path = root / "specs" / f"{feature}.md"
    if not dry_run and not spec_path.exists() and installed["specline"].installed:
        activity.stage_started("specline", "new")
        with stopwatch() as sw:
            ok, out = _run_cli(MODULES["specline"]["cli"], ["new", feature], root, heartbeat=activity.heartbeat)
        Receipt(module="specline", stage="new", feature=feature, ok=ok,
                outputs={"log_tail": out[-2000:]}).write(root)
        report["stages"].append({"module": "specline", "stage": "new",
                                 "status": "ok" if ok else "failed", "wall_ms": sw.wall_ms})
        activity.stage_finished("specline", "new", "ok" if ok else "failed", wall_ms=sw.wall_ms)
        if not ok:
            report["halted_at"] = "specline:new"
        else:
            report["paused_at"] = "author_spec"
            report["next_command"] = f"edit specs/{feature}.md and plans/{feature}.md, then rerun factory assemble {feature}"
        report["rollup"] = rollup_attributions(report["stages"])
        finish_activity()
        return report

    # ---------------------------------------------------------------------
    # CDTE — contradiction gate.
    #
    # Runs after the spec exists and before any build stage. Deliberately
    # model-free: constraints are read from a file that `factory cdte scan`
    # wrote, so assembly stays deterministic and offline. A spec with no
    # constraint file skips the gate rather than blocking on one.
    # ---------------------------------------------------------------------
    if not dry_run:
        cdte_outcome = _cdte_gate(root, feature)
        if cdte_outcome is not None:
            report["stages"].append(cdte_outcome["stage"])
            activity.stage_finished("factoryline", "cdte", "failed" if cdte_outcome["blocking"] else "ok")
            if cdte_outcome["blocking"]:
                report["cdte"] = cdte_outcome["summary"]
                report["paused_at"] = "nfr_conflict"
                report["next_command"] = (
                    f"factory cdte resolve {cdte_outcome['summary']['run_id']} "
                    f"<conflict-id> --decision ... --approved-by ..."
                )
                report["rollup"] = rollup_attributions(report["stages"])
                finish_activity()
                return report
            report["cdte"] = cdte_outcome["summary"]

    for module, args_tmpl in chain:
        cli = MODULES[module]["cli"]
        present = installed[module].installed
        args = [a.replace("{f}", feature) for a in args_tmpl]
        if module == "forgeline" and len(args) > 2 and args[2] == f"{feature}.ssat.yaml":
            args[2] = str(_ssat_contract(root, feature).relative_to(root))
        stage_name = args[0]
        if not present:
            report["stages"].append({"module": module, "stage": stage_name,
                                     "status": "skipped", "reason": f"{cli} not installed"})
            activity.stage_finished(module, stage_name, "skipped")
            continue
        if module == "prestige":
            ui_path = root / "smoke" / f"{feature}.ui"
            if not ui_path.is_file():
                report["stages"].append({"module": module, "stage": stage_name,
                                         "status": "skipped", "reason": "ui_scope_not_declared",
                                         "marker": "UI_PRESTIGE_GATE_NOT_APPLICABLE"})
                activity.stage_finished(module, stage_name, "skipped")
                continue
        if not dry_run and module == "forgeline" and stage_name == "architect":
            ssat = _ssat_contract(root, feature)
            state_path = root / ".forge" / feature / "state.json"
            state = None
            if state_path.exists():
                try:
                    state = json.loads(state_path.read_text(encoding="utf-8")).get("state")
                except (OSError, ValueError):
                    state = None
            if not ssat.exists():
                report["paused_at"] = "architecture_contract"
                report["next_command"] = f"write specs/{feature}.ssat.yaml, then run forge expand {feature}"
                activity.stage_finished(module, stage_name, "skipped")
                break
            if state in {None, "intent"}:
                activity.stage_started(module, "expand")
                ok, out = _run_cli(cli, ["expand", feature], root, heartbeat=activity.heartbeat)
                Receipt(module=module, stage="expand", feature=feature, ok=ok,
                        outputs={"log_tail": out[-2000:]}).write(root)
                report["stages"].append({"module": module, "stage": "expand", "status": "ok" if ok else "failed"})
                activity.stage_finished(module, "expand", "ok" if ok else "failed")
                report["paused_at"] = "architecture_approval"
                report["next_command"] = f"forge gate architected {feature}"
                break
            if state == "expanded":
                report["paused_at"] = "architecture_approval"
                report["next_command"] = f"forge gate architected {feature}"
                activity.stage_finished(module, stage_name, "skipped")
                break
        if not dry_run and module == "forgeline" and stage_name == "review":
            state_path = root / ".forge" / feature / "state.json"
            if state_path.exists():
                state = json.loads(state_path.read_text(encoding="utf-8")).get("state")
                if state == "scaffolded":
                    report["paused_at"] = "implementation_fill"
                    report["next_command"] = f"implement the scaffold, then run forge fill {feature} {feature}.ssat.yaml"
                    activity.stage_finished(module, stage_name, "skipped")
                    break
        if not dry_run and module == "hsf" and stage_name == "compile" and not (root / f"specs/{feature}.yaml").exists():
            report["stages"].append({"module": module, "stage": stage_name,
                                     "status": "skipped", "reason": "no deterministic decision spec"})
            activity.stage_finished(module, stage_name, "skipped")
            continue
        if dry_run:
            report["stages"].append({"module": module, "stage": stage_name,
                                     "status": "would-run", "cmd": f"{cli} {' '.join(args)}"})
            activity.stage_finished(module, stage_name, "would-run")
            continue
        activity.stage_started(module, stage_name)
        with stopwatch() as sw:
            ok, out = _run_cli(cli, args, root, heartbeat=activity.heartbeat)
        attribution_block = _attribution_from_output(out)
        module_meter, usage_reported = _meter_from_output(out)
        stage_meter = Meter(
            wall_ms=sw.wall_ms,
            model_calls=module_meter.model_calls,
            tokens_in=module_meter.tokens_in,
            tokens_out=module_meter.tokens_out,
        )
        meterlog.record(StageTiming(
            module, stage_name, sw.wall_ms, module_meter.model_calls,
            module_meter.tokens_in, module_meter.tokens_out, ok,
            usage_reported=usage_reported,
            feature=feature,
            run_id=run_id,
        ))
        Receipt(module=module, stage=stage_name, feature=feature, ok=ok,
                meter=stage_meter,
                outputs={"log_tail": out[-2000:]},
                attribution=attribution_block).write(root)
        report["stages"].append({"module": module, "stage": stage_name,
                                 "status": "ok" if ok else "failed",
                                 "wall_ms": sw.wall_ms,
                                 "attribution": attribution_block})
        activity.stage_finished(module, stage_name, "ok" if ok else "failed", wall_ms=sw.wall_ms)
        if not ok:
            report["halted_at"] = f"{module}:{stage_name}"
            break
    report["rollup"] = rollup_attributions(report["stages"])
    finish_activity()
    return report


def rollup_receipts(root: Path, feature: str) -> dict:
    """Load compatible factory receipts and roll up the latest stage records."""
    receipt_dir = Path(root) / "receipts"
    latest: dict[tuple[str, str], tuple[float, dict]] = {}
    for path in receipt_dir.glob(f"*-{feature}-*.json"):
        try:
            payload = __import__("json").loads(path.read_text(encoding="utf-8"))
            receipt = Receipt.from_dict(payload)
        except (ValueError, TypeError, OSError):
            continue
        latest[(receipt.module, receipt.stage)] = (
            path.stat().st_mtime,
            {
                "module": receipt.module,
                "stage": receipt.stage,
                "status": "ok" if receipt.ok else "failed",
                "attribution": receipt.attribution,
            },
        )
    stages = [item[1] for item in sorted(latest.values(), key=lambda item: item[0])]
    return rollup_attributions(stages)


def rollup_attributions(stages: list[dict]) -> dict:
    """Aggregate module attribution with canonical pipeline failure priority.

    Older receipts without attribution remain visible but do not crash the line.
    The recommendation is always the earliest failing stage, never the worst rate.
    """
    rows = []
    for stage in stages:
        raw = stage.get("attribution")
        if not raw:
            rows.append({
                **stage,
                "order": _stage_order(stage["module"], stage["stage"])[0],
                "rate": None,
                "dominant_failure_class": None,
            })
            continue
        attr = Attribution.from_dict(raw)
        dominant = attr.dominant_failure_class()
        rows.append({
            **stage,
            "order": _stage_order(stage["module"], stage["stage"])[0],
            "rate": attr.rate,
            "n_checked": attr.n_checked,
            "n_passed": attr.n_passed,
            "dominant_failure_class": dominant.value if dominant else None,
        })
    failures = [
        row for row in rows
        if row.get("status") == "failed" or (row["rate"] is not None and row["rate"] < 1.0)
    ]
    first = min(
        failures,
        key=lambda row: _stage_order(row["module"], row["stage"]),
        default=None,
    )
    return {
        "stages": rows,
        "earliest_failing_stage": (
            f"{first['module']}:{first['stage']}" if first else None
        ),
        "recommended_edit_class": (
            "structural" if first and first["dominant_failure_class"] else
            "inspect_stage_output" if first else None
        ),
    }


def _cdte_gate(root: Path, feature: str) -> dict[str, Any] | None:
    """Run the contradiction gate for a feature, if constraints were extracted.

    Returns None when no constraint file exists, so the gate is additive: an
    existing repository keeps working untouched until someone runs
    `factory cdte scan`.
    """
    constraints_path = root / "specs" / f"{feature}.nfr.json"
    if not constraints_path.is_file():
        return None

    from .cdte import CDTEError, record_scan

    try:
        payload = json.loads(constraints_path.read_text(encoding="utf-8"))
        constraints = payload["constraints"] if isinstance(payload, dict) else payload
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return {
            "blocking": False,
            "summary": {"error": f"unreadable constraints: {exc}"},
            "stage": {"module": "factoryline", "stage": "cdte", "status": "skipped",
                      "reason": f"unreadable constraints file: {exc}"},
        }

    run_id = re.sub(r"[^a-z0-9._-]", "-", feature.lower()) or "run"
    try:
        scan = record_scan(root, run_id, constraints, replace=True)
    except CDTEError as exc:
        return {
            "blocking": False,
            "summary": {"error": exc.code},
            "stage": {"module": "factoryline", "stage": "cdte", "status": "skipped",
                      "reason": f"{exc.code}: {exc}"},
        }

    blocking = bool(scan["fail_closed"])
    summary = {
        "run_id": scan["run_id"],
        "conflicts": [
            {"conflict_id": c["conflict_id"], "pair_id": c["pair_id"], "severity": c["severity"]}
            for c in scan["conflicts"]
        ],
        "requires_hitl_escalation": scan["requires_hitl_escalation"],
        "receipt": scan["receipt"],
    }
    return {
        "blocking": blocking,
        "summary": summary,
        "stage": {
            "module": "factoryline",
            "stage": "cdte",
            "status": "blocked" if blocking else "ok",
            "marker": "FAIL_CLOSED_ENGAGED" if blocking else "NO_LETHAL_PAIR_MATCHED",
        },
    }
