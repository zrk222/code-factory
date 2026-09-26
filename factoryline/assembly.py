"""factoryline.assembly — line the Lego pieces up.

factoryline drives whichever modules are installed by shelling out to their CLIs.
It hard-depends on none of them. A missing module is simply a stud with nothing
plugged in — the chain reports it and continues with what's present. This is what
makes the factory portable: any IDE/agent/OS that can run a subprocess can drive it.
"""

from __future__ import annotations
import shutil
import json
import hashlib
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .contract import MODULES, Meter, ensure_layout, Receipt
from .meter import MeterLog, StageTiming, stopwatch
from .attribution import Attribution
from .agent_contract import AgentContractError, validate_agent_contract
from .live_activity import LiveActivity
from .assembly_process import run_cli


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
        out.append(
            ModuleStatus(
                name=name,
                cli=meta["cli"],
                installed=shutil.which(meta["cli"]) is not None,
                role=meta["role"],
            )
        )
    return out


def _run_cli(
    cli: str, args: list[str], cwd: Path, *, heartbeat: Callable[[], bool] | None = None
) -> tuple[bool, str]:
    return run_cli(cli, args, cwd, heartbeat=heartbeat)


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


def _forge_ship_result(output: str) -> dict | None:
    """Extract only an explicit Forge ship JSON result with two boolean claims."""
    payloads: list[dict] = []
    decoder = json.JSONDecoder()
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(output[offset:])
        except ValueError:
            continue
        if isinstance(payload, dict):
            payloads.append(payload)
    return next(
        (
            payload
            for payload in reversed(payloads)
            if isinstance(payload.get("shipped"), bool)
            and isinstance(payload.get("intent_traceable"), bool)
        ),
        None,
    )


def _forge_receipt_lines(root: Path, feature: str) -> list[str] | None:
    """Read a bounded Forge receipt log strictly beneath the requested root."""
    try:
        root_path = Path(root).resolve()
        receipt_path = (root_path / ".forge" / feature / "receipts.jsonl").resolve()
        receipt_path.relative_to(root_path)
    except (OSError, ValueError):
        return None
    try:
        if receipt_path.stat().st_size > 1_048_576:
            return None
        return receipt_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def _latest_forge_ship(lines: list[str]) -> tuple[dict, str] | None:
    """Find the last ship entry, refusing the whole log if any line is malformed."""
    latest: tuple[dict, str] | None = None
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            return None
        if isinstance(value, dict) and value.get("phase") == "ship":
            latest = (value, line)
    return latest


def _forge_trace_fields(
    forge_receipt: dict, forge_result: dict
) -> tuple[Any, Any, Any]:
    """Prefer the local ship receipt's identity and timing fields."""
    intent_hash = forge_receipt.get("intent_hash")
    if not isinstance(intent_hash, str):
        intent_hash = (
            forge_result.get("intent_hash")
            if isinstance(forge_result.get("intent_hash"), str)
            else None
        )
    obligations = forge_receipt.get("obligations")
    if not isinstance(obligations, str):
        obligations = forge_result.get("obligations_met")
        if not isinstance(obligations, str):
            obligations = (
                forge_result.get("obligations")
                if isinstance(forge_result.get("obligations"), str)
                else None
            )
    timestamp = forge_receipt.get("ts")
    if not isinstance(timestamp, str):
        timestamp = (
            forge_result.get("ts") if isinstance(forge_result.get("ts"), str) else None
        )
    return intent_hash, obligations, timestamp


def _forge_intent_trace(root: Path, feature: str, output: str) -> dict | None:
    """Adapt one explicit Forge ship result into a Code Factory receipt.

    REQ_INTENT_ADAPTER_CAPTURE · REQ_INTENT_ADAPTER_READ_ONLY ·
    REQ_INTENT_ADAPTER_FAIL_CLOSED

    ForgeLine owns its append-only ``.forge`` store.  FactoryLine must not
    rewrite that store or infer a traceability result from a successful exit
    code.  The adapter is emitted only when the CLI explicitly reports both
    boolean fields and the corresponding Forge ship line is readable and
    consistent.  Missing fields therefore leave the legacy fail-closed path
    untouched.
    """
    forge_result = _forge_ship_result(output)
    if forge_result is None:  # REQ_INTENT_ADAPTER_FAIL_CLOSED
        return None
    lines = _forge_receipt_lines(root, feature)
    if lines is None:
        return None
    latest = _latest_forge_ship(lines)
    if latest is None:
        return None
    forge_receipt, raw_line = latest
    if not isinstance(forge_receipt.get("shipped"), bool):
        return None
    if forge_receipt["shipped"] is not forge_result["shipped"]:
        return None
    intent_hash, obligations, timestamp = _forge_trace_fields(
        forge_receipt, forge_result
    )
    return {
        "schema": "factoryline.intent-trace.v1",
        "source": "forgeline-cli",
        "shipped": forge_result["shipped"],
        "intent_traceable": forge_result["intent_traceable"],
        "intent_hash": intent_hash,
        "obligations": obligations,
        "forge_receipt_sha256": hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
        "ts": timestamp,
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
        "execution": False,
    }


# The default pipeline: (module, cli-args-template). {f} = feature.
# Only stages whose module is installed run; UI stage runs only if smoke/<f>.ui exists.
DEFAULT_CHAIN = [
    ("specline", ["strict", "{f}", "--json"]),
    ("specline", ["verify-validators", "{f}", "--json"]),
    ("specline", ["gate", "spec", "{f}"]),
    ("specline", ["tasks", "{f}"]),
    ("specline", ["gate", "plan", "{f}"]),
    ("forgeline", ["architect", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["review", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["arch-gate", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["verify-tests", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["smoke", "{f}"]),
    ("prestige", ["score", "smoke/{f}.ui", "--json", "--strict"]),
    ("hsf", ["compile", "specs/{f}.yaml"]),
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
        (mod, _receipt_stage(mod, args)): index
        for index, (mod, args) in enumerate(DEFAULT_CHAIN)
    }
    return (order.get((module, normalized), len(DEFAULT_CHAIN)), module, normalized)


def _receipt_stage(module: str, args: list[str]) -> str:
    """Name stages without collapsing distinct commands into one receipt.

    SpecLine's two ``gate`` calls protect different obligations.  Storing both
    as ``gate`` let a later plan gate replace the spec gate during rollup.
    """
    stage = args[0].replace("_", "-")
    if module == "specline" and stage == "gate" and len(args) > 1:
        return f"gate-{args[1].replace('_', '-')}"
    return stage


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


MAX_RECEIPT_BYTES = 1_048_576
MAX_RECEIPT_FILES = 1_000


def _release_contract_requires(
    root: Path, feature: str, stage: str, path: Path | None = None
) -> bool:
    """Detect a declared required stage without granting the file authority.

    ``factory verify --strict-release`` later validates the exact Oracle-bound
    contract.  Assembly uses this bounded hint only to avoid skipping a gate a
    release owner explicitly listed because an agent omitted its input file.
    """
    path = path or root / ".factory" / "release-contracts" / f"{feature}.json"
    try:
        if path.stat().st_size > MAX_RECEIPT_BYTES:
            return False
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    required = value.get("required_stages") if isinstance(value, dict) else None
    return isinstance(required, list) and stage in required


def _release_contract_binding(
    root: Path, feature: str, path: Path | None
) -> dict[str, str]:
    """Carry exact Oracle/policy digests into newly written stage receipts."""
    source = path or root / ".factory" / "release-contracts" / f"{feature}.json"
    try:
        if source.stat().st_size > MAX_RECEIPT_BYTES:
            return {}
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict) or value.get("feature") != feature:
        return {}
    oracle = value.get("oracle_contract_sha256")
    policy = value.get("policy_digest")
    if not isinstance(oracle, str) or not isinstance(policy, str):
        return {}
    return {"oracle_contract_sha256": oracle, "release_contract_policy_digest": policy}


def _finish_activity(report: dict, activity: LiveActivity) -> None:
    """Close the live activity with the report's terminal state."""
    terminal = (
        "halted"
        if report.get("halted_at")
        else "waiting_for_human"
        if report.get("paused_at")
        else "completed"
    )
    activity.finish(
        terminal,
        halted_at=report.get("halted_at"),
        paused_at=report.get("paused_at"),
    )


def _assembly_agent_contract(root: Path, report: dict, activity: LiveActivity) -> bool:
    """Bind a present agent contract or halt before any pipeline stage."""
    contract_path = root / ".factory" / "agent-contract.json"
    if not contract_path.is_file():
        return True
    try:
        contract = validate_agent_contract(contract_path)
    except AgentContractError as exc:
        report["stages"].append(
            {
                "module": "factoryline",
                "stage": "agent-contract",
                "status": "failed",
                "code": exc.code,
                "message": exc.message,
            }
        )
        activity.stage_finished("factoryline", "agent-contract", "failed")
        report["halted_at"] = "factoryline:agent-contract"
        _finish_activity(report, activity)
        return False
    report["agent_contract"] = {
        "path": str(contract_path),
        "digest": contract["contract_digest"],
        "marker": "AGENT_CONTRACT_BOUND",
    }
    report["stages"].append(
        {
            "module": "factoryline",
            "stage": "agent-contract",
            "status": "ok",
            "marker": "AGENT_CONTRACT_BOUND",
        }
    )
    activity.stage_finished("factoryline", "agent-contract", "ok")
    return True


def _assembly_spec_bootstrap(
    root: Path,
    feature: str,
    dry_run: bool,
    installed: dict[str, ModuleStatus],
    release_binding: dict[str, str],
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Create a missing spec and pause for its author before the build chain."""
    spec_path = root / "specs" / f"{feature}.md"
    if dry_run or spec_path.exists() or not installed["specline"].installed:
        return False
    activity.stage_started("specline", "new")
    with stopwatch() as sw:
        ok, out = _run_cli(
            MODULES["specline"]["cli"],
            ["new", feature],
            root,
            heartbeat=activity.heartbeat,
        )
    Receipt(
        module="specline",
        stage="new",
        feature=feature,
        ok=ok,
        inputs=dict(release_binding),
        outputs={"log_tail": out[-2000:]},
    ).write(root)
    report["stages"].append(
        {
            "module": "specline",
            "stage": "new",
            "status": "ok" if ok else "failed",
            "wall_ms": sw.wall_ms,
        }
    )
    activity.stage_finished(
        "specline", "new", "ok" if ok else "failed", wall_ms=sw.wall_ms
    )
    if not ok:
        report["halted_at"] = "specline:new"
    else:
        report["paused_at"] = "author_spec"
        report["next_command"] = (
            f"edit specs/{feature}.md and plans/{feature}.md, then rerun factory assemble {feature}"
        )
    report["rollup"] = rollup_attributions(report["stages"])
    _finish_activity(report, activity)
    return True


def _assembly_cdte_gate(
    root: Path, feature: str, dry_run: bool, report: dict, activity: LiveActivity
) -> bool:
    """Pause before build stages when a declared NFR contradiction blocks."""
    if dry_run:
        return False
    cdte_outcome = _cdte_gate(root, feature)
    if cdte_outcome is None:
        return False
    report["stages"].append(cdte_outcome["stage"])
    activity.stage_finished(
        "factoryline", "cdte", "failed" if cdte_outcome["blocking"] else "ok"
    )
    report["cdte"] = cdte_outcome["summary"]
    if not cdte_outcome["blocking"]:
        return False
    report["paused_at"] = "nfr_conflict"
    if "run_id" in cdte_outcome["summary"]:
        report["next_command"] = (
            f"factory cdte resolve {cdte_outcome['summary']['run_id']} "
            f"<conflict-id> --decision ... --approved-by ..."
        )
    else:
        report["next_command"] = (
            f"repair specs/{feature}.nfr.json, then rerun factory assemble {feature}"
        )
    report["rollup"] = rollup_attributions(report["stages"])
    _finish_activity(report, activity)
    return True


@dataclass(frozen=True)
class _AssemblyStage:
    module: str
    cli: str
    args: list[str]
    name: str
    stage_id: str
    required: bool
    present: bool


def _plan_assembly_stage(
    root: Path,
    feature: str,
    module: str,
    args_tmpl: list[str],
    installed: dict[str, ModuleStatus],
    release_contract_path: Path | None,
) -> _AssemblyStage:
    """Resolve one chain command, its exact receipt name, and contract scope."""
    cli = MODULES[module]["cli"]
    args = [arg.replace("{f}", feature) for arg in args_tmpl]
    if module == "forgeline" and len(args) > 2 and args[2] == f"{feature}.ssat.yaml":
        args[2] = str(_ssat_contract(root, feature).relative_to(root))
    name = _receipt_stage(module, args)
    stage_id = f"{module}:{name}"
    return _AssemblyStage(
        module,
        cli,
        args,
        name,
        stage_id,
        _release_contract_requires(root, feature, stage_id, release_contract_path),
        installed[module].installed,
    )


def _assembly_stage_failure(
    stage: _AssemblyStage,
    report: dict,
    activity: LiveActivity,
    reason: str,
    marker: str,
) -> None:
    """Record a contract-required stage that cannot be fulfilled."""
    report["stages"].append(
        {
            "module": stage.module,
            "stage": stage.name,
            "status": "failed",
            "reason": reason,
            "marker": marker,
        }
    )
    activity.stage_finished(stage.module, stage.name, "failed")
    report["halted_at"] = stage.stage_id


def _assembly_scope_blocked(
    root: Path,
    feature: str,
    stage: _AssemblyStage,
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Fail before availability checks when a declared UI or spec is absent."""
    if (
        stage.module == "prestige"
        and stage.required
        and not (root / "smoke" / f"{feature}.ui").is_file()
    ):
        _assembly_stage_failure(
            stage,
            report,
            activity,
            "declared_ui_scope_missing",
            "UI_SCOPE_REQUIRED_EVIDENCE_MISSING",
        )
        return True
    if (
        stage.module == "hsf"
        and stage.required
        and not (root / f"specs/{feature}.yaml").exists()
    ):
        _assembly_stage_failure(
            stage,
            report,
            activity,
            "declared_decision_spec_missing",
            "DECISION_SPEC_REQUIRED_EVIDENCE_MISSING",
        )
        return True
    return False


def _assembly_availability_action(
    root: Path,
    feature: str,
    stage: _AssemblyStage,
    report: dict,
    activity: LiveActivity,
) -> str | None:
    """Distinguish unavailable required gates from explicit optional skips."""
    if not stage.present:
        if stage.required:
            _assembly_stage_failure(
                stage,
                report,
                activity,
                f"{stage.cli} not installed",
                "REQUIRED_GATE_UNAVAILABLE",
            )
            return "halt"
        report["stages"].append(
            {
                "module": stage.module,
                "stage": stage.name,
                "status": "skipped",
                "reason": f"{stage.cli} not installed",
            }
        )
        activity.stage_finished(stage.module, stage.name, "skipped")
        return "skip"
    if stage.module == "prestige" and not (root / "smoke" / f"{feature}.ui").is_file():
        report["stages"].append(
            {
                "module": stage.module,
                "stage": stage.name,
                "status": "skipped",
                "reason": "ui_scope_not_declared",
                "marker": "UI_PRESTIGE_GATE_NOT_APPLICABLE",
            }
        )
        activity.stage_finished(stage.module, stage.name, "skipped")
        return "skip"
    return None


def _forge_architect_state(root: Path, feature: str) -> str | None:
    """Read a prior Forge state for the architect pause without trusting malformed bytes."""
    state_path = root / ".forge" / feature / "state.json"
    if not state_path.exists():
        return None
    try:
        return json.loads(state_path.read_text(encoding="utf-8")).get("state")
    except (OSError, ValueError):
        return None


def _assembly_forge_architect(
    root: Path,
    feature: str,
    dry_run: bool,
    stage: _AssemblyStage,
    release_binding: dict[str, str],
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Pause for a missing SSAT or architecture approval after expansion."""
    if dry_run or stage.module != "forgeline" or stage.name != "architect":
        return False
    ssat = _ssat_contract(root, feature)
    state = _forge_architect_state(root, feature)
    if not ssat.exists():
        report["paused_at"] = "architecture_contract"
        report["next_command"] = (
            f"write specs/{feature}.ssat.yaml, then run forge expand {feature}"
        )
        activity.stage_finished(stage.module, stage.name, "skipped")
        return True
    if state in {None, "intent"}:
        activity.stage_started(stage.module, "expand")
        ok, out = _run_cli(
            stage.cli, ["expand", feature], root, heartbeat=activity.heartbeat
        )
        Receipt(
            module=stage.module,
            stage="expand",
            feature=feature,
            ok=ok,
            inputs=dict(release_binding),
            outputs={"log_tail": out[-2000:]},
        ).write(root)
        report["stages"].append(
            {
                "module": stage.module,
                "stage": "expand",
                "status": "ok" if ok else "failed",
            }
        )
        activity.stage_finished(stage.module, "expand", "ok" if ok else "failed")
        report["paused_at"] = "architecture_approval"
        report["next_command"] = f"forge gate architected {feature}"
        return True
    if state == "expanded":
        report["paused_at"] = "architecture_approval"
        report["next_command"] = f"forge gate architected {feature}"
        activity.stage_finished(stage.module, stage.name, "skipped")
        return True
    return False


def _assembly_forge_review(
    root: Path,
    feature: str,
    dry_run: bool,
    stage: _AssemblyStage,
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Pause for implementation fill or halt on malformed Forge state."""
    if dry_run or stage.module != "forgeline" or stage.name != "review":
        return False
    state_path = root / ".forge" / feature / "state.json"
    if not state_path.exists():
        return False
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")).get("state")
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        TypeError,
    ):
        _assembly_stage_failure(
            stage, report, activity, "forge state is malformed", "FORGE_STATE_INVALID"
        )
        return True
    if state == "scaffolded":
        report["paused_at"] = "implementation_fill"
        report["next_command"] = (
            f"implement the scaffold, then run forge fill {feature} {feature}.ssat.yaml"
        )
        activity.stage_finished(stage.module, stage.name, "skipped")
        return True
    return False


def _assembly_hsf_action(
    root: Path,
    feature: str,
    dry_run: bool,
    stage: _AssemblyStage,
    report: dict,
    activity: LiveActivity,
) -> str | None:
    """Skip an undeclared decision spec or fail a required compile stage."""
    if dry_run or stage.module != "hsf" or stage.name != "compile":
        return None
    if (root / f"specs/{feature}.yaml").exists():
        return None
    if stage.required:
        _assembly_stage_failure(
            stage,
            report,
            activity,
            "declared_decision_spec_missing",
            "DECISION_SPEC_REQUIRED_EVIDENCE_MISSING",
        )
        return "halt"
    report["stages"].append(
        {
            "module": stage.module,
            "stage": stage.name,
            "status": "skipped",
            "reason": "no deterministic decision spec",
        }
    )
    activity.stage_finished(stage.module, stage.name, "skipped")
    return "skip"


def _assembly_dry_run(
    stage: _AssemblyStage, report: dict, activity: LiveActivity
) -> None:
    """Show an unexecuted command without creating a success receipt."""
    report["stages"].append(
        {
            "module": stage.module,
            "stage": stage.name,
            "status": "would-run",
            "cmd": f"{stage.cli} {' '.join(stage.args)}",
        }
    )
    activity.stage_finished(stage.module, stage.name, "would-run")


def _assembly_stage_outputs(
    root: Path, feature: str, stage: _AssemblyStage, output: str
) -> dict[str, Any]:
    """Attach an intent trace only when Forge ship supplied explicit proof."""
    outputs: dict[str, Any] = {"log_tail": output[-2000:]}
    if stage.module == "forgeline" and stage.name == "ship":
        intent_trace = _forge_intent_trace(root, feature, output)
        if intent_trace is not None:
            outputs["intent_trace"] = intent_trace
    return outputs


def _execute_assembly_stage(
    root: Path,
    feature: str,
    stage: _AssemblyStage,
    meterlog: MeterLog,
    run_id: str,
    release_binding: dict[str, str],
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Execute one present stage and record its timing, meter, and receipt."""
    activity.stage_started(stage.module, stage.name)
    with stopwatch() as sw:
        ok, out = _run_cli(stage.cli, stage.args, root, heartbeat=activity.heartbeat)
    attribution_block = _attribution_from_output(out)
    module_meter, usage_reported = _meter_from_output(out)
    stage_meter = Meter(
        wall_ms=sw.wall_ms,
        model_calls=module_meter.model_calls,
        tokens_in=module_meter.tokens_in,
        tokens_out=module_meter.tokens_out,
    )
    meterlog.record(
        StageTiming(
            stage.module,
            stage.name,
            sw.wall_ms,
            module_meter.model_calls,
            module_meter.tokens_in,
            module_meter.tokens_out,
            ok,
            usage_reported=usage_reported,
            feature=feature,
            run_id=run_id,
        )
    )
    Receipt(
        module=stage.module,
        stage=stage.name,
        feature=feature,
        ok=ok,
        inputs=dict(release_binding),
        meter=stage_meter,
        outputs=_assembly_stage_outputs(root, feature, stage, out),
        attribution=attribution_block,
    ).write(root)
    report["stages"].append(
        {
            "module": stage.module,
            "stage": stage.name,
            "status": "ok" if ok else "failed",
            "wall_ms": sw.wall_ms,
            "attribution": attribution_block,
        }
    )
    activity.stage_finished(
        stage.module, stage.name, "ok" if ok else "failed", wall_ms=sw.wall_ms
    )
    if not ok:
        report["halted_at"] = stage.stage_id
    return ok


def _assembly_stage_halts(
    root: Path,
    feature: str,
    dry_run: bool,
    stage: _AssemblyStage,
    release_binding: dict[str, str],
    meterlog: MeterLog,
    run_id: str,
    report: dict,
    activity: LiveActivity,
) -> bool:
    """Apply stage gates in order; return whether the chain must stop."""
    if _assembly_scope_blocked(root, feature, stage, report, activity):
        return True
    availability = _assembly_availability_action(root, feature, stage, report, activity)
    if availability is not None:
        return availability == "halt"
    if _assembly_forge_architect(
        root, feature, dry_run, stage, release_binding, report, activity
    ):
        return True
    if _assembly_forge_review(root, feature, dry_run, stage, report, activity):
        return True
    hsf_action = _assembly_hsf_action(root, feature, dry_run, stage, report, activity)
    if hsf_action is not None:
        return hsf_action == "halt"
    if dry_run:
        _assembly_dry_run(stage, report, activity)
        return False
    return not _execute_assembly_stage(
        root, feature, stage, meterlog, run_id, release_binding, report, activity
    )


def assemble(
    root: Path,
    feature: str,
    chain=None,
    dry_run: bool = False,
    release_contract_path: Path | None = None,
) -> dict:
    """Run the assembly line for a feature. Returns a per-stage report.
    Missing modules are skipped with a clear note (Lego stud left open)."""
    root = Path(root)
    ensure_layout(root)
    chain = chain or DEFAULT_CHAIN
    installed = {m.name: m for m in detect()}
    meterlog = MeterLog(root)
    run_id = uuid.uuid4().hex
    report = {
        "feature": feature,
        "root": str(root),
        "run_id": run_id,
        "stages": [],
        "dry_run": dry_run,
    }
    if release_contract_path is not None:
        report["release_contract_path"] = str(Path(release_contract_path))
    release_binding = _release_contract_binding(root, feature, release_contract_path)
    activity = LiveActivity(root, run_id, feature, len(chain))
    activity.start()

    if not _assembly_agent_contract(root, report, activity):
        return report
    if _assembly_spec_bootstrap(
        root, feature, dry_run, installed, release_binding, report, activity
    ):
        return report
    if _assembly_cdte_gate(root, feature, dry_run, report, activity):
        return report

    for module, args_tmpl in chain:
        stage = _plan_assembly_stage(
            root, feature, module, args_tmpl, installed, release_contract_path
        )
        if _assembly_stage_halts(
            root,
            feature,
            dry_run,
            stage,
            release_binding,
            meterlog,
            run_id,
            report,
            activity,
        ):
            break
    report["rollup"] = rollup_attributions(report["stages"])
    _finish_activity(report, activity)
    return report


def rollup_receipts(root: Path, feature: str) -> dict:
    """Load exact-feature receipts with deterministic supersession.

    A malformed or concurrently rewritten receipt is retained as invalid input
    to the decision instead of silently disappearing.  ``ts`` is producer data,
    so filesystem nanoseconds and a stable path tiebreaker define local
    supersession; neither establishes producer authenticity.
    """
    receipt_dir = Path(root) / "receipts"
    latest: dict[tuple[str, str], tuple[tuple[int, str], dict]] = {}
    invalid: list[dict[str, str]] = []
    paths = sorted(receipt_dir.glob(f"*-{feature}-*.json"), key=lambda item: item.name)
    truncated = len(paths) > MAX_RECEIPT_FILES
    if truncated:
        # We may still show a bounded diagnostic, but a readiness decision must
        # remain blocked because the complete evidence set was not observed.
        invalid.append(
            {
                "path": "receipts/",
                "reason": f"receipt scan exceeded {MAX_RECEIPT_FILES} files",
            }
        )
        paths = paths[-MAX_RECEIPT_FILES:]
    for path in paths:
        try:
            before = path.stat()
            if before.st_size > MAX_RECEIPT_BYTES:
                raise ValueError(f"receipt exceeds {MAX_RECEIPT_BYTES} bytes")
            raw = path.read_bytes()
            payload = __import__("json").loads(raw.decode("utf-8-sig"))
            after = path.stat()
            if (before.st_mtime_ns, before.st_size) != (
                after.st_mtime_ns,
                after.st_size,
            ):
                raise ValueError("receipt changed while being read")
            receipt = Receipt.from_dict(payload)
            if receipt.feature != feature:
                raise ValueError("receipt feature does not match requested feature")
        except (
            ValueError,
            TypeError,
            OSError,
            UnicodeDecodeError,
            __import__("json").JSONDecodeError,
        ) as exc:
            invalid.append({"path": path.name, "reason": str(exc)[:240]})
            continue
        # Receipt producers historically used both ``verify_tests`` and
        # ``verify-tests``.  Treat them as one gate before supersession so a
        # stale spelling cannot hide the current result.
        stage = receipt.stage.replace("_", "-")
        key = (receipt.module, stage)
        rank = (after.st_mtime_ns, path.name)
        row = {
            "module": receipt.module,
            "stage": stage,
            "status": "ok" if receipt.ok else "failed",
            "attribution": receipt.attribution,
            "inputs": receipt.inputs,
            "outputs": receipt.outputs,
            "receipt_path": path.name,
            "receipt_mtime_ns": after.st_mtime_ns,
            "run_id": receipt.run_id,
            "producer_version": receipt.producer_version,
            "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if key not in latest or rank > latest[key][0]:
            latest[key] = (rank, row)
    stages = [
        item[1]
        for item in sorted(
            latest.values(),
            key=lambda item: (item[1]["receipt_mtime_ns"], item[1]["receipt_path"]),
        )
    ]
    return rollup_attributions(stages) | {
        "receipt_snapshot": {
            "schema": "factory.receipt-snapshot.v1",
            "feature": feature,
            "valid_count": len(stages),
            "invalid_count": len(invalid),
            "invalid": invalid,
            "truncated": truncated,
            "claim_boundary": "Local stable-read snapshot only; receipt hashes and timestamps do not authenticate a producer or external execution.",
        },
    }


def rollup_attributions(stages: list[dict]) -> dict:
    """Aggregate module attribution with canonical pipeline failure priority.

    Older receipts without attribution remain visible but do not crash the line.
    The recommendation is always the earliest failing stage, never the worst rate.
    """
    rows = []
    for stage in stages:
        raw = stage.get("attribution")
        if not raw:
            rows.append(
                {
                    **stage,
                    "order": _stage_order(stage["module"], stage["stage"])[0],
                    "rate": None,
                    "dominant_failure_class": None,
                }
            )
            continue
        attr = Attribution.from_dict(raw)
        dominant = attr.dominant_failure_class()
        rows.append(
            {
                **stage,
                "order": _stage_order(stage["module"], stage["stage"])[0],
                "rate": attr.rate,
                "n_checked": attr.n_checked,
                "n_passed": attr.n_passed,
                "dominant_failure_class": dominant.value if dominant else None,
            }
        )
    failures = [
        row
        for row in rows
        if row.get("status") == "failed"
        or (row["rate"] is not None and row["rate"] < 1.0)
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
            "structural"
            if first and first["dominant_failure_class"]
            else "inspect_stage_output"
            if first
            else None
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
            "blocking": True,
            "summary": {"error": f"unreadable constraints: {exc}"},
            "stage": {
                "module": "factoryline",
                "stage": "cdte",
                "status": "blocked",
                "marker": "CDTE_INPUT_INVALID",
                "reason": f"unreadable constraints file: {exc}",
            },
        }

    run_id = re.sub(r"[^a-z0-9._-]", "-", feature.lower()) or "run"
    try:
        scan = record_scan(root, run_id, constraints, replace=True)
    except CDTEError as exc:
        return {
            "blocking": True,
            "summary": {"error": exc.code},
            "stage": {
                "module": "factoryline",
                "stage": "cdte",
                "status": "blocked",
                "marker": "CDTE_INPUT_INVALID",
                "reason": f"{exc.code}: {exc}",
            },
        }

    blocking = bool(scan["fail_closed"])
    summary = {
        "run_id": scan["run_id"],
        "conflicts": [
            {
                "conflict_id": c["conflict_id"],
                "pair_id": c["pair_id"],
                "severity": c["severity"],
            }
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
