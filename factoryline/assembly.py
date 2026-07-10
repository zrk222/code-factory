"""factoryline.assembly — line the Lego pieces up.

factoryline drives whichever modules are installed by shelling out to their CLIs.
It hard-depends on none of them. A missing module is simply a stud with nothing
plugged in — the chain reports it and continues with what's present. This is what
makes the factory portable: any IDE/agent/OS that can run a subprocess can drive it.
"""
from __future__ import annotations
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contract import MODULES, STAGES, ensure_layout, Receipt
from .meter import MeterLog, StageTiming, stopwatch
from .attribution import Attribution, FailureClass


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


def _run_cli(cli: str, args: list[str], cwd: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run([cli, *args], cwd=str(cwd),
                              capture_output=True, text=True, timeout=300)
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    except FileNotFoundError:
        return False, f"{cli} not installed"
    except subprocess.TimeoutExpired:
        return False, f"{cli} timed out"


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


# The default pipeline: (module, cli-args-template). {f} = feature.
# Only stages whose module is installed run; UI stage runs only if smoke/<f>.ui exists.
DEFAULT_CHAIN = [
    ("specline",  ["new", "{f}"]),
    ("specline",  ["strict", "{f}", "--json"]),
    ("specline",  ["verify-validators", "{f}", "--json"]),
    ("specline",  ["gate", "spec", "{f}"]),
    ("forgeline", ["architect", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["review", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["arch-gate", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["verify-tests", "{f}", "{f}.ssat.yaml"]),
    ("forgeline", ["smoke", "{f}"]),
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


def assemble(root: Path, feature: str, chain=None, dry_run: bool = False) -> dict:
    """Run the assembly line for a feature. Returns a per-stage report.
    Missing modules are skipped with a clear note (Lego stud left open)."""
    root = Path(root); ensure_layout(root)
    chain = chain or DEFAULT_CHAIN
    installed = {m.name: m for m in detect()}
    meterlog = MeterLog(root)
    report = {"feature": feature, "root": str(root), "stages": [], "dry_run": dry_run}

    for module, args_tmpl in chain:
        cli = MODULES[module]["cli"]
        present = installed[module].installed
        args = [a.replace("{f}", feature) for a in args_tmpl]
        stage_name = args[0]
        if not present:
            report["stages"].append({"module": module, "stage": stage_name,
                                     "status": "skipped", "reason": f"{cli} not installed"})
            continue
        if dry_run:
            report["stages"].append({"module": module, "stage": stage_name,
                                     "status": "would-run", "cmd": f"{cli} {' '.join(args)}"})
            continue
        with stopwatch() as sw:
            ok, out = _run_cli(cli, args, root)
        attribution_block = _attribution_from_output(out)
        meterlog.record(StageTiming(module, stage_name, sw.wall_ms, 0, 0, 0, ok))
        Receipt(module=module, stage=stage_name, feature=feature, ok=ok,
                outputs={"log_tail": out[-400:]},
                attribution=attribution_block).write(root)
        report["stages"].append({"module": module, "stage": stage_name,
                                 "status": "ok" if ok else "failed",
                                 "wall_ms": sw.wall_ms,
                                 "attribution": attribution_block})
        if not ok:
            report["halted_at"] = f"{module}:{stage_name}"
            break
    report["rollup"] = rollup_attributions(report["stages"])
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
    failures = [row for row in rows if row["rate"] is not None and row["rate"] < 1.0]
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
            "structural" if first and first["dominant_failure_class"] else None
        ),
    }
