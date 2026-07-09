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


# The default pipeline: (module, cli-args-template). {f} = feature.
# Only stages whose module is installed run; UI stage runs only if smoke/<f>.ui exists.
DEFAULT_CHAIN = [
    ("specline",  ["new", "{f}"]),
    ("specline",  ["strict", "{f}"]),
    ("specline",  ["gate", "spec", "{f}"]),
    ("forgeline", ["architect", "{f}"]),
    ("forgeline", ["review", "{f}"]),
    ("forgeline", ["arch-gate", "{f}"]),
    ("forgeline", ["smoke", "{f}"]),
    ("hsf",       ["compile", "specs/{f}.yaml"]),
    ("forgeline", ["ship", "{f}"]),
]


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
        meterlog.record(StageTiming(module, stage_name, sw.wall_ms, 0, 0, 0, ok))
        Receipt(module=module, stage=stage_name, feature=feature, ok=ok,
                outputs={"log_tail": out[-400:]}).write(root)
        report["stages"].append({"module": module, "stage": stage_name,
                                 "status": "ok" if ok else "failed",
                                 "wall_ms": sw.wall_ms})
        if not ok:
            report["halted_at"] = f"{module}:{stage_name}"
            break
    return report


def rollup_attributions(stages: list[dict]) -> dict:
    """Aggregate module attribution in declared pipeline order.

    Older receipts without attribution remain visible but do not crash the line.
    The recommendation is always the earliest failing stage, never the worst rate.
    """
    rows = []
    for index, stage in enumerate(stages):
        raw = stage.get("attribution")
        if not raw:
            rows.append({**stage, "rate": None, "dominant_failure_class": None})
            continue
        attr = Attribution.from_dict(raw)
        dominant = attr.dominant_failure_class()
        rows.append({
            **stage,
            "order": index,
            "rate": attr.rate,
            "n_checked": attr.n_checked,
            "n_passed": attr.n_passed,
            "dominant_failure_class": dominant.value if dominant else None,
        })
    first = next((row for row in rows if row["rate"] is not None and row["rate"] < 1.0), None)
    return {
        "stages": rows,
        "earliest_failing_stage": (
            f"{first['module']}:{first['stage']}" if first else None
        ),
        "recommended_edit_class": (
            "structural" if first and first["dominant_failure_class"] else None
        ),
    }
