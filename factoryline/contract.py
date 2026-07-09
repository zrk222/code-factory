"""factoryline.contract — the Lego stud/socket spec for the code factory.

Each module (SpecLine, ForgeLine, HSF, Prestige) is an independent, separately
installable package. This module defines the *shared shape* that lets them snap
together without depending on each other: a common on-disk layout and a common
receipt envelope. A module doesn't import factoryline; factoryline knows how to
line the modules up.

The contract is deliberately filesystem-based — the most portable interop there
is. Any IDE, agent (Codex / Claude Code / Cursor), CI runner, or OS can drive the
chain by reading and writing these paths. No network, no daemon, no lock-in.

## The assembly line

    intent ─► [SpecLine] ─► spec + strict contract ─► handoff/*_decisions.yaml
                                                          │
              [ForgeLine] ◄──── tasks / plan ◄───────────┘
                   │  architect → build → gates → smoke → ship
                   ├─► if UI in scope ─► [Prestige] design-quality gate
                   └─► if decision table ─► [HSF] compile → deterministic artifact

## The shared layout (a "factory root")

    <root>/
      specs/        <feature>.md            (SpecLine owns)
      plans/        <feature>.md            (SpecLine owns)
      handoff/      <feature>_decisions.yaml(SpecLine → HSF)
      slices/       <feature>/*.py          (ForgeLine builds here)
      smoke/        <feature>.json          (ForgeLine smoke gate reads)
      registry/     <feature>-<sha>.py      (HSF signed artifacts)
      receipts/     <module>-<feature>-*.json (every module writes here)
      .factory/     state.json, meter.jsonl (factoryline orchestration + metering)

## The receipt envelope (the common socket)

Every module, when driven through factoryline, emits a receipt with at least:

    {
      "module":   "specline|forgeline|hsf|prestige",
      "stage":    "<the step, e.g. 'strict' | 'smoke' | 'compile'>",
      "feature":  "<feature id>",
      "ok":       true|false,
      "inputs":   { "sha": "...", "paths": [...] },
      "outputs":  { "paths": [...], "sha": "..." },
      "meter":    { "wall_ms": 0, "model_calls": 0, "tokens_in": 0, "tokens_out": 0 },
      "ts":       "<iso8601>"
    }

The `meter` block is what makes the time/token/savings story *real*: each module
reports its own cost, factoryline aggregates. Numbers are measured, never invented.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
import datetime as _dt
import hashlib
import json

# Canonical subdirectories of a factory root.
LAYOUT = {
    "specs": "specs", "plans": "plans", "handoff": "handoff", "slices": "slices",
    "smoke": "smoke", "registry": "registry", "receipts": "receipts", "state": ".factory",
}

# The ordered assembly stages and which module owns each.
STAGES = [
    ("specline", "new",     "scaffold a spec + plan for the feature"),
    ("specline", "strict",  "reject ambiguity before the coder (input contract)"),
    ("specline", "gate",    "seal the spec/plan gate"),
    ("specline", "tasks",   "emit task packets for agents"),
    ("forgeline", "architect", "SSAT / architecture-as-code"),
    ("forgeline", "review",  "judge + adversary + QA audit"),
    ("forgeline", "arch-gate", "architecture CI gate"),
    ("forgeline", "smoke",   "runtime behavior verification"),
    ("prestige",  "score",   "design-quality gate (only if UI in scope)"),
    ("hsf",       "compile", "compile decision table → deterministic artifact"),
    ("forgeline", "ship",    "final ship with intent traceability"),
]

MODULES = {
    "specline":  {"cli": "specline", "pip": "code-factory-1-spec",   "role": "spec integrity + anti-drift input contract"},
    "forgeline": {"cli": "forge",    "pip": "code-factory-2-forge",  "role": "agentic SDLC state machine + gates + smoke"},
    "hsf":       {"cli": "hsf",      "pip": "code-factory-3-compile","role": "compile-once deterministic decision artifacts"},
    "prestige":  {"cli": "prestige", "pip": "code-factory-4-design", "role": "design-quality scoring gate for UI"},
}


@dataclass
class Meter:
    wall_ms: int = 0
    model_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0

    def merge(self, other: "Meter") -> "Meter":
        return Meter(self.wall_ms + other.wall_ms,
                     self.model_calls + other.model_calls,
                     self.tokens_in + other.tokens_in,
                     self.tokens_out + other.tokens_out)


@dataclass
class Receipt:
    module: str
    stage: str
    feature: str
    ok: bool
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    meter: Meter = field(default_factory=Meter)
    attribution: dict | None = None
    ts: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    def write(self, root: Path) -> Path:
        d = Path(root) / LAYOUT["receipts"]
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{self.module}-{self.feature}-{self.stage}-{int(_dt.datetime.now().timestamp())}.json"
        payload = asdict(self)
        p.write_text(json.dumps(payload, indent=2, sort_keys=True))
        return p

    @classmethod
    def from_dict(cls, payload: dict) -> "Receipt":
        required = {"module", "stage", "feature", "ok"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"receipt missing required fields: {sorted(missing)}")
        attribution = payload.get("attribution")
        if attribution is not None:
            from .attribution import Attribution
            Attribution.from_dict(attribution)
        meter = payload.get("meter", {})
        if isinstance(meter, dict):
            meter = Meter(**meter)
        return cls(
            module=payload["module"],
            stage=payload["stage"],
            feature=payload["feature"],
            ok=bool(payload["ok"]),
            inputs=payload.get("inputs", {}),
            outputs=payload.get("outputs", {}),
            meter=meter,
            attribution=attribution,
            ts=payload.get("ts", _dt.datetime.now(_dt.timezone.utc).isoformat()),
        )


def ensure_layout(root: Path) -> None:
    root = Path(root)
    for sub in LAYOUT.values():
        (root / sub).mkdir(parents=True, exist_ok=True)


def sha_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16] if Path(path).exists() else ""
