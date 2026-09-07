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
import uuid

from .protocol import RECEIPT_SCHEMA, package_version

# Canonical subdirectories of a factory root.
LAYOUT = {
    "specs": "specs", "plans": "plans", "handoff": "handoff", "slices": "slices",
    "smoke": "smoke", "registry": "registry", "receipts": "receipts", "state": ".factory",
}

# The ordered assembly stages and which module owns each.
STAGES = [
    ("specline", "new",     "scaffold a spec + plan for the feature"),
    ("specline", "strict",  "reject ambiguity before the coder (input contract)"),
    ("specline", "verify-validators", "prove strict validators kill requirement mutants"),
    ("specline", "gate",    "seal the spec/plan gate"),
    ("specline", "tasks",   "emit task packets for agents"),
    ("forgeline", "architect", "SSAT / architecture-as-code"),
    ("forgeline", "review",  "judge + adversary + QA audit"),
    ("forgeline", "arch-gate", "architecture CI gate"),
    ("forgeline", "verify-tests", "prove behavioral smoke checks fail on the SSAT scaffold"),
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
        """Return a new meter whose counters are the sums of both observations."""
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
    tenant_id: str = "local"
    schema: str = RECEIPT_SCHEMA
    producer_version: str | None = None
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    meter: Meter = field(default_factory=Meter)
    attribution: dict | None = None
    ts: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    def write(self, root: Path) -> Path:
        """Write this receipt into the standard layout and return its final path."""
        d = Path(root) / LAYOUT["receipts"]
        d.mkdir(parents=True, exist_ok=True)
        if self.producer_version is None:
            package = MODULES.get(self.module, {}).get("pip", "code-factory")
            self.producer_version = package_version(package)
        p = d / f"{self.module}-{self.feature}-{self.stage}-{self.run_id[:12]}.json"
        payload = asdict(self)
        p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, payload: dict) -> "Receipt":
        """Validate and construct a receipt from its serialized dictionary form."""
        if not isinstance(payload, dict):
            raise ValueError("receipt must be an object")
        required = {"module", "stage", "feature", "ok"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"receipt missing required fields: {sorted(missing)}")
        if not isinstance(payload["module"], str) or not payload["module"].strip():
            raise ValueError("receipt module must be a non-empty string")
        if not isinstance(payload["stage"], str) or not payload["stage"].strip():
            raise ValueError("receipt stage must be a non-empty string")
        if not isinstance(payload["feature"], str) or not payload["feature"].strip():
            raise ValueError("receipt feature must be a non-empty string")
        # Do not coerce truthy strings such as "false".  Receipts are evidence
        # envelopes, so an ambiguous result must be rejected rather than
        # interpreted as a passing stage.
        if not isinstance(payload["ok"], bool):
            raise ValueError("receipt ok must be a boolean")
        # A receipt is an evidence envelope, not an arbitrary JSON object.
        # Accepting unknown schemas or silently inventing run/timestamp data
        # lets stale or forged files enter a readiness decision.  Migration of
        # old v1 envelopes belongs in ``enterprise_receipts``; the assembly
        # line consumes only the current, explicit protocol.
        if payload.get("schema") != RECEIPT_SCHEMA:
            raise ValueError(f"receipt schema must be {RECEIPT_SCHEMA}")
        for field_name in ("tenant_id", "run_id"):
            value = payload.get(field_name)
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > 256:
                raise ValueError(f"receipt {field_name} must be a non-empty bounded string")
        producer_version = payload.get("producer_version")
        if producer_version is not None and (not isinstance(producer_version, str) or len(producer_version.strip()) > 128):
            raise ValueError("receipt producer_version must be a bounded string")
        for field_name in ("inputs", "outputs"):
            value = payload.get(field_name)
            if not isinstance(value, dict):
                raise ValueError(f"receipt {field_name} must be an object")
        attribution = payload.get("attribution")
        if attribution is not None:
            from .attribution import Attribution
            Attribution.from_dict(attribution)
        meter = payload.get("meter", {})
        if not isinstance(meter, dict) or set(meter) - {"wall_ms", "model_calls", "tokens_in", "tokens_out"}:
            raise ValueError("receipt meter must contain only known counters")
        counters: dict[str, int] = {}
        for name in ("wall_ms", "model_calls", "tokens_in", "tokens_out"):
            value = meter.get(name, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"receipt meter {name} must be a non-negative integer")
            counters[name] = value
        meter = Meter(**counters)
        timestamp = payload.get("ts")
        if not isinstance(timestamp, str) or not timestamp.strip() or len(timestamp) > 128:
            raise ValueError("receipt ts must be a bounded ISO-8601 string")
        try:
            _dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("receipt ts must be a valid ISO-8601 timestamp") from exc
        return cls(
            module=payload["module"].strip(),
            stage=payload["stage"].strip(),
            feature=payload["feature"].strip(),
            ok=payload["ok"],
            tenant_id=payload["tenant_id"].strip(),
            schema=payload["schema"],
            producer_version=producer_version.strip() if isinstance(producer_version, str) else producer_version,
            run_id=payload["run_id"].strip(),
            inputs=payload["inputs"],
            outputs=payload["outputs"],
            meter=meter,
            attribution=attribution,
            ts=timestamp.strip(),
        )


def ensure_layout(root: Path) -> None:
    """Create every standard Code Factory evidence directory below the given root."""
    root = Path(root)
    for sub in LAYOUT.values():
        (root / sub).mkdir(parents=True, exist_ok=True)


def sha_of(path: Path) -> str:
    """Return a short SHA-256 digest for an existing file, or empty text if absent."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16] if Path(path).exists() else ""
