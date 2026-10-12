"""PRD-to-app scaffolding for Factoryline.

This module is deliberately deterministic. It does not call a model or claim to
finish bespoke product logic. It turns a PRD or prompt into a full-stack starter
repo with a blueprint, handoff plan, smoke hooks, and docs that downstream agents
can harden through the existing factory gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import re
import os
import stat
import time
import tempfile
import secrets

from .assembly_process import run_cli_detailed
from .product_missions import (
    ProductMissionError,
    verify_mission_candidate,
    execute_mission_repair,
)

from .output_map import write_output_map


APP_SCHEMA = "factory.app_blueprint.v1"
STUDIO_JOURNEY_SCHEMA = "factory.studio.journey.v1"
STUDIO_ACTION_PLAN_SCHEMA = "factory.studio.action-plan.v1"
STUDIO_JOURNEY_MARKERS = tuple(f"STUDIO_JOURNEY_R{i}" for i in range(1, 10))
_STUDIO_MAX_LOG = 65_536
_STUDIO_MAX_PREVIEW = 8 * 1024
_STUDIO_MAX_TIME = 120
_STUDIO_MAX_MEMORY = 512
_STUDIO_MAX_PIDS = 64

STACKS = {
    "nextjs-fastapi-postgres": {
        "frontend": "Next.js",
        "backend": "FastAPI",
        "database": "Postgres",
        "test": "pytest + route smoke",
    },
    "react-fastapi-sqlite": {
        "frontend": "React + Vite",
        "backend": "FastAPI",
        "database": "SQLite",
        "test": "pytest + route smoke",
    },
    "react-fastapi-postgres": {
        "frontend": "React",
        "backend": "FastAPI",
        "database": "Postgres",
        "test": "pytest + route smoke",
    },
}

PURPOSE_DEFAULTS = {
    "healthcare": {
        "roles": ["patient", "clinician", "admin"],
        "workflows": ["submit_request", "clinical_review", "audit_decision"],
        "logic": ["eligibility_gate", "denial_reason_codes"],
    },
    "fintech": {
        "roles": ["customer", "analyst", "admin"],
        "workflows": ["submit_case", "risk_review", "audit_action"],
        "logic": ["risk_tier_gate", "approval_limit_rules"],
    },
    "saas": {
        "roles": ["user", "manager", "admin"],
        "workflows": ["create_record", "review_record", "export_receipt"],
        "logic": ["plan_limit_gate", "approval_policy"],
    },
    "marketplace": {
        "roles": ["buyer", "seller", "moderator"],
        "workflows": ["create_listing", "request_order", "resolve_dispute"],
        "logic": ["listing_quality_gate", "dispute_routing_rules"],
    },
    "developer": {
        "roles": ["developer", "maintainer", "reviewer"],
        "workflows": ["create_project", "run_checks", "publish_receipt"],
        "logic": ["gate_selection_rules", "release_readiness_rules"],
    },
}


@dataclass(frozen=True)
class AppBlueprint:
    name: str
    purpose: str
    stack: str
    prompt_source: str
    roles: list[str]
    workflows: list[str]
    deterministic_logic: list[str]
    required_gates: list[str]
    generated_at: str

    def to_dict(self) -> dict:
        """Serialize the blueprint as the stable public application schema."""
        return {
            "schema": APP_SCHEMA,
            "app": {
                "name": self.name,
                "purpose": self.purpose,
                "stack": {
                    "key": self.stack,
                    **STACKS[self.stack],
                },
                "prompt_source": self.prompt_source,
                "roles": self.roles,
                "workflows": self.workflows,
                "deterministic_logic": self.deterministic_logic,
                "required_gates": self.required_gates,
            },
            "generated_at": self.generated_at,
        }


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return text[:48] or "factory-app"


def _extract_name(text: str, fallback: str | None = None) -> str:
    if fallback:
        return _slug(fallback)
    heading = re.search(r"^#\s+(.+)$", text, re.M)
    if heading:
        return _slug(heading.group(1))
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9-]+", text.lower())
    stop = {"build", "create", "make", "an", "a", "the", "with", "for", "and"}
    useful = [word for word in words if word not in stop]
    return _slug("-".join(useful[:5]) or "factory-app")


def _purpose_from_text(text: str, explicit: str) -> str:
    if explicit != "auto":
        return explicit
    low = text.lower()
    if any(
        term in low
        for term in ("clinical", "patient", "hipaa", "prior-auth", "prior auth")
    ):
        return "healthcare"
    if any(term in low for term in ("payment", "invoice", "bank", "risk", "fintech")):
        return "fintech"
    if any(term in low for term in ("marketplace", "seller", "buyer", "listing")):
        return "marketplace"
    if any(term in low for term in ("api", "cli", "developer", "github")):
        return "developer"
    return "saas"


def build_blueprint(
    text: str,
    *,
    source: str,
    name: str | None = None,
    stack: str = "nextjs-fastapi-postgres",
    purpose: str = "auto",
) -> AppBlueprint:
    """Build a deterministic application blueprint or reject an unknown stack."""
    if stack not in STACKS:
        raise ValueError(f"unknown stack: {stack}")
    resolved_purpose = _purpose_from_text(text, purpose)
    defaults = PURPOSE_DEFAULTS.get(resolved_purpose, PURPOSE_DEFAULTS["saas"])
    return AppBlueprint(
        name=_extract_name(text, name),
        purpose=resolved_purpose,
        stack=stack,
        prompt_source=source,
        roles=list(defaults["roles"]),
        workflows=list(defaults["workflows"]),
        deterministic_logic=list(defaults["logic"]),
        required_gates=[
            "prd_optimized",
            "strict_spec",
            "hollow_validators",
            "architecture_gate",
            "hollow_tests",
            "runtime_smoke",
            "design_brief",
            "design_audit",
            "pr_pack",
        ],
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _studio_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _studio_sha(value: object) -> str:
    return sha256(_studio_json(value)).hexdigest()


def _studio_argv(argv: object) -> list[str]:
    shells = {
        "sh",
        "bash",
        "dash",
        "zsh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
    if (
        not isinstance(argv, list)
        or not argv
        or any(
            not isinstance(arg, str) or not arg or len(arg) > 4096 or "\x00" in arg
            for arg in argv
        )
    ):
        raise ValueError("approved argv is malformed")
    executable = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if executable in shells:
        raise ValueError("shell commands are not permitted in the isolated runner")
    return argv


def _studio_log(value: object) -> str:
    text = (
        value.decode("utf-8", errors="replace")
        if isinstance(value, bytes)
        else str(value or "")
    )
    return text.encode("utf-8", errors="replace")[:8_192].decode(
        "utf-8", errors="ignore"
    )


def _studio_file(path: Path, anchor: Path, maximum: int) -> Path:
    from .studio import _studio_file as implementation

    return implementation(path, anchor, maximum)


def _studio_evidence_dir(root: Path, *, create: bool = False) -> Path:
    from .studio import _studio_evidence_dir as implementation

    return implementation(root, create=create)


def _studio_binding(root: Path, payload: dict) -> tuple[Path, str, dict, dict]:
    root = root.resolve(strict=True)
    binding_value = payload.get("binding_path")
    if not isinstance(binding_value, str) or not binding_value:
        raise ValueError("binding_path is required")
    given = Path(binding_value)
    binding_path = _studio_file(
        given if given.is_absolute() else root / given, root, 1_048_576
    )
    owner = payload.get("owner")
    if (
        not isinstance(owner, str)
        or not owner.strip()
        or not binding_path.is_relative_to(root)
    ):
        raise ProductMissionError(
            "MISSION_CANDIDATE_INVALID", "binding or owner is invalid"
        )
    verification = verify_mission_candidate(binding_path, root, owner=owner)
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    return binding_path, owner, verification, binding


def _studio_revalidate(
    root: Path, payload: dict, expected: str
) -> tuple[Path, str, dict, dict]:
    current = _studio_binding(root, payload)
    if current[2]["binding_sha256"] != expected:
        raise ProductMissionError(
            "MISSION_CANDIDATE_INVALID", "candidate binding changed"
        )
    return current


def _studio_write(root: Path, kind: str, value: dict) -> Path:
    root = root.resolve(strict=True)
    directory = _studio_evidence_dir(root, create=True)
    digest = _studio_sha(value)
    path = (
        directory / f"{kind}-{time.time_ns()}-{secrets.token_hex(6)}-{digest[:12]}.json"
    )
    envelope = {"receipt": value, "receipt_sha256": digest}
    serialized = _studio_json(envelope)
    if len(serialized) > 65_536:
        raise ValueError("Studio stage receipt exceeds 65536 bytes")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(serialized)
    return path


def studio_journey_status(root: Path, payload: dict) -> dict:
    from .studio import studio_journey_status as implementation

    return implementation(root, payload)


def studio_journey_plan(root: Path, payload: dict) -> dict:
    from .studio import studio_journey_plan as implementation

    return implementation(root, payload)


def _studio_read_plan(root: Path, payload: dict) -> tuple[dict, str]:
    from .studio import _studio_read_plan as implementation

    return implementation(root, payload)


def _studio_bind_plan(root: Path, payload: dict, plan: dict) -> tuple[dict, dict]:
    from .studio import _studio_bind_plan as implementation

    return implementation(root, payload, plan)


def _studio_validated_plan(
    root: Path, payload: dict
) -> tuple[dict, str, dict, dict, dict]:
    root = root.resolve(strict=True)
    plan, digest = _studio_read_plan(root, payload)
    verification, binding = _studio_bind_plan(root, payload, plan)
    return (
        plan,
        digest,
        {"binding_path": plan["binding_path"], "owner": payload.get("owner")},
        verification,
        binding,
    )


def _studio_snapshot(workspace: Path, entries: list[dict]) -> Path:
    snapshot = Path(tempfile.mkdtemp(prefix="factory-studio-snapshot-"))
    try:
        for entry in entries:
            if entry["state"] != "existing":
                continue
            source = _studio_file(
                workspace / entry["path"], workspace, 16 * 1024 * 1024
            )
            if not stat.S_ISREG(source.lstat().st_mode):
                raise ProductMissionError(
                    "MISSION_CANDIDATE_INVALID",
                    "candidate snapshot contains a link or special file",
                )
            source_bytes = source.read_bytes()
            if sha256(source_bytes).hexdigest() != entry["sha256"]:
                raise ProductMissionError(
                    "MISSION_CANDIDATE_INVALID",
                    "candidate source changed during snapshot",
                )
            target = snapshot / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source_bytes)
    except BaseException:
        import shutil

        shutil.rmtree(snapshot, ignore_errors=True)
        raise
    return snapshot


def _studio_container(snapshot: Path, workspace: Path, plan: dict) -> tuple[dict, bool]:
    name = "studio-" + secrets.token_hex(10)
    argv = plan["argv"]
    if not argv or argv[0].startswith("-"):
        raise ValueError("approved command must begin with an explicit executable")
    args = [
        "run",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--memory=512m",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--mount",
        f"type=bind,src={snapshot},dst=/workspace,readonly",
        "--workdir",
        "/workspace",
        "--entrypoint",
        argv[0],
        plan["image"],
        *argv[1:],
    ]
    try:
        result = run_cli_detailed(
            "docker",
            args,
            workspace,
            timeout=_STUDIO_MAX_TIME,
            max_stream_bytes=_STUDIO_MAX_LOG,
        )
    except Exception as error:
        result = {
            "ok": False,
            "exit_code": None,
            "reason": type(error).__name__,
            "output": str(error),
            "cleanup_confirmed": False,
            "streams_closed": False,
        }
    try:
        cleanup = run_cli_detailed(
            "docker",
            ["rm", "--force", name],
            workspace,
            timeout=10,
            max_stream_bytes=4096,
        )
        inspect = run_cli_detailed(
            "docker",
            ["inspect", "--type", "container", name],
            workspace,
            timeout=10,
            max_stream_bytes=4096,
        )
    except Exception:
        cleanup, inspect = {}, {"output": "container absence not verified"}
    detail = (
        str(inspect.get("output", ""))
        + bytes(inspect.get("stderr", b"")).decode("utf-8", errors="replace")
    ).lower()
    removed = bool(
        ("no such container" in detail or "no such object" in detail)
        and cleanup.get("ok") is True
        and cleanup.get("exit_code") == 0
        and cleanup.get("cleanup_confirmed") is True
        and cleanup.get("streams_closed") is True
    )
    result["container_removed"] = removed
    result["ok"] = (
        bool(result.get("ok"))
        and result.get("exit_code") == 0
        and result.get("streams_closed") is True
        and removed
    )
    return result, removed


def _studio_after_execution(
    root: Path, payload: dict, plan: dict, verification: dict
) -> tuple[bool, str | None]:
    try:
        _, _, after, binding_after = _studio_revalidate(
            root, payload, plan["binding_sha256"]
        )
        return after["candidate_sha256"] == verification[
            "candidate_sha256"
        ] and binding_after["files"] == plan["candidate_files"], None
    except (OSError, ValueError, ProductMissionError) as error:
        return False, type(error).__name__


def _studio_telemetry(stage: str, result: dict, duration: float) -> dict:
    from .operations import TelemetryRecorder

    recorder = TelemetryRecorder("local-workspace", service="factory.studio")
    span = recorder.span(
        f"studio.{stage}",
        status="OK" if result.get("ok") is True else "ERROR",
        duration_ms=max(0, round(duration * 1000)),
        attributes={
            "stage": stage,
            "result_sha256": _studio_sha(result),
            "receipt_schema": "factory.studio.attempt.v1",
        },
    )
    return {
        key: span[key]
        for key in (
            "schema",
            "trace_id",
            "span_id",
            "name",
            "status",
            "duration_ms",
            "attributes",
            "span_sha256",
        )
    }


def _studio_execute_plan(root: Path, payload: dict) -> dict:
    root = root.resolve(strict=True)
    plan, digest, binding_payload, verification, binding = _studio_validated_plan(
        root, payload
    )
    workspace = Path(binding["workspace"]).resolve(strict=True)
    started = time.monotonic()
    snapshot = _studio_snapshot(workspace, plan["candidate_files"])
    try:
        _, _, before, _ = _studio_revalidate(
            root, binding_payload, plan["binding_sha256"]
        )
        if before["candidate_sha256"] != verification["candidate_sha256"]:
            raise ProductMissionError(
                "MISSION_CANDIDATE_INVALID", "candidate changed before execution"
            )
        result, container_removed = _studio_container(snapshot, workspace, plan)
    finally:
        import shutil

        shutil.rmtree(snapshot, ignore_errors=True)
    unchanged, drift = _studio_after_execution(
        root, binding_payload, plan, verification
    )
    attempt = {
        "schema": "factory.studio.attempt.v1",
        "stage": "verification" if plan["stage"] == "verify" else plan["stage"],
        "candidate_sha256": verification["candidate_sha256"],
        "binding_sha256": verification["binding_sha256"],
        "plan_sha256": digest,
        "argv": plan["argv"],
        "image": plan["image"],
        "exit_code": result.get("exit_code"),
        "ok": bool(result.get("ok")) and unchanged and container_removed,
        "timed_out": result.get("reason") == "timeout",
        "duration_seconds": round(time.monotonic() - started, 3),
        "cleanup_confirmed": result.get("cleanup_confirmed") is True
        and result.get("streams_closed") is True
        and container_removed,
        "container_removed": container_removed,
        "stdout": _studio_log(result.get("stdout", result.get("output", ""))),
        "stderr": _studio_log(result.get("stderr", b"")),
        "candidate_unchanged": unchanged,
        "post_execution_drift": drift,
        "markers": list(STUDIO_JOURNEY_MARKERS),
        "invariants": {
            marker: (
                "checked"
                if marker
                in {
                    "STUDIO_JOURNEY_R2",
                    "STUDIO_JOURNEY_R3",
                    "STUDIO_JOURNEY_R4",
                    "STUDIO_JOURNEY_R5",
                    "STUDIO_JOURNEY_R8",
                }
                else "not_applicable"
            )
            for marker in STUDIO_JOURNEY_MARKERS
        },
    }
    attempt["telemetry"] = _studio_telemetry(
        attempt["stage"], attempt, attempt["duration_seconds"]
    )
    receipt_path = _studio_write(root, "attempt", attempt)
    return {**attempt, "path": str(receipt_path)}


def serve_studio_preview_asset(
    root: Path,
    binding_path: Path,
    owner: str,
    relative_path: str,
    *,
    max_bytes: int = _STUDIO_MAX_PREVIEW,
) -> dict:
    from .studio import serve_studio_preview_asset as implementation

    return implementation(root, binding_path, owner, relative_path, max_bytes=max_bytes)


def studio_journey(root: Path, payload: dict) -> dict:
    """Dispatch a bounded Studio journey action over an existing approved mission."""
    action = payload.get("action")
    if action == "status":
        return studio_journey_status(root, payload)
    if action == "plan":
        return studio_journey_plan(root, payload)
    if action == "execute":
        return _studio_execute_plan(root, payload)
    if action == "preview":
        _, owner, verification, _ = _studio_binding(root, payload)
        result = serve_studio_preview_asset(
            root, Path(payload["binding_path"]), owner, payload.get("path", "")
        )
        receipt = {
            "schema": "factory.studio.attempt.v1",
            "stage": "preview",
            "candidate_sha256": verification["candidate_sha256"],
            "binding_sha256": verification["binding_sha256"],
            "ok": True,
            "path": result["path"],
            "markers": list(STUDIO_JOURNEY_MARKERS),
            "invariants": {
                marker: (
                    "checked"
                    if marker
                    in {
                        "STUDIO_JOURNEY_R2",
                        "STUDIO_JOURNEY_R3",
                        "STUDIO_JOURNEY_R6",
                        "STUDIO_JOURNEY_R8",
                    }
                    else "not_applicable"
                )
                for marker in STUDIO_JOURNEY_MARKERS
            },
        }
        response = {
            "schema": "factory.studio.preview.v1",
            **result,
            "receipt_path": str(_studio_write(root, "attempt", receipt)),
        }
        if len(_studio_json(response)) > 65_536:
            raise ValueError("preview stage response exceeds 65536 bytes")
        return response
    if action == "repair":
        _, owner, verification, _ = _studio_binding(root, payload)
        started = time.monotonic()
        result = execute_mission_repair(
            Path(payload["binding_path"]),
            Path(payload["approval_path"]),
            root,
            owner=owner,
        )
        duration = time.monotonic() - started
        receipt = {
            "schema": "factory.studio.attempt.v1",
            "stage": "repair",
            "candidate_sha256": verification["candidate_sha256"],
            "binding_sha256": verification["binding_sha256"],
            "ok": result.get("status") == "VERIFIED",
            "repair_result": {
                "status": result.get("status"),
                "attempt_id": result.get("attempt_id"),
            },
            "repair_result_sha256": _studio_sha(result),
            "duration_seconds": round(duration, 3),
            "markers": list(STUDIO_JOURNEY_MARKERS),
            "invariants": {
                marker: (
                    "checked"
                    if marker
                    in {"STUDIO_JOURNEY_R2", "STUDIO_JOURNEY_R7", "STUDIO_JOURNEY_R8"}
                    else "not_applicable"
                )
                for marker in STUDIO_JOURNEY_MARKERS
            },
        }
        receipt["telemetry"] = _studio_telemetry("repair", receipt, duration)
        return {**receipt, "path": str(_studio_write(root, "attempt", receipt))}
    raise ValueError("unknown Studio journey action")


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def _frontend_page(blueprint: AppBlueprint) -> str:
    title = blueprint.name.replace("-", " ").title()
    workflow = blueprint.workflows[0].replace("_", " ")
    return f"""export default function Home() {{
  return (
    <main>
      <section className="hero">
        <p className="eyebrow">{blueprint.purpose} app factory starter</p>
        <h1>{title}</h1>
        <p>Generated from a PRD with gates for spec clarity, architecture, smoke, design, and PR evidence.</p>
        <a className="primary" href="/api/health">Check API health</a>
      </section>
      <section className="panel">
        <h2>Primary workflow</h2>
        <p>{workflow}</p>
      </section>
    </main>
  );
}}
"""


def _frontend_css() -> str:
    return """:root { color-scheme: light; --ink: #172033; --accent: #166534; --signal: #b45309; --paper: #f6f8fa; --line: #d7dee7; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: var(--ink); background: white; }
.hero { min-height: 70vh; padding: 6rem 8vw; background: white; border-bottom: 1px solid var(--line); }
.eyebrow { text-transform: uppercase; font-size: .78rem; letter-spacing: 0; color: var(--signal); font-weight: 800; }
h1 { font-size: 4.5rem; line-height: 1.04; margin: 0 0 1rem; max-width: 840px; }
p { font-size: 1.12rem; line-height: 1.7; max-width: 720px; }
.primary { display: inline-block; margin-top: 1.4rem; padding: .95rem 1.15rem; border-radius: 6px; color: white; background: var(--accent); text-decoration: none; font-weight: 700; }
.panel { padding: 4rem 8vw; background: var(--paper); border-bottom: 4px solid var(--signal); }
@media (max-width: 720px) { .hero { min-height: 64vh; padding: 4rem 7vw; } h1 { font-size: 2.8rem; } }
"""


def _backend_main(blueprint: AppBlueprint) -> str:
    return f'''"""FastAPI starter generated by Code Factory."""
from fastapi import FastAPI

app = FastAPI(title="{blueprint.name}")


@app.get("/healthz")
def healthz():
    return {{"ok": True, "app": "{blueprint.name}", "purpose": "{blueprint.purpose}"}}
'''


def _pytest_health() -> str:
    return """from fastapi.testclient import TestClient
from backend.main import app


def test_healthz():
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json()["ok"] is True
"""


def _schema_sql(blueprint: AppBlueprint) -> str:
    if STACKS[blueprint.stack]["database"] == "SQLite":
        return f"""create table if not exists audit_events (
  id integer primary key autoincrement,
  app_name text not null default '{blueprint.name}',
  actor text not null,
  action text not null,
  created_at text not null default current_timestamp
);

create table if not exists workflow_items (
  id integer primary key autoincrement,
  workflow text not null,
  status text not null default 'draft',
  payload text not null default '{{}}',
  created_at text not null default current_timestamp
);
"""
    return f"""create table if not exists audit_events (
  id bigserial primary key,
  app_name text not null default '{blueprint.name}',
  actor text not null,
  action text not null,
  created_at timestamptz not null default now()
);

create table if not exists workflow_items (
  id bigserial primary key,
  workflow text not null,
  status text not null default 'draft',
  payload jsonb not null default '{{}}'::jsonb,
  created_at timestamptz not null default now()
);
"""


def _workflow_doc(blueprint: AppBlueprint) -> str:
    gates = "\n".join(f"- {gate}" for gate in blueprint.required_gates)
    workflows = "\n".join(f"- {item}" for item in blueprint.workflows)
    logic = "\n".join(f"- {item}" for item in blueprint.deterministic_logic)
    return f"""# PRD-to-App Factory Workflow

```mermaid
flowchart TD
    A["PRD or prompt"] --> B["SpecLine optimize-prd"]
    B --> C["App blueprint"]
    C --> D["Full-stack scaffold"]
    D --> E["Prestige design brief"]
    E --> F["ForgeLine hardening loop"]
    F --> G["HSF deterministic logic"]
    G --> H["Factory PR evidence packet"]
```

## Workflows

{workflows}

## Deterministic Logic Candidates

{logic}

## Required Gates

{gates}

## Illustrative Readiness Model

```text
PRD clarity      | NOT RUN
Architecture     | NOT RUN
Runtime smoke    | NOT RUN
Design fit       | NOT RUN
PR evidence      | NOT RUN
```

These bars are not measured gate results. They are a visual map of the readiness
dimensions this starter is prepared to hand off to the factory. Replace them
with receipt-backed evidence only after the gates run.

## Coverage Gate

```bash
factory coverage --root .
```

Generated starters cover only `RUNTIME_HEALTH` at first. Product requirements
remain intentionally uncovered until you add non-hollow smoke checks with
`covers[]` entries.
"""


def _readme(blueprint: AppBlueprint) -> str:
    title = blueprint.name.replace("-", " ").title()
    return f"""# {title}

Generated by `factory app` as a PRD-to-app starter.

## Stack

- Frontend: {STACKS[blueprint.stack]["frontend"]}
- Backend: {STACKS[blueprint.stack]["backend"]}
- Database: {STACKS[blueprint.stack]["database"]}
- Purpose: {blueprint.purpose}

## Next Commands

```bash
specline optimize-prd PRD.md
prestige brief PRD.md --purpose {blueprint.purpose}
forge verify-tests {blueprint.name} {blueprint.name}.ssat.yaml --root .
factory coverage --root .
factory optimize-pr --changed app_blueprint.json --feature {blueprint.name}
factory pr-pack {blueprint.name}
```

`factory coverage` is expected to report `hollow_coverage` on a fresh starter
until product-specific smoke checks are added.

The scaffold is intentionally reviewable: product-specific logic should move
through SpecLine, ForgeLine, HSF, Prestige, and Factoryline evidence before
release.
"""


def _ssat_yaml(blueprint: AppBlueprint) -> str:
    return f"""name: {blueprint.name}
modules:
  - name: backend
    path: backend/main.py
    imports: []
    functions:
      - name: healthz
        args: []
        returns: "dict"
        doc: "Return API health and app identity."
dependencies: []
invariants:
  - name: no_eval
    forbid_pattern: "\\\\beval\\\\("
  - name: no_hardcoded_secret
    forbid_pattern: "(?i)(api_key|secret|password)\\\\s*=\\\\s*['\\"]"
"""


def _coverage_manifest(blueprint: AppBlueprint) -> str:
    requirements = [
        {
            "id": "RUNTIME_HEALTH",
            "summary": "The backend exposes a health endpoint that returns ok=true.",
            "source": "generated",
        }
    ]
    for workflow in blueprint.workflows:
        requirements.append(
            {
                "id": f"WORKFLOW_{workflow.upper()}",
                "summary": f"The app supports the {workflow.replace('_', ' ')} workflow.",
                "source": "blueprint.workflow",
            }
        )
    for rule in blueprint.deterministic_logic:
        requirements.append(
            {
                "id": f"LOGIC_{rule.upper()}",
                "summary": f"The deterministic rule {rule.replace('_', ' ')} is enforced.",
                "source": "blueprint.deterministic_logic",
            }
        )
    return json.dumps(
        {
            "schema": "factory.requirement_coverage.v1",
            "app": blueprint.name,
            "requirements": requirements,
        },
        indent=2,
    )


def _forge_state(blueprint: AppBlueprint) -> str:
    return json.dumps(
        {
            "feature": blueprint.name,
            "state": "blocked",
            "created": blueprint.generated_at,
            "attempts": {},
            "history": [
                {
                    "ts": blueprint.generated_at,
                    "state": "blocked",
                    "note": "factory app starter generated; run forge verify-tests before smoke",
                }
            ],
        },
        indent=2,
    )


def scaffold_app(blueprint: AppBlueprint, *, out_dir: Path, prd_text: str) -> dict:
    """Write an app-shaped starter into the requested output directory."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write(out_dir / "app_blueprint.json", json.dumps(blueprint.to_dict(), indent=2))
    _write(out_dir / "PRD.md", prd_text)
    _write(out_dir / "README.md", _readme(blueprint))
    _write(out_dir / "docs" / "WORKFLOW.md", _workflow_doc(blueprint))
    _write(out_dir / f"{blueprint.name}.ssat.yaml", _ssat_yaml(blueprint))
    _write(out_dir / "coverage" / "requirements.json", _coverage_manifest(blueprint))
    _write(out_dir / ".forge" / blueprint.name / "state.json", _forge_state(blueprint))
    if STACKS[blueprint.stack]["frontend"] == "Next.js":
        _write(out_dir / "frontend" / "app" / "page.tsx", _frontend_page(blueprint))
        _write(
            out_dir / "frontend" / "app" / "layout.tsx",
            """import "./globals.css";
import type { ReactNode } from "react";

export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
""",
        )
        _write(
            out_dir / "frontend" / "tsconfig.json",
            json.dumps(
                {
                    "compilerOptions": {
                        "target": "ES2022",
                        "lib": ["dom", "dom.iterable", "esnext"],
                        "allowJs": False,
                        "skipLibCheck": True,
                        "strict": True,
                        "noEmit": True,
                        "esModuleInterop": True,
                        "module": "esnext",
                        "moduleResolution": "bundler",
                        "resolveJsonModule": True,
                        "isolatedModules": True,
                        "jsx": "react-jsx",
                        "incremental": True,
                        "plugins": [{"name": "next"}],
                    },
                    "include": [
                        "next-env.d.ts",
                        ".next/types/**/*.ts",
                        ".next/dev/types/**/*.ts",
                        "**/*.ts",
                        "**/*.tsx",
                    ],
                    "exclude": ["node_modules"],
                },
                indent=2,
            ),
        )
        _write(
            out_dir / "frontend" / "next-env.d.ts",
            '/// <reference types="next" />\n/// <reference types="next/image-types/global" />',
        )
        _write(
            out_dir / "frontend" / "next.config.ts",
            """import type { NextConfig } from "next";

const config: NextConfig = {
  turbopack: { root: process.cwd() },
};

export default config;
""",
        )
        frontend_package = {
            "scripts": {
                "dev": "next dev",
                "build": "next build",
                "typecheck": "tsc --noEmit",
            },
            "dependencies": {
                "next": "16.2.10",
                "react": "19.2.7",
                "react-dom": "19.2.7",
            },
            "devDependencies": {
                "@types/node": "^24.0.0",
                "@types/react": "^19.2.0",
                "@types/react-dom": "^19.2.0",
                "typescript": "^5.9.0",
            },
            "overrides": {"postcss": "8.5.19"},
        }
    else:
        _write(out_dir / "frontend" / "src" / "App.tsx", _frontend_page(blueprint))
        _write(
            out_dir / "frontend" / "src" / "main.tsx",
            """import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
""",
        )
        _write(
            out_dir / "frontend" / "index.html",
            '<!doctype html><html><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>',
        )
        _write(
            out_dir / "frontend" / "vite.config.ts",
            """import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({ plugins: [react()] });
""",
        )
        _write(
            out_dir / "frontend" / "tsconfig.json",
            json.dumps(
                {
                    "compilerOptions": {
                        "target": "ES2022",
                        "useDefineForClassFields": True,
                        "lib": ["ES2022", "DOM", "DOM.Iterable"],
                        "allowJs": False,
                        "skipLibCheck": True,
                        "esModuleInterop": True,
                        "allowSyntheticDefaultImports": True,
                        "strict": True,
                        "forceConsistentCasingInFileNames": True,
                        "module": "ESNext",
                        "moduleResolution": "Bundler",
                        "resolveJsonModule": True,
                        "isolatedModules": True,
                        "noEmit": True,
                        "jsx": "react-jsx",
                    },
                    "include": ["src", "vite.config.ts"],
                },
                indent=2,
            ),
        )
        frontend_package = {
            "scripts": {
                "dev": "vite",
                "build": "tsc && vite build",
                "typecheck": "tsc --noEmit",
            },
            "dependencies": {"react": "19.2.7", "react-dom": "19.2.7"},
            "devDependencies": {
                "@types/react": "^19.2.0",
                "@types/react-dom": "^19.2.0",
                "@vitejs/plugin-react": "^6.0.0",
                "typescript": "^5.9.0",
                "vite": "^8.0.0",
            },
        }
    css_path = (
        "app/globals.css"
        if STACKS[blueprint.stack]["frontend"] == "Next.js"
        else "src/globals.css"
    )
    _write(out_dir / "frontend" / css_path, _frontend_css())
    _write(
        out_dir / "frontend" / "package.json", json.dumps(frontend_package, indent=2)
    )
    _write(out_dir / "backend" / "__init__.py", "")
    _write(out_dir / "backend" / "main.py", _backend_main(blueprint))
    _write(
        out_dir / "backend" / "requirements.txt", "fastapi\nuvicorn\npytest\nhttpx\n"
    )
    _write(out_dir / "tests" / "test_health.py", _pytest_health())
    _write(out_dir / "db" / "schema.sql", _schema_sql(blueprint))
    _write(
        out_dir / "smoke" / f"{blueprint.name}.json",
        json.dumps(
            {
                "checks": [
                    {
                        "name": "backend_health",
                        "kind": "python",
                        "run": "from fastapi.testclient import TestClient\nfrom backend.main import app\nassert TestClient(app).get('/healthz').json()['ok'] is True\n",
                        "covers": ["RUNTIME_HEALTH"],
                        "must_fail_on_stub": True,
                    }
                ]
            },
            indent=2,
        ),
    )
    output_map = write_output_map(
        out_dir,
        name=blueprint.name,
        source_sha256=sha256(prd_text.encode("utf-8")).hexdigest(),
        status="compiled_blocked",
    )
    paths = sorted(
        str(path.relative_to(out_dir)).replace("\\", "/")
        for path in out_dir.rglob("*")
        if path.is_file()
    )
    return {
        "schema": "factory.app_scaffold.v1",
        "app": blueprint.name,
        "out_dir": str(out_dir),
        "files": paths,
        "output_map": str(out_dir / str(output_map["path"])),
        "output_map_sha256": output_map["sha256"],
        "markers": ["APP_OUTPUT_MAP_WRITTEN"],
        "next_commands": [
            f"specline optimize-prd {out_dir / 'PRD.md'}",
            f"prestige brief {out_dir / 'PRD.md'} --purpose {blueprint.purpose}",
            f"forge verify-tests {blueprint.name} {out_dir / (blueprint.name + '.ssat.yaml')} --root {out_dir}",
            f"factory coverage --root {out_dir}",
            f"factory optimize-pr --root {out_dir} --changed app_blueprint.json --feature {blueprint.name}",
        ],
    }


def app_from_prd(
    prd_path: Path,
    *,
    out_dir: Path | None = None,
    name: str | None = None,
    stack: str = "nextjs-fastapi-postgres",
    purpose: str = "auto",
) -> dict:
    """Build and scaffold an application from a readable PRD file."""
    prd_path = Path(prd_path)
    text = prd_path.read_text(encoding="utf-8")
    blueprint = build_blueprint(
        text, source=str(prd_path), name=name, stack=stack, purpose=purpose
    )
    target = Path(out_dir) if out_dir else Path.cwd() / blueprint.name
    return scaffold_app(blueprint, out_dir=target, prd_text=text)


def app_from_prompt(
    prompt: str,
    *,
    out_dir: Path | None = None,
    name: str | None = None,
    stack: str = "nextjs-fastapi-postgres",
    purpose: str = "auto",
) -> dict:
    """Build and scaffold an application from a product prompt."""
    prd_text = (
        f"# {_extract_name(prompt, name).replace('-', ' ').title()}\n\n{prompt}\n"
    )
    blueprint = build_blueprint(
        prd_text, source="prompt", name=name, stack=stack, purpose=purpose
    )
    target = Path(out_dir) if out_dir else Path.cwd() / blueprint.name
    return scaffold_app(blueprint, out_dir=target, prd_text=prd_text)
