"""PRD-to-app scaffolding for Factoryline.

This module is deliberately deterministic. It does not call a model or claim to
finish bespoke product logic. It turns a PRD or prompt into a full-stack starter
repo with a blueprint, proof plan, smoke hooks, and docs that downstream agents
can harden through the existing factory gates.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import re


APP_SCHEMA = "factory.app_blueprint.v1"

STACKS = {
    "nextjs-fastapi-postgres": {
        "frontend": "Next.js",
        "backend": "FastAPI",
        "database": "Postgres",
        "test": "pytest + route smoke",
    },
    "nextjs-api-sqlite": {
        "frontend": "Next.js",
        "backend": "Next.js API routes",
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
    if any(term in low for term in ("clinical", "patient", "hipaa", "prior-auth", "prior auth")):
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
    return """:root { color-scheme: light; --ink: #172033; --accent: #2563eb; --paper: #f8fafc; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: var(--ink); background: white; }
.hero { min-height: 70vh; padding: 6rem 8vw; background: linear-gradient(135deg, #eef2ff, #f8fafc 54%, #ecfeff); }
.eyebrow { text-transform: uppercase; font-size: .78rem; letter-spacing: .08em; color: #2563eb; font-weight: 700; }
h1 { font-size: clamp(2.4rem, 6vw, 5rem); line-height: 1; margin: 0 0 1rem; max-width: 840px; }
p { font-size: 1.12rem; line-height: 1.7; max-width: 720px; }
.primary { display: inline-block; margin-top: 1.4rem; padding: .95rem 1.15rem; color: white; background: var(--accent); text-decoration: none; font-weight: 700; }
.panel { padding: 4rem 8vw; background: var(--paper); }
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
    return '''from fastapi.testclient import TestClient
from backend.main import app


def test_healthz():
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json()["ok"] is True
'''


def _schema_sql(blueprint: AppBlueprint) -> str:
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

## Evidence Bar

```text
PRD clarity      | ########## 100%
Architecture     | #########  90%
Runtime smoke    | #########  90%
Design fit       | ########   80%
PR evidence      | ########## 100%
```
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
factory optimize-pr --changed app_blueprint.json --feature {blueprint.name}
factory pr-pack {blueprint.name}
```

The scaffold is intentionally reviewable: product-specific logic should move
through SpecLine, ForgeLine, HSF, Prestige, and Factoryline evidence before
release.
"""


def scaffold_app(blueprint: AppBlueprint, *, out_dir: Path, prd_text: str) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write(out_dir / "app_blueprint.json", json.dumps(blueprint.to_dict(), indent=2))
    _write(out_dir / "PRD.md", prd_text)
    _write(out_dir / "README.md", _readme(blueprint))
    _write(out_dir / "docs" / "WORKFLOW.md", _workflow_doc(blueprint))
    _write(out_dir / "frontend" / "app" / "page.tsx", _frontend_page(blueprint))
    _write(out_dir / "frontend" / "app" / "globals.css", _frontend_css())
    _write(out_dir / "frontend" / "package.json", json.dumps({
        "scripts": {"dev": "next dev", "build": "next build"},
        "dependencies": {"next": "latest", "react": "latest", "react-dom": "latest"},
        "devDependencies": {"typescript": "latest"},
    }, indent=2))
    _write(out_dir / "backend" / "__init__.py", "")
    _write(out_dir / "backend" / "main.py", _backend_main(blueprint))
    _write(out_dir / "backend" / "requirements.txt", "fastapi\nuvicorn\npytest\nhttpx\n")
    _write(out_dir / "tests" / "test_health.py", _pytest_health())
    _write(out_dir / "db" / "schema.sql", _schema_sql(blueprint))
    _write(out_dir / "smoke" / f"{blueprint.name}.json", json.dumps({
        "checks": [{
            "name": "backend_health",
            "kind": "python",
            "run": "from fastapi.testclient import TestClient\nfrom backend.main import app\nassert TestClient(app).get('/healthz').json()['ok'] is True\n",
        }]
    }, indent=2))
    paths = sorted(str(path.relative_to(out_dir)).replace("\\", "/") for path in out_dir.rglob("*") if path.is_file())
    return {
        "schema": "factory.app_scaffold.v1",
        "app": blueprint.name,
        "out_dir": str(out_dir),
        "files": paths,
        "next_commands": [
            f"specline optimize-prd {out_dir / 'PRD.md'}",
            f"prestige brief {out_dir / 'PRD.md'} --purpose {blueprint.purpose}",
            f"factory optimize-pr --root {out_dir} --changed app_blueprint.json --feature {blueprint.name}",
        ],
    }


def app_from_prd(prd_path: Path, *, out_dir: Path | None = None, name: str | None = None,
                 stack: str = "nextjs-fastapi-postgres", purpose: str = "auto") -> dict:
    prd_path = Path(prd_path)
    text = prd_path.read_text(encoding="utf-8")
    blueprint = build_blueprint(text, source=str(prd_path), name=name, stack=stack, purpose=purpose)
    target = Path(out_dir) if out_dir else Path.cwd() / blueprint.name
    return scaffold_app(blueprint, out_dir=target, prd_text=text)


def app_from_prompt(prompt: str, *, out_dir: Path | None = None, name: str | None = None,
                    stack: str = "nextjs-fastapi-postgres", purpose: str = "auto") -> dict:
    prd_text = f"# {_extract_name(prompt, name).replace('-', ' ').title()}\n\n{prompt}\n"
    blueprint = build_blueprint(prd_text, source="prompt", name=name, stack=stack, purpose=purpose)
    target = Path(out_dir) if out_dir else Path.cwd() / blueprint.name
    return scaffold_app(blueprint, out_dir=target, prd_text=prd_text)
