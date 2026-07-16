"""Compile one intent into a governed, reviewable software starter target."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import os
import re
import shutil
import tempfile

from .app_builder import app_from_prd, app_from_prompt, _extract_name, _purpose_from_text


TARGET_SCHEMA = "factory.target.v1"
COMPILE_RECEIPT_SCHEMA = "factory.target_compile_receipt.v1"
SUPPORTED_TRIGGERS = ("manual", "cron", "hook", "goal", "heartbeat")
TARGETS: dict[str, dict[str, Any]] = {
    "worker": {
        "label": "Headless worker",
        "runtime_mode": "deterministic",
        "entrypoint": "python -m worker.main",
        "summary": "A bounded Python worker for schedules, hooks, and local automation.",
    },
    "web": {
        "label": "Web app",
        "runtime_mode": "governed_application",
        "entrypoint": "frontend + backend",
        "summary": "A reviewable web starter with API, database, smoke, and proof hooks.",
    },
    "mobile": {
        "label": "Expo mobile app",
        "runtime_mode": "governed_application",
        "entrypoint": "npm --prefix mobile start",
        "summary": "An Expo SDK 57 TypeScript starter using Continuous Native Generation.",
    },
    "agent-ui": {
        "label": "Agent operator UI",
        "runtime_mode": "supervised_agent",
        "entrypoint": "frontend + backend",
        "summary": "A human-operated task surface with approval and receipt boundaries.",
    },
}


class TargetCompileError(ValueError):
    """A fail-closed target compilation error with a stable public code."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _write(path, json.dumps(value, indent=2, sort_keys=True))


def _file_sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _validate_request(text: str, target: str, trigger: str) -> None:
    if not text.strip():
        raise TargetCompileError("SOURCE_REQUIRED", "prompt or PRD content must be non-empty")
    if target not in TARGETS:
        raise TargetCompileError("TARGET_UNSUPPORTED", f"target must be one of {', '.join(TARGETS)}")
    if trigger not in SUPPORTED_TRIGGERS:
        raise TargetCompileError("TRIGGER_UNSUPPORTED", f"trigger must be one of {', '.join(SUPPORTED_TRIGGERS)}")


def _prepare_destination(out_dir: Path) -> Path:
    target = Path(out_dir).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if not target.is_dir() or any(target.iterdir()):
            raise TargetCompileError("OUTPUT_EXISTS", f"refusing non-empty output: {target}")
    return target


def _manifest(name: str, target: str, purpose: str, trigger: str, source_kind: str,
              source_sha256: str) -> dict[str, Any]:
    runtime = TARGETS[target]["runtime_mode"]
    return {
        "schema": TARGET_SCHEMA,
        "name": name,
        "target_kind": target,
        "runtime": {
            "mode": runtime,
            "model_calls": "disabled_by_default",
            "entrypoint": TARGETS[target]["entrypoint"],
        },
        "intent": {
            "source_kind": source_kind,
            "source_sha256": source_sha256,
            "purpose": purpose,
        },
        "trigger": {"kind": trigger, "configuration": "review_required" if trigger != "manual" else "local"},
        "connectors": [],
        "allowed_actions": ["read_project", "write_target_output", "run_local_checks"],
        "budgets": {
            "max_iterations": 5,
            "max_wall_seconds": 900,
            "max_build_tokens": 0,
            "max_runtime_cost_usd": 0,
        },
        "approvals": {
            "required_for": ["deploy", "publish", "sign", "destructive_action", "external_message", "connector_grant"],
        },
        "privacy": {
            "source_boundary": "local_workspace",
            "network_egress": "not_granted",
            "credential_injection": "not_granted",
        },
        "promotion": {
            "state": "blocked",
            "reason": "product-specific proof gates have not run",
        },
    }


def _architecture_mermaid(target: str) -> str:
    runtime = "Deterministic runtime" if target == "worker" else "Governed application runtime"
    return f'''flowchart LR
    I["Intent"] --> T["{TARGETS[target]['label']}"]
    T --> R["{runtime}"]
    T --> G["Spec, architecture, smoke, design gates"]
    G --> C["Hash-bound compile receipt"]
    C --> H["Human release approval"]
    R --> M["Measured local runtime"]
    classDef intent fill:#dbeafe,stroke:#2563eb,color:#10233f
    classDef target fill:#fef3c7,stroke:#d97706,color:#10233f
    classDef proof fill:#dcfce7,stroke:#16a34a,color:#10233f
    classDef human fill:#fee2e2,stroke:#dc2626,color:#10233f
    class I intent
    class T,R,M target
    class G,C proof
    class H human
'''


def _forge_state(name: str) -> dict[str, Any]:
    return {
        "feature": name,
        "state": "blocked",
        "attempts": {},
        "history": [{"state": "blocked", "note": "target compiled; product-specific proof has not run"}],
    }


def _common_docs(name: str, target: str) -> str:
    return f"""# Target workflow

```mermaid
{_architecture_mermaid(target).rstrip()}
```

## Promotion boundary

This `{target}` target is a starter. Deployment, publication, signing,
destructive actions, connector grants, and external messages require explicit
human approval. Run the generated smoke and coverage checks before adding
product-specific proof.

```bash
factory coverage --root .
forge verify-tests {name} {name}.ssat.yaml --root .
factory optimize-pr --changed target_manifest.json --feature {name}
```
"""


def _coverage(name: str, requirements: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "schema": "factory.requirement_coverage.v1",
        "app": name,
        "requirements": [
            {"id": requirement_id, "summary": summary, "source": "target_compiler"}
            for requirement_id, summary in requirements
        ],
    }


def _backend(name: str, purpose: str, *, agent_ui: bool = False) -> str:
    if not agent_ui:
        return f'''"""FastAPI boundary generated by Code Factory."""
from fastapi import FastAPI

app = FastAPI(title="{name}")


@app.get("/healthz")
def healthz():
    return {{"ok": True, "app": "{name}", "purpose": "{purpose}"}}
'''
    return f'''"""Supervised task preview boundary generated by Code Factory."""
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="{name}")


class TaskPreview(BaseModel):
    instruction: str = Field(min_length=1, max_length=4000)


@app.get("/healthz")
def healthz():
    return {{"ok": True, "app": "{name}", "purpose": "{purpose}"}}


@app.post("/tasks/preview")
def preview_task(request: TaskPreview):
    return {{
        "status": "previewed",
        "instruction": request.instruction,
        "approval_required": True,
        "executed": False,
        "receipt_status": "unassessed",
    }}


@app.get("/receipts/latest")
def latest_receipt():
    return {{"status": "unassessed", "verified": False, "source": "local"}}
'''


def _backend_test(agent_ui: bool = False) -> str:
    extra = '''

def test_task_preview_never_executes_without_approval():
    response = TestClient(app).post("/tasks/preview", json={"instruction": "prepare a release"})
    assert response.status_code == 200
    assert response.json()["approval_required"] is True
    assert response.json()["executed"] is False
''' if agent_ui else ""
    return '''from fastapi.testclient import TestClient
from backend.main import app


def test_healthz():
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json()["ok"] is True
''' + extra


def _write_backend(root: Path, name: str, purpose: str, *, agent_ui: bool = False) -> None:
    _write(root / "backend" / "__init__.py", "")
    _write(root / "backend" / "main.py", _backend(name, purpose, agent_ui=agent_ui))
    _write(root / "backend" / "requirements.txt", "fastapi\nuvicorn\npytest\nhttpx\n")
    _write(root / "tests" / "test_health.py", _backend_test(agent_ui=agent_ui))


def _scaffold_worker(root: Path, name: str, purpose: str, text: str) -> list[str]:
    _write(root / "PRD.md", text)
    _write(root / "worker" / "__init__.py", "")
    _write(root / "worker" / "main.py", '''"""Deterministic headless worker starter."""
from __future__ import annotations
import json
import sys


def run_task(payload: dict) -> dict:
    message = str(payload.get("message", "")).strip()
    if not message:
        raise ValueError("message is required")
    return {"status": "completed", "message": message, "characters": len(message)}


def main() -> int:
    payload = json.loads(sys.stdin.read() or "{}")
    print(json.dumps(run_task(payload), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''')
    _write(root / "tests" / "test_worker.py", '''import pytest
from worker.main import run_task


def test_worker_is_deterministic():
    payload = {"message": "review receipt"}
    assert run_task(payload) == run_task(payload)
    assert run_task(payload)["characters"] == 14


def test_worker_rejects_empty_input():
    with pytest.raises(ValueError, match="message is required"):
        run_task({})
''')
    _write(root / f"{name}.ssat.yaml", f'''name: {name}
modules:
  - name: worker
    path: worker/main.py
    imports: [json, sys]
    functions:
      - name: run_task
        args: ["payload: dict"]
        returns: "dict"
        doc: "Return the same normalized result for the same payload."
dependencies: []
invariants:
  - name: no_dynamic_execution
    forbid_pattern: "\\b(eval|exec)\\s*\\("
  - name: no_network_clients
    forbid_pattern: "\\b(requests|urllib3|httpx)\\b"
''')
    _write_json(root / "smoke" / f"{name}.json", {"checks": [{
        "name": "worker_determinism",
        "kind": "python",
        "run": "from worker.main import run_task\np={'message':'review receipt'}\nassert run_task(p) == run_task(p)\n",
        "covers": ["WORKER_DETERMINISM"],
        "must_fail_on_stub": True,
    }]})
    _write_json(root / "coverage" / "requirements.json", _coverage(name, [
        ("WORKER_DETERMINISM", "Identical payloads return identical worker results."),
        ("PRODUCT_WORKFLOW", "The product-specific worker workflow is implemented."),
    ]))
    _write(root / "README.md", f"""# {name.replace('-', ' ').title()}

Generated as a deterministic worker target for `{purpose}`.

```bash
echo '{{"message":"review receipt"}}' | python -m worker.main
python -m pytest -q
factory coverage --root .
```

The worker has no network, credential, or external-message grant. Add those
only through a reviewed Loop Passport and connector adapter.
""")
    return ["WORKER_EMITTED"]


def _mobile_app(name: str, purpose: str) -> str:
    title = name.replace("-", " ").title()
    return f'''import {{ StatusBar }} from "expo-status-bar";
import {{ SafeAreaView, StyleSheet, Text, View }} from "react-native";

export default function App() {{
  return (
    <SafeAreaView style={{styles.screen}}>
      <StatusBar style="dark" />
      <View style={{styles.header}}>
        <Text style={{styles.eyebrow}}>CODE FACTORY / {purpose.upper()}</Text>
        <Text style={{styles.title}}>{title}</Text>
        <Text style={{styles.body}}>A governed Expo starter with local proof hooks and human-owned release approval.</Text>
      </View>
      <View style={{styles.status}}>
        <Text style={{styles.statusLabel}}>PROMOTION STATE</Text>
        <Text style={{styles.statusValue}}>Blocked pending product proof</Text>
      </View>
    </SafeAreaView>
  );
}}

const styles = StyleSheet.create({{
  screen: {{ flex: 1, backgroundColor: "#f7f9fc", padding: 24 }},
  header: {{ flex: 1, justifyContent: "center", maxWidth: 520 }},
  eyebrow: {{ color: "#1d4ed8", fontSize: 12, fontWeight: "700" }},
  title: {{ color: "#111827", fontSize: 40, fontWeight: "700", marginTop: 12 }},
  body: {{ color: "#475569", fontSize: 18, lineHeight: 28, marginTop: 16 }},
  status: {{ borderTopWidth: 1, borderTopColor: "#cbd5e1", paddingVertical: 20 }},
  statusLabel: {{ color: "#64748b", fontSize: 11, fontWeight: "700" }},
  statusValue: {{ color: "#9a3412", fontSize: 16, fontWeight: "600", marginTop: 6 }},
}});
'''


def _scaffold_mobile(root: Path, name: str, purpose: str, text: str) -> list[str]:
    _write(root / "PRD.md", text)
    _write(root / "mobile" / "App.tsx", _mobile_app(name, purpose))
    _write_json(root / "mobile" / "package.json", {
        "name": name,
        "version": "0.1.0",
        "private": True,
        "main": "node_modules/expo/AppEntry.js",
        "scripts": {
            "start": "expo start",
            "android": "expo start --android",
            "ios": "expo start --ios",
            "web": "expo start --web",
            "typecheck": "tsc --noEmit",
            "doctor": "expo-doctor",
        },
        "dependencies": {
            "expo": "~57.0.0",
            "expo-status-bar": "~57.0.1",
            "react": "19.2.3",
            "react-native": "0.86.0",
        },
        "devDependencies": {
            "@types/react": "~19.2.2",
            "expo-doctor": "1.20.1",
            "typescript": "~6.0.3",
        },
        "overrides": {"uuid": "11.1.1"},
    })
    _write_json(root / "mobile" / "app.json", {
        "expo": {
            "name": name.replace("-", " ").title(),
            "slug": name,
            "version": "0.1.0",
            "orientation": "portrait",
            "userInterfaceStyle": "automatic",
        }
    })
    _write(root / "mobile" / "tsconfig.json", '{"extends":"expo/tsconfig.base","compilerOptions":{"strict":true}}')
    _write(root / "mobile" / ".gitignore", "node_modules\n.expo\ndist\nandroid\nios\n")
    _write_backend(root, name, purpose)
    _write(root / f"{name}.ssat.yaml", f'''name: {name}
modules:
  - name: backend
    path: backend/main.py
    imports: [fastapi]
    functions:
      - name: healthz
        args: []
        returns: "dict"
        doc: "Return API health and app identity."
  - name: mobile
    path: mobile/App.tsx
    imports: [expo-status-bar, react-native]
    functions:
      - name: App
        args: []
        returns: "JSX.Element"
        doc: "Render the governed mobile starter state."
dependencies: []
invariants:
  - name: no_dynamic_execution
    forbid_pattern: "\\b(eval|exec)\\s*\\("
''')
    _write_json(root / "smoke" / f"{name}.json", {"checks": [
        {"name": "backend_health", "kind": "python", "run": "from fastapi.testclient import TestClient\nfrom backend.main import app\nassert TestClient(app).get('/healthz').json()['ok'] is True\n", "covers": ["RUNTIME_HEALTH"], "must_fail_on_stub": True},
        {"name": "mobile_entry", "kind": "python", "run": "from pathlib import Path\nt=Path('mobile/App.tsx').read_text()\nassert 'export default function App' in t and 'Blocked pending product proof' in t\n", "covers": ["MOBILE_ENTRY"], "must_fail_on_stub": True},
    ]})
    _write_json(root / "coverage" / "requirements.json", _coverage(name, [
        ("RUNTIME_HEALTH", "The local API exposes a passing health endpoint."),
        ("MOBILE_ENTRY", "The Expo entry renders the blocked proof state."),
        ("PRODUCT_WORKFLOW", "The product-specific mobile workflow is implemented."),
    ]))
    _write(root / "README.md", f"""# {name.replace('-', ' ').title()}

Generated as an Expo SDK 57 CNG target for `{purpose}`. The New Architecture
is the SDK default and is not redundantly declared in app config.

```bash
npm --prefix mobile install
npm --prefix mobile run doctor
npm --prefix mobile run typecheck
npm --prefix mobile start
```

Native Android and iOS directories are intentionally not generated. Expo CNG
creates them on demand. Store submission and release approval remain external
to this starter.
""")
    return ["MOBILE_EMITTED"]


def _agent_page(name: str) -> str:
    title = name.replace("-", " ").title()
    return f'''"use client";

import {{ FormEvent, useState }} from "react";

export default function Home() {{
  const [instruction, setInstruction] = useState("");
  const [preview, setPreview] = useState("No task previewed");

  function previewTask(event: FormEvent) {{
    event.preventDefault();
    const normalized = instruction.trim();
    setPreview(normalized ? `Approval required: ${{normalized}}` : "Enter an instruction first");
  }}

  return (
    <main className="workspace">
      <header className="topbar"><strong>{title}</strong><span>Local / supervised</span></header>
      <section className="commandBand">
        <div><p className="eyebrow">OPERATOR CONTROL</p><h1>Preview work before anything runs.</h1></div>
        <div className="state"><span>Promotion</span><strong>Blocked</strong></div>
      </section>
      <section className="grid">
        <form className="task" onSubmit={{previewTask}}>
          <label htmlFor="instruction">Task instruction</label>
          <textarea id="instruction" value={{instruction}} onChange={{(event) => setInstruction(event.target.value)}} maxLength={{4000}} />
          <button type="submit">Preview task</button>
        </form>
        <aside className="receipt"><p className="eyebrow">LATEST RECEIPT</p><h2>Unassessed</h2><p>{{preview}}</p><dl><dt>Execution</dt><dd>Not started</dd><dt>Approval</dt><dd>Required</dd></dl></aside>
      </section>
    </main>
  );
}}
'''


def _agent_css() -> str:
    return ''':root { color-scheme: light; color: #15202b; background: #f5f7fa; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
.workspace { min-height: 100vh; }
.topbar { height: 64px; padding: 0 5vw; display: flex; align-items: center; justify-content: space-between; background: #111827; color: white; }
.topbar span { color: #93c5fd; font-size: 13px; }
.commandBand { padding: 52px 5vw 40px; display: grid; grid-template-columns: 1fr auto; gap: 32px; background: white; border-bottom: 1px solid #dbe2ea; }
.eyebrow { color: #1d4ed8; font-size: 12px; font-weight: 800; }
h1 { margin: 8px 0 0; max-width: 760px; font-size: 44px; line-height: 1.08; }
.state { min-width: 150px; padding: 16px; border-left: 4px solid #ea580c; background: #fff7ed; }
.state span, .state strong { display: block; }
.state span { color: #9a3412; font-size: 12px; }
.state strong { margin-top: 6px; font-size: 20px; }
.grid { padding: 40px 5vw; display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(280px, .6fr); gap: 24px; }
.task, .receipt { background: white; border: 1px solid #dbe2ea; border-radius: 8px; padding: 24px; }
label { display: block; font-weight: 700; margin-bottom: 10px; }
textarea { width: 100%; min-height: 220px; resize: vertical; border: 1px solid #94a3b8; border-radius: 6px; padding: 14px; font: inherit; }
button { margin-top: 14px; border: 0; border-radius: 6px; padding: 12px 16px; background: #166534; color: white; font-weight: 750; cursor: pointer; }
dl { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; border-top: 1px solid #e2e8f0; padding-top: 18px; }
dt { color: #64748b; } dd { margin: 0; font-weight: 700; text-align: right; }
@media (max-width: 760px) { .commandBand, .grid { grid-template-columns: 1fr; } h1 { font-size: 34px; } }
'''


def _scaffold_app_target(root: Path, name: str, purpose: str, text: str, source_kind: str, source_ref: Path | None, target: str) -> list[str]:
    kwargs = {"out_dir": root, "name": name, "purpose": purpose, "stack": "nextjs-fastapi-postgres"}
    if source_kind == "prd":
        assert source_ref is not None
        app_from_prd(source_ref, **kwargs)
    else:
        app_from_prompt(text, **kwargs)
    if target == "agent-ui":
        _write(root / "frontend" / "app" / "page.tsx", _agent_page(name))
        _write(root / "frontend" / "app" / "globals.css", _agent_css())
        _write_backend(root, name, purpose, agent_ui=True)
        smoke_path = root / "smoke" / f"{name}.json"
        smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
        smoke["checks"].append({
            "name": "approval_boundary",
            "kind": "python",
            "run": "from fastapi.testclient import TestClient\nfrom backend.main import app\nr=TestClient(app).post('/tasks/preview',json={'instruction':'prepare release'}).json()\nassert r['approval_required'] is True and r['executed'] is False\n",
            "covers": ["AGENT_APPROVAL"],
            "must_fail_on_stub": True,
        })
        _write_json(smoke_path, smoke)
        coverage_path = root / "coverage" / "requirements.json"
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        coverage["requirements"].append({"id": "AGENT_APPROVAL", "summary": "Tasks are previewed but never executed before approval.", "source": "target_compiler"})
        _write_json(coverage_path, coverage)
        return ["AGENT_UI_EMITTED"]
    return ["WEB_EMITTED"]


def _write_proof_contract(root: Path, name: str, target: str, manifest: dict[str, Any],
                          source_sha256: str) -> tuple[dict[str, Any], list[str]]:
    if not (root / "pyproject.toml").exists():
        _write(root / "pyproject.toml", '''[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
''')
    _write_json(root / "target_manifest.json", manifest)
    _write(root / ".factory" / "target-architecture.mmd", _architecture_mermaid(target))
    _write_json(root / ".forge" / name / "state.json", _forge_state(name))
    _write(root / "docs" / "TARGET_WORKFLOW.md", _common_docs(name, target))
    markers = ["TARGET_MANIFEST_WRITTEN", "MERMAID_PROOF_WRITTEN"]
    files = sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.name != "target-compile-receipt.json"
    )
    relative_hashes = {
        str(path.relative_to(root)).replace("\\", "/"): _file_sha(path)
        for path in files
    }
    receipt = {
        "schema": COMPILE_RECEIPT_SCHEMA,
        "target_kind": target,
        "name": name,
        "status": "compiled_blocked",
        "source_sha256": source_sha256,
        "manifest_sha256": relative_hashes["target_manifest.json"],
        "files": relative_hashes,
        "claims": {
            "model_calls": 0,
            "runtime_tokens": 0 if target == "worker" else "not_claimed",
            "production_ready": False,
        },
    }
    _write_json(root / ".factory" / "target-compile-receipt.json", receipt)
    markers.append("COMPILE_RECEIPT_BOUND")
    return receipt, markers


def _compile(text: str, *, source_kind: str, source_ref: Path | None, target: str, out_dir: Path,
             name: str | None, purpose: str, trigger: str, source_sha256: str) -> dict[str, Any]:
    _validate_request(text, target, trigger)
    destination = _prepare_destination(out_dir)
    resolved_name = _extract_name(text, name)
    resolved_purpose = _purpose_from_text(text, purpose)
    staging = Path(tempfile.mkdtemp(prefix=f".{resolved_name}.factory-", dir=str(destination.parent)))
    markers = ["TARGET_KIND_SET", "SOURCE_EXACTLY_ONE"]
    try:
        if target == "worker":
            markers.extend(_scaffold_worker(staging, resolved_name, resolved_purpose, text))
        elif target == "mobile":
            markers.extend(_scaffold_mobile(staging, resolved_name, resolved_purpose, text))
        else:
            markers.extend(_scaffold_app_target(staging, resolved_name, resolved_purpose, text, source_kind, source_ref, target))
        manifest = _manifest(resolved_name, target, resolved_purpose, trigger, source_kind, source_sha256)
        receipt, proof_markers = _write_proof_contract(staging, resolved_name, target, manifest, source_sha256)
        markers.extend(proof_markers)
        if destination.exists():
            destination.rmdir()
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    files = sorted(str(path.relative_to(destination)).replace("\\", "/") for path in destination.rglob("*") if path.is_file())
    return {
        "schema": "factory.target_compile_result.v1",
        "status": "compiled_blocked",
        "target_kind": target,
        "name": resolved_name,
        "out_dir": str(destination),
        "files": files,
        "receipt": str(destination / ".factory" / "target-compile-receipt.json"),
        "receipt_sha256": _file_sha(destination / ".factory" / "target-compile-receipt.json"),
        "markers": markers,
        "next_commands": [
            f"forge verify-tests {resolved_name} {destination / (resolved_name + '.ssat.yaml')} --root {destination}",
            f"factory coverage --root {destination}",
            f"factory optimize-pr --root {destination} --changed target_manifest.json --feature {resolved_name}",
        ],
        "claims": receipt["claims"],
    }


def create_target_from_prompt(prompt: str, target: str, out_dir: Path, name: str | None = None,
                              purpose: str = "auto", trigger: str = "manual") -> dict[str, Any]:
    """Compile one prompt into a governed target without replacing existing work."""
    source_sha256 = sha256(prompt.encode("utf-8")).hexdigest()
    return _compile(prompt, source_kind="prompt", source_ref=None, target=target, out_dir=Path(out_dir),
                    name=name, purpose=purpose, trigger=trigger, source_sha256=source_sha256)


def create_target_from_prd(prd_path: Path, target: str, out_dir: Path, name: str | None = None,
                           purpose: str = "auto", trigger: str = "manual") -> dict[str, Any]:
    """Compile one exact UTF-8 PRD into a governed target."""
    path = Path(prd_path)
    if not path.is_file():
        raise TargetCompileError("PRD_NOT_FOUND", f"PRD file does not exist: {path}")
    source_bytes = path.read_bytes()
    text = source_bytes.decode("utf-8")
    return _compile(text, source_kind="prd", source_ref=path, target=target, out_dir=Path(out_dir),
                    name=name, purpose=purpose, trigger=trigger,
                    source_sha256=sha256(source_bytes).hexdigest())
