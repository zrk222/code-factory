"""Generate and sign the reviewed first-party capability pack catalog.

The private key is supplied at release time and is never written into the repo.
Every generated pack carries only the corresponding public trust root.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from factoryline.capability_packs import REQUIRED_UX_STATES, sign_pack


ROOT = Path(__file__).resolve().parents[1]
PACK_ROOT = ROOT / "factoryline" / "builtin_packs"
IDENTITY = "https://github.com/zrk222/code-factory"
ISSUER = "code-factory-release"
KEY_ID = "code-factory-capability-packs-2026-07d"


def deployment(label: str, prerequisites: list[str], build: str, verify: str, release: str, approval: str) -> dict:
    return {
        "id": label.lower().replace(" ", "-"), "label": label,
        "prerequisites": prerequisites, "build": build, "verify": verify,
        "release": release, "approval": approval,
    }


LOCAL_PYTHON = deployment(
    "Local supervised", ["Python 3.10+"], "python -m pip install -e .",
    "python -m pytest -q", "run the declared local entrypoint", "local execution",
)
CONTAINER = deployment(
    "Container host", ["Reviewed Dockerfile", "container registry", "host credentials"],
    "docker build -t app .", "docker run --rm app", "push and deploy the reviewed image",
    "registry push and external deployment",
)
LOCAL_NODE = deployment(
    "Local Node", ["Node.js 20+", "reviewed lockfile"], "npm ci", "npm test",
    "npm run start", "local execution",
)
WEB_LOCAL = {"id":"local-split","label":"Local frontend and API","prerequisites":["Python 3.10+","Node.js 20+"],"build":"install backend requirements and frontend packages","verify":"run pytest and the frontend build","release":"start the reviewed backend and frontend locally","approval":"local execution"}
WEB_HOSTED = {"id":"split-hosting","label":"Managed frontend plus API host","prerequisites":["selected frontend provider","selected Python API provider","provider credentials"],"build":"build frontend and API artifacts independently","verify":"run health, browser, and cross-origin smoke checks","release":"deploy both artifacts with reviewed provider adapters","approval":"credentials and two external deploys"}
MOBILE_PREVIEW = {"id":"expo-preview","label":"Expo device preview","prerequisites":["Node.js 20+","Expo Go"],"build":"npm --prefix mobile install","verify":"npm --prefix mobile exec expo-doctor","release":"npm --prefix mobile start","approval":"local network device preview"}
MOBILE_STORE = {"id":"eas-store","label":"EAS store release","prerequisites":["Expo account","EAS configuration","store credentials"],"build":"eas build --platform all","verify":"expo-doctor plus signed-device smoke","release":"eas submit --platform all","approval":"credentials build spend and store submission"}
AGENT_LOCAL = {"id":"local-operator","label":"Local supervised operator","prerequisites":["Python 3.10+","Node.js 20+"],"build":"install backend requirements and frontend packages","verify":"run approval-boundary tests and browser smoke","release":"start both local services on loopback","approval":"local execution"}
AGENT_HOSTED = {"id":"private-container-host","label":"Private container host","prerequisites":["reviewed container manifests","identity provider","TLS","private registry"],"build":"build frontend and API images","verify":"run auth approval receipt and rollback canaries","release":"deploy through the selected private-host adapter","approval":"credentials registry push and external deploy"}


def spec(pack_id: str, kind: str, label: str, summary: str, adapter: str, entrypoint: str,
         provides: list[str], *, target_kind: str | None = None,
         compatible_targets: list[str] | None = None, requires_kinds: list[str] | None = None,
         languages: list[str] | None = None, capabilities: list[str] | None = None,
         profiles: list[dict] | None = None, runtime_mode: str = "deterministic") -> dict:
    value = {
        "schema": "factory.capability_pack.v1", "id": pack_id, "version": "1.0.0",
        "kind": kind, "label": label, "summary": summary,
        "generator_adapter": adapter, "runtime_mode": runtime_mode,
        "entrypoint": entrypoint, "languages": languages or [], "capabilities": capabilities or provides,
        "compatibility": {
            "compatible_targets": compatible_targets or ["*"],
            "requires_kinds": requires_kinds or ([] if kind == "target" else ["target"]),
            "conflicts_with": [], "provides": provides,
        },
        "deployment_profiles": profiles or [LOCAL_PYTHON, CONTAINER],
    }
    if target_kind:
        value["target_kind"] = target_kind
    return value


PACKS = [
    spec("target-cli", "target", "Command-line app", "A deterministic local CLI with structured output and smoke proof.", "cli", "python -m cli_app.main", ["cli"], target_kind="cli", languages=["python"], profiles=[LOCAL_PYTHON]),
    spec("target-api", "target", "HTTP API", "A validated FastAPI boundary with deterministic health and request contracts.", "api", "uvicorn backend.main:app", ["api"], target_kind="api", languages=["python"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("target-mcp", "target", "MCP server", "A local stdio MCP server with explicit tool contracts and no implicit network grant.", "mcp", "python -m mcp_server.main", ["mcp", "stdio"], target_kind="mcp", languages=["python"], profiles=[LOCAL_PYTHON]),
    spec("target-worker", "target", "Headless worker", "A deterministic worker for scheduled, hook, inbox, or manual execution.", "worker", "python -m worker.main", ["background-worker", "cli"], target_kind="worker", languages=["python"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("target-web", "target", "Web application", "A Next.js and FastAPI application with responsive UX and proof hooks.", "web", "frontend + backend", ["web", "api"], target_kind="web", languages=["typescript", "python"], profiles=[WEB_LOCAL, WEB_HOSTED], runtime_mode="governed_application"),
    spec("target-mobile", "target", "Mobile application", "An Expo application with local API proof and store-release approval boundaries.", "mobile", "npm --prefix mobile start", ["mobile", "api"], target_kind="mobile", languages=["typescript", "python"], profiles=[MOBILE_PREVIEW, MOBILE_STORE], runtime_mode="governed_application"),
    spec("target-agent-ui", "target", "Agentic application", "A supervised operator UI for previewing agent work before approval.", "agent-ui", "frontend + backend", ["agent-ui", "web", "api"], target_kind="agent-ui", languages=["typescript", "python"], profiles=[AGENT_LOCAL, AGENT_HOSTED], runtime_mode="supervised_agent"),
    spec("surface-react", "surface", "React surface", "Accessible React interaction states and component boundaries.", "surface-react", "npm run dev", ["react", "browser-ui"], compatible_targets=["web", "agent-ui"], profiles=[LOCAL_NODE]),
    spec("surface-nextjs", "surface", "Next.js surface", "App Router, server/client boundaries, responsive states, and route proof.", "surface-nextjs", "npm run dev", ["nextjs", "react", "browser-ui"], compatible_targets=["web", "agent-ui"], profiles=[LOCAL_NODE]),
    spec("surface-expo", "surface", "Expo surface", "Expo CNG mobile UX states, device canaries, and store approval boundaries.", "surface-expo", "npx expo start", ["expo", "mobile-ui"], compatible_targets=["mobile"], profiles=[LOCAL_NODE]),
    spec("surface-browser-extension", "surface", "Browser extension", "Manifest V3 UI and permission-state contracts with bounded browser APIs.", "surface-browser-extension", "npm run dev", ["browser-extension", "manifest-v3"], compatible_targets=["web", "agent-ui"], profiles=[LOCAL_NODE]),
    spec("language-python", "language", "Python", "Typed Python modules with pytest, Ruff-compatible policy, and wheel canaries.", "language-python", "python -m pytest", ["python"], languages=["python"], profiles=[LOCAL_PYTHON]),
    spec("language-typescript", "language", "TypeScript", "Strict TypeScript modules with executable tests and ESM-aware symbol proof.", "language-typescript", "npm test", ["typescript", "javascript", "esm"], languages=["typescript", "javascript"], profiles=[LOCAL_NODE]),
    spec("language-java", "language", "Java", "Java modules with Gradle test, package boundaries, and JVM canaries.", "language-java", "./gradlew test", ["java", "jvm"], languages=["java"], profiles=[deployment("Local Gradle", ["JDK 21+", "Gradle wrapper"], "./gradlew assemble", "./gradlew test", "publish reviewed artifact", "artifact publication")]),
    spec("language-kotlin", "language", "Kotlin", "Kotlin/JVM modules with Gradle tests and coroutine-safe canaries.", "language-kotlin", "./gradlew test", ["kotlin", "jvm"], languages=["kotlin"], profiles=[deployment("Local Gradle", ["JDK 21+", "Gradle wrapper"], "./gradlew assemble", "./gradlew test", "publish reviewed artifact", "artifact publication")]),
    spec("language-dotnet", "language", ".NET", "C#/.NET projects with nullable analysis, tests, and package canaries.", "language-dotnet", "dotnet test", ["csharp", "dotnet"], languages=["csharp"], profiles=[deployment("Local dotnet", [".NET SDK 8+"], "dotnet build", "dotnet test", "dotnet publish", "artifact publication")]),
    spec("language-go", "language", "Go", "Go modules with race-aware tests, vet gates, and binary canaries.", "language-go", "go test ./...", ["go"], languages=["go"], profiles=[deployment("Local Go", ["Go 1.23+"], "go build ./...", "go test ./...", "publish reviewed binary", "artifact publication")]),
    spec("language-rust", "language", "Rust", "Rust crates with Clippy, Cargo tests, and unsafe-code policy.", "language-rust", "cargo test", ["rust"], languages=["rust"], profiles=[deployment("Local Cargo", ["stable Rust toolchain"], "cargo build --locked", "cargo test --locked", "cargo publish", "crate publication")]),
    spec("language-cpp", "language", "C and C++", "CMake projects with compiler matrices, sanitizers, and binary canaries.", "language-cpp", "ctest --test-dir build", ["c", "cpp"], languages=["c", "cpp"], profiles=[deployment("Local CMake", ["CMake 3.28+", "C/C++ compiler"], "cmake -S . -B build && cmake --build build", "ctest --test-dir build", "publish reviewed binary", "artifact publication")]),
    spec("capability-auth", "capability", "Authentication", "Session, identity, permission, recovery, and audit contracts.", "capability-auth", "project-defined", ["auth", "permissions", "session"], capabilities=["auth"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("capability-billing", "capability", "Billing", "Plan, entitlement, webhook, idempotency, and refund approval contracts.", "capability-billing", "project-defined", ["billing", "entitlements"], capabilities=["billing"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("capability-search", "capability", "Search", "Index ownership, relevance evaluation, empty states, and rollback contracts.", "capability-search", "project-defined", ["search", "indexing"], capabilities=["search"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("capability-import-export", "capability", "Import and export", "Schema validation, progress, partial failure, and recovery contracts.", "capability-import-export", "project-defined", ["import", "export", "data-portability"], capabilities=["import-export"], profiles=[LOCAL_PYTHON]),
    spec("capability-accessibility", "capability", "Accessibility", "Keyboard, semantics, contrast, motion, and screen-reader proof.", "capability-accessibility", "project-defined", ["accessibility", "wcag"], requires_kinds=["target", "surface"], capabilities=["accessibility"], profiles=[LOCAL_NODE]),
    spec("capability-i18n", "capability", "Internationalization", "Locale, pluralization, layout expansion, and fallback contracts.", "capability-i18n", "project-defined", ["i18n", "localization"], capabilities=["i18n"], profiles=[LOCAL_NODE]),
    spec("capability-offline", "capability", "Offline operation", "Offline, sync, conflict, retry, and data-loss prevention contracts.", "capability-offline", "project-defined", ["offline", "sync", "conflict-resolution"], compatible_targets=["web", "mobile", "agent-ui"], capabilities=["offline"], profiles=[LOCAL_NODE]),
    spec("data-pipeline", "data", "Data pipeline", "Batch and streaming ownership, lineage, replay, and quality gates.", "data-pipeline", "project-defined", ["data-pipeline", "lineage", "replay"], compatible_targets=["worker", "api"], profiles=[LOCAL_PYTHON, CONTAINER]),
    spec("data-evals", "data", "Evaluation harness", "Dataset identity, evaluator independence, score provenance, and regression gates.", "data-evals", "project-defined", ["evals", "datasets", "score-provenance"], compatible_targets=["worker", "cli", "api"], profiles=[LOCAL_PYTHON]),
    spec("ops-admin", "ops", "Admin and operations", "Operator permissions, approval inboxes, audit trails, and rollback controls.", "ops-admin", "project-defined", ["admin", "operations", "audit"], compatible_targets=["agent-ui", "web", "api"], profiles=[LOCAL_NODE, CONTAINER]),
]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def generate(private_key: Path, trust_root: Path) -> None:
    expected = {item["id"] for item in PACKS}
    for existing in PACK_ROOT.iterdir():
        if existing.is_dir() and existing.name not in expected:
            shutil.rmtree(existing)
    trust = json.loads(trust_root.read_text(encoding="utf-8"))
    for manifest in PACKS:
        root = PACK_ROOT / manifest["id"]
        if root.exists():
            shutil.rmtree(root)
        write_json(root / "pack.yaml", manifest)
        write_json(root / "generator" / "adapter.json", {
            "schema": "factory.pack.generator.v1", "adapter": manifest["generator_adapter"],
            "deterministic": True, "external_effects": False,
            "outputs": ["source-or-integration-plan", "acceptance-tests", "proof-receipt"],
        })
        write_json(root / "validators" / "manifest.json", {
            "schema": "factory.pack.validators.v1",
            "validators": ["manifest-shape", "generator-binding", "smoke-non-hollow", "authority-boundary", "compatibility"],
        })
        write_json(root / "goldens" / "manifest.json", {
            "schema": "factory.pack.goldens.v1",
            "goldens": ["deterministic-repeat", "declared-contract-present", "failure-state-actionable"],
        })
        write_json(root / "canaries" / "manifest.json", {
            "schema": "factory.pack.canaries.v1",
            "canaries": ["adapter-loads", "validator-rejects-stub", "receipt-emitted"],
        })
        write_json(root / "ux-states" / "manifest.json", {
            "schema": "factory.pack.ux-states.v1", "states": sorted(REQUIRED_UX_STATES),
        })
        write_json(root / "migration-policy.json", {
            "schema": "factory.pack.migration-policy.v1", "breaking_changes": "deny",
            "human_review_required": True, "rollback_required": True,
        })
        write_json(root / "pack.trust.json", trust)
        sign_pack(root, private_key, keyid=KEY_ID, identity=IDENTITY, issuer=ISSUER)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-root", type=Path, required=True)
    args = parser.parse_args()
    generate(args.private_key.resolve(), args.trust_root.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
