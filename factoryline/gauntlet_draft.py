"""Deterministic, inert Gauntlet promise discovery from repository structure."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


GAUNTLET_DRAFT_SCHEMA = "factory.gauntlet-draft.v1"
GAUNTLET_SOURCE_DRAFT_SCHEMA = "factory.gauntlet-source.draft.v1"
E2E_DRAFT_SCHEMA = "factory.e2e-proof-draft.v1"
_ID = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
_SKIP = {".git", ".factory", "__pycache__", "node_modules", ".venv", "venv"}
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "admission": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class GauntletDraftError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical(payload) + b"\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)
    return path


def _project_scripts(root: Path) -> list[dict[str, str]]:
    path = root / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    scripts = (
        value.get("project", {}).get("scripts", {})
        if isinstance(value.get("project"), dict)
        else {}
    )
    if not isinstance(scripts, dict):
        return []
    return [
        {"name": name, "target": target, "evidence_path": "pyproject.toml"}
        for name, target in sorted(scripts.items())
        if isinstance(name, str) and isinstance(target, str)
    ]


def _routes(root: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.py")):
        if _SKIP.intersection(path.relative_to(root).parts):
            continue
        tree = _parse_python_file(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            found.extend(_node_routes(root, path, node))
    return sorted(
        found,
        key=lambda item: (
            item["evidence_path"],
            item["route"],
            item["method"],
            item["handler"],
        ),
    )


def _parse_python_file(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


def _node_routes(root: Path, path: Path, node: ast.AST) -> list[dict[str, str]]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    routes = []
    for decorator in node.decorator_list:
        route = _route_record(root, path, node, decorator)
        if route is not None:
            routes.append(route)
    return routes


def _route_record(
    root: Path,
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    decorator: ast.expr,
) -> dict[str, str] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(
        decorator.func, ast.Attribute
    ):
        return None
    method = decorator.func.attr.lower()
    if method not in _ROUTE_METHODS or not decorator.args:
        return None
    route = decorator.args[0]
    if not isinstance(route, ast.Constant) or not isinstance(route.value, str):
        return None
    return {
        "method": method.upper(),
        "route": route.value,
        "handler": node.name,
        "evidence_path": path.relative_to(root).as_posix(),
    }


def _tests(root: Path) -> list[str]:
    paths: list[str] = []
    for pattern in (
        "tests/test_*.py",
        "test_*.py",
        "**/*.test.ts",
        "**/*.spec.ts",
        "**/*.test.js",
        "**/*.spec.js",
    ):
        for path in root.glob(pattern):
            if path.is_file() and not _SKIP.intersection(path.relative_to(root).parts):
                paths.append(path.relative_to(root).as_posix())
    return sorted(set(paths))


def _pack_templates(root: Path) -> list[dict[str, str]]:
    templates = _registered_templates()
    _apply_pack_entrypoints(root, templates)
    return sorted(templates, key=lambda item: item["target_pack"])


def _registered_templates() -> list[dict[str, str]]:
    templates: list[dict[str, str]] = []
    registry = (
        Path(__file__).resolve().parent / "data" / "gauntlet_target_promises.json"
    )
    try:
        registered = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        registered = {}
    for item in registered.get("templates", []) if isinstance(registered, dict) else []:
        if isinstance(item, dict) and isinstance(item.get("target_pack"), str):
            templates.append(
                {
                    **item,
                    "evidence_path": "factoryline/data/gauntlet_target_promises.json",
                }
            )
    return templates


def _apply_pack_entrypoints(root: Path, templates: list[dict[str, str]]) -> None:
    base = root / "factoryline" / "builtin_packs"
    for path in sorted(base.glob("target-*/pack.yaml")) if base.is_dir() else []:
        pack = _pack_identity(path)
        if pack is None:
            continue
        entrypoint, pack_id = pack
        for template in templates:
            if template.get("target_pack") == pack_id:
                template["entrypoint"] = entrypoint
                template["pack_evidence_path"] = path.relative_to(root).as_posix()


def _pack_identity(path: Path) -> tuple[str, str] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    entrypoint = value.get("entrypoint")
    if not isinstance(entrypoint, str) or not entrypoint.strip():
        return None
    pack_id = str(value.get("id", path.parent.name))
    return entrypoint.strip(), pack_id


def draft_gauntlet(root: Path, source_id: str) -> dict[str, Any]:
    """Write review-only promise candidates; never execute or approve them."""
    workspace = Path(root).resolve()
    if not workspace.is_dir() or not _ID.fullmatch(source_id):
        raise GauntletDraftError(
            "GAUNTLET_DRAFT_INVALID", "root and lowercase source_id are required"
        )
    scripts, routes, tests, packs = (
        _project_scripts(workspace),
        _routes(workspace),
        _tests(workspace),
        _pack_templates(workspace),
    )
    target = workspace / ".factory" / "gauntlet" / "drafts" / source_id
    promises: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    for script in scripts:
        safe_id = (
            re.sub(r"[^a-z0-9-]+", "-", script["name"].lower()).strip("-")[:64] or "cli"
        )
        manifest_core = {
            "schema": E2E_DRAFT_SCHEMA,
            "id": f"{safe_id}-cli-contract",
            "status": "DRAFT",
            "working_directory": ".",
            "timeout_seconds": 60,
            "network_egress": "not_granted",
            "positive": {"argv": [script["name"], "--help"]},
            "negative": {"argv": [script["name"], "--__factory-invalid-option__"]},
            "artifact_paths": [],
            "evidence": script,
            "review_required": [
                "Confirm --help is a supported positive contract.",
                "Replace or confirm the structurally generated invalid-option sabotage.",
                "Name an approver when promoting to factory.e2e_proof_manifest.v1.",
            ],
        }
        manifest = {**manifest_core, "draft_sha256": _sha(manifest_core)}
        manifest_path = _write(target / f"{safe_id}.e2e.draft.json", manifest)
        manifests.append(
            {
                "path": manifest_path.relative_to(workspace).as_posix(),
                "sha256": _file_sha(manifest_path),
                "id": manifest["id"],
            }
        )
        promises.append(
            {
                "id": f"{safe_id}-cli-availability",
                "statement": f"The declared {script['name']} CLI entrypoint exposes a working command contract.",
                "evidence": script,
                "e2e_draft": manifest_path.relative_to(workspace).as_posix(),
                "status": "DRAFT",
            }
        )
    source_core = {
        "schema": GAUNTLET_SOURCE_DRAFT_SCHEMA,
        "id": source_id,
        "status": "DRAFT",
        "promises": promises,
        "unresolved_http_routes": [
            {
                **route,
                "marker": "HTTP_COMMAND_WITHHELD",
                "reason": "No explicit positive and sabotage argv pair is derivable from a route decorator alone.",
            }
            for route in routes
        ],
        "existing_tests": tests,
        "target_pack_shapes": packs,
        "promotion_requirements": [
            "Human review of every promise statement.",
            "Named approval in each E2E manifest.",
            "Promotion to factory.gauntlet-source.v1 before factory gauntlet plan.",
            "A separate expiring Gauntlet admission before execution.",
        ],
    }
    source = {**source_core, "draft_sha256": _sha(source_core)}
    source_path = _write(target / "gauntlet-source.draft.json", source)
    receipt_core = {
        "schema": GAUNTLET_DRAFT_SCHEMA,
        "marker": "GAUNTLET_DRAFT_CREATED",
        "markers": ["GAUNTLET_DRAFT_CREATED", "GAUNTLET_DRAFT_INERT"],
        "status": "DRAFT",
        "source_id": source_id,
        "source": {
            "path": source_path.relative_to(workspace).as_posix(),
            "sha256": _file_sha(source_path),
        },
        "manifests": manifests,
        "facts": {
            "cli_entrypoint_count": len(scripts),
            "http_route_count": len(routes),
            "existing_test_count": len(tests),
            "target_pack_count": len(packs),
            "runnable_manifest_count": 0,
        },
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Drafting is static repository inspection only.",
            "DRAFT artifacts are inert and rejected by the executable Gauntlet schemas.",
            "No HTTP test command is inferred from prose or from a route decorator alone.",
        ],
    }
    receipt = {**receipt_core, "receipt_sha256": _sha(receipt_core)}
    receipt_path = _write(target / "draft-receipt.json", receipt)
    return {
        "draft": receipt,
        "path": str(receipt_path),
        "source_path": str(source_path),
    }
