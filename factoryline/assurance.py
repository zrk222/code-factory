"""Deterministic assurance-plane primitives.

The module is deliberately standard-library only. It provides the contracts
that a hosted runner, container sandbox, SBOM provider, or private challenge
service can implement later without changing the evidence shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import subprocess
from typing import Any, Callable, Iterable

from .control_plane import ControlPlaneError, canonical_json, sha256


ASSURANCE_SCHEMA = "factory.assurance.v1"
GRAPH_SCHEMA = "factory.evidence.graph.v1"
DAG_SCHEMA = "factory.risk.dag.v1"
RUNNER_SCHEMA = "factory.runner.result.v1"
SBOM_SCHEMA = "factory.sbom.cyclonedx.v1"
VEX_SCHEMA = "factory.vex.v1"
CHALLENGE_SCHEMA = "factory.private.challenge-set.v1"


class AssuranceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AssuranceError("E_REQUIRED", f"{name} is required")
    return value.strip()


def build_evidence_graph(records: Iterable[dict[str, Any]], *, tenant_id: str) -> dict[str, Any]:
    """Build and verify a tenant-scoped DAG from receipt-like records."""
    tenant_id = _required(tenant_id, "tenant_id")
    nodes: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise AssuranceError("E_GRAPH_RECORD", "graph records must be JSON objects")
        evidence_id = _required(record.get("evidence_id"), "evidence_id")
        record_tenant = _required(record.get("tenant_id"), "tenant_id")
        if record_tenant != tenant_id:
            raise AssuranceError("E_TENANT_BOUNDARY", "evidence graph cannot mix tenants")
        if evidence_id in nodes:
            raise AssuranceError("E_GRAPH_DUPLICATE", f"duplicate evidence id: {evidence_id}")
        parents = record.get("parent_ids", record.get("parents", []))
        if not isinstance(parents, list) or not all(isinstance(parent, str) and parent.strip() for parent in parents):
            raise AssuranceError("E_GRAPH_PARENTS", f"parents for {evidence_id} must be a list of ids")
        nodes[evidence_id] = {
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "stage": str(record.get("stage", "unknown")),
            "verdict": str(record.get("verdict", "UNKNOWN")),
            "parent_ids": sorted(set(parents)),
            "subject_digest": record.get("subject_digest"),
        }
    for node in nodes.values():
        missing = [parent for parent in node["parent_ids"] if parent not in nodes]
        if missing:
            raise AssuranceError("E_GRAPH_MISSING_PARENT", f"{node['evidence_id']} references missing parent(s): {missing}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise AssuranceError("E_GRAPH_CYCLE", f"evidence graph cycle includes {node_id}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for parent in nodes[node_id]["parent_ids"]:
            visit(parent)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in sorted(nodes):
        visit(node_id)
    child_ids = {parent for node in nodes.values() for parent in node["parent_ids"]}
    payload = {
        "schema": GRAPH_SCHEMA,
        "tenant_id": tenant_id,
        "nodes": [nodes[node_id] for node_id in sorted(nodes)],
        "roots": sorted(node_id for node_id in nodes if not nodes[node_id]["parent_ids"]),
        "heads": sorted(node_id for node_id in nodes if node_id not in child_ids),
    }
    payload["graph_sha256"] = sha256(canonical_json(payload))
    return payload


@dataclass(frozen=True)
class GateNode:
    name: str
    risk: int
    depends_on: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()


class RiskDAG:
    def __init__(self, nodes: Iterable[GateNode]):
        self.nodes = {node.name: node for node in nodes}
        if not self.nodes:
            raise AssuranceError("E_DAG_EMPTY", "risk DAG needs at least one gate")
        for node in self.nodes.values():
            if node.risk < 1 or node.risk > 5:
                raise AssuranceError("E_DAG_RISK", f"gate {node.name} risk must be between 1 and 5")
            missing = [dep for dep in node.depends_on if dep not in self.nodes]
            if missing:
                raise AssuranceError("E_DAG_DEPENDENCY", f"gate {node.name} references missing dependency {missing}")
        self._topological()

    def _topological(self) -> list[str]:
        state: dict[str, int] = {}
        ordered: list[str] = []

        def visit(name: str) -> None:
            if state.get(name) == 1:
                raise AssuranceError("E_DAG_CYCLE", f"risk DAG cycle includes {name}")
            if state.get(name) == 2:
                return
            state[name] = 1
            for dependency in sorted(self.nodes[name].depends_on):
                visit(dependency)
            state[name] = 2
            ordered.append(name)

        for name in sorted(self.nodes):
            visit(name)
        return ordered

    def plan(self, changed_paths: Iterable[str], *, minimum_risk: int = 1) -> dict[str, Any]:
        changed = tuple(sorted({str(path).replace("\\", "/") for path in changed_paths if str(path).strip()}))
        selected: set[str] = {
            node.name for node in self.nodes.values()
            if node.risk >= minimum_risk and (not node.paths or any(
                changed_path == path or changed_path.startswith(path.rstrip("/") + "/")
                for changed_path in changed for path in node.paths
            ))
        }
        # Every selected gate brings its dependencies, preserving correctness
        # when a low-risk leaf depends on a higher-risk contract gate.
        def include_dependencies(name: str) -> None:
            for dependency in self.nodes[name].depends_on:
                if dependency not in selected:
                    selected.add(dependency)
                include_dependencies(dependency)
        for name in tuple(sorted(selected)):
            include_dependencies(name)
        ordered = [name for name in self._topological() if name in selected]
        return {
            "schema": DAG_SCHEMA,
            "changed_paths": list(changed),
            "minimum_risk": minimum_risk,
            "selected": ordered,
            "gates": [{"name": name, "risk": self.nodes[name].risk} for name in ordered],
        }


def run_constrained(
    command: list[str],
    *,
    root: Path,
    cwd: str = ".",
    timeout: int = 60,
    env_keys: Iterable[str] = (),
) -> dict[str, Any]:
    """Run a command with no shell, a contained cwd, and an allow-listed env.

    This is a process boundary, not a kernel/container sandbox. The result
    states that limitation so callers can require a stronger runner for
    untrusted code.
    """
    if not command or not all(isinstance(item, str) and item for item in command):
        raise AssuranceError("E_RUNNER_COMMAND", "command must be a non-empty argv list")
    root_path = Path(root).resolve()
    work_path = (root_path / cwd).resolve()
    try:
        work_path.relative_to(root_path)
    except ValueError as exc:
        raise AssuranceError("E_RUNNER_CWD", "runner cwd must remain inside root") from exc
    if not work_path.is_dir():
        raise AssuranceError("E_RUNNER_CWD", "runner cwd does not exist")
    # Keep only the runtime variables required to launch a process on the
    # host. Application secrets and user variables remain opt-in.
    runtime_keys = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP"}
    env = {key: os.environ[key] for key in runtime_keys.union(set(env_keys)) if key in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        completed = subprocess.run(
            command, cwd=work_path, env=env, shell=False, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
        return {
            "schema": RUNNER_SCHEMA,
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "isolation": "process-boundary",
            "network": "not-enforced-by-stdlib-runner",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "schema": RUNNER_SCHEMA,
            "ok": False,
            "returncode": None,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "error": "E_RUNNER_TIMEOUT",
            "isolation": "process-boundary",
            "network": "not-enforced-by-stdlib-runner",
        }


def build_cyclonedx_sbom(components: Iterable[dict[str, Any]]) -> dict[str, Any]:
    normalized = []
    for component in components:
        if not isinstance(component, dict):
            raise AssuranceError("E_SBOM_COMPONENT", "SBOM components must be objects")
        name = _required(component.get("name"), "component.name")
        version = _required(component.get("version"), "component.version")
        normalized.append({
            "type": str(component.get("type", "library")),
            "name": name,
            "version": version,
            "purl": component.get("purl"),
            "scope": str(component.get("scope", "required")),
        })
    normalized.sort(key=lambda item: (item["name"], item["version"], item["type"]))
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "schema": SBOM_SCHEMA,
        "components": normalized,
    }
    result["serialNumber"] = "urn:uuid:" + hashlib.sha256(canonical_json(result)).hexdigest()[:32]
    result["bom_sha256"] = sha256(canonical_json(result))
    return result


VEX_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})


def build_vex(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    normalized = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise AssuranceError("E_VEX_ENTRY", "VEX entries must be objects")
        status = _required(entry.get("status"), "status")
        if status not in VEX_STATUSES:
            raise AssuranceError("E_VEX_STATUS", f"unsupported VEX status: {status}")
        normalized.append({
            "vulnerability": _required(entry.get("vulnerability"), "vulnerability"),
            "component": _required(entry.get("component"), "component"),
            "status": status,
            "justification": str(entry.get("justification", "")),
            "action": str(entry.get("action", "")),
        })
    normalized.sort(key=lambda item: (item["vulnerability"], item["component"]))
    result = {"schema": VEX_SCHEMA, "entries": normalized}
    result["vex_sha256"] = sha256(canonical_json(result))
    return result


def policy_mutations(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate delete/invert mutations for the explicit policy rule list."""
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise AssuranceError("E_HOLLOW_POLICY", "policy must contain a non-empty rules list")
    mutations: list[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or not rule.get("id"):
            raise AssuranceError("E_POLICY_RULE", "each policy rule needs an id")
        deleted = json.loads(json.dumps(policy))
        deleted["rules"].pop(index)
        deleted["mutation"] = {"kind": "delete", "rule_id": rule["id"]}
        mutations.append(deleted)
        for field in ("required", "enabled", "allow"):
            if isinstance(rule.get(field), bool):
                inverted = json.loads(json.dumps(policy))
                inverted["rules"][index][field] = not rule[field]
                inverted["mutation"] = {"kind": "invert", "rule_id": rule["id"], "field": field}
                mutations.append(inverted)
                break
    return mutations


def verify_policy_mutations(policy: dict[str, Any], evaluator: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    baseline = bool(evaluator(policy))
    if not baseline:
        raise AssuranceError("E_POLICY_BASELINE", "policy evaluator did not pass the unmutated policy")
    results = []
    for mutation in policy_mutations(policy):
        caught = not bool(evaluator(mutation))
        results.append({"mutation": mutation["mutation"], "caught": caught})
    hollow = [item for item in results if not item["caught"]]
    return {
        "schema": ASSURANCE_SCHEMA,
        "challenge": "policy-mutation",
        "status": "VERIFIED" if not hollow else "HOLLOW_POLICY",
        "mutations": results,
        "hollow": hollow,
    }


def private_challenge_manifest(name: str, challenges: Iterable[dict[str, Any]], *, tenant_id: str) -> dict[str, Any]:
    payload = [challenge for challenge in challenges]
    if not payload:
        raise AssuranceError("E_CHALLENGE_EMPTY", "private challenge set cannot be empty")
    digest = sha256(canonical_json(payload))
    return {
        "schema": CHALLENGE_SCHEMA,
        "name": _required(name, "name"),
        "tenant_id": _required(tenant_id, "tenant_id"),
        "challenge_count": len(payload),
        "challenge_sha256": digest,
        "disclosure": "digest-and-count-only",
    }
