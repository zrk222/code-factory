"""Deterministic, read-only portfolio planning over a Graph Ops snapshot.

The planner intentionally makes structural recommendations only.  It never
executes commands or treats a shared graph node as permission to reuse a proof.
Exact proof reuse remains the separate proof-reuse gate.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any


GRAPH_PORTFOLIO_SCHEMA = "factory.graph-portfolio.v1"
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
    "proof_reuse": False,
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _dependency_graph(snapshot: dict[str, Any]) -> tuple[list[str], dict[str, list[str]], dict[str, dict[str, Any]]]:
    raw_nodes = snapshot.get("nodes")
    raw_edges = snapshot.get("edges")
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        return [], {}, {}
    nodes = {
        item["id"]: item
        for item in raw_nodes
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]
    }
    related = {node_id for node_id, node in nodes.items() if node.get("kind") == "slice"}
    successors: dict[str, set[str]] = defaultdict(set)
    for edge in raw_edges:
        if not isinstance(edge, dict) or edge.get("relation") != "depends_on":
            continue
        source, target = edge.get("source"), edge.get("target")
        if isinstance(source, str) and isinstance(target, str) and source in nodes and target in nodes:
            related.update({source, target})
            successors[source].add(target)
    ordered = sorted(related)
    return ordered, {node_id: sorted(successors.get(node_id, set())) for node_id in ordered}, nodes


def _cycle_components(nodes: list[str], successors: dict[str, list[str]]) -> list[list[str]]:
    """Return lexical strongly connected components with at least one cycle."""
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node_id: str) -> None:
        nonlocal index
        indexes[node_id] = index
        lowlinks[node_id] = index
        index += 1
        stack.append(node_id)
        on_stack.add(node_id)
        for child in successors[node_id]:
            if child not in indexes:
                visit(child)
                lowlinks[node_id] = min(lowlinks[node_id], lowlinks[child])
            elif child in on_stack:
                lowlinks[node_id] = min(lowlinks[node_id], indexes[child])
        if lowlinks[node_id] != indexes[node_id]:
            return
        component: list[str] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node_id:
                break
        component.sort()
        if len(component) > 1 or node_id in successors[node_id]:
            components.append(component)

    for node_id in nodes:
        if node_id not in indexes:
            visit(node_id)
    return sorted(components, key=lambda component: tuple(component))


def _topological_order(nodes: list[str], successors: dict[str, list[str]]) -> list[str]:
    indegree = {node_id: 0 for node_id in nodes}
    for children in successors.values():
        for child in children:
            indegree[child] += 1
    ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
    ordered: list[str] = []
    while ready:
        node_id = ready.pop(0)
        ordered.append(node_id)
        for child in successors[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    return ordered


def _valid_durations(nodes: list[str], observations: object) -> dict[str, int] | None:
    if not nodes or not isinstance(observations, dict) or set(observations) != set(nodes):
        return None
    normalized: dict[str, int] = {}
    for node_id in nodes:
        value = observations[node_id]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 10**12:
            return None
        normalized[node_id] = value
    return normalized


def _descendants(nodes: list[str], successors: dict[str, list[str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for node_id in nodes:
        seen: set[str] = set()
        pending = list(reversed(successors[node_id]))
        while pending:
            candidate = pending.pop()
            if candidate in seen:
                continue
            seen.add(candidate)
            pending.extend(reversed(successors[candidate]))
        result[node_id] = sorted(seen)
    return result


def _blocked_ancestors(nodes: list[str], successors: dict[str, list[str]], source_nodes: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Return lexical root blockers for each downstream node without scheduling work."""
    blockers = sorted(node_id for node_id in nodes if _disposition(source_nodes[node_id]) == "BLOCK")
    result: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for blocker in blockers:
        pending = list(reversed(successors[blocker]))
        seen: set[str] = set()
        while pending:
            node_id = pending.pop()
            if node_id in seen:
                continue
            seen.add(node_id)
            result[node_id].append(blocker)
            pending.extend(reversed(successors[node_id]))
    return {node_id: sorted(values) for node_id, values in result.items()}


def _disposition(node: dict[str, Any]) -> str:
    status = str(node.get("status", "")).casefold()
    if status in {"block", "blocked", "invalid"}:
        return "BLOCK"
    if status in {"current", "verified", "completed"}:
        return "REUSE_CANDIDATE"
    return "RUN"


def _common(snapshot: object) -> dict[str, Any]:
    graph_sha256 = snapshot.get("base_graph_sha256", snapshot.get("graph_sha256")) if isinstance(snapshot, dict) else None
    return {
        "schema": GRAPH_PORTFOLIO_SCHEMA,
        "graph_sha256": graph_sha256 if isinstance(graph_sha256, str) else None,
        "authority": dict(_AUTHORITY),
        "scope_limits": [
            "Structural planning is advisory and read-only.",
            "Shared candidates do not authorize proof reuse.",
            "No time, token, cost, or productivity savings are inferred without paired evidence.",
        ],
    }


def _blocked_plan(common: dict[str, Any], marker: str, cycles: list[list[str]]) -> dict[str, Any]:
    core = {
        **common, "verdict": "BLOCKED", "markers": [marker], "cycles": cycles,
        "critical_path": [], "workset": [], "parallel_waves": [],
        "shared_candidates": [], "quantitative": _unmeasured(),
    }
    return {**core, "portfolio_sha256": _sha(core)}


def _predecessors(nodes: list[str], successors: dict[str, list[str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for source, children in successors.items():
        for child in children:
            result[child].append(source)
    return {node_id: sorted(values) for node_id, values in result.items()}


def _schedule(ordered: list[str], successors: dict[str, list[str]], predecessors: dict[str, list[str]], durations: dict[str, int] | None) -> tuple[dict[str, int], dict[str, str | None], dict[str, int]]:
    earliest: dict[str, int] = {}
    parents: dict[str, str | None] = {}
    for node_id in ordered:
        prior, parent = max(((earliest[item], item) for item in predecessors[node_id]), default=(0, None))
        earliest[node_id] = prior + (durations[node_id] if durations else 1)
        parents[node_id] = parent
    downstream: dict[str, int] = {}
    for node_id in reversed(ordered):
        own = durations[node_id] if durations else 1
        downstream[node_id] = own + max((downstream[child] for child in successors[node_id]), default=0)
    return earliest, parents, downstream


def _critical_path(nodes: list[str], earliest: dict[str, int], parents: dict[str, str | None]) -> tuple[list[str], int]:
    horizon = max(earliest.values(), default=0)
    terminal = min((node_id for node_id in nodes if earliest.get(node_id) == horizon), default=None)
    path: list[str] = []
    while terminal is not None:
        path.append(terminal)
        terminal = parents[terminal]
    return list(reversed(path)), horizon


def _workset(ordered: list[str], source_nodes: dict[str, dict[str, Any]], earliest: dict[str, int], downstream: dict[str, int], horizon: int, descendants: dict[str, list[str]], blocked: dict[str, list[str]], durations: dict[str, int] | None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for sequence, node_id in enumerate(ordered, 1):
        duration = durations[node_id] if durations else None
        unit = duration if duration is not None else 1
        disposition = "BLOCK" if blocked[node_id] else _disposition(source_nodes[node_id])
        result.append({
            "sequence": sequence, "node_id": node_id, "disposition": disposition,
            "structural_depth": earliest[node_id] - unit,
            "slack": horizon - earliest[node_id] - (downstream[node_id] - unit),
            "descendant_count": len(descendants[node_id]), "shared_candidate": len(descendants[node_id]) >= 2,
            "duration_ms": duration, "blocked_by": blocked[node_id],
            "independent_verifier_required": disposition == "RUN",
        })
    return result


def _parallel_waves(workset: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ready = [item for item in workset if not item["blocked_by"] and item["disposition"] != "BLOCK"]
    depths = sorted({item["structural_depth"] for item in ready})
    return [{"index": depth + 1, "node_ids": [item["node_id"] for item in ready if item["structural_depth"] == depth], "authority": "proposal_only"} for depth in depths]


def graph_portfolio_plan(snapshot: dict[str, Any], duration_observations: object = None) -> dict[str, Any]:
    """Compile a deterministic structural plan without writing or executing."""
    common = _common(snapshot)
    nodes, successors, source_nodes = _dependency_graph(snapshot if isinstance(snapshot, dict) else {})
    if not isinstance(snapshot, dict) or not snapshot.get("complete"):
        return _blocked_plan(common, "GRAPH_PORTFOLIO_GRAPH_INCOMPLETE", [])
    cycles = _cycle_components(nodes, successors)
    if cycles:
        return _blocked_plan(common, "GRAPH_PORTFOLIO_CYCLE_BLOCKED", cycles)
    ordered = _topological_order(nodes, successors)
    durations = _valid_durations(nodes, duration_observations)
    earliest, parents, downstream = _schedule(ordered, successors, _predecessors(nodes, successors), durations)
    critical_path, horizon = _critical_path(nodes, earliest, parents)
    descendants = _descendants(nodes, successors)
    blockers = _blocked_ancestors(nodes, successors, source_nodes)
    workset = _workset(ordered, source_nodes, earliest, downstream, horizon, descendants, blockers, durations)
    shared = [{"node_id": node_id, "descendant_count": len(descendants[node_id]), "proof_reuse_authorized": False} for node_id in nodes if len(descendants[node_id]) >= 2]
    quantitative = _quantitative(horizon, durations)
    markers = ["GRAPH_PORTFOLIO_STRUCTURAL_PLAN", "GRAPH_PORTFOLIO_STABLE_ORDER", "GRAPH_PORTFOLIO_SAFE_PARALLEL_WAVES", *quantitative["markers"]]
    if shared:
        markers.append("GRAPH_PORTFOLIO_SHARED_CANDIDATE")
    if any(item["blocked_by"] for item in workset):
        markers.append("GRAPH_PORTFOLIO_BLOCKER_CHAINS")
    core = {**common, "verdict": "READY", "markers": sorted(markers), "cycles": [], "critical_path": critical_path, "workset": workset, "parallel_waves": _parallel_waves(workset), "shared_candidates": shared, "quantitative": quantitative}
    return {**core, "portfolio_sha256": _sha(core)}


def _unmeasured() -> dict[str, Any]:
    return {
        "markers": ["GRAPH_PORTFOLIO_SAVINGS_UNMEASURED"],
        "durations_measured": False,
        "critical_path_ms": None,
        "time_saved_ms": None,
        "tokens_saved": None,
        "cost_saved_usd": None,
        "productivity_gain_rate": None,
    }


def _quantitative(horizon: int, durations: dict[str, int] | None) -> dict[str, Any]:
    if durations is None:
        return _unmeasured()
    return {
        "markers": ["GRAPH_PORTFOLIO_DURATION_OBSERVATIONS_BOUND", "GRAPH_PORTFOLIO_SAVINGS_UNMEASURED"],
        "durations_measured": True,
        "critical_path_ms": horizon,
        "time_saved_ms": None,
        "tokens_saved": None,
        "cost_saved_usd": None,
        "productivity_gain_rate": None,
    }
