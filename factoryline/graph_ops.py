"""Read-only, deterministic unification of local Factory graph artifacts.

Graph Ops is deliberately an overlay.  It never becomes an authority source and
never runs a gate: it links the existing Product Mission, proof reuse, and
proof-trace receipts so a user can inspect the smallest fact-derived next step.
"""
from __future__ import annotations

from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any
import hashlib
import json

from .product_missions import verify_mission_completion
from .proof import verify_trace
from .proof_reuse import verify_proof_receipt
from .graph_forensics import graph_forensics, verify_graph_lineage
from .proofsearch import verify_proofsearch_evaluation
from .evidence_frontier import verify_evidence_frontier
from .reality_check import RealityCheckError, validate_reality_check_receipt
from .graph_authorization import GraphAuthorizationError, validate_graph_authorization
from .continuity import CONTINUITY_DB_RELATIVE_PATH, continuity_projection
from .counterexample import CounterexampleError, verify_counterexample_plan
from .guardrails import GuardrailError, verify_guardrail_evaluation
from .proof_delta import ProofDeltaError, verify_proof_delta
from .intake_grill import verify_intake_confirmation
from .gauntlet import GauntletError, validate_survival_card
from .resilience import ResilienceError, verify_temporal_resilience_plan
from .agent_license import license_projection
from .combine import combine_projection


GRAPH_OPS_SCHEMA = "factory.graph-ops.v1"
MAX_SOURCE_BYTES = 1_048_576
MAX_NODES = 500
MAX_EDGES = 1_000
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _source(root: Path, path: Path) -> tuple[Path, str]:
    """Resolve a source only when it remains a regular file below *root*."""
    resolved = Path(path).resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("OUTSIDE_ROOT") from exc
    if not resolved.is_file():
        raise ValueError("NOT_A_FILE")
    return resolved, relative.as_posix()


def _record_error(errors: list[dict[str, str]], path: Path, code: str) -> None:
    value = {"source": str(path).replace("\\", "/"), "code": code}
    if value not in errors:
        errors.append(value)


def _load_json(root: Path, candidate: Path, errors: list[dict[str, str]]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        path, relative = _source(root, candidate)
    except ValueError as exc:
        _record_error(errors, candidate, str(exc))
        return None, None
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            _record_error(errors, relative, "SOURCE_TOO_LARGE")
            return None, relative
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _record_error(errors, relative, "SOURCE_UNREADABLE")
        return None, relative
    if not isinstance(value, dict):
        _record_error(errors, relative, "SOURCE_NOT_OBJECT")
        return None, relative
    return value, relative


def _text(value: object, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()[:240]
    return fallback


def _node(state: dict[str, Any], *, node_id: str, kind: str, label: str,
          source: str | None = None, status: str | None = None, facts: dict[str, Any] | None = None) -> bool:
    if node_id in state["nodes"]:
        return True
    if len(state["nodes"]) >= MAX_NODES:
        state["truncated"] = True
        _record_error(state["errors"], ".factory", "NODE_LIMIT")
        return False
    value: dict[str, Any] = {"id": node_id, "kind": kind, "label": label}
    if source:
        value["source"] = source
    if status:
        value["status"] = status
    if facts:
        value["facts"] = facts
    state["nodes"][node_id] = value
    return True


def _edge(state: dict[str, Any], source: str, target: str, relation: str) -> bool:
    if source not in state["nodes"] or target not in state["nodes"]:
        return False
    key = (source, target, relation)
    if key in state["edge_keys"]:
        return True
    if len(state["edges"]) >= MAX_EDGES:
        state["truncated"] = True
        _record_error(state["errors"], ".factory", "EDGE_LIMIT")
        return False
    state["edge_keys"].add(key)
    state["edges"].append({"source": source, "target": target, "relation": relation})
    return True


def _artifact(state: dict[str, Any], root: Path, raw: object, *, source: str, role: str) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = Path(raw)
    candidate = candidate if candidate.is_absolute() else root / candidate
    try:
        path, relative = _source(root, candidate)
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.stat().st_size <= MAX_SOURCE_BYTES else None
        if digest is None:
            _record_error(state["errors"], relative, "SOURCE_TOO_LARGE")
            return None
    except (OSError, ValueError):
        _record_error(state["errors"], candidate, "ARTIFACT_UNREADABLE")
        return None
    node_id = f"artifact:{_sha({'path': relative, 'sha256': digest})[:24]}"
    _node(state, node_id=node_id, kind="artifact", label=relative, source=source, status="bound",
          facts={"path": relative, "sha256": digest, "role": role})
    return node_id


def _append_product_graphs(state: dict[str, Any], root: Path) -> tuple[dict[tuple[str, str], str], dict[str, list[str]]]:
    requirements: dict[tuple[str, str], str] = {}
    slices: dict[str, list[str]] = {}
    state["slice_plan_seen"] = False
    state["slice_links_exact"] = True
    product_root = root / ".factory" / "products"
    for graph_path in sorted(product_root.glob("*/product_graph.json")):
        graph, source = _load_json(root, graph_path, state["errors"])
        if graph is None or source is None:
            continue
        project = _text(graph.get("project"), graph_path.parent.name)
        product_id = f"product:{project}"
        _node(state, node_id=product_id, kind="product", label=project, source=source, status=_text(graph.get("status"), "unknown"))
        for entry in graph.get("requirements", []):
            if not isinstance(entry, dict):
                continue
            requirement_id = _text(entry.get("id"), "requirement")
            node_id = f"requirement:{project}:{requirement_id}"
            _node(state, node_id=node_id, kind="requirement", label=requirement_id, source=source,
                  status="unverified", facts={"statement": _text(entry.get("statement"), requirement_id)})
            _edge(state, product_id, node_id, "declares")
            requirements[(project, requirement_id)] = node_id

        slices_path = graph_path.parent / "value_slices.json"
        plan, plan_source = _load_json(root, slices_path, state["errors"]) if slices_path.exists() else (None, None)
        if plan is None or plan_source is None:
            continue
        state["slice_plan_seen"] = True
        planned_slices: list[tuple[dict[str, Any], str]] = []
        for entry in plan.get("slices", []):
            if not isinstance(entry, dict):
                continue
            slice_id = _text(entry.get("id"), "slice")
            node_id = f"slice:{project}:{slice_id}"
            _node(state, node_id=node_id, kind="slice", label=slice_id, source=plan_source,
                  status=_text(entry.get("risk"), "unknown"), facts={"theme": _text(entry.get("theme"), "unknown")})
            _edge(state, product_id, node_id, "plans")
            slices.setdefault(slice_id, []).append(node_id)
            planned_slices.append((entry, node_id))
            for req_id in entry.get("requirement_ids", []):
                requirement = requirements.get((project, str(req_id)))
                if requirement:
                    _edge(state, requirement, node_id, "assigned_to")
        for entry, node_id in planned_slices:
            for dependency in entry.get("depends_on", []):
                for dependency_id in slices.get(str(dependency), []):
                    _edge(state, dependency_id, node_id, "depends_on")
        for requirement_id, requirement_node in (
            (item["id"], requirements.get((project, item["id"])))
            for item in graph.get("requirements", []) if isinstance(item, dict) and isinstance(item.get("id"), str)
        ):
            assigned = [edge for edge in state["edges"] if edge["source"] == requirement_node and edge["relation"] == "assigned_to"]
            if requirement_node is None or len(assigned) != 1:
                state["slice_links_exact"] = False
                _record_error(state["errors"], plan_source, f"SLICE_ASSIGNMENT_{requirement_id}")
        for entry, node_id in planned_slices:
            for dependency in entry.get("depends_on", []):
                expected = [(dependency_id, node_id, "depends_on") for dependency_id in slices.get(str(dependency), [])]
                if len(expected) != 1 or expected[0] not in state["edge_keys"]:
                    state["slice_links_exact"] = False
                    _record_error(state["errors"], plan_source, f"SLICE_DEPENDENCY_{dependency}")
    return requirements, slices


def _append_missions(state: dict[str, Any], root: Path, requirements: dict[tuple[str, str], str],
                     slices: dict[str, list[str]]) -> set[str]:
    evidenced: set[str] = set()
    mission_root = root / ".factory" / "missions"
    for mission_path in sorted(mission_root.glob("*/mission.json")):
        mission, source = _load_json(root, mission_path, state["errors"])
        if mission is None or source is None:
            continue
        mission_id = _text(mission.get("id"), mission_path.parent.name)
        node_id = f"mission:{mission_id}"
        _node(state, node_id=node_id, kind="mission", label=mission_id, source=source,
              status=_text(mission.get("approval_state"), _text(mission.get("status"), "unknown")))
        slice_id = _text(mission.get("slice_id"), "")
        for slice_node in slices.get(slice_id, []):
            _edge(state, slice_node, node_id, "governs")

        decision_path = mission_path.parent / "execution_decision.json"
        if decision_path.exists():
            decision, decision_source = _load_json(root, decision_path, state["errors"])
            if decision is not None and decision_source is not None:
                decision_id = f"approval:{mission_id}"
                _node(state, node_id=decision_id, kind="approval", label=f"approval for {mission_id}", source=decision_source,
                      status=_text(decision.get("decision"), "unknown"))
                _edge(state, decision_id, node_id, "decides")

        completion_path = mission_path.parent / "completion.json"
        if completion_path.exists():
            completion, completion_source = _load_json(root, completion_path, state["errors"])
            verification: dict[str, Any] | None = None
            if completion is not None:
                try:
                    verification = verify_mission_completion(completion_path)
                except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                    verification = {"valid": False, "errors": ["completion verification failed"]}
            if completion is not None and completion_source is not None:
                completion_id = f"completion:{mission_id}"
                status = "verified" if verification and verification.get("valid") is True else "invalid"
                _node(state, node_id=completion_id, kind="completion", label=f"completion for {mission_id}", source=completion_source,
                      status=status, facts={"errors": verification.get("errors", []) if verification else []})
                _edge(state, node_id, completion_id, "completed_by")
                if verification and verification.get("valid") is True:
                    project = _text(mission.get("project"), "")
                    for requirement_id in mission.get("slice", {}).get("requirement_ids", []):
                        req_node = requirements.get((project, str(requirement_id)))
                        if req_node:
                            _edge(state, completion_id, req_node, "verifies")
                            evidenced.add(req_node)
    return evidenced


def _append_intake_confirmations(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project only source-bound human intake decisions already present in graphs."""
    facts = {"count": 0, "confirmed_count": 0, "invalid_count": 0}
    for graph_path in sorted((root / ".factory" / "products").glob("*/product_graph.json")):
        graph, source = _load_json(root, graph_path, state["errors"])
        if graph is None or source is None:
            continue
        binding = graph.get("intake")
        if binding is None:
            continue
        project = _text(graph.get("project"), graph_path.parent.name)
        if not isinstance(binding, dict) or not isinstance(binding.get("path"), str):
            _record_error(state["errors"], source, "INTAKE_CONFIRMATION_INVALID")
            facts["invalid_count"] += 1
            continue
        try:
            confirmation = verify_intake_confirmation(root, Path(binding["path"]))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            confirmation = {"valid": False, "errors": ["intake confirmation verification failed"]}
        value = confirmation.get("confirmation") if isinstance(confirmation.get("confirmation"), dict) else None
        valid = bool(confirmation.get("valid")) and value is not None
        digest = _text(binding.get("confirmation_sha256"), _sha(binding)[:24])
        node_id = f"intake:{digest[:24]}"
        decision = value.get("decision", {}) if value else {}
        _node(
            state, node_id=node_id, kind="intake", label=f"intake · {_text(decision.get('framework'), 'unconfirmed')}",
            source=source, status="confirmed" if valid else "invalid",
            facts={
                "framework": _text(decision.get("framework"), "unconfirmed"),
                "source_sha256": binding.get("source_sha256"),
                "acceptance_evidence": "bound" if valid else "unverified",
                "external_effects": _text(decision.get("external_effects"), "unknown"),
                "re_evaluation_declared": bool(decision.get("re_evaluate_when")) if isinstance(decision, dict) else False,
                "authority": _AUTHORITY,
            },
        )
        product_id = f"product:{project}"
        if product_id in state["nodes"]:
            _edge(state, node_id, product_id, "sets_intent_for")
        facts["count"] += 1
        facts["confirmed_count"] += int(valid)
        facts["invalid_count"] += int(not valid)
    return facts


def _append_proofs(state: dict[str, Any], root: Path) -> int:
    stale = 0
    proof_root = root / ".factory" / "proofs"
    for receipt_path in sorted(proof_root.glob("*.json")):
        receipt, source = _load_json(root, receipt_path, state["errors"])
        if receipt is None or source is None:
            continue
        key = _text(receipt.get("proof_key"), receipt_path.stem)
        try:
            verification = verify_proof_receipt(root, receipt_path)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            verification = {"valid": False, "errors": ["proof verification failed"]}
        status = "verified" if verification.get("valid") is True else "stale"
        stale += status == "stale"
        proof_id = f"proof:{key}"
        _node(state, node_id=proof_id, kind="proof", label=_text(receipt.get("gate"), key), source=source,
              status=status, facts={"proof_key": key, "errors": verification.get("errors", [])})
        for role in ("inputs", "outputs"):
            for item in receipt.get(role, []):
                if not isinstance(item, dict):
                    continue
                artifact_id = _artifact(state, root, item.get("path"), source=source, role=role[:-1])
                if artifact_id:
                    _edge(state, artifact_id, proof_id, "input_to" if role == "inputs" else "validated_by")
    return stale


def _append_plans(state: dict[str, Any], root: Path) -> Counter[str]:
    dispositions: Counter[str] = Counter()
    for plan_path in sorted((root / ".factory" / "proof-plans").glob("*.json")):
        plan, source = _load_json(root, plan_path, state["errors"])
        if plan is None or source is None:
            continue
        for index, item in enumerate(plan.get("items", []), 1):
            if not isinstance(item, dict):
                continue
            disposition = _text(item.get("disposition"), "UNKNOWN").upper()
            dispositions[disposition] += 1
            proof_key = _text(item.get("proof_key"), f"item-{index}")
            gate_id = f"gate:{plan_path.stem}:{index}"
            _node(state, node_id=gate_id, kind="gate", label=_text(item.get("gate"), proof_key), source=source,
                  status=disposition, facts={"reason": _text(item.get("reason"), "not declared"), "proof_key": proof_key})
            proof_id = f"proof:{proof_key}"
            if proof_id in state["nodes"]:
                _edge(state, gate_id, proof_id, "uses_proof")
    return dispositions


def _append_traces(state: dict[str, Any], root: Path) -> None:
    for trace_path in sorted((root / ".factory" / "traces").glob("*.trace.json")):
        trace, source = _load_json(root, trace_path, state["errors"])
        if trace is None or source is None:
            continue
        try:
            verification = verify_trace(trace_path, root=root)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            verification = {"valid": False, "errors": ["trace verification failed"]}
        trace_id = f"trace:{_text(trace.get('feature'), trace_path.stem)}"
        _node(state, node_id=trace_id, kind="trace", label=_text(trace.get("feature"), trace_path.stem), source=source,
              status="verified" if verification.get("valid") is True else "invalid",
              facts={"errors": verification.get("errors", [])})
        for index, item in enumerate(trace.get("nodes", []), 1):
            if not isinstance(item, dict):
                continue
            receipt_hash = _text(item.get("receipt_sha256"), f"receipt-{index}")
            receipt_id = f"receipt:{receipt_hash[:24]}"
            _node(state, node_id=receipt_id, kind="receipt", label=_text(item.get("receipt_path"), receipt_hash[:12]), source=source,
                  status="verified" if verification.get("valid") is True else "unverified")
            _edge(state, trace_id, receipt_id, "contains")
            for artifact in item.get("artifacts", []):
                if not isinstance(artifact, dict):
                    continue
                artifact_id = _artifact(state, root, artifact.get("path"), source=source, role=_text(artifact.get("kind"), "artifact"))
                if artifact_id:
                    _edge(state, receipt_id, artifact_id, "observes")


def _append_verifier_sessions(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Expose declared verifier-session boundaries without treating them as execution proof."""
    facts = {"session_count": 0, "runtime_unattested_count": 0}
    session_root = root / ".factory" / "verifier-sessions"
    for session_path in sorted(session_root.glob("*.session.json")):
        session, source = _load_json(root, session_path, state["errors"])
        if session is None or source is None:
            continue
        digest = _text(session.get("session_sha256"), session_path.stem)
        runtime_unattested = "VERIFIER_RUNTIME_UNATTESTED" in session.get("markers", [])
        status = "runtime-unattested" if runtime_unattested else "bound"
        session_id = f"verifier-session:{digest[:24]}"
        _node(
            state,
            node_id=session_id,
            kind="verifier_session",
            label=f"verifier session for {_text(session.get('mission_id'), session_path.stem)}",
            source=source,
            status=status,
            facts={
                "mission_id": _text(session.get("mission_id"), "unknown"),
                "owner": _text(session.get("owner"), "unknown"),
                "candidate_root": _text(session.get("candidate_root"), "unknown"),
                "scope": "evidence contract only",
            },
        )
        mission_id = _artifact(state, root, session.get("mission_path"), source=source, role="mission")
        if mission_id:
            _edge(state, mission_id, session_id, "governs")
        candidate_root = _text(session.get("candidate_root"), "candidate")
        candidate_id = f"candidate-tree:{_sha({'session': digest, 'path': candidate_root})[:24]}"
        _node(
            state,
            node_id=candidate_id,
            kind="candidate_tree",
            label=candidate_root,
            source=source,
            status="declared",
            facts={"baseline_sha256": _text(session.get("candidate_baseline_sha256"), "unavailable")},
        )
        _edge(state, session_id, candidate_id, "bounds")
        for entry in session.get("verifier_bundle", []):
            if not isinstance(entry, dict):
                continue
            bundle_id = _artifact(state, root, entry.get("path"), source=source, role="verifier_bundle")
            if bundle_id:
                _edge(state, bundle_id, session_id, "verifies_with")
        facts["session_count"] += 1
        facts["runtime_unattested_count"] += int(runtime_unattested)
    return facts


def _append_graph_forensics(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Add verified lineage and latest-pair forensic facts to the read-only map."""
    facts = {"lineage_count": 0, "anomaly_count": 0, "divergence_count": 0}
    verified: list[tuple[Path, dict[str, Any], str, str]] = []
    for path in sorted((root / ".factory" / "graph-runs").glob("*.lineage.json")):
        lineage, source = _load_json(root, path, state["errors"])
        if lineage is None or source is None:
            continue
        result = verify_graph_lineage(path)
        run_id = _text(result.get("run_id"), path.stem)
        node_id = f"lineage:{run_id}"
        _node(state, node_id=node_id, kind="lineage", label=run_id, source=source,
              status="verified" if result["valid"] else "invalid",
              facts={"graph_id": _text(result.get("graph_id"), "unknown"), "steps": len(result["steps"]), "errors": result["errors"]})
        facts["lineage_count"] += 1
        if result["valid"]:
            verified.append((path, result, node_id, source))
    by_graph: dict[str, list[tuple[Path, dict[str, Any], str, str]]] = {}
    for item in verified:
        by_graph.setdefault(str(item[1]["graph_id"]), []).append(item)
    for graph_id, items in sorted(by_graph.items()):
        if len(items) < 2:
            continue
        baseline, candidate = items[-2], items[-1]
        result = graph_forensics(baseline[0], candidate[0])
        forensic_id = f"forensics:{_sha({'graph_id': graph_id, 'sha': result['forensics_sha256']})[:24]}"
        status = "anomaly" if result["anomalies"] else "diverged" if result["divergence"] else "verified"
        _node(state, node_id=forensic_id, kind="forensics", label=f"{baseline[1]['run_id']} vs {candidate[1]['run_id']}",
              source=candidate[3], status=status,
              facts={
                  "graph_id": graph_id,
                  "baseline": result["baseline"],
                  "candidate": result["candidate"],
                  "baseline_path": baseline[3],
                  "candidate_path": candidate[3],
                  "first_divergence": result["divergence"],
                  "anomaly_count": len(result["anomalies"]),
                  "anomalies": result["anomalies"],
                  "recovery_plan": result["recovery_plan"],
                  "authority": result["authority"],
                  "forensics_sha256": result["forensics_sha256"],
              })
        _edge(state, baseline[2], forensic_id, "baseline_for")
        _edge(state, candidate[2], forensic_id, "candidate_for")
        facts["anomaly_count"] += len(result["anomalies"])
        facts["divergence_count"] += int(result["divergence"] is not None)
    return facts


def _append_proofsearch(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Add sealed counterfactual evaluations and their candidate decisions."""
    facts = {"evaluation_count": 0, "candidate_count": 0, "eligible_count": 0, "winner_count": 0}
    directory = root / ".factory" / "proofsearch"
    for path in sorted(directory.glob("*.evaluation.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        verification = verify_proofsearch_evaluation(root, path)
        digest = _text(value.get("evaluation_sha256"), path.stem)
        evaluation_id = f"proofsearch:{digest[:24]}"
        winner = value.get("winner")
        _node(
            state, node_id=evaluation_id, kind="proofsearch", label=f"ProofSearch · {winner or 'no winner'}",
            source=source, status="verified" if verification["valid"] and winner else "blocked" if verification["valid"] else "invalid",
            facts={
                "winner": winner, "decision": value.get("decision"), "apply": value.get("apply"),
                "savings": value.get("savings", {}), "authority": value.get("authority", {}),
                "evaluation_sha256": digest, "valid": verification["valid"], "errors": verification["errors"],
                "candidate_count": len(value.get("candidates", [])),
            },
        )
        facts["evaluation_count"] += 1
        for candidate in value.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            candidate_id = _text(candidate.get("candidate_id"), "candidate")
            node_id = f"repair-candidate:{_sha({'evaluation': digest, 'candidate': candidate_id})[:24]}"
            is_winner = candidate_id == winner
            eligible = candidate.get("eligible") is True
            status = "winner" if is_winner else "eligible" if eligible else "rejected"
            _node(
                state, node_id=node_id, kind="repair_candidate", label=candidate_id, source=source, status=status,
                facts={
                    "winner": is_winner, "eligible": eligible, "reasons": candidate.get("reasons", []),
                    "risk_score": candidate.get("risk_score"), "changed_lines": candidate.get("changed_lines"),
                    "changed_paths": candidate.get("changed_paths", []), "mutation": candidate.get("mutation", {}),
                    "metrics": candidate.get("metrics", {}), "proofs": candidate.get("proofs", []),
                    "patch": candidate.get("patch", {}), "guardrails": candidate.get("guardrails", {}),
                },
            )
            _edge(state, node_id, evaluation_id, "evaluated_by")
            facts["candidate_count"] += 1
            facts["eligible_count"] += int(eligible)
            facts["winner_count"] += int(is_winner)
    return facts


def _append_evidence_frontiers(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project sealed, non-executing next-evidence choices into Graph Ops."""
    facts = {"frontier_count": 0, "ready_count": 0, "halted_count": 0}
    directory = root / ".factory" / "proofsearch"
    for path in sorted(directory.glob("*.frontier.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        verification = verify_evidence_frontier(root, path)
        digest = _text(value.get("frontier_sha256"), path.stem)
        next_experiment = value.get("next_experiment")
        status = "ready" if verification["valid"] and next_experiment else "halted" if verification["valid"] else "invalid"
        frontier_id = f"evidence-frontier:{digest[:24]}"
        _node(
            state, node_id=frontier_id, kind="evidence_frontier", label=f"Evidence Frontier · {next_experiment or 'no separating test'}",
            source=source, status=status,
            facts={
                "next_experiment": next_experiment, "decision": value.get("decision"),
                "eligible_candidate_ids": value.get("eligible_candidate_ids", []),
                "max_experiments": value.get("max_experiments"), "savings": value.get("savings", {}),
                "authority": value.get("authority", {}), "frontier_sha256": digest,
                "valid": verification["valid"], "errors": verification["errors"],
            },
        )
        evaluation_path = value.get("evaluation", {}).get("path") if isinstance(value.get("evaluation"), dict) else None
        for node in state["nodes"].values():
            if node.get("kind") == "proofsearch" and node.get("source") == evaluation_path:
                _edge(state, frontier_id, node["id"], "selects_evidence_for")
        for experiment in value.get("experiments", []):
            if not isinstance(experiment, dict):
                continue
            experiment_id = _text(experiment.get("experiment_id"), "experiment")
            node_id = f"evidence-experiment:{_sha({'frontier': digest, 'experiment': experiment_id})[:24]}"
            _node(
                state, node_id=node_id, kind="evidence_experiment", label=experiment_id, source=source,
                status="next" if experiment_id == next_experiment else "ranked",
                facts={
                    "rank": experiment.get("rank"), "kind": experiment.get("kind"),
                    "description": experiment.get("description"), "predictions": experiment.get("predictions", {}),
                    "separation_count": experiment.get("separation_count"),
                    "candidate_pair_count": experiment.get("candidate_pair_count"),
                    "measurement": experiment.get("measurement"), "execution_allowed": False,
                },
            )
            _edge(state, node_id, frontier_id, "ranked_by")
        facts["frontier_count"] += 1
        facts["ready_count"] += int(status == "ready")
        facts["halted_count"] += int(status == "halted")
    return facts


def _append_reality_checks(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project sealed supervised behavior receipts without rerunning commands."""
    facts = {"count": 0, "verified_count": 0, "blocked_count": 0}
    directory = root / ".factory" / "reality"
    for path in sorted(directory.glob("*.reality.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            receipt = validate_reality_check_receipt(value)
        except RealityCheckError as exc:
            state["errors"].append({"code": exc.code, "source": source})
            continue
        manifest = receipt["manifest"]
        status = "verified" if receipt["ok"] else "hollow" if receipt["marker"] == "REALITY_CHECK_HOLLOW" else "blocked"
        node_id = f"reality-check:{receipt['receipt_sha256'][:24]}"
        _node(
            state, node_id=node_id, kind="reality_check", label=manifest["id"], source=source, status=status,
            facts={
                "promise": manifest["behavior"]["promise"], "happy_path": manifest["behavior"]["happy_path"],
                "failure_case": manifest["behavior"]["failure_case"], "marker": receipt["marker"],
                "receipt_sha256": receipt["receipt_sha256"], "e2e_marker": receipt["e2e_receipt"]["marker"],
                "authority": receipt["authority"], "verified": receipt["ok"],
            },
        )
        facts["count"] += 1; facts["verified_count"] += int(receipt["ok"]); facts["blocked_count"] += int(not receipt["ok"])
    return facts


def _append_graph_authorizations(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project named, expiring Graph Ops authorizations without consuming them."""
    facts = {"count": 0, "approved_count": 0, "consumed_count": 0}
    directory = root / ".factory" / "graph-ops" / "authorizations"
    for path in sorted(directory.glob("*.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            authorization = validate_graph_authorization(value)
        except GraphAuthorizationError as exc:
            _record_error(state["errors"], source, exc.code)
            continue
        binding = authorization["binding"]
        node_id = f"authorization:{authorization['id']}"
        _node(
            state, node_id=node_id, kind="authorization", label=authorization["id"], source=source,
            status=authorization["state"],
            facts={
                "action": authorization["action"], "approved_by": authorization["approved_by"],
                "expires_at": authorization["expires_at"], "authorization_sha256": authorization["authorization_sha256"],
                "target_node_id": binding["node_id"], "authority": authorization["authority"],
            },
        )
        _edge(state, node_id, binding["node_id"], "authorizes")
        facts["count"] += 1
        facts["approved_count"] += int(authorization["state"] == "approved")
        facts["consumed_count"] += int(authorization["state"] == "consumed")
    return facts


def _append_github_assurance_dossiers(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project local merge-evidence dossiers without treating them as GitHub policy truth."""
    # Deferred to avoid the existing change-review -> Graph Ops import cycle.
    from .github_assurance_dossier import GitHubAssuranceDossierError, validate_assurance_dossier
    facts = {"count": 0, "review_required_count": 0, "unresolved_high_count": 0}
    directory = root / ".factory" / "github-assurance"
    for path in sorted(directory.glob("*.dossier.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            dossier = validate_assurance_dossier(value)
        except GitHubAssuranceDossierError as exc:
            _record_error(state["errors"], source, exc.code)
            continue
        node_id = f"assurance-dossier:{dossier['dossier_sha256'][:24]}"
        _node(
            state, node_id=node_id, kind="assurance_dossier", label=f"Merge evidence: {dossier['status']}",
            source=source, status=dossier["status"], facts={
                "head_sha": dossier["head_sha"], "dossier_sha256": dossier["dossier_sha256"],
                "policy_current_sha256": dossier["policy"]["current_sha256"], "baseline_supplied": dossier["drift"]["baseline_supplied"],
                "unresolved_high_count": dossier["drift"]["unresolved_high_count"], "authority": dossier["authority"],
            },
        )
        for finding in dossier["drift"]["findings"]:
            finding_id = f"policy-drift:{dossier['dossier_sha256'][:16]}:{finding['id']}"
            _node(state, node_id=finding_id, kind="policy_drift", label=finding["id"], source=source,
                  status="unresolved" if finding["id"] not in {item for exception in dossier["exceptions"] for item in exception["finding_ids"]} else "exceptioned",
                  facts={"severity": finding["severity"], "message": finding["message"], "ruleset_id": finding["ruleset_id"]})
            _edge(state, finding_id, node_id, "reported_by")
        facts["count"] += 1
        facts["review_required_count"] += int(dossier["status"] == "review_required")
        facts["unresolved_high_count"] += dossier["drift"]["unresolved_high_count"]
    return facts


def _append_continuity(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project redacted local continuity metadata without recalling memory content.

    Graph Ops only reads the local ledger projection.  It cannot record,
    promote, sign, or authorize a continuity record, and it intentionally does
    not expose a stored memory reference or its summary.
    """
    projection = continuity_projection(root)
    facts = {
        "record_count": 0,
        "draft_count": 0,
        "verified_current_count": 0,
        "expired_count": 0,
    }
    if projection["error"]:
        _record_error(state["errors"], CONTINUITY_DB_RELATIVE_PATH, projection["error"])
        return facts
    if not projection["available"]:
        return facts
    facts = {key: int(projection["facts"].get(key, 0)) for key in facts}
    source = CONTINUITY_DB_RELATIVE_PATH.as_posix()
    for record in projection["records"]:
        record_id = str(record["record_id"])
        record_node = f"continuity:{record_id}"
        status = str(record["effective_status"])
        _node(
            state,
            node_id=record_node,
            kind="continuity_record",
            label=f"{record['record_type']} memory reference",
            source=source,
            status=status,
            facts={
                "record_id": record_id,
                "purpose_ref": record["purpose_ref"],
                "scope_ref_sha256": record["scope_ref_sha256"],
                "memory_ref_sha256": record["memory_ref_sha256"],
                "evidence_sha256": record["evidence_sha256"],
                "expires_at": record["expires_at"],
                "promotion": "independently_promoted" if record["status"] == "verified" else "not_promoted",
            },
        )
        purpose_node = f"continuity-purpose:{_sha(record['purpose_ref'])[:24]}"
        scope_node = f"continuity-scope:{record['scope_ref_sha256'][:24]}"
        _node(state, node_id=purpose_node, kind="continuity_purpose", label=record["purpose_ref"], source=source, status="bound")
        _node(state, node_id=scope_node, kind="continuity_scope", label="bounded repository scope", source=source, status="bound", facts={"scope_ref_sha256": record["scope_ref_sha256"]})
        _edge(state, purpose_node, record_node, "governs")
        _edge(state, scope_node, record_node, "scopes")
        for evidence_ref in record["evidence_refs"]:
            evidence_node = f"continuity-evidence:{_sha(evidence_ref)[:24]}"
            _node(state, node_id=evidence_node, kind="continuity_evidence", label="bound evidence reference", source=source, status="declared", facts={"reference_sha256": _sha(evidence_ref)})
            _edge(state, record_node, evidence_node, "requires_evidence")
    if projection.get("truncated"):
        state["truncated"] = True
        _record_error(state["errors"], CONTINUITY_DB_RELATIVE_PATH, "CONTINUITY_RECORD_LIMIT")
    return facts


def _append_proof_deltas(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project retry-admission evidence without starting a retry or a worker."""
    facts = {"count": 0, "advance_count": 0, "halted_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "proof-deltas"
    for path in sorted(directory.glob("*.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            facts["invalid_count"] += 1
            continue
        try:
            verification = verify_proof_delta(root, path)
        except ProofDeltaError as exc:
            _record_error(state["errors"], source, exc.code)
            facts["invalid_count"] += 1
            continue
        status = "admitted" if verification["eligible"] else "halted"
        digest = _text(verification.get("proof_delta_sha256"), path.stem)
        node_id = f"proof-delta:{digest[:24]}"
        _node(
            state, node_id=node_id, kind="proof_delta", label=f"retry · {verification['criterion_id']}",
            source=source, status=status,
            facts={
                "marker": verification["marker"], "mission_id": verification["mission_id"],
                "criterion_id": verification["criterion_id"], "new_evidence_count": len(verification["new_evidence"]),
                "reason": verification["reason"], "proof_delta_sha256": digest,
                "authority": verification["authority"], "execution": False,
            },
        )
        mission_id = f"mission:{verification['mission_id']}"
        if mission_id in state["nodes"]:
            _edge(state, node_id, mission_id, "admits_retry_for")
        facts["count"] += 1
        facts["advance_count"] += int(verification["eligible"])
        facts["halted_count"] += int(not verification["eligible"])
    return facts


def _append_survival_cards(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project existing Gauntlet cards without compiling, admitting, or rerunning a case."""
    facts = {"count": 0, "survived_count": 0, "hollow_count": 0, "blocked_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "gauntlets"
    for path in sorted(directory.glob("*/*.card.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            facts["invalid_count"] += 1
            continue
        try:
            card = validate_survival_card(value)
        except GauntletError as exc:
            _record_error(state["errors"], source, exc.code)
            facts["invalid_count"] += 1
            continue
        status = "survived" if card["ok"] else "hollow" if card["marker"] == "GAUNTLET_HOLLOW" else "blocked"
        node_id = f"gauntlet:{card['card_sha256'][:24]}"
        _node(
            state, node_id=node_id, kind="gauntlet", label=f"Survival Card · {card['source']['id']}", source=source, status=status,
            facts={
                "marker": card["marker"], "card_sha256": card["card_sha256"], "source_id": card["source"]["id"],
                "summary": card["summary"], "unproven_promises": card["unproven_promises"],
                "continuity": {"bound": card["continuity"] is not None, "record_count": len(card["continuity"]["records"]) if card["continuity"] else 0, "binding_sha256": card["continuity"]["binding_sha256"] if card["continuity"] else None},
                "commit": card["commit"], "authority": card["authority"], "execution": False,
            },
        )
        for outcome in card["outcomes"]:
            promise_id = outcome["promise"]["id"]
            for reality_node in state["nodes"].values():
                if reality_node.get("kind") == "reality_check" and reality_node.get("facts", {}).get("promise") == outcome["reality"]["promise"]:
                    _edge(state, reality_node["id"], node_id, "sabotage_evidence_for")
            _node(
                state, node_id=f"gauntlet-case:{card['card_sha256'][:16]}:{_sha(outcome['proposal_id'])[:8]}", kind="gauntlet_case",
                label=f"{promise_id} · {outcome['sabotage']['risk_tag']}", source=source, status=outcome["status"],
                facts={"risk_tag": outcome["sabotage"]["risk_tag"], "mutation": outcome["sabotage"]["mutation"], "e2e_marker": outcome["e2e_receipt"]["marker"]},
            )
            _edge(state, f"gauntlet-case:{card['card_sha256'][:16]}:{_sha(outcome['proposal_id'])[:8]}", node_id, "reported_by")
        facts["count"] += 1
        facts["survived_count"] += int(status == "survived")
        facts["hollow_count"] += int(status == "hollow")
        facts["blocked_count"] += int(status == "blocked")
    return facts


def _append_agent_supervision(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project license and Combine evidence without granting agent authority.

    The view is deliberately derived from the immutable local ledgers.  It does
    not issue a license, invoke a candidate, make an approval decision, or turn
    declared identity into an authenticated one.
    """
    facts = {
        "license_count": 0,
        "human_controlled_count": 0,
        "supervised_count": 0,
        "autonomous_count": 0,
        "incident_count": 0,
        "combine_scoreboard_count": 0,
        "combine_passing_candidate_count": 0,
    }
    licenses = license_projection(root)
    for license_value in licenses.get("licenses", []):
        if not isinstance(license_value, dict):
            continue
        agent = license_value.get("agent")
        evidence = license_value.get("evidence")
        incidents = license_value.get("incidents")
        if not isinstance(agent, dict) or not isinstance(evidence, dict) or not isinstance(incidents, list):
            continue
        identity = _text(agent.get("identity_sha256"), "unknown")
        tier = _text(license_value.get("tier"), "human_controlled")
        node_id = f"agent-license:{identity[:24]}"
        _node(
            state,
            node_id=node_id,
            kind="agent_license",
            label=f"{_text(agent.get('subject'), 'declared agent')} · {tier.replace('_', ' ')}",
            source=".factory/agent-licenses/events",
            status=tier,
            facts={
                "identity_sha256": identity,
                "identity_provenance": license_value.get("identity_provenance"),
                "tier": tier,
                "reason": license_value.get("reason"),
                "expires_at": license_value.get("expires_at"),
                "allowed_paths": license_value.get("allowed_paths", []),
                "evidence": evidence,
                "latest_event_sha256": evidence.get("latest_event_sha256"),
                "derivation": "live_read_only_not_a_sealed_license_artifact",
                "incident_count": len(incidents),
                "authority": license_value.get("authority", _AUTHORITY),
                "execution": False,
            },
        )
        facts["license_count"] += 1
        if tier in {"human_controlled", "supervised", "autonomous"}:
            facts[f"{tier}_count"] += 1
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            event_id = _text(incident.get("event_id"), "incident")
            incident_id = f"agent-incident:{identity[:12]}:{event_id}"
            _node(
                state,
                node_id=incident_id,
                kind="agent_incident",
                label=f"automatic demotion · {event_id}",
                source=".factory/agent-licenses/incidents",
                status="demoted",
                facts={
                    "recorded_at": incident.get("recorded_at"),
                    "failure_classes": incident.get("failure_classes", []),
                    "event_sha256": incident.get("event_sha256"),
                    "effect": "human_controlled_pending_requalification",
                },
            )
            _edge(state, incident_id, node_id, "demotes")
            facts["incident_count"] += 1

    scoreboards = combine_projection(root)
    for scoreboard in scoreboards.get("scoreboards", []):
        if not isinstance(scoreboard, dict):
            continue
        digest = _text(scoreboard.get("scoreboard_sha256"), "scoreboard")
        task_id = _text(scoreboard.get("task_id"), "sealed task")
        candidates = scoreboard.get("candidates")
        if not isinstance(candidates, list):
            continue
        node_id = f"combine-scoreboard:{digest[:24]}"
        _node(
            state,
            node_id=node_id,
            kind="combine_scoreboard",
            label=f"Combine · {task_id}",
            source=".factory/combines/scoreboards",
            status="verified",
            facts={
                "scoreboard_sha256": digest,
                "task_id": task_id,
                "scored_at": scoreboard.get("scored_at"),
                "summary": scoreboard.get("summary", {}),
                "candidate_count": len(candidates),
                "authority": scoreboards.get("authority", _AUTHORITY),
                "execution": False,
            },
        )
        facts["combine_scoreboard_count"] += 1
        for candidate in candidates:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("agent"), dict):
                continue
            candidate_agent = candidate["agent"]
            candidate_identity = candidate_agent.get("identity_sha256")
            if isinstance(candidate_identity, str):
                license_node = f"agent-license:{candidate_identity[:24]}"
                if license_node in state["nodes"]:
                    _edge(state, license_node, node_id, "compared_in")
            facts["combine_passing_candidate_count"] += int(candidate.get("passed") is True)
    return facts


def _append_counterexamples(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project negative-proof plans as facts; never execute the derived cases."""
    facts = {"count": 0, "verified_count": 0, "hollow_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "counterexamples"
    for path in sorted(directory.glob("*.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            verification = verify_counterexample_plan(root, path)
        except CounterexampleError as exc:
            _record_error(state["errors"], source, exc.code)
            facts["invalid_count"] += 1
            continue
        marker = str(verification.get("marker", "COUNTEREXAMPLE_PLAN_INVALID"))
        status = "verified" if verification.get("ok") else "hollow" if marker == "HOLLOW_COUNTEREXAMPLE" else "stale" if marker == "COUNTEREXAMPLE_SOURCE_STALE" else "invalid"
        digest = _text(value.get("plan_sha256"), path.stem)
        node_id = f"counterexample:{digest[:24]}"
        _node(
            state, node_id=node_id, kind="counterexample_plan", label=_text(value.get("source", {}).get("id") if isinstance(value.get("source"), dict) else None, path.stem),
            source=source, status=status,
            facts={
                "marker": marker, "case_count": verification.get("case_count", value.get("facts", {}).get("case_count", 0)),
                "risk_tags": value.get("facts", {}).get("risk_tags", []), "plan_sha256": digest,
                "authority": value.get("authority", _AUTHORITY), "execution": False,
            },
        )
        facts["count"] += 1
        facts["verified_count"] += int(status == "verified")
        facts["hollow_count"] += int(status == "hollow")
        facts["invalid_count"] += int(status in {"stale", "invalid"})
    return facts


def _append_guardrail_evaluations(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project hash-bound redacted guardrail evaluations, never query a ledger."""
    facts = {"count": 0, "active_count": 0, "withheld_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "guardrails"
    for path in sorted(directory.glob("*.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            evaluation = verify_guardrail_evaluation(value)
        except GuardrailError as exc:
            _record_error(state["errors"], source, exc.code)
            facts["invalid_count"] += 1
            continue
        digest = _text(evaluation.get("evaluation_sha256"), path.stem)
        guardrail_id = _text(evaluation.get("manifest", {}).get("id") if isinstance(evaluation.get("manifest"), dict) else None, path.stem)
        node_id = f"guardrail-evaluation:{digest[:24]}"
        rows = evaluation.get("guardrails", []) if isinstance(evaluation.get("guardrails"), list) else []
        _node(
            state, node_id=node_id, kind="guardrail_evaluation", label=guardrail_id, source=source, status="verified",
            facts={
                "evaluation_sha256": digest, "active_count": sum(row.get("status") == "active" for row in rows if isinstance(row, dict)),
                "withheld_count": sum(row.get("status") == "withheld" for row in rows if isinstance(row, dict)),
                "authority": evaluation.get("authority", _AUTHORITY), "memory_content": False,
            },
        )
        facts["count"] += 1
        facts["active_count"] += sum(row.get("status") == "active" for row in rows if isinstance(row, dict))
        facts["withheld_count"] += sum(row.get("status") == "withheld" for row in rows if isinstance(row, dict))
    return facts


def _append_resilience_plans(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project sealed temporal schedules without replaying the underlying graph."""
    facts = {"count": 0, "verified_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "resilience"
    for path in sorted(directory.glob("*.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        try:
            verification = verify_temporal_resilience_plan(root, path)
        except ResilienceError as exc:
            _record_error(state["errors"], source, exc.code)
            facts["invalid_count"] += 1
            continue
        marker = str(verification.get("marker", "TEMPORAL_RESILIENCE_PLAN_INVALID"))
        status = "verified" if verification.get("ok") else "stale" if marker == "TEMPORAL_RESILIENCE_SOURCE_STALE" else "incomplete" if marker == "TEMPORAL_RESILIENCE_PLAN_INCOMPLETE" else "invalid"
        digest = _text(value.get("plan_sha256"), path.stem)
        node_id = f"temporal-resilience:{digest[:24]}"
        _node(
            state, node_id=node_id, kind="temporal_resilience", label=_text(value.get("source", {}).get("graph_id") if isinstance(value.get("source"), dict) else None, path.stem),
            source=source, status=status,
            facts={
                "marker": marker, "schedule_count": verification.get("schedule_count", value.get("facts", {}).get("schedule_count", 0)),
                "kinds": value.get("facts", {}).get("kinds", []), "plan_sha256": digest,
                "authority": value.get("authority", _AUTHORITY), "execution": False,
            },
        )
        facts["count"] += 1
        facts["verified_count"] += int(status == "verified")
        facts["invalid_count"] += int(status != "verified")
    return facts


def _mermaid(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    visible = nodes[:80]
    allowed = {node["id"] for node in visible}
    lines = ["flowchart LR"]
    aliases = {node_id: f"N{index}" for index, node_id in enumerate(sorted(allowed), 1)}
    for node in visible:
        label = node["label"].replace('"', "'")[:80]
        lines.append(f'    {aliases[node["id"]]}["{label}"]')
    for edge in edges:
        if edge["source"] in allowed and edge["target"] in allowed:
            lines.append(f'    {aliases[edge["source"]]} -->|{edge["relation"]}| {aliases[edge["target"]]}')
    return "\n".join(lines) + "\n"


def _recommendation(facts: dict[str, int]) -> tuple[str, str]:
    if facts["node_count"] == 0:
        return "initialize_graph", "No readable local Factory graph artifacts were found."
    if facts["agent_incident_count"] > 0:
        return "review_agent_demotion", "A governed agent result triggered automatic demotion. Inspect the bound incident capsule and collect fresh independent evidence before expanding autonomy."
    if facts["agent_license_human_controlled_count"] > 0:
        return "collect_governed_agent_evidence", "At least one declared agent is human-controlled because its current governed evidence is insufficient or was demoted. Keep approval explicit."
    if facts["proof_delta_halted_count"] > 0:
        return "review_no_evidence_gain", "A proposed retry adds no new hash-bound evidence. Keep the mission paused or revise its evidence packet."
    if facts["intake_invalid_count"] > 0:
        return "refresh_intake_confirmation", "A Product Graph points at an invalid or drifted intake confirmation. Reconfirm framework, intent, acceptance evidence, and external-effects scope before mission work."
    if facts["continuity_expired_count"] > 0:
        return "refresh_expired_continuity", "At least one local continuity record is expired and is withheld from future recall."
    if facts["continuity_draft_count"] > 0:
        return "review_continuity_promotion", "At least one evidence-bound continuity record awaits an independent human promotion."
    if facts["counterexample_hollow_count"] > 0:
        return "restore_negative_proof_coverage", "A counterexample plan is missing a declared negative proof obligation; restore coverage before trusting its result."
    if facts["counterexample_invalid_count"] > 0:
        return "refresh_counterexample_plan", "A counterexample plan is stale or invalid; recompile it from its current bounded requirement source."
    if facts["resilience_invalid_count"] > 0:
        return "refresh_temporal_resilience_plan", "A temporal resilience plan is stale, incomplete, or invalid; recompile it from verified current lineage."
    if facts["guardrail_withheld_count"] > 0:
        return "review_guardrail_withheld", "At least one scoped guardrail lacks independently promoted current continuity evidence."
    if facts["assurance_unresolved_high_count"] > 0:
        return "resolve_policy_drift", "A supplied GitHub policy snapshot has unexceptioned high-severity drift; a human must resolve it before a merge decision."
    if facts["assurance_review_required_count"] > 0:
        return "record_policy_baseline", "A merge-evidence dossier has no comparable baseline; record one before relying on policy alignment."
    if facts["runtime_unattested_session_count"] > 0:
        return "collect_independent_verifier_evidence", "A verifier session is bound, but no Code Factory runtime isolation has been proven."
    if facts["forensic_anomaly_count"] > 0:
        return "review_graph_anomaly", "Verified lineage exposes at least one state or concurrency anomaly."
    if facts["reality_check_blocked_count"] > 0:
        return "repair_reality_check", "A declared user behavior is blocked or hollow; inspect its local proof card before trusting the feature."
    if facts["gauntlet_hollow_count"] > 0:
        return "repair_hollow_sabotage", "At least one declared sabotage still exits zero. Treat its promise as unproven and repair the negative proof before trusting the feature."
    if facts["gauntlet_blocked_count"] > 0:
        return "resolve_blocked_gauntlet", "At least one admitted sabotage batch was blocked. Inspect its public Survival Card and the bound local E2E receipt."
    if facts["proof_delta_advance_count"] > 0:
        return "review_proof_delta_retry", "A retry packet has a new candidate diff and new hash-bound evidence. A named owner must still admit the retry, then an independent validator must check the outcome."
    if facts["evidence_frontier_ready_count"] > 0:
        return "review_evidence_frontier", "A sealed Evidence Frontier ranks the next supplied experiment that separates viable repair candidates; execution remains human-owned."
    if facts["proofsearch_evaluation_count"] > 0 and facts["proofsearch_winner_count"] == 0:
        return "repair_candidate_evidence", "ProofSearch has no eligible candidate; repair the exact rejected evidence."
    if facts["proofsearch_winner_count"] > 0:
        return "review_verified_repair", "ProofSearch selected one hash-bound candidate; human approval is still required before apply."
    if facts["forensic_divergence_count"] > 0:
        return "review_counterfactual_fork", "Two verified graph runs diverge; review the bounded recovery preview."
    if facts["stale_proof_count"] > 0:
        return "rerun_invalid_proof", "At least one recorded proof is stale."
    if facts["blocked_gate_count"] > 0:
        return "resolve_blocked_gate", "At least one declared proof gate is blocked."
    if facts["run_gate_count"] > 0:
        return "run_required_validation", "At least one declared proof gate requires validation."
    if facts["unevidenced_requirement_count"] > 0:
        return "collect_completion_evidence", "At least one declared requirement lacks a valid completion receipt."
    return "review_verified_graph", "All currently represented requirements have valid completion evidence."


def _snapshot_facts(nodes: list[dict[str, Any]], evidenced: set[str], stale_proof_count: int,
                    gates: Counter[str], verifier_sessions: dict[str, int],
                    forensics: dict[str, int], proofsearch: dict[str, int],
                    frontier: dict[str, int], reality: dict[str, int], authorizations: dict[str, int], assurance: dict[str, int], continuity: dict[str, int],
                    counterexamples: dict[str, int], guardrails: dict[str, int], resilience: dict[str, int], proof_deltas: dict[str, int], survival_cards: dict[str, int], agent_supervision: dict[str, int]) -> dict[str, int]:
    requirement_nodes = [node["id"] for node in nodes if node["kind"] == "requirement"]
    return {
        "node_count": len(nodes),
        "edge_count": 0,
        "stale_proof_count": stale_proof_count,
        "blocked_gate_count": gates["BLOCK"],
        "run_gate_count": gates["RUN"],
        "unevidenced_requirement_count": sum(node not in evidenced for node in requirement_nodes),
        "evidenced_requirement_count": sum(node in evidenced for node in requirement_nodes),
        "verifier_session_count": verifier_sessions["session_count"],
        "runtime_unattested_session_count": verifier_sessions["runtime_unattested_count"],
        "lineage_run_count": forensics["lineage_count"],
        "forensic_anomaly_count": forensics["anomaly_count"],
        "forensic_divergence_count": forensics["divergence_count"],
        "proofsearch_evaluation_count": proofsearch["evaluation_count"],
        "proofsearch_candidate_count": proofsearch["candidate_count"],
        "proofsearch_eligible_count": proofsearch["eligible_count"],
        "proofsearch_winner_count": proofsearch["winner_count"],
        "evidence_frontier_count": frontier["frontier_count"],
        "evidence_frontier_ready_count": frontier["ready_count"],
        "evidence_frontier_halted_count": frontier["halted_count"],
        "reality_check_count": reality["count"],
        "reality_check_verified_count": reality["verified_count"],
        "reality_check_blocked_count": reality["blocked_count"],
        "graph_authorization_count": authorizations["count"],
        "graph_authorization_approved_count": authorizations["approved_count"],
        "graph_authorization_consumed_count": authorizations["consumed_count"],
        "assurance_dossier_count": assurance["count"],
        "assurance_review_required_count": assurance["review_required_count"],
        "assurance_unresolved_high_count": assurance["unresolved_high_count"],
        "continuity_record_count": continuity["record_count"],
        "continuity_draft_count": continuity["draft_count"],
        "continuity_verified_current_count": continuity["verified_current_count"],
        "continuity_expired_count": continuity["expired_count"],
        "counterexample_plan_count": counterexamples["count"],
        "counterexample_verified_count": counterexamples["verified_count"],
        "counterexample_hollow_count": counterexamples["hollow_count"],
        "counterexample_invalid_count": counterexamples["invalid_count"],
        "guardrail_evaluation_count": guardrails["count"],
        "guardrail_active_count": guardrails["active_count"],
        "guardrail_withheld_count": guardrails["withheld_count"],
        "guardrail_invalid_count": guardrails["invalid_count"],
        "temporal_resilience_plan_count": resilience["count"],
        "temporal_resilience_verified_count": resilience["verified_count"],
        "resilience_invalid_count": resilience["invalid_count"],
        "proof_delta_count": proof_deltas["count"],
        "proof_delta_advance_count": proof_deltas["advance_count"],
        "proof_delta_halted_count": proof_deltas["halted_count"],
        "proof_delta_invalid_count": proof_deltas["invalid_count"],
        "gauntlet_card_count": survival_cards["count"],
        "gauntlet_survived_count": survival_cards["survived_count"],
        "gauntlet_hollow_count": survival_cards["hollow_count"],
        "gauntlet_blocked_count": survival_cards["blocked_count"],
        "gauntlet_invalid_count": survival_cards["invalid_count"],
        "agent_license_count": agent_supervision["license_count"],
        "agent_license_human_controlled_count": agent_supervision["human_controlled_count"],
        "agent_license_supervised_count": agent_supervision["supervised_count"],
        "agent_license_autonomous_count": agent_supervision["autonomous_count"],
        "agent_incident_count": agent_supervision["incident_count"],
        "combine_scoreboard_count": agent_supervision["combine_scoreboard_count"],
        "combine_passing_candidate_count": agent_supervision["combine_passing_candidate_count"],
        "intake_confirmation_count": sum(node["kind"] == "intake" for node in nodes),
        "intake_confirmed_count": sum(node["kind"] == "intake" and node.get("status") == "confirmed" for node in nodes),
        "intake_invalid_count": sum(node["kind"] == "intake" and node.get("status") == "invalid" for node in nodes),
    }


def _snapshot_markers(state: dict[str, Any], nodes: list[dict[str, Any]],
                      verifier_sessions: dict[str, int], forensics: dict[str, int],
                      proofsearch: dict[str, int], frontier: dict[str, int], reality: dict[str, int], authorizations: dict[str, int], assurance: dict[str, int], continuity: dict[str, int],
                      counterexamples: dict[str, int], guardrails: dict[str, int], resilience: dict[str, int], proof_deltas: dict[str, int], survival_cards: dict[str, int], agent_supervision: dict[str, int]) -> list[str]:
    markers = [
        "GRAPH_OPS_UNIFIED_READ_ONLY", "GRAPH_OPS_TYPED_LOCAL_NODES", "GRAPH_OPS_RECOMMENDATION_EXACT",
        "GRAPH_OPS_AUTHORITY_RETAINED",
    ]
    if state["slice_plan_seen"] and state["slice_links_exact"]:
        markers.append("GRAPH_OPS_SLICE_LINKS_EXACT")
    if any(node["kind"] == "mission" for node in nodes):
        markers.append("GRAPH_OPS_MISSION_EVIDENCE_LINKED")
    if any(node["kind"] == "proof" for node in nodes):
        markers.append("GRAPH_OPS_PROOF_HASH_STATUS")
    if any(node["kind"] in {"gate", "trace", "receipt"} for node in nodes):
        markers.append("GRAPH_OPS_DECLARED_GATE_STATE")
    if verifier_sessions["session_count"]:
        markers.append("GRAPH_OPS_VERIFIER_SESSIONS_READ_ONLY")
    if forensics["lineage_count"]:
        markers.append("GRAPH_OPS_SEMANTIC_LINEAGE")
    if forensics["divergence_count"]:
        markers.append("GRAPH_OPS_COUNTERFACTUAL_RECOVERY_PREVIEW")
    if proofsearch["evaluation_count"]:
        markers.extend(["GRAPH_OPS_PROOFSEARCH_ARENA", "GRAPH_OPS_VERIFIED_REPAIR_LOCKED"])
    if frontier["frontier_count"]:
        markers.append("GRAPH_OPS_EVIDENCE_FRONTIER_READ_ONLY")
    if reality["count"]:
        markers.append("GRAPH_OPS_REALITY_CHECK_SUPERVISED")
    if authorizations["count"]:
        markers.append("GRAPH_OPS_HUMAN_AUTHORIZATIONS_PROJECTED")
    if assurance["count"]:
        markers.append("GRAPH_OPS_GITHUB_ASSURANCE_PROJECTED")
    if continuity["record_count"]:
        markers.append("GRAPH_OPS_CONTINUITY_METADATA_READ_ONLY")
    if counterexamples["count"]:
        markers.append("GRAPH_OPS_COUNTEREXAMPLE_PROOFS_READ_ONLY")
    if guardrails["count"]:
        markers.append("GRAPH_OPS_GUARDRAIL_EVALUATIONS_REDACTED")
    if resilience["count"]:
        markers.append("GRAPH_OPS_TEMPORAL_RESILIENCE_READ_ONLY")
    if proof_deltas["count"]:
        markers.append("GRAPH_OPS_PROOF_DELTA_ADMISSION_READ_ONLY")
    if survival_cards["count"]:
        markers.append("GRAPH_OPS_GAUNTLET_SURVIVAL_CARDS_READ_ONLY")
    if agent_supervision["license_count"]:
        markers.append("GRAPH_OPS_AGENT_LICENSES_READ_ONLY")
    if agent_supervision["combine_scoreboard_count"]:
        markers.append("GRAPH_OPS_COMBINE_SCOREBOARDS_READ_ONLY")
    if any(node["kind"] == "intake" for node in nodes):
        markers.append("GRAPH_OPS_INTAKE_DECISIONS_READ_ONLY")
    if state["errors"] or state["truncated"]:
        markers.append("GRAPH_OPS_PARTIAL_RESULT")
    return sorted(markers)


def _append_admission_packets(state: dict[str, Any], root: Path) -> dict[str, int]:
    """Project sealed admission metadata after calculating the stable base graph."""
    facts = {"count": 0, "sealed_count": 0, "invalid_count": 0}
    directory = root / ".factory" / "admissions"
    for path in sorted(directory.glob("*.admission.json")):
        value, source = _load_json(root, path, state["errors"])
        if value is None or source is None:
            continue
        packet_id = _text(value.get("id"), path.stem) if isinstance(value, dict) else path.stem
        valid = isinstance(value, dict) and value.get("schema") == "factory.run-admission.packet.v1" and isinstance(value.get("packet_sha256"), str)
        status = "sealed" if valid and value.get("verdict") == "SEALED" else "invalid"
        _node(state, node_id=f"admission:{packet_id}", kind="admission", label=f"admission {packet_id}", source=source, status=status,
              facts={"packet_sha256": value.get("packet_sha256") if isinstance(value, dict) else None, "authority": _AUTHORITY})
        facts["count"] += 1
        facts["sealed_count"] += int(status == "sealed")
        facts["invalid_count"] += int(status == "invalid")
    return facts


def graph_ops_snapshot(root: Path) -> dict[str, Any]:
    """Compile a bounded graph snapshot from existing local files without writes."""
    workspace = Path(root).resolve()
    state: dict[str, Any] = {
        "nodes": {}, "edges": [], "edge_keys": set(), "errors": [], "truncated": False,
    }
    requirements, slices = _append_product_graphs(state, workspace)
    _append_intake_confirmations(state, workspace)
    evidenced = _append_missions(state, workspace, requirements, slices)
    stale_proof_count = _append_proofs(state, workspace)
    gates = _append_plans(state, workspace)
    _append_traces(state, workspace)
    verifier_sessions = _append_verifier_sessions(state, workspace)
    forensics = _append_graph_forensics(state, workspace)
    proofsearch = _append_proofsearch(state, workspace)
    frontier = _append_evidence_frontiers(state, workspace)
    reality = _append_reality_checks(state, workspace)
    authorizations = _append_graph_authorizations(state, workspace)
    assurance = _append_github_assurance_dossiers(state, workspace)
    continuity = _append_continuity(state, workspace)
    counterexamples = _append_counterexamples(state, workspace)
    guardrails = _append_guardrail_evaluations(state, workspace)
    resilience = _append_resilience_plans(state, workspace)
    proof_deltas = _append_proof_deltas(state, workspace)
    survival_cards = _append_survival_cards(state, workspace)
    agent_supervision = _append_agent_supervision(state, workspace)

    nodes = sorted(state["nodes"].values(), key=lambda item: item["id"])
    edges = sorted(state["edges"], key=lambda item: (item["source"], item["target"], item["relation"]))
    facts = _snapshot_facts(nodes, evidenced, stale_proof_count, gates, verifier_sessions, forensics, proofsearch, frontier, reality, authorizations, assurance, continuity, counterexamples, guardrails, resilience, proof_deltas, survival_cards, agent_supervision)
    facts["edge_count"] = len(edges)
    action, reason = _recommendation(facts)
    complete = not state["errors"] and not state["truncated"]
    markers = _snapshot_markers(state, nodes, verifier_sessions, forensics, proofsearch, frontier, reality, authorizations, assurance, continuity, counterexamples, guardrails, resilience, proof_deltas, survival_cards, agent_supervision)
    base_core = {
        "schema": GRAPH_OPS_SCHEMA,
        "marker": "GRAPH_OPS_UNIFIED_READ_ONLY",
        "markers": markers,
        "complete": complete,
        "authority": _AUTHORITY,
        "nodes": nodes,
        "edges": edges,
        "facts": facts,
        "recommendation": {"action": action, "reason": reason},
        "source_errors": sorted(state["errors"], key=lambda item: (item["source"], item["code"])),
    }
    base_graph_sha256 = _sha(base_core)
    from .graph_portfolio import graph_portfolio_plan
    portfolio = graph_portfolio_plan({**base_core, "graph_sha256": base_graph_sha256})
    admissions = _append_admission_packets(state, workspace)
    projected_nodes = sorted(state["nodes"].values(), key=lambda item: item["id"])
    projected_edges = sorted(state["edges"], key=lambda item: (item["source"], item["target"], item["relation"]))
    projected_facts = {
        **facts,
        "node_count": len(projected_nodes),
        "edge_count": len(projected_edges),
        "admission_packet_count": admissions["count"],
        "admission_packet_sealed_count": admissions["sealed_count"],
    }
    core = {
        **base_core,
        "markers": sorted([*markers, "GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY"]),
        "nodes": projected_nodes,
        "edges": projected_edges,
        "facts": projected_facts,
        "portfolio": portfolio,
        "admissions": admissions,
        "agent_supervision": agent_supervision,
    }
    return {**core, "base_graph_sha256": base_graph_sha256, "graph_sha256": _sha(core), "mermaid": _mermaid(projected_nodes, projected_edges)}


def _changed_path(value: str) -> str:
    # Remove one optional shell-style relative prefix without stripping a
    # meaningful leading dot from workspace files such as `.github/...`.
    path = str(value).replace("\\", "/").strip().removeprefix("./").rstrip("/")
    if not path or path.startswith("/") or path.startswith("../") or "/../" in path:
        raise ValueError("changed paths must be non-empty workspace-relative paths")
    return path


def graph_ops_impact(root: Path, changed_paths: list[str]) -> dict[str, Any]:
    """Return exact input-edge impact facts without running or skipping validation."""
    changed = sorted({_changed_path(value) for value in changed_paths})
    if not changed:
        raise ValueError("at least one changed path is required")
    snapshot = graph_ops_snapshot(root)
    nodes = {node["id"]: node for node in snapshot["nodes"]}
    inputs = {
        edge["source"]: edge["target"]
        for edge in snapshot["edges"]
        if edge["relation"] == "input_to" and nodes.get(edge["source"], {}).get("kind") == "artifact"
    }
    gate_for_proof: dict[str, list[str]] = {}
    for edge in snapshot["edges"]:
        if edge["relation"] == "uses_proof":
            gate_for_proof.setdefault(edge["target"], []).append(edge["source"])

    matched: dict[str, dict[str, Any]] = {}
    for artifact_id, proof_id in inputs.items():
        artifact = nodes[artifact_id]
        artifact_path = str(artifact.get("facts", {}).get("path", artifact.get("label", "")))
        path_matches = [path for path in changed if artifact_path == path or artifact_path.startswith(path + "/")]
        if not path_matches:
            continue
        proof = nodes.get(proof_id)
        if proof is None:
            continue
        entry = matched.setdefault(proof_id, {
            "proof_id": proof_id,
            "label": proof["label"],
            "status": proof.get("status", "unknown"),
            "input_artifacts": [],
            "gates": [],
        })
        entry["input_artifacts"].append({"path": artifact_path, "changed_paths": path_matches})
    for proof_id, entry in matched.items():
        entry["input_artifacts"].sort(key=lambda item: item["path"])
        entry["gates"] = sorted({
            nodes[gate_id]["label"]
            for gate_id in gate_for_proof.get(proof_id, [])
            if gate_id in nodes
        })
    matched_rows = [matched[key] for key in sorted(matched)]
    stale = [item for item in matched_rows if item["status"] == "stale"]
    verified_current = [item for item in matched_rows if item["status"] == "verified"]
    core = {
        "schema": "factory.graph-impact.v1",
        "marker": "GRAPH_OPS_IMPACT_EXACT",
        "markers": ["GRAPH_OPS_IMPACT_EXACT", "GRAPH_OPS_UNIFIED_READ_ONLY", "GRAPH_OPS_AUTHORITY_RETAINED"],
        "changed_paths": changed,
        "matched_proofs": matched_rows,
        "verified_current_proofs": verified_current,
        "rerun_proofs": stale,
        "unmatched_changed_paths": [
            path for path in changed
            if not any(path in artifact["changed_paths"] for item in matched_rows for artifact in item["input_artifacts"])
        ],
        "authority": _AUTHORITY,
        "graph_sha256": snapshot["graph_sha256"],
        "complete": snapshot["complete"],
        "source_errors": snapshot["source_errors"],
    }
    return {**core, "impact_sha256": _sha(core)}


def graph_ops_html(token: str) -> str:
    """Load the local visual template and inject only the current session token."""
    template = resources.files("factoryline").joinpath("graph_ops.html").read_text(encoding="utf-8")
    return template.replace("__FACTORY_STUDIO_TOKEN__", json.dumps(token))
