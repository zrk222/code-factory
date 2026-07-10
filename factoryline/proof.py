"""Proof-carrying PR evidence for Factoryline.

The proof layer turns existing receipts into a hash-linked trace. It does not
invent a new verdict: it makes the verdict replayable, tamper-evident, and easy
to summarize for humans.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
from typing import Iterable

from .assembly import DEFAULT_CHAIN, _stage_order, rollup_attributions
from .boundary import assert_build_metadata_locations
from .contract import LAYOUT, MODULES, Receipt, ensure_layout
from .meter import summarize

TRACE_SCHEMA = "factoryline.proof_trace.v1"


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def _coerce_paths(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_coerce_paths(item))
        return out
    return []


def _declared_paths(container: object) -> list[str]:
    if not isinstance(container, dict):
        return []
    out: list[str] = []
    for key, value in container.items():
        if "path" in key or key in {"file", "files", "artifact", "artifacts"}:
            out.extend(_coerce_paths(value))
        elif isinstance(value, dict):
            out.extend(_declared_paths(value))
    return out


def _artifact_hashes(root: Path, receipt: Receipt) -> list[dict]:
    artifacts: list[dict] = []
    for kind, container in (("input", receipt.inputs), ("output", receipt.outputs)):
        for raw in _declared_paths(container):
            path = Path(raw)
            if not path.is_absolute():
                path = root / path
            if path.is_file():
                artifacts.append({
                    "kind": kind,
                    "path": _rel(path, root),
                    "sha256": _sha256_file(path),
                })
    return sorted(artifacts, key=lambda item: (item["kind"], item["path"]))


def _load_latest_receipts(root: Path, feature: str) -> list[dict]:
    receipt_dir = root / LAYOUT["receipts"]
    latest: dict[tuple[str, str], tuple[float, Path, Receipt, dict]] = {}
    for path in receipt_dir.glob(f"*-{feature}-*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            receipt = Receipt.from_dict(payload)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
        key = (receipt.module, receipt.stage)
        current = latest.get(key)
        if current is None or path.stat().st_mtime >= current[0]:
            latest[key] = (path.stat().st_mtime, path, receipt, payload)

    rows = []
    for _, path, receipt, payload in latest.values():
        rows.append({
            "path": path,
            "receipt": receipt,
            "payload": payload,
            "order": _stage_order(receipt.module, receipt.stage)[0],
        })
    return sorted(rows, key=lambda row: (row["order"], row["receipt"].module, row["receipt"].stage))


def _stage_command(feature: str, module: str, stage: str) -> str | None:
    normalized = stage.replace("_", "-")
    for chain_module, args in DEFAULT_CHAIN:
        if chain_module == module and args[0].replace("_", "-") == normalized:
            cli = MODULES[module]["cli"]
            rendered = [part.replace("{f}", feature) for part in args]
            return f"{cli} {' '.join(rendered)}"
    return None


def build_trace(root: Path, feature: str, *, out: Path | None = None) -> dict:
    """Build and persist a tamper-evident trace from latest feature receipts."""
    root = Path(root)
    ensure_layout(root)
    rows = _load_latest_receipts(root, feature)
    stages_for_rollup = []
    nodes = []
    previous_hash = "0" * 64

    for row in rows:
        receipt = row["receipt"]
        path = row["path"]
        artifacts = _artifact_hashes(root, receipt)
        receipt_hash = _sha256_file(path)
        node_core = {
            "module": receipt.module,
            "stage": receipt.stage,
            "ok": receipt.ok,
            "receipt_path": _rel(path, root),
            "receipt_sha256": receipt_hash,
            "artifacts": artifacts,
            "previous_hash": previous_hash,
        }
        node_hash = _sha256_bytes(_canonical(node_core))
        previous_hash = node_hash
        nodes.append({
            **node_core,
            "order": row["order"],
            "ts": receipt.ts,
            "meter": asdict(receipt.meter),
            "attribution": receipt.attribution,
            "command": _stage_command(feature, receipt.module, receipt.stage),
            "node_sha256": node_hash,
        })
        stages_for_rollup.append({
            "module": receipt.module,
            "stage": receipt.stage,
            "status": "ok" if receipt.ok else "failed",
            "attribution": receipt.attribution,
        })

    rollup = rollup_attributions(stages_for_rollup)
    trace_core = {
        "schema": TRACE_SCHEMA,
        "feature": feature,
        "root": str(root.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain_head": previous_hash,
        "nodes": nodes,
        "rollup": rollup,
        "meter": summarize(root),
        "guarantees": {
            "hash_linked_receipts": True,
            "stage_order": "canonical DEFAULT_CHAIN order",
            "h0_boundary": "build metadata must stay out of registry artifacts",
        },
    }
    trace_hash = _sha256_bytes(_canonical(trace_core))
    trace = {**trace_core, "trace_sha256": trace_hash}

    if out is None:
        out = root / LAYOUT["state"] / "traces" / f"{feature}.trace.json"
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(trace, indent=2, sort_keys=True), encoding="utf-8")
    trace["trace_path"] = _rel(out, root)
    return trace


def load_trace(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_trace(trace_path: Path, *, root: Path | None = None) -> dict:
    """Verify trace hash chain, receipt hashes, artifact hashes, and H=0 boundary."""
    trace_path = Path(trace_path)
    trace = load_trace(trace_path)
    trace_root = Path(root or trace.get("root") or trace_path.parent)
    errors: list[str] = []
    previous_hash = "0" * 64
    previous_order = -1

    for node in trace.get("nodes", []):
        canonical_order = _stage_order(node["module"], node["stage"])[0]
        if node.get("order") != canonical_order:
            errors.append(f"stage order mismatch: {node['module']}:{node['stage']}")
        if canonical_order < previous_order:
            errors.append(f"stage order regression: {node['module']}:{node['stage']}")
        previous_order = canonical_order

        receipt_path = Path(node["receipt_path"])
        if not receipt_path.is_absolute():
            receipt_path = trace_root / receipt_path
        if not receipt_path.exists():
            errors.append(f"missing receipt: {node['receipt_path']}")
            continue
        receipt_hash = _sha256_file(receipt_path)
        if receipt_hash != node.get("receipt_sha256"):
            errors.append(f"receipt hash mismatch: {node['receipt_path']}")

        for artifact in node.get("artifacts", []):
            artifact_path = Path(artifact["path"])
            if not artifact_path.is_absolute():
                artifact_path = trace_root / artifact_path
            if not artifact_path.exists():
                errors.append(f"missing artifact: {artifact['path']}")
                continue
            if _sha256_file(artifact_path) != artifact.get("sha256"):
                errors.append(f"artifact hash mismatch: {artifact['path']}")

        node_core = {
            "module": node["module"],
            "stage": node["stage"],
            "ok": node["ok"],
            "receipt_path": node["receipt_path"],
            "receipt_sha256": node["receipt_sha256"],
            "artifacts": node.get("artifacts", []),
            "previous_hash": previous_hash,
        }
        node_hash = _sha256_bytes(_canonical(node_core))
        if node_hash != node.get("node_sha256"):
            errors.append(f"node hash mismatch: {node['module']}:{node['stage']}")
        previous_hash = node_hash

    if previous_hash != trace.get("chain_head"):
        errors.append("chain head mismatch")

    trace_core = {key: value for key, value in trace.items()
                  if key not in {"trace_sha256", "trace_path"}}
    if _sha256_bytes(_canonical(trace_core)) != trace.get("trace_sha256"):
        errors.append("trace hash mismatch")

    try:
        assert_build_metadata_locations(trace_root)
    except ValueError as exc:
        errors.append(f"H=0 boundary violation: {exc}")

    return {
        "trace": str(trace_path),
        "feature": trace.get("feature"),
        "valid": not errors,
        "errors": errors,
        "chain_head": trace.get("chain_head"),
        "trace_sha256": trace.get("trace_sha256"),
        "nodes_verified": len(trace.get("nodes", [])) if not errors else None,
    }


def risk_for_paths(paths: Iterable[str]) -> dict:
    """Map changed paths to invalidated factory guarantees and rerun stages."""
    stage_reasons: dict[tuple[str, str], set[str]] = {}
    path_entries = []
    for raw in paths:
        path = raw.replace("\\", "/").lstrip("./")
        stages: list[tuple[str, str, str]] = []
        if path.startswith(("specs/", "plans/", "handoff/")):
            stages.extend([
                ("specline", "strict", "spec contract changed"),
                ("specline", "gate", "sealed spec evidence changed"),
                ("forgeline", "architect", "architecture may need regeneration"),
                ("forgeline", "review", "architecture review may be stale"),
                ("forgeline", "arch-gate", "architecture gate may be stale"),
                ("forgeline", "verify-tests", "test instrument must match new spec"),
                ("forgeline", "smoke", "runtime evidence may be stale"),
            ])
        elif path.endswith(".ssat.yaml") or "ssat" in path:
            stages.extend([
                ("forgeline", "architect", "SSAT scaffold changed"),
                ("forgeline", "review", "SSAT review may be stale"),
                ("forgeline", "arch-gate", "SSAT gate may be stale"),
                ("forgeline", "verify-tests", "stub identity and hollow-test proof changed"),
                ("forgeline", "smoke", "runtime evidence may be stale"),
            ])
        elif path.startswith("smoke/"):
            stages.extend([
                ("forgeline", "verify-tests", "smoke instrument changed"),
                ("forgeline", "smoke", "runtime smoke evidence changed"),
            ])
        elif path.startswith("slices/"):
            stages.extend([
                ("forgeline", "smoke", "implementation behavior changed"),
                ("forgeline", "ship", "shipping receipt must reflect new implementation"),
            ])
        elif path.startswith(("registry/", "registry_store/")):
            stages.extend([
                ("hsf", "compile", "compiled artifact changed"),
            ])
        elif path.endswith((".md", ".rst", ".txt")):
            stages.extend([
                ("factoryline", "evidence", "public evidence/docs changed"),
            ])
        else:
            stages.extend([
                ("specline", "strict", "unknown change; safest minimal entry is input contract"),
                ("forgeline", "smoke", "unknown change may affect behavior"),
            ])

        for module, stage, reason in stages:
            stage_reasons.setdefault((module, stage), set()).add(reason)
        path_entries.append({
            "path": path,
            "invalidates": [
                {"module": module, "stage": stage, "reason": reason}
                for module, stage, reason in stages
            ],
        })

    ordered = [
        {
            "module": module,
            "stage": stage,
            "reasons": sorted(reasons),
        }
        for (module, stage), reasons in sorted(stage_reasons.items(), key=lambda item: _stage_order(*item[0]))
    ]
    return {"paths": path_entries, "rerun_stages": ordered}


def replay_plan(trace: dict, changed_paths: Iterable[str]) -> dict:
    """Plan the minimal canonical-stage replay implied by changed paths."""
    risk = risk_for_paths(changed_paths)
    feature = trace["feature"]
    commands = []
    for item in risk["rerun_stages"]:
        command = _stage_command(feature, item["module"], item["stage"])
        commands.append({**item, "command": command})
    return {
        "feature": feature,
        "trace_sha256": trace.get("trace_sha256"),
        "changed_paths": list(changed_paths),
        "commands": commands,
        "note": "Plan only; run these commands after `factory verify-trace` succeeds.",
    }


def execute_replay(plan: dict, *, root: Path) -> dict:
    """Execute a replay plan after the caller has verified the trace."""
    results = []
    for item in plan.get("commands", []):
        command = item.get("command")
        if not command:
            results.append({**item, "status": "skipped", "reason": "no executable command"})
            continue
        proc = subprocess.run(
            command.split(),
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
        )
        results.append({
            **item,
            "status": "ok" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "log_tail": (proc.stdout + proc.stderr)[-1200:],
        })
        if proc.returncode != 0:
            break
    return {
        "feature": plan["feature"],
        "trace_sha256": plan.get("trace_sha256"),
        "executed": True,
        "results": results,
        "ok": all(item.get("status") in {"ok", "skipped"} for item in results),
    }


def export_attestations(trace: dict, *, out_dir: Path) -> dict:
    """Export unsigned in-toto/SLSA-shaped statements for a proof trace."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    subjects = [
        {
            "name": artifact["path"],
            "digest": {"sha256": artifact["sha256"]},
        }
        for node in trace.get("nodes", [])
        for artifact in node.get("artifacts", [])
    ]
    if not subjects:
        subjects = [{
            "name": f"{trace['feature']}.trace.json",
            "digest": {"sha256": trace["trace_sha256"]},
        }]

    in_toto = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://code-factory.dev/proof-carrying-pr/v1",
        "predicate": {
            "feature": trace["feature"],
            "trace_sha256": trace["trace_sha256"],
            "chain_head": trace["chain_head"],
            "earliest_failing_stage": trace.get("rollup", {}).get("earliest_failing_stage"),
            "stage_count": len(trace.get("nodes", [])),
            "verified_by": "factory verify-trace",
        },
    }
    slsa = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://code-factory.dev/buildtypes/proof-carrying-pr/v1",
                "externalParameters": {
                    "feature": trace["feature"],
                    "factory_trace_sha256": trace["trace_sha256"],
                },
                "internalParameters": {
                    "stage_order": trace.get("guarantees", {}).get("stage_order"),
                },
            },
            "runDetails": {
                "builder": {"id": "pkg:github/zrk222/code-factory"},
                "metadata": {
                    "invocationId": trace["chain_head"],
                    "startedOn": trace.get("generated_at"),
                    "finishedOn": trace.get("generated_at"),
                },
            },
        },
    }

    outputs = {
        "in_toto": out_dir / f"{trace['feature']}.intoto.statement.json",
        "slsa": out_dir / f"{trace['feature']}.slsa.provenance.json",
    }
    outputs["in_toto"].write_text(json.dumps(in_toto, indent=2, sort_keys=True), encoding="utf-8")
    outputs["slsa"].write_text(json.dumps(slsa, indent=2, sort_keys=True), encoding="utf-8")
    return {key: str(path) for key, path in outputs.items()}


def git_changed_paths(root: Path, base: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip())
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def public_evidence(root: Path, feature: str, *, trace_path: Path | None = None) -> dict:
    """Create a public-safe proof summary from a trace."""
    root = Path(root)
    if trace_path is None:
        trace_path = root / LAYOUT["state"] / "traces" / f"{feature}.trace.json"
    trace = load_trace(trace_path)
    verification = verify_trace(trace_path, root=root)
    stages = []
    for node in trace.get("nodes", []):
        attr = node.get("attribution") or {}
        stages.append({
            "stage": f"{node['module']}:{node['stage']}",
            "ok": node["ok"],
            "receipt_sha256": node["receipt_sha256"],
            "rate": attr.get("rate"),
            "dominant_failure_class": attr.get("dominant_failure_class"),
        })
    return {
        "feature": feature,
        "trace_sha256": trace.get("trace_sha256"),
        "chain_head": trace.get("chain_head"),
        "verified": verification["valid"],
        "verification_errors": verification["errors"],
        "earliest_failing_stage": trace.get("rollup", {}).get("earliest_failing_stage"),
        "recommended_edit_class": trace.get("rollup", {}).get("recommended_edit_class"),
        "stages": stages,
        "meter": trace.get("meter"),
        "scope_limits": [
            "Public evidence omits raw logs and private receipt payloads.",
            "Token savings are measured only when modules report token counts; otherwise they remain labeled as a model.",
        ],
    }


def public_evidence_text(evidence: dict) -> str:
    status = "verified" if evidence["verified"] else "not verified"
    lines = [
        "PROOF-CARRYING PR EVIDENCE",
        "-" * 52,
        f"feature              : {evidence['feature']}",
        f"trace_sha256         : {evidence['trace_sha256']}",
        f"chain_head           : {evidence['chain_head']}",
        f"verification         : {status}",
        f"earliest failure     : {evidence.get('earliest_failing_stage') or 'none'}",
        f"recommended edit     : {evidence.get('recommended_edit_class') or 'none'}",
        "",
        "STAGES",
        "-" * 52,
    ]
    for stage in evidence["stages"]:
        verdict = "ok" if stage["ok"] else "failed"
        failure = stage.get("dominant_failure_class") or "-"
        rate = "-" if stage.get("rate") is None else stage["rate"]
        lines.append(f"{stage['stage']:<28} {verdict:<7} rate={rate} class={failure}")
    meter = evidence.get("meter") or {}
    if meter:
        lines.extend([
            "",
            "COST / TOKEN MODEL",
            "-" * 52,
            f"stages measured      : {meter.get('stages_measured')}",
            f"build wall ms        : {meter.get('build_wall_ms')}",
            f"tokens saved         : {meter.get('tokens_saved')}",
            f"percent saved        : {meter.get('pct_tokens_saved')}%",
        ])
    if evidence["verification_errors"]:
        lines.extend(["", "VERIFICATION ERRORS", "-" * 52])
        lines.extend(f"- {error}" for error in evidence["verification_errors"])
    lines.extend(["", "SCOPE LIMITS", "-" * 52])
    lines.extend(f"- {limit}" for limit in evidence["scope_limits"])
    return "\n".join(lines)
