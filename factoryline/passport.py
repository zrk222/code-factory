"""Factory Passport: portable proof-by-sabotage evidence and Mermaid graph."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from .proof import load_trace, verify_trace
from .protocol import CHALLENGE_SCHEMA, PASSPORT_SCHEMA


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _safe_label(value: object) -> str:
    return str(value).replace('"', "'").replace("\n", " ")


def mermaid_for(passport: dict) -> str:
    lines = [
        "flowchart LR",
        '    A["Intent / PRD"] --> B["Real build + gates"]',
        '    A --> C["Counterfactual challenges"]',
    ]
    challenge_nodes = []
    for index, challenge in enumerate(passport.get("challenges", []), 1):
        node = f"C{index}"
        challenge_nodes.append(node)
        label = _safe_label(
            f"{challenge['brick']}: {challenge['mutants_killed']}/{challenge['mutants_total']} rejected"
        )
        lines.append(f'    C --> {node}["{label}"]')
    if challenge_nodes:
        for node in challenge_nodes:
            lines.append(f'    {node} --> P["Factory Passport"]')
    else:
        lines.append('    C --> P["Factory Passport"]')
    lines.extend([
        '    B --> P',
        '    P --> G["GitHub PR summary + badge + attestations"]',
    ])
    return "\n".join(lines) + "\n"


def _badge(passport: dict) -> str:
    killed = sum(item["mutants_killed"] for item in passport["challenges"])
    total = sum(item["mutants_total"] for item in passport["challenges"])
    status = "verified" if passport["verified"] else "blocked"
    color = "#2ea44f" if passport["verified"] else "#b42318"
    label = f"factory passport | {status} | {killed}/{total} sabotages rejected"
    width = max(420, len(label) * 7 + 24)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="32" role="img" aria-label="{label}">
<rect width="{width}" height="32" fill="#20242c"/><rect x="145" width="{width - 145}" height="32" fill="{color}"/>
<text x="12" y="21" fill="white" font-family="Verdana,sans-serif" font-size="12">factory passport</text>
<text x="157" y="21" fill="white" font-family="Verdana,sans-serif" font-size="12">{status} | {killed}/{total} sabotages rejected</text>
</svg>\n'''


def build_passport(root: Path, feature: str, trace_path: Path, challenge_paths: list[Path]) -> dict:
    root = Path(root)
    trace_path = Path(trace_path)
    verification = verify_trace(trace_path, root=root)
    if not verification["valid"]:
        raise ValueError("trace verification failed: " + "; ".join(verification["errors"]))
    challenges = []
    for path in challenge_paths:
        path = Path(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != CHALLENGE_SCHEMA:
            raise ValueError(f"unsupported challenge schema in {path}")
        if payload.get("feature") not in {None, feature}:
            raise ValueError(f"challenge feature mismatch in {path}")
        total = int(payload.get("mutants_total", 0))
        killed = int(payload.get("mutants_killed", 0))
        passed = bool(payload.get("passed")) and total > 0 and killed == total
        challenges.append({
            "brick": payload["brick"],
            "stage": payload.get("stage", "challenge"),
            "passed": passed,
            "mutants_total": total,
            "mutants_killed": killed,
            "receipt_path": str(path.resolve()),
            "receipt_sha256": _sha256(path),
        })
    if not challenges:
        raise ValueError("at least one counterfactual challenge receipt is required")
    challenge_keys = [(item["brick"], item["stage"]) for item in challenges]
    if len(set(challenge_keys)) != len(challenge_keys):
        raise ValueError("duplicate challenge brick/stage receipts are not allowed")
    trace = load_trace(trace_path)
    verified = all(item["passed"] for item in challenges)
    core = {
        "schema": PASSPORT_SCHEMA,
        "feature": feature,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trace_path": str(trace_path.resolve()),
        "trace_sha256": trace["trace_sha256"],
        "trace_nodes": len(trace["nodes"]),
        "challenges": challenges,
        "verified": verified,
        "scope": "proofs observed gates and counterfactual rejection; it does not replace human release authority",
    }
    passport = {**core, "passport_sha256": hashlib.sha256(_canonical(core)).hexdigest()}
    out_dir = root / ".factory" / "passports"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{feature}.passport.json"
    mmd_path = out_dir / f"{feature}.passport.mmd"
    svg_path = out_dir / f"{feature}.passport.svg"
    json_path.write_text(json.dumps(passport, indent=2, sort_keys=True), encoding="utf-8")
    mmd_path.write_text(mermaid_for(passport), encoding="utf-8")
    svg_path.write_text(_badge(passport), encoding="utf-8")
    return {**passport, "paths": {"json": str(json_path), "mermaid": str(mmd_path), "badge": str(svg_path)}}


def verify_passport(path: Path) -> dict:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    if payload.get("schema") != PASSPORT_SCHEMA:
        errors.append("unsupported passport schema")
    core = {key: value for key, value in payload.items() if key not in {"passport_sha256", "paths"}}
    if hashlib.sha256(_canonical(core)).hexdigest() != payload.get("passport_sha256"):
        errors.append("passport hash mismatch")
    for item in payload.get("challenges", []):
        receipt = Path(item["receipt_path"])
        if not receipt.exists():
            errors.append(f"missing challenge receipt: {receipt}")
        elif _sha256(receipt) != item.get("receipt_sha256"):
            errors.append(f"challenge receipt hash mismatch: {receipt}")
    trace_path = Path(payload.get("trace_path", ""))
    if not trace_path.exists():
        errors.append(f"missing trace: {trace_path}")
    else:
        trace_result = verify_trace(trace_path)
        errors.extend(trace_result["errors"])
        if load_trace(trace_path).get("trace_sha256") != payload.get("trace_sha256"):
            errors.append("passport trace hash mismatch")
    if not payload.get("challenges"):
        errors.append("passport contains no challenge receipts")
    if not payload.get("verified"):
        errors.append("passport verdict is blocked")
    return {"valid": not errors, "errors": errors, "feature": payload.get("feature"), "passport_sha256": payload.get("passport_sha256")}
