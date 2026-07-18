"""PR/PRD optimization helpers for the factory control plane."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import subprocess

from .contract import LAYOUT, ensure_layout
from .meter import summarize
from .proof import git_changed_paths, public_evidence, public_evidence_text, risk_for_paths


DEFAULT_POLICY = {
    "schema": "factory.policy.v1",
    "risk": {
        "default": "supervised",
        "require_human_approval_for": ["security", "auth", "billing", "production-deploy"],
    },
    "quality": {
        "require_hollow_tests": True,
        "require_hollow_validators": True,
        "min_goldens": 1.0,
        "max_complexity_delta": 10,
    },
    "tokens": {
        "require_meter": True,
        "max_estimated_cost_usd": 5.0,
    },
    "design": {
        "purpose_profile": "developer",
        "require_prestige_audit": True,
    },
    "release": {
        "require_clean_install": True,
        "require_license": True,
        "require_ci": True,
    },
}


def write_policy(root: Path, *, force: bool = False) -> Path:
    """Write the default optimizer policy, refusing replacement unless forced."""
    root = Path(root)
    path = root / "factory.policy.json"
    if path.exists() and not force:
        return path
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
    return path


def _git_current_branch(root: Path) -> str | None:
    proc = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _changed_paths(root: Path, base: str, explicit: list[str] | None = None) -> list[str]:
    if explicit:
        return explicit
    try:
        return git_changed_paths(root, base)
    except RuntimeError:
        proc = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def pr_pack(root: Path, feature: str, *, trace_path: Path | None = None, out: Path | None = None) -> dict:
    """Write a reviewer packet with public-safe proof and meter nuance."""
    root = Path(root)
    ensure_layout(root)
    if trace_path is None:
        trace_path = root / LAYOUT["state"] / "traces" / f"{feature}.trace.json"
    evidence = public_evidence(root, feature, trace_path=trace_path)
    meter = summarize(root)
    packet = {
        "schema": "factory.pr_pack.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "feature": feature,
        "branch": _git_current_branch(root),
        "evidence": evidence,
        "meter": meter,
        "review_contract": {
            "no_hand_copied_metrics": True,
            "deterministic_gates_before_ai_review": True,
            "auto_merge": False,
        },
    }
    if out is None:
        out = root / LAYOUT["state"] / "pr-packs" / f"{feature}.PR_EVIDENCE.md"
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# PR Evidence: {feature}",
        "",
        public_evidence_text(evidence),
        "",
        "## Review Contract",
        "",
        "- Metrics come from receipts, traces, or command output.",
        "- Deterministic gates run before AI review loops.",
        "- Auto-merge is intentionally out of scope.",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    packet["packet_path"] = str(out)
    return packet


def optimize_pr(root: Path, *, base: str = "main", changed: list[str] | None = None, feature: str | None = None) -> dict:
    """Create a bounded PR hardening plan from the current diff."""
    root = Path(root)
    paths = _changed_paths(root, base, changed)
    risk = risk_for_paths(paths)
    needs_design = any(path.endswith((".html", ".css", ".tsx", ".jsx", ".vue", ".svelte")) for path in paths)
    needs_release = any(Path(path).name in {"pyproject.toml", "package.json", "uv.lock", "requirements.txt"} for path in paths)
    stages = [f"{item['module']}:{item['stage']}" for item in risk["rerun_stages"]]
    if needs_design and "prestige:audit" not in stages:
        stages.append("prestige:audit")
    if needs_release and "factoryline:release-readiness" not in stages:
        stages.append("factoryline:release-readiness")
    return {
        "schema": "factory.optimize_pr.v1",
        "feature": feature,
        "base": base,
        "changed_paths": paths,
        "risk": risk,
        "recommended_stages": stages,
        "loop": {
            "max_iterations": 5,
            "terminal_states": ["ready", "blocked", "approval_required", "stagnated"],
            "authority": "may edit local PR branch; must not merge, publish, deploy, or message externally without approval",
        },
        "next_commands": [
            "factory risk-diff --changed <path>",
            "factory replay <trace> --changed <path>",
            "factory pr-pack <feature>",
        ],
    }
