"""Prepare a source-bound release contract inside a protected CI run.

The release contract cannot be committed alongside the candidate because its
candidate commit is the commit that contains the contract itself.  This helper
therefore creates the contract after checkout, while the protected provider
environment is active.  It still seals the original release intent, Oracle
rules, source commit, and platform versions before any upload step.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    # Allow the helper to run directly from a source checkout as well as from
    # the installed preflight package used by protected CI.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.release_candidate import source_snapshot
from factoryline.release_contract import _sha


CORE_STAGES = [
    "specline:strict",
    "specline:verify-validators",
    "specline:gate-spec",
    "specline:tasks",
    "specline:gate-plan",
    "forgeline:architect",
    "forgeline:review",
    "forgeline:arch-gate",
    "forgeline:verify-tests",
    "forgeline:smoke",
    "forgeline:ship",
]


def _rule(identifier: str, statement: str, *, group: str, path: str | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "id": identifier,
        "statement": statement,
        "origin": "human_confirmed",
        "effect": "blocking",
        "source_id": "original-intent",
        "critical": True,
    }
    if group == "gates":
        value.update({"comparison": "present", "value": True})
    if group == "tests":
        value["path"] = path or "tests/"
    return value


def prepare(root: Path, *, feature: str, source_path: Path, out: Path, approved_by: str) -> dict[str, object]:
    workspace = root.resolve()
    source = (source_path if source_path.is_absolute() else workspace / source_path).resolve()
    destination = (out if out.is_absolute() else workspace / out).resolve()
    try:
        source.relative_to(workspace)
        destination.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("release contract paths must remain inside the workspace") from exc
    if not source.is_file():
        raise ValueError(f"release intent source is unavailable: {source}")
    if destination.exists():
        raise ValueError(f"release contract output already exists: {destination}")

    runtime = workspace / ".factory" / "release-runtime" / feature
    runtime.mkdir(parents=True, exist_ok=False)
    agent = {
        "schema": "factory.agent-identity.v1",
        "subject": "release-workflow",
        "provider": "github-actions",
        "model": "protected-review",
    }
    handoff = capture_intent_handoff(workspace, source, agent, f"{feature}-handoff", runtime / "handoff.json")
    oracle_input = {
        "schema": "factory.oracle-contract-input.v1",
        "id": feature,
        "version": 1,
        "approved_by": approved_by,
        "approval_rationale": "Protected environment approval authorizes this source-bound release candidate after all gates pass.",
        "scope_paths": ["."],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [_rule("candidate-integrity", "The candidate source and declared platform versions remain immutable.", group="requirements")],
        "forbidden_behaviors": [_rule("gate-bypass", "No external upload may occur before the sealed preflight passes.", group="forbidden_behaviors")],
        "gates": [_rule("release-preflight", "The source, metadata, and packaged artifacts must pass the release preflight.", group="gates")],
        "exceptions": [_rule("no-implicit-exception", "No unreviewed exception is permitted for this release.", group="exceptions")],
        "negative_cases": [_rule("stale-artifact", "A stale or mismatched artifact must fail closed.", group="negative_cases")],
        "invariants": [_rule("intent-chain", "The release decision remains traceable to the captured intent.", group="invariants")],
        "tests": [_rule("release-tests", "The release test suite and package checks must pass.", group="tests", path="tests/")],
    }
    oracle_input_path = runtime / "oracle-contract-input.json"
    oracle_input_path.write_text(json.dumps(oracle_input, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    oracle_path = workspace / ".factory" / "oracles" / "contracts" / f"{feature}.json"
    oracle = seal_oracle_contract(workspace, oracle_input_path, oracle_path)
    source_info = source_snapshot(workspace)
    if not source_info.get("ok"):
        raise ValueError(str(source_info.get("reason", "source snapshot failed")))
    core: dict[str, object] = {
        "schema": "factory.release-contract.v1",
        "feature": feature,
        "oracle_contract": oracle["path"],
        "oracle_contract_sha256": oracle["contract_sha256"],
        "required_stages": CORE_STAGES,
        "approved_by": approved_by,
        "candidate": {
            "source_version": source_info["version"],
            "source_commit": source_info["commit"],
            "artifact_versions": source_info.get("platform_versions", {"python": source_info["version"]}),
        },
    }
    payload = {**core, "policy_digest": _sha(core)}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "schema": "factory.release-contract-prepared.v1",
        "marker": "RELEASE_CONTRACT_PREPARED",
        "path": destination.relative_to(workspace).as_posix(),
        "feature": feature,
        "source_commit": source_info["commit"],
        "oracle_contract_sha256": oracle["contract_sha256"],
        "policy_digest": payload["policy_digest"],
        "approved_by": approved_by,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--feature", required=True)
    parser.add_argument("--source", type=Path, default=Path("docs/RELEASE_NOTES_0.46.3.md"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--approved-by", required=True)
    args = parser.parse_args()
    result = prepare(args.root, feature=args.feature, source_path=args.source, out=args.out, approved_by=args.approved_by)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
