"""Portable strict release-decision smoke for the pinned companion train.

The script is intentionally runnable with the built wheel from a directory
outside the checkout.  It proves incomplete evidence is rejected, a complete
Oracle-bound and receipt-bound pipeline is accepted, and a stale receipt binding
is rejected.  It makes no provider or publication claim.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

source_root = Path(__file__).resolve().parents[1]
if (source_root / "factoryline" / "release_contract.py").is_file():
    # Source-tree convenience only.  The clean-wheel CI invocation copies this
    # script outside the checkout, so this branch cannot mask a missing wheel
    # module.
    import sys
    sys.path.insert(0, str(source_root))

from factoryline.contract import Receipt
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.release_contract import _sha
from factoryline.verification import verify_feature


SPEC = ("strict", "verify-validators", "gate-spec", "tasks", "gate-plan")
FORGE = ("architect", "review", "arch-gate", "verify-tests", "smoke")


STAGES = [*(f"specline:{stage}" for stage in SPEC), *(f"forgeline:{stage}" for stage in (*FORGE, "ship"))]


def write_complete(root: Path, binding: dict[str, str]) -> None:
    for stage in SPEC:
        Receipt("specline", stage, "release-train", True, inputs=dict(binding)).write(root)
    for stage in FORGE:
        Receipt("forgeline", stage, "release-train", True, inputs=dict(binding)).write(root)
    Receipt("forgeline", "ship", "release-train", True,
            inputs=dict(binding),
            outputs={"intent_trace": {"intent_traceable": True, "shipped": True}}).write(root)


def write_release_contract(root: Path) -> dict[str, str]:
    brief = root / "brief.md"
    brief.write_text("Preserve intent traceability for the release train.", encoding="utf-8")
    agent = {"schema": "factory.agent-identity.v1", "subject": "release-owner", "provider": "local", "model": "reviewer"}
    handoff = capture_intent_handoff(root, brief, agent, "release-train")
    rule = lambda identifier, statement, **extra: {"id": identifier, "statement": statement, "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, **extra}
    oracle_input = {
        "schema": "factory.oracle-contract-input.v1", "id": "release-train", "version": 1,
        "approved_by": "Release Owner", "approval_rationale": "A human reviewed the release boundary.",
        "scope_paths": ["."], "handoff": handoff["path"], "sources": [],
        "requirements": [rule("intent", "Preserve the approved intent.")],
        "forbidden_behaviors": [rule("weaken", "Do not weaken a required gate.")],
        "gates": [rule("proof", "A proof receipt is required.", comparison="present", value=True)],
        "exceptions": [{"id": "note", "statement": "Advisory note.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False}],
        "negative_cases": [rule("negative", "A missing receipt cannot pass.")],
        "invariants": [rule("bound", "Evidence stays bound to this feature.")],
        "tests": [rule("test", "The required proof test must run.", path="tests/test_release.py")],
    }
    source = root / "oracle-input.json"
    source.write_text(json.dumps(oracle_input), encoding="utf-8")
    oracle_path = Path(seal_oracle_contract(root, source, Path(".factory/oracles/contracts/release-train.json"))["path"])
    oracle = json.loads((root / oracle_path).read_text(encoding="utf-8"))
    core = {"schema": "factory.release-contract.v1", "feature": "release-train", "oracle_contract": oracle_path.as_posix(), "oracle_contract_sha256": oracle["contract_sha256"], "required_stages": STAGES, "approved_by": "Release Owner"}
    release = {**core, "policy_digest": _sha(core)}
    destination = root / ".factory/release-contracts/release-train.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(release), encoding="utf-8")
    return {"oracle_contract_sha256": oracle["contract_sha256"], "release_contract_policy_digest": release["policy_digest"]}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="factory-release-train-") as temporary:
        root = Path(temporary)
        Receipt("specline", "strict", "incomplete", True).write(root)
        incomplete = verify_feature(root, "incomplete")
        if incomplete["shippable"]:
            raise RuntimeError("incomplete evidence incorrectly became locally shippable")
        binding = write_release_contract(root)
        write_complete(root, binding)
        complete = verify_feature(root, "release-train", strict_release=True)
        if not complete["release_ready"]:
            raise RuntimeError(f"complete evidence was rejected: {complete['blockers']}")
        receipts = sorted((root / "receipts").glob("*.json"))
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        payload["inputs"]["oracle_contract_sha256"] = "0" * 64
        receipts[0].write_text(json.dumps(payload), encoding="utf-8")
        stale = verify_feature(root, "release-train", strict_release=True)
        if stale["release_ready"] or not any(item["code"] == "RECEIPT_ORACLE_BINDING_MISMATCH" for item in stale["blockers"]):
            raise RuntimeError("stale receipt binding incorrectly remained release-ready")
    print("release-train-e2e: incomplete rejected; strict bound pipeline accepted; stale receipt rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
