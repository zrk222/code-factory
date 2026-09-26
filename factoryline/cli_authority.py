"""CLI boundary for sealed intent, oracle, and semantic authority controls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register authority and proof-continuity command families."""
    oracle = sub.add_parser(
        "oracle",
        help="seal and independently challenge the definition of done before a coding run",
    )
    oracle_sub = oracle.add_subparsers(required=True, dest="oracle_cmd")
    oracle_init = oracle_sub.add_parser(
        "init",
        help="create a full, intentionally incomplete source-bound Oracle Firewall workspace",
    )
    oracle_init.add_argument("--root", default=".")
    oracle_init.add_argument("--out-dir", required=True)
    oracle_init.add_argument("--source", required=True)
    oracle_init.add_argument("--agent", required=True, help="agent identity JSON file")
    oracle_init.add_argument("--id", required=True)
    oracle_init.add_argument(
        "--scope",
        action="append",
        required=True,
        help="workspace-relative scope path; repeat as needed",
    )
    oracle_init.add_argument(
        "--appforge",
        action="store_true",
        help="also add the AppForge policy-and-candidate authority template",
    )
    oracle_init.add_argument("--json", action="store_true")
    oracle_handoff = oracle_sub.add_parser(
        "handoff",
        help="capture exact original user intent bytes from a declared handing-off agent",
    )
    oracle_handoff.add_argument("--root", default=".")
    oracle_handoff.add_argument("--source", required=True)
    oracle_handoff.add_argument(
        "--agent", required=True, help="agent identity JSON file"
    )
    oracle_handoff.add_argument("--id", required=True)
    oracle_handoff.add_argument("--out")
    oracle_handoff.add_argument("--json", action="store_true")
    oracle_seal = oracle_sub.add_parser(
        "seal", help="seal a provenance-bound Oracle Contract from approved local input"
    )
    oracle_seal.add_argument("--root", default=".")
    oracle_seal.add_argument("--input", required=True)
    oracle_seal.add_argument("--out", required=True)
    oracle_seal.add_argument("--json", action="store_true")
    oracle_verify = oracle_sub.add_parser(
        "verify", help="verify a sealed Oracle Contract and its bound sources"
    )
    oracle_verify.add_argument("contract")
    oracle_verify.add_argument("--root", default=".")
    oracle_verify.add_argument("--json", action="store_true")
    oracle_diff = oracle_sub.add_parser(
        "diff", help="fail closed when a successor weakens the prior oracle"
    )
    oracle_diff.add_argument("--root", default=".")
    oracle_diff.add_argument("--prior", required=True)
    oracle_diff.add_argument("--candidate", required=True)
    oracle_diff.add_argument("--out")
    oracle_diff.add_argument("--json", action="store_true")
    oracle_challenge = oracle_sub.add_parser(
        "challenge",
        help="compile or verify an independent implementation-targeted challenge lane",
    )
    oracle_challenge_sub = oracle_challenge.add_subparsers(
        required=True, dest="oracle_challenge_cmd"
    )
    oracle_challenge_compile = oracle_challenge_sub.add_parser(
        "compile",
        help="compile independent counterfactual cases from a sealed contract",
    )
    oracle_challenge_compile.add_argument("--root", default=".")
    oracle_challenge_compile.add_argument("--contract", required=True)
    oracle_challenge_compile.add_argument("--out")
    oracle_challenge_compile.add_argument("--json", action="store_true")
    oracle_challenge_verify = oracle_challenge_sub.add_parser(
        "verify", help="verify a challenge result against the exact plan"
    )
    oracle_challenge_verify.add_argument("--root", default=".")
    oracle_challenge_verify.add_argument("--plan", required=True)
    oracle_challenge_verify.add_argument("--result", required=True)
    oracle_challenge_verify.add_argument("--json", action="store_true")
    oracle_incident = oracle_sub.add_parser(
        "incident",
        help="record a demoting oracle-weakening incident for a declared agent",
    )
    oracle_incident.add_argument("--root", default=".")
    oracle_incident.add_argument(
        "--agent", required=True, help="agent identity JSON file"
    )
    oracle_incident.add_argument("--contract", required=True)
    oracle_incident.add_argument("--drift", required=True)
    oracle_incident.add_argument("--out")
    oracle_incident.add_argument("--json", action="store_true")
    oracle_status = oracle_sub.add_parser(
        "status", help="read local Oracle Firewall status without changing any artifact"
    )
    oracle_status.add_argument("--root", default=".")
    oracle_status.add_argument("--json", action="store_true")

    continuity = sub.add_parser(
        "proof-continuity",
        help="seal and monitor a senior-engineering source-to-decision audit chain",
    )
    continuity_sub = continuity.add_subparsers(
        required=True, dest="proof_continuity_cmd"
    )
    continuity_seal = continuity_sub.add_parser(
        "seal",
        help="seal one source-to-obligation-to-evidence audit receipt without running work",
    )
    continuity_seal.add_argument("--root", default=".")
    continuity_seal.add_argument("--input", required=True)
    continuity_seal.add_argument("--out", required=True)
    continuity_seal.add_argument("--json", action="store_true")
    continuity_observe = continuity_sub.add_parser(
        "observe",
        help="record later local evidence and reopen the audit on contradiction",
    )
    continuity_observe.add_argument("--root", default=".")
    continuity_observe.add_argument("--contract", required=True)
    continuity_observe.add_argument("--observation", required=True)
    continuity_observe.add_argument("--out", required=True)
    continuity_observe.add_argument("--json", action="store_true")
    continuity_status = continuity_sub.add_parser(
        "status",
        help="read continuity audit and incident state without changing artifacts",
    )
    continuity_status.add_argument("--root", default=".")
    continuity_status.add_argument("--json", action="store_true")

    semantic = sub.add_parser(
        "semantic-authority",
        help="seal typed handoffs and expiring local authority leases without executing a runner",
    )
    semantic_sub = semantic.add_subparsers(required=True, dest="semantic_cmd")
    semantic_handoff = semantic_sub.add_parser(
        "handoff",
        help="seal a source-bound goal, context, epistemic declaration, scope, and action envelope",
    )
    semantic_handoff.add_argument("--root", default=".")
    semantic_handoff.add_argument("--input", required=True)
    semantic_handoff.add_argument("--out", required=True)
    semantic_handoff.add_argument("--json", action="store_true")
    semantic_lease = semantic_sub.add_parser(
        "lease",
        help="issue a short-lived, least-privilege local lease from one sealed handoff",
    )
    semantic_lease.add_argument("--root", default=".")
    semantic_lease.add_argument("--input", required=True)
    semantic_lease.add_argument("--out", required=True)
    semantic_lease.add_argument("--json", action="store_true")
    semantic_verify = semantic_sub.add_parser(
        "verify",
        help="verify a handoff or lease without sending, executing, or approving anything",
    )
    semantic_verify.add_argument("kind", choices=["handoff", "lease"])
    semantic_verify.add_argument("path")
    semantic_verify.add_argument("--root", default=".")
    semantic_verify.add_argument("--json", action="store_true")
    semantic_check = semantic_sub.add_parser(
        "check",
        help="evaluate one supplied action request against a current local lease",
    )
    semantic_check.add_argument("--root", default=".")
    semantic_check.add_argument("--lease", required=True)
    semantic_check.add_argument("--request", required=True)
    semantic_check.add_argument("--json", action="store_true")
    semantic_record = semantic_sub.add_parser(
        "record",
        help="record one replay-safe local admission decision; this never executes the request",
    )
    semantic_record.add_argument("--root", default=".")
    semantic_record.add_argument("--lease", required=True)
    semantic_record.add_argument("--request", required=True)
    semantic_record.add_argument("--out", required=True)
    semantic_record.add_argument("--json", action="store_true")
    semantic_status = semantic_sub.add_parser(
        "status", help="read local handoff/lease/decision facts without mutation"
    )
    semantic_status.add_argument("--root", default=".")
    semantic_status.add_argument("--json", action="store_true")


def _handle_proof_continuity(args):
    from .oracle_firewall import OracleFirewallError
    from .proof_continuity_ledger import (
        ProofContinuityError,
        proof_continuity_projection,
        record_proof_continuity_observation,
        seal_proof_continuity,
    )

    root = Path(args.root).resolve()
    try:
        if args.proof_continuity_cmd == "seal":
            result = seal_proof_continuity(root, Path(args.input), Path(args.out))
        elif args.proof_continuity_cmd == "observe":
            result = record_proof_continuity_observation(
                root, Path(args.contract), Path(args.observation), Path(args.out)
            )
        else:
            result = proof_continuity_projection(root)
        code = 0 if result.get("verdict") != "BLOCKED" else 1
    except (
        ProofContinuityError,
        OracleFirewallError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.proof-continuity.error.v1",
            "marker": "PROOF_CONTINUITY_REFUSED",
            "code": getattr(exc, "code", "PROOF_CONTINUITY_INPUT_INVALID"),
            "message": str(exc),
        }
        code = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(result.get("marker", "PROOF_CONTINUITY_OK"))
        print(
            "authority   : local hash-bound audit only; no test run, candidate mutation, provider action, release, or approval"
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    return code


def _oracle_setup(args, root):
    from .oracle_firewall import capture_intent_handoff, initialize_oracle_firewall

    agent = json.loads((root / args.agent).read_text(encoding="utf-8-sig"))
    if args.oracle_cmd == "init":
        return initialize_oracle_firewall(
            root,
            Path(args.out_dir),
            Path(args.source),
            agent,
            args.id,
            args.scope,
            appforge=args.appforge,
        )
    return capture_intent_handoff(
        root,
        Path(args.source),
        agent,
        args.id,
        Path(args.out) if args.out else None,
    )


def _oracle_contract_action(args, root):
    from .oracle_firewall import (
        compare_oracle_contracts,
        seal_oracle_contract,
        verify_oracle_contract,
    )

    if args.oracle_cmd == "seal":
        return seal_oracle_contract(root, Path(args.input), Path(args.out))
    if args.oracle_cmd == "verify":
        return verify_oracle_contract(root, Path(args.contract))
    return compare_oracle_contracts(
        root,
        Path(args.prior),
        Path(args.candidate),
        Path(args.out) if args.out else None,
    )


def _oracle_challenge_action(args, root):
    from .oracle_firewall import (
        compile_oracle_challenge,
        verify_oracle_challenge_result,
    )

    if args.oracle_challenge_cmd == "compile":
        return compile_oracle_challenge(
            root, Path(args.contract), Path(args.out) if args.out else None
        )
    return verify_oracle_challenge_result(root, Path(args.plan), Path(args.result))


def _oracle_incident(args, root):
    from .oracle_firewall import record_oracle_incident

    agent = json.loads((root / args.agent).read_text(encoding="utf-8-sig"))
    return record_oracle_incident(
        root,
        agent,
        Path(args.contract),
        Path(args.drift),
        Path(args.out) if args.out else None,
    )


def _oracle_dispatch(args, root):
    from .oracle_firewall import oracle_firewall_projection

    actions = {
        "init": lambda: _oracle_setup(args, root),
        "handoff": lambda: _oracle_setup(args, root),
        "seal": lambda: _oracle_contract_action(args, root),
        "verify": lambda: _oracle_contract_action(args, root),
        "diff": lambda: _oracle_contract_action(args, root),
        "challenge": lambda: _oracle_challenge_action(args, root),
        "incident": lambda: _oracle_incident(args, root),
    }
    action = actions.get(args.oracle_cmd)
    return action() if action else oracle_firewall_projection(root)


def _handle_oracle(args):
    from .oracle_firewall import OracleFirewallError

    root = Path(args.root).resolve()
    try:
        result = _oracle_dispatch(args, root)
        code = 0 if result.get("ok", True) and result.get("verdict") != "BLOCKED" else 1
    except (
        OracleFirewallError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.oracle-firewall.error.v1",
            "marker": "ORACLE_FIREWALL_REFUSED",
            "code": getattr(exc, "code", "ORACLE_INPUT_INVALID"),
            "message": str(exc),
        }
        code = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(result.get("marker", "ORACLE_FIREWALL_OK"))
        print(
            "authority   : local integrity and read-only supervision only; no candidate mutation, approval, release, credential, or network action"
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    return code


def _semantic_handoff(args, root):
    from .semantic_authority import seal_semantic_handoff

    return seal_semantic_handoff(root, Path(args.input), Path(args.out))


def _semantic_lease(args, root):
    from .semantic_authority import seal_authority_lease

    return seal_authority_lease(root, Path(args.input), Path(args.out))


def _semantic_verify(args, root):
    from .semantic_authority import verify_authority_lease, verify_semantic_handoff

    verifier = (
        verify_semantic_handoff if args.kind == "handoff" else verify_authority_lease
    )
    return verifier(root, Path(args.path))


def _semantic_check(args, root):
    from .semantic_authority import authorize_semantic_action

    request = json.loads((root / args.request).read_text(encoding="utf-8-sig"))
    return authorize_semantic_action(root, Path(args.lease), request)


def _semantic_record(args, root):
    from .semantic_authority import record_semantic_action_decision

    request = json.loads((root / args.request).read_text(encoding="utf-8-sig"))
    return record_semantic_action_decision(
        root, Path(args.lease), request, Path(args.out)
    )


def _semantic_dispatch(args, root):
    from .semantic_authority import semantic_authority_projection

    actions = {
        "handoff": lambda: _semantic_handoff(args, root),
        "lease": lambda: _semantic_lease(args, root),
        "verify": lambda: _semantic_verify(args, root),
        "check": lambda: _semantic_check(args, root),
        "record": lambda: _semantic_record(args, root),
    }
    action = actions.get(args.semantic_cmd)
    return action() if action else semantic_authority_projection(root)


def _handle_semantic_authority(args):
    from .semantic_authority import SemanticAuthorityError

    root = Path(args.root).resolve()
    try:
        result = _semantic_dispatch(args, root)
        code = 0 if result.get("ok", result.get("allowed", True)) else 1
    except (
        SemanticAuthorityError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.semantic-authority.error.v1",
            "marker": "SEMANTIC_AUTHORITY_REFUSED",
            "code": getattr(exc, "code", "SEMANTIC_INPUT_INVALID"),
            "message": str(exc),
        }
        code = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(result.get("marker", "SEMANTIC_AUTHORITY_READ_ONLY"))
        print(
            "authority   : sealed local constraints only; no message, tool, sandbox, candidate, approval, release, credential, or network action"
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    return code


def run(args: Any) -> int:
    """Dispatch one authority command."""
    handlers = {"proof-continuity": _handle_proof_continuity, "oracle": _handle_oracle}
    return handlers.get(args.cmd, _handle_semantic_authority)(args)
