"""Bounded, lazily loaded assurance-artifact CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "assurance"
OWNER = "assurance-maintainers"


def add_parser(sub: Any) -> None:
    """Register assurance commands without importing evidence engines."""
    parser = sub.add_parser(
        "assurance", help="produce deterministic assurance artifacts"
    )
    commands = parser.add_subparsers(required=True, dest="assurance_cmd")
    graph = commands.add_parser("graph", help="build a tenant-scoped evidence graph")
    graph.add_argument("records")
    graph.add_argument("--tenant", required=True)
    graph.add_argument("--out", required=True)
    sbom = commands.add_parser("sbom", help="build a sorted CycloneDX-shaped SBOM")
    sbom.add_argument("components")
    sbom.add_argument("--out", required=True)
    vex = commands.add_parser("vex", help="build a validated VEX artifact")
    vex.add_argument("entries")
    vex.add_argument("--out", required=True)
    mutation = commands.add_parser(
        "policy-mutate", help="emit explicit policy mutations for a challenge run"
    )
    mutation.add_argument("policy")
    mutation.add_argument("--out", required=True)
    supply_chain = commands.add_parser(
        "supply-chain",
        help="verify a local source, dependency, vulnerability and reproducible-build manifest",
    )
    supply_chain.add_argument(
        "manifest", help="workspace-relative supply-chain attestation JSON"
    )
    supply_chain.add_argument("--root", default=".")
    supply_chain.add_argument(
        "--out", default=".factory/supply-chain/supply-chain-receipt.json"
    )
    supply_chain.add_argument("--candidate-sha256")
    supply_chain.add_argument("--json", action="store_true")
    verify = commands.add_parser(
        "supply-chain-verify",
        help="verify an independently collected signed supply-chain attestation",
    )
    verify.add_argument("attestation")
    verify.add_argument("--root", default=".")
    verify.add_argument("--trust-root", required=True)
    verify.add_argument("--candidate-sha256")
    verify.add_argument("--json", action="store_true")


def _run_supply_chain(args: Any) -> int:
    from .supply_chain import write_supply_chain_receipt

    root = Path(args.root).resolve()
    manifest = Path(args.manifest)
    manifest = manifest if manifest.is_absolute() else root / manifest
    result = write_supply_chain_receipt(
        root, manifest, Path(args.out), candidate_sha256=args.candidate_sha256
    )
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.json
        else f"supply-chain: {result.get('decision')} ({result.get('path')})"
    )
    return 0 if result.get("decision") == "PASS" else 1


def _run_supply_chain_verify(args: Any) -> int:
    from .supply_chain import verify_signed_supply_chain_attestation

    root = Path(args.root).resolve()
    attestation = Path(args.attestation)
    trust_root = Path(args.trust_root)
    if not attestation.is_absolute():
        attestation = root / attestation
    if not trust_root.is_absolute():
        trust_root = root / trust_root
    result = verify_signed_supply_chain_attestation(
        attestation, trust_root, root, candidate_sha256=args.candidate_sha256
    )
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.json
        else f"supply-chain signature: {result.get('state')} ({result.get('attestation_id')})"
    )
    return 0


def _assurance_result(args: Any) -> dict[str, Any]:
    from .assurance import (
        build_cyclonedx_sbom,
        build_evidence_graph,
        build_vex,
        policy_mutations,
    )

    if args.assurance_cmd == "graph":
        return build_evidence_graph(
            json.loads(Path(args.records).read_text(encoding="utf-8")),
            tenant_id=args.tenant,
        )
    if args.assurance_cmd == "sbom":
        return build_cyclonedx_sbom(
            json.loads(Path(args.components).read_text(encoding="utf-8"))
        )
    if args.assurance_cmd == "vex":
        return build_vex(json.loads(Path(args.entries).read_text(encoding="utf-8")))
    return {
        "schema": "factory.assurance.policy-mutations.v1",
        "mutations": policy_mutations(
            json.loads(Path(args.policy).read_text(encoding="utf-8"))
        ),
    }


def _write_assurance_result(path: str, result: dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")


def _print_assurance_error(code: str, message: str) -> None:
    print(
        json.dumps(
            {
                "schema": "factory.assurance.result.v1",
                "verdict": "ERROR",
                "error": {"code": code, "message": message},
            },
            indent=2,
        )
    )


def run(args: Any) -> int:
    """Execute assurance commands without granting release authority."""
    try:
        if args.assurance_cmd == "supply-chain":
            return _run_supply_chain(args)
        if args.assurance_cmd == "supply-chain-verify":
            return _run_supply_chain_verify(args)
        result = _assurance_result(args)
        _write_assurance_result(args.out, result)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _print_assurance_error("E_INPUT", str(exc))
        return 1
    except Exception as exc:
        _print_assurance_error(
            getattr(exc, "code", "E_ASSURANCE"), getattr(exc, "message", str(exc))
        )
        return 1
    print(
        json.dumps(
            {
                "schema": "factory.assurance.result.v1",
                "verdict": "WRITTEN",
                "path": str(Path(args.out).resolve()),
            },
            indent=2,
        )
    )
    return 0
