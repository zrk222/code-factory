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


def run(args: Any) -> int:
    """Execute assurance commands without granting release authority."""
    from .assurance import (
        build_cyclonedx_sbom,
        build_evidence_graph,
        build_vex,
        policy_mutations,
    )
    from .supply_chain import (
        verify_signed_supply_chain_attestation,
        write_supply_chain_receipt,
    )

    try:
        if args.assurance_cmd == "supply-chain":
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
        if args.assurance_cmd == "supply-chain-verify":
            root = Path(args.root).resolve()
            attestation = Path(args.attestation)
            trust_root = Path(args.trust_root)
            attestation = (
                attestation if attestation.is_absolute() else root / attestation
            )
            trust_root = trust_root if trust_root.is_absolute() else root / trust_root
            result = verify_signed_supply_chain_attestation(
                attestation, trust_root, root, candidate_sha256=args.candidate_sha256
            )
            print(
                json.dumps(result, indent=2, sort_keys=True)
                if args.json
                else f"supply-chain signature: {result.get('state')} ({result.get('attestation_id')})"
            )
            return 0
        if args.assurance_cmd == "graph":
            result = build_evidence_graph(
                json.loads(Path(args.records).read_text(encoding="utf-8")),
                tenant_id=args.tenant,
            )
        elif args.assurance_cmd == "sbom":
            result = build_cyclonedx_sbom(
                json.loads(Path(args.components).read_text(encoding="utf-8"))
            )
        elif args.assurance_cmd == "vex":
            result = build_vex(
                json.loads(Path(args.entries).read_text(encoding="utf-8"))
            )
        else:
            result = {
                "schema": "factory.assurance.policy-mutations.v1",
                "mutations": policy_mutations(
                    json.loads(Path(args.policy).read_text(encoding="utf-8"))
                ),
            }
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.assurance.result.v1",
                    "verdict": "ERROR",
                    "error": {"code": "E_INPUT", "message": str(exc)},
                },
                indent=2,
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.assurance.result.v1",
                    "verdict": "ERROR",
                    "error": {
                        "code": getattr(exc, "code", "E_ASSURANCE"),
                        "message": getattr(exc, "message", str(exc)),
                    },
                },
                indent=2,
            )
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
