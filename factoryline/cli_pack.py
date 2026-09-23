"""Bounded, lazily loaded CLI commands for signed capability packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "pack"
OWNER = "capability-governance"


def add_parser(sub: Any) -> None:
    """Register pack commands without importing pack validators."""
    pack = sub.add_parser(
        "pack", help="list, verify, and install signed mutation-tested capability packs"
    )
    pack_sub = pack.add_subparsers(dest="pack_cmd", required=True)
    pack_sub.add_parser("list", help="list first-party packs and their trust status")
    validate = pack_sub.add_parser(
        "validate", help="verify structure, signature, and validator mutations"
    )
    validate.add_argument("path")
    install = pack_sub.add_parser(
        "install", help="atomically install one verified pack into a workspace"
    )
    install.add_argument("path")
    install.add_argument("--root", default=".")
    install.add_argument("--force", action="store_true")
    compose = pack_sub.add_parser(
        "compose", help="write a compatible, hash-bound pack composition plan"
    )
    compose.add_argument("paths", nargs="+")
    compose.add_argument("--root", default=".")
    compose.add_argument("--name", default="default")
    compose.add_argument("--force", action="store_true")


def run(args: Any) -> int:
    """Execute a pack command and render its deterministic JSON receipt."""
    from .capability_packs import (
        CapabilityPackError,
        builtin_packs,
        compose_packs,
        install_pack,
        validate_pack,
    )

    try:
        if args.pack_cmd == "list":
            packs = []
            for item in builtin_packs():
                validation = validate_pack(Path(item["path"]))
                packs.append(
                    {
                        "id": item["id"],
                        "version": item["version"],
                        "kind": item["kind"],
                        "target_kind": item.get("target_kind"),
                        "label": item["label"],
                        "path": item["path"],
                        "valid": validation["valid"],
                        "signature": validation["signature"],
                        "mutations": validation["mutations"],
                    }
                )
            result = {
                "schema": "factory.capability_pack.inventory.v1",
                "packs": packs,
                "markers": ["PACK_INVENTORY_DERIVED", "PACK_SIGNATURE_BYPASS_DENIED"],
            }
        elif args.pack_cmd == "validate":
            result = validate_pack(Path(args.path), verify_signature=True, mutate=True)
        elif args.pack_cmd == "install":
            result = install_pack(Path(args.path), Path(args.root), force=args.force)
        else:
            result = compose_packs(
                [Path(path) for path in args.paths],
                Path(args.root),
                name=args.name,
                force=args.force,
            )
    except CapabilityPackError as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.capability_pack.error.v1",
                    "status": "failed",
                    "code": exc.code,
                    "message": exc.message,
                    "markers": exc.markers,
                    "failure": exc.guidance,
                },
                indent=2,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("valid", True) else 1
