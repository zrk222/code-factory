"""Bounded, lazily loaded MCP and Junie integration CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "integrations"
OWNER = "agent-integration-maintainers"


def add_parser(sub: Any) -> None:
    """Register MCP and Junie integration commands without loading adapters."""
    mcp = sub.add_parser("mcp", help="serve or inspect the local read-only MCP adapter")
    mcp_sub = mcp.add_subparsers(required=True, dest="mcp_cmd")
    mcp_status = mcp_sub.add_parser("status", help="show the local read-only MCP boundary")
    mcp_status.add_argument("--root", default=".")
    mcp_status.add_argument("--json", action="store_true")
    mcp_config = mcp_sub.add_parser(
        "config", help="render copy-only setup for a local stdio MCP client"
    )
    mcp_config.add_argument("--root", default=".")
    mcp_config.add_argument(
        "--client",
        choices=["generic", "cursor", "opencode", "codex", "junie", "copilot"],
        default="generic",
    )
    mcp_config.add_argument("--json", action="store_true")
    mcp_install = mcp_sub.add_parser(
        "install", help="install one explicit, secret-free project MCP entry"
    )
    mcp_install.add_argument("--root", default=".")
    mcp_install.add_argument("--client", choices=["junie", "copilot"], required=True)
    mcp_install.add_argument("--confirmation", required=True)
    mcp_install.add_argument("--json", action="store_true")
    mcp_request = mcp_sub.add_parser(
        "request", help="evaluate one self-contained stateless JSON-RPC request"
    )
    mcp_request.add_argument("request", help="workspace-relative JSON request file")
    mcp_request.add_argument("--root", default=".")
    mcp_request.add_argument("--json", action="store_true")
    mcp_serve = mcp_sub.add_parser(
        "serve", help="serve newline-delimited JSON-RPC over stdio"
    )
    mcp_serve.add_argument("--root", default=".")

    junie = sub.add_parser(
        "junie", help="inspect or explicitly install the local Junie FactoryLine pack"
    )
    junie_sub = junie.add_subparsers(required=True, dest="junie_cmd")
    junie_taxonomy_parser = junie_sub.add_parser(
        "taxonomy", help="show the complete progressive Junie FactoryLine taxonomy"
    )
    junie_taxonomy_parser.add_argument("--root", default=".")
    junie_taxonomy_parser.add_argument("--json", action="store_true")
    junie_manifest_parser = junie_sub.add_parser(
        "manifest", help="show the copy-only Junie FactoryLine project-pack manifest"
    )
    junie_manifest_parser.add_argument("--root", default=".")
    junie_manifest_parser.add_argument("--json", action="store_true")
    junie_install = junie_sub.add_parser(
        "install",
        help="install secret-free project Junie guidance and MCP config after exact confirmation",
    )
    junie_install.add_argument("--root", default=".")
    junie_install.add_argument("--confirmation", required=True)
    junie_install.add_argument("--json", action="store_true")
    junie_contribution = junie_sub.add_parser(
        "contribution",
        help="validate a Junie-declared FactoryLine contribution from a local JSON object",
    )
    junie_contribution.add_argument("--root", default=".")
    junie_contribution.add_argument(
        "--declaration", required=True, help="workspace-relative JSON declaration file"
    )
    junie_contribution.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one MCP or Junie integration command."""
    if args.cmd == "mcp":
        from .mcp import McpError, dispatch_stateless, mcp_status, serve_stdio
        from .mcp_setup import (
            McpSetupError,
            install_project_mcp_config,
            mcp_connection_config,
        )

        try:
            if args.mcp_cmd == "status":
                payload = mcp_status(Path(args.root))
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print("Factory MCP status")
                    print(f"marker    : {payload['marker']}")
                    print(f"transport : {payload['transport']}")
                    print(f"tools     : {', '.join(payload['tools'])}")
                    print("authority : all external-effect authority is false")
                return 0
            if args.mcp_cmd == "config":
                payload = mcp_connection_config(Path(args.root), args.client)
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(f"Factory MCP config ({payload['client']})")
                    print("=" * 44)
                    print(f"target       : {payload['target']}")
                    print(f"workspace    : {payload['workspace_root']}")
                    print(
                        "authority    : read-only local context; no execution, approval, publish, deploy, signing, messaging, credentials, or connectors"
                    )
                    if "command_line" in payload:
                        print(f"copy command : {payload['command_line']}")
                    else:
                        print(json.dumps(payload["config"], indent=2))
                return 0
            if args.mcp_cmd == "install":
                payload = install_project_mcp_config(
                    Path(args.root), args.client, args.confirmation
                )
                print(
                    json.dumps(payload, indent=2, sort_keys=True)
                    if args.json
                    else f"Factory MCP {payload['state']}: {payload['target']}"
                )
                return 0
            if args.mcp_cmd == "request":
                request_path = Path(args.request)
                root = Path(args.root).resolve()
                try:
                    if request_path.is_absolute() or ".." in request_path.parts:
                        raise McpError(
                            "request must be a workspace-relative JSON file",
                            "MCP_STATELESS_REQUEST_PATH_REJECTED",
                        )
                    request_path = (root / request_path).resolve()
                    request_path.relative_to(root)
                except ValueError as exc:
                    raise McpError(
                        "request must be a workspace-relative JSON file",
                        "MCP_STATELESS_REQUEST_PATH_REJECTED",
                    ) from exc
                if request_path.suffix.lower() != ".json" or not request_path.is_file():
                    raise McpError(
                        "request must name an existing workspace-relative JSON file",
                        "MCP_STATELESS_REQUEST_PATH_REJECTED",
                    )
                try:
                    request = json.loads(request_path.read_text(encoding="utf-8-sig"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise McpError(
                        "request file must contain valid UTF-8 JSON",
                        "MCP_STATELESS_REQUEST_INVALID",
                    ) from exc
                payload = dispatch_stateless(request, root)
                print(
                    json.dumps(payload, indent=2, sort_keys=True)
                    if args.json
                    else json.dumps(payload, sort_keys=True)
                )
                return 0
            return serve_stdio(Path(args.root))
        except (McpError, McpSetupError) as exc:
            print(f"mcp failed: {exc.marker}: {exc}", file=sys.stderr)
            return 2

    from .junie_taxonomy import (
        JunieTaxonomyError,
        install_junie_factoryline_pack,
        junie_manifest,
        junie_taxonomy,
        validate_junie_contribution,
    )

    try:
        root = Path(args.root)
        if args.junie_cmd == "taxonomy":
            payload = junie_taxonomy(root)
        elif args.junie_cmd == "manifest":
            payload = junie_manifest(root)
        elif args.junie_cmd == "install":
            payload = install_junie_factoryline_pack(root, args.confirmation)
        else:
            declaration_path = Path(args.declaration)
            declaration_path = (
                declaration_path if declaration_path.is_absolute() else root / declaration_path
            )
            try:
                declaration_path.resolve().relative_to(root.resolve())
            except ValueError as exc:
                raise JunieTaxonomyError(
                    "declaration must stay inside the workspace",
                    "JUNIE_CONTRIBUTION_PATH_REJECTED",
                ) from exc
            payload = validate_junie_contribution(
                root, json.loads(declaration_path.read_text(encoding="utf-8"))
            )
    except JunieTaxonomyError as exc:
        print(f"junie failed: {exc.marker}: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        print(f"junie failed: JUNIE_INPUT_INVALID: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if getattr(args, "json", False)
        else payload.get("marker", "JUNIE_FACTORYLINE_OK")
    )
    return 0
