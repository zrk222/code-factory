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
    mcp_status = mcp_sub.add_parser(
        "status", help="show the local read-only MCP boundary"
    )
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
    mcp_http = mcp_sub.add_parser(
        "serve-http", help="serve stateless MCP Streamable HTTP on loopback only"
    )
    mcp_http.add_argument("--root", default=".")
    mcp_http.add_argument("--port", type=int, default=8765)
    mcp_http.add_argument(
        "--token-env",
        default="FACTORY_MCP_HTTP_TOKEN",
        help="environment variable containing a local bearer token (minimum 24 characters)",
    )
    mcp_http.add_argument(
        "--auth-mode",
        choices=["local-token", "oidc"],
        default="local-token",
        help="use a local shared token or verify an OIDC JWT against pinned issuer, audience, and JWKS",
    )
    mcp_http.add_argument("--oidc-issuer-env", default="FACTORY_MCP_OIDC_ISSUER")
    mcp_http.add_argument("--oidc-audience-env", default="FACTORY_MCP_OIDC_AUDIENCE")
    mcp_http.add_argument("--oidc-jwks-url-env", default="FACTORY_MCP_OIDC_JWKS_URL")
    mcp_http.add_argument("--oidc-tenant-env", default="FACTORY_MCP_OIDC_TENANT_ID")
    mcp_http.add_argument(
        "--oidc-required-group-env", default="FACTORY_MCP_OIDC_REQUIRED_GROUP"
    )
    mcp_http.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="exact browser Origin to permit; by default cross-origin requests are rejected",
    )

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
        from .mcp import (
            McpError,
            create_streamable_http_server,
            dispatch_stateless,
            mcp_status,
            serve_stdio,
        )
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
            if args.mcp_cmd == "serve-http":
                import os

                auth_kwargs: dict[str, Any]
                if args.auth_mode == "local-token":
                    auth_kwargs = {"bearer_token": os.environ.get(args.token_env, "")}
                    auth_description = (
                        "Local shared-token guard; no OAuth server or remote bind."
                    )
                else:
                    auth_names = {
                        "issuer": args.oidc_issuer_env,
                        "audience": args.oidc_audience_env,
                        "jwks_url": args.oidc_jwks_url_env,
                        "tenant_id": args.oidc_tenant_env,
                        "required_group": args.oidc_required_group_env,
                    }
                    config = {
                        key: os.environ.get(name, "").strip()
                        for key, name in auth_names.items()
                    }
                    if not all(config.values()):
                        missing = sorted(
                            auth_names[key]
                            for key, value in config.items()
                            if not value
                        )
                        raise McpError(
                            "OIDC mode requires configured issuer, audience, JWKS URL, tenant, and group: "
                            + ", ".join(missing),
                            "MCP_HTTP_OIDC_CONFIG_INVALID",
                        )
                    auth_kwargs = {"bearer_validator": _oidc_bearer_validator(**config)}
                    auth_description = (
                        "OIDC RS256 access-token verification; exact issuer, audience, tenant, and group required; "
                        "JWKS cached with bounded freshness; no OAuth authorization server or remote bind."
                    )
                server = create_streamable_http_server(
                    Path(args.root),
                    **auth_kwargs,
                    port=args.port,
                    allowed_origins=tuple(args.allow_origin),
                )
                try:
                    print(
                        f"Factory MCP Streamable HTTP listening at http://127.0.0.1:{server.server_address[1]}/mcp",
                        file=sys.stderr,
                    )
                    print(auth_description, file=sys.stderr)
                    print(
                        "No SSE, subscriptions, remote bind, or A2A endpoint.",
                        file=sys.stderr,
                    )
                    server.serve_forever(poll_interval=0.25)
                except KeyboardInterrupt:
                    return 0
                finally:
                    server.server_close()
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
                declaration_path
                if declaration_path.is_absolute()
                else root / declaration_path
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


def _oidc_bearer_validator(
    *, issuer: str, audience: str, jwks_url: str, tenant_id: str, required_group: str
):
    """Build a cached, fail-closed OIDC token validator for the local MCP adapter."""
    from urllib.parse import urlsplit

    from .hosted_identity import HttpxTransport, JwksCache, get_jwks
    from .mcp import McpError
    from .pr_assurance import PRAssuranceError, verify_oidc_token

    issuer_parts = urlsplit(issuer) if isinstance(issuer, str) else None
    if (
        issuer_parts is None
        or issuer_parts.scheme != "https"
        or not issuer_parts.netloc
        or issuer_parts.username
        or issuer_parts.password
        or issuer_parts.fragment
        or len(issuer) > 2048
        or not isinstance(audience, str)
        or not audience
        or len(audience) > 512
        or not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id) > 256
        or not isinstance(required_group, str)
        or not required_group
        or len(required_group) > 256
    ):
        raise McpError(
            "OIDC issuer, audience, tenant, or group configuration is invalid",
            "MCP_HTTP_OIDC_CONFIG_INVALID",
        )

    try:
        cache = JwksCache(jwks_url, HttpxTransport())
    except PRAssuranceError as exc:
        raise McpError(
            "OIDC verifier configuration or optional hosted dependency is invalid",
            "MCP_HTTP_OIDC_CONFIG_INVALID",
        ) from exc

    def validate(token: str) -> bool:
        try:
            claims = verify_oidc_token(token, get_jwks(cache), issuer, audience)
        except PRAssuranceError as exc:
            if exc.code.startswith(("E_JWKS_", "E_HTTP_")):
                raise McpError(
                    "OIDC signing keys are temporarily unavailable",
                    "MCP_HTTP_AUTH_UNAVAILABLE",
                ) from exc
            return False
        groups = claims.get("groups")
        return (
            claims.get("tenant_id") == tenant_id
            and isinstance(groups, list)
            and required_group in groups
        )

    return validate
