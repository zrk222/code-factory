"""Bounded, lazily loaded MCP and Junie integration CLI."""

from __future__ import annotations

import json
import sys
from functools import partial
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
        return _run_mcp(args)
    return _run_junie(args)


def _run_mcp(args: Any) -> int:
    from .mcp import McpError
    from .mcp_setup import McpSetupError

    try:
        return _dispatch_mcp(args)
    except (McpError, McpSetupError) as exc:
        print(f"mcp failed: {exc.marker}: {exc}", file=sys.stderr)
        return 2


def _dispatch_mcp(args: Any) -> int:
    if args.mcp_cmd == "status":
        return _run_mcp_status(args)
    if args.mcp_cmd == "config":
        return _run_mcp_config(args)
    if args.mcp_cmd == "install":
        return _run_mcp_install(args)
    if args.mcp_cmd == "request":
        return _run_mcp_request(args)
    if args.mcp_cmd == "serve-http":
        return _run_mcp_http(args)
    return _run_mcp_stdio(args)


def _run_mcp_status(args: Any) -> int:
    from .mcp import mcp_status

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


def _run_mcp_config(args: Any) -> int:
    from .mcp_setup import mcp_connection_config

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


def _run_mcp_install(args: Any) -> int:
    from .mcp_setup import install_project_mcp_config

    payload = install_project_mcp_config(
        Path(args.root), args.client, args.confirmation
    )
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if args.json
        else f"Factory MCP {payload['state']}: {payload['target']}"
    )
    return 0


def _mcp_request_file(args: Any, mcp_error: type[Exception]) -> tuple[Path, Any]:
    request_path = Path(args.request)
    root = Path(args.root).resolve()
    try:
        if request_path.is_absolute() or ".." in request_path.parts:
            raise mcp_error(
                "request must be a workspace-relative JSON file",
                "MCP_STATELESS_REQUEST_PATH_REJECTED",
            )
        request_path = (root / request_path).resolve()
        request_path.relative_to(root)
    except ValueError as exc:
        raise mcp_error(
            "request must be a workspace-relative JSON file",
            "MCP_STATELESS_REQUEST_PATH_REJECTED",
        ) from exc
    if request_path.suffix.lower() != ".json" or not request_path.is_file():
        raise mcp_error(
            "request must name an existing workspace-relative JSON file",
            "MCP_STATELESS_REQUEST_PATH_REJECTED",
        )
    try:
        request = json.loads(request_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise mcp_error(
            "request file must contain valid UTF-8 JSON",
            "MCP_STATELESS_REQUEST_INVALID",
        ) from exc
    return root, request


def _run_mcp_request(args: Any) -> int:
    from .mcp import McpError, dispatch_stateless

    root, request = _mcp_request_file(args, McpError)
    payload = dispatch_stateless(request, root)
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if args.json
        else json.dumps(payload, sort_keys=True)
    )
    return 0


def _oidc_environment(args: Any, environ: Any) -> dict[str, str]:
    names = {
        "issuer": args.oidc_issuer_env,
        "audience": args.oidc_audience_env,
        "jwks_url": args.oidc_jwks_url_env,
        "tenant_id": args.oidc_tenant_env,
        "required_group": args.oidc_required_group_env,
    }
    return {key: environ.get(name, "").strip() for key, name in names.items()}


def _http_authentication(args: Any, environ: Any, mcp_error: type[Exception]):
    if args.auth_mode == "local-token":
        return (
            {"bearer_token": environ.get(args.token_env, "")},
            "Local shared-token guard; no OAuth server or remote bind.",
        )
    names = {
        "issuer": args.oidc_issuer_env,
        "audience": args.oidc_audience_env,
        "jwks_url": args.oidc_jwks_url_env,
        "tenant_id": args.oidc_tenant_env,
        "required_group": args.oidc_required_group_env,
    }
    config = _oidc_environment(args, environ)
    missing = sorted(names[key] for key, value in config.items() if not value)
    if missing:
        raise mcp_error(
            "OIDC mode requires configured issuer, audience, JWKS URL, tenant, and group: "
            + ", ".join(missing),
            "MCP_HTTP_OIDC_CONFIG_INVALID",
        )
    return (
        {"bearer_validator": _oidc_bearer_validator(**config)},
        "OIDC RS256 access-token verification; exact issuer, audience, tenant, and group required; "
        "JWKS cached with bounded freshness; no OAuth authorization server or remote bind.",
    )


def _run_mcp_http(args: Any) -> int:
    import os

    from .mcp import McpError, create_streamable_http_server

    auth_kwargs, auth_description = _http_authentication(args, os.environ, McpError)
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
        print("No SSE, subscriptions, remote bind, or A2A endpoint.", file=sys.stderr)
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _run_mcp_stdio(args: Any) -> int:
    from .mcp import serve_stdio

    return serve_stdio(Path(args.root))


def _run_junie(args: Any) -> int:
    from . import junie_taxonomy

    try:
        payload = _junie_payload(args, junie_taxonomy)
    except junie_taxonomy.JunieTaxonomyError as exc:
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


def _junie_payload(args: Any, taxonomy: Any) -> dict:
    root = Path(args.root)
    if args.junie_cmd == "taxonomy":
        return taxonomy.junie_taxonomy(root)
    if args.junie_cmd == "manifest":
        return taxonomy.junie_manifest(root)
    if args.junie_cmd == "install":
        return taxonomy.install_junie_factoryline_pack(root, args.confirmation)
    return _junie_contribution_payload(args, root, taxonomy)


def _junie_contribution_payload(args: Any, root: Path, taxonomy: Any) -> dict:
    declaration_path = Path(args.declaration)
    if not declaration_path.is_absolute():
        declaration_path = root / declaration_path
    try:
        declaration_path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise taxonomy.JunieTaxonomyError(
            "declaration must stay inside the workspace",
            "JUNIE_CONTRIBUTION_PATH_REJECTED",
        ) from exc
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    return taxonomy.validate_junie_contribution(root, declaration)


def _valid_https_issuer(issuer: Any, urlsplit: Any) -> bool:
    if not isinstance(issuer, str) or len(issuer) > 2048:
        return False
    parts = urlsplit(issuer)
    return all(
        (
            parts.scheme == "https",
            bool(parts.netloc),
            not parts.username,
            not parts.password,
            not parts.fragment,
        )
    )


def _bounded_oidc_value(value: Any, maximum: int) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= maximum


def _validate_oidc_configuration(
    issuer: Any,
    audience: Any,
    tenant_id: Any,
    required_group: Any,
    urlsplit: Any,
    mcp_error: type[Exception],
) -> None:
    if (
        not _valid_https_issuer(issuer, urlsplit)
        or not _bounded_oidc_value(audience, 512)
        or not _bounded_oidc_value(tenant_id, 256)
        or not _bounded_oidc_value(required_group, 256)
    ):
        raise mcp_error(
            "OIDC issuer, audience, tenant, or group configuration is invalid",
            "MCP_HTTP_OIDC_CONFIG_INVALID",
        )


def _validate_oidc_token(
    token: str,
    *,
    cache: Any,
    issuer: str,
    audience: str,
    tenant_id: str,
    required_group: str,
    get_jwks: Any,
    mcp_error: type[Exception],
    assurance_error: type[Exception],
    verify_oidc_token: Any,
) -> bool:
    try:
        claims = verify_oidc_token(token, get_jwks(cache), issuer, audience)
    except assurance_error as exc:
        if exc.code.startswith(("E_JWKS_", "E_HTTP_")):
            raise mcp_error(
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


def _oidc_bearer_validator(
    *, issuer: str, audience: str, jwks_url: str, tenant_id: str, required_group: str
):
    """Build a cached, fail-closed OIDC token validator for the local MCP adapter."""
    from urllib.parse import urlsplit

    from .hosted_identity import HttpxTransport, JwksCache, get_jwks
    from .mcp import McpError
    from .pr_assurance import PRAssuranceError, verify_oidc_token

    _validate_oidc_configuration(
        issuer, audience, tenant_id, required_group, urlsplit, McpError
    )
    try:
        cache = JwksCache(jwks_url, HttpxTransport())
    except PRAssuranceError as exc:
        raise McpError(
            "OIDC verifier configuration or optional hosted dependency is invalid",
            "MCP_HTTP_OIDC_CONFIG_INVALID",
        ) from exc
    return partial(
        _validate_oidc_token,
        cache=cache,
        issuer=issuer,
        audience=audience,
        tenant_id=tenant_id,
        required_group=required_group,
        get_jwks=get_jwks,
        mcp_error=McpError,
        assurance_error=PRAssuranceError,
        verify_oidc_token=verify_oidc_token,
    )
