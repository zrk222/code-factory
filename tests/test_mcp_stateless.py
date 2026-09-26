from __future__ import annotations

from hashlib import sha256
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread

import pytest

from factoryline.cli import main
from factoryline.mcp import (
    MCP_STREAMABLE_HTTP_VERSION,
    McpError,
    create_streamable_http_server,
    dispatch_stateless,
)
from factoryline.cli_integrations import _oidc_bearer_validator


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _request_digest(request: object) -> str:
    canonical = json.dumps(
        request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def test_one_shot_request_is_hash_bound_and_does_not_mutate_workspace(tmp_path: Path):
    request = {"jsonrpc": "2.0", "id": "r1", "method": "tools/list", "params": {}}
    before = _files(tmp_path)

    first = dispatch_stateless(request, tmp_path)
    second = dispatch_stateless(request, tmp_path)

    assert first == second
    assert first["schema"] == "factory.mcp.stateless-response.v1"
    assert first["marker"] == "MCP_STATELESS_RESPONSE"
    assert first["request_sha256"] == _request_digest(request)
    assert first["state"] == "stateless"
    assert first["server_state"] == "none"
    assert first["response"]["result"]["marker"] == "FACTORY_MCP_TOOL_INVENTORY"
    assert first["replay"]["marker"] == "MCP_STATELESS_REPLAY_HINTS"
    assert first["replay"]["requestKey"] == f"sha256:{first['request_sha256']}"
    assert first["replay"]["retry"]["safe"] is True
    assert first["replay"]["retry"]["serverReplayStore"] is False
    assert first["replay"]["cache"]["cacheable"] is True
    assert all(value is False for value in first["authority"].values())
    assert _files(tmp_path) == before


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "sessionId": "abc"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "state": {"cursor": "x"}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "cursor": "x"},
    ],
)
def test_stateful_extensions_are_rejected(tmp_path: Path, payload: dict[str, object]):
    with pytest.raises(McpError) as error:
        dispatch_stateless(payload, tmp_path)
    assert error.value.marker == "MCP_STATELESS_STATE_REJECTED"


def test_oversized_request_is_rejected_before_dispatch(tmp_path: Path):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"padding": "x" * 70_000},
    }
    with pytest.raises(McpError) as error:
        dispatch_stateless(request, tmp_path)
    assert error.value.marker == "MCP_STATELESS_REQUEST_TOO_LARGE"


def test_non_object_request_and_non_string_keys_are_rejected(tmp_path: Path):
    with pytest.raises(McpError) as not_object:
        dispatch_stateless(["not", "an", "object"], tmp_path)
    assert not_object.value.marker == "MCP_STATELESS_REQUEST_INVALID"
    with pytest.raises(McpError) as non_string:
        dispatch_stateless({1: "non-string key"}, tmp_path)
    assert non_string.value.marker == "MCP_STATELESS_REQUEST_INVALID"


def test_notification_returns_null_response_inside_stateless_envelope(tmp_path: Path):
    payload = dispatch_stateless(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        tmp_path,
    )
    assert payload["response"] is None
    assert payload["state"] == "stateless"


def test_cli_request_reads_relative_json_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    before = _files(tmp_path)

    assert (
        main(["mcp", "request", "request.json", "--root", str(tmp_path), "--json"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["marker"] == "MCP_STATELESS_RESPONSE"
    assert payload["request_sha256"] == _request_digest(request)
    assert payload["server_state"] == "none"
    assert payload["replay"]["cache"]["cacheable"] is True
    assert _files(tmp_path) == before


@pytest.mark.parametrize(
    "request_path", ["..\\request.json", "C:\\outside\\request.json"]
)
def test_cli_rejects_parent_or_absolute_request_paths(
    tmp_path: Path, request_path: str, capsys: pytest.CaptureFixture[str]
):
    assert (
        main(["mcp", "request", request_path, "--root", str(tmp_path), "--json"]) == 2
    )
    assert "MCP_STATELESS_REQUEST_PATH_REJECTED" in capsys.readouterr().err


def test_streamable_http_is_authenticated_loopback_and_protocol_bound(
    tmp_path: Path,
) -> None:
    token = "local-test-token-0123456789abcdef"
    server = create_streamable_http_server(tmp_path, bearer_token=token, port=0)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    port = server.server_address[1]

    def request(
        method: str,
        *,
        params: dict[str, object] | None = None,
        auth: str | None = token,
        origin: str | None = None,
        method_header: str | None = None,
        transfer_encoding: bool = False,
    ) -> tuple[int, dict[str, object] | None]:
        payload = {
            "jsonrpc": "2.0",
            "id": "http-1",
            "method": method,
            "params": {
                **(params or {}),
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_STREAMABLE_HTTP_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_STREAMABLE_HTTP_VERSION,
            "Mcp-Method": method_header or method,
            "Host": f"127.0.0.1:{port}",
        }
        if method == "tools/call" and isinstance(params, dict):
            headers["Mcp-Name"] = str(params.get("name", ""))
        elif method == "resources/read" and isinstance(params, dict):
            headers["Mcp-Name"] = str(params.get("uri", ""))
        if auth is not None:
            headers["Authorization"] = f"Bearer {auth}"
        if origin is not None:
            headers["Origin"] = origin
        if transfer_encoding:
            headers["Transfer-Encoding"] = "chunked"
        connection = HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request(
                "POST",
                "/mcp",
                json.dumps(payload),
                headers,
                encode_chunked=transfer_encoding,
            )
            response = connection.getresponse()
            raw = response.read()
            decoded = json.loads(raw) if raw else None
            return response.status, decoded
        finally:
            connection.close()

    try:
        status, discovery = request("server/discover")
        assert status == 200
        assert discovery is not None
        assert discovery["result"]["resultType"] == "complete"
        assert discovery["result"]["supportedVersions"] == [MCP_STREAMABLE_HTTP_VERSION]
        assert discovery["result"]["cacheScope"] == "private"
        assert discovery["result"]["ttlMs"] == 0

        status, tool_list = request("tools/list")
        assert status == 200
        assert tool_list is not None
        assert tool_list["result"]["resultType"] == "complete"
        assert "io.modelcontextprotocol/serverInfo" in tool_list["result"]["_meta"]

        status, call = request(
            "tools/call", params={"name": "factory.status", "arguments": {}}
        )
        assert status == 200
        assert call is not None
        assert call["result"]["resultType"] == "complete"

        assert request("server/discover", auth="wrong-token")[0] == 401
        assert request("server/discover", origin="https://attacker.example")[0] == 403
        assert request("server/discover", transfer_encoding=True)[0] == 400
        status, mismatch = request("tools/list", method_header="resources/list")
        assert status == 400
        assert mismatch is not None
        assert mismatch["error"]["code"] == -32020
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
    assert not worker.is_alive()


def test_oidc_bearer_validator_binds_exact_tenant_and_group(
    monkeypatch: pytest.MonkeyPatch,
):
    import factoryline.hosted_identity as hosted_identity
    import factoryline.pr_assurance as pr_assurance

    class FakeCache:
        def __init__(self, url: str, transport: object):
            assert url == "https://identity.example/jwks.json"
            assert transport is not None

    monkeypatch.setattr(hosted_identity, "HttpxTransport", lambda: object())
    monkeypatch.setattr(hosted_identity, "JwksCache", FakeCache)
    monkeypatch.setattr(hosted_identity, "get_jwks", lambda _cache: {"keys": [{}]})
    token_claims = {
        "valid": {"tenant_id": "team-a", "groups": ["factory-reviewers"]},
        "wrong-tenant": {"tenant_id": "team-b", "groups": ["factory-reviewers"]},
        "wrong-group": {"tenant_id": "team-a", "groups": ["developers"]},
        "bad-groups": {"tenant_id": "team-a", "groups": "factory-reviewers"},
    }

    def verify(token: str, jwks: dict[str, object], issuer: str, audience: str):
        assert jwks == {"keys": [{}]}
        assert issuer == "https://identity.example/issuer"
        assert audience == "factory-local"
        if token == "malformed":
            raise pr_assurance.PRAssuranceError("E_OIDC_TOKEN", "invalid token")
        return token_claims[token]

    monkeypatch.setattr(pr_assurance, "verify_oidc_token", verify)
    validator = _oidc_bearer_validator(
        issuer="https://identity.example/issuer",
        audience="factory-local",
        jwks_url="https://identity.example/jwks.json",
        tenant_id="team-a",
        required_group="factory-reviewers",
    )

    assert validator("valid") is True
    assert validator("wrong-tenant") is False
    assert validator("wrong-group") is False
    assert validator("bad-groups") is False
    assert validator("malformed") is False


def test_oidc_bearer_validator_maps_jwks_outage_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    import factoryline.hosted_identity as hosted_identity
    import factoryline.pr_assurance as pr_assurance

    class FakeCache:
        def __init__(self, _url: str, _transport: object):
            pass

    monkeypatch.setattr(hosted_identity, "HttpxTransport", lambda: object())
    monkeypatch.setattr(hosted_identity, "JwksCache", FakeCache)

    def unavailable(_cache: object):
        raise pr_assurance.PRAssuranceError("E_JWKS_UNAVAILABLE", "private detail")

    monkeypatch.setattr(hosted_identity, "get_jwks", unavailable)
    validator = _oidc_bearer_validator(
        issuer="https://identity.example/issuer",
        audience="factory-local",
        jwks_url="https://identity.example/jwks.json",
        tenant_id="team-a",
        required_group="factory-reviewers",
    )

    with pytest.raises(McpError) as error:
        validator("opaque-token")
    assert error.value.marker == "MCP_HTTP_AUTH_UNAVAILABLE"
    assert "private detail" not in str(error.value)


def test_oidc_bearer_validator_rejects_non_https_issuer():
    with pytest.raises(McpError) as error:
        _oidc_bearer_validator(
            issuer="http://identity.example/issuer",
            audience="factory-local",
            jwks_url="https://identity.example/jwks.json",
            tenant_id="team-a",
            required_group="factory-reviewers",
        )
    assert error.value.marker == "MCP_HTTP_OIDC_CONFIG_INVALID"


def test_streamable_http_oidc_verifies_tenant_and_handles_jwks_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import factoryline.hosted_identity as hosted_identity
    import factoryline.pr_assurance as pr_assurance

    class FakeCache:
        def __init__(self, _url: str, _transport: object):
            pass

    monkeypatch.setattr(hosted_identity, "HttpxTransport", lambda: object())
    monkeypatch.setattr(hosted_identity, "JwksCache", FakeCache)
    monkeypatch.setattr(hosted_identity, "get_jwks", lambda _cache: {"keys": [{}]})

    def verify(token: str, _jwks: dict[str, object], _issuer: str, _audience: str):
        if token == "jwks-outage":
            raise pr_assurance.PRAssuranceError("E_JWKS_UNAVAILABLE", "private detail")
        claims = {
            "accepted": {"tenant_id": "team-a", "groups": ["factory-reviewers"]},
            "wrong-tenant": {"tenant_id": "team-b", "groups": ["factory-reviewers"]},
        }
        if token not in claims:
            raise pr_assurance.PRAssuranceError("E_OIDC_SIGNATURE", "invalid token")
        return claims[token]

    monkeypatch.setattr(pr_assurance, "verify_oidc_token", verify)
    validator = _oidc_bearer_validator(
        issuer="https://identity.example/issuer",
        audience="factory-local",
        jwks_url="https://identity.example/jwks.json",
        tenant_id="team-a",
        required_group="factory-reviewers",
    )
    server = create_streamable_http_server(tmp_path, bearer_validator=validator, port=0)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    port = server.server_address[1]
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_STREAMABLE_HTTP_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }

    def post(token: str) -> tuple[int, str]:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_STREAMABLE_HTTP_VERSION,
            "Mcp-Method": "tools/list",
            "Host": f"127.0.0.1:{port}",
        }
        connection = HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("POST", "/mcp", json.dumps(payload), headers)
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            connection.close()

    try:
        assert post("accepted")[0] == 200
        assert post("invalid")[0] == 401
        assert post("wrong-tenant")[0] == 401
        unavailable_status, unavailable_body = post("jwks-outage")
        assert unavailable_status == 503
        assert "private detail" not in unavailable_body
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
    assert not worker.is_alive()


def test_cli_oidc_mode_requires_explicit_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    for name in (
        "FACTORY_MCP_OIDC_ISSUER",
        "FACTORY_MCP_OIDC_AUDIENCE",
        "FACTORY_MCP_OIDC_JWKS_URL",
        "FACTORY_MCP_OIDC_TENANT_ID",
        "FACTORY_MCP_OIDC_REQUIRED_GROUP",
    ):
        monkeypatch.delenv(name, raising=False)

    assert (
        main(["mcp", "serve-http", "--auth-mode", "oidc", "--root", str(tmp_path)]) == 2
    )
    assert "MCP_HTTP_OIDC_CONFIG_INVALID" in capsys.readouterr().err


def test_streamable_http_uses_bearer_validator(tmp_path: Path) -> None:
    def validate(token: str) -> bool:
        if token == "unavailable-token":
            raise McpError("identity unavailable", "MCP_HTTP_AUTH_UNAVAILABLE")
        return token == "verified-token"

    server = create_streamable_http_server(tmp_path, bearer_validator=validate, port=0)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    port = server.server_address[1]
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_STREAMABLE_HTTP_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }

    def post(token: str) -> int:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_STREAMABLE_HTTP_VERSION,
            "Mcp-Method": "tools/list",
            "Host": f"127.0.0.1:{port}",
        }
        connection = HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("POST", "/mcp", json.dumps(payload), headers)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    try:
        assert post("verified-token") == 200
        assert post("invalid-token") == 401
        assert post("unavailable-token") == 503
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
    assert not worker.is_alive()


def test_streamable_http_requires_matching_name_and_supported_version(
    tmp_path: Path,
) -> None:
    server = create_streamable_http_server(
        tmp_path, bearer_token="local-test-token-0123456789abcdef", port=0
    )
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    port = server.server_address[1]

    def post(payload: dict[str, object], *, protocol: str, name: str | None = None):
        headers = {
            "Authorization": "Bearer local-test-token-0123456789abcdef",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": protocol,
            "Mcp-Method": str(payload["method"]),
            "Host": f"127.0.0.1:{port}",
        }
        if name is not None:
            headers["Mcp-Name"] = name
        connection = HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("POST", "/mcp", json.dumps(payload), headers)
            response = connection.getresponse()
            decoded = json.loads(response.read())
            return response.status, decoded
        finally:
            connection.close()

    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "factory.status",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_STREAMABLE_HTTP_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
        status, mismatch = post(
            request, protocol=MCP_STREAMABLE_HTTP_VERSION, name="different"
        )
        assert status == 400
        assert mismatch["error"]["code"] == -32020
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = (
            "2099-01-01"
        )
        status, unsupported = post(
            request, protocol="2099-01-01", name="factory.status"
        )
        assert status == 400
        assert unsupported["error"]["code"] == -32022
        assert unsupported["error"]["data"]["supported"] == [
            MCP_STREAMABLE_HTTP_VERSION
        ]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_http_transport_stages_stay_within_complexity_budget():
    """Count private helpers too so extraction cannot hide transport complexity."""
    import ast
    import inspect
    import textwrap
    from factoryline.mcp import (
        _McpHttpHandler,
        _validate_http_options,
        _validate_http_address,
    )

    sources = [
        _McpHttpHandler,
        create_streamable_http_server,
        _validate_http_options,
        _validate_http_address,
    ]
    for target in sources:
        tree = ast.parse(textwrap.dedent(inspect.getsource(target)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            complexity = 1
            for child in ast.walk(node):
                if isinstance(
                    child,
                    (
                        ast.If,
                        ast.For,
                        ast.While,
                        ast.ExceptHandler,
                        ast.With,
                        ast.Assert,
                        ast.IfExp,
                    ),
                ):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            assert complexity <= 10, (node.name, complexity)
