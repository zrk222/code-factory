import pytest

from factoryline.mcp_replay import (
    DEFAULT_CACHE_TTL_SECONDS,
    MAX_CACHE_TTL_SECONDS,
    McpReplayHintsError,
    build_stateless_replay_hints,
)


REQUEST_DIGEST = "a" * 64


def test_replay_hints_are_deterministic_and_client_only() -> None:
    response = {"result": {"marker": "FACTORY_MCP_STATUS", "value": 1}}
    first = build_stateless_replay_hints(REQUEST_DIGEST, response)
    second = build_stateless_replay_hints(REQUEST_DIGEST, response)

    assert first == second
    assert first["marker"] == "MCP_STATELESS_REPLAY_HINTS"
    assert first["requestKey"] == f"sha256:{REQUEST_DIGEST}"
    assert first["responseSha256"].startswith("sha256:")
    assert first["retry"] == {
        "safe": True,
        "scope": "one_request",
        "serverReplayStore": False,
        "duplicateExecution": False,
        "requiresFreshRequest": True,
    }
    assert first["cache"]["cacheable"] is True
    assert first["cache"]["ttlSeconds"] == DEFAULT_CACHE_TTL_SECONDS
    assert all(value is False for value in first["authority"].values())


def test_error_and_notification_responses_are_not_cacheable() -> None:
    error = build_stateless_replay_hints(REQUEST_DIGEST, {"error": {"code": -32601}})
    notification = build_stateless_replay_hints(REQUEST_DIGEST, None)

    for hints in (error, notification):
        assert hints["cache"]["cacheable"] is False
        assert hints["cache"]["ttlSeconds"] == 0


@pytest.mark.parametrize(
    "request_sha256",
    ["", "A" * 64, "a" * 63, "not-a-digest"],
)
def test_request_digest_is_strictly_bound(request_sha256: str) -> None:
    with pytest.raises(McpReplayHintsError):
        build_stateless_replay_hints(request_sha256, {"result": {}})


@pytest.mark.parametrize("ttl_seconds", [-1, MAX_CACHE_TTL_SECONDS + 1, True, 1.5])
def test_ttl_is_bounded_and_integer_only(ttl_seconds: object) -> None:
    with pytest.raises(McpReplayHintsError):
        build_stateless_replay_hints(REQUEST_DIGEST, {"result": {}}, ttl_seconds=ttl_seconds)  # type: ignore[arg-type]
