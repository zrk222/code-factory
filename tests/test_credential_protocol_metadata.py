import json

import pytest

from factoryline.credential_protocol_metadata import (
    endpoint_metadata,
    matches_endpoint_declaration,
)


ISSUER = "https://issuer.example/tenant"
SOURCE = "https://issuer.example/.well-known/oauth-authorization-server/tenant"
ENDPOINT = "https://issuer.example/tenant/oauth/token"


def _raw(**changes):
    return json.dumps(
        {"issuer": ISSUER, "token_endpoint": ENDPOINT, **changes}
    ).encode()


def _parse(raw=None, source=SOURCE, issuer=ISSUER):
    return endpoint_metadata(
        _raw() if raw is None else raw, source_url=source, expected_issuer=issuer
    )


def test_metadata_binds_exact_values_and_retains_unverified_origin_boundary():
    raw = _raw()
    declaration = _parse(raw)
    assert declaration["origin_authenticity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert declaration["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert matches_endpoint_declaration(ENDPOINT, declaration, raw)
    for value in (ENDPOINT + "/", ENDPOINT + "/secret", ENDPOINT.upper()):
        assert not matches_endpoint_declaration(value, declaration, raw)


def test_oidc_path_and_rfc8414_path_are_distinct():
    assert _parse(source=ISSUER + "/.well-known/openid-configuration")
    assert _parse(source=ISSUER + "/.well-known/oauth-authorization-server") is None


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"not json",
        b"\xff",
        _raw(issuer=ISSUER + "/"),
        _raw(token_endpoint=ENDPOINT + "?client_secret=fixture"),
        _raw(token_endpoint="https://user:fixture@issuer.example/token"),
        _raw(token_endpoint="http://issuer.example/token"),
        _raw(token_endpoint=ENDPOINT + "#fragment"),
        _raw(token_endpoint=42),
        _raw(token_endpoint="https://issuer.example:bad/token"),
        _raw(token_endpoint="https://issuer.example/\\token"),
        _raw(token_endpoint="https://issuer.example/\ud800"),
        b'{"issuer":"https://issuer.example/tenant","token_endpoint":"a",'
        b'"token_endpoint":"https://issuer.example/token"}',
        b" " * 262145,
    ],
    ids=lambda raw: f"bytes-{len(raw)}",
)
def test_malformed_ambiguous_or_credential_bearing_metadata_fails_closed(raw):
    assert _parse(raw) is None


def test_wrong_origin_or_forged_record_does_not_match():
    assert (
        _parse(source="https://other.example/.well-known/openid-configuration") is None
    )
    record = _parse()
    record["value"] = ENDPOINT + "/secret"
    assert not matches_endpoint_declaration(record["value"], record, _raw())
    assert not matches_endpoint_declaration(ENDPOINT, _parse(), _raw(extra="changed"))


def test_publication_can_contain_a_path_token_without_becoming_a_safety_verdict():
    raw = _raw(token_endpoint="https://issuer.example/bot/fixture-credential/getMe")
    record = _parse(raw)
    assert record is not None
    assert record["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
