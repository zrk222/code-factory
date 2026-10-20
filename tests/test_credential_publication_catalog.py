import hashlib
from importlib import resources
import json

import pytest

from factoryline import credential_publication_catalog as catalog


def _raw():
    return (
        resources.files("factoryline")
        .joinpath("data/protocol_publications.json")
        .read_bytes()
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://cloud.digitalocean.com/v1/oauth/token",
        "https://appleid.apple.com/auth/token",
        "https://id.twitch.tv/oauth2/token",
        "https://api.login.yahoo.com/oauth2/get_token",
        "https://api.hubapi.com/oauth/v1/token",
        "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        "https://oauth.yandex.com/token",
        "https://open.feishu.cn/open-apis/authen/v1/access_token",
        "https://auth.dataporten.no/oauth/token",
    ],
)
def test_exact_publications_are_offline_facts_not_safety(value, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("catalog lookup must not connect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    fact = catalog.endpoint_publication(value)
    assert fact["value"] == value
    assert fact["catalog_sha256"] == hashlib.sha256(_raw()).hexdigest()
    assert fact["credential_safety"] == "UNASSESSED"
    assert fact["runtime_assurance"] == "INCOMPLETE"
    assert "disposition" not in fact


@pytest.mark.parametrize(
    "value",
    [
        "https://appleid.apple.com/auth/token/",
        "https://appleid.apple.com/auth/token?secret=credential",
        "https://appleid.apple.com/auth/token/credential",
        "https://name:credential@appleid.apple.com/auth/token",
        "https://api.telegram.org/botliteral-credential/getMe",
        "https://appleid.apple.com/auth/{token}",
        "https://appleid.apple.com/auth/",
        "HTTPS://appleid.apple.com/auth/token",
        "https://appleid.apple.com/auth/token#fragment",
        "https://oauth.yandex.com/token/",
        "https://open.feishu.cn/open-apis/authen/v1/access_token/",
        "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/",
        "https://auth.dataporten.no/oauth/token/",
        "https://auth.dataporten.no/oauth/token?secret=credential",
        None,
    ],
)
def test_no_prefix_template_normalization_or_url_credential_exemptions(value):
    assert catalog.endpoint_publication(value) is None


def test_corruption_or_missing_resource_is_not_a_publication(monkeypatch):
    assert catalog._read(_raw() + b" ") == ()
    assert catalog._read(b"x" * 1048577) == ()
    assert catalog._read(None) == ()

    class Missing:
        def joinpath(self, *args):
            return self

        def open(self, *args):
            raise FileNotFoundError("missing data")

    monkeypatch.setattr(catalog.resources, "files", lambda *args: Missing())
    assert catalog.endpoint_publication("https://appleid.apple.com/auth/token") is None


def test_raw_metadata_and_capture_are_revalidated():
    row = json.loads(_raw())["entries"][0]
    row["document_utf8"] += " "
    assert catalog._entry(row) is None
    row = json.loads(_raw())["entries"][0]
    row["capture"]["redirect_policy"] = "follow"
    assert catalog._entry(row) is None
    row = json.loads(_raw())["entries"][0]
    row["capture"]["final_url"] += "/other"
    assert catalog._entry(row) is None


def test_catalog_contains_publication_data_only():
    raw = _raw()
    document = json.loads(raw)
    assert (
        document["admission"]["decision"] == "ADMITTED_PUBLIC_PROTOCOL_PUBLICATION_ONLY"
    )
    assert len(document["entries"]) == 27
    assert not any(
        term in raw
        for term in (
            b"case_id",
            b"raw_ids",
            b"packet_id",
            b"repository",
            b"adjudication_label",
        )
    )


def test_batch_snapshot_has_immutable_facts():
    snapshot = catalog.endpoint_publications()
    assert isinstance(snapshot, tuple) and len(snapshot) == 27
    with pytest.raises(TypeError):
        snapshot[0]["value"] = "changed"
    assert catalog.endpoint_publication(snapshot[0]["value"]) == dict(snapshot[0])


def test_catalog_data_changes_invalidate_native_context_cache_key(
    tmp_path, monkeypatch
):
    import io
    from factoryline.review_audits import _oracle_context_cache_key

    before = _oracle_context_cache_key(tmp_path, [], {})
    raw = _raw()

    class Changed:
        def joinpath(self, *args):
            return self

        def open(self, *args):
            return io.BytesIO(raw + b" ")

    monkeypatch.setattr(catalog.resources, "files", lambda *args: Changed())
    after = _oracle_context_cache_key(tmp_path, [], {})
    assert before != after
    assert catalog.endpoint_publications() == ()


@pytest.mark.parametrize(
    "name",
    [
        "_unique_object",
        "_public_https",
        "endpoint_metadata",
        "matches_endpoint_declaration",
    ],
)
def test_moved_parser_callables_invalidate_native_context_cache_key(
    tmp_path, monkeypatch, name
):
    from factoryline.review_audits import _oracle_context_cache_key

    before = _oracle_context_cache_key(tmp_path, [], {})
    original = getattr(catalog, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(catalog, name, replacement)
    after = _oracle_context_cache_key(tmp_path, [], {})
    assert before != after


ISSUER = "https://issuer.example/tenant"
SOURCE = "https://issuer.example/.well-known/oauth-authorization-server/tenant"
ENDPOINT = "https://issuer.example/tenant/oauth/token"


def _metadata_raw(**changes):
    return json.dumps(
        {"issuer": ISSUER, "token_endpoint": ENDPOINT, **changes}
    ).encode()


def _parse(raw=None, source=SOURCE, issuer=ISSUER):
    return catalog.endpoint_metadata(
        _metadata_raw() if raw is None else raw,
        source_url=source,
        expected_issuer=issuer,
    )


def test_metadata_binds_exact_values_and_retains_unverified_origin_boundary():
    raw = _metadata_raw()
    declaration = _parse(raw)
    assert declaration["origin_authenticity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert declaration["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert catalog.matches_endpoint_declaration(ENDPOINT, declaration, raw)
    for value in (ENDPOINT + "/", ENDPOINT + "/secret", ENDPOINT.upper()):
        assert not catalog.matches_endpoint_declaration(value, declaration, raw)


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
        _metadata_raw(issuer=ISSUER + "/"),
        _metadata_raw(token_endpoint=ENDPOINT + "?client_secret=fixture"),
        _metadata_raw(token_endpoint="https://user:fixture@issuer.example/token"),
        _metadata_raw(token_endpoint="http://issuer.example/token"),
        _metadata_raw(token_endpoint=ENDPOINT + "#fragment"),
        _metadata_raw(token_endpoint=42),
        _metadata_raw(token_endpoint="https://issuer.example:bad/token"),
        _metadata_raw(token_endpoint="https://issuer.example/\\token"),
        _metadata_raw(token_endpoint="https://issuer.example/\ud800"),
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
    assert not catalog.matches_endpoint_declaration(
        record["value"], record, _metadata_raw()
    )
    assert not catalog.matches_endpoint_declaration(
        ENDPOINT, _parse(), _metadata_raw(extra="changed")
    )


def test_publication_can_contain_a_path_token_without_becoming_a_safety_verdict():
    raw = _metadata_raw(
        token_endpoint="https://issuer.example/bot/fixture-credential/getMe"
    )
    record = _parse(raw)
    assert record is not None
    assert record["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
