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
    assert len(document["entries"]) == 24
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
    assert isinstance(snapshot, tuple) and len(snapshot) == 24
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
