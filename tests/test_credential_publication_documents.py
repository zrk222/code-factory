"""Whole-document declarations require the separately pinned catalog bytes."""

import hashlib
import json

import pytest

from factoryline import credential_publication_catalog as catalog


def row(endpoint="https://issuer.example/oauth/token"):
    doc = {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {
                "OAuth": {
                    "type": "oauth2",
                    "flows": {
                        "clientCredentials": {"tokenUrl": endpoint, "scopes": {}}
                    },
                }
            }
        },
    }
    raw = json.dumps(doc).encode()
    return {
        "document_profile": "OPENAPI3_OAUTH2_TOKEN_URL_V1",
        "json_pointer": (
            "/components/securitySchemes/OAuth/flows/clientCredentials/tokenUrl"
        ),
        "document_utf8": raw.decode(),
        "capture": {
            "source_url": "https://publisher.example/api.json",
            "final_url": "https://publisher.example/api.json",
            "status": 200,
            "content_type": "application/json",
            "https_profile": "urllib_default_certificate_verification",
            "redirect_policy": "reject_before_follow",
            "bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        },
    }


def test_whole_openapi_document_yields_exact_pointer_fact_only():
    fact = catalog._entry(row())
    assert fact["value"] == "https://issuer.example/oauth/token"
    assert fact["document_profile"] == "OPENAPI3_OAUTH2_TOKEN_URL_V1"
    assert fact["credential_safety"] == "UNASSESSED"
    assert fact["runtime_assurance"] == "INCOMPLETE"
    assert "disposition" not in fact


@pytest.mark.parametrize(
    "mutation", ["pointer", "profile", "bytes", "hash", "redirect", "document"]
)
def test_changed_or_ambiguous_publication_capture_is_rejected(mutation):
    entry = row()
    if mutation == "pointer":
        entry["json_pointer"] += "/other"
    elif mutation == "profile":
        entry["document_profile"] = "UNTRUSTED_HTML"
    elif mutation == "bytes":
        entry["capture"]["bytes"] += 1
    elif mutation == "hash":
        entry["capture"]["raw_sha256"] = "0" * 64
    elif mutation == "redirect":
        entry["capture"]["final_url"] += "/redirected"
    else:
        entry["document_utf8"] += " "
    assert catalog._entry(entry) is None


def test_unreviewed_capture_cannot_enter_pinned_catalog_or_get_scanner_credit():
    entry = row("https://publisher.example/private/capability-secret")
    # Extraction is not admission. A crafted file must not satisfy the source pin.
    raw = json.dumps(
        {"schema": "factory.protocol-publication-catalog.v1", "entries": [entry]}
    ).encode()
    assert catalog._entry(entry)["credential_safety"] == "UNASSESSED"
    assert catalog._read(raw) == ()
    assert (
        catalog.endpoint_publication(
            "https://publisher.example/private/capability-secret"
        )
        is None
    )


def test_declared_fact_requires_entire_capture_not_endpoint_fragment():
    entry = row()
    entry["document_utf8"] = json.dumps(
        {"tokenUrl": "https://issuer.example/oauth/token"}
    )
    raw = entry["document_utf8"].encode()
    entry["capture"].update(bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest())
    assert catalog._entry(entry) is None
