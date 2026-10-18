import copy
import hashlib

import pytest

from factoryline.credential_publication_excerpt import (
    PROFILE,
    digest,
    reviewed_excerpt_fact,
)
from factoryline import credential_publication_catalog as catalog


def sample():
    quote = "Token endpoint: https://issuer.example/oauth/token (POST)."
    raw = quote.encode()
    payload = {
        "document_profile": PROFILE,
        "value": "https://issuer.example/oauth/token",
        "capture": {
            "source_url": "https://publisher.example/docs",
            "final_url": "https://publisher.example/docs",
            "status": 200,
            "bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "observed_at": "2026-10-18T00:00:00Z",
            "https_profile": "urllib_default_certificate_verification",
            "redirect_policy": "reject_before_follow",
        },
        "excerpt": {
            "profile": "RAW_UTF8_BYTE_RANGE_V1",
            "quote_utf8": quote,
            "offset": 0,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
    }
    payload["review"] = {
        "decision": "ADMITTED_PROTOCOL_ENDPOINT_ONLY",
        "publisher_origin": "https://publisher.example",
        "fact_sha256": digest(payload),
        "review_sha256": "a" * 64,
        "publisher_and_endpoint_context_checked": True,
        "revoked": False,
    }
    return payload


def test_validated_review_record_does_not_claim_live_authentication_or_safety():
    fact = reviewed_excerpt_fact(sample())
    assert fact["value"] == "https://issuer.example/oauth/token"
    assert fact["raw_document_rederived_at_runtime"] is False
    assert fact["credential_safety"] == "UNASSESSED"
    assert "disposition" not in fact
    # A self-declared review record still cannot change the pinned shipped catalog.
    assert catalog.endpoint_publication(fact["value"]) is None


@pytest.mark.parametrize(
    "change",
    [
        "literal",
        "quote",
        "offset",
        "digest",
        "origin",
        "revoked",
        "decision",
        "profile",
        "redirect",
        "unchecked",
    ],
)
def test_mutated_or_unreviewed_record_is_rejected(change):
    row = copy.deepcopy(sample())
    if change == "literal":
        row["value"] += "/other"
    elif change == "quote":
        row["excerpt"]["quote_utf8"] += " altered"
    elif change == "offset":
        row["excerpt"]["offset"] = -1
    elif change == "digest":
        row["review"]["fact_sha256"] = "0" * 64
    elif change == "origin":
        row["review"]["publisher_origin"] = "https://other.example"
    elif change == "revoked":
        row["review"]["revoked"] = True
    elif change == "decision":
        row["review"]["decision"] = "SAFE"
    elif change == "profile":
        row["excerpt"]["profile"] = "HTML_DECODED_UNBOUND"
    elif change == "redirect":
        row["capture"]["final_url"] += "/elsewhere"
    else:
        row["review"]["publisher_and_endpoint_context_checked"] = False
    assert reviewed_excerpt_fact(row) is None


def test_review_assertion_is_untrusted_without_catalog_admission():
    row = sample()
    row["value"] = "https://issuer.example/private/capability-secret"
    quote = "Token endpoint: " + row["value"]
    raw = quote.encode()
    row["excerpt"].update(
        quote_utf8=quote, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
    )
    row["capture"].update(bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest())
    row["review"]["fact_sha256"] = digest(
        {k: v for k, v in row.items() if k != "review"}
    )
    assert reviewed_excerpt_fact(row)["credential_safety"] == "UNASSESSED"
    assert catalog.endpoint_publication(row["value"]) is None
