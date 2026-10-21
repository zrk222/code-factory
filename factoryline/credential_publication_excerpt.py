"""Validate pinned, historically reviewed excerpt facts; never fetch documents."""

import hashlib
import json
import re
from urllib.parse import urlsplit

from .credential_publication_catalog import _public_https

PROFILE = "REVIEWED_PROTOCOL_PUBLICATION_V1"


def digest(value):
    """Compute a stable SHA-256 digest for JSON-compatible evidence using sorted keys and compact separators."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _sha(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _https(value):
    return _public_https(value) and not any(c in value for c in "?#")


def _excerpt_valid(excerpt, value, capture):
    if (
        not isinstance(excerpt, dict)
        or excerpt.get("profile") != "RAW_UTF8_BYTE_RANGE_V1"
    ):
        return False
    quote = excerpt.get("quote_utf8")
    if not isinstance(quote, str) or value not in quote:
        return False
    try:
        raw = quote.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    offset, count = excerpt.get("offset"), capture.get("bytes")
    return bool(
        0 < len(raw) <= 8192
        and type(offset) is int
        and offset >= 0
        and type(count) is int
        and 0 < count <= 8 * 1024 * 1024
        and offset + len(raw) <= count
        and excerpt.get("bytes") == len(raw)
        and excerpt.get("sha256") == hashlib.sha256(raw).hexdigest()
    )


def reviewed_excerpt_fact(row):
    """Read a historical review assertion, requiring the caller's catalog pin.

    This cannot rederive a quotation from an omitted full document or establish
    publisher authenticity. Only the reviewed source/data change admitting the
    exact pinned catalog supplies that trust. An unpinned row grants no credit.
    """
    if not isinstance(row, dict) or row.get("document_profile") != PROFILE:
        return None
    value, capture, review = row.get("value"), row.get("capture"), row.get("review")
    if (
        not _https(value)
        or not isinstance(capture, dict)
        or not isinstance(review, dict)
    ):
        return None
    source = capture.get("source_url")
    if not (
        _https(source)
        and source == capture.get("final_url")
        and capture.get("status") == 200
        and _sha(capture.get("raw_sha256"))
        and isinstance(capture.get("observed_at"), str)
        and capture["observed_at"]
        and capture.get("https_profile") == "urllib_default_certificate_verification"
        and capture.get("redirect_policy") == "reject_before_follow"
    ):
        return None
    if not _excerpt_valid(row.get("excerpt"), value, capture):
        return None
    parsed = urlsplit(source)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    payload = {key: val for key, val in row.items() if key != "review"}
    if not (
        review.get("decision") == "ADMITTED_PROTOCOL_ENDPOINT_ONLY"
        and review.get("publisher_origin") == origin
        and review.get("fact_sha256") == digest(payload)
        and _sha(review.get("review_sha256"))
        and review.get("publisher_and_endpoint_context_checked") is True
        and review.get("revoked") is False
    ):
        return None
    return {
        "schema": "factory.protocol-endpoint-declaration.v1",
        "document_profile": PROFILE,
        "field": "reviewed_protocol_endpoint",
        "value": value,
        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "source_url": source,
        "metadata_sha256": capture["raw_sha256"],
        "review_sha256": review["review_sha256"],
        "fact_sha256": review["fact_sha256"],
        "publication_basis": "reviewed_historical_publication_excerpt",
        "raw_document_rederived_at_runtime": False,
        "credential_safety": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
    }
