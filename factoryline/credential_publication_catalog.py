"""Read reviewed, offline protocol-publication facts; never grant safety."""

import hashlib
from importlib import resources
import json

from .credential_protocol_metadata import endpoint_metadata, _unique_object

CATALOG_SHA256 = "b185932f6eb38882b691ae79da885e1ffdabac38f5a9e44a587d654b51015613"


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _entry(row):
    if not isinstance(row, dict):
        return None
    capture = row.get("capture", {})
    document = row.get("document_utf8")
    if not isinstance(document, str):
        return None
    raw = document.encode("utf-8")
    if not (
        capture.get("source_url") == capture.get("final_url")
        and capture.get("status") == 200
        and capture.get("content_type") == "application/json"
        and capture.get("https_profile") == "urllib_default_certificate_verification"
        and capture.get("redirect_policy") == "reject_before_follow"
        and capture.get("bytes") == len(raw)
        and capture.get("raw_sha256") == _digest(raw)
    ):
        return None
    declaration = endpoint_metadata(
        raw, source_url=capture.get("source_url"), expected_issuer=row.get("issuer")
    )
    if declaration is None:
        return None
    return {
        **declaration,
        "catalog_sha256": CATALOG_SHA256,
        "capture_sha256": _digest(
            json.dumps(capture, sort_keys=True, separators=(",", ":")).encode()
        ),
        "publication_basis": "reviewed_packaged_https_capture",
        "credential_safety": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
    }


def _read(raw):
    if (
        not isinstance(raw, bytes)
        or len(raw) > 1048576
        or _digest(raw) != CATALOG_SHA256
    ):
        return ()
    try:
        catalog = json.loads(raw, object_pairs_hook=_unique_object)
        if catalog.get("schema") != "factory.protocol-publication-catalog.v1":
            return ()
        rows = catalog.get("entries")
        if not isinstance(rows, list) or not 0 < len(rows) <= 128:
            return ()
        facts = [_entry(row) for row in rows]
        if any(fact is None for fact in facts):
            return ()
        return tuple(facts)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return ()


def endpoint_publication(value):
    """Exact published endpoint equality; no prefix/template or safety verdict."""
    if not isinstance(value, str):
        return None
    try:
        raw = (
            resources.files("factoryline")
            .joinpath("data/protocol_publications.json")
            .read_bytes()
        )
    except (OSError, ValueError):
        return None
    matches = [fact for fact in _read(raw) if fact["value"] == value]
    return dict(matches[0]) if len(matches) == 1 else None
