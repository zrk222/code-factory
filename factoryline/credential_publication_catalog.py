"""Read reviewed, offline protocol-publication facts; never grant safety."""

import hashlib
from importlib import resources
import json

from .credential_protocol_metadata import endpoint_metadata, _unique_object

CATALOG_SHA256 = "192d6386503ec5d346bb94fef5b348d46dd755b34913e37415a25f6629af95bc"


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _entry(row):
    if not isinstance(row, dict):
        return None
    if row.get("document_profile") == "REVIEWED_PROTOCOL_PUBLICATION_V1":
        return _reviewed_entry(row)
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
    declaration = _declaration(row, raw, capture.get("source_url"))
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


def _reviewed_entry(row):
    from .credential_publication_excerpt import reviewed_excerpt_fact

    fact = reviewed_excerpt_fact(row)
    return {**fact, "catalog_sha256": CATALOG_SHA256} if fact else None


def _declaration(row, raw, source_url):
    profile = row.get("document_profile")
    if profile is None:
        return endpoint_metadata(
            raw, source_url=source_url, expected_issuer=row.get("issuer")
        )
    if profile != "OPENAPI3_OAUTH2_TOKEN_URL_V1":
        return None
    from .credential_protocol_documents import openapi_endpoint_declarations

    declarations = openapi_endpoint_declarations(raw, source_url=source_url)
    selected = [
        fact
        for fact in declarations or ()
        if fact["json_pointer"] == row.get("json_pointer")
    ]
    return selected[0] if len(selected) == 1 else None


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


def _catalog_bytes():
    try:
        resource = resources.files("factoryline").joinpath(
            "data/protocol_publications.json"
        )
        with resource.open("rb") as stream:
            raw = stream.read(1048577)
    except (OSError, ValueError):
        return None
    return raw


def catalog_content_digest():
    """Fresh data identity for native context caches, including corrupt/missing data."""
    raw = _catalog_bytes()
    return _digest(raw) if raw is not None else "MISSING"


def endpoint_publications():
    """Read one immutable historical publication snapshot; never a safety verdict."""
    from types import MappingProxyType

    return tuple(MappingProxyType(fact) for fact in _read(_catalog_bytes()))


def endpoint_publication(value):
    """Exact published endpoint equality; no prefix/template or safety verdict."""
    if not isinstance(value, str):
        return None
    matches = [fact for fact in endpoint_publications() if fact["value"] == value]
    return dict(matches[0]) if len(matches) == 1 else None
