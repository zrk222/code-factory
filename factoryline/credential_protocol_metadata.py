"""Parse independent OAuth metadata; declarations alone never clear findings."""

import hashlib
import json
from urllib.parse import urlsplit


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _public_https(value):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        return False
    try:
        value.encode("utf-8", errors="strict")
        url = urlsplit(value)
        url.port
        return bool(
            url.scheme == "https"
            and url.hostname
            and url.username is None
            and url.password is None
            and not url.fragment
            and not url.query
            and "\\" not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
        )
    except (ValueError, UnicodeError):
        return False


def endpoint_metadata(raw, *, source_url, expected_issuer):
    """Return exact token-endpoint declarations, not authenticity/safety verdicts.

    The caller must independently establish the metadata origin. This pure,
    bounded parser does not fetch URLs, follow redirects, normalize endpoint
    values, grant trust, or decide whether a credential finding is actionable.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 262144:
        return None
    if not _public_https(expected_issuer) or not _public_https(source_url):
        return None
    issuer = urlsplit(expected_issuer)
    allowed_sources = {
        expected_issuer.rstrip("/") + "/.well-known/openid-configuration",
        f"{issuer.scheme}://{issuer.netloc}/.well-known/oauth-authorization-server"
        + issuer.path.rstrip("/"),
    }
    if source_url not in allowed_sources:
        return None
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(document, dict) or document.get("issuer") != expected_issuer:
        return None
    endpoint = document.get("token_endpoint")
    if not _public_https(endpoint):
        return None
    return {
        "schema": "factory.protocol-endpoint-declaration.v1",
        "field": "token_endpoint",
        "value": endpoint,
        "value_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
        "issuer": expected_issuer,
        "source_url": source_url,
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
        "origin_authenticity": "NOT_ESTABLISHED_BY_PARSER",
        "credential_safety": "NOT_ESTABLISHED_BY_PARSER",
    }


def matches_endpoint_declaration(value, declaration, raw):
    """Re-derive every field before exact matching; no prefix/path equivalence."""
    if not isinstance(declaration, dict) or not isinstance(value, str):
        return False
    verified = endpoint_metadata(
        raw,
        source_url=declaration.get("source_url"),
        expected_issuer=declaration.get("issuer"),
    )
    return (
        verified is not None and verified == declaration and value == verified["value"]
    )
