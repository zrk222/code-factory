"""Extract endpoint declarations from whole standard documents, without trust."""

import hashlib
import json
import re

from .credential_publication_catalog import _public_https, _unique_object

MAX_DOCUMENT_BYTES = 1_048_576
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 48
MAX_DECLARATIONS = 128
_FLOWS = frozenset({"authorizationCode", "clientCredentials", "password"})


def _invalid_constant(value):
    raise ValueError("nonstandard JSON constant")


def _https(value):
    return (
        _public_https(value)
        and not any(c in value for c in "?#")
        and not re.search(r"%(?![0-9a-fA-F]{2})", value)
    )


def _document(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_DOCUMENT_BYTES:
        return None
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        return None
    pending, count = [(document, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            return None
        if isinstance(value, dict):
            pending.extend(
                (child, depth + 1) for pair in value.items() for child in pair
            )
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeError:
                return None
    return document if isinstance(document, dict) else None


def _flow_rows(name, scheme):
    if not isinstance(scheme, dict) or "$ref" in scheme:
        return None
    if scheme.get("type") != "oauth2":
        return []
    flows = scheme.get("flows")
    if not isinstance(flows, dict) or not flows:
        return None
    rows = []
    for flow_name, flow in flows.items():
        if not _valid_flow(flow_name, flow):
            return None
        if flow_name != "implicit":
            rows.append((name, flow_name, flow["tokenUrl"]))
    return rows


def _valid_flow(name, flow):
    if name not in _FLOWS | {"implicit"} or not isinstance(flow, dict):
        return False
    scopes = flow.get("scopes")
    if "$ref" in flow or not isinstance(scopes, dict):
        return False
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in scopes.items()):
        return False
    if name in {"authorizationCode", "implicit"} and not _https(
        flow.get("authorizationUrl")
    ):
        return False
    if name == "implicit":
        return "tokenUrl" not in flow
    return bool(_https(flow.get("tokenUrl")))


def openapi_endpoint_declarations(raw, *, source_url):
    """Read OpenAPI 3 OAuth tokenUrl facts; never fetch, admit, or clear alerts.

    The caller must establish publisher identity and independently admit the
    complete captured document. Source URL validity alone grants no trust.
    Relative URLs and references are deliberately unsupported, not resolved.
    """
    if not _https(source_url):
        return None
    document = _document(raw)
    if document is None:
        return None
    version = document.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.[01]\.[0-9]+", version):
        return None
    components = document.get("components")
    if not isinstance(components, dict) or "$ref" in components:
        return None
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict) or not schemes or len(schemes) > 128:
        return None
    rows = []
    for name, scheme in schemes.items():
        extracted = _flow_rows(name, scheme)
        if extracted is None:
            return None
        rows.extend(extracted)
        if len(rows) > MAX_DECLARATIONS:
            return None
    digest = hashlib.sha256(raw).hexdigest()
    return tuple(
        {
            "schema": "factory.protocol-endpoint-declaration.v1",
            "document_profile": "OPENAPI3_OAUTH2_TOKEN_URL_V1",
            "json_pointer": "/components/securitySchemes/"
            + name.replace("~", "~0").replace("/", "~1")
            + "/flows/"
            + flow
            + "/tokenUrl",
            "field": "tokenUrl",
            "value": endpoint,
            "value_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
            "source_url": source_url,
            "metadata_sha256": digest,
            "security_scheme": name,
            "flow": flow,
            "origin_authenticity": "NOT_ESTABLISHED_BY_PARSER",
            "credential_safety": "NOT_ESTABLISHED_BY_PARSER",
        }
        for name, flow, endpoint in rows
    )


def matches_openapi_endpoint(value, declaration, raw):
    """Rederive the complete fact from exact document bytes before equality."""
    if not isinstance(declaration, dict) or not isinstance(value, str):
        return False
    rows = openapi_endpoint_declarations(raw, source_url=declaration.get("source_url"))
    return rows is not None and any(
        row == declaration and row["value"] == value for row in rows
    )
