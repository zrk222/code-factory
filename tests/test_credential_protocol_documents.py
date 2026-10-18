import json

import pytest

from factoryline.credential_protocol_documents import (
    matches_openapi_endpoint,
    openapi_endpoint_declarations,
)

SOURCE = "https://publisher.example/openapi.json"
ENDPOINT = "https://auth.example/oauth/token"


def document(endpoint=ENDPOINT):
    return {
        "openapi": "3.0.3",
        "components": {
            "securitySchemes": {
                "OAuth": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "tokenUrl": endpoint,
                            "authorizationUrl": "https://auth.example/authorize",
                            "scopes": {},
                        }
                    },
                }
            }
        },
    }


def encode(value):
    return json.dumps(value).encode()


def test_whole_document_extracts_exact_standard_role_without_granting_trust():
    raw = encode(document())
    rows = openapi_endpoint_declarations(raw, source_url=SOURCE)
    assert len(rows) == 1
    assert rows[0]["value"] == ENDPOINT
    assert rows[0]["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert rows[0]["origin_authenticity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert matches_openapi_endpoint(ENDPOINT, rows[0], raw)
    assert not matches_openapi_endpoint(ENDPOINT + "/", rows[0], raw)


@pytest.mark.parametrize(
    "endpoint",
    [
        "/oauth/token",
        "http://auth.example/token",
        "https://u:p@auth.example/token",
        "https://auth.example/token?secret=x",
        "https://auth.example/token#secret",
        "https://auth.example:bad/token",
        "https://auth.example/\\token",
        None,
    ],
)
def test_unsafe_or_unsupported_url_is_not_a_publication_fact(endpoint):
    assert (
        openapi_endpoint_declarations(encode(document(endpoint)), source_url=SOURCE)
        is None
    )


def test_opaque_capability_path_is_only_a_declaration_never_safety_evidence():
    raw = encode(document("https://auth.example/private/capability-abc123"))
    rows = openapi_endpoint_declarations(raw, source_url=SOURCE)
    assert rows[0]["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert "disposition" not in rows[0]


@pytest.mark.parametrize(
    "mutation", ["reference", "duplicate", "wrong_type", "version", "flow", "scopes"]
)
def test_ambiguous_documents_fail_closed(mutation):
    doc = document()
    scheme = doc["components"]["securitySchemes"]["OAuth"]
    if mutation == "reference":
        scheme["$ref"] = "https://elsewhere.example/schema"
    elif mutation == "duplicate":
        raw = encode(doc).replace(
            b'"tokenUrl":', b'"tokenUrl":"https://evil.example", "tokenUrl":'
        )
        assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None
        return
    elif mutation == "wrong_type":
        doc["components"]["securitySchemes"] = []
    elif mutation == "version":
        doc["openapi"] = "2.0"
    elif mutation == "flow":
        scheme["flows"] = {"unknown": {"tokenUrl": ENDPOINT, "scopes": {}}}
    else:
        scheme["flows"]["authorizationCode"]["scopes"] = []
    assert openapi_endpoint_declarations(encode(doc), source_url=SOURCE) is None


def test_forged_fact_and_changed_document_do_not_match():
    raw = encode(document())
    row = openapi_endpoint_declarations(raw, source_url=SOURCE)[0]
    assert not matches_openapi_endpoint(
        ENDPOINT, {**row, "credential_safety": "SAFE"}, raw
    )
    assert not matches_openapi_endpoint(
        ENDPOINT, row, encode(document("https://other.example/token"))
    )


def test_size_and_node_budgets_fail_closed(monkeypatch):
    import factoryline.credential_protocol_documents as parser

    raw = encode(document())
    monkeypatch.setattr(parser, "MAX_DOCUMENT_BYTES", len(raw) - 1)
    assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None
    monkeypatch.setattr(parser, "MAX_DOCUMENT_BYTES", len(raw) + 1)
    monkeypatch.setattr(parser, "MAX_DOCUMENT_NODES", 2)
    assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None


def test_multiple_flows_and_schemes_preserve_exact_provenance():
    doc = document()
    schemes = doc["components"]["securitySchemes"]
    schemes["OAuth"]["flows"]["clientCredentials"] = {
        "tokenUrl": ENDPOINT,
        "scopes": {},
    }
    schemes["Basic"] = {"type": "http", "scheme": "basic"}
    rows = openapi_endpoint_declarations(encode(doc), source_url=SOURCE)
    assert len(rows) == 2
    assert {r["flow"] for r in rows} == {"authorizationCode", "clientCredentials"}


@pytest.mark.parametrize(
    "mutation",
    [
        "empty_query",
        "empty_fragment",
        "nan",
        "surrogate",
        "missing_authorize",
        "bad_scopes",
        "deep",
        "ref_sibling",
        "implicit",
    ],
)
def test_reviewer_document_boundary_controls(mutation):
    doc = document()
    flow = doc["components"]["securitySchemes"]["OAuth"]["flows"]["authorizationCode"]
    if mutation == "empty_query":
        flow["tokenUrl"] += "?"
    elif mutation == "empty_fragment":
        flow["tokenUrl"] += "#"
    elif mutation == "nan":
        doc["extra"] = float("nan")
    elif mutation == "surrogate":
        doc["extra"] = "\ud800"
    elif mutation == "missing_authorize":
        flow.pop("authorizationUrl")
    elif mutation == "bad_scopes":
        flow["scopes"] = {"read": 123}
    elif mutation == "deep":
        for _ in range(60):
            doc = {"nested": doc}
    elif mutation == "ref_sibling":
        flow["$ref"] = "https://other.example/doc"
    else:
        doc["components"]["securitySchemes"]["OAuth"]["flows"] = {"implicit": flow}
    assert openapi_endpoint_declarations(encode(doc), source_url=SOURCE) is None
