"""Exercise actual source derivation and scanner output, with no mocked proofs."""

import pytest
from factoryline.review_audits import security_scan
import copy
import json
from factoryline import credential_endpoint_admission as evidence
from factoryline.credential_endpoint_admission import endpoint_publication
from test_runtime_audit_integrity import _JSON_CLIENT, _JSON_TEST, _json_enum_graph
import hashlib
from factoryline import credential_endpoint_admission as catalog
from factoryline.credential_endpoint_admission import (
    PROFILE,
    digest,
    reviewed_excerpt_fact,
)

ENDPOINT = "https://appleid.apple.com/auth/token"


def _write(root, extra=""):
    (root / "client.py").write_text(
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {ENDPOINT!r}\n"
        "    def send(self):\n"
        "        return requests.get(self.ACCESS_TOKEN_URL)\n" + extra,
        encoding="utf-8",
    )


def _secrets(result, primitive=False):
    key = "primitive_observations" if primitive else "findings"
    return [f for f in result.get(key, []) if f["code"] == "SECURITY_HARDCODED_SECRET"]


@pytest.mark.parametrize("cache", [False, True])
def test_actual_complete_role_partitions_only_heuristic_and_preserves_priority(
    tmp_path, cache
):
    _write(tmp_path)
    for _ in range(2):
        result = security_scan(tmp_path, cache_enabled=cache)
        assert not _secrets(result)
        observations = _secrets(result, primitive=True)
        assert len(observations) == 1
        assert observations[0]["severity"] == "CRITICAL"
        facts = observations[0]["facts"]
        assert facts["disposition"] == "ENDPOINT_DECLARATION_ROLE_PROVEN"
        assert facts["value_use_audit"]["state"] == "COMPLETE"
        assert facts["runtime_assurance"] == "INCOMPLETE"
        assert facts["credential_safety"] == "UNASSESSED"


@pytest.mark.parametrize(
    "extra",
    [
        "    def auth(self):\n"
        "        requests.get('https://example.test', auth=('u', self.ACCESS_TOKEN_URL))\n",
        "    def auth(self):\n"
        "        requests.get(self.ACCESS_TOKEN_URL, auth=opaque(self.ACCESS_TOKEN_URL))\n",
        "    def escape(self):\n        consume(self.ACCESS_TOKEN_URL)\n",
        "class Child(Client):\n    pass\n"
        "requests.get('https://example.test', auth=('u', Child.ACCESS_TOKEN_URL))\n",
        "consume(getattr(Client, 'ACCESS_TOKEN_URL'))\n",
        "Alias = Client\n"
        "requests.get('https://example.test', auth=('u', Alias.ACCESS_TOKEN_URL))\n",
        "instance = Client()\nconsume(instance.ACCESS_TOKEN_URL)\n",
        "import builtins\nconsume(builtins.getattr(Client, 'ACCESS_TOKEN_URL'))\n",
        "from builtins import getattr as read\nconsume(read(Client, 'ACCESS_TOKEN_URL'))\n",
    ],
)
def test_actual_mixed_or_unresolved_use_keeps_original_critical(tmp_path, extra):
    _write(tmp_path, extra)
    result = security_scan(tmp_path, cache_enabled=False)
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["line"] == 3
    assert not _secrets(result, primitive=True)


def test_source_change_invalidates_both_context_and_role_projection(tmp_path):
    _write(tmp_path)
    first = security_scan(tmp_path, cache_enabled=True)
    assert len(_secrets(first, primitive=True)) == 1
    _write(tmp_path, "    def escape(self):\n        consume(self.ACCESS_TOKEN_URL)\n")
    second = security_scan(tmp_path, cache_enabled=True)
    assert len(_secrets(second)) == 1
    assert not _secrets(second, primitive=True)


def test_real_credential_positive_is_retained_at_original_priority(tmp_path):
    _write(tmp_path, "PASSWORD = 'synthetic-fixed-credential-control'\n")
    result = security_scan(tmp_path, cache_enabled=False)
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["facts"]["name"] == "PASSWORD"
    assert alerts[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "mutation",
    [
        "requests.get = supplied",
        "setattr(requests, 'get', supplied)",
    ],
)
def test_mutated_http_provider_cannot_supply_endpoint_proof(tmp_path, mutation):
    _write(tmp_path, mutation + "\n")
    result = security_scan(tmp_path, cache_enabled=False)
    assert len(_secrets(result)) == 1
    assert not _secrets(result, primitive=True)


def test_omitted_oversized_auth_consumer_keeps_original_credential_alert(
    tmp_path, monkeypatch
):
    from factoryline import review_audits as scanner

    _write(tmp_path)
    monkeypatch.setattr(scanner, "MAX_BYTES", 500)
    hidden = "from client import Client\n" + "#" * 501 + "\n"
    hidden += (
        "import requests\nrequests.get('https://other.example', "
        "auth=('u', Client.ACCESS_TOKEN_URL))\n"
    )
    (tmp_path / "hidden.py").write_text(hidden, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["audit_coverage"]["complete"] is False
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert not _secrets(result, primitive=True)


# --- Merged from test_credential_endpoint_escape_controls.py; test definitions and fixtures retained ---
"""Candidate-linked unsupported shapes must retain the credential heuristic."""


@pytest.mark.parametrize(
    "extra",
    [
        "aliases = [Client]\n"
        "requests.get('https://example.test', auth=('u', aliases[0].ACCESS_TOKEN_URL))\n",
        "registry = {'client': Client}\nconsume(registry['client'].ACCESS_TOKEN_URL)\n",
    ],
)
def test_candidate_escape_is_unresolved(tmp_path, extra):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "class Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n"
        "        requests.get(self.ACCESS_TOKEN_URL)\n" + extra,
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in result["findings"])


def test_local_provider_mutation_cannot_supply_url_role(tmp_path):
    (tmp_path / "app.py").write_text(
        "class Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n"
        "        import requests as local\n"
        "        local.get = supplied\n"
        "        local.get(self.ACCESS_TOKEN_URL)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in result["findings"])


# --- Merged from test_credential_endpoint_evidence.py; test definitions and fixtures retained ---


def _case(**overrides):
    sources = [{"path": "source.py", "sha256": "a" * 64}]
    bindings = {row["path"]: row["sha256"] for row in sources}
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "source.py",
        "line": 2,
        "column": 4,
        "severity": "CRITICAL",
        "message": "original",
    }
    facts = {
        "schema": "factory.public-protocol-endpoint.v1",
        "disposition": "ENDPOINT_DECLARATION_ROLE_PROVEN",
        "flow_profile": "DECLARED_CLASS_MAY_FLOW",
        "runtime_assurance": "INCOMPLETE",
        "credential_safety": "UNASSESSED",
        "source_path": "source.py",
        "source_sha256": "a" * 64,
        "workspace_sources_sha256": evidence._digest(sorted(bindings.items())),
        "known_auth_uses": [],
        "linked_unknown_uses": [],
        "publication": endpoint_publication("https://appleid.apple.com/auth/token"),
        **overrides,
    }
    finding["facts"] = evidence.mint_endpoint_facts(facts, finding, bindings)
    return finding, sources, bindings


def test_native_marker_validates_only_current_bound_facts():
    finding, sources, bindings = _case()
    assert evidence.endpoint_binding(finding, sources, bindings)
    assert finding["severity"] == "CRITICAL"
    assert finding["facts"]["credential_safety"] == "UNASSESSED"


def test_json_roundtrip_and_plain_self_hashed_forgeries_have_no_native_marker():
    finding, sources, bindings = _case()
    document = json.loads(json.dumps(finding))
    document["facts"]["proof_facts_sha256"] = evidence._digest(document["facts"])
    assert not evidence.endpoint_binding(document, sources, bindings)
    assert not evidence.endpoint_binding(copy.deepcopy(finding), sources, bindings)
    assert not evidence.endpoint_binding(
        {**finding, "facts": copy.copy(finding["facts"])}, sources, bindings
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "other.py"),
        ("line", 3),
        ("column", 5),
        ("code", "OTHER"),
        ("severity", "INFO"),
        ("message", "changed"),
    ],
)
def test_finding_identity_changes_invalidate_native_marker(field, value):
    finding, sources, bindings = _case()
    finding[field] = value
    assert not evidence.endpoint_binding(finding, sources, bindings)


def test_fact_or_attestation_mutation_cannot_keep_validation():
    finding, sources, bindings = _case()
    finding["facts"]["source_sha256"] = "b" * 64
    assert not evidence.endpoint_binding(finding, sources, bindings)
    with pytest.raises(AttributeError):
        finding["facts"]._attestation = ()
    with pytest.raises(ValueError):
        evidence._NativeEndpointFacts({}, finding, bindings, object())


def test_stale_or_expanded_source_inventory_is_rejected():
    finding, sources, bindings = _case()
    assert not evidence.endpoint_binding(finding, sources, {"source.py": "b" * 64})
    extra = {"path": "new_consumer.py", "sha256": "b" * 64}
    assert not evidence.endpoint_binding(
        finding, sources + [extra], {**bindings, extra["path"]: extra["sha256"]}
    )
    assert not evidence.endpoint_binding(finding, sources + sources, bindings)


@pytest.mark.parametrize(
    "overrides",
    [
        {"known_auth_uses": [{"slot": "password"}]},
        {"linked_unknown_uses": [{"reason": "unresolved_value_escape"}]},
        {"credential_safety": "SAFE"},
        {"runtime_assurance": "VERIFIED"},
    ],
)
def test_mixed_or_unknown_uses_and_inflated_claims_are_never_admitted(overrides):
    finding, sources, bindings = _case(**overrides)
    assert not evidence.endpoint_binding(finding, sources, bindings)
    assert finding["severity"] == "CRITICAL"


def test_publication_is_revalidated_even_with_native_marker(monkeypatch):
    finding, sources, bindings = _case()
    monkeypatch.setattr(evidence, "endpoint_publication", lambda value: None)
    assert not evidence.endpoint_binding(finding, sources, bindings)


def test_partition_roundtrip_rejection_retains_original_priority_and_message():
    from factoryline.review_integrity import partition_proven_primitive_observations

    finding, sources, _ = _case()
    core = {
        "sources": sources,
        "findings": [finding],
        "audit_coverage": {"complete": True},
    }
    partition_proven_primitive_observations(core)
    assert core["findings"] == []
    assert len(core["primitive_observations"]) == 1
    decoded = json.loads(json.dumps(core))
    partition_proven_primitive_observations(decoded)
    assert decoded["primitive_observations"] == []
    assert decoded["findings"][0]["severity"] == "CRITICAL"
    assert decoded["findings"][0]["message"] == "original"
    assert decoded["findings"][0]["facts"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize("coverage", [None, {}, {"complete": False}, {"complete": 1}])
def test_incomplete_or_missing_capture_cannot_partition_endpoint(coverage):
    from factoryline.review_integrity import partition_proven_primitive_observations

    finding, sources, _ = _case()
    core = {"sources": sources, "findings": [finding]}
    if coverage is not None:
        core["audit_coverage"] = coverage
    partition_proven_primitive_observations(core)
    assert len(core["findings"]) == 1
    assert core["findings"][0]["severity"] == finding["severity"]
    assert not core["primitive_observations"]


@pytest.mark.parametrize(
    "disposition",
    [
        "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER",
        "PROVEN_FIXED_LITERAL_PROGRAM",
        "PROVEN_CLOSED_DECLARATION_INPUT",
        "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "PROVEN_FINITE_TEMPLATE_INPUT",
    ],
)
@pytest.mark.parametrize("origin", ["findings", "primitive_observations"])
def test_rejected_secret_role_proofs_preserve_original_alert(disposition, origin):
    from factoryline.review_integrity import partition_proven_primitive_observations

    original = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "source.py",
        "line": 2,
        "column": 0,
        "severity": "CRITICAL",
        "message": "Credential-like material is assigned as a source literal.",
        "facts": {
            "schema": "factory.public-symbolic-identifier.v1",
            "disposition": disposition,
            "role_candidate": "symbolic_enum_identifier",
            "name": "PASSWORD",
            "source_sha256": "b" * 64,
        },
    }
    core = {
        "sources": [{"path": "source.py", "sha256": "a" * 64}],
        "findings": [copy.deepcopy(original)] if origin == "findings" else [],
        "primitive_observations": (
            [copy.deepcopy(original)] if origin == "primitive_observations" else []
        ),
        "audit_coverage": {"complete": True},
    }
    partition_proven_primitive_observations(core)
    retained = core["findings"][0]
    assert retained["severity"] == original["severity"]
    assert retained["message"] == original["message"]
    assert retained["facts"]["name"] == "PASSWORD"
    assert retained["facts"]["disposition"] == "UNVERIFIED_CREDENTIAL_ROLE"
    assert retained["facts"]["state"] == "INCOMPLETE"
    assert core["primitive_observations"] == []
    assert core["primitive_observation_count"] == 0
    assert core["state"] == "BLOCKED"
    before_repeat = copy.deepcopy(core)
    partition_proven_primitive_observations(core)
    assert core == before_repeat


def test_rejected_dynamic_execution_retains_existing_risk_diagnostic():
    from factoryline.primitive_observation_binding import rejected_primitive_proof

    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "severity": "INFO",
        "message": "prior proof",
        "facts": {"disposition": "PROVEN_FIXED_LITERAL_PROGRAM"},
    }
    rejected = rejected_primitive_proof(finding)
    assert rejected["severity"] == "HIGH"
    assert rejected["facts"]["disposition"] == "UNVERIFIED_FIXED_PROGRAM"
    assert rejected["message"].startswith("The fixed-program proof is not bound")


# --- Merged from test_credential_method_endpoint_scanner.py; test definitions and fixtures retained ---
"""Exercise method-value admission through the actual scanner and native partition."""


URL = "https://appleid.apple.com/auth/token"


def _scan(tmp_path, getter, extra="", cache=False):
    source = (
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {URL!r}\n"
        "    def endpoint(self):\n" + getter + "    def send(self, url):\n"
        "        return requests.request('POST', url)\n"
        "    def run(self):\n"
        "        return self.send(self.endpoint())\n" + extra
    )
    path = tmp_path / "client.py"
    path.write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=cache)
    alerts = [
        f
        for f in result["findings"]
        if f["code"] == "SECURITY_HARDCODED_SECRET" and f["line"] == 3
    ]
    observations = [
        f
        for f in result.get("primitive_observations", [])
        if f["code"] == "SECURITY_HARDCODED_SECRET" and f["line"] == 3
    ]
    return alerts, observations


@pytest.mark.parametrize("cache", [False, True])
@pytest.mark.parametrize(
    "getter",
    [
        "        return self.ACCESS_TOKEN_URL\n",
        "        return None or self.ACCESS_TOKEN_URL\n",
    ],
)
def test_public_endpoint_method_return_has_exact_scanner_partition(
    tmp_path, cache, getter
):
    alerts, observations = _scan(tmp_path, getter, cache=cache)
    assert not alerts
    assert len(observations) == 1
    assert observations[0]["severity"] == "CRITICAL"
    assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"
    assert observations[0]["facts"]["credential_safety"] == "UNASSESSED"


def test_exact_other_receiver_field_origin_is_excluded_from_getter_closure(tmp_path):
    getter = "        return self.ACCESS_TOKEN_URL\n"
    extra = (
        "class Other(Client):\n"
        "    ACCESS_TOKEN_URL = 'https://other.example/token'\n"
        "    def inspect(self):\n"
        "        backend = Other()\n"
        "        return backend.endpoint()\n"
    )
    alerts, observations = _scan(tmp_path, getter, extra)
    assert not alerts
    assert len(observations) == 1
    assert observations[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "getter,extra",
    [
        (
            "        url = self.ACCESS_TOKEN_URL\n        opaque(url)\n        return url\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def leak(self):\n        return opaque(self.endpoint())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "class Child(Client):\n    def leak(self):\n        return opaque(self.endpoint())\n",
        ),
        (
            "        url = self.ACCESS_TOKEN_URL\n        return url.format(**opaque(url))\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def leak(self):\n        getter = self.endpoint\n        return opaque(getter())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "opaque(Client().endpoint())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "def leak(client):\n    return opaque(client.endpoint())\nleak(Client())\n",
        ),
        (
            "        return opaque(self.ACCESS_TOKEN_URL) or self.ACCESS_TOKEN_URL\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def invoke_leak(self):\n        return leak(self)\n"
            "def leak(client):\n    return opaque(client.endpoint())\n",
        ),
    ],
)
def test_opaque_candidate_value_uses_retain_original_priority(tmp_path, getter, extra):
    alerts, observations = _scan(tmp_path, getter, extra)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert not observations


# --- Merged from test_credential_publication_controls.py; test definitions and fixtures retained ---
"""Adversarial controls for source-bound public credential evidence."""


def _finding_key(tmp_path):
    return (tmp_path.resolve() / "common.py", 3, "REGISTER_INVALID_PASSWORD")


def test_json_witness_requires_unaliased_test_client(tmp_path):
    source = _JSON_TEST.replace(
        "response = await app_client.post",
        "client = app_client\n    response = await client.post",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_json_witness_rejects_test_client_rebinding(tmp_path):
    source = _JSON_TEST.replace(
        "response = await app_client.post",
        "app_client = supplied\n    response = await app_client.post",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_json_witness_rejects_mutated_httpx_provider(tmp_path):
    source = _JSON_CLIENT.replace(
        "            async with httpx.AsyncClient(",
        "            httpx.AsyncClient = supplied\n"
        "            async with httpx.AsyncClient(",
    )
    graph = _json_enum_graph(tmp_path, client_source=source)
    assert graph.complete
    assert _finding_key(tmp_path) not in graph.witnesses()


def test_closed_json_fixture_still_proves_real_client(tmp_path):
    graph = _json_enum_graph(tmp_path)
    assert graph.complete
    assert _finding_key(tmp_path) in graph.witnesses()


# --- Merged from test_credential_publication_documents.py; test definitions and fixtures retained ---
"""Whole-document declarations require the separately pinned catalog bytes."""


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


# --- Merged from test_credential_publication_excerpt.py; test definitions and fixtures retained ---


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
