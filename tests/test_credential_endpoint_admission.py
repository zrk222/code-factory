"""Coordinator boundaries; mocked rows test admission, not source-flow accuracy."""

import ast
from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from factoryline import credential_endpoint_admission as admission
from factoryline.credential_endpoint_admission import endpoint_binding

ENDPOINT = "https://appleid.apple.com/auth/token"


def _case(tmp_path, monkeypatch, overrides=None):
    admission._WORKSPACES.clear()
    path = tmp_path / "client.py"
    raw = f"class Client:\n    ACCESS_TOKEN_URL = {ENDPOINT!r}\n".encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    tree._security_source_context = (tmp_path, {path: raw})
    node = tree.body[0].body[0]
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "client.py",
        "line": node.lineno,
        "column": node.col_offset,
        "severity": "CRITICAL",
        "message": "original heuristic",
        "facts": {"name": "ACCESS_TOKEN_URL"},
    }
    row = {
        "declaration": {
            "source_sha256": digest,
            "path": "client.py",
            "member": "ACCESS_TOKEN_URL",
            "line": node.lineno,
            "column": node.col_offset,
            "value_sha256": hashlib.sha256(ENDPOINT.encode()).hexdigest(),
        },
        "profile": "DECLARED_CLASS_MAY_FLOW",
        "url_witnesses": [{"path": "client.py", "line": 2}],
        "known_auth_uses": [],
        "linked_unknown_uses": [],
        "value_use_audit": {
            "state": "COMPLETE",
            "profile": admission.USE_AUDIT_PROFILE,
        },
        **(overrides or {}),
    }
    monkeypatch.setattr(
        admission, "_derive", lambda *args: {("client.py", 2, "ACCESS_TOKEN_URL"): row}
    )
    integrity = SimpleNamespace(_security_module_scope=lambda _: tree)
    return node, finding, row, tree, integrity


def test_coordinator_mints_bound_local_marker_without_changing_priority(
    tmp_path, monkeypatch
):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    digest = tree._oracle_source_sha256
    assert endpoint_binding(
        finding, [{"path": "client.py", "sha256": digest}], {"client.py": digest}
    )
    assert finding["severity"] == "CRITICAL"
    assert finding["message"] == "original heuristic"


@pytest.mark.parametrize(
    "overrides",
    [
        {"value_use_audit": {}},
        {"value_use_audit": {"state": "INCOMPLETE", "profile": "partial"}},
        {"value_use_audit": {"state": "COMPLETE", "profile": "unknown_profile"}},
        {"known_auth_uses": [{"slot": "password"}]},
        {"linked_unknown_uses": [{"reason": "unresolved_receiver"}]},
        {"url_witnesses": []},
    ],
)
def test_missing_or_conflicting_source_proof_preserves_original_alert(
    tmp_path, monkeypatch, overrides
):
    node, finding, _, _, integrity = _case(tmp_path, monkeypatch, overrides)
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_source_mutation_invalidates_workspace_projection(tmp_path, monkeypatch):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    source_root, sources = tree._security_source_context
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert len(admission._WORKSPACES) == 1
    sources[source_root / "new.py"] = b"new_consumer = None\n"
    finding["facts"] = {"name": "ACCESS_TOKEN_URL"}
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert len(admission._WORKSPACES) == 2
    assert len(finding["facts"]._attestation[2]) == 2


def test_mismatched_declaration_cannot_receive_native_marker(tmp_path, monkeypatch):
    node, finding, row, _, integrity = _case(tmp_path, monkeypatch)
    row["declaration"]["line"] = 20
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_retained_source_changed_under_current_tree_is_rejected(tmp_path, monkeypatch):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    root, sources = tree._security_source_context
    sources[root / "client.py"] += b"ACCESS_TOKEN_URL = replacement\n"
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_changed_derivation_cannot_reuse_prior_complete_row(tmp_path, monkeypatch):
    node, finding, _, _, integrity = _case(tmp_path, monkeypatch)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding["facts"].get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN"
    finding["facts"] = {"name": "ACCESS_TOKEN_URL"}
    monkeypatch.setattr(admission, "_derive", lambda *args: {})
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding["facts"] == {"name": "ACCESS_TOKEN_URL"}
    assert len(admission._WORKSPACES) == 2


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_real_scanner_partition_uses_current_coordinator(
    tmp_path, monkeypatch, cache_enabled
):
    from factoryline.review_audits import security_scan

    _, _, _, tree, _ = _case(tmp_path, monkeypatch)
    root, sources = tree._security_source_context
    for path, raw in sources.items():
        path.write_bytes(raw)
    for _ in range(2):
        result = security_scan(root, cache_enabled=cache_enabled)
        assert not [
            f for f in result["findings"] if f["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        observations = [
            f
            for f in result.get("primitive_observations", [])
            if f["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        assert len(observations) == 1
        assert observations[0]["severity"] == "CRITICAL"
        assert observations[0]["facts"]["credential_safety"] == "UNASSESSED"


def test_precision257_endpoint_helper_inventory_and_catalog_digest_are_content_bound(
    monkeypatch,
):
    from factoryline import credential_endpoint_admission as endpoint

    catalog_helpers = endpoint.catalog_callable_helpers()
    validation = endpoint.validation_helpers()
    evidence = endpoint.endpoint_evidence_helpers()
    assert len(catalog_helpers) == 14 and all(
        callable(item) for item in catalog_helpers
    )
    assert len(validation) == 35 and all(callable(item) for item in validation)
    assert len(evidence) == 7 and all(callable(item) for item in evidence)
    catalog = endpoint._catalog_bytes()
    assert catalog is not None
    assert endpoint.catalog_content_digest() == endpoint._catalog_digest(catalog)
    monkeypatch.setattr(endpoint, "_catalog_bytes", lambda: None)
    assert endpoint.catalog_content_digest() == "MISSING"
    finding = {
        "code": "E",
        "path": "a.py",
        "line": 1,
        "column": 0,
        "severity": "HIGH",
        "message": "x",
    }
    digest = endpoint._endpoint_evidence_digest({"a": 1})
    assert digest == endpoint._endpoint_evidence_digest({"a": 1})
    assert digest != endpoint._endpoint_evidence_digest({"a": 2})
    assert endpoint._identity(finding) == ("E", "a.py", 1, 0, "HIGH", "x")
    assert (
        endpoint.factory_fixture_consumer_status(
            None, "x", "fixture", "source", ast.parse("pass").body[0], True, True
        )
        is None
    )


def test_precision257_fixture_consumer_status_classifies_supported_and_unsupported_calls():
    import ast
    from types import SimpleNamespace
    from factoryline.credential_endpoint_admission import (
        factory_fixture_consumer_status,
    )

    def graph_for(source):
        tree = ast.parse(source)
        fixture, caller = tree.body
        parents = {
            id(child): node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        graph = SimpleNamespace(
            parents=parents,
            _is_pytest_fixture=lambda *_: True,
            _walk=lambda node: ast.walk(node),
            _nearest_fixture=lambda _source, name, _caller: (
                "tests/test_api.py",
                fixture,
            )
            if name == fixture.name
            else None,
        )
        return graph, fixture, caller

    path = "tests/test_api.py"
    graph, fixture, caller = graph_for(
        "def client_fixture():\n    pass\ndef consumer(client_fixture):\n    return client_fixture()"
    )
    assert (
        factory_fixture_consumer_status(
            graph, path, fixture, path, caller, lambda *_: True, lambda *_: True
        )
        is True
    )
    graph, fixture, caller = graph_for(
        "def client_fixture():\n    pass\ndef consumer(client_fixture):\n    return client_fixture"
    )
    assert (
        factory_fixture_consumer_status(
            graph, path, fixture, path, caller, lambda *_: False, lambda *_: True
        )
        is False
    )
