"""Exercise native resolver contracts and lazy source validation."""

import ast
import hashlib

import pytest

from factoryline.credential_role_bindings import auth_constructor_password
from factoryline.credential_role_session_calls import session_request_context
from factoryline.credential_role_sources import (
    SourceSnapshotIndex,
    source_session_factories,
)


def test_auth_constructor_uses_canonical_call_contract(tmp_path):
    path = tmp_path / "client.py"
    call = ast.parse("requests.auth.HTTPBasicAuth('user', secret)").body[0].value
    aliases = {path: {"requests": "requests"}}
    assert auth_constructor_password(call, path, aliases) is call.args[1]


def test_source_factory_uses_canonical_call_contract():
    tree = ast.parse(
        "def factory():\n    session = requests.Session()\n    return session\n"
    )
    assert source_session_factories(tree, {"requests": "requests"}) == {"factory"}


def test_session_context_validates_lazy_source_before_parent_lookup(tmp_path):
    path = tmp_path / "client.py"
    raw = (
        b"def send():\n"
        b"    with get_adapter().get_requests_session() as session:\n"
        b"        session.request('GET', endpoint)\n"
    )
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert not index.parents
    aliases = {"get_adapter": "provider.get_adapter"}
    assert session_request_context(call, index, path, aliases) == "provider.get_adapter"
    assert path in index.parents


def test_session_context_rejects_stale_source(tmp_path):
    path = tmp_path / "client.py"
    raw = b"session.request('GET', endpoint)"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = "0" * 64
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: "0" * 64})
    assert session_request_context(tree.body[0].value, index, path, {}) is False


@pytest.mark.parametrize(
    "prefix",
    [
        "session = supplied",
        "session.request = supplied",
        "del session.request",
        "mutate(session)",
        "setattr(session, 'request', supplied)",
    ],
)
def test_session_receiver_mutation_is_unresolved(tmp_path, prefix):
    path = tmp_path / "client.py"
    raw = (
        "def send():\n"
        "    with get_adapter().get_requests_session() as session:\n"
        f"        {prefix}\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert session_request_context(call, index, path, {}) is False


@pytest.mark.parametrize("arguments", ["supplied", "**options", "auth=secret"])
def test_session_factory_arguments_are_unresolved(tmp_path, arguments):
    path = tmp_path / "client.py"
    raw = (
        "def send():\n"
        f"    with get_adapter().get_requests_session({arguments}) as session:\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert session_request_context(call, index, path, {}) is False


@pytest.mark.parametrize(
    "body, expected_slots, expected_checks",
    [
        ("consume(1)\nconsume(2)\nconsume(3)", [], 0),
        ("requests.get(endpoint)", ["endpoint_locator"], 1),
        ("requests.auth.HTTPBasicAuth('user', secret)", ["password"], 1),
        ("consume(requests)\nrequests.get(endpoint)", [], 1),
        ("requests.get = replacement\nrequests.get(endpoint)", [], 1),
    ],
)
def test_sink_planning_checks_provider_only_for_candidate_slots(
    tmp_path, monkeypatch, body, expected_slots, expected_checks
):
    from factoryline import credential_role_paths as paths
    from factoryline import review_audits as audit
    from factoryline.review_integrity import bind_security_call_scopes

    path = tmp_path / "client.py"
    raw = ("import requests\n" + body + "\n").encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    aliases = {path: audit._module_security_aliases(tree)}
    original = paths._provider_identity_uncertain
    checks = []

    def observed(*args, **kwargs):
        checks.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(paths, "_provider_identity_uncertain", observed)
    rows = paths._sink_rows({path: tree}, aliases, index, None)
    assert [row[3] for row in rows] == expected_slots
    assert len(checks) == expected_checks
