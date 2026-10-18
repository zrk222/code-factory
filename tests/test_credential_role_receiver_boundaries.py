"""Unknown receiver aliases, rebinding and scopes cannot establish HTTP identity."""

import ast
import hashlib

import pytest

from factoryline.credential_role_session_calls import session_request_context
from factoryline.credential_role_sources import SourceSnapshotIndex


@pytest.mark.parametrize(
    "body",
    [
        "alias = session\n        alias.request = supplied\n"
        "        session.request('GET', endpoint)",
        "for item in items:\n            session.request('GET', endpoint)\n"
        "            session = supplied",
        "session.__dict__['request'] = supplied\n"
        "        session.request('GET', endpoint)",
        "session.__dict__.update(request=supplied)\n"
        "        session.request('GET', endpoint)",
        "def session():\n            pass\n        session.request('GET', endpoint)",
        "if condition:\n            class session:\n                pass\n"
        "        session.request('GET', endpoint)",
        "callback = lambda session: session.request('GET', endpoint)",
        "values = [session.request('GET', endpoint) for session in supplied]",
        "import supplied as session\n        session.request('GET', endpoint)",
        "match supplied:\n            case session:\n"
        "                session.request('GET', endpoint)",
        "match supplied:\n            case {**session}:\n"
        "                session.request('GET', endpoint)",
    ],
)
def test_receiver_binding_and_escape_boundaries(tmp_path, body):
    raw = (
        "def send():\n"
        "    with get_adapter().get_requests_session() as session:\n"
        f"        {body}\n"
    ).encode()
    assert _identity(tmp_path, raw) is False


def _identity(tmp_path, raw):
    path = tmp_path / "client.py"
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    return session_request_context(call, index, path, {})


def test_later_context_target_overwrite_is_unresolved(tmp_path):
    raw = (
        "def send():\n"
        "    with get_adapter().get_requests_session() as session, "
        "other() as session:\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    assert _identity(tmp_path, raw) is False


@pytest.mark.parametrize(
    "mutation",
    [
        "exec('session = supplied')",
        "globals()['session'] = supplied",
        "locals()['session'] = supplied",
        "vars()['session'] = supplied",
    ],
)
def test_module_dynamic_namespace_is_unresolved(tmp_path, mutation):
    raw = (
        "with get_adapter().get_requests_session() as session:\n"
        f"    {mutation}\n"
        "    session.request('GET', endpoint)\n"
    ).encode()
    assert _identity(tmp_path, raw) is False


def test_async_context_requires_a_separate_factory_contract(tmp_path):
    raw = (
        "async def send():\n"
        "    async with get_adapter().get_requests_session() as session:\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    assert _identity(tmp_path, raw) is False


def test_module_star_import_can_replace_receiver(tmp_path):
    raw = (
        "with get_adapter().get_requests_session() as session:\n"
        "    from supplied import *\n"
        "    session.request('GET', endpoint)\n"
    ).encode()
    assert _identity(tmp_path, raw) is False
