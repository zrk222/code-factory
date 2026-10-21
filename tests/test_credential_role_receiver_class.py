"""Exact local-constructor identity for getter-use relations."""

import ast
import hashlib
import pytest
from factoryline.credential_role_method_use_getter_audit import (
    candidate_getter_fields,
    exact_local_receiver_relation,
)
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.credential_role_paths import session_request_context
from factoryline.credential_role_scope_bindings import declared_origins
from factoryline import review_audits as audit
from factoryline.credential_endpoint_admission import session_factory_witness
from factoryline import review_integrity as integrity
from factoryline.credential_role_paths import endpoint_role_evidence


class _Audit:
    @staticmethod
    def _name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{_Audit._name(node.value)}.{node.attr}"
        return ""


def _context(tmp_path, source):
    path = tmp_path / "client.py"
    raw = source.encode()
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    class_nodes = {
        (path, node.name): node for node in tree.body if isinstance(node, ast.ClassDef)
    }
    literal = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "ACCESS_TOKEN_URL"
            for target in node.targets
        )
    )
    member = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "ACCESS_TOKEN_URL"
    )
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "endpoint"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )
    receiver_call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "endpoint"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "backend"
    )
    trace = [_row(path, digest, literal, "declared_literal")]
    trace.extend(
        [
            _row(path, digest, member, "declared_member_read"),
            _row(path, digest, call, "method_call"),
        ]
    )
    nodes = {_key(row): node for row, node in zip(trace, [literal, member, call])}
    fields = candidate_getter_fields([trace], nodes, index)
    run_function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    constructor_receiver = next(
        node
        for node in ast.walk(run_function)
        if isinstance(node, ast.Call) and node is receiver_call
    ).func.value
    return path, index, class_nodes, fields, constructor_receiver


def _row(path, digest, node, role):
    return {
        "path": "client.py",
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": node.end_lineno,
        "end_column": node.end_col_offset,
        "source_sha256": digest,
        "role": role,
    }


def _key(row):
    return tuple(
        row.get(name)
        for name in (
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "source_sha256",
            "role",
        )
    )


_BASE = """
class Client:
    ACCESS_TOKEN_URL = "https://provider.example/token"
    def endpoint(self):
        return self.ACCESS_TOKEN_URL
    def uses_endpoint(self):
        return self.endpoint()
    def run(self):
        backend = Client()
        return backend.endpoint()
"""


def _linked(tmp_path, source=_BASE):
    path, index, class_nodes, fields, receiver = _context(tmp_path, source)
    related = {(path, "Client")}
    return (
        exact_local_receiver_relation(
            path,
            receiver,
            "endpoint",
            index,
            {path: {}},
            class_nodes,
            _Audit(),
            related,
            fields,
        )
        == "LINKED"
    )


def _relation(tmp_path, source):
    path, index, class_nodes, fields, receiver = _context(tmp_path, source)
    return exact_local_receiver_relation(
        path,
        receiver,
        "endpoint",
        index,
        {path: {}},
        class_nodes,
        _Audit(),
        {(path, "Client")},
        fields,
    )


def test_unique_constructor_and_exact_field_origin_link(tmp_path):
    assert _linked(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        _BASE.replace(
            "        backend = Client()",
            "        if True:\n            backend = Client()",
        ),
        _BASE.replace(
            "        return backend.endpoint()",
            "        backend = Client()\n        return backend.endpoint()",
        ),
        _BASE.replace(
            "class Client:\n",
            "class Client:\n    __new__ = lambda cls: object()\n",
        ),
        _BASE.replace(
            "        backend = Client()",
            "        Client = object\n        backend = Client()",
        ),
        _BASE.replace(
            "        backend = Client()",
            "        backend = Client()\n        backend = object()",
        ),
        _BASE + "\nClient = object\n",
    ],
)
def test_unresolved_local_constructor_shapes_stay_unlinked(tmp_path, source):
    assert not _linked(tmp_path, source)


def test_subclass_override_with_distinct_literal_origin_is_not_linked(tmp_path):
    source = (
        _BASE.replace(
            "        backend = Client()",
            "        backend = Child()",
        )
        + """
class Child(Client):
    ACCESS_TOKEN_URL = "https://other.example/token"
"""
    )
    assert not _linked(tmp_path, source)


def test_exact_other_receiver_with_inherited_getter_is_unrelated(tmp_path):
    source = (
        _BASE.replace("        backend = Client()", "        backend = Other()")
        + """\nclass Other(Client):
    ACCESS_TOKEN_URL = "https://other.example/token"
"""
    )
    assert _relation(tmp_path, source) == "UNRELATED"


def test_candidate_subclass_getter_override_stays_unknown(tmp_path):
    source = (
        _BASE.replace("        backend = Client()", "        backend = Child()")
        + """\nclass Child(Client):
    ACCESS_TOKEN_URL = "https://other.example/token"
    def endpoint(self):
        return self.ACCESS_TOKEN_URL
"""
    )
    assert _relation(tmp_path, source) == "UNKNOWN"


def test_setting_fallback_getter_classifies_exact_other_field_origin(tmp_path):
    source = (
        _BASE.replace(
            "    def endpoint(self):",
            "    def setting(self, name, default):\n        return default\n"
            "    def endpoint(self):",
        )
        .replace(
            "        return self.ACCESS_TOKEN_URL",
            "        return self.setting('ACCESS_TOKEN_URL', self.ACCESS_TOKEN_URL)",
        )
        .replace("        backend = Client()", "        backend = Other()")
        + """\nclass Other(Client):
    ACCESS_TOKEN_URL = "https://other.example/token"
"""
    )
    assert _relation(tmp_path, source) == "UNRELATED"


def test_setting_fallback_getter_override_stays_unknown(tmp_path):
    source = (
        _BASE.replace(
            "    def endpoint(self):",
            "    def setting(self, name, default):\n        return default\n"
            "    def endpoint(self):",
        )
        .replace(
            "        return self.ACCESS_TOKEN_URL",
            "        return self.setting('ACCESS_TOKEN_URL', self.ACCESS_TOKEN_URL)",
        )
        .replace("        backend = Client()", "        backend = Child()")
        + """\nclass Child(Client):
    ACCESS_TOKEN_URL = "https://other.example/token"
    def endpoint(self):
        return self.setting('ACCESS_TOKEN_URL', self.ACCESS_TOKEN_URL)
"""
    )
    assert _relation(tmp_path, source) == "UNKNOWN"


# --- Merged from test_credential_role_receiver_boundaries.py; test definitions and fixtures retained ---
"""Unknown receiver aliases, rebinding and scopes cannot establish HTTP identity."""


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


# --- Merged from test_credential_role_object_identity.py; test definitions and fixtures retained ---
"""Lambda bodies are expressions and cannot be traversed as statement suites."""


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("lambda: Client", True),
        ("lambda Client: Client", False),
        ("lambda: getattr(Client, 'FIELD')", True),
    ],
)
def test_lambda_lexical_origin_does_not_crash(tmp_path, expression, expected):
    path = tmp_path / "module.py"
    raw = f"class Client:\n    pass\ncallback = {expression}\n".encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    owner = tree.body[0]
    node = next(
        n
        for n in ast.walk(tree.body[1])
        if isinstance(n, ast.Name) and n.id == "Client"
    )
    result = declared_origins(path, node, index, {path: {}}, {(path, "Client"): owner})
    assert bool(result) is expected


# --- Merged from test_credential_session_forwarding.py; test definitions and fixtures retained ---


SOURCE = (
    "import functools\n"
    "class Adapter:\n"
    "    def factory(self):\n"
    "        import requests\n"
    "        session = requests.Session()\n"
    "        session.request = functools.partial(session.request, timeout=30)\n"
    "        return session\n"
)


def _input(tmp_path, source=SOURCE):
    path = tmp_path / "adapter.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    return path, function, index, audit._module_security_aliases(tree)


def test_timeout_only_forwarder_preserves_slots_and_binds_every_hop(tmp_path):
    args = _input(tmp_path)
    witness = session_factory_witness(*args)
    assert witness["preserved_slots"] == ["method", "url", "auth", "headers"]
    assert witness["runtime_provider_identity"] == "UNASSESSED"
    assert witness["runtime_factory_dispatch"] == "UNASSESSED"
    assert len(witness["hops"]) == 4
    assert all(
        hop["source_sha256"] == args[2].inventory[args[0]]
        and hop["path"] == "adapter.py"
        for hop in witness["hops"]
    )


def test_unmodified_session_factory_has_three_hops(tmp_path):
    source = SOURCE.replace(
        "        session.request = functools.partial(session.request, timeout=30)\n", ""
    )
    assert len(session_factory_witness(*_input(tmp_path, source))["hops"]) == 3


@pytest.mark.parametrize(
    "replacement",
    [
        "functools.partial(session.request, url='other')",
        "functools.partial(session.request, auth=('u', 'secret'))",
        "functools.partial(session.request, 'POST', timeout=30)",
        "functools.partial(session.request, timeout=30, headers={})",
        "functools.partial(session.request, **options)",
        "functools.partial(*arguments, timeout=30)",
        "functools.partial(other.request, timeout=30)",
        "other.request",
        "opaque(session.request)",
    ],
)
def test_changed_slot_binding_or_unknown_forwarder_is_unresolved(tmp_path, replacement):
    source = SOURCE.replace(
        "functools.partial(session.request, timeout=30)", replacement
    )
    assert session_factory_witness(*_input(tmp_path, source)) is None


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("requests.Session()", "unknown.Session()"),
        SOURCE.replace("requests.Session()", "requests.Session(config)"),
        SOURCE.replace("return session", "return other"),
        SOURCE.replace("    def factory", "    @unknown\n    def factory"),
        SOURCE.replace("class Adapter:", "@unknown\nclass Adapter:"),
        SOURCE.replace("class Adapter:", "class Adapter(metaclass=Unknown):"),
        SOURCE + "    factory = replacement\n",
        SOURCE + "requests.Session = replacement\n",
        SOURCE + "functools.partial = replacement\n",
        SOURCE + "setattr(functools, 'partial', replacement)\n",
        SOURCE + "    if True:\n        def factory(self): return replacement\n",
        SOURCE + "    if True:\n        class factory: pass\n",
    ],
)
def test_unknown_factory_identity_or_mutation_cannot_be_canonical(tmp_path, source):
    assert session_factory_witness(*_input(tmp_path, source)) is None


def test_stale_or_forged_source_tree_cannot_supply_hops(tmp_path):
    path, function, index, aliases = _input(tmp_path)
    index.source_bytes[path] += b"# changed\n"
    assert session_factory_witness(path, function, index, aliases) is None
    path, function, index, aliases = _input(tmp_path)
    forged = next(
        n for n in ast.walk(ast.parse(SOURCE)) if isinstance(n, ast.FunctionDef)
    )
    assert session_factory_witness(path, forged, index, aliases) is None


# --- Merged from test_credential_role_transferred_field.py; test definitions and fixtures retained ---
"""A constructor-renamed value retains its identity in declared descendants."""


@pytest.mark.parametrize(
    "consumer,complete", [("opaque(self.url)", False), ("requests.get(self.url)", True)]
)
def test_descendant_of_client_field_consumer_role(tmp_path, consumer, complete):
    path = tmp_path / "app.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        "    def __init__(self, endpoint):\n        self.url = endpoint\n"
        "    def send(self):\n        return requests.get(self.url)\n"
        "class DerivedClient(Client):\n"
        f"    def auth(self):\n        return {consumer}\n"
        "class Adapter:\n"
        "    client_class = Client\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def get_client(self):\n"
        "        return self.client_class(self.ACCESS_TOKEN_URL)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    integrity.bind_security_call_scopes(tree)
    rows = endpoint_role_evidence(
        tmp_path,
        {path: tree},
        {path: {}},
        {path: raw},
        {path: digest},
        audit,
        integrity,
    )
    row = next(
        r for r in rows.values() if r["declaration"]["member"] == "ACCESS_TOKEN_URL"
    )
    assert bool(row["linked_unknown_uses"]) is not complete
    assert row["value_use_audit"]["state"] == ("COMPLETE" if complete else "INCOMPLETE")


def test_selected_subclass_does_not_link_unrelated_sibling_instance(tmp_path):
    path = tmp_path / "app.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        "    def __init__(self, endpoint):\n        self.url = endpoint\n"
        "    def send(self):\n        return requests.get(self.url)\n"
        "class Selected(Client):\n    pass\n"
        "class Sibling(Client):\n"
        "    def auth(self):\n        return opaque(self.url)\n"
        "class Adapter:\n    client_class = Selected\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def get_client(self):\n"
        "        return self.client_class(self.ACCESS_TOKEN_URL)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    integrity.bind_security_call_scopes(tree)
    rows = endpoint_role_evidence(
        tmp_path,
        {path: tree},
        {path: {}},
        {path: raw},
        {path: digest},
        audit,
        integrity,
    )
    row = next(
        r for r in rows.values() if r["declaration"]["member"] == "ACCESS_TOKEN_URL"
    )
    assert row["value_use_audit"]["state"] == "COMPLETE"
    assert not row["linked_unknown_uses"]
