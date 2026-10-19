"""Exact local-constructor identity for getter-use relations."""

import ast
import hashlib

import pytest

from factoryline.credential_role_method_use_getter_audit import (
    candidate_getter_fields,
    exact_local_receiver_relation,
)
from factoryline.credential_role_sources import SourceSnapshotIndex


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
