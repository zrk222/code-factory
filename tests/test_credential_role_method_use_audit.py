import ast
import hashlib

import pytest

from factoryline.credential_role_method_use_audit import method_value_use_audit
from factoryline.credential_role_sources import SourceSnapshotIndex


def _case(tmp_path, source):
    path = tmp_path / "client.py"
    raw = source.encode()
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    nodes = list(ast.walk(tree))
    endpoint = next(
        n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == "endpoint"
    )
    dispatch = next(
        n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == "dispatch"
    )
    send = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == "send")
    sink = next(
        n
        for n in nodes
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    get_call = next(
        n
        for n in nodes
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "endpoint"
    )
    member = next(
        n
        for n in ast.walk(endpoint)
        if isinstance(n, ast.Attribute) and n.attr == "ENDPOINT"
    )
    literal = next(
        n
        for n in nodes
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "ENDPOINT" for t in n.targets)
    )
    actual = next(
        n
        for n in ast.walk(send)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "dispatch"
    ).args[0]
    parameter = next(a for a in dispatch.args.args if a.arg == "url")
    digest_by_path = index.inventory[path]

    def row(node, role):
        return {
            "path": "client.py",
            "line": node.lineno,
            "column": node.col_offset,
            "end_line": node.end_lineno,
            "end_column": node.end_col_offset,
            "source_sha256": digest_by_path,
            "role": role,
        }

    witness = [
        row(literal, "declared_literal"),
        row(member, "declared_member_read"),
        row(get_call, "method_call"),
        row(actual, "method_argument_binding"),
        row(parameter, "bound_method_parameter"),
        row(sink, "canonical_http_url_sink"),
    ]
    return method_value_use_audit(witness, index), witness, index


_GOOD = """
import requests
class Client:
    ENDPOINT = "https://provider.example/token"
    def endpoint(self):
        return self.ENDPOINT
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        return self.dispatch(self.endpoint())
"""


def test_getter_wrapper_and_exact_sink_value_are_closed(tmp_path):
    result, _, _ = _case(tmp_path, _GOOD)
    assert result["state"] == "COMPLETE"
    assert result["unknown_uses"] == []
    assert any(
        row["role"] == "canonical_http_url_argument"
        for row in result["allowed_member_spans"]
    )


def test_auth_keyword_load_of_same_parameter_is_unknown(tmp_path):
    source = _GOOD.replace(
        'requests.request("GET", url)', 'requests.request("GET", url, auth=("u", url))'
    )
    result, _, _ = _case(tmp_path, source)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "unrepresented_parameter_use" for row in result["unknown_uses"]
    )


def test_unwitnessed_sibling_getter_call_is_unknown(tmp_path):
    source = _GOOD.replace(
        "    def send(self):",
        "    def unused(self):\n        return self.endpoint()\n    def send(self):",
    )
    result, _, _ = _case(tmp_path, source)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "unwitnessed_sibling_getter_call"
        for row in result["unknown_uses"]
    )


def test_class_symbol_getter_alias_is_not_skipped(tmp_path):
    source = _GOOD + "\ngetter = Client.endpoint\nopaque(getter(Client()))\n"
    result, _, _ = _case(tmp_path, source)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "getter_receiver_relation_unresolved"
        for row in result["unknown_uses"]
    )


def test_staticmethod_first_argument_is_not_stable_self(tmp_path):
    source = (
        _GOOD
        + """
class Other:
    @staticmethod
    def leak(self):
        return opaque(self.endpoint())
"""
    )
    result, _, _ = _case(tmp_path, source)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "getter_receiver_relation_unresolved"
        for row in result["unknown_uses"]
    )


@pytest.mark.parametrize(
    "source, reason",
    [
        (
            _GOOD.replace(
                '        return requests.request("GET", url)',
                '        url = "/replacement"\n        return requests.request("GET", url)',
            ),
            "parameter_rebinding",
        ),
        (
            _GOOD.replace(
                '        return requests.request("GET", url)',
                '        def nested():\n            return url\n        return requests.request("GET", url)',
            ),
            "unrepresented_parameter_use",
        ),
    ],
)
def test_parameter_rebinding_and_nested_capture_fail_closed(tmp_path, source, reason):
    result, _, _ = _case(tmp_path, source)
    assert result["state"] == "INCOMPLETE"
    assert any(row["reason"] == reason for row in result["unknown_uses"])


def test_hash_mismatch_and_dynamic_role_are_unknown(tmp_path):
    result, witness, index = _case(tmp_path, _GOOD)
    witness[-1] = {**witness[-1], "source_sha256": "0" * 64}
    result = method_value_use_audit(witness, index)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "source_hash_mismatch" for row in result["unknown_uses"]
    )
    witness[-1] = {
        **witness[-1],
        "source_sha256": index.inventory[next(iter(index.inventory))],
        "role": "dynamic_reflection",
    }
    result = method_value_use_audit(witness, index)
    assert result["state"] == "INCOMPLETE"
    assert any(row["reason"] == "unsupported_role" for row in result["unknown_uses"])
