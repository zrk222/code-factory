import ast
import hashlib
import pytest
from factoryline.credential_role_method_use_getter_audit import method_value_use_audit
from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
from types import SimpleNamespace
from factoryline.credential_role_paths import method_url_hops
from factoryline.credential_role_constructor_provider import declaration_fact
from factoryline.review_integrity import bind_source_call
from test_credential_endpoint_scanner import _scan


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


# --- Merged from test_credential_role_method_boolean_choice.py; test definitions and fixtures retained ---


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _module_security_aliases(tree):
        return {
            item.asname or item.name.split(".")[0]: item.name
            for statement in tree.body
            if isinstance(statement, ast.Import)
            for item in statement.names
        }


def _trace(tmp_path, source, member="ENDPOINT"):
    path = (tmp_path / "client.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    declaration = next(
        node
        for node in owner.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == member
            for target in node.targets
        )
    )
    fact = declaration_fact(index, path, declaration)
    sink = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    aliases = {path: _Audit._module_security_aliases(tree)}
    classes = {(path, owner.name): owner}
    return method_url_hops(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        {path: {}},
        classes,
        aliases,
        _Audit(),
        SimpleNamespace(bind_source_call=bind_source_call),
    )


def _source(values, returned):
    return (
        "import requests\n"
        "class Client:\n"
        f"{values}\n"
        "    def endpoint(self):\n"
        f"        return {returned}\n"
        "    def send(self):\n"
        '        return requests.request("GET", self.endpoint())\n'
    )


def test_boolean_value_choice_can_carry_exact_source_member(tmp_path):
    for member, expression in (
        ("ENDPOINT", "self.OTHER or self.ENDPOINT"),
        ("OTHER", "self.ENDPOINT or self.OTHER"),
    ):
        source = _source(
            '    ENDPOINT = "https://service.example/token"\n'
            '    OTHER = "https://other.example/token"',
            expression,
        )
        hops = _trace(tmp_path / member, source, member)
        assert hops
        roles = {row["role"] for row in hops}
        assert "declared_boolean_value_choice" in roles
        assert "declared_boolean_operand" in roles
        assert "declared_member_read" in roles


def test_boolean_other_credential_does_not_witness_unread_candidate(tmp_path):
    source = _source(
        '    ENDPOINT = "https://service.example/token"\n'
        '    SECRET = "credential-literal"',
        "self.SECRET or self.OTHER",
    )
    assert _trace(tmp_path, source, "ENDPOINT") is None


def test_opaque_argument_does_not_become_a_boolean_choice_witness(tmp_path):
    source = _source(
        '    ENDPOINT = "https://service.example/token"\n'
        '    OTHER = "https://other.example/token"',
        "opaque(self.ENDPOINT) or self.OTHER",
    )
    assert _trace(tmp_path, source, "ENDPOINT") is None


def test_and_never_claims_earlier_operand_as_the_result(tmp_path):
    source = _source(
        '    ENDPOINT = "https://service.example/token"\n'
        '    OTHER = "https://other.example/token"',
        "self.ENDPOINT and self.OTHER",
    )
    assert _trace(tmp_path, source, "ENDPOINT") is None


def test_statically_truthy_or_operand_blocks_later_value(tmp_path):
    source = _source(
        '    ENDPOINT = "https://service.example/token"\n'
        '    OTHER = "https://other.example/token"',
        "'fixed' or self.ENDPOINT",
    )
    assert _trace(tmp_path, source, "ENDPOINT") is None


# --- Merged from test_credential_role_method_use_edges.py; test definitions and fixtures retained ---


def test_local_alias_is_closed_only_for_its_exact_sink_value(tmp_path):
    source = _GOOD.replace(
        'return requests.request("GET", url)',
        'target = url\n        return requests.request("GET", target)',
    )

    _, witness, index = _case(tmp_path, source)

    alias = next(
        n
        for n in ast.walk(index.snapshots[next(iter(index.snapshots))])
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "target" for t in n.targets)
    )

    witness.insert(
        -1,
        {
            **witness[0],
            "line": alias.lineno,
            "column": alias.col_offset,
            "end_line": alias.end_lineno,
            "end_column": alias.end_col_offset,
            "role": "unique_local_alias",
        },
    )

    result = method_value_use_audit(witness, index)

    assert result["state"] == "COMPLETE"

    source = source.replace(
        'request("GET", target)', 'request("GET", target, auth=("u", target))'
    )

    _, witness, index = _case(tmp_path / "auth", source)

    alias = next(
        n
        for n in ast.walk(index.snapshots[next(iter(index.snapshots))])
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "target" for t in n.targets)
    )

    witness.insert(
        -1,
        {
            **witness[0],
            "line": alias.lineno,
            "column": alias.col_offset,
            "end_line": alias.end_lineno,
            "end_column": alias.end_col_offset,
            "role": "unique_local_alias",
        },
    )

    result = method_value_use_audit(witness, index)

    assert result["state"] == "INCOMPLETE"

    assert any(
        row["reason"] == "unrepresented_alias_use" for row in result["unknown_uses"]
    )


def test_format_receiver_does_not_cover_opaque_sibling_use(tmp_path):
    source = _GOOD.replace(
        'return requests.request("GET", url)',
        'target = url.format(**opaque(url))\n        return requests.request("GET", target)',
    )

    _, witness, index = _case(tmp_path, source)

    tree = index.snapshots[next(iter(index.snapshots))]

    alias = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "target" for t in n.targets)
    )

    transform = alias.value

    witness.insert(
        -1,
        {
            **witness[0],
            "line": alias.lineno,
            "column": alias.col_offset,
            "end_line": alias.end_lineno,
            "end_column": alias.end_col_offset,
            "role": "unique_local_alias",
        },
    )

    witness.insert(
        -1,
        {
            **witness[0],
            "line": transform.lineno,
            "column": transform.col_offset,
            "end_line": transform.end_lineno,
            "end_column": transform.end_col_offset,
            "role": "declared_string_format_input",
        },
    )

    result = method_value_use_audit(witness, index)

    assert result["state"] == "INCOMPLETE"

    assert any(
        row["reason"] == "unrepresented_parameter_use" for row in result["unknown_uses"]
    )


def test_boolean_choice_validates_unique_exact_member_operand(tmp_path):
    source = _GOOD.replace(
        "return self.ENDPOINT",
        "return self.ENDPOINT or 'https://fallback.example/token'",
    )
    result, witness, index = _case(tmp_path, source)
    tree = index.snapshots[next(iter(index.snapshots))]
    choice = next(node for node in ast.walk(tree) if isinstance(node, ast.BoolOp))
    witness.insert(
        2,
        {
            **witness[0],
            "line": choice.lineno,
            "column": choice.col_offset,
            "end_line": choice.end_lineno,
            "end_column": choice.end_col_offset,
            "role": "declared_boolean_value_choice",
        },
    )
    assert method_value_use_audit(witness, index)["state"] == "COMPLETE"


def test_boolean_choice_does_not_cover_repeated_opaque_candidate_read(tmp_path):
    source = _GOOD.replace(
        "return self.ENDPOINT",
        "return self.ENDPOINT or opaque(self.ENDPOINT)",
    )
    result, witness, index = _case(tmp_path, source)
    tree = index.snapshots[next(iter(index.snapshots))]
    choice = next(node for node in ast.walk(tree) if isinstance(node, ast.BoolOp))
    witness.insert(
        2,
        {
            **witness[0],
            "line": choice.lineno,
            "column": choice.col_offset,
            "end_line": choice.end_lineno,
            "end_column": choice.end_col_offset,
            "role": "declared_boolean_value_choice",
        },
    )
    result = method_value_use_audit(witness, index)
    assert result["state"] == "INCOMPLETE"
    assert any(
        row["reason"] == "boolean_choice_has_untraced_candidate_read"
        for row in result["unknown_uses"]
    )


@pytest.mark.parametrize(
    "extra",
    [
        'opaque(getattr(Client(), "endpoint")())\n',
        '    def leak(self):\n        return opaque(self.__getattribute__("endpoint")())\n',
        'def leak(client):\n    return opaque(getattr(client, "endpoint")())\nleak(Client())\n',
        "def leak(client):\n    alias = client\n    return opaque(alias.endpoint())\nleak(client=Client())\n",
        "def leak(client):\n    return opaque(client.endpoint())\nconsume = leak\nconsume(Client())\n",
        "def leak(client):\n    first = client\n    second = first\n    return opaque(second.endpoint())\nleak(client=Client())\n",
        "    def invoke_leak(self):\n        consume = leak\n        return consume(self)\n"
        "def leak(client):\n    return opaque(client.endpoint())\n",
    ],
)
def test_reflective_getter_result_is_unrepresented(tmp_path, extra):
    alerts, observations = _scan(
        tmp_path,
        "        return self.ENDPOINT\n",
        extra,
    )
    assert len(alerts) == 1
    assert not observations
