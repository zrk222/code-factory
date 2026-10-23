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


def test_public_trace_identity_projection_retains_only_stable_fields(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter

    result, trace, index = _case(tmp_path, _GOOD)
    assert result["state"] == "COMPLETE"
    row = trace[1]
    decorated = {**row, "private_value": "do-not-export"}
    expected = tuple(
        row[key]
        for key in (
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "source_sha256",
            "role",
        )
    )
    assert getter.span_key(decorated) == expected
    assert getter.public_span(decorated) == row
    assert "private_value" not in getter.public_span(decorated)
    projected = getter.public_span(decorated)
    projected["role"] = "changed"
    assert getter.public_span(decorated) == row


def test_public_getter_scope_and_argument_navigation_uses_exact_ast_identity(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, trace, index = _case(tmp_path, _GOOD)
    path = tmp_path / "client.py"
    module = index.snapshots[path]
    owner = next(node for node in module.body if isinstance(node, ast.ClassDef))
    send = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "send"
    )
    call = send.body[0].value
    actual = call.args[0]
    assert getter.argument_call(actual, index, "client.py") is call
    assert (
        getter.argument_call(ast.parse("foreign").body[0].value, index, "client.py")
        is None
    )
    assert getter.source_scope(actual, index.parents[path]) == (send, owner)
    assert getter.class_identity(actual, index, path) == ("client.py", "Client")
    assert getter.class_identity(module, index, path) is None
    assert getter.owner_keys(index, {(path, "Client")}) == {("client.py", "Client")}
    assert getter.owner_keys(index, None) == set()


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("request('GET', selected)", "selected"),
        ("request(method='GET', url=selected)", "selected"),
        ("request('GET')", None),
        ("request('GET', first, url=second)", "first"),
    ],
)
def test_public_url_slot_projection_is_structural_not_a_provider_proof(
    expression, expected
):
    from factoryline import credential_role_method_use_getter_audit as getter

    call = ast.parse(expression).body[0].value
    actual = getter.url_argument(call)
    assert (ast.unparse(actual) if actual is not None else None) == expected


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("getattr(client, 'ENDPOINT')", True),
        ("setattr(client, 'ENDPOINT', value)", True),
        ("getattr(client, 'OTHER')", False),
        ("opaque(client, 'ENDPOINT')", False),
        ("vars(client)", True),
    ],
)
def test_public_reflective_member_selection_respects_exact_field(expression, expected):
    from factoryline import credential_role_method_use_getter_audit as getter

    call = ast.parse(expression).body[0].value
    actual = getter.reflective_member_use(call, {"ENDPOINT"})
    assert actual is (call.args[0] if expected else None)


def test_snapshot_candidates_cache_only_current_source_inventory_signature(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, _, index = _case(tmp_path, _GOOD)
    first = getter.snapshot_candidates(index)
    assert len(first) == 1
    path, module, candidates = first[0]
    expected = [
        node for node in ast.walk(module) if isinstance(node, (ast.Attribute, ast.Call))
    ]
    assert candidates == expected
    assert getter.snapshot_candidates(index) is first
    index.inventory[path] = "0" * 64
    assert getter.snapshot_candidates(index) == []


def test_value_closure_and_getter_scan_preserve_a_complete_captured_trace(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter

    result, trace, index = _case(tmp_path, _GOOD)
    assert result["state"] == "COMPLETE"
    path = tmp_path / "client.py"
    by_span = {
        getter.coordinates(node): node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.stmt, ast.expr, ast.arg))
    }
    nodes = {
        getter.span_key(row): by_span[
            tuple(row[key] for key in ("line", "column", "end_line", "end_column"))
        ]
        for row in trace
    }
    unknown = []
    getter.audit_value_closure([trace], nodes, index, unknown)
    assert unknown == []
    getter.alias_uses([trace], nodes, index, unknown)
    assert unknown == []
    getter.audit_getter_uses([trace], nodes, index, unknown)
    assert unknown == []


def test_value_spans_capture_explicit_witness_without_expanding_unrelated_fields(
    tmp_path,
):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, trace, index = _case(tmp_path, _GOOD)
    row = trace[1]
    coordinates = [row[key] for key in ("line", "column", "end_line", "end_column")]
    spans, fields = getter.value_spans(
        {
            "url_witnesses": [
                {"path": "client.py", "value_span": coordinates, "hops": []}
            ]
        },
        index,
        {},
        {},
    )
    assert spans == {tmp_path / "client.py": [coordinates]}
    assert fields == {}


@pytest.mark.parametrize("mutation", ["bytes", "inventory", "producer", "tree"])
def test_snapshot_candidate_cache_revalidates_replaced_source_and_recovers(
    tmp_path, mutation
):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, _, index = _case(tmp_path, _GOOD)
    first = getter.snapshot_candidates(index)
    path = tmp_path / "client.py"
    tree, raw, digest = (
        index.snapshots[path],
        index.source_bytes[path],
        index.inventory[path],
    )
    assert index.validate(path)
    if mutation == "bytes":
        index.source_bytes[path] = b"foreign()\n"
    elif mutation == "inventory":
        index.inventory[path] = "0" * 64
    elif mutation == "producer":
        tree._oracle_source_sha256 = "0" * 64
    else:
        index.snapshots[path] = ast.parse("foreign()\n")
    assert getter.snapshot_candidates(index) == []
    assert not index.validate(path)
    assert path not in index.parents
    index.snapshots[path], index.source_bytes[path], index.inventory[path] = (
        tree,
        raw,
        digest,
    )
    tree._oracle_source_sha256 = digest
    restored = getter.snapshot_candidates(index)
    assert restored == first
    assert index.validate(path)
    assert index.parents[path]


def test_snapshot_validation_reuses_unchanged_bytes_without_reparsing(
    tmp_path, monkeypatch
):
    from factoryline import credential_role_constructor_provider as provider

    _, _, index = _case(tmp_path, _GOOD)
    path = tmp_path / "client.py"
    assert index.validate(path)

    def unexpected_parse(*args):
        raise AssertionError("unchanged captured source was reparsed")

    monkeypatch.setattr(provider, "_ast_matches_source", unexpected_parse)
    for _ in range(100):
        assert index.validate(path)


def test_trace_edge_and_alias_closure_require_exact_nodes_and_all_uses(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, trace, index = _case(tmp_path, _GOOD)
    path = tmp_path / "client.py"
    nodes = {
        getter.span_key(row): next(
            n
            for n in ast.walk(index.snapshots[path])
            if isinstance(n, (ast.stmt, ast.expr, ast.arg))
            and getter.coordinates(n)
            == tuple(row[key] for key in ("line", "column", "end_line", "end_column"))
        )
        for row in trace
    }
    row = trace[3]
    node = nodes[getter.span_key(row)]
    assert getter.covered_value_edge(node, "client.py", [trace], nodes)
    assert not getter.covered_value_edge(node, "foreign.py", [trace], nodes)
    assert not getter.covered_value_edge(
        ast.parse("foreign").body[0].value, "client.py", [trace], nodes
    )
    tree = ast.parse("def use(value):\n    alias = value\n    consume(alias)\n")
    function = tree.body[0]
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    load = function.body[1].value.args[0]
    assert getter.alias_is_closed(
        function.body[0].value, function, parents, [getter.coordinates(load)]
    )
    assert not getter.alias_is_closed(function.body[0].value, function, parents, [])


def test_getter_owner_inheritance_and_distinct_shadow_origin_are_source_bound(tmp_path):
    from factoryline import credential_role_method_use_getter_audit as getter
    from factoryline import review_audits as audit

    source = (
        _GOOD.replace(
            "    def endpoint(self):",
            "    def __init__(self):\n        pass\n    def endpoint(self):",
        )
        + "\nclass Derived(Client): pass\nclass Other:\n    ENDPOINT = 'different'\n"
    )
    _, _, index = _case(tmp_path, source)
    path = tmp_path / "client.py"
    tree = index.snapshots[path]
    classes = {
        (path, owner.name): owner
        for owner in tree.body
        if isinstance(owner, ast.ClassDef)
    }
    imports = {path: {}}
    owner = classes[(path, "Client")]
    fact = declaration_fact(index, path, owner.body[0])
    assert getter.related_owners(fact, index, imports, classes, audit) == {
        (path, "Client"),
        (path, "Derived"),
    }
    fields = {(path, "Client"): {"ENDPOINT"}}
    getter.inherited_fields(fields, index, imports, classes, audit)
    assert fields[(path, "Derived")] == {"ENDPOINT"}
    other = classes[(path, "Other")].body[0]
    different = ("client.py", getter.coordinates(other), index.inventory[path])
    same = ("client.py", getter.coordinates(owner.body[0]), index.inventory[path])
    assert getter.different_field_origin(
        ("client.py", "Client"),
        "endpoint",
        {"endpoint": [("ENDPOINT", different)]},
        index,
        imports,
        classes,
        audit,
    )
    assert not getter.different_field_origin(
        ("client.py", "Client"),
        "endpoint",
        {"endpoint": [("ENDPOINT", same)]},
        index,
        imports,
        classes,
        audit,
    )
    row = {"url_witnesses": [], "linked_unknown_uses": []}
    getter.audit_value_uses(fact, row, index, imports, classes, audit)
    assert row["value_use_audit"]["state"] == "INCOMPLETE"
    assert row["value_use_audit"]["declared_member_reads"] > 0
    assert row["linked_unknown_uses"]


@pytest.mark.parametrize(
    "use,expected",
    [("execute()", True), ("return execute()", False), ("execute(argument)", False)],
)
def test_discarded_finite_callable_projection_requires_discarded_zero_arg_use(
    use, expected
):
    from factoryline import credential_role_method_use_getter_audit as getter

    tree = ast.parse(
        "def run(self):\n    for execute, label in ((self.endpoint, 'label'),):\n        "
        + use
        + "\n"
    )
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "endpoint"
    )
    assert getter.discarded_callable_projection(node, parents) is expected


def test_record_projection_uses_captured_response_provider_and_not_unknown_calls(
    tmp_path,
):
    from factoryline import credential_role_method_use_getter_audit as getter

    _, _, index = _case(
        tmp_path,
        "import responses\n"
        + _GOOD
        + "\nvalue = responses.calls[0].request.url\nother = opaque()\n",
    )
    path = tmp_path / "client.py"
    tree = index.snapshots[path]
    model = getter.record_projection(
        index, path, {"responses": "responses", "requests": "requests"}
    )
    assert model.kind(tree.body[-2].value) == "url"
    assert model.kind(tree.body[-1].value) is None


def test_parameter_linkage_requires_captured_call_and_known_constructor_origin(
    tmp_path,
):
    from factoryline import credential_role_method_use_getter_audit as getter

    source = (
        _GOOD
        + "\ndef inspect(candidate):\n    return candidate.endpoint()\ninspect(Client())\n"
    )
    _, _, index = _case(tmp_path, source)
    path = tmp_path / "client.py"
    tree = index.snapshots[path]
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "inspect"
    )
    receiver = function.body[0].value.func.value
    call = tree.body[-1].value
    classes = {(path, "Client"): owner}
    assert getter.parameter_linked(
        path, receiver, [call], index, {path: {}}, classes, {(path, "Client")}
    )
    assert not getter.parameter_linked(
        path, receiver, [], index, {path: {}}, classes, {(path, "Client")}
    )


@pytest.mark.parametrize(
    "relation,reason",
    [
        ("LINKED", "reflective_getter_use"),
        ("UNKNOWN", "reflective_getter_receiver_unresolved"),
        ("UNRELATED", None),
    ],
)
def test_reflective_getter_reports_linked_and_unresolved_receivers_without_silent_clear(
    tmp_path, relation, reason
):
    from factoryline import credential_role_method_use_getter_audit as getter
    from factoryline import review_audits as audit

    source = (
        _GOOD + "\n    def reflect(self):\n        return getattr(self, 'endpoint')\n"
    )
    _, _, index = _case(tmp_path, source)
    path = tmp_path / "client.py"
    tree = index.snapshots[path]
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "getattr"
    )
    classes, imports = {(path, "Client"): owner}, {path: {}}
    unknown = []
    getter.audit_reflective(
        node,
        path,
        "client.py",
        [],
        {(path, "Client")},
        {"endpoint"},
        {},
        index,
        (imports, classes, audit),
        {(path, "Client")},
        imports,
        classes,
        audit,
        {},
        unknown,
        lambda *args: relation,
    )
    assert [row["reason"] for row in unknown] == ([] if reason is None else [reason])
