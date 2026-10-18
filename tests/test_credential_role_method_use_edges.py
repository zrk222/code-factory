import ast

import pytest

from test_credential_role_method_use_audit import _GOOD, _case
from test_credential_method_endpoint_scanner import _scan
from factoryline.credential_role_method_use_audit import method_value_use_audit


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
