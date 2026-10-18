import ast
import hashlib
from types import SimpleNamespace

from factoryline.credential_role_method_flow import method_url_hops
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.review_integrity import bind_source_call


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
