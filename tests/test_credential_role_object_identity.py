"""Lambda bodies are expressions and cannot be traversed as statement suites."""

import ast
import hashlib

import pytest

from factoryline.credential_role_object_identity import declared_origins
from factoryline.credential_role_sources import SourceSnapshotIndex


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
