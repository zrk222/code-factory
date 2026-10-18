import ast
import hashlib
import textwrap

import pytest

from factoryline.credential_role_method_return import method_returns
from factoryline.credential_role_sources import SourceSnapshotIndex


def _method_index(tmp_path, function_source):
    source = textwrap.dedent(function_source).strip() + "\n"
    path = (tmp_path / "oauth.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    index.validate(path)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    return method_returns(function, index, path)


def test_try_return_with_reraising_handler_is_source_preserving(tmp_path):
    returns = _method_index(
        tmp_path,
        """def refresh_token_url(self):
    try:
        return self.REFRESH_URL or self.access_token_url()
    except AuthError as error:
        error.stage = 'refresh'
        raise""",
    )
    assert len(returns) == 1
    assert isinstance(returns[0].value, ast.BoolOp)


@pytest.mark.parametrize(
    "source",
    [
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        raise
    finally:
        return None""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        return self.other()""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        error.stage = 'refresh'
        pass""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        raise
    else:
        return self.other()""",
    ],
)
def test_try_return_rejects_overrides_and_normal_handler_paths(tmp_path, source):
    assert _method_index(tmp_path, source) == []
