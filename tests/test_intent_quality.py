from __future__ import annotations

import ast

import pytest

from factoryline.intent_quality import (
    IntentFinding,
    IntentQualityError,
    assess,
    findings_as_dict,
    normalize,
    require_clear,
)


def test_normalize_and_findings_as_dict_preserve_text_and_emit_stable_diagnostics():
    assert normalize("  A reviewer\n checks   the receipt. ") == (
        "A reviewer checks the receipt."
    )
    assert normalize(None) == ""

    findings = findings_as_dict("Make it better", field="acceptance")

    assert findings == [
        {
            "code": "INTENT_VAGUE_LANGUAGE",
            "message": "acceptance contains vague phrase: make_it_better",
        },
        {
            "code": "INTENT_NO_ACTION",
            "message": "acceptance does not state an observable action or state transition",
        },
    ]
    assert IntentFinding("INTENT_NO_ACTION", "missing action").as_dict() == {
        "code": "INTENT_NO_ACTION",
        "message": "missing action",
    }


def test_intent_quality_accepts_concrete_action_and_observation() -> None:
    text, findings = assess(
        "A reviewer can create a hash-bound receipt.",
        field="intent",
        require_observable=True,
    )
    assert text == "A reviewer can create a hash-bound receipt."
    assert findings == []


@pytest.mark.parametrize(
    "value, field, observable, code",
    [
        ("Make it better", "intent", False, "INTENT_VAGUE_LANGUAGE"),
        ("TODO", "intent", False, "INTENT_PLACEHOLDER"),
        ("Fine", "intent", False, "INTENT_NO_ACTION"),
        ("Do something", "acceptance", True, "INTENT_VAGUE_LANGUAGE"),
        ("The task runs", "acceptance", True, "INTENT_NOT_OBSERVABLE"),
    ],
)
def test_intent_quality_rejects_unverifiable_language(
    value: str, field: str, observable: bool, code: str
) -> None:
    with pytest.raises(IntentQualityError, match=code):
        require_clear(value, field=field, require_observable=observable)


@pytest.mark.parametrize(
    ("import_statement", "call_expression", "expected"),
    [
        (
            "import unittest.mock\n",
            "unittest.mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import unittest.mock as mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest import mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest.mock import MagicMock as Mock\n",
            "Mock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import xml.etree.ElementTree\n",
            "xml.etree.ElementTree.fromstring(data)",
            "xml.etree.ElementTree.fromstring",
        ),
        ("import pickle\n", "pickle.loads(data)", "pickle.loads"),
        (
            "import pickle as serializer\n",
            "serializer.loads(data)",
            "pickle.loads",
        ),
    ],
)
def test_import_aliases_follow_python_binding_semantics(
    import_statement: str, call_expression: str, expected: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(import_statement + f"def test_case():\n    {call_expression}\n")
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert _normalized_call_name(call, aliases) == expected


@pytest.mark.parametrize(
    ("import_statement", "binding", "call_expression"),
    [
        (
            "import unittest.mock\n",
            "unittest",
            "unittest.mock.MagicMock()",
        ),
        (
            "import unittest.mock as mock\n",
            "mock",
            "mock.MagicMock()",
        ),
        (
            "from unittest import mock\n",
            "mock",
            "mock.MagicMock()",
        ),
    ],
)
def test_import_aliases_are_invalidated_by_local_rebinding(
    import_statement: str, binding: str, call_expression: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        import_statement
        + f"def test_case():\n    {binding} = replacement\n    {call_expression}\n"
    )
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert binding not in aliases
    assert _normalized_call_name(call, aliases) == call_expression.removesuffix("()")


def test_local_dotted_import_rebinds_the_top_level_package_after_shadowing() -> None:
    from factoryline.review_audits import (
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        "def test_case():\n"
        "    unittest = replacement\n"
        "    import unittest.mock\n"
        "    unittest.mock.MagicMock()\n"
    )
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases({}, scope)

    assert aliases["unittest"] == "unittest"
    assert _normalized_call_name(call, aliases) == "unittest.mock.MagicMock"


@pytest.mark.parametrize(
    "case, source, rule, expected",
    [
        ('open_raw', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = request.args.get('filename')\n    open(os.path.join('/srv/uploads', name), 'wb')\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('open_exact_return_fixed_root', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = secure_filename(request.args.get('filename'))\n    open(os.path.join('/srv/uploads', name), 'wb')\n", 'SECURITY_PATH_TRAVERSAL', False),
        ('open_sibling_unsanitized', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    raw = request.args.get('filename')\n    clean = secure_filename(raw)\n    open(os.path.join('/srv/uploads', raw), 'wb')\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('open_later_rebind', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    name = secure_filename(request.args.get('filename'))\n    name = request.args.get('other')\n    open(os.path.join('/srv/uploads', name), 'wb')\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('open_custom_same_name', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    def secure_filename(value):\n        return value\n    name = secure_filename(request.args.get('filename'))\n    open(os.path.join('/srv/uploads', name), 'wb')\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('upload_fixed_root', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    file.save(os.path.join('/srv/uploads', secure_filename(file.filename)))\n", 'SECURITY_PATH_TRAVERSAL', False),
        ('upload_tainted_root', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    file.save(os.path.join(request.args.get('root'), secure_filename(file.filename)))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('upload_ignore_return', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    secure_filename(file.filename)\n    file.save(os.path.join('/srv/uploads', file.filename))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('upload_module_replaced', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    import werkzeug.utils\n    werkzeug.utils.secure_filename = lambda value: value\n    file = request.files['file']\n    file.save(os.path.join('/srv/uploads', werkzeug.utils.secure_filename(file.filename)))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('upload_return_rebind', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    leaf = secure_filename(file.filename)\n    leaf = file.filename\n    file.save(os.path.join('/srv/uploads', leaf))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('upload_branch_mismatch', "from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    file = request.files['file']\n    if request.args.get('safe'):\n        leaf = secure_filename(file.filename)\n    else:\n        leaf = file.filename\n    file.save(os.path.join('/srv/uploads', leaf))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('url_positional', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    requests.get(url)\n', 'SECURITY_SSRF', True),
        ('url_keyword', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    requests.get(url=url)\n', 'SECURITY_SSRF', True),
        ('url_guard_true', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {\'example.test\'}:\n        requests.get(url)\n', 'SECURITY_SSRF', False),
        ('url_guard_else', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {\'example.test\'}:\n        pass\n    else:\n        requests.get(url)\n', 'SECURITY_SSRF', True),
        ('url_guard_other', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    other = request.args.get(\'other\')\n    if urllib.parse.urlparse(other).hostname in {\'example.test\'}:\n        requests.get(url)\n', 'SECURITY_SSRF', True),
        ('url_guard_rebind', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {\'example.test\'}:\n        url = request.args.get(\'other\')\n        requests.get(url)\n', 'SECURITY_SSRF', True),
        ('url_custom_parser', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url = request.args.get("url")\n    def fake_parse(value):\n        return type(\'URL\', (), {\'hostname\':\'example.test\'})()\n    urllib.parse.urlparse = fake_parse\n    if urllib.parse.urlparse(url).hostname in {\'example.test\'}:\n        requests.get(url)\n', 'SECURITY_SSRF', True),
        ('sql_interpolated_positional', 'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users WHERE name=\' + name)\n', 'SECURITY_SQL_INJECTION', True),
        ('sql_interpolated_keyword', 'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(query=\'SELECT * FROM users WHERE name=\' + name)\n', 'SECURITY_SQL_INJECTION', True),
        ('sql_bound_parameter', 'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users WHERE name=%s\', (name,))\n', 'SECURITY_SQL_INJECTION', False),
        ('sql_bound_parameter_keyword', 'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(query=\'SELECT * FROM users WHERE name=%s\', params=(name,))\n', 'SECURITY_SQL_INJECTION', False),
        ('sql_tainted_query_with_params', 'from flask import request\nimport psycopg\ndef view():\n    conn = psycopg.connect("dbname=app")\n    cursor = conn.cursor()\n    name = request.args.get("name")\n    cursor.execute(\'SELECT * FROM users ORDER BY \' + name, ())\n', 'SECURITY_SQL_INJECTION', True),
        ('open_keyword_file', "from flask import request\ndef view():\n    open(file=request.args.get('path'))\n", 'SECURITY_PATH_TRAVERSAL', True),
        ('url_sibling_params', "from flask import request\nimport requests\ndef view():\n    requests.get('https://example.test', params={'next':request.args.get('url')})\n", 'SECURITY_SSRF', False),
        ('os_path_parent_replaced', 'from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\nfrom types import SimpleNamespace\nos.path=SimpleNamespace(join=lambda root,leaf: request.args.get("path"))\ndef view():\n    leaf=secure_filename(request.args.get("filename"))\n    open(os.path.join("/srv/uploads",leaf),"wb")\n', 'SECURITY_PATH_TRAVERSAL', True),
        ('urllib_parse_parent_replaced', 'from flask import request\nimport requests\nimport urllib.parse\nfrom types import SimpleNamespace\nurllib.parse=SimpleNamespace(urlparse=lambda value: SimpleNamespace(hostname="example.test"))\ndef view():\n    url=request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {"example.test"}:\n        requests.get(url=url)\n', 'SECURITY_SSRF', True),
        ('werkzeug_utils_parent_replaced', 'from flask import request\nimport werkzeug.utils\nimport os\nfrom types import SimpleNamespace\nwerkzeug.utils=SimpleNamespace(secure_filename=lambda value:value)\ndef view():\n    leaf=werkzeug.utils.secure_filename(request.args.get("filename"))\n    open(os.path.join("/srv/uploads",leaf),"wb")\n', 'SECURITY_PATH_TRAVERSAL', True),
        ('url_keyword_rebind_during_evaluation', 'from flask import request\nimport requests\nimport urllib.parse\ndef view():\n    url=request.args.get("url")\n    if urllib.parse.urlparse(url).hostname in {"example.test"}:\n        requests.get(params=(url := request.args.get("other")),url=url)\n', 'SECURITY_SSRF', True),
        ('sanitized_leaf_augmented_with_raw', 'from flask import request\nfrom werkzeug.utils import secure_filename\nimport os\ndef view():\n    leaf=secure_filename(request.args.get("filename"))\n    leaf += request.args.get("suffix")\n    open(os.path.join("/srv/uploads",leaf),"wb")\n', 'SECURITY_PATH_TRAVERSAL', True),
        ('bound-secure-filename-import-alias', "from flask import request\nfrom werkzeug.utils import secure_filename\ndef save_upload():\n    clean = secure_filename\n    uploaded = request.files['file']\n    uploaded.save('/uploads/' + clean(uploaded.filename))\n", 'SECURITY_PATH_TRAVERSAL', False),
    ],
)
def test_security_sink_slots_and_exact_sanitizer_results(
    tmp_path, case, source, rule, expected
):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    matching = [finding for finding in result["findings"] if finding["code"] == rule]
    assert bool(matching) is expected, (case, result)
    if expected:
        assert all(finding["severity"] == "HIGH" for finding in matching)


def test_sanitizer_provider_cache_is_invalidated_at_scope_binding():
    from factoryline.review_integrity import (
        _security_proven_callee,
        bind_security_call_scopes,
    )

    tree = ast.parse("import urllib.parse\ndef f(url):\n    return urllib.parse.urlparse(url)\n")
    call = tree.body[1].body[0].value
    aliases = {"urllib": "urllib"}
    bind_security_call_scopes(tree)
    assert _security_proven_callee(call, aliases, "urllib.parse.urlparse")
    tree.body.insert(1, ast.parse("urllib.parse.urlparse = replacement").body[0])
    bind_security_call_scopes(tree)
    assert not _security_proven_callee(call, aliases, "urllib.parse.urlparse")


def test_url_guard_does_not_survive_sibling_argument_effect(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(
        "from flask import request\nimport requests\nimport urllib.parse\n"
        "def view():\n    url = request.args.get('url')\n"
        "    def change_url():\n        nonlocal url\n"
        "        url = request.args.get('other')\n"
        "    if urllib.parse.urlparse(url).hostname in {'example.test'}:\n"
        "        requests.get(params=change_url(), url=url)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(row["code"] == "SECURITY_SSRF" for row in result["findings"])
