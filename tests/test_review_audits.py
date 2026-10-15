from __future__ import annotations


import json
import hashlib
from pathlib import Path
import textwrap

import pytest

from factoryline.review_audits import (
    ReviewAuditError,
    audit_code,
    audit_fingerprint,
    load_tenant_read_contract,
    security_evals,
    security_scan,
)
from factoryline.change_review import ChangeReviewError, review_change
from factoryline.cli import main


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import httpx\nhttpx.Client(verify=False)", True),
        ("from httpx import AsyncClient as Client\nClient(verify=False)", True),
        ("import ssl\nssl._create_unverified_context()", True),
        ("from ssl import _create_unverified_context as context\ncontext()", True),
        ("import requests\nrequests.put(url, verify=False)", True),
        ("import httpx\nhttpx.stream('GET', url, verify=False)", True),
        ("import httpx\nhttpx.Client(verify=True)", False),
        ("import httpx\nhttpx.Client()", False),
        ("import ssl\nssl.create_default_context()", False),
        ("class Client:\n    pass\nClient(verify=False)", False),
        ("import httpx\ndef f(httpx):\n    return httpx.Client(verify=False)", False),
    ],
)
def test_tls_api_boundaries_detect_explicit_bypass(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source + "\n", encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_TLS_VERIFY_DISABLED" in result["finding_counts"]) is expected
    assert result["audit_coverage"]["complete"] is True


def _redirect_flow_source(
    *, sanitize, aliases=False, reverse_tuple=False, branch=False
):
    request_name = "Incoming" if aliases else "Request"
    sink_name = "Found" if aliases else "HTTPFound"
    request_import = (
        f"from aiohttp.web_request import Request as {request_name}"
        if aliases
        else "from aiohttp.web_request import Request"
    )
    sink_import = (
        f"from aiohttp.web_exceptions import HTTPFound as {sink_name}"
        if aliases
        else "from aiohttp.web_exceptions import HTTPFound"
    )
    clone_return = "return copied, True" if reverse_tuple else "return True, copied"
    caller_unpack = "clone, matched" if reverse_tuple else "matched, clone"
    candidate_alias = "path" if aliases else "candidate"
    normalize = (
        f"        {candidate_alias} = re.sub('^//+', '/', {candidate_alias})\n"
        if sanitize
        else ""
    )
    if branch:
        normalize = (
            "        if enabled:\n"
            f"            {candidate_alias} = re.sub('^//+', '/', {candidate_alias})\n"
        )
    imports = (
        f"{request_import}\n{sink_import}\n"
        "from aiohttp.web_exceptions import HTTPMove, HTTPPermanentRedirect\n"
        "from typing import Type\nimport re\n"
    )
    return (
        imports
        + "async def resolve(source: "
        + request_name
        + ", target):\n"
        + "    copied = source.clone(rel_url=target)\n"
        + "    "
        + clone_return
        + "\n"
        + "    return False, source\n"
        + "async def handle(request: "
        + request_name
        + ", redirect_class: Type[HTTPMove] = HTTPPermanentRedirect):\n"
        + "    original, query = request.raw_path.split('?', 1)\n"
        + "    candidates = [original]\n"
        + "    for "
        + candidate_alias
        + " in candidates:\n"
        + normalize
        + "        "
        + caller_unpack
        + " = await resolve(request, "
        + candidate_alias
        + ")\n"
        + "        if matched:\n"
        + "            raise redirect_class(clone.raw_path + query)\n"
    )


@pytest.mark.parametrize("sanitize", [False, True])
def test_redirect_source_findings_direct_api(sanitize):
    import ast

    from factoryline.review_audits import _security_aliases
    from factoryline.review_integrity import (
        bind_security_call_scopes,
        redirect_source_findings,
    )

    tree = ast.parse(_redirect_flow_source(sanitize=sanitize))
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    bind_security_call_scopes(tree)
    findings = redirect_source_findings("app.py", tree, aliases, nodes)
    expected = [] if sanitize else ["SECURITY_OPEN_REDIRECT"]
    assert [row["code"] for row in findings] == expected


@pytest.mark.parametrize("request_derived", [False, True])
def test_security_source_sink_findings_direct_api(request_derived):
    import ast

    from factoryline.review_audits import _security_aliases
    from factoryline.review_integrity import security_source_sink_findings

    target = "request.args['url']" if request_derived else "'https://example.com/items'"
    tree = ast.parse(
        "from flask import request\nimport requests\n"
        f"def fetch():\n    return requests.get({target})\n"
    )
    nodes = list(ast.walk(tree))
    findings = security_source_sink_findings(
        "app.py", tree, nodes, _security_aliases(nodes)
    )
    expected = ["SECURITY_SSRF"] if request_derived else []
    assert [row["code"] for row in findings] == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    password = request.GET['password']\n"
            "    if password == 'myPa55word':\n        return HttpResponse()\n",
            True,
        ),
        (
            "from flask import request\n"
            "def process_request():\n"
            "    if request.args['password'] == 'myPa55word':\n"
            "        return True\n",
            True,
        ),
        (
            "from flask import request as web_request\n"
            "def process_request():\n"
            "    supplied = web_request.args['password']\n"
            "    if supplied == 'myPa55word':\n        return True\n",
            True,
        ),
        (
            "from flask import request\n"
            "def process_request():\n"
            "    if request.form['password'] == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "from flask import request\n"
            "def process_request():\n"
            "    if request.args.get('password') == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "from flask import request as web_request\n"
            "def process_request():\n"
            "    supplied = web_request.form.get('password')\n"
            "    if supplied == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "import flask as web\n"
            "def process_request():\n"
            "    if web.request.form.get('password') == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "from flask import request\n"
            "def process_request():\n"
            "    if request.form.get('username') == 'literal-value':\n"
            "        return True\n",
            False,
        ),
        (
            "def process_request(data):\n"
            "    if data.get('password') == 'literal-value':\n"
            "        return True\n",
            False,
        ),
        (
            "def process_request():\n"
            "    if get('password') == 'literal-value':\n"
            "        return True\n",
            False,
        ),
        (
            "import flask\n"
            "def process_request():\n"
            "    if flask.request.args['password'] == 'myPa55word':\n"
            "        return True\n",
            True,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    if request.GET['password'] == 'myPa55word':\n"
            "        return HttpResponse()\n",
            True,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    supplied = request.GET['password']\n"
            "    password = supplied\n"
            "    if password == 'myPa55word':\n        return HttpResponse()\n",
            True,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    if request.GET['next'] == 'https://example.com/login':\n"
            "        return HttpResponse()\n",
            False,
        ),
        (
            "def process_request(password):\n"
            "    if password == 'myPa55word':\n        return True\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    request = object()\n"
            "    if request.GET['password'] == 'myPa55word':\n"
            "        return HttpResponse()\n",
            False,
        ),
        (
            "from django.http import HttpResponse\nimport os\n"
            "def process_request(request):\n"
            "    password = os.getenv('PASSWORD')\n"
            "    if password == 'myPa55word':\n        return HttpResponse()\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request, supplied):\n"
            "    password = request.GET['password']\n"
            "    password = supplied\n"
            "    if password == 'myPa55word':\n        return HttpResponse()\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request, expected):\n"
            "    password = request.GET['password']\n"
            "    if password == expected:\n        return HttpResponse()\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request, flag):\n"
            "    password = request.GET['password']\n"
            "    if flag:\n        password = ''\n"
            "    if password == 'myPa55word':\n        return HttpResponse()\n",
            True,
        ),
        (
            "from flask import request as web_request\n"
            "def process_request(web_request):\n"
            "    if web_request.args['password'] == 'myPa55word':\n"
            "        return True\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def process_request(request):\n"
            "    if request.GET['url'] == \"%!*'();:@&=+$,/?#[] \":\n"
            "        return HttpResponse()\n",
            False,
        ),
        (
            "from flask import request\nrequest = custom\n"
            "def check():\n"
            "    if request.args['password'] == 'literal-value':\n"
            "        return True\n",
            False,
        ),
        (
            "def check():\n"
            "    if request.args['password'] == 'literal-value':\n"
            "        return True\n"
            "    from flask import request\n",
            False,
        ),
        (
            "def check():\n"
            "    from flask import request\n"
            "    if request.args['password'] == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "from django.http import HttpResponse\n"
            "def check(request, flag, clean_a, clean_b):\n"
            "    supplied = request.GET['password']\n"
            "    if flag:\n        supplied = clean_a\n"
            "    else:\n        supplied = clean_b\n"
            "    if supplied == 'literal-value':\n        return HttpResponse()\n",
            False,
        ),
        (
            "from django.http import HttpResponse\n"
            "def check(request):\n"
            "    if request.GET['password'] == 'https://example.test/secret':\n"
            "        return HttpResponse()\n",
            True,
        ),
        (
            "from django.http import HttpResponse\n"
            "def check(request):\n"
            "    password = request.GET['password']\n"
            "    if password == 'todo':\n"
            "        return HttpResponse()\n",
            True,
        ),
        (
            "from flask import request\n"
            "def check():\n"
            "    for item in [0]:\n"
            "        password = request.args['password']\n"
            "    if password == 'literal-value':\n"
            "        return True\n",
            True,
        ),
        (
            "from flask import request\n"
            "def check():\n"
            "    if request.args['password'] == 'literal-value':\n"
            "        return True\n"
            "    from flask import request\n",
            False,
        ),
        (
            "from flask import request\n"
            "def check():\n"
            "    if request.args['password'] == 'literal-value':\n"
            "        return True\n"
            "    request = custom\n",
            False,
        ),
    ],
    ids=[
        "django-password-alias",
        "flask-password-direct",
        "flask-password-bound-alias",
        "flask-form-password-subscript",
        "flask-query-password-get",
        "flask-form-password-get-bound-alias",
        "flask-module-form-password-get",
        "flask-form-non-password-field",
        "unrelated-get-password-key",
        "unrelated-bare-get-password-key",
        "flask-module-qualified-request-args",
        "django-password-direct",
        "django-password-bound-alias",
        "safe-url-comparison",
        "ordinary-source-parameter",
        "local-request-rebind",
        "environment-value",
        "password-source-rebind",
        "nonliteral-comparison",
        "branch-rebind-possible-source",
        "flask-local-request-shadow",
        "url-quoting-safe-key",
        "flask-module-rebind",
        "flask-local-import-after-comparison",
        "flask-local-import-before-comparison",
        "both-branches-kill-password-source",
        "hardcoded-url-password-value",
        "hardcoded-placeholder-password-value",
        "loop-introduced-password-source-survives",
        "module-flask-alias-late-local-import-clears",
        "module-flask-alias-late-assignment-clears",
    ],
)
def test_security_scan_request_password_literal_comparison(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    secret_findings = [
        finding
        for finding in findings
        if finding["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert bool(secret_findings) is expected
    if expected:
        assert all(
            finding["facts"].get("name") == "password_comparison"
            for finding in secret_findings
        )


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + uploaded.filename)\n",
            True,
        ),
        (
            "from flask import request as req\nimport os\n"
            "def save_upload():\n"
            "    uploaded = req.files.get('file')\n"
            "    name = uploaded.filename\n"
            "    target = os.path.join('/uploads', name)\n"
            "    uploaded.save(target)\n",
            True,
        ),
        (
            "import flask\n"
            "def save_upload():\n"
            "    uploaded = flask.request.files['file']\n"
            "    uploaded.save('/uploads/' + uploaded.filename)\n",
            True,
        ),
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    alias = uploaded\n"
            "    alias.save('/uploads/' + alias.filename)\n",
            True,
        ),
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save(f'/uploads/{uploaded.filename}')\n",
            True,
        ),
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + identity(value=uploaded.filename))\n",
            True,
        ),
        (
            "from flask import request\n"
            "from pathlib import Path\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save(Path('/uploads') / uploaded.filename)\n",
            True,
        ),
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/fixed.bin')\n",
            False,
        ),
        (
            "from flask import request\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + secure_filename(uploaded.filename))\n",
            False,
        ),
        (
            "from flask import request\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload(secure_filename):\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + secure_filename(uploaded.filename))\n",
            True,
        ),
        (
            "from flask import request\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload():\n"
            "    clean = secure_filename\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + clean(uploaded.filename))\n",
            False,
        ),
        (
            "from flask import request\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload():\n"
            "    clean = secure_filename\n"
            "    clean = identity\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save('/uploads/' + clean(uploaded.filename))\n",
            True,
        ),
        (
            "from flask import request\n"
            "def save_upload(request):\n"
            "    uploaded = request.files['file']\n"
            "    uploaded.save(uploaded.filename)\n",
            False,
        ),
        (
            "from flask import request\n"
            "def save_upload(other):\n"
            "    uploaded = request.files['file']\n"
            "    uploaded = other\n"
            "    uploaded.save(uploaded.filename)\n",
            False,
        ),
        (
            "from flask import request\n"
            "def save_upload():\n"
            "    fake = object()\n"
            "    fake.save(request.files['file'].filename)\n",
            False,
        ),
        (
            "from flask import request\n"
            "def save_upload(flag):\n"
            "    uploaded = request.files['file']\n"
            "    if flag:\n        uploaded = object()\n"
            "    else:\n        uploaded = object()\n"
            "    uploaded.save(uploaded.filename)\n",
            False,
        ),
        (
            "from flask import request\n"
            "def save_upload(flag):\n"
            "    uploaded = request.files['file']\n"
            "    if flag:\n        uploaded = object()\n"
            "    uploaded.save(uploaded.filename)\n",
            True,
        ),
        (
            "from flask import request\nimport os\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload():\n"
            "    uploaded = request.files['file']\n"
            "    directory = request.form['directory']\n"
            "    clean = secure_filename(uploaded.filename)\n"
            "    uploaded.save(os.path.join(directory, clean))\n",
            True,
        ),
        (
            "from flask import request\nimport os\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload(flag):\n"
            "    uploaded = request.files['file']\n"
            "    directory = request.form['directory']\n"
            "    if flag:\n        clean = secure_filename(uploaded.filename)\n"
            "    else:\n        clean = request.form['name']\n"
            "    uploaded.save(os.path.join(directory, clean))\n",
            True,
        ),
        (
            "from flask import request\nimport os\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload(flag):\n"
            "    uploaded = request.files['file']\n"
            "    directory = '/uploads'\n"
            "    if flag:\n        clean = secure_filename(uploaded.filename)\n"
            "    else:\n        clean = secure_filename(uploaded.filename)\n"
            "    uploaded.save(os.path.join(directory, clean))\n",
            False,
        ),
        (
            "from flask import request\nimport os\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload(flag):\n"
            "    uploaded = request.files['file']\n"
            "    directory = request.form['directory']\n"
            "    if flag:\n        directory = secure_filename(directory)\n"
            "    uploaded.save(os.path.join(directory, 'fixed.txt'))\n",
            True,
        ),
        (
            "from flask import request\nimport os\n"
            "from werkzeug.utils import secure_filename\n"
            "def save_upload(flags):\n"
            "    uploaded = request.files['file']\n"
            "    directory = request.form['directory']\n"
            "    for flag in flags:\n        directory = secure_filename(directory)\n"
            "    uploaded.save(os.path.join(directory, 'fixed.txt'))\n",
            True,
        ),
    ],
    ids=[
        "direct-request-files-subscript",
        "get-bound-alias-join-path",
        "module-qualified-flask-request-files",
        "upload-object-alias",
        "fstring-destination",
        "unknown-keyword-wrapper-preserves-path-taint",
        "pathlib-destination",
        "constant-destination",
        "werkzeug-secure-filename",
        "shadowed-secure-filename-does-not-sanitize",
        "bound-secure-filename-import-alias",
        "rebound-sanitizer-alias-is-not-proven",
        "shadowed-flask-request-parameter",
        "rebound-upload-alias",
        "unrelated-save-method",
        "both-branches-rebind-upload",
        "one-branch-retains-possible-upload",
        "sanitized-leaf-does-not-contain-untrusted-directory",
        "one-branch-unsafe-upload-leaf-still-finds",
        "both-branches-sanitize-upload-leaf",
        "one-branch-sanitizes-directory-still-finds",
        "zero-iteration-loop-retains-directory-taint",
    ],
)
def test_security_scan_flask_upload_filename_save_paths(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = [
        finding
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
        if finding["code"] == "SECURITY_PATH_TRAVERSAL"
    ]
    assert len(findings) == int(expected)
    if findings:
        assert findings[0]["facts"] == {"call": "flask.FileStorage.save"}
        assert findings[0]["severity"] == "HIGH"


def test_security_scan_synthetic_django_password_comparison(tmp_path):
    source = (
        "from django.http import HttpResponse\n"
        "def compare_password(request):\n"
        "    candidate = request.GET['password']\n"
        "    if candidate == 'synthetic-password-value':\n"
        "        return HttpResponse()\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert any(
        finding["code"] == "SECURITY_HARDCODED_SECRET"
        and finding["facts"].get("name") == "password_comparison"
        for finding in findings
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        (_redirect_flow_source(sanitize=False), True),
        (_redirect_flow_source(sanitize=True), False),
        (
            _redirect_flow_source(sanitize=False, aliases=True, reverse_tuple=True),
            True,
        ),
        (_redirect_flow_source(sanitize=True, branch=True), True),
    ],
)
def test_aiohttp_request_clone_tuple_redirect_flow(tmp_path, source, expected):
    compile(source, "redirect_fixture.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_OPEN_REDIRECT" in report["finding_counts"]) is expected
    assert report["audit_coverage"]["complete"] is True
    if expected:
        finding = next(
            item
            for item in report["findings"]
            if item["code"] == "SECURITY_OPEN_REDIRECT"
        )
        assert finding["facts"]["cwe"] == "CWE-601"


def test_aiohttp_clone_summary_rejects_competing_success_return(tmp_path):
    source = _redirect_flow_source(sanitize=True).replace(
        "    return True, copied\n    return False, source\n",
        "    if bypass:\n        return bypass, source\n    return True, copied\n",
    )
    compile(source, "redirect_competing_return.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_clone_summary_rejects_rebound_clone_value(tmp_path):
    source = _redirect_flow_source(sanitize=True).replace(
        "    copied = source.clone(rel_url=target)\n",
        "    copied = source.clone(rel_url=target)\n    copied = source\n",
    )
    compile(source, "redirect_rebound_clone.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_clone_summary_rejects_unknown_success_request_slot(tmp_path):
    source = (
        _redirect_flow_source(sanitize=True)
        .replace(
            "async def resolve(source: Request, target):",
            "async def resolve(source: Request, target, bypass=False):",
        )
        .replace(
            "    return True, copied\n    return False, source\n",
            "    alias = source\n"
            "    if bypass:\n"
            "        return True, alias\n"
            "    return True, copied\n"
            "    return False, source\n",
        )
    )
    compile(source, "redirect_unknown_success_slot.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_second_clone_call_does_not_clear_aliased_first_tuple(tmp_path):
    source = (
        _redirect_flow_source(sanitize=True)
        .replace(
            "        matched, clone = await resolve(request, candidate)\n",
            "        matched, clone = await resolve(request, original)\n"
            "        old_clone = clone\n"
            "        matched, clone = await resolve(request, candidate)\n",
        )
        .replace(
            "raise redirect_class(clone.raw_path + query)",
            "raise redirect_class(old_clone.raw_path + query)",
        )
    )
    compile(source, "redirect_reused_tuple_guard.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


@pytest.mark.parametrize("binding", ["matched = False", "clone = request"])
def test_aiohttp_assignment_invalidates_success_tuple_guard(tmp_path, binding):
    source = _redirect_flow_source(sanitize=True).replace(
        "        if matched:\n", f"        {binding}\n        if matched:\n"
    )
    compile(source, "redirect_overwritten_guard.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


@pytest.mark.parametrize(
    "loop",
    [
        "for candidate in [request.raw_path]:",
        "for candidate in request.raw_path.split('?'):",
    ],
)
def test_aiohttp_redirect_flow_handles_expression_iterables(tmp_path, loop):
    source = _redirect_flow_source(sanitize=False).replace(
        "    candidates = [original]\n    for candidate in candidates:",
        f"    {loop}",
    )
    compile(source, "redirect_expression_loop.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_clone_helper_supports_keyword_only_path_argument(tmp_path):
    source = (
        _redirect_flow_source(sanitize=False)
        .replace(
            "async def resolve(source: Request, target):",
            "async def resolve(*, source: Request, target):",
        )
        .replace(
            "await resolve(request, candidate)",
            "await resolve(source=request, target=candidate)",
        )
    )
    compile(source, "redirect_keyword_only.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


@pytest.mark.parametrize(
    "shadow",
    ["parameter", "local"],
)
def test_aiohttp_clone_helper_name_rebinding_is_not_trusted(tmp_path, shadow):
    source = _redirect_flow_source(sanitize=True)
    signature = "async def handle(request: Request, redirect_class: Type[HTTPMove] = HTTPPermanentRedirect):"
    if shadow == "parameter":
        source = source.replace(
            signature,
            "async def handle(request: Request, resolve, redirect_class: Type[HTTPMove] = HTTPPermanentRedirect):",
        )
    else:
        source = source.replace(
            "    original, query = request.raw_path.split('?', 1)",
            "    resolve = other\n    original, query = request.raw_path.split('?', 1)",
        )
    compile(source, "redirect_shadowed_helper.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_loop_carried_path_reaches_later_iteration_sink(tmp_path):
    source = (
        "from aiohttp.web_request import Request\n"
        "from aiohttp.web_exceptions import HTTPFound\n"
        "def send(request: Request):\n"
        "    target = '/'\n"
        "    for item in (1, 2):\n"
        "        if item == 2:\n"
        "            raise HTTPFound(target)\n"
        "        target = request.raw_path\n"
    )
    compile(source, "redirect_loop_carried.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


@pytest.mark.parametrize(
    "source",
    [
        "from aiohttp.web_request import Request\n"
        "from aiohttp.web_exceptions import HTTPBadRequest\n"
        "def send(request: Request):\n"
        "    raise HTTPBadRequest(request.raw_path)\n",
        "from aiohttp.web_request import Request\n"
        "from aiohttp.web_exceptions import HTTPFound\n"
        "HTTPFound = custom\n"
        "def send(request: Request):\n"
        "    raise HTTPFound(request.raw_path)\n",
    ],
)
def test_nonredirect_or_rebound_exception_is_not_redirect_sink(tmp_path, source):
    compile(source, "redirect_sink_control.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "SECURITY_OPEN_REDIRECT" not in report["finding_counts"]


@pytest.mark.parametrize(
    "source",
    [
        "from aiohttp.web_request import Request as Incoming\n"
        "Incoming = CustomRequest\n"
        "from aiohttp.web_exceptions import HTTPFound\n"
        "def send(request: Incoming):\n"
        "    raise HTTPFound(request.raw_path)\n",
        "from aiohttp.web_request import Request\n"
        "from aiohttp.web_exceptions import HTTPFound\n"
        "def send(request: Request, HTTPFound):\n"
        "    raise HTTPFound(request.raw_path)\n",
    ],
)
def test_aiohttp_rebound_request_or_local_sink_is_not_trusted(tmp_path, source):
    compile(source, "redirect_binding_control.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "SECURITY_OPEN_REDIRECT" not in report["finding_counts"]


def test_aiohttp_redirect_alias_flags_full_url_despite_path_only_rewrite(tmp_path):
    source = (
        "from aiohttp.web_request import Request as Incoming\n"
        "from aiohttp.web_exceptions import HTTPFound as Found\n"
        "import re\n"
        "def send(request: Incoming):\n"
        "    target = request.url\n"
        "    target = re.sub('^//+', '/', target)\n"
        "    raise Found(target)\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_aiohttp_normalized_candidate_without_success_guard_is_not_cleared(tmp_path):
    source = _redirect_flow_source(sanitize=True).replace(
        "        if matched:\n            raise redirect_class(",
        "        raise redirect_class(",
    )
    compile(source, "redirect_control.py", "exec")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"]["SECURITY_OPEN_REDIRECT"] == 1


def test_untyped_clone_lookalike_does_not_claim_aiohttp_flow(tmp_path):
    source = (
        "class Request:\n"
        "    def clone(self, rel_url):\n"
        "        return self\n"
        "def send(request):\n"
        "    copy = request.clone(rel_url=request.path)\n"
        "    raise redirect(copy.path)\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "SECURITY_OPEN_REDIRECT" not in report["finding_counts"]


def test_tls_default_expression_uses_enclosing_import_not_parameter(tmp_path):
    (tmp_path / "app.py").write_text(
        "import httpx\ndef f(httpx=httpx.Client(verify=False)):\n    return httpx\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"]["SECURITY_TLS_VERIFY_DISABLED"] == 1


@pytest.mark.parametrize(
    "body,expected",
    [
        ("session = requests.Session()\n    session.verify = False", True),
        ("session = requests.Session()\n    session.verify = True", False),
        ("session = object()\n    session.verify = False", False),
        (
            "session = requests.Session()\n    session = object()\n    session.verify = False",
            False,
        ),
        (
            "requests = custom\n    session = requests.Session()\n    session.verify = False",
            False,
        ),
        (
            "if condition:\n        session = requests.Session()\n    session.verify = False",
            False,
        ),
    ],
)
def test_session_tls_assignment_requires_known_unrebound_receiver(
    tmp_path, body, expected
):
    (tmp_path / "app.py").write_text(
        "import requests\ndef configure():\n    " + body + "\n", encoding="utf-8"
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_TLS_VERIFY_DISABLED" in result["finding_counts"]) is expected


@pytest.mark.parametrize(
    "body,code,expected",
    [
        (
            "flag = True\n    subprocess.run(command, shell=flag)",
            "SECURITY_SHELL_COMMAND",
            True,
        ),
        (
            "flag = True\n    alias = flag\n    subprocess.run(command, shell=alias)",
            "SECURITY_SHELL_COMMAND",
            True,
        ),
        (
            "flag = True\n    flag = False\n    subprocess.run(command, shell=flag)",
            "SECURITY_SHELL_COMMAND",
            False,
        ),
        (
            "flag = True\n    if condition:\n        flag = False\n    subprocess.run(command, shell=flag)",
            "SECURITY_SHELL_COMMAND",
            False,
        ),
        (
            "reader = pickle.loads\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
        ),
        (
            "reader = pickle.loads\n    other = reader\n    other(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
        ),
        (
            "import _pickle as cPickle\n    cPickle.loads(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
        ),
        (
            "from _pickle import loads as reader\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
        ),
        pytest.param(
            "import _pickle as cPickle\n    cPickle.load(handle)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
            id="pickle-load-module",
        ),
        pytest.param(
            "from _pickle import load as reader\n    reader(handle)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
            id="pickle-load-import",
        ),
        (
            "import _pickle as cPickle\n    reader = cPickle.loads\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            True,
        ),
        (
            "import _pickle as cPickle\n    cPickle = custom\n    cPickle.loads(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "import _pickle as cPickle\n    def nested(cPickle):\n        cPickle.loads(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "import _pickle as cPickle\n    cPickle.dumps(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "reader = pickle.loads\n    reader = lambda value: value\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "reader = pickle.loads\n    if condition:\n        reader = safe\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "pickle = custom\n    reader = pickle.loads\n    reader(data)",
            "SECURITY_UNSAFE_DESERIALIZATION",
            False,
        ),
        (
            "import httpx\n    httpx.Client(verify=False)",
            "SECURITY_TLS_VERIFY_DISABLED",
            True,
        ),
    ],
)
def test_security_binding_flow_rejects_uncertain_or_rebound_aliases(
    tmp_path, body, code, expected
):
    (tmp_path / "app.py").write_text(
        "import subprocess\nimport pickle\ndef operate(httpx=None):\n    "
        + body
        + "\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert (code in result["finding_counts"]) is expected


def test_security_flow_cache_preserves_per_call_alias_state(monkeypatch):
    import ast
    import factoryline.review_integrity as integrity
    from factoryline.review_integrity import (
        bind_security_call_scopes,
        security_call_name,
    )

    tree = ast.parse(
        "import pickle\ndef f(data):\n    reader = pickle.loads\n    reader(data)\n    reader = safe\n    reader(data)\n"
    )
    bind_security_call_scopes(tree)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    original = integrity._security_flow_snapshots
    visits = []

    def count(scope, aliases):
        visits.append(scope)
        return original(scope, aliases)

    monkeypatch.setattr(integrity, "_security_flow_snapshots", count)
    assert security_call_name(calls[0], {"pickle": "pickle"}) == "pickle.loads"
    assert security_call_name(calls[1], {"pickle": "pickle"}) == "reader"
    assert security_call_name(calls[0], {"pickle": "pickle"}) == "pickle.loads"
    assert len(visits) == len(set(visits)) == 2


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def f():\n    reader(data)\n    from pickle import loads as reader\n",
            False,
        ),
        (
            "def f():\n    from pickle import loads as reader\n    reader(data)\n",
            True,
        ),
        (
            "import pickle\ndef outer():\n    reader = pickle.loads\n"
            "    def inner():\n        reader(data)\n",
            True,
        ),
        (
            "import pickle\ndef outer():\n    reader = pickle.loads\n"
            "    def middle():\n        def inner():\n            reader(data)\n",
            True,
        ),
        (
            "import pickle\ndef outer():\n    reader = pickle.loads\n"
            "    def inner():\n        reader(data)\n    reader = safe\n",
            False,
        ),
        (
            "import pickle\ndef outer():\n    if condition:\n"
            "        reader = pickle.loads\n    def inner():\n        reader(data)\n",
            False,
        ),
    ],
)
def test_security_alias_flow_tracks_late_imports_and_stable_closures(
    tmp_path, source, expected
):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_UNSAFE_DESERIALIZATION" in result["finding_counts"]) is expected


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import subprocess\ndef outer():\n    flag = True\n"
            "    def inner():\n        subprocess.run(command, shell=flag)\n",
            True,
        ),
        (
            "import subprocess\ndef outer():\n    flag = True\n"
            "    def inner():\n        subprocess.run(command, shell=flag)\n    flag = False\n",
            False,
        ),
        (
            "import subprocess\ndef outer():\n    if condition:\n        flag = True\n"
            "    def inner():\n        subprocess.run(command, shell=flag)\n",
            False,
        ),
    ],
)
def test_shell_flag_closure_requires_stable_unconditional_binding(
    tmp_path, source, expected
):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_SHELL_COMMAND" in result["finding_counts"]) is expected


def test_security_flow_separates_class_defaults_from_method_globals(tmp_path):
    (tmp_path / "app.py").write_text(
        "class TestClient:\n"
        "    from pickle import loads as reader\n"
        "    def method(self):\n        reader(data)\n"
        "\nimport httpx\n"
        "class App:\n"
        "    def request(self, client=httpx.Client(verify=False)):\n        return client\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"]["SECURITY_TLS_VERIFY_DISABLED"] == 1
    assert "SECURITY_UNSAFE_DESERIALIZATION" not in result["finding_counts"]


@pytest.mark.parametrize(
    "source",
    [
        "from pickle import loads as reader\n"
        "def outer(reader):\n    def inner():\n        reader(data)\n",
        "from pickle import loads as reader\n"
        "def outer():\n    reader = safe\n"
        "    def nested():\n        global reader\n"
        "    def inner():\n        reader(data)\n",
        "from pickle import loads as reader\n"
        "def outer(reader):\n    def middle():\n"
        "        def inner():\n            reader(data)\n",
    ],
)
def test_security_closure_shadow_never_resurrects_module_import(tmp_path, source):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert "SECURITY_UNSAFE_DESERIALIZATION" not in result["finding_counts"]


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def fetch(httpx):\n    httpx.get(url, verify=False)\n",
            False,
        ),
        (
            "def fetch():\n    requests = custom\n"
            "    requests.get(url, verify=False)\n",
            False,
        ),
        (
            "import httpx as client\n"
            "def fetch(httpx):\n    client.get(url, verify=False)\n",
            True,
        ),
    ],
)
def test_tls_call_requires_unshadowed_import_binding(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_TLS_VERIFY_DISABLED" in result["finding_counts"]) is expected


def test_class_body_does_not_see_module_import_after_class_definition(tmp_path):
    (tmp_path / "app.py").write_text(
        "class C:\n    reader(data)\nfrom pickle import loads as reader\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert "SECURITY_UNSAFE_DESERIALIZATION" not in result["finding_counts"]


def test_shell_flow_cache_preserves_boolean_changes_without_cross_call_leakage():
    import ast
    from factoryline.review_integrity import (
        bind_security_call_scopes,
        shell_execution_enabled,
    )

    tree = ast.parse(
        "def f(command):\n    enabled = True\n    launch(command, shell=enabled)\n"
        "    enabled = False\n    launch(command, shell=enabled)\n"
    )
    bind_security_call_scopes(tree)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert shell_execution_enabled(calls[0]) is True
    assert shell_execution_enabled(calls[1]) is False
    assert shell_execution_enabled(calls[0]) is True


@pytest.mark.parametrize(
    "body,hollow",
    [
        ("import product.interface", False),
        ("from product import interface", False),
        ("import product.interface as api", False),
        (
            '"""The public interface is importable."""\nfrom product import interface',
            False,
        ),
        ("try:\n    import product.interface\nexcept ImportError:\n    pass", True),
        ("if False:\n    import product.interface", True),
        ("def deferred():\n    import product.interface", True),
        ("return\nimport product.interface", True),
        ("import product.interface\nassert True", True),
        ("import product.interface\nresult = compute()", True),
        ('"""import product.interface"""', True),
        ("from product import *", True),
    ],
)
def test_import_behavior_oracle_requires_direct_complete_body(tmp_path, body, hollow):
    (tmp_path / "test_interfaces.py").write_text(
        "def test_import_interface():\n" + textwrap.indent(body, "    ") + "\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"]) is hollow


def test_import_behavior_does_not_exempt_unrelated_test_name(tmp_path):
    (tmp_path / "test_interfaces.py").write_text(
        "def test_compute():\n    import product.interface\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])


def test_import_smoke_oracle_direct_async_and_missing_body():
    import ast
    from factoryline.review_integrity import import_smoke_oracle

    assert import_smoke_oracle(
        ast.parse("async def test_import_api():\n    from product import api").body[0]
    )
    assert not import_smoke_oracle(
        ast.parse("def test_import_api():\n    pass").body[0]
    )
    assert not import_smoke_oracle(ast.parse("import product"))


def test_import_behavior_negative_control_fails_on_removed_export(tmp_path):
    import subprocess
    import sys

    module = tmp_path / "public_interface.py"
    module.write_text("supported = object()\n")
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        f"import sys; sys.path.insert(0, {str(tmp_path)!r}); from public_interface import supported",
    ]
    baseline = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert baseline.returncode == 0, baseline.stderr
    module.write_text("removed = object()\n")
    mutated = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert mutated.returncode != 0
    assert "ImportError" in mutated.stderr and "supported" in mutated.stderr


def test_attribute_access_oracle_requires_import_binding_and_no_dynamic_fallback(
    tmp_path,
):
    product = tmp_path / "product.py"
    product.write_text("public = object()\n")
    test_file = tmp_path / "test_product.py"
    test_file.write_text("import product\ndef test_public():\n    product.public\n")
    assert not any(
        f["code"] == "QUALITY_HOLLOW_TEST"
        for f in security_scan(tmp_path, cache_enabled=False)["findings"]
    )

    test_file.write_text(
        "from unittest.mock import Mock\nproduct = Mock()\ndef test_public():\n    product.public\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    test_file.write_text(
        "import product\ndef test_public():\n"
        "    from unittest.mock import sentinel as product\n    product.anything\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    test_file.write_text("def test_public():\n    unresolved.public\n")
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    product.write_text("def __getattr__(name):\n    return object()\n")
    test_file.write_text("import product\ndef test_public():\n    product.missing\n")
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])


def test_annotated_stub_oracle_requires_source_bound_constructor(tmp_path):
    (tmp_path / "api.py").write_text(
        "class Middleware:\n    def __init__(self, handler):\n        self.handler = handler\n"
    )
    test = tmp_path / "test_api.py"
    test.write_text(
        "from api import Middleware\n"
        "def test_constructs():\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(
        f["code"] == "QUALITY_TYPECHECK_NOT_VERIFIED" for f in report["findings"]
    )
    assert not any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    test.write_text(
        "from api import Middleware\nfrom unittest.mock import Mock\nMiddleware = Mock()\n"
        "def test_constructs():\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    test.write_text(
        "from api import Middleware\n"
        "def test_constructs(Middleware):\n"
        "    class App(Middleware):\n"
        "        pass\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    App(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])

    test.write_text(
        "from api import Middleware\n"
        "def test_constructs(Middleware):\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in report["findings"])


def test_annotated_callable_oracle_requires_source_bound_constructor():
    import ast

    from factoryline.review_integrity import annotated_callable_oracle

    node = ast.parse(
        "def test_constructs():\n"
        "    def handler(request: Request) -> Response:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    ).body[0]
    context = {
        "class_imports": {"Middleware": "Middleware"},
        "module_rebindings": set(),
    }
    assert annotated_callable_oracle(node, context)
    assert not annotated_callable_oracle(
        node, {**context, "module_rebindings": {"Middleware"}}
    )


def test_structural_oracle_status_reports_attribute_and_abstains_on_unknown_root():
    import ast

    from factoryline.review_integrity import structural_oracle_status

    trusted = ast.parse("def test_public():\n    api.public\n").body[0]
    context = {"module_imports": {"api": "product.api"}}
    assert structural_oracle_status(trusted, context) == "attribute"

    unresolved = ast.parse("def test_public():\n    unknown.public\n").body[0]
    assert structural_oracle_status(unresolved, context) is None


def test_structural_oracle_finding_preserves_unverified_typecheck_state():
    import ast

    from factoryline.review_integrity import structural_oracle_finding

    node = ast.parse(
        "def test_constructs():\n"
        "    def handler(request: Request) -> Response:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    ).body[0]
    context = {
        "class_imports": {"Middleware": "Middleware"},
        "module_rebindings": set(),
    }
    finding = structural_oracle_finding(node, "tests/test_api.py", context)
    assert finding == {
        "code": "QUALITY_TYPECHECK_NOT_VERIFIED",
        "severity": "INFO",
        "path": "tests/test_api.py",
        "line": 1,
        "column": 0,
        "message": "Source-bound API construction passed; no type-checker receipt was verified.",
        "facts": {
            "symbol": "test_constructs",
            "state": "INCOMPLETE",
            "typecheck": "NOT_VERIFIED",
        },
    }
    assert (
        structural_oracle_finding(
            node,
            "tests/test_api.py",
            {**context, "module_rebindings": {"Middleware"}},
        )
        is None
    )


@pytest.mark.parametrize(
    "call,expected",
    [
        ("dispatch(check)", "check"),
        ("dispatch(callback=check)", "check"),
        ("dispatch(lambda: None)", None),
        ("dispatch(**options)", None),
    ],
)
def test_callback_argument_binding(call, expected):
    import ast
    from factoryline.review_integrity import callback_argument

    function = ast.parse("def dispatch(callback): pass").body[0]
    assert (
        callback_argument(ast.parse(call).body[0].value, function, "callback")
        == expected
    )


def test_registered_callback_oracle_checks_initializer_and_live_assertion():
    import ast
    from factoryline.review_integrity import registered_callback_oracle

    function = ast.parse(
        textwrap.dedent("""
        def test_dispatch():
            checks = []
            def install(fn):
                checks.append(fn)
                return fn
            @install
            def verify(value):
                assert value == 42
            for callback in checks:
                callback(42)
    """)
    ).body[0]

    def strong(fn, aliases):
        return any(isinstance(node, ast.Assert) for node in ast.walk(fn))

    def effective(node, aliases):
        return True

    assert registered_callback_oracle(function, {}, strong, effective)
    assert not registered_callback_oracle(
        function, {}, strong, lambda node, aliases: False
    )
    callback = function.body[2]
    saved_body = callback.body
    callback.body = [ast.Pass()]
    assert not registered_callback_oracle(function, {}, strong, effective)
    callback.body = saved_body
    function.body[0].value.elts.append(ast.Constant(1))
    assert not registered_callback_oracle(function, {}, strong, effective)


def test_mock_patch_dict_slot_rejects_nonliteral_receiver():
    import ast
    from factoryline.review_integrity import mock_patch_dict_slot

    receiver = ast.parse("proxies[key]").body[0].value
    assert not mock_patch_dict_slot(
        receiver,
        "proxies",
        ast.parse("check()").body[0],
        {},
        [],
        set(),
        lambda node, aliases: ast.unparse(node),
        lambda *args: False,
        lambda *args: True,
        lambda *args: "proxies",
    )


@pytest.mark.parametrize(
    "registration,mutation,dispatch,hollow",
    [
        (
            "checks.append(fn); return fn",
            "",
            "for callback in checks:\n        callback(42)",
            False,
        ),
        ("return fn", "", "for callback in checks:\n        callback(42)", True),
        (
            "checks.append(lambda value: None); return fn",
            "",
            "for callback in checks:\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "checks.clear()",
            "for callback in checks:\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "checks = []",
            "for callback in checks:\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "alias = checks; alias.clear()",
            "for callback in checks:\n        callback(42)",
            True,
        ),
        ("checks.append(fn); return fn", "", "pass", True),
        (
            "checks.append(fn); return fn",
            "",
            "for callback in []:\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "",
            "for callback in checks:\n        callback = lambda value: None\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "",
            "try:\n        for callback in checks:\n            callback(42)\n    except AssertionError:\n        pass",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "mutate(checks)",
            "for callback in checks:\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "",
            "for callback in checks:\n        if False:\n            callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "",
            "for callback in checks:\n        break\n        callback(42)",
            True,
        ),
        (
            "checks.append(fn); return fn",
            "return",
            "for callback in checks:\n        callback(42)",
            True,
        ),
    ],
)
def test_local_registered_callback_requires_identity_dispatch_and_escape(
    tmp_path, registration, mutation, dispatch, hollow
):
    source = (
        "def test_behavior():\n    checks = []\n    def register(fn):\n        "
        + registration
        + "\n    @register\n    def check(value):\n        assert value == 42\n    "
        + mutation
        + "\n    "
        + dispatch
        + "\n"
    )
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    flagged = any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )
    assert flagged is hollow


def test_local_registry_proof_is_independent_of_names(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    tasks = []\n    def install(handler):\n"
        "        tasks.append(handler)\n        return handler\n    @install\n"
        "    def verify(value):\n        assert value == 42\n    for action in tasks:\n"
        "        action(42)\n",
        encoding="utf-8",
    )
    assert not any(
        f["code"] == "QUALITY_HOLLOW_TEST" for f in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize(
    "variant",
    [
        "async_decorator",
        "async_callback",
        "generator_callback",
        "decorator_rebound",
        "code_replaced",
        "loop_alias_replaced",
        "early_conditional_return",
        "stacked_decorator",
        "unreachable_assertion",
        "assertion_after_return",
    ],
)
def test_local_registry_rejects_deferred_or_replaced_callbacks(tmp_path, variant):
    source = (
        "def test_behavior():\n    checks = []\n    def register(fn):\n"
        "        checks.append(fn)\n        return fn\n    @register\n"
        "    def check(value):\n        assert value == 42\n    for callback in checks:\n"
        "        callback(42)\n"
    )
    if variant == "async_decorator":
        source = source.replace("def register", "async def register")
    elif variant == "async_callback":
        source = source.replace("def check", "async def check")
    elif variant == "generator_callback":
        source = source.replace(
            "assert value == 42", "assert value == 42\n        yield value"
        )
    elif variant == "decorator_rebound":
        source = source.replace(
            "    @register", "    register = lambda fn: fn\n    @register"
        )
    elif variant == "code_replaced":
        source = source.replace(
            "    for callback",
            "    check.__code__ = (lambda value: None).__code__\n    for callback",
        )
    elif variant == "loop_alias_replaced":
        source = source.replace(
            "        callback(42)",
            "        alias = callback\n        alias.__code__ = (lambda value: None).__code__\n        callback(42)",
        )
    elif variant == "early_conditional_return":
        source = source.replace(
            "    for callback", "    if True:\n        return\n    for callback"
        )
    elif variant == "unreachable_assertion":
        source = source.replace(
            "assert value == 42", "if False:\n            assert value == 42"
        )
    elif variant == "assertion_after_return":
        source = source.replace(
            "assert value == 42", "return\n        assert value == 42"
        )
    else:
        source = source.replace(
            "    @register",
            "    def discard(fn):\n        return lambda value: None\n    @register\n    @discard",
        )
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert any(
        f["code"] == "QUALITY_HOLLOW_TEST" for f in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize(
    "expression",
    [
        "obj.version is obj.version",
        "obj.value == obj.value",
        "obj[0] is obj[0]",
        "obj[0] == obj[0]",
    ],
)
def test_repeated_descriptor_and_index_reads_are_not_tautologies(tmp_path, expression):
    (tmp_path / "test_case.py").write_text(
        f"def test_behavior(obj):\n    assert {expression}\n", encoding="utf-8"
    )
    assert not any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize(
    "expression",
    ["obj is obj", "obj == obj", "obj <= obj", "obj >= obj", "True", "1 == 1"],
)
def test_repeated_local_values_remain_hollow(tmp_path, expression):
    (tmp_path / "test_case.py").write_text(
        f"def test_behavior(obj):\n    assert {expression}\n", encoding="utf-8"
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


def test_hollow_callback_report_provides_native_assertion_probe(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    def check():\n        assert compute() == 42\n    pass\n"
    )
    finding = security_scan(tmp_path)["findings"][0]
    probe = finding["facts"]["native_assertion_probe"]
    assert probe["available"] is True
    assert probe["assertion_lines"] == [3]
    assert probe["nodeid_hint"] == "test_case.py::test_behavior"
    assert probe["exact_collection_id_required"] is True
    assert probe["command"][:3] == ["python", "-m", "factoryline.pytest_readiness"]
    assert probe["command"] == [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--root",
        ".",
        "--nodeid",
        "<exact collected pytest node ID>",
        "--line",
        "<assertion line>",
        "--timeout",
        "30",
    ]
    assert probe["call_available"] is False
    assert probe["call_lines"] == []
    assert "--kind" not in probe["command"]
    assert "--kind" in probe["call_command"]
    assert probe["call_command"][probe["call_command"].index("--kind") + 1] == "call"
    assert "mutation sensitivity and semantic quality are not assessed" in " ".join(
        probe["call_limits"]
    )


def test_native_test_probe_attribution_excludes_ambiguous_call_shapes():
    import ast
    from factoryline.review_integrity import native_test_probe

    test = ast.parse(
        "def test_behavior():\n"
        "    callback()\n"
        "    value = callback()\n"
        "    callback(); other()\n"
        "    callback() or other()\n"
        "    def helper():\n        callback()\n"
        "    class Container:\n        callback()\n"
        "        def method(self):\n            callback()\n"
        "    @register(other())\n    def decorated(value=other()):\n        pass\n"
        "    async def deferred():\n        await callback()\n"
        "    lambda: callback()\n"
    ).body[0]

    probe = native_test_probe("tests/test_behavior.py", test)

    assert probe["call_lines"] == [2, 7, 11]
    assert probe["call_available"] is True
    assert probe["call_command"][0:5] == [
        "python",
        "-m",
        "factoryline.pytest_readiness",
        "--kind",
        "call",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "def test_behavior():\n    value = callback()\n    pass\n",
        "def test_behavior():\n    callback(); other()\n",
        "def test_behavior():\n    callback(other())\n",
        "def test_behavior():\n    callback() or other()\n",
        "async def test_behavior():\n    await callback()\n",
        "def test_behavior():\n    lambda: callback()\n",
        "@register(callback())\ndef test_behavior():\n    pass\n",
        "def test_behavior(value=callback()):\n    pass\n",
        "def test_behavior():\n    class Container:\n        callback()\n",
        "callback()\ndef test_behavior():\n    pass\n",
    ],
)
def test_hollow_test_call_probe_guidance_rejects_non_direct_targets(tmp_path, source):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")

    finding = next(
        item
        for item in security_scan(tmp_path)["findings"]
        if item["code"] == "QUALITY_HOLLOW_TEST"
    )
    probe = finding["facts"]["native_assertion_probe"]

    assert probe["call_available"] is False
    assert probe["call_lines"] == []


def test_native_test_probe_excludes_module_level_calls():
    import ast
    from factoryline.review_integrity import native_test_probe

    module = ast.parse("callback()\ndef test_behavior():\n    pass\n")

    assert native_test_probe("tests/test_case.py", module)["call_lines"] == []


def test_hollow_test_call_guidance_is_static_and_explicitly_bounded(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pathlib import Path\n"
        "Path('scanner-ran-source').write_text('unexpected')\n"
        "def test_behavior():\n    callback()\n    pass\n"
        "def callback():\n    pass\n",
        encoding="utf-8",
    )

    finding = next(
        item
        for item in security_scan(tmp_path)["findings"]
        if item["code"] == "QUALITY_HOLLOW_TEST"
    )
    probe = finding["facts"]["native_assertion_probe"]

    assert probe["call_available"] is True
    assert probe["call_lines"] == [4]
    assert probe["nodeid_hint"] == "test_case.py::test_behavior"
    assert probe["call_command"][-4:] == [
        "--line",
        "<call line>",
        "--timeout",
        "30",
    ]
    assert "never started by a static scan" in probe["execution"]
    assert not (tmp_path / "scanner-ran-source").exists()


def test_flask_fixture_apps_and_flask_invoked_callbacks_direct_contract():
    import ast
    from factoryline.review_integrity import flask_fixture_apps, flask_invoked_callbacks

    tree = ast.parse(
        "@pytest.fixture\ndef app():\n    app = Flask('test')\n"
        "    app.config.update(TESTING=True)\n    return app\n"
    )
    aliases = {"pytest": "pytest", "Flask": "flask.Flask"}
    assert flask_fixture_apps(tree, aliases) == {"app": True}
    test = ast.parse(
        "def test_behavior(app):\n    @app.route('/checked')\n"
        "    def check():\n        assert compute() == 42\n"
        "    client = app.test_client()\n    client.get('/checked')\n"
    ).body[0]
    assert flask_invoked_callbacks(
        test, aliases, {"app"}, {"check"}, lambda *_: True
    ) == {"check"}
    assert (
        flask_invoked_callbacks(test, aliases, {"app"}, set(), lambda *_: True) == set()
    )


@pytest.mark.parametrize(
    ("setup", "expected_findings"),
    [
        ("alias = app", False),
        ("alias = app; alias.testing = False", True),
        ("first = app; second = first; second.testing = False", True),
        ("alias = app; alias.replace_dispatcher()", True),
        ("alias = client; alias.get = lambda path: None", True),
    ],
)
def test_flask_dispatch_rejects_mutated_app_and_client_aliases(
    tmp_path, setup, expected_findings
):
    fixture = (
        "import pytest\nfrom flask import Flask\n"
        "@pytest.fixture\ndef app():\n    app = Flask('test')\n"
        "    app.testing = True\n    return app\n"
    )
    test = (
        "def test_behavior(app):\n    client = app.test_client()\n    "
        + setup
        + "\n    @app.route('/checked')\n    def check():\n"
        "        assert compute() == 42\n    client.get('/checked')\n"
    )
    (tmp_path / "test_behavior.py").write_text(fixture + test)
    findings = security_scan(tmp_path, cache_enabled=False)["finding_counts"]
    assert ("QUALITY_HOLLOW_TEST" in findings) is expected_findings


def test_virtual_dispatch_defaults_direct_contract():
    import ast
    from factoryline.review_integrity import virtual_dispatch_defaults

    tree = ast.parse(
        "class Engine:\n    def __init__(self, app, dispatch=None):\n"
        "        self.dispatch_func = self.dispatch if dispatch is None else dispatch\n"
        "    async def __call__(self, scope):\n        await self.dispatch_func(scope)\n"
        "    async def dispatch(self, scope):\n        pass\n"
    )
    methods = {node.name: node for node in tree.body[0].body}
    assert virtual_dispatch_defaults(methods, {}, lambda *_: True) == {
        "methods": ["dispatch"],
        "required_arguments": 1,
        "guards": [],
    }
    assert virtual_dispatch_defaults({}, {}, lambda *_: True) == {}


@pytest.mark.parametrize(
    ("helper", "invocation", "hollow"),
    [
        ("def bar():\n        assert compute() == 4", "bar()", False),
        ("def bar():\n        assert compute() == 4", "pass", True),
        ("def bar():\n        assert True", "bar()", True),
        (
            "def bar():\n        try:\n            assert compute() == 4\n        except AssertionError:\n            pass",
            "bar()",
            True,
        ),
        ("def bar():\n        assert compute() == 4", "bar = noop\n    bar()", True),
        ("@swallow\n    def bar():\n        assert compute() == 4", "bar()", True),
        ("async def bar():\n        assert compute() == 4", "bar()", True),
        ("async def bar():\n        assert compute() == 4", "await bar()", False),
        (
            "def bar():\n        assert compute() == 4",
            "try:\n        bar()\n    except AssertionError:\n        pass",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4\n    def foo():\n        bar()",
            "foo()",
            False,
        ),
        (
            "async def bar():\n        assert compute() == 4\n    def foo():\n        bar()",
            "foo()",
            True,
        ),
        (
            "def foo():\n        def bar():\n            assert compute() == 4",
            "bar()",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4\n    def foo(bar):\n        bar()",
            "foo(noop)",
            True,
        ),
        ("def bar():\n        return\n        assert compute() == 4", "bar()", True),
        (
            "def bar():\n        assert compute() == 4\n    def bar():\n        pass",
            "bar()",
            True,
        ),
        ("def bar():\n        x = 5\n        assert x == 5", "bar()", True),
        ("def bar():\n        assert compute() == 4", "True or bar()", True),
        ("def bar():\n        assert compute() == 4", "value or True or bar()", True),
        (
            "def bar():\n        assert compute() == 4",
            "value and False and bar()",
            True,
        ),
        ("def bar():\n        assert compute() == 4", "False and bar()", True),
        ("def bar():\n        assert compute() == 4", "bar() if False else None", True),
        ("def bar():\n        assert compute() == 4", "None if True else bar()", True),
        ("def bar():\n        assert compute() == 4", "False or bar()", False),
        ("def bar():\n        assert compute() == 4", "True and bar()", False),
        (
            "def bar():\n        assert compute() == 4",
            "from somewhere import noop as bar\n    bar()",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4\n    def foo(*bar):\n        bar()",
            "foo(noop)",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4",
            "class bar:\n        pass\n    bar()",
            True,
        ),
    ],
)
def test_security_scan_tracks_invoked_nested_oracle_helpers(
    tmp_path, helper, invocation, hollow
):
    (tmp_path / "test_behavior.py").write_text(
        "async def test_behavior():\n    " + helper + "\n    " + invocation + "\n"
    )
    result = security_scan(tmp_path)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in result["findings"]) is hollow


def test_security_scan_does_not_credit_nested_helper_before_definition(tmp_path):
    (tmp_path / "test_behavior.py").write_text(
        "def test_behavior():\n    bar()\n    def bar():\n        assert compute() == 4\n"
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_nested_helper_shadows_module_oracle(tmp_path):
    (tmp_path / "test_behavior.py").write_text(
        "def assert_ok():\n    assert compute() == 4\n"
        "def test_behavior():\n    def assert_ok():\n        pass\n"
        "    def foo():\n        assert_ok()\n    foo()\n"
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "case",
    json.loads(
        (Path(__file__).parent / "fixtures/external_oracle_cases.json").read_text()
    ),
    ids=lambda case: case["id"],
)
def test_security_scan_external_repository_oracle_regressions(tmp_path, case):
    fixture_source = case.get("fixture_source", "")
    if fixture_source:
        assert (
            hashlib.sha256(fixture_source.encode()).hexdigest()
            == case["fixture_source_sha256"]
        )
        assert case["fixture_source_commit"] == case["commit"]
    (tmp_path / "test_external.py").write_text(
        fixture_source + case["source"], encoding="utf-8"
    )
    result = security_scan(tmp_path)
    hollow = any(
        finding["code"] == "QUALITY_HOLLOW_TEST" for finding in result["findings"]
    )
    assert hollow is case["expected_hollow"], (case["id"], result["findings"])


@pytest.mark.parametrize(
    "body",
    [
        "perform(send)\n    send.assert_called_once_with('payload')",
        "perform(send)\n    send.assert_called_with('payload', timeout=3)",
        "perform(send)\n    send.assert_any_call('payload')",
        "perform(send)\n    send.assert_called_once_with()",
        "await perform(send)\n    send.assert_awaited_once_with('payload')",
        "try:\n        operation()\n        pytest.fail('should raise')\n    except TimeoutError:\n        pass",
        "try:\n        operation()\n        pytest.fail('should raise')\n    except Exception:\n        pass",
        "with contextlib.suppress(Exception):\n        operation()\n        pytest.fail('should raise')",
    ],
)
def test_security_scan_accepts_argument_and_exception_oracles(tmp_path, body):
    (tmp_path / "test_behavior.py").write_text(
        "import pytest, contextlib\nfrom unittest.mock import Mock\n"
        "async def test_behavior():\n    send = Mock()\n    " + body + "\n"
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        "send('payload')\n    send.assert_called_once_with('payload')",
        "send('payload'); send.assert_called_once_with('payload')",
        "send('payload')\n    unrelated_helper()\n    send.assert_called_once_with('payload')",
        "send('payload')\n    print('test')\n    send.assert_called_once_with('payload')",
        "try:\n        operation()\n        pytest.fail('should raise')\n    except BaseException:\n        pass",
        "try:\n        operation()\n        pytest.fail('should raise')\n    finally:\n        return",
        "with contextlib.suppress(BaseException):\n        pytest.fail('should raise')",
        "return\n    pytest.fail('should raise')",
        "pytest = fake_framework\n    pytest.fail('should raise')",
        "try:\n        operation()\n        pytest.fail('should raise')\n    except pytest.fail.Exception:\n        pass",
    ],
)
def test_security_scan_keeps_self_checks_and_swallowed_failures_flagged(tmp_path, body):
    (tmp_path / "test_behavior.py").write_text(
        "import pytest, contextlib\ndef test_behavior():\n    " + body + "\n"
    )
    assert security_scan(tmp_path)["findings"]


def test_url_reserved_character_assignment_is_not_reported_as_a_secret(tmp_path):
    (tmp_path / "test_url_charset.py").write_text(
        'USER = PASSWORD = "%!*\'();:@&=+$,/?#[] "\n', encoding="utf-8"
    )
    assert not any(
        finding["code"] == "SECURITY_HARDCODED_SECRET"
        for finding in security_scan(tmp_path)["findings"]
    )


def test_reserved_alphabet_outside_test_source_remains_a_secret(tmp_path):
    (tmp_path / "credentials.py").write_text(
        'PASSWORD = "%!*\'();:@&=+$,/?#[] "\n', encoding="utf-8"
    )
    assert any(
        finding["code"] == "SECURITY_HARDCODED_SECRET"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize("value", ["!!!!!!!!!!!!", "!@#$%&*()_+"])
def test_punctuation_only_passwords_remain_secrets(tmp_path, value):
    (tmp_path / "test_credentials.py").write_text(
        f"PASSWORD = {value!r}\n", encoding="utf-8"
    )
    assert any(
        finding["code"] == "SECURITY_HARDCODED_SECRET"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize(
    "assertion",
    [
        "assert_not_called()",
        "assert_not_awaited()",
        "assert_awaited()",
        "assert_awaited_once()",
    ],
)
def test_mock_state_oracle_requires_an_invoked_injected_dependency(tmp_path, assertion):
    source = (
        "from unittest.mock import AsyncMock\n"
        "from starlette.requests import Request\n"
        "async def test_request():\n"
        "    send = AsyncMock()\n"
        "    request = Request({'type': 'http'}, send=send)\n"
        "    await request.send_early_hints([])\n"
        f"    send.{assertion}\n"
    )
    (tmp_path / "test_request.py").write_text(source, encoding="utf-8")
    assert not security_scan(tmp_path)["findings"]


@pytest.mark.parametrize(
    "body",
    [
        "send = AsyncMock()\n    send.assert_not_awaited()",
        "send = AsyncMock()\n    request = Request({'type': 'http'}, send=send)\n"
        "    if False:\n        await request.send_early_hints([])\n"
        "    send.assert_not_awaited()",
        "send = AsyncMock()\n    def unused():\n"
        "        request = Request({'type': 'http'}, send=send)\n"
        "        request.send_early_hints([])\n"
        "    send.assert_not_awaited()",
    ],
)
def test_mock_state_oracle_does_not_credit_unused_or_unreachable_dependencies(
    tmp_path, body
):
    (tmp_path / "test_request.py").write_text(
        "from unittest.mock import AsyncMock\n"
        "from starlette.requests import Request\n"
        "async def test_request():\n    " + body + "\n",
        encoding="utf-8",
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize(
    "method",
    [
        "assert_not_called",
        "assert_not_awaited",
        "assert_awaited",
        "assert_awaited_once",
        "assert_called",
        "assert_called_once",
    ],
)
def test_mock_oracle_supports_function_dependency_injection(tmp_path, method):
    (tmp_path / "test_case.py").write_text(
        "from unittest.mock import AsyncMock\n"
        "async def test_behavior():\n    dependency = AsyncMock()\n"
        f"    await perform(dependency)\n    dependency.{method}()\n",
        encoding="utf-8",
    )
    assert not security_scan(tmp_path)["findings"]


@pytest.mark.parametrize(
    "body",
    [
        "dependency()",
        "perform(dependency)\n    dependency = AsyncMock()",
        "if False:\n        perform(dependency)",
    ],
)
def test_mock_oracle_rejects_self_unused_and_rebound_state(tmp_path, body):
    (tmp_path / "test_case.py").write_text(
        "from unittest.mock import AsyncMock\ndef test_behavior():\n"
        "    dependency = AsyncMock()\n    "
        + body
        + "\n    dependency.assert_called_once()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    m = Mock()\n    ret = (lambda f: None)(m)\n    m.assert_not_called()\n",
        "from unittest.mock import Mock\ndef perform(dep):\n    pass\n"
        "def test_behavior():\n    m = Mock()\n    ret = perform(m)\n"
        "    m.assert_not_called()\n",
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    def perform(dep):\n        pass\n    m = Mock()\n"
        "    ret = perform(m)\n    m.assert_not_called()\n",
    ],
    ids=["inline-lambda", "module-function", "local-function"],
)
def test_mock_oracle_accepts_assigned_direct_sync_dependency_calls(tmp_path, source):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert not security_scan(tmp_path)["findings"]


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    m = Mock()\n    m.assert_not_called()\n",
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    m = Mock()\n    if False:\n        ret = (lambda f: None)(m)\n"
        "    m.assert_not_called()\n",
        "from unittest.mock import Mock\nclass Dependency:\n    pass\n"
        "def test_behavior():\n    m = Mock()\n    ret = Dependency(m)\n"
        "    m.assert_not_called()\n",
        "from unittest.mock import Mock\n@wrapper\ndef perform(dep):\n    pass\n"
        "def test_behavior():\n    m = Mock()\n    ret = perform(m)\n"
        "    m.assert_not_called()\n",
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    def perform(dep):\n        pass\n    perform = unknown\n"
        "    m = Mock()\n    ret = perform(m)\n    m.assert_not_called()\n",
        "from unittest.mock import Mock\nasync def perform(dep):\n    pass\n"
        "def test_behavior():\n    m = Mock()\n    ret = perform(m)\n"
        "    m.assert_not_called()\n",
        "from unittest.mock import Mock\ndef test_behavior():\n"
        "    m = Mock()\n    ret = (lambda f: None)(m)\n"
        "    m = object()\n    m.assert_not_called()\n",
    ],
    ids=[
        "unused",
        "unreachable",
        "constructor-only",
        "decorated",
        "rebound-callable",
        "unawaited-async",
        "rebound-mock",
    ],
)
def test_mock_oracle_rejects_unsafe_assigned_dependency_calls(tmp_path, source):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "shadow",
    [
        "parameter",
        "wildcard",
        "local_assignment",
        "conditional_class",
        "pattern_capture",
    ],
)
def test_assigned_sync_function_call_rejects_shadowed_module_binding(shadow):
    import ast
    from factoryline.review_integrity import assigned_sync_function_call

    parameter = "perform" if shadow == "parameter" else ""
    imported = "from plugin import *\n" if shadow == "wildcard" else ""
    rebound = "    perform = replacement\n" if shadow == "local_assignment" else ""
    if shadow == "conditional_class":
        rebound = "    if True:\n        class perform:\n            pass\n"
    if shadow == "pattern_capture":
        rebound = (
            "    match [replacement]:\n        case [perform]:\n            pass\n"
        )
    tree = ast.parse(
        "def perform(value):\n    return None\n"
        + imported
        + f"def test_behavior({parameter}):\n"
        + rebound
        + "    result = perform(dependency)\n"
    )
    scope = tree.body[-1]
    call = scope.body[-1].value
    assert not assigned_sync_function_call(call, scope, tree)


def test_assigned_sync_function_call_helper_attributes_direct_targets():
    import ast

    from factoryline.review_integrity import assigned_sync_function_call

    module = ast.parse(
        "def perform(dep): pass\ndef test_behavior():\n    ret = perform(dep)\n"
    )
    scope = module.body[1]
    call = next(item for item in ast.walk(scope) if isinstance(item, ast.Call))
    assert assigned_sync_function_call(call, scope, module)

    inline = ast.parse("def test_behavior():\n    ret = (lambda f: None)(dep)\n")
    inline_scope = inline.body[0]
    inline_call = next(
        item for item in ast.walk(inline_scope) if isinstance(item, ast.Call)
    )
    assert assigned_sync_function_call(inline_call, inline_scope, inline)

    decorated = ast.parse(
        "@decorator\ndef perform(dep): pass\n"
        "def test_behavior():\n    ret = perform(dep)\n"
    )
    decorated_scope = decorated.body[1]
    decorated_call = next(
        item for item in ast.walk(decorated_scope) if isinstance(item, ast.Call)
    )
    assert not assigned_sync_function_call(decorated_call, decorated_scope, decorated)


def test_mock_assertion_spelling_on_fake_object_is_not_an_oracle(tmp_path):
    (tmp_path / "test_fake.py").write_text(
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "def test_behavior():\n    send = Fake()\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_uncalled_mock_assertion_attribute_is_a_weak_oracle(tmp_path):
    (tmp_path / "test_mock_attribute.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_behavior():\n"
        "    send = Mock()\n"
        "    assert send.assert_called_once\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


def test_standalone_uncalled_mock_assertion_attribute_stays_hollow(tmp_path):
    (tmp_path / "test_mock_attribute.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_behavior():\n"
        "    send = Mock()\n"
        "    send.assert_called_once\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_uninvoked_mock_assertion_is_reported_alongside_real_assertion(tmp_path):
    (tmp_path / "test_mock_attribute.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_behavior():\n"
        "    send = Mock()\n"
        "    perform(send)\n"
        "    assert render() == '<ok>'\n"
        "    send.assert_called_with\n",
        encoding="utf-8",
    )
    findings = security_scan(tmp_path)["findings"]
    assert [(item["code"], item["line"]) for item in findings] == [
        ("QUALITY_WEAK_TEST_ORACLE", 6)
    ]


@pytest.mark.parametrize(
    ("source", "expected_line"),
    [
        (
            "async def fetch():\n    return False\n"
            "def test_fetch():\n    assert fetch()\n",
            4,
        ),
        (
            "async def fetch():\n    return False\n"
            "def test_fetch():\n    result = fetch()\n    assert result\n",
            5,
        ),
    ],
    ids=["direct", "assigned"],
)
def test_asserting_unawaited_local_async_result_is_reported(
    tmp_path, source, expected_line
):
    (tmp_path / "test_async_result.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path)["findings"]
    assert [
        (item["code"], item["line"])
        for item in findings
        if item["code"] == "QUALITY_UNAWAITED_COROUTINE"
    ] == [("QUALITY_UNAWAITED_COROUTINE", expected_line)]


@pytest.mark.parametrize(
    "source",
    [
        "async def fetch():\n    return True\n"
        "async def test_fetch():\n    assert await fetch()\n",
        "def fetch():\n    return True\ndef test_fetch():\n    assert fetch()\n",
        "async def fetch():\n    return True\n"
        "def test_fetch():\n    result = fetch()\n    result = True\n    assert result\n",
        "async def fetch():\n    return True\n"
        "def test_fetch():\n    assert asyncio.run(fetch())\n",
    ],
)
def test_awaited_or_reassigned_async_assertions_stay_clean(tmp_path, source):
    (tmp_path / "test_async_result.py").write_text(source, encoding="utf-8")
    assert (
        "QUALITY_UNAWAITED_COROUTINE" not in security_scan(tmp_path)["finding_counts"]
    )


@pytest.mark.parametrize(
    "source",
    [
        "class Flag:\n"
        "    @property\n"
        "    def assert_called_once(self):\n"
        "        return True\n"
        "def test_behavior():\n"
        "    flag = Flag()\n"
        "    assert flag.assert_called_once\n",
        "from unittest.mock import Mock\n"
        "class Flag:\n"
        "    @property\n"
        "    def assert_called_once(self):\n"
        "        return True\n"
        "def Mock():\n"
        "    return Flag()\n"
        "def test_behavior():\n"
        "    send = Mock()\n"
        "    assert send.assert_called_once\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n"
        "    send = Mock()\n"
        "    send.assert_called_once = lambda: True\n"
        "    assert send.assert_called_once\n",
    ],
)
def test_uncalled_mock_assertion_attribute_requires_unmutated_mock_provenance(
    tmp_path, source
):
    (tmp_path / "test_mock_attribute.py").write_text(source, encoding="utf-8")
    assert "QUALITY_WEAK_TEST_ORACLE" not in security_scan(tmp_path)["finding_counts"]


@pytest.mark.parametrize(
    "receiver",
    [
        "legacy_term_mock.write_text",
        "getattr(legacy_term_mock, method_name)",
    ],
)
def test_source_mock_fixture_proves_child_assertion(tmp_path, receiver):
    (tmp_path / "test_mock_fixture.py").write_text(
        "import pytest\nfrom unittest.mock import create_autospec\n"
        "class LegacyTerm:\n    def write_text(self, text):\n        pass\n"
        "@pytest.fixture\ndef legacy_term_mock():\n"
        "    return create_autospec(LegacyTerm)\n"
        "def test_behavior(legacy_term_mock):\n    method_name = 'write_text'\n"
        "    perform(legacy_term_mock)\n    "
        + receiver
        + ".assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert not security_scan(tmp_path)["findings"]


@pytest.mark.parametrize(
    "mutation,receiver",
    [
        ("legacy_term_mock.write_text = Fake()", "legacy_term_mock.write_text"),
        (
            "setattr(legacy_term_mock, method_name, Fake())",
            "getattr(legacy_term_mock, method_name)",
        ),
    ],
)
def test_mock_fixture_child_replacement_is_not_an_oracle(tmp_path, mutation, receiver):
    (tmp_path / "test_mock_fixture.py").write_text(
        "import pytest\nfrom unittest.mock import create_autospec\n"
        "class LegacyTerm:\n    def write_text(self, text):\n        pass\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "@pytest.fixture\ndef legacy_term_mock():\n"
        "    return create_autospec(LegacyTerm)\n"
        "def test_behavior(legacy_term_mock):\n    method_name = 'write_text'\n    "
        + mutation
        + "\n    perform(legacy_term_mock)\n    "
        + receiver
        + ".assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_source_fixture_returning_fake_does_not_prove_mock(tmp_path):
    (tmp_path / "test_fake_fixture.py").write_text(
        "import pytest\nclass Fake:\n"
        "    def assert_called_once_with(self, *args):\n        pass\n"
        "@pytest.fixture\ndef legacy_term_mock():\n    return Fake()\n"
        "def test_behavior(legacy_term_mock):\n    perform(legacy_term_mock)\n"
        "    legacy_term_mock.write_text.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "decorator",
    [
        "@patch('module.send', new=Fake())",
        "@patch('module.send', new_callable=Fake)",
        "@wrapper\n@patch('module.send')",
    ],
)
def test_patch_parameter_requires_resolved_default_mock_injection(tmp_path, decorator):
    (tmp_path / "test_patched_mock.py").write_text(
        "from unittest.mock import patch\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        + decorator
        + "\ndef test_behavior(send):\n    perform(send)\n"
        "    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import patch\n"
        "def patch(target):\n    return lambda function: function\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "@patch('module.send')\ndef test_send(send):\n    perform()\n"
        "    send.assert_called_once_with('payload')\n",
        "from unittest.mock import Mock\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "def Mock():\n    return Fake()\n"
        "def test_send():\n    send = Mock()\n    perform()\n"
        "    send.assert_called_once_with('payload')\n",
        "from unittest.mock import Mock\n"
        "def test_send():\n    send = Mock()\n"
        "    send.assert_called_once_with = lambda *args: None\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
    ],
)
def test_mock_provenance_rejects_shadowed_constructors_and_assertion_methods(
    tmp_path, source
):
    (tmp_path / "test_mock_shadow.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "setup,context,receiver,expected_hollow",
    [
        (
            "proxies = {'one': Mock(), 'two': Mock()}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            False,
        ),
        (
            "proxies = {'one': Fake(), 'two': Fake()}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies, clear=True):\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    proxies['one'] = Fake()\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target):\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock(), 'one': Fake()}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "extra = {'one': Fake()}\nproxies = {'one': Mock(), **extra}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    proxies.update({'one': Fake()})\n",
            "proxies['one'].clear",
            True,
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    mutate(proxies)\n",
            "proxies['one'].clear",
            True,
        ),
    ],
    ids=[
        "valid",
        "fake-values",
        "clear-true",
        "rebound-slot",
        "missing-values",
        "duplicate-key",
        "mapping-unpack",
        "update-mutation",
        "unknown-mapping-use",
    ],
)
def test_mock_patch_dict_slot_requires_literal_mock_value_and_default_context(
    tmp_path, setup, context, receiver, expected_hollow
):
    body = context.splitlines()
    (tmp_path / "test_patch_dict.py").write_text(
        "from unittest.mock import Mock, patch\n"
        "class Fake:\n    def assert_called_once_with(self, *args): pass\n"
        "def test_behavior():\n    target = {}\n"
        + "".join(f"    {line}\n" for line in setup.splitlines())
        + f"    {body[0]}\n"
        + "".join(f"        {line.strip()}\n" for line in body[1:])
        + "        perform()\n        "
        + receiver
        + ".assert_called_once_with()\n",
        encoding="utf-8",
    )
    hollow_count = security_scan(tmp_path)["finding_counts"].get(
        "QUALITY_HOLLOW_TEST", 0
    )
    assert hollow_count == int(expected_hollow)


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import patch\n"
        "def patch(target): return lambda function: function\n"
        "def test_behavior():\n    with patch('module.target') as send:\n"
        "        perform()\n        send.assert_called_once_with('payload')\n",
        "from unittest.mock import patch\n"
        "class Fake:\n    def assert_called_once_with(self, *args): pass\n"
        "def test_behavior():\n    with patch('module.target', new=Fake()) as send:\n"
        "        perform()\n        send.assert_called_once_with('payload')\n",
        "from unittest.mock import patch\n"
        "def helper():\n    with patch('module.target') as send:\n        perform()\n"
        "def test_behavior():\n    helper()\n"
        "    send.assert_called_once_with('payload')\n",
        "from unittest.mock import patch\n"
        "class Fake:\n    def assert_called_once_with(self, *args): pass\n"
        "def test_behavior():\n    with patch('module.send') as send: send = Fake(); perform(); send.assert_called_once_with('payload')\n",
    ],
    ids=["shadowed-patch", "replacement", "outside-scope", "same-line-rebind"],
)
def test_mock_context_patch_rejects_shadow_or_replacement(tmp_path, source):
    (tmp_path / "test_patch_context.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_mock_configure_mock_cannot_replace_assertion_method(tmp_path):
    (tmp_path / "test_mock_configure.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    send = Mock()\n"
        "    send.configure_mock(assert_called_once_with=lambda *args: None)\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("", {}),
        (
            "alias.configure_mock(assert_called_once_with=lambda *args: None)\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "alias.assert_called_once_with = lambda *args: None\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "alias.__dict__['assert_called_once_with'] = lambda *args: None\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "alias = send; alias.configure_mock(assert_called_once_with=lambda *args: None)\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "alias.assert_called_once_with = lambda *args: None\n    alias = object()\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "alias = object()\n    alias.assert_called_once_with = lambda *args: None\n    ",
            {},
        ),
    ],
)
def test_mock_alias_mutations_invalidate_root_provenance(tmp_path, mutation, expected):
    (tmp_path / "test_mock_alias.py").write_text(
        "from unittest.mock import Mock\n"
        "def perform(send):\n    send('payload')\n"
        "def test_behavior():\n    send = Mock()\n    alias = send\n    "
        + mutation
        + "perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize(
    "source",
    [
        "from unittest.mock import Mock, patch\n"
        "def test_behavior():\n    target = {}\n"
        "    proxies = {'one': Mock()}; alias = proxies; alias.update({'one': Fake()})\n"
        "    with patch.dict(target, proxies):\n        perform()\n"
        "        proxies['one'].clear.assert_called_once_with()\n",
        "from unittest.mock import Mock, patch\n"
        "def test_behavior():\n    target = {}\n"
        "    proxies = {'one': Mock()}\n"
        "    with patch.dict(target, proxies): proxies.update({'one': Fake()}); perform(); proxies['one'].clear.assert_called_once_with()\n",
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    send = Mock(); send.configure_mock(assert_called_once_with=lambda *args: None); perform(send); send.assert_called_once_with('payload')\n",
        "from unittest.mock import Mock\n"
        "class Fake:\n    def assert_called_once_with(self, *args): pass\n"
        "def test_behavior():\n    send = Mock(); send.configure_mock(clear=Fake()); perform(send); send.clear.assert_called_once_with()\n",
    ],
)
def test_mock_provenance_rejects_same_line_mutation_and_escape(tmp_path, source):
    (tmp_path / "test_same_line_mutation.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_module_mock_provenance_is_shadowed_by_local_fake(tmp_path):
    (tmp_path / "test_fake.py").write_text(
        "from unittest.mock import Mock\nsend = Mock()\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "def test_behavior(send=Fake()):\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize("invoke", ["check(42)", "return check(42)"])
def test_callback_oracle_follows_setup_and_return(tmp_path, invoke):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    def check(value):\n        assert compute() == value\n"
        "    def execute(callback):\n        setup = 42\n        "
        + invoke.replace("check", "callback")
        + "\n    execute(check)\n",
        encoding="utf-8",
    )
    assert not security_scan(tmp_path)["findings"]


def test_mock_oracle_does_not_credit_unawaited_async_dependency(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from unittest.mock import AsyncMock\nasync def perform(dep):\n    await dep()\n"
        "async def test_behavior():\n    dependency = AsyncMock()\n"
        "    perform(dependency)\n    dependency.assert_not_awaited()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_HOLLOW_TEST": 1,
        "QUALITY_UNAWAITED_COROUTINE": 1,
    }


def test_execution_findings_resolves_module_helpers_without_sync_credit():
    import ast
    from factoryline import review_audits as audit, review_integrity as integrity

    tree = ast.parse(
        "def test_example():\n    check()\nasync def check():\n    return 1\n"
    )
    test, helper = tree.body
    call = test.body[0].value
    candidates, body = integrity._oracle_call_candidates(
        "check", test, tree, ast.AsyncFunctionDef
    )
    assert candidates == [helper]
    assert body is tree.body
    assert integrity._oracle_stable_call(helper, call, test, body, True) is True
    assert integrity.assigned_sync_function_call(call, test, tree) is False
    findings, shadowed = integrity.test_execution_findings(
        test, "test_example.py", audit._oracle_ancestor_map(tree.body), tree
    )
    assert shadowed is False
    assert [(item["code"], item["line"]) for item in findings] == [
        ("QUALITY_UNAWAITED_COROUTINE", 2)
    ]


def test_unawaited_local_async_test_helper_is_reported_even_with_other_assertion(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "async def test_behavior():\n"
        "    async def check():\n        assert compute() == 3\n"
        "    check()\n    assert compute() == 4\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNAWAITED_COROUTINE": 1
    }


def test_unawaited_module_async_test_helper_survives_comprehension_and_lambda_scopes(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "async def check():\n    assert compute()\n"
        "async def test_behavior():\n"
        "    [check for check in helpers]\n"
        "    identity = lambda check: check\n"
        "    check()\n    assert compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNAWAITED_COROUTINE": 1
    }


@pytest.mark.parametrize(
    "binding",
    [
        "from helpers import check",
        "if enabled:\n    async def check():\n        pass",
        "try:\n    pass\nexcept Exception as check:\n    pass",
        "match value:\n    case check:\n        pass",
    ],
)
def test_unawaited_module_async_helper_rejects_rebound_scope_names(tmp_path, binding):
    (tmp_path / "test_case.py").write_text(
        "async def check():\n    pass\n"
        "async def test_behavior():\n    "
        + binding.replace("\n", "\n    ")
        + "\n    check()\n    assert compute()\n",
        encoding="utf-8",
    )
    assert (
        "QUALITY_UNAWAITED_COROUTINE" not in security_scan(tmp_path)["finding_counts"]
    )


@pytest.mark.parametrize(
    "body",
    [
        "await check()",
        "pending = check()",
        "return check()",
        "schedule(check())",
        "register(check)",
        "external_check()",
        "check()\ncheck = replacement",
        "nested()\n    async def nested():\n        check()",
    ],
)
def test_unawaited_local_async_test_helper_requires_discarded_direct_call(
    tmp_path, body
):
    (tmp_path / "test_case.py").write_text(
        "async def test_behavior():\n"
        "    async def check():\n        assert compute() == 3\n"
        "    " + body.replace("\n", "\n    ") + "\n    assert compute() == 4\n",
        encoding="utf-8",
    )
    assert (
        "QUALITY_UNAWAITED_COROUTINE" not in security_scan(tmp_path)["finding_counts"]
    )


def test_unawaited_local_async_test_helper_excludes_decorated_and_generator_defs(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "def decorate(function):\n    return function\n"
        "async def test_behavior():\n"
        "    @decorate\n    async def decorated():\n        pass\n"
        "    async def generator():\n        yield 1\n"
        "    decorated()\n    generator()\n"
        "    assert compute() == 4\n",
        encoding="utf-8",
    )
    assert (
        "QUALITY_UNAWAITED_COROUTINE" not in security_scan(tmp_path)["finding_counts"]
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def test_after():\n    check()\n    assert actual == expected\n"
            "async def check():\n    return 1\n",
            True,
        ),
        (
            "async def check():\n    return 1\n"
            "def test_default():\n"
            "    identity = lambda value=(check := lambda: None): value\n"
            "    check()\n    assert actual == expected\n",
            False,
        ),
        (
            "async def check():\n    return 1\n"
            "def test_body():\n"
            "    identity = lambda: (check := lambda: None)\n"
            "    check()\n    assert actual == expected\n",
            True,
        ),
        (
            "async def check():\n    return 1\n"
            "def test_nested_default():\n"
            "    identity = lambda value=(lambda value=(check := lambda: None): value): value\n"
            "    check()\n    assert actual == expected\n",
            False,
        ),
    ],
    ids=[
        "module-definition-after-test",
        "evaluated-default-rebinds",
        "deferred-body-is-local",
        "nested-evaluated-default",
    ],
)
def test_unawaited_coroutine_respects_module_loading_and_lambda_defaults(
    tmp_path, source, expected
):
    (tmp_path / "test_async.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert (
        any(item["code"] == "QUALITY_UNAWAITED_COROUTINE" for item in findings)
        is expected
    )


def test_shadowed_duplicate_module_test_reports_only_shadow_and_final_binding(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    assert compute() == 3\n"
        "def test_behavior():\n    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_SHADOWED_TEST": 1,
        "QUALITY_HOLLOW_TEST": 1,
    }


def test_shadowed_duplicate_class_test_is_reported(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "class TestCases:\n"
        "    def test_behavior(self):\n        assert compute() == 3\n"
        "    def test_behavior(self):\n        assert compute() == 4\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_SHADOWED_TEST": 1}


@pytest.mark.parametrize(
    "source",
    [
        "class TestA:\n    def test_behavior(self):\n        assert compute() == 3\n"
        "class TestB:\n    def test_behavior(self):\n        assert compute() == 4\n",
        "if flag:\n    def test_behavior():\n        assert compute() == 3\n"
        "else:\n    def test_behavior():\n        assert compute() == 4\n",
        "def test_behavior():\n    def helper():\n        pass\n"
        "def test_other():\n    def helper():\n        pass\n",
    ],
)
def test_shadowed_duplicate_test_requires_same_direct_module_or_class_body(
    tmp_path, source
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert "QUALITY_SHADOWED_TEST" not in security_scan(tmp_path)["finding_counts"]


def test_explicit_pyright_type_source_credits_only_real_type_assertion(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyright]\ninclude = ["test_typing.py"]\n', encoding="utf-8"
    )
    (tmp_path / "test_typing.py").write_text(
        "from typing import assert_type\ndef test_types():\n    assert_type(compute(), int)\n"
        "def test_missing():\n    compute()\n",
        encoding="utf-8",
    )
    findings = security_scan(tmp_path)["findings"]
    assert [item["facts"]["symbol"] for item in findings] == ["test_missing"]


def test_callback_oracle_requires_direct_invocation_not_callback_passing(tmp_path):
    (tmp_path / "test_callback.py").write_text(
        "def test_direct_callback():\n"
        "    def callback():\n        assert compute() == 3\n"
        "    callback()\n"
        "def test_first_party_invoker():\n"
        "    def callback():\n        assert compute() == 3\n"
        "    def invoke(check):\n        check()\n"
        "    invoke(callback)\n"
        "def test_conditional_invoker():\n"
        "    def callback():\n        assert compute() == 3\n"
        "    def invoke(check):\n        if enabled:\n            check()\n"
        "    invoke(callback)\n"
        "def test_swallowed_invoker():\n"
        "    def callback():\n        assert compute() == 3\n"
        "    def invoke(check):\n        try:\n            check()\n"
        "        except AssertionError:\n            pass\n"
        "    invoke(callback)\n"
        "def test_unproven_callback():\n"
        "    def callback():\n        assert compute() == 3\n"
        "    register(callback)\n",
        encoding="utf-8",
    )
    findings = security_scan(tmp_path)["findings"]
    hollow = {
        finding["facts"]["symbol"]
        for finding in findings
        if finding["code"] == "QUALITY_HOLLOW_TEST"
    }
    assert hollow == {
        "test_conditional_invoker",
        "test_swallowed_invoker",
        "test_unproven_callback",
    }


def test_library_methods_and_pytest_fixtures_are_not_collected_tests(tmp_path):
    library = tmp_path / "src" / "library.py"
    library.parent.mkdir()
    library.write_text(
        "class Client:\n"
        "    def test_client(self):\n        pass\n"
        "    def test_request_context(self):\n        pass\n",
        encoding="utf-8",
    )
    tests = tmp_path / "test_helpers.py"
    tests.write_text(
        "import pytest\n@pytest.fixture\ndef test_client_factory():\n    pass\n",
        encoding="utf-8",
    )
    assert not any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


def test_pytest_collects_inherited_test_methods_from_non_test_base(tmp_path):
    (tmp_path / "test_inherited.py").write_text(
        "class Base:\n    def test_inherited(self):\n        pass\n"
        "class TestChild(Base):\n    pass\n",
        encoding="utf-8",
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        and finding["facts"]["symbol"] == "test_inherited"
        for finding in security_scan(tmp_path)["findings"]
    )


def test_pytest_custom_collection_pattern_is_respected_and_cache_bound(tmp_path):
    from factoryline.review_audits import (
        _oracle_context_cache_clear,
        _oracle_context_cache_info,
    )

    _oracle_context_cache_clear()
    (tmp_path / "check_feature.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    assert not any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )
    misses_before = _oracle_context_cache_info()["misses"]
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = check_*.py\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npython_files = ["ignored_*.py"]\n',
        encoding="utf-8",
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )
    assert _oracle_context_cache_info()["misses"] > misses_before


def test_runtime_oracle_config_uses_active_config_and_test_ancestor_conftests(tmp_path):
    from factoryline.review_audits import _pytest_collection_config
    from factoryline.runtime_audit_common import runtime_config_sources

    def bind(path, content):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }

    config = bind("pyproject.toml", b"[tool.pytest.ini_options]\ntestpaths=['tests']\n")
    root_conf = bind("conftest.py", b"# root\n")
    tests_conf = bind("tests/conftest.py", b"# tests\n")
    nested_conf = bind("tests/unit/conftest.py", b"# unit\n")
    sibling_conf = bind("other/conftest.py", b"# sibling\n")
    selected = _pytest_collection_config(tmp_path)[1]
    assert selected["path"] == "pyproject.toml"
    core = {
        "sources": [root_conf, tests_conf, nested_conf, sibling_conf],
        "oracle_context": {"configuration_sources": [config]},
    }

    result = runtime_config_sources(
        tmp_path,
        core,
        {
            "path": "tests/unit/test_case.py",
            "baseline": {"collection_catalog": {}},
            "mutation": {"collection_catalog": {}},
        },
        "factory.test-oracle-verification.v3",
    )

    assert result == sorted(
        [
            {"path": "pyproject.toml", "sha256": config["sha256"]},
            {"path": "conftest.py", "sha256": root_conf["sha256"]},
            {"path": "tests/conftest.py", "sha256": tests_conf["sha256"]},
            {"path": "tests/unit/conftest.py", "sha256": nested_conf["sha256"]},
        ],
        key=lambda item: item["path"],
    )
    assert all(item["path"] != sibling_conf["path"] for item in result)


def test_runtime_oracle_config_missing_primary_and_unbound_conftest_fail_closed(
    tmp_path,
):
    from factoryline.review_audits import _pytest_collection_config
    from factoryline.runtime_audit_common import (
        RuntimeAuditError,
        runtime_config_sources,
    )

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text("# inherited\n", encoding="utf-8")
    selected = _pytest_collection_config(tmp_path)[1]
    assert selected["state"] == "missing"
    core = {"sources": [], "oracle_context": {"configuration_sources": []}}
    with pytest.raises(RuntimeAuditError, match="ancestor conftest is unbound"):
        runtime_config_sources(
            tmp_path,
            core,
            {
                "path": "tests/test_case.py",
                "baseline": {"collection_catalog": {}},
                "mutation": {"collection_catalog": {}},
            },
            "factory.test-oracle-verification.v3",
        )


def test_runtime_oracle_config_rejects_duplicate_scan_bindings(tmp_path):
    from factoryline.runtime_audit_common import (
        RuntimeAuditError,
        runtime_config_sources,
    )

    row = {
        "path": "test_case.py",
        "baseline": {"collection_catalog": {}},
        "mutation": {"collection_catalog": {}},
    }
    duplicate = {"path": "test_case.py", "sha256": "a" * 64}
    cases = (
        [duplicate, duplicate.copy()],
        [{"path": "test_case.py", "sha256": "bad"}],
    )
    for source_rows in cases:
        core = {
            "sources": source_rows,
            "oracle_context": {"configuration_sources": []},
        }
        with pytest.raises(RuntimeAuditError, match="scan bindings are malformed"):
            runtime_config_sources(
                tmp_path, core, row, "factory.test-oracle-verification.v3"
            )


def test_runtime_oracle_config_rejects_stale_active_config_binding(tmp_path):
    from factoryline.review_audits import _pytest_collection_config
    from factoryline.runtime_audit_common import (
        RuntimeAuditError,
        runtime_config_sources,
    )

    data = b"[pytest]\npython_files = test_*.py\n"
    (tmp_path / "pytest.ini").write_bytes(data)
    selected = _pytest_collection_config(tmp_path)[1]
    assert selected["path"] == "pytest.ini"
    core = {
        "sources": [],
        "oracle_context": {
            "configuration_sources": [{"path": "pytest.ini", "sha256": "0" * 64}]
        },
    }
    row = {
        "path": "test_case.py",
        "baseline": {"collection_catalog": {}},
        "mutation": {"collection_catalog": {}},
    }
    with pytest.raises(RuntimeAuditError, match="pytest configuration is unbound"):
        runtime_config_sources(
            tmp_path, core, row, "factory.test-oracle-verification.v3"
        )


def test_runtime_oracle_config_errors_are_normalized_by_reconciliation(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as audit
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    core = security_scan(tmp_path)
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = test_*.py\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V3,
            "tests": [
                {
                    **row,
                    "baseline": {**row["baseline"], "collection_catalog": {}},
                    "mutation": {**row["mutation"], "collection_catalog": {}},
                }
            ],
        },
    )
    with pytest.raises(ReviewAuditError, match="Runtime oracle evidence rejected"):
        audit._reconcile_runtime_oracles(tmp_path, core, tuple(kwargs.values()))


def test_runtime_oracle_config_preserves_legacy_config_sources(tmp_path):
    from factoryline.runtime_audit_common import runtime_config_sources

    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    legacy = [{"path": "pyproject.toml", "sha256": "a" * 64}]
    core = {"oracle_context": {"configuration_sources": legacy}}
    row = {"path": "test_case.py", "baseline": {}, "mutation": {}}
    assert (
        runtime_config_sources(
            tmp_path, core, row, "factory.test-oracle-verification.v2"
        )
        == legacy
    )


@pytest.mark.parametrize(
    "config",
    [
        "[pytest]\npython_functions = check_*\n",
        "[pytest\npython_files = test_*.py\n",
    ],
)
def test_unsupported_or_malformed_pytest_collection_config_fails_closed(
    tmp_path, config
):
    from factoryline.review_audits import ReviewAuditError

    (tmp_path / "pytest.ini").write_text(config, encoding="utf-8")
    with pytest.raises(ReviewAuditError, match="pytest test collection"):
        security_scan(tmp_path)


@pytest.mark.parametrize("filename", ["pytest.toml", ".pytest.toml"])
def test_toml_pytest_config_file_patterns_are_honored(tmp_path, filename):
    (tmp_path / filename).write_text(
        '[pytest]\npython_files = ["check_*.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / "check_hollow.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


def test_dot_pytest_ini_and_native_pyproject_pytest_table_are_honored(tmp_path):
    (tmp_path / ".pytest.ini").write_text(
        "[pytest]\npython_files = check_*.py\n", encoding="utf-8"
    )
    (tmp_path / "check_hollow.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )
    (tmp_path / ".pytest.ini").unlink()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest]\npython_files = ["check_*.py"]\n', encoding="utf-8"
    )
    assert any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize("filename", ["pytest.ini", ".pytest.ini"])
def test_empty_pytest_ini_takes_precedence_over_lower_pyproject(tmp_path, filename):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest]\npython_files = ["check_*.py"]\n', encoding="utf-8"
    )
    (tmp_path / filename).write_text("", encoding="utf-8")
    (tmp_path / "check_hollow.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    assert not any(
        finding["code"] == "QUALITY_HOLLOW_TEST"
        for finding in security_scan(tmp_path)["findings"]
    )


@pytest.mark.parametrize("library", ["pickle", "dill"])
def test_security_scan_classifies_test_roundtrip_as_nonblocking(tmp_path, library):
    (tmp_path / "test_roundtrip.py").write_text(
        f"import {library} as serializer\n"
        "def test_roundtrip():\n"
        "    own_object = {'value': 4}\n"
        "    assert serializer.loads(serializer.dumps(own_object)) == own_object\n"
    )
    result = security_scan(tmp_path)
    assert result["state"] == "FINDINGS"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "INFO"
    assert (
        result["findings"][0]["facts"]["input_provenance"]
        == "direct_local_serialization"
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "from flask import request\n"
            "def download():\n"
            "    name = request.args.get('name')\n"
            "    open(name)\n",
            "SECURITY_PATH_TRAVERSAL",
        ),
        (
            "from flask import request\n"
            "def download():\n"
            "    open(request.form['path'])\n",
            "SECURITY_PATH_TRAVERSAL",
        ),
        (
            "from flask import request\n"
            "def download():\n"
            "    name = request.args.get('name')\n"
            "    open(secure_filename(name))\n",
            "SECURITY_PATH_TRAVERSAL",
        ),
        (
            "import mysql.connector\n"
            "def get_connection():\n"
            "    return mysql.connector.connect()\n"
            "def lookup(name):\n"
            "    cursor = get_connection().cursor()\n"
            "    query = \"SELECT * FROM records WHERE name = '%s'\" % name\n"
            "    cursor.execute(query)\n",
            "SECURITY_SQL_INJECTION",
        ),
        (
            "import mysql.connector\n"
            "def get_connection():\n"
            "    return mysql.connector.connect()\n"
            "def lookup(name):\n"
            "    cursor = get_connection().cursor()\n"
            "    query = f\"SELECT * FROM records WHERE name='{name}'\"\n"
            "    cursor.execute(query, (name,))\n",
            "SECURITY_SQL_INJECTION",
        ),
        (
            "from flask import request as incoming\n"
            "import requests\n"
            "def fetch():\n"
            "    host = incoming.args['host']\n"
            "    url = 'https://' + host + '/items'\n"
            "    requests.get(url)\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request as incoming\n"
            "import requests\n"
            "def fetch():\n"
            "    requests.get(incoming.form.get('url'))\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\n"
            "import mysql.connector\n"
            "def lookup():\n"
            "    cursor = mysql.connector.connect().cursor()\n"
            "    query = \"SELECT * FROM records WHERE name = '%s'\" % request.form['name']\n"
            "    cursor.execute(query)\n",
            "SECURITY_SQL_INJECTION",
        ),
        (
            "from flask import request\n"
            "import requests\n"
            "def fetch():\n"
            "    if requests.get(request.args.get('url')).ok:\n"
            "        pass\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\n"
            "import requests\n"
            "def fetch():\n"
            "    while requests.get(request.args.get('url')).ok:\n"
            "        break\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\n"
            "import requests\n"
            "def fetch():\n"
            "    for item in requests.get(request.args.get('url')).json():\n"
            "        consume(item)\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\nimport requests\n"
            "def get_url():\n    return request.args.get('url')\n"
            "url_helper = get_url\n"
            "def fetch():\n    requests.get(url_helper())\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\nimport requests\n"
            "def identity(value):\n    return value\n"
            "def fetch():\n"
            "    requests.get(identity(value=request.form['url']))\n",
            "SECURITY_SSRF",
        ),
        (
            "from flask import request\n"
            "def get_path():\n    return request.form['path']\n"
            "def download():\n    open(get_path())\n",
            "SECURITY_PATH_TRAVERSAL",
        ),
        (
            "from flask import request\nimport mysql.connector\n"
            "def get_name():\n    return request.form.get('name')\n"
            "def lookup():\n"
            "    value = get_name()\n"
            "    query = f\"SELECT * FROM records WHERE name='{value}'\"\n"
            "    mysql.connector.connect().cursor().execute(query)\n",
            "SECURITY_SQL_INJECTION",
        ),
    ],
)
def test_security_scan_finds_bounded_request_to_sink_flows(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert [finding["code"] for finding in result["findings"]].count(expected) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import mysql.connector\n"
        "def get_connection():\n"
        "    return mysql.connector.connect()\n"
        "def lookup(name):\n"
        "    cursor = get_connection().cursor()\n"
        '    query = "SELECT * FROM records WHERE name = %s"\n'
        "    cursor.execute(query, (name,))\n",
        "from flask import request\n"
        "import requests\n"
        "import urllib.parse\n"
        "def fetch():\n"
        "    host = request.args.get('host')\n"
        "    url = 'https://' + host + '/items'\n"
        "    if urllib.parse.urlparse(url).hostname in {'api.example.test'}:\n"
        "        requests.get(url)\n",
        "def read():\n"
        "    open('welcome.txt')\n"
        "import requests\n"
        "def fetch():\n"
        "    requests.get('https://example.test/items')\n",
        "from flask import request\n"
        "def download():\n"
        "    request = object()\n"
        "    name = request.args.get('name')\n"
        "    open(name)\n",
        "from flask import request\n"
        "def download():\n"
        "    name = request.args.get('name')\n"
        "    name = 'welcome.txt'\n"
        "    open(name)\n",
        "import mysql.connector\n"
        "def get_connection():\n"
        "    return mysql.connector.connect()\n"
        "def lookup(name):\n"
        "    get_connection = lambda: object()\n"
        "    cursor = get_connection().cursor()\n"
        "    query = f\"SELECT * FROM records WHERE name='{name}'\"\n"
        "    cursor.execute(query)\n",
        "import requests\n"
        "def pass_through(path, url):\n"
        "    open(path)\n"
        "    requests.get(url)\n",
        "from flask import request\nimport requests\n"
        "def helper():\n    return 'https://fixed.example.test'\n"
        "def fetch():\n    requests.get(helper())\n",
        "from flask import request\nimport requests\n"
        "def helper():\n    return request.args.get('url')\n"
        "helper = lambda: 'https://fixed.example.test'\n"
        "requests.get(helper())\n",
        "from flask import request\nimport requests\n"
        "def helper():\n"
        "    if enabled:\n        return request.args.get('url')\n"
        "    return 'https://fixed.example.test'\n"
        "def fetch():\n    requests.get(helper())\n",
        "from flask import request\nimport requests\n"
        "def helper():\n    return helper()\n"
        "def fetch():\n    requests.get(helper())\n",
        "from flask import request\nimport requests\n"
        "def helper():\n    return request.args.get('url')\n"
        "def fetch(helper):\n    requests.get(helper())\n",
        "from flask import request\nimport requests\n"
        "def helper():\n    return request.args.get('url')\n"
        "helper = lambda: 'https://fixed.example.test'\n"
        "alias = helper\nrequests.get(alias())\n",
        "from flask import request\nimport requests\n"
        "def identity(value, /):\n    return value\n"
        "def fetch():\n"
        "    requests.get(identity(value=request.args.get('url')))\n",
    ],
)
def test_security_scan_source_flow_controls_keep_safety_distinctions(tmp_path, source):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    codes = {
        finding["code"]
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
    }
    assert not codes.intersection(
        {"SECURITY_PATH_TRAVERSAL", "SECURITY_SQL_INJECTION", "SECURITY_SSRF"}
    )


def test_security_scan_rejects_url_string_prefix_as_allowlist(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "def fetch():\n"
        "    host = request.args.get('host')\n"
        "    url = 'https://' + host + '/items'\n"
        "    if url.startswith('https://example.test'):\n"
        "        requests.get(url)\n",
        encoding="utf-8",
    )
    codes = {
        finding["code"]
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
    }
    assert "SECURITY_SSRF" in codes


@pytest.mark.parametrize(
    "condition",
    [
        "urllib.parse.urlparse(url).hostname not in {'api.example.test'}",
        "urllib.parse.urlparse(url).hostname in ALLOWED_HOSTS",
        "urllib.parse.urlparse(other).hostname in {'api.example.test'}",
    ],
)
def test_security_scan_does_not_trust_incomplete_host_guards(tmp_path, condition):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "import urllib.parse\n"
        "def fetch():\n"
        "    host = request.args.get('host')\n"
        "    url = 'https://' + host + '/items'\n"
        "    other = 'https://fixed.example.test/items'\n"
        f"    if {condition}:\n"
        "        requests.get(url)\n",
        encoding="utf-8",
    )
    codes = {
        finding["code"]
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
    }
    assert "SECURITY_SSRF" in codes


def test_security_scan_does_not_suppress_url_rebound_inside_host_guard(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "import urllib.parse\n"
        "def fetch():\n"
        "    host = request.args.get('host')\n"
        "    url = 'https://' + host + '/items'\n"
        "    if urllib.parse.urlparse(url).hostname in {'api.example.test'}:\n"
        "        url = 'https://' + request.args.get('other')\n"
        "        requests.get(url)\n",
        encoding="utf-8",
    )
    codes = {
        finding["code"]
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
    }
    assert "SECURITY_SSRF" in codes


def test_security_scan_does_not_trust_nested_call_after_host_guard(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "import urllib.parse\n"
        "def fetch():\n"
        "    host = request.args.get('host')\n"
        "    url = 'https://' + host + '/items'\n"
        "    if urllib.parse.urlparse(url).hostname in {'api.example.test'}:\n"
        "        dispatch(mutate(url), requests.get(url))\n",
        encoding="utf-8",
    )
    codes = {
        finding["code"]
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
    }
    assert "SECURITY_SSRF" in codes


@pytest.mark.parametrize(
    ("filename", "expression"),
    [
        ("production.py", "pickle.loads(pickle.dumps(value))"),
        ("test_input.py", "pickle.loads(payload)"),
        ("test_input.py", "pickle.loads(transform(pickle.dumps(value)))"),
        ("test_input.py", "pickle.loads(dill.dumps(value))"),
    ],
)
def test_security_scan_keeps_unproven_deserialization_blocked(
    tmp_path, filename, expression
):
    (tmp_path / filename).write_text(f"import pickle, dill\nresult = {expression}\n")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["findings"][0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "replacement",
    [
        "pickle.dumps = get_external_bytes",
        "setattr(pickle, 'dumps', get_external_bytes)",
        "monkeypatch.setattr('pickle.dumps', get_external_bytes)",
        "patch('pickle.dumps', side_effect=get_external_bytes).start()",
    ],
)
def test_security_scan_does_not_trust_replaced_serializer(tmp_path, replacement):
    (tmp_path / "test_input.py").write_text(
        f"import pickle\n{replacement}\nresult = pickle.loads(pickle.dumps(value))\n"
    )
    assert security_scan(tmp_path)["state"] == "BLOCKED"


def test_security_scan_preserves_high_severity_for_patched_serializer_alias(tmp_path):
    (tmp_path / "test_input.py").write_text(
        "import pickle as serializer\nfrom unittest.mock import patch\n"
        "@patch('pickle.dumps', side_effect=get_external_bytes)\n"
        "def test_input(mock_dumps):\n"
        "    assert serializer.loads(serializer.dumps(value)) == value\n"
    )
    assert security_scan(tmp_path)["state"] == "BLOCKED"


def test_security_scan_retains_pickle_decorator_roundtrip_evidence(tmp_path):
    (tmp_path / "test_roundtrip.py").write_text(
        "import pickle, pytest\n"
        "@pytest.mark.parametrize('duplicate', [lambda value: pickle.loads(pickle.dumps(value))])\n"
        "def test_copy(duplicate):\n    assert duplicate({'value': 4}) == {'value': 4}\n"
    )
    result = security_scan(tmp_path)
    assert result["state"] == "FINDINGS"
    assert result["findings"][0]["severity"] == "INFO"


@pytest.mark.parametrize(
    ("source", "mutation"),
    [
        (
            "from unittest.mock import Mock\nsend = Mock()\n"
            "def perform(send):\n    send('payload')\n"
            "def test_behavior():\n    perform(send)\n"
            "    send.assert_called_once_with('payload')\n",
            "send.assert_called_once_with('incorrect')",
        ),
        (
            "import pytest\ndef operation():\n    raise TimeoutError()\n"
            "def test_behavior():\n    try:\n        operation()\n"
            "        pytest.fail('should raise')\n    except TimeoutError:\n        pass\n",
            "return None",
        ),
    ],
)
def test_argument_and_exception_oracles_fail_runtime_negative_controls(
    tmp_path, source, mutation
):
    import runpy

    (tmp_path / "test_behavior.py").write_text(source)
    assert security_scan(tmp_path)["findings"] == []
    namespace = runpy.run_path(str(tmp_path / "test_behavior.py"))
    namespace["test_behavior"]()
    if "Mock" in source:
        broken = source.replace("send.assert_called_once_with('payload')", mutation)
    else:
        broken = source.replace("raise TimeoutError()", mutation)
    (tmp_path / "test_negative_control.py").write_text(broken)
    namespace = runpy.run_path(str(tmp_path / "test_negative_control.py"))
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        namespace["test_behavior"]()


def test_security_scan_rejects_external_source_link(tmp_path):
    outside = tmp_path.parent / "external-source.txt"
    outside.write_text("PRIVATE_SOURCE = 1\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("source symlinks require OS permission")
    result = security_scan(tmp_path)
    assert result["unreadable_sources"] == 1
    assert result["audit_coverage"]["complete"] is False
    assert "PRIVATE_SOURCE" not in json.dumps(result)


def test_security_source_rejects_linked_parent(tmp_path):
    from factoryline.review_audits import _security_source_bytes
    from factoryline.runtime_audit_common import RuntimeAuditError

    outside = tmp_path.parent / "external-sources"
    outside.mkdir(exist_ok=True)
    (outside / "source.py").write_text("PRIVATE_SOURCE = 1\n", encoding="utf-8")
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks require OS permission")
    with pytest.raises(RuntimeAuditError, match="linked evidence"):
        _security_source_bytes(tmp_path, "linked/source.py")


def test_security_binding_recheck_rejects_link_swap(tmp_path):
    from factoryline.review_audits import _verify_security_bindings
    from hashlib import sha256

    source = tmp_path / "source.py"
    raw = b"VALUE = 1\n"
    source.write_bytes(raw)
    binding = {
        "path": "source.py",
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    outside = tmp_path.parent / "external-binding.txt"
    outside.write_bytes(raw)
    source.unlink()
    try:
        source.symlink_to(outside)
    except OSError:
        pytest.skip("source symlinks require OS permission")
    with pytest.raises(ReviewAuditError, match="Evidence changed"):
        _verify_security_bindings(tmp_path, [binding])


def test_security_syntax_diagnostic_omits_source_and_absolute_path(tmp_path):
    (tmp_path / "source.py").write_text("PRIVATE_SOURCE = (\n", encoding="utf-8")
    result = security_scan(tmp_path)
    details = [finding["facts"].get("detail") for finding in result["findings"]]
    assert details == ["invalid Python syntax"]


def test_audit_command_boundary_is_lazily_loaded() -> None:
    import factoryline.cli as cli
    from factoryline import cli_audit

    assert not hasattr(cli, "audit_code")
    assert cli_audit.COMMAND_GROUP == "audit"
    assert cli_audit.OWNER == "quality-security"


def test_audit_agent_context_cli_routes_specialist_domains(capsys) -> None:
    assert (
        main(
            [
                "audit",
                "agent-context",
                "--role",
                "specialty_ai_security_reviewer",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "factory.audit-agent-context.v1"
    assert result["role_resolution_state"] == "RESOLVED_FROM_CANONICAL_REGISTRY"
    assert (
        result["specialist_roles"][0]["specialist_role"]
        == "specialty_ai_security_reviewer"
    )
    assert result["domains"]
    assert all(
        row["specialist_role"] == "specialty_ai_security_reviewer"
        for row in result["domains"]
    )


def test_audit_cli_private_handlers_stay_bounded():
    import ast
    import inspect
    from factoryline import cli_audit

    for name, function in vars(cli_audit).items():
        if name != "run" and not name.startswith("_run_"):
            continue
        count = 1
        for node in ast.walk(ast.parse(inspect.getsource(function))):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)


def test_security_scan_orchestration_stays_within_complexity_budget():
    import ast
    import inspect

    import factoryline.review_audits as module

    for name in (
        "security_scan",
        "_tenant_contract_bindings",
        "_tenant_binding_entry",
        "_tenant_binding_parts",
        "_normalize_tenant_selector",
    ):
        count = 1
        tree = ast.parse(inspect.getsource(getattr(module, name)))
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)


def workspace(root: Path, body: str = "require_auth()\nstore.delete()") -> Path:
    source = (
        "def safe():\n    require_auth()\n    store.delete()\n\ndef candidate():\n"
        + textwrap.indent(body, "    ")
        + "\n"
    )
    (root / "app.py").write_text(source, encoding="utf-8")
    policy = {
        "schema": "factory.review-audit-policy.v1",
        "pattern_groups": [
            {
                "id": "peer-guards",
                "origin": "agent_proposed",
                "members": [
                    {"path": "app.py", "symbol": "safe"},
                    {"path": "app.py", "symbol": "candidate"},
                ],
                "required_calls": ["require_auth", "store.delete"],
            }
        ],
        "effect_rules": [
            {
                "id": "delete-guard",
                "origin": "human_confirmed",
                "target": {"path": "app.py", "symbol": "candidate"},
                "guard_call": "require_auth",
                "effect_call": "store.delete",
            }
        ],
    }
    folder = root / ".factory"
    folder.mkdir(exist_ok=True)
    path = folder / "review-audits.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_missing_peer_call_has_exact_peer_evidence(tmp_path):
    workspace(tmp_path, "store.delete()")
    result = audit_code(tmp_path, tool="patterns")
    assert result["state"] == "findings"
    (finding,) = result["findings"]
    assert finding["code"] == "PATTERN_REQUIRED_CALL_MISSING"
    assert finding["target"]["symbol"] == "candidate"
    assert finding["facts"]["missing_call"] == "require_auth"
    assert finding["facts"]["peers_with_call"] == [{"path": "app.py", "symbol": "safe"}]
    assert finding["declared_origin"] == "agent_proposed"


def test_guard_audit_catches_what_pattern_presence_misses(tmp_path):
    workspace(tmp_path, "if permitted:\n    require_auth()\nstore.delete()")
    result = audit_code(tmp_path)
    assert result["results"][0]["state"] == "no_structural_findings"
    (finding,) = result["findings"]
    assert finding["code"] == "GUARD_PATH_BYPASS"
    assert finding["facts"]["structural_witness"] == ["line 6: condition false"]
    assert finding["facts"]["effect_line"] == 8


@pytest.mark.parametrize(
    "body",
    [
        "require_auth()\nstore.delete()",
        "if permitted:\n    require_auth()\nelse:\n    require_auth()\nstore.delete()",
        "if not permitted:\n    return\nrequire_auth()\nstore.delete()",
        "if not permitted:\n    raise ValueError()\nrequire_auth()\nstore.delete()",
    ],
)
def test_supported_guarded_paths_have_no_structural_findings(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path)
    assert result["state"] == "no_structural_findings"
    assert not any(result["authority"].values())
    assert result["governance"] == "human_controlled"


@pytest.mark.parametrize(
    "body",
    [
        "store.delete()\nrequire_auth()",
        "require_auth(store.delete())",
        "return store.delete()",
        "if require_auth():\n    store.delete()",
        "allowed = require_auth()\nstore.delete()",
    ],
)
def test_non_dominating_guards_never_hide_effect(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert any(f["code"] == "GUARD_PATH_BYPASS" for f in result["findings"])


@pytest.mark.parametrize(
    "body",
    [
        "for x in values:\n    require_auth()\nstore.delete()",
        "try:\n    require_auth()\nexcept Exception:\n    pass\nstore.delete()",
        "with lock:\n    require_auth()\nstore.delete()",
        "require_auth() or store.delete()",
        "require_auth()\nstore.delete = fake\nstore.delete()",
        "require_auth()",  # absent effect cannot validate the declared release path
        "def child():\n    require_auth()\nstore.delete()",
    ],
)
def test_unknown_semantics_never_receive_clean_state(tmp_path, body):
    workspace(tmp_path, body)
    result = audit_code(tmp_path, tool="guard-paths")
    assert result["state"] == "incomplete"
    assert result["results"][0]["analysis_gaps"]


def test_nested_guard_does_not_count_as_peer_pattern(tmp_path):
    workspace(tmp_path, "def child():\n    require_auth()\nstore.delete()")
    assert (
        audit_code(tmp_path, tool="patterns")["findings"][0]["facts"]["missing_call"]
        == "require_auth"
    )


def test_explicit_scope_hashes_no_execution_or_writes(tmp_path):
    workspace(tmp_path)
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("\nraise RuntimeError('this module must never be imported')\n")
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    first = audit_code(tmp_path)
    assert len(first["sources"]) == 1
    assert len(first["policy"]["sha256"]) == 64
    assert audit_code(tmp_path) == first
    assert before == {
        str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    with (tmp_path / "app.py").open("a") as stream:
        stream.write("# changed\n")
    assert audit_code(tmp_path)["audit_sha256"] != first["audit_sha256"]


@pytest.mark.parametrize(
    "path", ["../app.py", "/app.py", "C:/app.py", "C:app.py", "missing.py"]
)
def test_invalid_source_path_rejected(tmp_path, path):
    policy_path = workspace(tmp_path)
    policy = json.loads(policy_path.read_text())
    policy["effect_rules"][0]["target"]["path"] = path
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(ReviewAuditError):
        audit_code(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["duplicate", "extra", "symbol", "empty", "origin", "same-call", "missing-tool"],
)
def test_policy_validation_and_missing_lane(tmp_path, mutation):
    path = workspace(tmp_path)
    policy = json.loads(path.read_text())
    if mutation == "duplicate":
        policy["effect_rules"][0]["id"] = "peer-guards"
    elif mutation == "extra":
        policy["execute"] = True
    elif mutation == "symbol":
        policy["effect_rules"][0]["target"]["symbol"] = "absent"
    elif mutation == "empty":
        policy["pattern_groups"] = policy["effect_rules"] = []
    elif mutation == "origin":
        policy["effect_rules"][0]["origin"] = ["human_confirmed"]
    elif mutation == "same-call":
        policy["effect_rules"][0]["guard_call"] = "store.delete"
    else:
        policy["effect_rules"] = []
    path.write_text(json.dumps(policy))
    if mutation == "missing-tool":
        assert audit_code(tmp_path)["state"] == "incomplete"
    else:
        with pytest.raises(ReviewAuditError):
            audit_code(tmp_path)


def test_path_explosion_is_explicit(tmp_path):
    workspace(
        tmp_path,
        "\n".join(f"if condition{i}:\n    pass" for i in range(8))
        + "\nrequire_auth()\nstore.delete()",
    )
    result = audit_code(tmp_path, tool="guard-paths")
    assert result["state"] == "incomplete"
    assert "path exploration limit" in result["results"][0]["analysis_gaps"]


def test_cli_and_change_review_integration(tmp_path, capsys):
    workspace(tmp_path, "if permitted:\n    require_auth()\nstore.delete()")
    assert main(["audit", "all", "--root", str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["findings"][0]["code"] == "GUARD_PATH_BYPASS"
    review = review_change(tmp_path, changed=["app.py"])
    assert review["findings"][0]["kind"] == "unmatched_changed_path"
    assert any(f["kind"] == "GUARD_PATH_BYPASS" for f in review["findings"])
    assert "GUARD_PATH_BYPASS" in review["review_markdown"]
    assert "GUARD_PATH_BYPASS" in review["mermaid"]
    assert review["code_audits"] == result


def test_audit_fingerprint_is_self_hash_bound_and_reusable(tmp_path):
    workspace(tmp_path)
    out = tmp_path / ".factory" / "fingerprint.json"
    first = audit_fingerprint(tmp_path, out_path=out)
    assert first["state"] == "CURRENT"
    assert first["reusable"] is True
    assert (
        first["receipt_sha256"]
        == __import__("hashlib")
        .sha256(
            __import__("json")
            .dumps(
                {k: v for k, v in first.items() if k != "receipt_sha256"},
                sort_keys=True,
                separators=(",", ":"),
            )
            .encode()
        )
        .hexdigest()
    )
    second = audit_fingerprint(tmp_path, baseline_path=out)
    assert second["state"] == "CURRENT"
    assert second["changes"]["policy"] is False


def test_audit_fingerprint_blocks_stale_baseline_and_reports_added_finding(tmp_path):
    workspace(tmp_path)
    baseline = tmp_path / ".factory" / "fingerprint.json"
    audit_fingerprint(tmp_path, out_path=baseline)
    (tmp_path / "app.py").write_text(
        "def safe():\n    require_auth()\n    store.delete()\n\ndef candidate():\n    store.delete()\n",
        encoding="utf-8",
    )
    result = audit_fingerprint(tmp_path, baseline_path=baseline)
    assert result["state"] == "DRIFT_DETECTED"
    assert result["code"] == "E_AUDIT_FINGERPRINT_STALE"
    assert result["reusable"] is False
    assert result["changes"]["sources"] is True


def test_audit_fingerprint_rejects_tampered_baseline(tmp_path):
    workspace(tmp_path)
    baseline = tmp_path / ".factory" / "fingerprint.json"
    audit_fingerprint(tmp_path, out_path=baseline)
    value = json.loads(baseline.read_text(encoding="utf-8"))
    value["fingerprint"]["state"] = "findings"
    baseline.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ReviewAuditError, match="digest is invalid"):
        audit_fingerprint(tmp_path, baseline_path=baseline)


def test_audit_fingerprint_cli_emits_actionable_json(tmp_path, capsys):
    workspace(tmp_path)
    assert (
        main(
            [
                "audit",
                "fingerprint",
                "--root",
                str(tmp_path),
                "--out",
                ".factory/fingerprint.json",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "AUDIT_FINGERPRINT_READY"
    assert result["authority"]["approval"] is False


def test_security_scan_blocks_dynamic_execution_and_shell(tmp_path):
    (tmp_path / "unsafe.py").write_text(
        "import os\nimport subprocess\ndef run(value):\n    eval(value)\n    os.system(value)\n    subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
    }
    assert all(item["path"] == "unsafe.py" for item in result["findings"])
    assert result["authority"] == {
        "execution": False,
        "approval": False,
        "publication": False,
        "deployment": False,
    }


def test_security_scan_accepts_reviewed_loaders_and_argv_bound_processes(tmp_path):
    (tmp_path / "safe.py").write_text(
        'import subprocess\nimport yaml\ndef run(value):\n    yaml.load(value, Loader=yaml.SafeLoader)\n    subprocess.run(["tool", value], shell=False, check=True)\n',
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "CLEAN"
    assert result["parse_errors"] == 0


def test_security_scan_receipt_measures_complete_supported_source_coverage(tmp_path):
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    generated = tmp_path / ".venv" / "ignored.py"
    generated.parent.mkdir()
    generated.write_text("not scanned", encoding="utf-8")
    coverage = security_scan(tmp_path)["audit_coverage"]
    assert coverage == {
        "language": "Python",
        "files_discovered": 1,
        "files_attempted": 1,
        "files_audited": 1,
        "audit_rate": 1.0,
        "rate_defined": True,
        "inventory_complete": True,
        "measurement_state": "complete",
        "complete": True,
        "limit": 460,
    }


@pytest.mark.parametrize(
    "source,expected",
    [
        ("def run():\n    hidden = [x for x in range(10)]\n", {"run"}),
        ("async def run():\n    hidden = [x for x in range(10)]\n", {"run"}),
        ("class Run:\n    hidden = [x for x in range(10)]\n", {"Run"}),
        ("lambda: [x for x in range(10)]", set()),
    ],
)
def test_bound_definition_names_do_not_walk_deferred_bodies(
    monkeypatch, source, expected
):
    import ast
    import factoryline.review_audits as module

    node = ast.parse(source).body[0]
    if isinstance(node, ast.Expr):
        node = node.value

    def forbidden_walk(_node):
        pytest.fail("bound-name lookup traversed a deferred definition body")

    monkeypatch.setattr(module, "_iter_ast_nodes", forbidden_walk)
    assert module._bound_names(node) == expected


def test_scan_bound_name_cache_reuses_walk_and_copies_results(monkeypatch):
    import ast
    import factoryline.review_audits as module

    statement = ast.parse("values = [x for x in source if (seen := x)]").body[0]
    statement._scan_bound_names = None
    walk = module._iter_ast_nodes
    calls = []

    def counted(node):
        calls.append(node)
        yield from walk(node)

    monkeypatch.setattr(module, "_iter_ast_nodes", counted)
    first = module._bound_names(statement)
    count = len(calls)
    first.add("caller_only")
    assert module._bound_names(statement) == {"values", "seen"}
    assert len(calls) == count


def test_scanner_resets_binding_cache_for_reused_changed_ast(tmp_path):
    import ast
    import factoryline.review_audits as module

    tree = ast.parse("values = [x for x in source]")
    statement = tree.body[0]
    module._security_scan_tree(tmp_path, tmp_path / "app.py", tree)
    assert module._bound_names(statement) == {"values"}
    statement.targets.append(ast.Name(id="changed", ctx=ast.Store()))
    module._security_scan_tree(tmp_path, tmp_path / "app.py", tree)
    assert module._bound_names(statement) == {"values", "changed"}


@pytest.mark.parametrize("root_name", ["tmp", "vendor", "project"])
def test_security_inventory_prunes_ignored_descendants_not_workspace(
    tmp_path, monkeypatch, root_name
):
    import factoryline.review_audits as module

    root = tmp_path / root_name
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    for ignored in (".factory", "node_modules", ".venv", "vendor"):
        folder = root / ignored / "nested"
        folder.mkdir(parents=True)
        (folder / "cached.py").write_text("value = 2\n", encoding="utf-8")
    visited = []
    walk = module.os.walk

    def observed_walk(*args, **kwargs):
        for row in walk(*args, **kwargs):
            visited.append(row[0])
            yield row

    monkeypatch.setattr(module.os, "walk", observed_walk)
    assert module._security_source_files(root) == [root / "app.py"]
    assert visited == [str(root)]


def test_import_index_reuses_resolved_sources_without_reindexing(tmp_path, monkeypatch):
    import ast
    import factoryline.review_audits as module

    source = tmp_path / "helpers.py"
    source.write_text("def check():\n    assert value\n", encoding="utf-8")
    caller = tmp_path / "test_app.py"
    tree = ast.parse("from helpers import check\n")
    index = {source.resolve(): source}
    expected = module._oracle_imports(tmp_path, caller, tree, {source})
    original = type(source).resolve
    calls = []

    def observed_resolve(path, *args, **kwargs):
        if path == source:
            calls.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(source), "resolve", observed_resolve)
    assert module._oracle_imports(tmp_path, caller, tree, index) == expected
    indexed_calls = len(calls)
    calls.clear()
    assert module._oracle_imports(tmp_path, caller, tree, {source}) == expected
    assert len(calls) == indexed_calls + 1


def test_oracle_context_cache_reuses_only_context_and_preserves_report(tmp_path):
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text(
        "def run(value):\n    return value\n", encoding="utf-8"
    )
    module._oracle_context_cache_clear()
    uncached = security_scan(tmp_path, cache_enabled=False)
    cached_first = security_scan(tmp_path, cache_enabled=True)
    cached_second = security_scan(tmp_path, cache_enabled=True)
    assert cached_first == uncached == cached_second
    info = module._oracle_context_cache_info()
    assert info["hits"] >= 1
    assert info["misses"] >= 1
    assert info["entries"] <= module.MAX_ORACLE_CONTEXT_CACHE_ENTRIES
    assert info["serialized_bytes"] <= module.MAX_ORACLE_CONTEXT_CACHE_BYTES


def test_oracle_context_cache_is_used_by_default(tmp_path):
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    first = security_scan(tmp_path)
    second = security_scan(tmp_path)
    assert first == second
    assert module._oracle_context_cache_info()["hits"] >= 1


def test_oracle_context_cache_invalidates_source_and_configuration_changes(tmp_path):
    import factoryline.review_audits as module

    module._oracle_context_cache_clear()
    source = tmp_path / "app.py"
    source.write_text("def run(value):\n    return value\n", encoding="utf-8")
    first = security_scan(tmp_path, cache_enabled=True)
    assert first["state"] == "CLEAN"
    first_misses = module._oracle_context_cache_info()["misses"]
    source.write_text("def run(value):\n    eval(value)\n", encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=True)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"] == {"SECURITY_DYNAMIC_EXECUTION": 1}
    assert module._oracle_context_cache_info()["misses"] > first_misses

    (tmp_path / "typing_probe.py").write_text(
        "from typing_extensions import assert_type\n"
        "def test_type():\n    assert_type(compute(), int)\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = typing_probe.py\n", encoding="utf-8"
    )
    unconfigured = security_scan(tmp_path, cache_enabled=True)
    assert unconfigured["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1
    (tmp_path / "pyproject.toml").write_text(
        '[tool.mypy]\nfiles = ["typing_probe.py"]\n', encoding="utf-8"
    )
    configured = security_scan(tmp_path, cache_enabled=True)
    assert configured["finding_counts"].get("QUALITY_HOLLOW_TEST") is None
    assert any(
        row["kind"] == "static_type_configuration"
        for row in configured["oracle_context"]["resolved_edges"]
    )


def test_oracle_context_cache_invalidates_when_projector_helper_changes(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    (tmp_path / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    test_path = tmp_path / "test_case.py"
    test_path.write_text("def test_case():\n    assert True\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    first_contexts, _, _, _ = module._project_oracle_context(
        tmp_path, module._security_source_files(tmp_path), cache_enabled=True
    )
    first_misses = module._oracle_context_cache_info()["misses"]
    monkeypatch.setattr(
        module, "_click_runner_fixtures", lambda tree, aliases: {"runner": True}
    )
    changed_contexts, _, _, _ = module._project_oracle_context(
        tmp_path, module._security_source_files(tmp_path), cache_enabled=True
    )
    assert (
        first_contexts[test_path]["click_runners"]
        != changed_contexts[test_path]["click_runners"]
    )
    assert module._oracle_context_cache_info()["misses"] > first_misses


def test_security_scan_reuses_projected_source_bytes_on_cache_miss_and_hit(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    reads = []
    original = module._security_source_bytes

    def counted_read(root, relative):
        if relative == "app.py":
            reads.append(relative)
        return original(root, relative)

    monkeypatch.setattr(module, "_security_source_bytes", counted_read)
    first = security_scan(tmp_path, cache_enabled=True)
    assert len(reads) == 3
    reads.clear()

    second = security_scan(tmp_path, cache_enabled=True)

    assert first == second
    assert len(reads) == 3


def test_security_scan_falls_back_to_secure_reads_when_bytes_are_not_retained(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    expected = security_scan(tmp_path, cache_enabled=False)
    reads = []
    original_read = module._security_source_bytes
    original_inputs = module._oracle_source_inputs

    def counted_read(root, relative):
        if relative == "app.py":
            reads.append(relative)
        return original_read(root, relative)

    def discard_retained(root, files):
        _, bindings, manifest, cacheable = original_inputs(root, files)
        return {}, bindings, manifest, cacheable

    monkeypatch.setattr(module, "_security_source_bytes", counted_read)
    monkeypatch.setattr(module, "_oracle_source_inputs", discard_retained)
    actual = security_scan(tmp_path, cache_enabled=False)

    assert actual == expected
    assert len(reads) == 5


@pytest.mark.parametrize(
    "collaborator", ["builder", "configuration"], ids=["builder", "configuration"]
)
def test_oracle_context_cache_invalidates_when_direct_collaborator_changes(
    tmp_path, monkeypatch, collaborator
):
    import factoryline.review_audits as module
    from factoryline import review_integrity

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    files = module._security_source_files(tmp_path)
    module._project_oracle_context(tmp_path, files, cache_enabled=True)
    first_misses = module._oracle_context_cache_info()["misses"]
    owner, name = (
        (module, "_build_oracle_context")
        if collaborator == "builder"
        else (review_integrity, "oracle_configuration")
    )
    original = getattr(owner, name)
    calls = []

    def wrapped(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, name, wrapped)
    module._project_oracle_context(tmp_path, files, cache_enabled=True)

    assert calls == [None]
    assert module._oracle_context_cache_info()["misses"] > first_misses


def test_oracle_context_cache_expiration_and_corruption_are_cache_misses(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    (tmp_path / "test_case.py").write_text("def test_case():\n    assert True\n")
    module._oracle_context_cache_clear()
    expected = security_scan(tmp_path, cache_enabled=False)
    first = security_scan(tmp_path, cache_enabled=True)
    assert first == expected
    info = module._oracle_context_cache_info()
    assert info["entries"] == 1
    key, (_, size, created) = next(iter(module._ORACLE_CONTEXT_CACHE.items()))
    module._ORACLE_CONTEXT_CACHE[key] = ("{", size, created)
    corrupt_recovery = security_scan(tmp_path, cache_enabled=True)
    assert corrupt_recovery == expected
    assert module._oracle_context_cache_info()["entries"] == 1
    _, (_, _, refreshed) = next(iter(module._ORACLE_CONTEXT_CACHE.items()))

    monkeypatch.setattr(
        module.time,
        "monotonic",
        lambda: refreshed + module.ORACLE_CONTEXT_CACHE_TTL_SECONDS + 1,
    )
    expired_recovery = security_scan(tmp_path, cache_enabled=True)
    assert expired_recovery == expected
    assert module._oracle_context_cache_info()["entries"] == 1


def test_security_cli_displays_measured_source_audit_rate(tmp_path, capsys):
    (tmp_path / "app.py").write_text("answer = 42\n", encoding="utf-8")
    factory_dir = tmp_path / ".factory"
    factory_dir.mkdir()
    (factory_dir / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )

    assert main(["audit", "security", "--root", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "Coverage: 100.0% (1/1 Python sources; complete)" in output


def test_security_scan_does_not_report_vacuous_full_coverage(tmp_path):
    result = security_scan(tmp_path)
    coverage = result["audit_coverage"]

    assert result["state"] == "NO_SOURCES"
    assert coverage["files_discovered"] == 0
    assert coverage["files_attempted"] == 0
    assert coverage["files_audited"] == 0
    assert coverage["audit_rate"] is None
    assert coverage["rate_defined"] is False
    assert coverage["measurement_state"] == "no_eligible_sources"
    assert coverage["inventory_complete"] is True
    assert coverage["complete"] is False


def test_security_cli_returns_indeterminate_for_empty_inventory(tmp_path, capsys):
    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])

    result = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert result["state"] == "NO_SOURCES"
    assert result["audit_coverage"]["audit_rate"] is None


def test_security_scan_blocks_instead_of_truncating_over_limit_inventory(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    assert module.MAX_SECURITY_SOURCE_FILES == 460
    monkeypatch.setattr(module, "MAX_SECURITY_SOURCE_FILES", 2)
    for index in range(3):
        (tmp_path / f"module_{index}.py").write_text("value = 1\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["audit_coverage"]["files_discovered"] == 3
    assert result["audit_coverage"]["files_attempted"] == 0
    assert result["audit_coverage"]["files_audited"] == 0
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["inventory_complete"] is True
    assert result["audit_coverage"]["complete"] is False
    assert result["audit_coverage"]["measurement_state"] == "blocked"
    assert result["finding_counts"] == {"SECURITY_AUDIT_INCOMPLETE": 1}


def test_security_cli_preserves_over_limit_report_in_receipt(
    tmp_path, monkeypatch, capsys
):
    import factoryline.review_audits as module

    monkeypatch.setattr(module, "MAX_SECURITY_SOURCE_FILES", 2)
    for index in range(3):
        (tmp_path / f"module_{index}.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 2
    captured = capsys.readouterr()
    assert not captured.err
    result = json.loads(captured.out)
    assert result["state"] == "BLOCKED"
    assert result["audit_coverage"]["files_attempted"] == 0
    assert result["audit_coverage"]["complete"] is False
    assert result["finding_counts"] == {"SECURITY_AUDIT_INCOMPLETE": 1}
    assert result["oracle_context"]["mode"] == "not_assessed_source_limit"
    receipt = json.loads(
        (tmp_path / ".factory/security-scan/latest.json").read_text(encoding="utf-8")
    )
    assert receipt["schema"] == "factory.security-scan-receipt.v1"
    assert receipt["report"] == result


@pytest.mark.parametrize(
    "statement",
    [
        "return request.form.get('password') == 'literal-value'",
        "accepted = request.form.get('password') == 'literal-value'",
        "assert request.form.get('password') == 'literal-value'",
    ],
)
def test_security_password_comparison_in_value_statements(tmp_path, statement):
    (tmp_path / "app.py").write_text(
        f"from flask import request\ndef login():\n    {statement}\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"SECURITY_HARDCODED_SECRET": 1}


def test_security_scan_tracks_import_aliases_and_unsafe_yaml_loaders(tmp_path):
    (tmp_path / "aliases.py").write_text(
        "from subprocess import run as launch\nimport yaml as y\n"
        "def run(value):\n    launch(value, shell=True)\n    y.load(value, Loader=y.UnsafeLoader)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_YAML",
    }


def test_security_tree_scan_reuses_one_ast_inventory_for_alias_and_tenant_checks(
    tmp_path, monkeypatch
):
    import ast

    import factoryline.review_audits as module

    source = (
        "import subprocess as sp\n"
        "def fetch(tenant_id):\n    return store.fetch(tenant_id=tenant_id)\n"
        "def run():\n    sp.run('cmd', shell=True)\n"
    )
    tree = ast.parse(source)
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    original_walk = ast.walk
    calls = 0

    def counted_walk(node):
        nonlocal calls
        calls += 1
        return original_walk(node)

    monkeypatch.setattr(module.ast, "walk", counted_walk)
    findings = module._security_scan_tree(tmp_path, path, tree, ("store.fetch",), {})

    assert calls == 1
    assert [finding["code"] for finding in findings] == ["SECURITY_SHELL_COMMAND"]


def test_security_log_flow_reuses_prebound_call_inventory(tmp_path, monkeypatch):
    import ast

    import factoryline.review_audits as module

    source = (
        "import logging\ndef record():\n    raw = input()\n    logging.error(raw)\n"
    )
    tree = ast.parse(source)
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    original_walk = ast.walk
    calls = 0

    def counted_walk(node):
        nonlocal calls
        calls += 1
        return original_walk(node)

    monkeypatch.setattr(module.ast, "walk", counted_walk)
    findings = module._security_scan_tree(tmp_path, path, tree, (), {})

    assert calls == 1
    assert [finding["code"] for finding in findings] == ["SECURITY_LOG_INJECTION"]


@pytest.mark.parametrize(
    "source,expected",
    [
        pytest.param(
            "import logging\ndef record():\n    logging.error('plain')\n",
            False,
            id="constant-log-message-does-not-crash",
        ),
        pytest.param(
            "import logging\ndef record():\n    logging.error('plain' + ' text')\n",
            False,
            id="binop-log-message-does-not-crash",
        ),
        pytest.param(
            "import logging\ndef record():\n    if True:\n        if logging.error(input()):\n            pass\n",
            True,
            id="nested-if-header-input-is-logged",
        ),
        pytest.param(
            "import logging\ndef record():\n    if True:\n        while logging.error(input()):\n            break\n",
            True,
            id="nested-loop-header-input-is-logged",
        ),
        pytest.param(
            "import logging\ndef record():\n    if True:\n        with logging.error(input()):\n            pass\n",
            True,
            id="nested-with-header-input-is-logged",
        ),
    ],
)
def test_security_log_flow_handles_plain_messages_and_nested_headers(
    tmp_path, source, expected
):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert ("SECURITY_LOG_INJECTION" in result["finding_counts"]) is expected


def test_security_scan_reports_parse_errors_fail_closed(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"] == {"QUALITY_SYNTAX_ERROR": 1}
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["complete"] is False
    assert result["audit_coverage"]["measurement_state"] == "incomplete"


def test_security_scan_separates_unreadable_sources_from_parse_errors(
    tmp_path, monkeypatch
):
    from pathlib import Path

    import factoryline.review_audits as module

    readable = tmp_path / "readable.py"
    unreadable = tmp_path / "unreadable.py"
    readable.write_text("value = 1\n", encoding="utf-8")
    unreadable.write_text("value = 2\n", encoding="utf-8")
    original_open = module.os.open

    def open_path(path, *args, **kwargs):
        if Path(path).resolve() == unreadable.resolve():
            raise PermissionError("denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", open_path)

    result = module.security_scan(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["parse_errors"] == 0
    assert result["unreadable_sources"] == 1
    assert result["oversized_sources"] == 0
    assert result["audit_coverage"] == {
        "language": "Python",
        "files_discovered": 2,
        "files_attempted": 2,
        "files_audited": 1,
        "audit_rate": 0.5,
        "rate_defined": True,
        "inventory_complete": True,
        "measurement_state": "incomplete",
        "complete": False,
        "limit": 460,
    }
    assert result["finding_counts"] == {"SECURITY_SOURCE_UNREADABLE": 1}


def test_security_scan_counts_oversized_source_as_attempted_but_unaudited(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as module

    monkeypatch.setattr(module, "MAX_BYTES", 4)
    (tmp_path / "large.py").write_text("value = 123\n", encoding="utf-8")

    result = security_scan(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["oversized_sources"] == 1
    assert result["unreadable_sources"] == 0
    assert result["parse_errors"] == 0
    assert result["audit_coverage"]["files_discovered"] == 1
    assert result["audit_coverage"]["files_attempted"] == 1
    assert result["audit_coverage"]["files_audited"] == 0
    assert result["audit_coverage"]["audit_rate"] == 0.0
    assert result["audit_coverage"]["complete"] is False
    assert result["finding_counts"] == {"SECURITY_SOURCE_TOO_LARGE": 1}


def test_security_scan_rejects_large_file_without_unbounded_read(tmp_path, monkeypatch):
    from pathlib import Path

    import factoryline.review_audits as module

    monkeypatch.setattr(module, "MAX_BYTES", 4)
    (tmp_path / "large.py").write_text("value = 123\n", encoding="utf-8")

    def reject_unbounded_read(_path):
        raise AssertionError("security scan must not call read_bytes")

    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)

    result = module.security_scan(tmp_path)

    assert result["finding_counts"] == {"SECURITY_SOURCE_TOO_LARGE": 1}
    assert result["audit_coverage"]["files_audited"] == 0


def test_security_scan_rejects_concurrent_source_mutation(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def ok():\n    return 1\n", encoding="utf-8")
    import factoryline.review_audits as module

    original = module._security_scan_tree

    def mutate(*args):
        result = original(*args)
        source.write_text("def ok():\n    return 2\n", encoding="utf-8")
        return result

    monkeypatch.setattr(module, "_security_scan_tree", mutate)
    with pytest.raises(ReviewAuditError, match="Evidence changed during security scan"):
        security_scan(tmp_path)


def test_security_evals_kill_all_adversarial_fixtures_and_keep_safe_control_clean():
    result = security_evals()
    assert result["marker"] == "SECURITY_EVALS_COMPLETE"
    assert result["state"] == "PASS"
    assert result["mutation_coverage"] == {"attempted": 14, "caught": 14, "rate": 1.0}
    assert result["safe_controls"] == {"attempted": 4, "passed": 4}
    assert result["authority"]["approval"] is False


@pytest.mark.parametrize(
    "body",
    [
        "assert True",
        "compute_value()",
        "actual = compute_value()\n    assert actual == actual",
        "assert len(result) >= 0",
    ],
)
def test_security_scan_detects_local_hollow_test_oracles(tmp_path, body):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["findings"][0]["facts"]["symbol"] == "test_behavior"


@pytest.mark.parametrize(
    "body,expected",
    [
        ("assert (compute(), expected)", "QUALITY_HOLLOW_TEST"),
        ("assert (*values, compute())", "QUALITY_HOLLOW_TEST"),
        ("assert isinstance(compute(), object)", "QUALITY_WEAK_TEST_ORACLE"),
        ("while False:\n        assert compute() == 3", "QUALITY_HOLLOW_TEST"),
        ("for item in []:\n        assert compute(item) == 3", "QUALITY_HOLLOW_TEST"),
        ("for item in ():\n        assert compute(item) == 3", "QUALITY_HOLLOW_TEST"),
        ("for item in {}:\n        assert compute(item) == 3", "QUALITY_HOLLOW_TEST"),
        ("for item in '':\n        assert compute(item) == 3", "QUALITY_HOLLOW_TEST"),
        ("assert (compute(), other()) == expected", None),
        ("assert (*values,)", None),
        ("assert isinstance(compute(), str)", None),
        ("object = Expected\n    assert isinstance(compute(), object)", None),
        ("isinstance = check\n    assert isinstance(compute(), object)", None),
        ("for item in [1]:\n        assert compute(item) == 3", None),
        ("for item in values:\n        assert compute(item) == 3", None),
        ("while False:\n        pass\n    else:\n        assert compute() == 3", None),
        (
            "for item in []:\n        pass\n    else:\n        assert compute() == 3",
            None,
        ),
        (
            "try:\n        assert compute() == 3\n    except AssertionError:\n        pass",
            "QUALITY_HOLLOW_TEST",
        ),
        ("raise AssertionError('natural failure')", None),
    ],
)
def test_oracle_precision_reported_truth_and_reachability(tmp_path, body, expected):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    " + body + "\n", encoding="utf-8"
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == ({expected: 1} if expected else {})
    if expected:
        assert result["findings"][0]["facts"]["symbol"] == "test_behavior"
        assert result["findings"][0]["line"] > 0


@pytest.mark.parametrize(
    "body,hollow",
    [
        ("self.assertTrue(True)", True),
        ("self.assertFalse(False)", True),
        ("self.assertEqual(1, 1)", True),
        ("self.assertTupleEqual((1,), (1,))", True),
        ("self.assertListEqual([1], [1])", True),
        ("self.assertEqual(value, value)", True),
        ("self.assertTrue(compute())", False),
        ("self.assertFalse(compute())", False),
        ("self.assertEqual(compute(), 1)", False),
        ("self.assertTupleEqual(compute(), (1,))", False),
        ("self.assertEqual(obj.value, obj.value)", False),
    ],
)
def test_oracle_precision_unittest_vacuity(tmp_path, body, hollow):
    (tmp_path / "test_case.py").write_text(
        "import unittest\nclass Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n        " + body + "\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == ({"QUALITY_HOLLOW_TEST": 1} if hollow else {})


@pytest.mark.parametrize("binding", ["object", "isinstance"])
@pytest.mark.parametrize("scope", ["module", "parameter"])
def test_oracle_precision_universal_type_shadow_controls(tmp_path, binding, scope):
    source = (
        f"{binding} = custom\ndef test_behavior():\n"
        if scope == "module"
        else f"def test_behavior({binding}):\n"
    )
    (tmp_path / "test_case.py").write_text(
        source + "    assert isinstance(compute(), object)\n", encoding="utf-8"
    )
    assert security_scan(tmp_path, cache_enabled=False)["findings"] == []


@pytest.mark.parametrize(
    "prefix,decorator,flagged",
    [
        ("import pytest\n", "pytest.mark.parametrize('value', [])", True),
        ("import pytest as p\n", "p.mark.parametrize('value', ())", True),
        ("from pytest import mark as m\n", "m.parametrize('value', {})", True),
        (
            "import pytest\n",
            "pytest.mark.parametrize(argnames='value', argvalues=[])",
            True,
        ),
        ("import pytest\n", "pytest.mark.parametrize('value', '')", True),
        ("import pytest\n", "pytest.mark.parametrize('value', [1])", False),
        ("import pytest\n", "pytest.mark.parametrize('value', values)", False),
        ("import pytest\n", "pytest.mark.parametrize('value', build_cases())", False),
        ("import pytest\n", "pytest.mark.parametrize(*names, [])", False),
        ("import other as p\n", "p.mark.parametrize('value', [])", False),
        (
            "import pytest\npytest = custom\n",
            "pytest.mark.parametrize('value', [])",
            False,
        ),
        ("", "pytest.mark.parametrize('value', [])", False),
    ],
)
def test_empty_parameter_set_reports_missing_execution(
    tmp_path, prefix, decorator, flagged
):
    (tmp_path / "test_cases.py").write_text(
        prefix + "@" + decorator + "\ndef test_value(value):\n"
        "    assert compute(value) == 1\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == (
        {"QUALITY_EMPTY_PARAMETER_SET": 1} if flagged else {}
    )
    if flagged:
        finding = result["findings"][0]
        assert finding["severity"] == "INFO"
        assert finding["facts"]["state"] == "INCOMPLETE"
        assert finding["facts"]["symbol"] == "test_value"


def test_empty_parameter_set_does_not_credit_body_shadow_over_decorator(tmp_path):
    (tmp_path / "test_cases.py").write_text(
        "import pytest\n@pytest.mark.parametrize('pytest', [])\n"
        "def test_value(pytest):\n    assert compute(pytest) == 1\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path, cache_enabled=False)["finding_counts"] == {
        "QUALITY_EMPTY_PARAMETER_SET": 1
    }


def test_empty_parameter_set_does_not_change_unittest_method_collection(tmp_path):
    (tmp_path / "test_cases.py").write_text(
        "import pytest, unittest\nclass Checks(unittest.TestCase):\n"
        "    @pytest.mark.parametrize('value', [])\n"
        "    def test_value(self):\n        self.assertEqual(compute(), 1)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path, cache_enabled=False)["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        "expected = 3\n    alias = expected\n    assert alias == expected",
        "value = value\n    assert value == value",
        "result = 3\n    assert result == 3",
        "x = 5\n    x = x + 1\n    assert x == 6",
        "assert result or True",
    ],
)
def test_security_scan_detects_constant_and_boolean_tautologies(tmp_path, body):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "body",
    [
        "assert compute_value() == 1",
        "self.assertEqual(compute_value(), 1)",
        "with pytest.raises(ValueError):\n        compute_value()",
    ],
)
def test_security_scan_preserves_real_assertions_and_exception_controls(tmp_path, body):
    if body.startswith("self.assert"):
        source = (
            "import unittest\n"
            "class Checks(unittest.TestCase):\n"
            "    def test_behavior(self):\n"
            f"        {body}\n"
        )
    else:
        source = "def test_behavior():\n    " + body + "\n"
    (tmp_path / "test_case.py").write_text(source)
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        "argument = 5\n    result = compute(argument)\n    assert result == 6",
        "cases = [(2, 4)]\n    for value, expected in cases:\n        assert compute(value) == expected",
        "result = compute_value()\n    assert result == 6",
        "result = 0\n    if condition:\n        result = compute_value()\n    assert result == 6",
        "result = 0\n    try:\n        result = compute_value()\n    except ValueError:\n        result = fallback()\n    assert result == 6",
        "result = 0\n    with resource() as result:\n        pass\n    assert result == 6",
    ],
)
def test_security_scan_preserves_runtime_and_branch_rebound_oracles(tmp_path, body):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_use_a_constant_reassigned_after_assertion(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    result = 3\n"
        "    assert result == 3\n"
        "    result = compute_value()\n"
        "    assert result == 3\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["findings"] == []


@pytest.mark.parametrize(
    ("body", "finding"),
    [
        ("result = compute_value()\n    assert (result or 1) == 1", False),
        ("value = compute_value() or 1\n    assert value == 1", False),
        ("value = True or compute_value()\n    assert value", True),
        ("value = False and compute_value()\n    assert not value", True),
        ("result = 2\n    assert (result or 1) == 1", False),
        ("result = 0\n    assert (result or 1) == 1", True),
        ("result = 3\n    assert (result or 1) == 1", False),
    ],
)
def test_security_scan_preserves_python_boolean_operand_semantics(
    tmp_path, body, finding
):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert bool(result["findings"]) is finding


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (
            "assert value is not None",
            "non-null assertion does not verify the expected behavior",
        ),
        (
            "operation()\n    assert operation_mock.called",
            "mock invocation state does not verify its result or arguments",
        ),
        (
            "assert next_value() == next_value()",
            "repeated invocation compares a result to itself",
        ),
    ],
)
def test_security_scan_reports_weak_only_test_oracles(tmp_path, body, reason):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}
    assert reason in result["findings"][0]["message"]


def test_oracle_builder_summarizes_imported_helpers_once_per_snapshot(
    tmp_path, monkeypatch
):
    import ast
    from pathlib import Path

    import factoryline.review_audits as module

    helpers = tmp_path / "helpers.py"
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    helpers.write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n"
        "\ndef assert_present(value):\n    assert value is not None\n",
        encoding="utf-8",
    )
    first.write_text(
        "import helpers as helper_alias\n"
        "from helpers import assert_expected as direct_assertion\n"
        "from helpers import assert_present as weak_assertion\n",
        encoding="utf-8",
    )
    second.write_text("import helpers as other_alias\n", encoding="utf-8")
    files = [helpers, first, second]
    snapshots = {
        path: ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for path in files
    }
    strong_calls = []
    weak_calls = []
    original_strong = module._local_assertion_helpers
    original_weak = module._local_weak_assertion_helpers

    def count_strong(*args, **kwargs):
        strong_calls.append(None)
        return original_strong(*args, **kwargs)

    def count_weak(*args, **kwargs):
        weak_calls.append(None)
        return original_weak(*args, **kwargs)

    monkeypatch.setattr(module, "_local_assertion_helpers", count_strong)
    monkeypatch.setattr(module, "_local_weak_assertion_helpers", count_weak)
    _contexts, edges = module._build_oracle_context(tmp_path, files, snapshots, set())

    assert len(strong_calls) == 1
    assert len(weak_calls) == 1
    helper_edges = {
        (row["caller"], row["symbol"], row["strength"])
        for row in edges
        if row["target"] == Path("helpers.py").as_posix()
        and row["kind"] == "assertion_helper"
    }
    assert helper_edges == {
        ("first.py", "helper_alias.assert_expected", "strong"),
        ("first.py", "helper_alias.assert_present", "weak"),
        ("first.py", "assert_expected", "strong"),
        ("first.py", "direct_assertion.assert_present", "weak"),
        ("first.py", "weak_assertion.assert_expected", "strong"),
        ("first.py", "assert_present", "weak"),
        ("second.py", "other_alias.assert_expected", "strong"),
        ("second.py", "other_alias.assert_present", "weak"),
    }


def test_local_weak_helper_uses_supplied_strong_summary_without_recomputing(
    monkeypatch,
):
    import ast

    import factoryline.review_audits as module

    tree = ast.parse("def assert_present(value):\n    assert value is not None\n")
    monkeypatch.setattr(
        module,
        "_local_assertion_helpers",
        lambda *args, **kwargs: pytest.fail("strong helpers were recomputed"),
    )

    assert module._local_weak_assertion_helpers(tree, {}, strong_helpers=set()) == {
        "assert_present"
    }


def test_oracle_builder_refreshes_helper_summary_for_changed_snapshot(tmp_path):
    import ast

    import factoryline.review_audits as module

    helper_path = tmp_path / "helpers.py"
    caller_path = tmp_path / "test_case.py"
    helper_path.write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    caller_path.write_text("from helpers import assert_expected\n", encoding="utf-8")
    files = [helper_path, caller_path]
    first_snapshots = {
        path: ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for path in files
    }
    _first_contexts, first_edges = module._build_oracle_context(
        tmp_path, files, first_snapshots, set()
    )
    helper_path.write_text(
        "def assert_expected(value):\n    assert value is not None\n",
        encoding="utf-8",
    )
    second_snapshots = {
        path: ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for path in files
    }
    _second_contexts, second_edges = module._build_oracle_context(
        tmp_path, files, second_snapshots, set()
    )

    first_edge_keys = {
        (edge["caller"], edge["target"], edge["kind"], edge["symbol"], edge["strength"])
        for edge in first_edges
    }
    second_edge_keys = {
        (edge["caller"], edge["target"], edge["kind"], edge["symbol"], edge["strength"])
        for edge in second_edges
    }
    strong_edge = (
        "test_case.py",
        "helpers.py",
        "assertion_helper",
        "assert_expected",
        "strong",
    )
    weak_edge = (*strong_edge[:-1], "weak")
    assert strong_edge in first_edge_keys
    assert weak_edge in second_edge_keys
    assert strong_edge not in second_edge_keys


def test_security_scan_accepts_local_helper_with_independent_assertion(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    assert actual == expected\n\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_imported_helper_with_independent_assertion(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["findings"] == []
    assert result["oracle_context"]["edge_count"] == 1
    assert result["oracle_context"]["resolved_edges"][0]["kind"] == "assertion_helper"


def test_security_scan_rejects_imported_helper_that_swallows_assertion(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        "    except AssertionError:\n        return\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_recognizes_test_named_assertion_helper(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_expected(actual, expected):\n    assert actual == expected\n\n"
        "def test_behavior():\n    test_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_recognizes_imported_test_named_assertion_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def test_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import test_expected\n"
        "def test_behavior():\n    test_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_recognizes_assertion_hidden_by_warning_policy(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', UserWarning)\n"
        "        emit_user_warning()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "filters",
    [
        "warnings.simplefilter('error', UserWarning)\n"
        "warnings.simplefilter('ignore', UserWarning)\n"
        "emit_user_warning()",
        "warnings.simplefilter('error', UserWarning)",
    ],
)
def test_security_scan_does_not_trust_inactive_warning_filter(tmp_path, filters):
    (tmp_path / "test_case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        + "\n".join("        " + line for line in filters.splitlines())
        + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_credit_unrelated_call_after_swallowed_warning(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', UserWarning)\n"
        "        try:\n"
        "            warnings.warn('expected', UserWarning)\n"
        "        except UserWarning:\n"
        "            pass\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_ignores_manual_raise_after_unconditional_return(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    return\n    raise AssertionError('unreachable')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "handler", ["UserWarning", "Warning", "(ValueError, UserWarning)"]
)
def test_security_scan_rejects_warning_swallowed_outside_context(tmp_path, handler):
    (tmp_path / "test_case.py").write_text(
        "import warnings\ndef test_warning():\n"
        "    try:\n        with warnings.catch_warnings():\n"
        "            warnings.simplefilter('error', UserWarning)\n"
        "            warnings.warn('expected', UserWarning)\n"
        f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "hidden_filter",
    [
        "if False:\n            warnings.simplefilter('error')",
        "def configure():\n            warnings.simplefilter('error')",
    ],
)
def test_security_scan_does_not_execute_nested_warning_filter_syntax(
    tmp_path, hidden_filter
):
    (tmp_path / "test_case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        + "\n".join("        " + line for line in hidden_filter.splitlines())
        + "\n        perform()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize("handler", ["Exception", "(AssertionError, ValueError)"])
def test_security_scan_rejects_helper_swallowing_broad_assertion(tmp_path, handler):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_accepts_assertion_reraised_from_handler(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    except Exception:\n        raise\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "imports,handler",
    [
        ("from builtins import BaseException as Ignore\n", "Ignore"),
        ("from builtins import Exception as Ignore\n", "Ignore"),
        ("import builtins as bi\n", "bi.BaseException"),
    ],
)
def test_security_scan_detects_aliased_exception_catch(tmp_path, imports, handler):
    (tmp_path / "test_case.py").write_text(
        imports
        + "def test_behavior():\n"
        + "    try:\n        assert compute() == 4\n"
        + f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "imports,suppress",
    [
        ("from contextlib import suppress as ignore\n", "ignore"),
        ("import contextlib as context\n", "context.suppress"),
    ],
)
def test_security_scan_detects_suppress_context_for_assertion(
    tmp_path, imports, suppress
):
    (tmp_path / "test_case.py").write_text(
        imports
        + "def test_behavior():\n"
        + f"    with {suppress}(AssertionError):\n"
        + "        assert compute() == 4\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_detects_assertion_suppressed_in_finally(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    finally:\n        return None\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_accepts_tuple_handler_with_named_reraise(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    except (AssertionError, ValueError) as error:\n        raise error\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_rejects_assertion_swallowed_by_finally_return(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n"
        "    try:\n        assert actual == expected\n"
        "    except AssertionError:\n"
        "        try:\n            pass\n"
        "        finally:\n            return\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n    assert_expected(compute(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "body",
    [
        "if compute() != 4:\n        raise AssertionError('wrong value')",
        "if not compute():\n        raise AssertionError('empty result')",
    ],
)
def test_security_scan_recognizes_conditional_manual_assertion(tmp_path, body):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    " + body + "\n", encoding="utf-8"
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_finds_hollow_inherited_test_in_helper_module(tmp_path):
    (tmp_path / "base.py").write_text(
        "class SharedCases:\n    def test_inherited(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from base import SharedCases\nclass TestConcreteCases(SharedCases):\n    pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    finding = next(
        item for item in result["findings"] if item["code"] == "QUALITY_HOLLOW_TEST"
    )
    assert finding["path"] == "base.py"
    assert finding["facts"]["symbol"] == "test_inherited"


def test_security_scan_does_not_trust_assertion_caught_in_nested_try(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n"
        "        if condition:\n            assert compute() == 4\n"
        "    except Exception:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_rejects_builtin_exception_alias_and_finally_return(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from builtins import Exception as Ignore\n"
        "def test_alias():\n"
        "    try:\n        assert compute() == 4\n"
        "    except Ignore:\n        pass\n\n"
        "def test_finally():\n"
        "    try:\n        assert compute() == 4\n"
        "    finally:\n        return\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}


def test_security_scan_rejects_contextlib_suppress_and_unreachable_manual_raise(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "from contextlib import suppress\n"
        "def test_suppress():\n"
        "    with suppress(AssertionError):\n        assert compute() == 4\n\n"
        "def test_unreachable():\n"
        "    if False:\n        raise AssertionError('wrong')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 2}


def test_security_scan_does_not_trust_imported_production_function(tmp_path):
    (tmp_path / "library.py").write_text(
        "def render(value):\n    assert value is not None\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from library import render\n"
        "def test_behavior():\n"
        "    render(compute_value())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_imported_noop_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_expected(actual, expected):\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_expected\n"
        "def test_behavior():\n"
        "    assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {
        "QUALITY_HOLLOW_TEST": 1,
        "QUALITY_EMPTY_IMPLEMENTATION": 1,
    }


def test_security_scan_accepts_testcase_mixin_assertions(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "class SharedMixin:\n"
        "    def test_shared(self):\n"
        "        self.assertEqual(compute_value(), 4)\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "import unittest\n"
        "from helpers import SharedMixin\n"
        "class Case(unittest.TestCase, SharedMixin):\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_aliased_indirect_testcase_mixin(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "class SharedMixin:\n"
        "    def test_shared(self):\n"
        "        self.assertEqual(compute_value(), 4)\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "import unittest as ut\n"
        "from helpers import SharedMixin\n"
        "class Base(ut.TestCase):\n"
        "    pass\n"
        "class Case(Base, SharedMixin):\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_resolves_assertion_submodule_imports(tmp_path):
    package = tmp_path / "checks"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "assertions.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from checks import assertions\n"
        "def test_behavior():\n"
        "    assertions.assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_resolves_relative_assertion_submodule_imports(tmp_path):
    package = tmp_path / "suite"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "assertions.py").write_text(
        "def assert_expected(actual, expected):\n    assert actual == expected\n",
        encoding="utf-8",
    )
    (package / "test_case.py").write_text(
        "from . import assertions\n"
        "def test_behavior():\n"
        "    assertions.assert_expected(compute_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_imported_weak_helper(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def assert_present(value):\n    assert value is not None\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from helpers import assert_present\n"
        "def test_behavior():\n"
        "    assert_present(compute_value())\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


def test_security_scan_ignores_performance_benchmark_oracles(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest_codspeed import BenchmarkFixture\n"
        "def test_speed(benchmark: BenchmarkFixture):\n"
        "    benchmark(compute_value)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_call_form_benchmark_marker(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest import mark as marks\n"
        "@marks.benchmark(group='throughput')\n"
        "def test_speed(benchmark):\n"
        "    benchmark(compute_value)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_pedantic_benchmark_fixture(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest_benchmark.fixture import BenchmarkFixture\n"
        "def test_speed(benchmark: BenchmarkFixture):\n"
        "    benchmark.pedantic(compute_value, iterations=5, rounds=2)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_decorator_form_benchmark_with_marker(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import pytest\n"
        "@pytest.mark.benchmark(group='throughput')\n"
        "def test_speed(benchmark):\n"
        "    @benchmark\n"
        "    def run():\n"
        "        compute_value()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_decorator_form_benchmark_with_typed_fixture(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest_benchmark.fixture import BenchmarkFixture\n"
        "def test_speed(benchmark: BenchmarkFixture):\n"
        "    @benchmark\n"
        "    async def run():\n"
        "        await compute_value()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "source",
    [
        # No marker or typed fixture: the untyped parameter alone never exempts.
        "def test_security_invariant(benchmark):\n"
        "    @benchmark\n"
        "    def run():\n"
        "        dangerous_operation()\n",
        # Marked, but the nested decorator is not the benchmark fixture.
        "import pytest\n"
        "@pytest.mark.benchmark\n"
        "def test_security_invariant(benchmark):\n"
        "    @other_decorator\n"
        "    def run():\n"
        "        dangerous_operation()\n",
        # Marked, but the decorator is a call to something that only looks similar.
        "import pytest\n"
        "@pytest.mark.benchmark\n"
        "def test_security_invariant(benchmark):\n"
        "    @benchmarks\n"
        "    def run():\n"
        "        dangerous_operation()\n",
        # Marked, but no fixture parameter exists for the decorator to name.
        "import pytest\n"
        "@pytest.mark.benchmark\n"
        "def test_security_invariant():\n"
        "    @benchmark\n"
        "    def run():\n"
        "        dangerous_operation()\n",
        # Marked and decorated, but the decorated function is never the nested one.
        "import pytest\n"
        "@pytest.mark.benchmark\n"
        "def test_security_invariant(benchmark):\n"
        "    def run():\n"
        "        dangerous_operation()\n",
    ],
)
def test_security_scan_rejects_lookalike_decorator_form_benchmarks(tmp_path, source):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "binding",
    [
        "benchmark = other_decorator",
        "import other_decorator as benchmark",
        "if flag:\n        benchmark = other_decorator",
    ],
)
def test_security_scan_rejects_rebound_benchmark_decorator(tmp_path, binding):
    (tmp_path / "test_case.py").write_text(
        "import pytest\n@pytest.mark.benchmark\ndef test_speed(benchmark):\n"
        f"    {binding}\n    @benchmark\n    def run():\n        compute_value()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize("nested", [False, True])
def test_security_scan_preserves_benchmark_use_before_rebinding(tmp_path, nested):
    body = "    @benchmark\n    def run():\n        compute_value()\n    benchmark = other_decorator\n"
    if nested:
        body = "    if flag:\n" + "".join(
            "    " + line for line in body.splitlines(keepends=True)
        )
    (tmp_path / "test_case.py").write_text(
        "import pytest\n@pytest.mark.benchmark\ndef test_speed(benchmark):\n" + body,
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "body",
    [
        "    scratch: int\n    @benchmark\n    def run():\n        compute_value()\n",
        "    benchmark = benchmark(compute_value)\n",
    ],
)
def test_security_scan_preserves_benchmark_evaluation_order(tmp_path, body):
    (tmp_path / "test_case.py").write_text(
        "import pytest\n@pytest.mark.benchmark\ndef test_speed(benchmark):\n" + body,
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_skip_untyped_benchmark_named_security_test(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_security_invariant(benchmark):\n"
        "    benchmark(lambda: dangerous_operation())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_exempt_untyped_benchmark_parameter_alone(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior(benchmark):\n    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "declaration",
    [
        "def test_security_invariant(benchmark: NotBenchmarkFixture):",
        "@pytest.mark.benchmarking\ndef test_security_invariant(benchmark):",
    ],
)
def test_security_scan_rejects_lookalike_benchmark_signals(tmp_path, declaration):
    (tmp_path / "test_case.py").write_text(
        f"{declaration}\n    benchmark(lambda: dangerous_operation())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "imports",
    [
        "import custom_benchmarks",
        "from pytest_benchmark import plugin",
    ],
)
def test_security_scan_rejects_unrelated_benchmark_imports(tmp_path, imports):
    decorator = (
        "@custom_benchmarks.benchmark()\n"
        if imports.startswith("import custom")
        else ""
    )
    (tmp_path / "test_case.py").write_text(
        f"{imports}\n{decorator}"
        "def test_security_invariant(benchmark):\n"
        "    benchmark(lambda: dangerous_operation())\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_rejects_noop_assertion_named_helper(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def assert_nothing():\n"
        "    pass\n\n"
        "def test_behavior():\n"
        "    assert_nothing()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_local_noop_unittest_named_method(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "class NoOp:\n"
        "    def assertEqual(self, actual, expected):\n"
        "        pass\n\n"
        "def test_behavior():\n"
        "    NoOp().assertEqual(load_value(), 4)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_reports_unittest_non_null_only_oracle(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertIsNotNone(load_value())\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


def test_security_scan_accepts_unittest_isinstance_assertion(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import unittest\n"
        "class Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertIsInstance(load_value(), Result)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_inherited_unittest_case_assertions(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import unittest\n"
        "class ProjectTestCase(unittest.TestCase):\n"
        "    pass\n\n"
        "class Checks(ProjectTestCase):\n"
        "    def test_behavior(self):\n"
        "        self.assertEqual(load_value(), 4)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_ignores_explicitly_skipped_hollow_test(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import pytest\n"
        "@pytest.mark.skip(reason='requires external service')\n"
        "def test_behavior():\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_keeps_strong_oracle_when_weak_assertion_is_also_present(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    assert result is not None\n"
        "    assert result == expected\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_tenant_contract_is_explicit_and_hash_bound(tmp_path):
    path = tmp_path / "service.py"
    path.write_text(
        "async def fetch(record_id):\n    return await store.fetch(record_id)\n"
    )
    assert security_scan(tmp_path)["findings"] == []
    missing = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert missing["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    assert missing["tenant_read_contract"]["calls"] == ["store.fetch"]
    assert missing["tenant_read_contract"]["keyword"] == "tenant_id"
    assert missing["audit_sha256"] != security_scan(tmp_path)["audit_sha256"]
    path.write_text(
        "async def fetch(record_id, tenant_id):\n    return await store.fetch(record_id, tenant_id=tenant_id)\n"
    )
    assert security_scan(tmp_path, tenant_read_calls=("store.fetch",))["findings"] == []
    path.write_text(
        "def fetch(record_id):\n    return store.fetch(record_id, tenant_id=record_id)\n"
    )
    assert (
        security_scan(tmp_path, tenant_read_calls=("store.fetch",))["state"]
        == "BLOCKED"
    )


def test_security_scan_rejects_invalid_tenant_contract(tmp_path):
    with pytest.raises(ReviewAuditError, match="qualified"):
        security_scan(tmp_path, tenant_read_calls=("invalid.call()",))


@pytest.mark.parametrize(
    ("source", "binding"),
    [
        (
            "async def fetch(record_id, org_scope):\n"
            "    return await store.fetch(record_id, tenant_id=org_scope)\n",
            "store.fetch=keyword:tenant_id:org_scope",
        ),
        (
            "def fetch(record_id, workspace_key):\n"
            "    return store.fetch(record_id, workspace_key)\n",
            "store.fetch=position:1:workspace_key",
        ),
    ],
)
def test_security_scan_accepts_declared_tenant_argument_bindings(
    tmp_path, source, binding
):
    (tmp_path / "service.py").write_text(source, encoding="utf-8")
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=(binding,),
    )
    assert result["state"] == "CLEAN"
    assert result["tenant_read_contract"]["argument_bindings"] == {
        "store.fetch": [binding.split("=", 1)[1]]
    }


def test_security_scan_accepts_tenant_parameter_copied_to_local_alias(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["state"] == "CLEAN"


def test_security_scan_rejects_tenant_alias_rebound_before_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    scope = request.args['tenant']\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_tenant_alias_shadowed_by_match_capture(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id, event):\n"
        "    scope = tenant_id\n"
        "    match event:\n"
        "        case {'scope': scope}:\n"
        "            pass\n"
        "    return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_tenant_alias_shadowed_by_exception_capture(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, tenant_id):\n"
        "    scope = tenant_id\n"
        "    try:\n"
        "        risky_operation()\n"
        "    except ValueError as scope:\n"
        "        return store.fetch(record_id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, tenant_read_calls=("store.fetch",))
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_blocks_uncontracted_sqlalchemy_reads(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def fetch_user(user_id):\n"
        "    return session.query(User).filter_by(id=user_id).first()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_blocks_uncontracted_django_exclude_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "from django.db import models\n"
        "def list_users():\n"
        "    return User.objects.exclude(is_active=False)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_blocks_uncontracted_sqlmodel_exec_read(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlmodel import Session, select\n"
        "def list_users(session: Session):\n"
        "    return session.exec(select(User))\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["state"] == "BLOCKED"
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] >= 1


def test_security_scan_rejects_declared_binding_to_wrong_function_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, workspace_key):\n"
        "    return store.fetch(record_id, record_id)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:1:workspace_key",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_rebound_tenant_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, org_scope):\n"
        "    org_scope = 'another-tenant'\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:org_scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


@pytest.mark.parametrize(
    "comprehension",
    [
        "[scope for scope in ids]",
        "{scope for scope in ids}",
        "{scope: value for scope, value in pairs}",
        "(scope for scope in ids)",
    ],
)
def test_security_scan_allows_comprehension_target_shadowing(tmp_path, comprehension):
    (tmp_path / "service.py").write_text(
        "def fetch(scope, ids):\n"
        f"    cached = {comprehension}\n"
        "    return store.fetch(id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:scope",),
    )
    assert result["state"] == "CLEAN"


def test_security_scan_rejects_outer_parameter_rebound_by_comprehension_walrus(
    tmp_path,
):
    (tmp_path / "service.py").write_text(
        "def fetch(scope, ids):\n"
        "    cached = [scope := value for value in ids]\n"
        "    return store.fetch(id, tenant_id=scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=keyword:tenant_id:scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_multiple_bindings_for_one_read_call(tmp_path):
    with pytest.raises(ReviewAuditError, match="only one tenant argument binding"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=(
                "store.fetch=position:1:workspace_key",
                "store.fetch=position:0:record_id",
            ),
        )


def test_security_scan_rejects_optional_tenant_parameter(tmp_path):
    (tmp_path / "service.py").write_text(
        "def fetch(record_id, org_scope=None):\n"
        "    return store.fetch(record_id, org_scope)\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:1:org_scope",),
    )
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}


def test_security_scan_rejects_unlisted_or_malformed_tenant_binding(tmp_path):
    with pytest.raises(ReviewAuditError, match="declared qualified read call"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=("db.get=position:1:tenant_id",),
        )
    with pytest.raises(ReviewAuditError, match="position:INDEX:PARAMETER"):
        security_scan(
            tmp_path,
            tenant_read_calls=("store.fetch",),
            tenant_read_bindings=("store.fetch=position:tenant_id",),
        )


def test_security_scan_keeps_negative_callback_and_import_alias_controls(tmp_path):
    path = tmp_path / "test_controls.py"
    path.write_text(
        "from pytest import raises as expect_error\n"
        "def test_error():\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n"
        "def test_no_read(monkeypatch):\n"
        "    def fail_on_read(*args):\n"
        "        raise AssertionError('unexpected read')\n"
        "    monkeypatch.setattr(store, 'fetch', fail_on_read)\n"
        "    compute()\n"
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["findings"][0]["facts"]["symbol"] == "test_no_read"


def test_security_scan_accepts_test_scoped_pytest_raises_import(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_expected_error():\n"
        "    from pytest import raises as expect_error\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_restores_module_alias_after_later_pytest_import(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import contextlib\n"
        "raises = contextlib.nullcontext\n"
        "from pytest import raises\n"
        "def test_expected_error():\n"
        "    with raises(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_restores_local_alias_after_later_pytest_import(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from contextlib import nullcontext as expect_error\n"
        "def test_expected_error():\n"
        "    expect_error = nullcontext\n"
        "    from pytest import raises as expect_error\n"
        "    with expect_error(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_helper_with_rebound_assertion_alias(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "def assert_expected():\n"
        "    expect_error = contextlib.nullcontext\n"
        "    with expect_error(ValueError):\n"
        "        pass\n"
        "def test_behavior():\n"
        "    assert_expected()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_keeps_pytest_alias_across_nested_local_bindings(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises\n"
        "def test_expected_error():\n"
        "    def helper():\n"
        "        raises = None\n"
        "    values = [raises() for raises in callables]\n"
        "    with raises(ValueError):\n"
        "        compute()\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_does_not_trust_assertion_alias_call_inside_comprehension(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises\n"
        "def test_behavior():\n"
        "    results = [raises(ValueError) for raises in factories]\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_rebound_pytest_raises_alias(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "def test_behavior():\n"
        "    expect_error = contextlib.nullcontext\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_module_rebound_pytest_alias(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises as expect_error\n"
        "import contextlib\n"
        "expect_error = contextlib.nullcontext\n"
        "def test_behavior():\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_imports_from_other_scopes(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from contextlib import nullcontext as expect_error\n"
        "def unrelated():\n"
        "    from pytest import raises as expect_error\n"
        "def test_behavior():\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_invalidates_oracle_alias_after_module_star_import(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "from contextlib import nullcontext as raises\n", encoding="utf-8"
    )
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises\n"
        "from helpers import *\n"
        "def test_behavior():\n"
        "    with raises(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_invalidates_oracle_alias_after_branch_star_import(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "from contextlib import nullcontext as raises\n", encoding="utf-8"
    )
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises\n"
        "if USE_HELPERS:\n"
        "    from helpers import *\n"
        "def test_behavior():\n"
        "    with raises(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "binding",
    [
        "try:\n    compute_value()\nexcept Exception as expect_error:\n    pass",
        "match event:\n    case {'error': expect_error}:\n        pass",
    ],
)
def test_security_scan_does_not_trust_captured_pytest_raises_alias(tmp_path, binding):
    (tmp_path / "test_case.py").write_text(
        "from pytest import raises as expect_error\n"
        "def test_behavior(event):\n"
        f"    {binding.replace(chr(10), chr(10) + '    ')}\n"
        "    with expect_error(ValueError):\n"
        "        pass\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_does_not_trust_unused_assertion_callback(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    def fail_on_read(*args):\n"
        "        raise AssertionError('unexpected read')\n"
        "    compute_value()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_cli_applies_explicit_tenant_contract(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "def fetch(record_id):\n    return store.fetch(record_id)\n"
    )
    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 1
    missing_contract = json.loads(capsys.readouterr().out)
    assert missing_contract["state"] == "INCOMPLETE"
    assert missing_contract["tenant_read_contract"]["configuration"]["state"] == (
        "missing"
    )
    assert "Tenant isolation remains unassessed" in missing_contract["action_summary"]
    assert (
        main(
            [
                "audit",
                "security",
                "--root",
                str(tmp_path),
                "--tenant-read-call",
                "store.fetch",
                "--json",
            ]
        )
        == 2
    )
    result = json.loads(capsys.readouterr().out)
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "def fetch(record_id, organization_scope):\n"
        "    return store.fetch(record_id, organization_scope)\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "audit",
                "security",
                "--root",
                str(tmp_path),
                "--tenant-read-call",
                "store.fetch",
                "--tenant-read-binding",
                "store.fetch=position:1:organization_scope",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["state"] == "CLEAN"


def test_security_cli_loads_project_contract_for_original_tenant_cases(
    tmp_path, capsys
):
    factory_dir = tmp_path / ".factory"
    factory_dir.mkdir()
    contract_path = factory_dir / "tenant-read-contract.json"
    contract_path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [
                    {
                        "call": "store.fetch",
                        "binding": "keyword:tenant_id:org_scope",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    source_path = tmp_path / "app.py"
    source_path.write_text(
        "def unscoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=record_id)\n\n"
        "def scoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )

    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["finding_counts"] == {"SECURITY_MISSING_TENANT_ISOLATION": 1}
    assert result["tenant_read_contract"]["configuration"]["state"] == "loaded"
    assert result["tenant_read_contract"]["configuration"]["sha256"]

    source_path.write_text(
        "def unscoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n\n"
        "def scoped(record_id, org_scope):\n"
        "    return store.fetch(record_id, tenant_id=org_scope)\n",
        encoding="utf-8",
    )
    assert main(["audit", "security", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "CLEAN"
    assert result["tenant_read_contract"]["configuration"]["path"] == (
        ".factory/tenant-read-contract.json"
    )


def test_tenant_read_contract_rejects_unknown_fields_and_duplicate_calls(tmp_path):
    folder = tmp_path / ".factory"
    folder.mkdir()
    path = folder / "tenant-read-contract.json"
    path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [{"call": "store.fetch", "extra": True}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="Each tenant read requires"):
        load_tenant_read_contract(tmp_path)

    path.write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v1",
                "reads": [
                    {"call": "store.fetch"},
                    {"call": "store.fetch"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="calls must be unique"):
        load_tenant_read_contract(tmp_path)


def test_security_evals_cli_reports_fail_closed_contract(tmp_path, capsys):
    assert main(["audit", "evals", "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "PASS"
    assert result["claim_boundary"].startswith("Fixed local AST evaluation")


def test_no_policy_is_not_a_pass_and_invalid_policy_fails_closed(tmp_path, capsys):
    assert (
        review_change(tmp_path, changed=["app.py"])["code_audits"]["state"]
        == "not_configured"
    )
    assert main(["audit", "all", "--root", str(tmp_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["state"] == "invalid"
    path = workspace(tmp_path)
    path.write_text("{}")
    with pytest.raises(ChangeReviewError):
        review_change(tmp_path, changed=["app.py"])


def test_evidence_race_rejected(tmp_path, monkeypatch):
    import factoryline.review_audits as module

    workspace(tmp_path)
    original = module._patterns

    def mutate(*args):
        result = original(*args)
        (tmp_path / "app.py").write_text("# changed during audit")
        return result

    monkeypatch.setattr(module, "_patterns", mutate)
    with pytest.raises(ReviewAuditError, match="Evidence changed"):
        audit_code(tmp_path)


def test_malformed_and_oversized_source(tmp_path):
    workspace(tmp_path)
    for source in ["def (", "x" * 1_000_001]:
        (tmp_path / "app.py").write_text(source)
        with pytest.raises(ReviewAuditError):
            audit_code(tmp_path)


def test_documented_example_is_executable(tmp_path):
    import re

    doc = (
        Path(__file__).resolve().parents[1] / "docs/CODE_REVIEW_AUDITS.md"
    ).read_text(encoding="utf-8")
    (tmp_path / "app.py").write_text(
        re.search(r"```python\n(.*?)```", doc, re.S)[1], encoding="utf-8"
    )
    (tmp_path / "policy.json").write_text(
        re.search(r"```json\n(.*?)```", doc, re.S)[1], encoding="utf-8"
    )
    result = audit_code(tmp_path, "policy.json")
    assert result["results"][0]["state"] == "no_structural_findings"
    assert result["findings"][0]["code"] == "GUARD_PATH_BYPASS"


def test_duplicate_json_fields_rejected(tmp_path):
    path = workspace(tmp_path)
    path.write_text(
        path.read_text().replace(
            '"origin": "human_confirmed"',
            '"origin": "human_confirmed", "origin": "agent_proposed"',
        )
    )
    with pytest.raises(ReviewAuditError, match="Duplicate JSON"):
        audit_code(tmp_path)


def test_duplicate_peer_alias_rejected(tmp_path):
    path = workspace(tmp_path)
    policy = json.loads(path.read_text())
    policy["pattern_groups"][0]["members"][1] = {"path": "./app.py", "symbol": "safe"}
    path.write_text(json.dumps(policy))
    with pytest.raises(ReviewAuditError, match="Duplicate peer"):
        audit_code(tmp_path)


def test_async_guard_and_effect(tmp_path):
    workspace(tmp_path, "await require_auth()\nawait store.delete()")
    source = tmp_path / "app.py"
    source.write_text(
        source.read_text().replace("def candidate", "async def candidate")
    )
    assert audit_code(tmp_path)["state"] == "no_structural_findings"


def test_dynamic_execution_is_incomplete(tmp_path):
    workspace(tmp_path, "require_auth()\nexec(payload)\nstore.delete()")
    assert audit_code(tmp_path)["state"] == "incomplete"


def test_github_delivery_preserves_findings_and_rejects_tampering(tmp_path):
    from factoryline.github_proof_review import (
        GitHubProofReviewError,
        render_github_proof_review,
    )

    workspace(tmp_path, "store.delete()")
    review = review_change(tmp_path, changed=["app.py"])
    payload = render_github_proof_review(review, "a" * 40)
    assert payload["check"]["conclusion"] == "neutral"
    assert "GUARD_PATH_BYPASS" in payload["github_comment"]
    review["code_audits"]["authority"]["approval"] = True
    with pytest.raises(GitHubProofReviewError):
        render_github_proof_review(review, "a" * 40)


def test_expressions_do_not_treat_argument_guards_as_prior_authorization(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths, _Path

    policy = json.loads(workspace(tmp_path).read_text())
    rule = policy["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    engine.expressions(ast.parse("store.delete(require_auth())").body[0], [_Path()])
    assert engine.findings[0]["code"] == "GUARD_PATH_BYPASS"
    assert engine.effects == 1


def test_simple_statement_checks_effect_arguments_before_guard(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths, _Path

    rule = json.loads(workspace(tmp_path).read_text())["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    paths = engine.simple_statement(
        ast.parse("require_auth(store.delete())").body[0], [_Path()]
    )
    assert paths[0].guarded is True
    assert len(engine.findings) == 1  # invocation arguments run before the guard


def test_rebinds_identity_distinguishes_local_data_from_guard_alias_changes(tmp_path):
    import ast
    from factoryline.review_audits import _GuardPaths

    rule = json.loads(workspace(tmp_path).read_text())["effect_rules"][0]
    engine = _GuardPaths(rule, rule["target"])
    assert engine.rebinds_identity(ast.parse("require_auth = noop").body[0])
    assert engine.rebinds_identity(ast.parse("store.delete = noop").body[0])
    assert not engine.rebinds_identity(ast.parse("count = 4").body[0])
    assert not engine.rebinds_identity(ast.parse("require_auth()").body[0])


@pytest.mark.parametrize(
    "body",
    [
        "errors = []; errors.append(compute()); assert errors == []",
        "errors = []; alias = errors; alias.append(compute()); assert errors == []",
        "errors = []\n    for item in inputs:\n        errors.append(item)\n    assert errors == []",
        "errors = []; mutate(errors); assert errors == []",
    ],
)
def test_mutable_test_state_is_not_folded_across_calls(tmp_path, body):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    assert security_scan(tmp_path)["findings"] == []


def test_unmodified_container_constant_assertion_remains_hollow(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    errors = []\n    assert errors == []\n"
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize("nested", ["def", "async def"])
def test_security_scan_does_not_collect_nested_test_named_helper(tmp_path, nested):
    (tmp_path / "test_case.py").write_text(
        f"def test_behavior():\n    {nested} test_prompt():\n        pass\n"
        "    assert compute() == 4\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "invoke, assertion, expected",
    [
        ("runner.invoke(cli, catch_exceptions=False)", "assert compute() == 4", {}),
        ("runner.invoke(cli)", "assert compute() == 4", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "runner.invoke(cli, catch_exceptions=True)",
            "assert compute() == 4",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=False)",
            "assert True",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=False)",
            "assert compute() is not None",
            {"QUALITY_WEAK_TEST_ORACLE": 1},
        ),
        ("pass", "assert compute() == 4", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "runner.invoke(other, catch_exceptions=False)",
            "assert compute() == 4",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=False)\n    assert result.output == 'expected'",
            "assert compute() == 4",
            {},
        ),
    ],
)
def test_security_scan_follows_only_invoked_noncatching_click_callback(
    tmp_path, invoke, assertion, expected
):
    (tmp_path / "test_case.py").write_text(
        "import click\nfrom click.testing import CliRunner\ndef test_behavior():\n"
        "    @click.command()\n    def cli():\n        " + assertion + "\n"
        "    runner = CliRunner()\n    " + invoke + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize(
    "body",
    [
        "try:\n        runner.invoke(cli, catch_exceptions=False)\n    except AssertionError:\n        pass",
        "with suppress(AssertionError):\n        runner.invoke(cli, catch_exceptions=False)",
        "with suppress(Exception):\n        runner.invoke(cli, catch_exceptions=False)",
        "if False:\n        runner.invoke(cli, catch_exceptions=False)",
        "return\n    runner.invoke(cli, catch_exceptions=False)",
        "runner = fake_runner\n    runner.invoke(cli, catch_exceptions=False)",
        "runner.invoke = swallow\n    runner.invoke(cli, catch_exceptions=False)",
        "setattr(runner, 'invoke', swallow)\n    runner.invoke(cli, catch_exceptions=False)",
        "configure(runner)\n    runner.invoke(cli, catch_exceptions=False)",
        "other = runner\n    other.invoke = swallow\n    runner.invoke(cli, catch_exceptions=False)",
        "cli = other\n    runner.invoke(cli, catch_exceptions=False)",
    ],
)
def test_security_scan_keeps_swallowed_or_rebound_click_callback_hollow(tmp_path, body):
    (tmp_path / "test_case.py").write_text(
        "import click\nfrom click.testing import CliRunner\n"
        "from contextlib import suppress\ndef test_behavior():\n"
        "    @click.command()\n    def cli():\n        assert compute() == 4\n"
        "    runner = CliRunner()\n    " + body + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "decorators, assertion",
    [
        ("@click.command()\n    @swallow", "assert compute() == 4"),
        ("@click.command(cls=CustomCommand)", "assert compute() == 4"),
        (
            "@click.command()",
            "try:\n            assert compute() == 4\n        except AssertionError:\n            pass",
        ),
        ("@click.command()", "expected = True\n        assert expected"),
        ("@click.command()", "raise click.ClickException('oops')"),
        ("@click.command()", "raise click.Abort()"),
        ("@click.command()", "raise SystemExit(1)"),
        ("@click.command()", "with contextlib.nullcontext():\n            pass"),
    ],
)
def test_security_scan_rejects_unproven_click_callback_propagation(
    tmp_path, decorators, assertion
):
    (tmp_path / "test_case.py").write_text(
        "import click\nimport contextlib\nfrom click.testing import CliRunner\ndef test_behavior():\n    "
        + decorators
        + "\n    def cli():\n        "
        + assertion
        + "\n"
        "    runner = CliRunner()\n    runner.invoke(cli, catch_exceptions=False)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "oracle",
    [
        "if compute() != 4:\n            raise AssertionError('wrong outcome')",
        "with pytest.raises(ValueError):\n            compute()",
    ],
)
def test_security_scan_keeps_escaping_click_callback_failure_oracles(tmp_path, oracle):
    (tmp_path / "test_case.py").write_text(
        "import click\nimport pytest\nfrom click.testing import CliRunner\n"
        "def test_behavior():\n    @click.command()\n    def cli():\n        "
        + oracle
        + "\n    runner = CliRunner()\n"
        "    runner.invoke(cli, catch_exceptions=False)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "fixture_body, expected",
    [
        ("return CliRunner()", {}),
        ("return fake_runner", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "if arbitrary():\n        return fake_runner\n    return CliRunner()",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_security_scan_binds_click_runner_fixture_source(
    tmp_path, fixture_body, expected
):
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom click.testing import CliRunner\n"
        "@pytest.fixture\ndef runner():\n    " + fixture_body + "\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "import click\ndef test_behavior(runner):\n"
        "    @click.command()\n    def cli():\n        assert compute() == 4\n"
        "    runner.invoke(cli, catch_exceptions=False)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


def test_security_scan_nearer_fixture_override_invalidates_click_runner(tmp_path):
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom click.testing import CliRunner\n"
        "@pytest.fixture\ndef runner():\n    return CliRunner()\n",
        encoding="utf-8",
    )
    suite = tmp_path / "nested"
    suite.mkdir()
    (suite / "conftest.py").write_text(
        "import pytest\n@pytest.fixture\ndef runner():\n    return fake_runner\n",
        encoding="utf-8",
    )
    (suite / "test_case.py").write_text(
        "import click\ndef test_behavior(runner):\n"
        "    @click.command()\n    def cli():\n        assert compute() == 4\n"
        "    runner.invoke(cli, catch_exceptions=False)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_keeps_uninvoked_command_with_recursive_invoke_hollow(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import click\nfrom click.testing import CliRunner\ndef test_behavior():\n"
        "    runner = CliRunner()\n    @click.command()\n    def cli():\n"
        "        result = runner.invoke(cli, catch_exceptions=False)\n"
        "        assert result.output == 'value'\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "filename, declared, body, expected",
    [
        ("typing_probe.py", True, "assert_type(compute(), int)", {}),
        (
            "typing_probe.py",
            False,
            "assert_type(compute(), int)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "test_runtime.py",
            True,
            "assert_type(compute(), int)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        ("typing_probe.py", True, "compute()", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "typing_probe.py",
            True,
            "assert_type = lambda *args: None\n    assert_type(compute(), int)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_security_scan_recognizes_individual_declared_static_type_oracle(
    tmp_path, filename, declared, body, expected
):
    (tmp_path / "typing").mkdir()
    if declared:
        (tmp_path / "pyproject.toml").write_text('[tool.mypy]\nfiles = ["typing"]\n')
    (tmp_path / "typing" / filename).write_text(
        "from typing_extensions import assert_type\ndef test_type():\n    "
        + body
        + "\n"
        "def test_runtime_without_oracle():\n    compute()\n",
        encoding="utf-8",
    )
    if filename == "typing_probe.py":
        (tmp_path / "pytest.ini").write_text(
            "[pytest]\npython_files = typing_probe.py\n", encoding="utf-8"
        )
    result = security_scan(tmp_path)
    counts = dict(expected)
    counts["QUALITY_HOLLOW_TEST"] = counts.get("QUALITY_HOLLOW_TEST", 0) + 1
    assert result["finding_counts"] == counts
    if declared and filename == "typing_probe.py":
        edge = next(
            item
            for item in result["oracle_context"]["resolved_edges"]
            if item["kind"] == "static_type_configuration"
        )
        assert edge["target"] == "pyproject.toml"
        assert len(edge["sha256"]) == 64


@pytest.mark.parametrize(
    "body, expected",
    [
        ("class Custom(base):\n            pass", {}),
        ("class Custom:\n            pass", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "warnings.simplefilter('ignore')\n        class Custom(base):\n            pass",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "return\n        class Custom(base):\n            pass",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_security_scan_recognizes_warning_policy_during_class_construction(
    tmp_path, body, expected
):
    (tmp_path / "test_case.py").write_text(
        "import warnings\ndef test_silent(base):\n    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', DeprecationWarning)\n        "
        + body
        + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize(
    ("config", "collection_error"),
    [
        ('[tool.mypy]\nfiles = ["../typing"]\n', False),
        ('[tool.mypy]\nfiles = "typing"\n', False),
        ("broken = [\n", True),
        ("#" * 1_000_001, True),
    ],
    ids=["escaping-root", "wrong-type", "malformed", "oversized"],
)
def test_security_scan_does_not_trust_invalid_typecheck_configuration(
    tmp_path, config, collection_error
):
    (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    (tmp_path / "test_typing_probe.py").write_text(
        "from typing_extensions import assert_type\ndef test_type():\n"
        "    assert_type(compute(), int)\n",
        encoding="utf-8",
    )
    if collection_error:
        from factoryline.review_audits import ReviewAuditError

        with pytest.raises(ReviewAuditError, match="pytest test collection"):
            security_scan(tmp_path)
    else:
        assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


def test_security_scan_rejects_typecheck_configuration_race(tmp_path, monkeypatch):
    import factoryline.review_audits as module

    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.mypy]\nfiles = ["typing_probe.py"]\n', encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = typing_probe.py\n", encoding="utf-8"
    )
    (tmp_path / "typing_probe.py").write_text(
        "from typing_extensions import assert_type\ndef test_type():\n"
        "    assert_type(compute(), int)\n",
        encoding="utf-8",
    )
    original = module._security_scan_file

    def mutate_after_read(*args):
        result = original(*args)
        config.write_text("[tool.mypy]\nfiles = []\n", encoding="utf-8")
        return result

    monkeypatch.setattr(module, "_security_scan_file", mutate_after_read)
    with pytest.raises(ReviewAuditError, match="Evidence changed.*pyproject.toml"):
        security_scan(tmp_path)


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_security_scan_rejects_source_change_after_oracle_context_projection(
    tmp_path, monkeypatch, cache_enabled
):
    import factoryline.review_audits as module

    source = tmp_path / "app.py"
    source.write_text("def run(value):\n    return value\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    if cache_enabled:
        security_scan(tmp_path, cache_enabled=True)
    original = module._security_scan_file

    def mutate_after_scan(*args, **kwargs):
        result = original(*args, **kwargs)
        source.write_text("def run(value):\n    eval(value)\n", encoding="utf-8")
        return result

    monkeypatch.setattr(module, "_security_scan_file", mutate_after_scan)
    with pytest.raises(ReviewAuditError, match="Evidence changed.*app.py"):
        security_scan(tmp_path, cache_enabled=cache_enabled)


@pytest.mark.parametrize(
    "before,argument,expected",
    [
        ("", "principal.tenant_id", False),
        ("scope = principal.tenant_id", "scope", False),
        ("alias = principal", "alias.tenant_id", False),
        ("principal = other", "principal.tenant_id", True),
        ("principal.tenant_id = other", "principal.tenant_id", True),
        ("alias = principal\nalias.tenant_id = other", "principal.tenant_id", True),
        ("if ready:\n    principal = other", "principal.tenant_id", True),
        ("if ready:\n    principal.tenant_id = other", "principal.tenant_id", True),
        ("setattr(principal, 'tenant_id', other)", "principal.tenant_id", True),
        ("principal.tenant_id[0] = other", "principal.tenant_id", True),
        (
            "alias = principal\nsetattr(alias, 'tenant_id', other)",
            "principal.tenant_id",
            True,
        ),
        ("", "other.tenant_id", True),
        ("", "principal.organization_id", True),
        ("", "principal.tenant_id()", True),
        ("", "principal[tenant_id]", True),
    ],
)
def test_tenant_attribute_binding_rejects_rebinding_and_wrong_scope(
    tmp_path, before, argument, expected
):
    body = "\n".join("    " + line for line in before.splitlines())
    (tmp_path / "app.py").write_text(
        f"def read(principal, other, ready):\n{body}\n    return store.fetch({argument})\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_read_bindings=("store.fetch=position:0:principal.tenant_id",),
    )
    assert bool(result["findings"]) is expected
    assert all(
        item["code"] == "SECURITY_MISSING_TENANT_ISOLATION"
        for item in result["findings"]
    )


def test_scoped_tenant_contract_keeps_other_files_in_security_scan(tmp_path):
    from factoryline.review_audits import load_tenant_read_contract

    (tmp_path / "app.py").write_text(
        "def read(principal):\n    return store.fetch(principal.tenant_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "test_other.py").write_text(
        "def test_hollow():\n    assert True\n", encoding="utf-8"
    )
    path = tmp_path / ".factory"
    path.mkdir()
    (path / "tenant-read-contract.json").write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v2",
                "reads": [
                    {
                        "path": "app.py",
                        "reads": [
                            {
                                "call": "store.fetch",
                                "binding": "position:0:principal.tenant_id",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    calls, bindings, evidence = load_tenant_read_contract(tmp_path)
    result = security_scan(
        tmp_path,
        tenant_read_calls=calls,
        tenant_read_bindings=bindings,
        tenant_read_scopes=evidence["scoped_reads"],
    )
    assert result["files_scanned"] == 2
    assert [item["code"] for item in result["findings"]] == ["QUALITY_HOLLOW_TEST"]
    assert evidence["state"] == "loaded"


@pytest.mark.parametrize(
    "path,call", [("missing.py", "store.fetch"), ("app.py", "store.typo")]
)
def test_scoped_tenant_contract_rejects_missing_source_or_read(tmp_path, path, call):
    from factoryline.review_audits import load_tenant_read_contract

    (tmp_path / "app.py").write_text(
        "def read(tenant_id):\n    return store.fetch(tenant_id)\n", encoding="utf-8"
    )
    folder = tmp_path / ".factory"
    folder.mkdir()
    (folder / "tenant-read-contract.json").write_text(
        json.dumps(
            {
                "schema": "factory.tenant-read-contract.v2",
                "reads": [
                    {
                        "path": path,
                        "reads": [{"call": call, "binding": "position:0:tenant_id"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="unique existing|absent from"):
        load_tenant_read_contract(tmp_path)


@pytest.mark.parametrize(
    "body,eligible",
    [
        ("validate(5)", True),
        ("pass", False),
        ("validate(5)\n    assert True", False),
        (
            "try:\n        assert result == 4\n    except AssertionError:\n        pass",
            False,
        ),
        ("def helper():\n        assert compute() == 4", False),
    ],
)
def test_runtime_oracle_eligibility_does_not_weaken_static_scan(
    tmp_path, body, eligible
):
    (tmp_path / "test_app.py").write_text(
        "def test_validate():\n    " + body + "\n", encoding="utf-8"
    )
    result = security_scan(tmp_path)
    finding = next(
        item for item in result["findings"] if item["code"] == "QUALITY_HOLLOW_TEST"
    )
    import ast
    from factoryline.review_audits import _completion_only_oracle

    node = ast.parse("def test_validate():\n    " + body + "\n").body[0]
    assert _completion_only_oracle(node) is eligible
    assert finding["facts"]["runtime_oracle_eligible"] is eligible
    assert result["state"] == "FINDINGS"


def _runtime_oracle_scan_fixture(tmp_path):
    from hashlib import sha256
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text(
        "def validate(value):\n    return value\n", encoding="utf-8"
    )
    (tmp_path / "test_app.py").write_text(
        "from app import validate\ndef test_validate():\n    validate(5)\n",
        encoding="utf-8",
    )
    (tmp_path / "oracle.json").write_text("{}", encoding="utf-8")
    (tmp_path / "trust.json").write_text("{}", encoding="utf-8")
    row = {
        "path": "test_app.py",
        "line": 2,
        "symbol": "test_validate",
        "test_sha256": sha256((tmp_path / "test_app.py").read_bytes()).hexdigest(),
        "baseline": {
            "status": "PASS",
            "phase": "call",
            "collection_complete": True,
            "case_ids": ["test_app.py::test_validate"],
            "report_sha256": "a" * 64,
        },
        "mutation": {
            "source_path": "app.py",
            "source_sha256": sha256((tmp_path / "app.py").read_bytes()).hexdigest(),
            "mutant_sha256": "b" * 64,
            "status": "FAIL",
            "phase": "call",
            "case_ids": ["test_app.py::test_validate"],
            "failure_kind": "exception",
            "report_sha256": "c" * 64,
        },
    }
    kwargs = {
        "oracle_evidence": "oracle.json",
        "oracle_trust_root": "trust.json",
        "oracle_trust_sha256": "d" * 64,
        "oracle_environment_sha256": "e" * 64,
    }
    return module, row, kwargs


def test_scan_reconciles_bound_completion_oracle_and_retains_static_history(
    tmp_path, monkeypatch
):
    import factoryline.runtime_attestation as attestation

    module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    initial = security_scan(tmp_path)

    def verified(*args, **values):
        assert values["source_manifest_sha256"] == initial["source_manifest_sha256"]
        assert values["environment_sha256"] == "e" * 64
        return {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA,
            "state": "VERIFIED",
            "tests": [row],
            "receipt_sha256": "f" * 64,
        }

    monkeypatch.setattr(attestation, "verify_signed_test_oracles", verified)
    module._oracle_bound_row(
        tmp_path, row, {item["path"]: item["sha256"] for item in initial["sources"]}
    )
    result = security_scan(tmp_path, **kwargs)
    replay = module._reconcile_runtime_oracles(
        tmp_path, initial.copy(), tuple(kwargs.values())
    )
    assert replay == result
    assert result["state"] == "CLEAN" and result["findings"] == []
    assert (
        result["runtime_oracles"]["reconciled"][0]["static_finding"]
        == initial["findings"][0]
    )
    assert result["runtime_oracles"]["reconciled_count"] == 1
    assert result["candidate_sha256"] == initial["candidate_sha256"]
    assert (
        result["audit_sha256"]
        == module._seal_security_scan(result.copy())["audit_sha256"]
    )


@pytest.mark.parametrize("change", ["test_hash", "source_hash", "line", "class"])
def test_scan_rejects_misbound_runtime_oracle(tmp_path, monkeypatch, change):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    if change == "test_hash":
        row["test_sha256"] = "0" * 64
    elif change == "source_hash":
        row["mutation"]["source_sha256"] = "0" * 64
    elif change == "line":
        row["line"] = 1
    else:
        row["baseline"]["case_ids"] = ["test_app.py::OtherClass::test_validate"]
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {"tests": [row]},
    )
    with pytest.raises(ReviewAuditError, match="Runtime oracle evidence rejected"):
        security_scan(tmp_path, **kwargs)


def test_scan_keeps_constant_assertion_despite_runtime_receipt(tmp_path, monkeypatch):
    from hashlib import sha256
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    (tmp_path / "test_app.py").write_text(
        "from app import validate\ndef test_validate():\n    validate(5)\n    assert True\n",
        encoding="utf-8",
    )
    row["test_sha256"] = sha256((tmp_path / "test_app.py").read_bytes()).hexdigest()
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {"tests": [row]},
    )
    result = security_scan(tmp_path, **kwargs)
    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0


def test_scan_keeps_parameterized_test_without_full_collection_catalog(
    tmp_path, monkeypatch
):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    (tmp_path / "test_app.py").write_text(
        "import pytest\nfrom app import validate\n"
        "@pytest.mark.parametrize('value', [1, 2])\n"
        "def test_validate(value):\n    validate(value)\n",
        encoding="utf-8",
    )
    row["line"] = 4
    row["test_sha256"] = hashlib.sha256(
        (tmp_path / "test_app.py").read_bytes()
    ).hexdigest()
    for run in ("baseline", "mutation"):
        row[run]["case_ids"] = ["test_app.py::test_validate[1]"]
    monkeypatch.setattr(
        attestation, "verify_signed_test_oracles", lambda *a, **k: {"tests": [row]}
    )
    result = security_scan(tmp_path, **kwargs)
    assert result["finding_counts"]["QUALITY_HOLLOW_TEST"] == 1
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert result["findings"][0]["facts"]["runtime_case_coverage"]["eligible"] is False


@pytest.mark.parametrize("complete", [True, False])
def test_scan_applies_v3_callback_coverage_without_clearing_partial_cases(
    tmp_path, monkeypatch, complete
):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    source = (
        "from app import validate\ndef test_validate():\n"
        "    def callback():\n        assert observed == expected\n"
        "    validate(callback)\n"
    )
    (tmp_path / "test_app.py").write_text(source, encoding="utf-8")
    row["test_sha256"] = hashlib.sha256(
        (tmp_path / "test_app.py").read_bytes()
    ).hexdigest()
    selected = ["test_app.py::test_validate[a]"]
    if complete:
        selected.append("test_app.py::test_validate[b]")
    catalog = {
        "status": "PASS",
        "phase": "collection",
        "complete": True,
        "scope": "test_function",
        "source_path": row["path"],
        "source_sha256": row["test_sha256"],
        "config_manifest": [],
        "config_identity": "pytest-default",
        "case_ids": ["test_app.py::test_validate[a]", "test_app.py::test_validate[b]"],
    }
    for phase in ("baseline", "mutation"):
        run = row[phase]
        run.update(
            case_ids=selected,
            collection_catalog=catalog,
            setup_status="PASS",
            teardown_status="PASS",
        )
        run["module_origins"] = [
            {
                "case_id": case,
                "source_path": path,
                "source_sha256": digest,
                "observation_kind": "executed_frame",
                "frame_qualname": qualname,
            }
            for case in selected
            for path, digest, qualname in (
                (row["path"], row["test_sha256"], "test_validate.<locals>.callback"),
                (
                    "app.py",
                    row["mutation"][
                        "mutant_sha256" if phase == "mutation" else "source_sha256"
                    ],
                    "validate",
                ),
            )
        ]
        run["assertion_observations"] = [
            {
                "case_id": case,
                "callback_qualname": "test_validate.<locals>.callback",
                "line": 4,
                "assertion_kind": "assert",
                "hits": 1,
                "outcome": "PASS" if phase == "baseline" else "FAIL",
                "failure_visible": phase == "mutation",
            }
            for case in selected
        ]
    row["mutation"]["failure_kind"] = "assertion"
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *a, **k: {
            "schema": "factory.test-oracle-verification.v3",
            "tests": [row],
        },
    )
    result = security_scan(tmp_path, **kwargs)
    assert result["runtime_oracles"]["reconciled_count"] == int(complete)
    assert ("QUALITY_HOLLOW_TEST" in result["finding_counts"]) is not complete
    if not complete:
        coverage = result["findings"][0]["facts"]["runtime_case_coverage"]
        assert coverage["remaining_case_ids"] == ["test_app.py::test_validate[b]"]


def test_scan_v3_oracle_cannot_bypass_callback_check_for_unparameterized_smoke(
    tmp_path, monkeypatch
):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    row["mutation"]["failure_kind"] = "assertion"
    catalog = {
        "status": "PASS",
        "phase": "collection",
        "complete": True,
        "scope": "test_function",
        "source_path": row["path"],
        "source_sha256": row["test_sha256"],
        "config_manifest": [],
        "config_identity": "pytest-default",
        "case_ids": list(row["baseline"]["case_ids"]),
    }
    for run in (row["baseline"], row["mutation"]):
        run.update(
            collection_catalog=catalog,
            setup_status="PASS",
            teardown_status="PASS",
            module_origins=[],
            assertion_observations=[],
        )
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V3,
            "tests": [row],
        },
    )

    result = security_scan(tmp_path, **kwargs)

    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert result["findings"][0]["facts"]["runtime_case_coverage"]["eligible"] is False


def test_scan_keeps_finding_if_test_source_changes_after_oracle_binding(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as audit
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    core = security_scan(tmp_path)
    original_read = audit._security_source_bytes
    test_reads = 0

    def drift_after_binding(workspace, relative):
        nonlocal test_reads
        if relative == row["path"]:
            test_reads += 1
            if test_reads == 3:
                return b"def test_replaced():\n    pass\n"
        return original_read(workspace, relative)

    monkeypatch.setattr(audit, "_security_source_bytes", drift_after_binding)
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V2,
            "tests": [row],
        },
    )

    result = audit._reconcile_runtime_oracles(tmp_path, core, tuple(kwargs.values()))

    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0


def test_scan_keeps_finding_if_test_body_changes_after_oracle_binding(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as audit
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    core = security_scan(tmp_path)
    original_read = audit._security_source_bytes
    test_reads = 0

    def drift_after_binding(workspace, relative):
        nonlocal test_reads
        if relative == row["path"]:
            test_reads += 1
            if test_reads == 3:
                return (
                    b"from app import validate\ndef test_validate():\n    validate(6)\n"
                )
        return original_read(workspace, relative)

    monkeypatch.setattr(audit, "_security_source_bytes", drift_after_binding)
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V2,
            "tests": [row],
        },
    )

    result = audit._reconcile_runtime_oracles(tmp_path, core, tuple(kwargs.values()))

    assert result["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0


def test_scan_rejects_partial_runtime_evidence_configuration(tmp_path):
    _module, _row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    del kwargs["oracle_environment_sha256"]
    with pytest.raises(
        ReviewAuditError, match="requires receipt, trust root and both pins"
    ):
        security_scan(tmp_path, **kwargs)


def test_security_scan_seal_is_idempotent(tmp_path):
    import factoryline.review_audits as module

    (tmp_path / "app.py").write_text("value = 5\n", encoding="utf-8")
    result = security_scan(tmp_path)
    assert module._seal_security_scan(result.copy()) == result


@pytest.mark.parametrize(
    "command_prefix", [["audit", "security"], ["scan"], ["scan", "--deep"]]
)
def test_signed_runtime_oracle_cli_after_observed_mutant_failure(
    tmp_path, capsys, command_prefix
):
    from datetime import datetime, timedelta, timezone
    from hashlib import sha256
    import os
    import subprocess
    import sys
    from factoryline.enterprise_receipts import generate_key_material, sign_payload
    from factoryline.runtime_attestation import (
        TEST_ORACLE_SCHEMA,
        TEST_ORACLE_PAYLOAD_TYPE,
    )

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    environment = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPATH": str(tmp_path),
        "NO_COLOR": "1",
    }
    command = [
        sys.executable,
        "-m",
        "pytest",
        "test_app.py::test_validate",
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    baseline = subprocess.run(
        command,
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=20,
        check=False,
    )
    original = (tmp_path / "app.py").read_bytes()
    mutant = b"def validate(value):\n    raise ValueError('negative control')\n"
    try:
        (tmp_path / "app.py").write_bytes(mutant)
        mutated = subprocess.run(
            command,
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            timeout=20,
            check=False,
        )
    finally:
        (tmp_path / "app.py").write_bytes(original)
    assert baseline.returncode == 0 and b"1 passed" in baseline.stdout
    assert mutated.returncode == 1 and b"ValueError: negative control" in mutated.stdout
    assert b"FAILED test_app.py::test_validate" in mutated.stdout
    row["baseline"]["report_sha256"] = sha256(
        baseline.stdout + baseline.stderr
    ).hexdigest()
    row["mutation"]["report_sha256"] = sha256(
        mutated.stdout + mutated.stderr
    ).hexdigest()
    row["mutation"]["mutant_sha256"] = sha256(mutant).hexdigest()
    initial = security_scan(tmp_path)
    now = datetime.now(timezone.utc)
    payload = {
        "schema": TEST_ORACLE_SCHEMA,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "source_manifest_sha256": initial["source_manifest_sha256"],
        "environment_sha256": kwargs["oracle_environment_sha256"],
        "authority": "none",
        "tests": [row],
    }
    keys = generate_key_material(
        out_dir=tmp_path / ".factory" / "keys",
        keyid="local-test-oracle",
        identity="test-only@example",
        issuer="local-test",
    )
    trust = json.loads(Path(keys["trust_root"]).read_text(encoding="utf-8"))
    trust["keys"][0]["roles"] = ["oracle-verifier"]
    (tmp_path / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
    kwargs["oracle_trust_sha256"] = sha256(
        (tmp_path / "trust.json").read_bytes()
    ).hexdigest()
    envelope = sign_payload(
        payload,
        payload_type=TEST_ORACLE_PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    (tmp_path / "oracle.json").write_text(json.dumps(envelope), encoding="utf-8")
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    code = main(
        [
            *command_prefix,
            "--root",
            str(tmp_path),
            "--oracle-evidence",
            "oracle.json",
            "--oracle-trust-root",
            "trust.json",
            "--oracle-trust-sha256",
            kwargs["oracle_trust_sha256"],
            "--oracle-environment-sha256",
            kwargs["oracle_environment_sha256"],
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    if command_prefix[0] == "scan":
        assert result["state"] == "INCOMPLETE"
        result = result["static_security"]
    assert result["state"] == "CLEAN"
    assert result["runtime_oracles"]["reconciled_count"] == 1
    assert result["runtime_oracles"]["signature"]["identity"] == "test-only@example"
    assert "not established" in result["runtime_oracles"]["claim_boundary"]
    assert (
        result["runtime_oracles"]["reconciled"][0]["static_finding"]["code"]
        == "QUALITY_HOLLOW_TEST"
    )


def test_runtime_oracle_rechecks_scanner_configuration_after_verification(
    tmp_path, monkeypatch
):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    config = tmp_path / "pyproject.toml"
    config.write_text("[tool.mypy]\nfiles = []\n", encoding="utf-8")

    def drift(*args, **values):
        config.write_text('[tool.mypy]\nfiles = ["test_app.py"]\n', encoding="utf-8")
        return {"tests": [row]}

    monkeypatch.setattr(attestation, "verify_signed_test_oracles", drift)
    with pytest.raises(ReviewAuditError, match="Runtime oracle evidence rejected"):
        security_scan(tmp_path, **kwargs)


def test_runtime_oracle_rechecks_source_after_verification(tmp_path, monkeypatch):
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)

    def drift(*args, **values):
        (tmp_path / "app.py").write_text(
            "def validate(value):\n    eval(value)\n", encoding="utf-8"
        )
        return {"tests": [row]}

    monkeypatch.setattr(attestation, "verify_signed_test_oracles", drift)
    with pytest.raises(ReviewAuditError, match="Runtime oracle evidence rejected"):
        security_scan(tmp_path, **kwargs)


@pytest.mark.parametrize(
    "testing,path,mutation,expected",
    [
        (True, "/checked", "", {}),
        (False, "/checked", "", {"QUALITY_HOLLOW_TEST": 1}),
        (True, "/other", "", {"QUALITY_HOLLOW_TEST": 1}),
        (True, "/checked", "app.testing = False\n    ", {"QUALITY_HOLLOW_TEST": 1}),
        (True, "/checked", "client = fake_client\n    ", {"QUALITY_HOLLOW_TEST": 1}),
        (
            True,
            "/checked",
            "app.view_functions['check'] = noop\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "client.application.testing = False\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "views = app.view_functions\n    views.clear()\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions').clear()\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions').pop('check', None)\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "views = getattr(app, 'view_functions')\n    views.clear()\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "alias = app; getattr(alias, 'view_functions').clear()\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions')['check'] = noop\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "getattr(app, 'config')['TESTING'] = False\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "setattr(getattr(app, 'config'), 'TESTING', False)\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            True,
            "/checked",
            "app.config.update(TESTING=False)\n    ",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_registered_flask_callback_requires_dispatch_and_propagation(
    tmp_path, testing, path, mutation, expected
):
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom flask import Flask\n@pytest.fixture\ndef app():\n    app = Flask('test')\n    app.config.update(TESTING="
        + str(testing)
        + ")\n    return app\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_behavior(app):\n    @app.route('/checked')\n    def check():\n        assert compute() == 42\n        return ''\n    client = app.test_client()\n    "
        + mutation
        + "client.get('"
        + path
        + "')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("await send(scope)", {}),
        ("send(scope)", {"QUALITY_HOLLOW_TEST": 1}),
        ("if False:\n            await send(scope)", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "try:\n            await send(scope)\n        except AssertionError:\n            pass",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        ("send = noop\n        await send(scope)", {"QUALITY_HOLLOW_TEST": 1}),
    ],
)
def test_source_resolved_async_callback_requires_escaping_await(
    tmp_path, operation, expected
):
    (tmp_path / "engine.py").write_text(
        "class Application:\n    async def __call__(self, scope, receive, send):\n        await self.deliver(scope, send)\n    async def deliver(self, scope, send):\n        "
        + operation
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Application\nasync def test_behavior():\n    async def check(message):\n        assert message == expected\n    app = Application()\n    await app({}, None, check)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


def test_flask_fixture_rejects_positional_config_update(tmp_path):
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom flask import Flask\n"
        "@pytest.fixture\ndef app():\n"
        "    app = Flask('test')\n"
        "    app.testing = True\n"
        "    app.config.update({'TESTING': False})\n"
        "    yield app\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_behavior(app):\n"
        "    @app.route('/checked')\n"
        "    def check():\n"
        "        assert compute() == 42\n"
        "    client = app.test_client()\n"
        "    client.get('/checked')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "setup,dispatch,expected",
    [
        ("run = partial(self.deliver, send)", "await run()", {}),
        ("run = partial(self.deliver, send)", "run()", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "run = partial(self.deliver, send)\n        run: object = noop",
            "await run()",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "run = partial(self.deliver, send)\n        send = noop",
            "await self.deliver(send)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "",
            "await run()\n        run = partial(self.deliver, send)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "run = partial(self.deliver, send)",
            "try:\n            await run()\n        except AssertionError:\n            pass",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_source_partial_callback_rejects_rebinding_and_swallowing(
    tmp_path, setup, dispatch, expected
):
    (tmp_path / "engine.py").write_text(
        "from functools import partial\nclass Application:\n    async def __call__(self, scope, receive, send):\n        "
        + setup
        + "\n        "
        + dispatch
        + "\n    async def deliver(self, send):\n        await send({})\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Application\nasync def test_behavior():\n    async def check(message):\n        assert message == expected\n    app = Application()\n    await app({}, None, check)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize(
    "wrapper,expected",
    [
        ("async def wrapped(message):\n            await send(message)", {}),
        (
            "async def wrapped(send):\n            await send({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "async def wrapped(message):\n            send = noop\n            await send(message)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "async def wrapped(message):\n            try:\n                await send(message)\n            except AssertionError:\n                pass",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_source_callback_wrapper_requires_original_escaping_callback(
    tmp_path, wrapper, expected
):
    (tmp_path / "engine.py").write_text(
        "class Application:\n    async def __call__(self, scope, receive, send):\n        send = self.wrap(send)\n        await send({})\n    def wrap(self, send):\n        "
        + wrapper
        + "\n        return wrapped\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Application\nasync def test_behavior():\n    async def check(message):\n        assert message == expected\n    app = Application()\n    await app({}, None, check)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == expected


@pytest.mark.parametrize("wrapped", [False, True])
def test_source_callback_rejects_aliased_assertion_handler(tmp_path, wrapped):
    direct = "class Application:\n    async def __call__(self, scope, receive, send):\n        try:\n            await send(scope)\n        except E:\n            pass\n"
    wrapper = "class Application:\n    async def __call__(self, scope, receive, send):\n        send = self.wrap(send)\n        await send(scope)\n    def wrap(self, send):\n        async def wrapped(message):\n            try:\n                await send(message)\n            except E:\n                pass\n        return wrapped\n"
    (tmp_path / "engine.py").write_text(
        "from builtins import AssertionError as E\n" + (wrapper if wrapped else direct),
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Application\nasync def test_behavior():\n    async def check(message):\n        assert message == expected\n    app = Application()\n    await app({}, None, check)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "mutation", ["self.deliver = noop", "setattr(self, 'deliver', noop)"]
)
def test_source_callback_rejects_constructor_method_override(tmp_path, mutation):
    (tmp_path / "engine.py").write_text(
        "class Application:\n    def __init__(self):\n        "
        + mutation
        + "\n    async def __call__(self, scope, receive, send):\n        await self.deliver(send)\n    async def deliver(self, send):\n        await send({})\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Application\nasync def test_behavior():\n    async def check(message):\n        assert message == expected\n    app = Application()\n    await app({}, None, check)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "base_call,override,construct,operation,expected",
    [
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "await app({})",
            {},
        ),
        (
            "self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "if False:\n            await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "try:\n            await self.dispatch_func(scope)\n        except AssertionError:\n            pass",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert True",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None, dispatch=noop)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "app.dispatch_func = noop\n    await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def __call__(self, value):\n            pass\n        async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected\n        dispatch = noop",
            "Application(None)",
            "await app({})",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_inherited_virtual_dispatch_requires_default_binding_and_await(
    tmp_path, base_call, override, construct, operation, expected
):
    (tmp_path / "engine.py").write_text(
        "class Base:\n    def __init__(self, app, dispatch=None):\n        self.app = app\n        self.dispatch_func = self.dispatch if dispatch is None else dispatch\n    async def __call__(self, scope):\n        "
        + base_call
        + "\n    async def dispatch(self, value):\n        raise NotImplementedError\n",
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "from engine import Base\nasync def test_behavior():\n    class Application(Base):\n        "
        + override
        + "\n    app: object = "
        + construct
        + "\n    "
        + operation
        + "\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    counts = dict(result["finding_counts"])
    assert counts.pop("QUALITY_EMPTY_IMPLEMENTATION") >= 1
    assert counts == expected
    if not expected:
        assert any(
            edge["kind"] == "default_virtual_dispatch"
            for edge in result["oracle_context"]["resolved_edges"]
        )


@pytest.mark.parametrize(
    "base_call,override,operation",
    [
        (
            "self.dispatch_func = noop\n        await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "await app({})",
        ),
        (
            "await self.dispatch_func(scope)",
            "Base.__init__ = noop\n        async def dispatch(self, value):\n            assert value == expected",
            "await app({})",
        ),
        (
            "await self.dispatch_func(scope)",
            "setattr(Base, '__init__', noop)\n        async def dispatch(self, value):\n            assert value == expected",
            "await app({})",
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application.dispatch = noop\n    await app({})",
        ),
    ],
)
def test_virtual_dispatch_rejects_class_and_source_mutations(
    tmp_path, base_call, override, operation
):
    test_inherited_virtual_dispatch_requires_default_binding_and_await(
        tmp_path,
        base_call,
        override,
        "Application(None)",
        operation,
        {"QUALITY_HOLLOW_TEST": 1},
    )


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("await app({'type': 'http'})", {}),
        ("scope = {'type': 'http'}\n    await app(scope)", {}),
        ("await app({'type': 'websocket'})", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "scope = {'type': 'http'}\n    scope['type'] = 'websocket'\n    await app(scope)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
        (
            "scope = {'type': 'http'}\n    mutate(scope)\n    await app(scope)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_virtual_dispatch_requires_scope_guard_to_reach_override(
    tmp_path, operation, expected
):
    test_inherited_virtual_dispatch_requires_default_binding_and_await(
        tmp_path,
        "if scope['type'] != 'http':\n            return\n        await self.dispatch_func(scope)",
        "async def dispatch(self, value):\n            assert value == expected",
        "Application(None)",
        operation,
        expected,
    )


@pytest.mark.parametrize(
    "guard,operation",
    [
        ("scope[b'type'] != b'http'", "await app({b'type': b'http'})"),
        (
            "scope['type'] != 'http'",
            "scope = {'type': 'http'}\n    scope['type'] = 'websocket'; await app(scope)",
        ),
    ],
)
def test_virtual_dispatch_unsupported_guard_and_same_line_mutation_fail_closed(
    tmp_path, guard, operation
):
    test_inherited_virtual_dispatch_requires_default_binding_and_await(
        tmp_path,
        "if "
        + guard
        + ":\n            return\n        await self.dispatch_func(scope)",
        "async def dispatch(self, value):\n            assert value == expected",
        "Application(None)",
        operation,
        {"QUALITY_HOLLOW_TEST": 1},
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def configure():\n    client = rq.Session()\n"
            "    client.verify = False\n    import requests as rq\n",
            0,
        ),
        (
            "def configure():\n    import requests as rq\n"
            "    client = rq.Session()\n    client.verify = False\n",
            1,
        ),
        (
            "import requests as rq\ndef configure():\n"
            "    rq = object()\n    client = rq.Session()\n"
            "    client.verify = False\n",
            0,
        ),
    ],
)
def test_session_tls_constructor_respects_import_execution_order(
    tmp_path, source, expected
):
    (tmp_path / "service.py").write_text(source)
    result = security_scan(tmp_path)
    assert result["finding_counts"].get("SECURITY_TLS_VERIFY_DISABLED", 0) == expected


def test_security_flow_indexes_conditional_function_default_at_parent_statement(
    tmp_path,
):
    (tmp_path / "service.py").write_text(
        "import httpx\n"
        "if ENABLED:\n"
        "    def configure(client=httpx.Client(verify=False)):\n"
        "        return client\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"].get("SECURITY_TLS_VERIFY_DISABLED", 0) == 1


def test_security_scan_reports_production_implementation_completeness(tmp_path):
    (tmp_path / "service.py").write_text("def build():\n    pass\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"]["QUALITY_EMPTY_IMPLEMENTATION"] == 1
    finding = next(
        f for f in result["findings"] if f["code"] == "QUALITY_EMPTY_IMPLEMENTATION"
    )
    assert finding["facts"]["action"]


def test_security_scan_keeps_legitimate_stub_interfaces_and_tests(tmp_path):
    (tmp_path / "service.py").write_text(
        "from typing import Protocol\nclass Contract(Protocol):\n    def build(self): ...\n"
    )
    (tmp_path / "test_fixture.py").write_text("def helper():\n    pass\n")
    assert (
        "QUALITY_EMPTY_IMPLEMENTATION" not in security_scan(tmp_path)["finding_counts"]
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def test_repr():\n    value = object()\n"
            "    assert isinstance(repr(value), str)\n",
            {"QUALITY_WEAK_TEST_ORACLE": 1},
        ),
        (
            "def test_result_type():\n    assert isinstance(compute(), str)\n",
            {},
        ),
        (
            "def test_repr_contents():\n    value = object()\n"
            '    assert repr(value) == "expected"\n',
            {},
        ),
        (
            "def test_repr():\n    isinstance = check\n    repr = render\n"
            "    str = expected_type\n"
            "    assert isinstance(repr(object()), str)\n",
            {},
        ),
        (
            "isinstance = check\nrepr = render\nstr = expected_type\n"
            "def test_repr():\n    assert isinstance(repr(object()), str)\n",
            {},
        ),
        (
            "def test_repr(isinstance, repr, str):\n"
            "    assert isinstance(repr(object()), str)\n",
            {},
        ),
    ],
    ids=[
        "builtin-repr-weak",
        "actual-result-type",
        "repr-equality",
        "local-shadow",
        "module-shadow",
        "parameter-shadow",
    ],
)
def test_builtin_repr_type_check_oracle_is_weak_only_when_unshadowed(
    tmp_path, source, expected
):
    (tmp_path / "test_repr_oracle.py").write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == expected
    if expected:
        finding = next(
            item
            for item in result["findings"]
            if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
        )
        assert "does not verify the expected representation" in finding["message"]


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error('bad: ' + raw)\n",
            True,
        ),
        (
            "from builtins import input as read_input\n"
            "import logging\n"
            "def record():\n"
            "    logging.error(read_input())\n",
            True,
        ),
        (
            "import builtins\nimport logging\nlogging.info(builtins.input())\n",
            True,
        ),
        (
            "import builtins as bi\nimport logging\nlogging.info(bi.input())\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    alias = raw\n"
            "    logging.error(f'bad: {alias}')\n",
            True,
        ),
        (
            "from logging import error as log_error\n"
            "def record():\n"
            "    raw = input()\n"
            "    log_error('bad: %s', raw)\n",
            True,
        ),
        (
            "def record():\n"
            "    from logging import error as log_error\n"
            "    log_error(input())\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    log_error = logging.error\n"
            "    log_error(input())\n",
            True,
        ),
        (
            "import logging as log\ndef record():\n    log.error(input())\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    if enabled:\n"
            "        raw = input()\n"
            "    logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "        raw = int(raw)\n"
            "    except ValueError:\n"
            "        logging.error('bad integer: ' + raw)\n",
            True,
        ),
        (
            "from flask import request\n"
            "import logging\n"
            "def record():\n"
            "    raw = request.args.get('q')\n"
            "    logging.error(raw)\n",
            True,
        ),
        (
            "from django.http import HttpRequest\n"
            "import logging\n"
            "def record(request: HttpRequest):\n"
            "    raw = request.GET['q']\n"
            "    logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error(f'bad: {raw!r}')\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    callback = lambda: input()\n"
            "    logging.info(callback)\n",
            False,
        ),
        (
            "import logging\ndef record():\n    logging.info((lambda: input())())\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error('%r', raw)\n",
            False,
        ),
        (
            "import builtins\n"
            "import logging\n"
            "raw = builtins.input()\n"
            "logging.info(builtins.repr(raw))\n",
            False,
        ),
        (
            "import builtins\n"
            "import logging\n"
            "raw = builtins.input()\n"
            "logging.info(builtins.int(raw))\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error('%s', raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error(msg=raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.log(logging.INFO, msg=raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error(msg='%r', args=(raw,))\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error(msg='%s', args=(raw,))\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\r', '').replace('\\n', '')\n"
            "    logging.error(clean)\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\n', '')\n"
            "    logging.error(clean)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\n', '\\n')\n"
            "    logging.error(clean)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\n', '', 0).replace('\\r', '')\n"
            "    logging.error(clean)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\n', '', 1).replace('\\r', '')\n"
            "    logging.error(clean)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\r', '').replace('\\n', '')\n"
            "    unsafe = clean.replace('x', '\\n')\n"
            "    logging.error(unsafe)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "        number = int(raw)\n"
            "    except ValueError:\n"
            "        logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "        number = int(raw)\n"
            "    except Exception:\n"
            "        logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "        number = int(raw)\n"
            "    except:\n"
            "        logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "        number = int(raw)\n"
            "    except ValueError:\n"
            "        pass\n"
            "    else:\n"
            "        logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    try:\n"
            "        raw = input()\n"
            "    finally:\n"
            "        logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    for raw in [input()]:\n"
            "        pass\n"
            "    logging.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    value = input()\n"
            "    for value in ['fixed']:\n"
            "        logging.info(value)\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    value = input()\n"
            "    for value in ['fixed']:\n"
            "        pass\n"
            "    logging.info(value)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    clean = raw.replace('\\n', '\\n').replace('\\r', '')\n"
            "    logging.error(clean)\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    count = int(raw)\n"
            "    logging.error('count %s', count)\n",
            False,
        ),
        (
            "import logging\n"
            "int = lambda value: value\n"
            "value = input()\n"
            "logging.info(int(value))\n",
            True,
        ),
        (
            "import logging\n"
            "repr = lambda value: value\n"
            "value = input()\n"
            "logging.info(repr(value))\n",
            True,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    raw = input()\n"
            "    raw = 'constant'\n"
            "    logging.error(raw)\n",
            False,
        ),
        (
            "import logging\n"
            "def shadowed(input):\n"
            "    logging.error(input())\n"
            "def unrelated():\n"
            "    logger.error(input())\n",
            False,
        ),
        (
            "import logging\nbuiltins = object()\nlogging.info(builtins.input())\n",
            False,
        ),
        (
            "import logging\n"
            "builtins = object()\n"
            "raw = input()\n"
            "logging.info(builtins.repr(raw))\n",
            True,
        ),
        (
            "import logging\ndef shadowed(logging):\n    logging.error(input())\n",
            False,
        ),
        (
            "from flask import request\n"
            "import logging\n"
            "def record():\n"
            "    request = object()\n"
            "    logging.error(request.args.get('q'))\n",
            False,
        ),
        (
            "class Fake:\n"
            "    def error(self, value):\n"
            "        pass\n"
            "logging = Fake()\n"
            "def record():\n"
            "    raw = input()\n"
            "    logging.error(raw)\n",
            False,
        ),
        (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def record():\n"
            "    raw = input()\n"
            "    logger.error(raw)\n",
            True,
        ),
        (
            "import logging as logmod\n"
            "logger = logmod.getLogger(__name__)\n"
            "def record():\n"
            "    raw = input()\n"
            "    logger.error(raw)\n",
            True,
        ),
        (
            "from logging import getLogger as make_logger\n"
            "logger = make_logger(__name__)\n"
            "def record():\n"
            "    raw = input()\n"
            "    logger.error(raw)\n",
            True,
        ),
        (
            "from logging import Logger\n"
            "logger = Logger(__name__)\n"
            "def record():\n"
            "    raw = input()\n"
            "    logger.error(raw)\n",
            True,
        ),
        (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "logger = object()\n"
            "def record():\n"
            "    raw = input()\n"
            "    logger.error(raw)\n",
            False,
        ),
        (
            "import logging\n"
            "def record():\n"
            "    with open('input.txt'):\n"
            "        raw = input()\n"
            "        logging.error(raw)\n",
            True,
        ),
    ],
    ids=[
        "direct-input-concatenation",
        "imported-builtin-input-alias",
        "imported-builtins-input-source",
        "aliased-builtins-input-source",
        "input-alias-fstring",
        "imported-log-function-format-args",
        "locally-imported-log-function",
        "assigned-logging-function-alias",
        "imported-logging-module-alias",
        "if-branch-source-reaches-log",
        "valueerror-keeps-preassignment-raw",
        "exception-keeps-preassignment-raw",
        "bare-handler-keeps-preassignment-raw",
        "proven-flask-request-args-get",
        "proven-django-request-get",
        "fstring-repr-is-safe",
        "deferred-lambda-input-is-not-evaluated",
        "immediate-lambda-input-is-evaluated",
        "percent-repr-is-safe",
        "imported-builtins-repr-is-safe",
        "imported-builtins-int-is-safe",
        "percent-string-is-unsafe",
        "keyword-message-is-unsafe",
        "logging-log-keyword-message-is-unsafe",
        "keyword-percent-repr-is-safe",
        "keyword-percent-string-is-unsafe",
        "both-crlf-neutralized",
        "partial-newline-neutralization",
        "no-op-newline-replacement-is-unsafe",
        "replace-count-zero-is-not-sanitization",
        "replace-positive-count-is-not-complete",
        "outer-replacement-cannot-reintroduce-newline",
        "rhs-source-snapshot-for-valueerror",
        "try-else-flow-is-analyzed",
        "try-finally-flow-is-analyzed",
        "loop-taint-survives-after-loop",
        "loop-safe-target-clears-prior-taint-in-body",
        "loop-zero-iteration-retains-prior-taint-afterward",
        "replacement-reintroduces-newline",
        "successful-int-result-safe",
        "module-rebound-int-is-not-sanitizer",
        "module-rebound-repr-is-not-sanitizer",
        "source-rebound-to-constant",
        "shadowed-input-and-unrelated-logger",
        "rebound-builtins-module-is-not-input-source",
        "rebound-builtins-module-is-not-safe-repr",
        "shadowed-logging-module",
        "rebound-flask-request-safe",
        "fake-global-logging-name-is-not-stdlib",
        "stdlib-getlogger-return-is-a-proven-logger",
        "stdlib-module-alias-getlogger-return-is-proven",
        "imported-getlogger-alias-return-is-proven",
        "imported-logger-class-return-is-proven",
        "rebound-logger-variable-is-not-stdlib",
        "with-body-direct-input-logging",
    ],
)
def test_audit_log_source_findings_via_security_scan_input_and_request_log_injection(
    tmp_path, source, expected
):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    log_findings = [
        item for item in findings if item["code"] == "SECURITY_LOG_INJECTION"
    ]
    assert bool(log_findings) is expected
    if expected:
        assert all(item["facts"]["cwe"] == "CWE-117" for item in log_findings)
