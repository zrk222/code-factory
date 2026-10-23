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
    "body,expected_findings",
    [
        ("import product.interface", {}),
        ("from product import interface", {}),
        ("import product.interface as api", {}),
        (
            '"""The public interface is importable."""\nfrom product import interface',
            {},
        ),
        (
            "try:\n    import product.interface\nexcept ImportError:\n    pass",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        ("if False:\n    import product.interface", {"QUALITY_HOLLOW_TEST": 1}),
        ("def deferred():\n    import product.interface", {"QUALITY_HOLLOW_TEST": 1}),
        ("return\nimport product.interface", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "import product.interface\nassert True",
            {"QUALITY_WEAK_TEST_ORACLE": 1},
        ),
        (
            "import product.interface\nresult = compute()",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        ('"""import product.interface"""', {"QUALITY_HOLLOW_TEST": 1}),
        (
            "from product import *",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
    ],
)
def test_import_behavior_oracle_requires_direct_complete_body(
    tmp_path, body, expected_findings
):
    (tmp_path / "test_interfaces.py").write_text(
        "def test_import_interface():\n" + textwrap.indent(body, "    ") + "\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == expected_findings


def test_import_behavior_does_not_exempt_unrelated_test_name(tmp_path):
    (tmp_path / "test_interfaces.py").write_text(
        "def test_compute():\n    import product.interface\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE" for f in report["findings"])


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
    test_file = tmp_path / "test_product.py"
    test_import = "import product\ndef test_public():\n    product.missing\n"
    scenarios = {
        "direct_source_attribute": (
            "public = object()\n",
            "import product\ndef test_public():\n    product.public\n",
        ),
        "mock_rebinding": (
            "public = object()\n",
            "from unittest.mock import Mock\nproduct = Mock()\ndef test_public():\n    product.public\n",
        ),
        "test_scope_import_rebinding": (
            "public = object()\n",
            "import product\ndef test_public():\n    from unittest.mock import sentinel as product\n    product.anything\n",
        ),
        "unresolved_root": (
            "public = object()\n",
            "def test_public():\n    unresolved.public\n",
        ),
        "source_catchall_getattr": (
            "def __getattr__(name):\n    return object()\n",
            test_import,
        ),
    }
    expected = {
        "direct_source_attribute": {},
        "mock_rebinding": {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        "test_scope_import_rebinding": {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        "unresolved_root": {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        # A getter definition alone does not prove that the current imported
        # module, builtin, or lookup path is unchanged at the test operation.
        "source_catchall_getattr": {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
    }
    observed = {}
    for case, (module_source, test_source) in scenarios.items():
        product.write_text(module_source)
        test_file.write_text(test_source)
        observed[case] = security_scan(tmp_path, cache_enabled=False)["finding_counts"]
    assert observed == expected


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
    assert report["finding_counts"] == {"QUALITY_TYPECHECK_NOT_VERIFIED": 1}

    test.write_text(
        "from api import Middleware\nfrom unittest.mock import Mock\nMiddleware = Mock()\n"
        "def test_constructs():\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}

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
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}

    test.write_text(
        "from api import Middleware\n"
        "def test_constructs(Middleware):\n"
        "    def handler(request: object) -> object:\n"
        "        raise NotImplementedError\n"
        "    Middleware(handler)\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


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
            False,  # Undefined mutation is opaque, not proof of an inert test.
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
    findings = security_scan(tmp_path)["findings"]
    flagged = any(finding["code"] == "QUALITY_HOLLOW_TEST" for finding in findings)
    assert flagged is hollow
    if mutation == "mutate(checks)":
        unknown = next(
            f for f in findings if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
        )
        assert unknown["severity"] == "INFO"
        assert unknown["facts"]["state"] == "INCOMPLETE"


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
    "expression,diagnostic",
    [
        ("obj is obj", "QUALITY_HOLLOW_TEST"),
        ("obj == obj", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("obj <= obj", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("obj >= obj", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("True", "QUALITY_HOLLOW_TEST"),
        ("1 == 1", "QUALITY_HOLLOW_TEST"),
    ],
)
def test_repeated_local_values_require_identity_or_literal_proof(
    tmp_path, expression, diagnostic
):
    (tmp_path / "test_case.py").write_text(
        f"def test_behavior(obj):\n    assert {expression}\n", encoding="utf-8"
    )
    report = security_scan(tmp_path)
    assert report["finding_counts"] == {diagnostic: 1}
    assert report["findings"][0]["severity"] == (
        "INFO" if diagnostic == "QUALITY_UNKNOWN_TEST_ORACLE" else "MEDIUM"
    )
    if diagnostic == "QUALITY_UNKNOWN_TEST_ORACLE":
        # Unknown objects can overload comparisons; even ordinary float NaN
        # falsifies all three expressions. Repeated spelling is not a proof.
        import operator

        compare = {
            "obj == obj": operator.eq,
            "obj <= obj": operator.le,
            "obj >= obj": operator.ge,
        }[expression]
        value = float("nan")
        assert compare(value, value) is False


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
    "source,expected_code",
    [
        (
            "def test_behavior():\n    value = callback()\n    pass\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "def test_behavior():\n    callback(); other()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "def test_behavior():\n    callback(other())\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "def test_behavior():\n    callback() or other()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "async def test_behavior():\n    await callback()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        ("def test_behavior():\n    lambda: callback()\n", "QUALITY_HOLLOW_TEST"),
        (
            "@register(callback())\ndef test_behavior():\n    pass\n",
            "QUALITY_HOLLOW_TEST",
        ),
        ("def test_behavior(value=callback()):\n    pass\n", "QUALITY_HOLLOW_TEST"),
        (
            "def test_behavior():\n    class Container:\n        callback()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        ("callback()\ndef test_behavior():\n    pass\n", "QUALITY_HOLLOW_TEST"),
    ],
)
def test_hollow_test_call_probe_guidance_rejects_non_direct_targets(
    tmp_path, source, expected_code
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")

    finding = next(
        item
        for item in security_scan(tmp_path)["findings"]
        if item["code"] == expected_code
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
        ("alias = app", None),
        pytest.param(
            "alias = app; alias.testing = False",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="alias = app; alias.testing = False-QUALITY_HOLLOW_TEST",
        ),
        pytest.param(
            "first = app; second = first; second.testing = False",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="first = app; second = first; second.testing = False-QUALITY_HOLLOW_TEST",
        ),
        ("alias = app; alias.replace_dispatcher()", "QUALITY_UNKNOWN_TEST_ORACLE"),
        pytest.param(
            "alias = client; alias.get = lambda path: None",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="alias = client; alias.get = lambda path: None-QUALITY_HOLLOW_TEST",
        ),
    ],
)
# Flask dispatch and exception propagation depend on framework hooks not closed by these AST facts.
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
    assert findings == ({expected_findings: 1} if expected_findings else {})


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
            "def compute():\n        return 5\n    def bar():\n        try:\n            assert compute() == 4\n        except AssertionError:\n            pass",
            "bar()",
            True,
        ),
        (
            "def compute():\n        return 5\n    def noop():\n        pass\n"
            "    def bar():\n        assert compute() == 4",
            "bar = noop\n    bar()",
            True,
        ),
        (
            "def compute():\n        return 5\n    def swallow(fn):\n"
            "        def wrapped():\n            try:\n                fn()\n"
            "            except AssertionError:\n                pass\n"
            "        return wrapped\n    @swallow\n    def bar():\n"
            "        assert compute() == 4",
            "bar()",
            True,
        ),
        ("async def bar():\n        assert compute() == 4", "bar()", True),
        ("async def bar():\n        assert compute() == 4", "await bar()", False),
        (
            "def compute():\n        return 5\n    def bar():\n        assert compute() == 4",
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
            "foo()",
            True,
        ),
        (
            "def compute():\n        return 5\n    def noop():\n        pass\n"
            "    def bar():\n        assert compute() == 4\n"
            "    def foo(bar):\n        bar()",
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
        (
            "def bar():\n        assert compute() == 4",
            "value = False\n    value or True or bar()",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4",
            "value = True\n    value and False and bar()",
            True,
        ),
        ("def bar():\n        assert compute() == 4", "False and bar()", True),
        ("def bar():\n        assert compute() == 4", "bar() if False else None", True),
        ("def bar():\n        assert compute() == 4", "None if True else bar()", True),
        ("def bar():\n        assert compute() == 4", "False or bar()", False),
        ("def bar():\n        assert compute() == 4", "True and bar()", False),
        (
            "def compute():\n        return 5\n    def bar():\n        assert compute() == 4",
            "from somewhere import noop as bar\n    bar()",
            True,
        ),
        (
            "def compute():\n        return 5\n    def noop():\n        pass\n"
            "    def bar():\n        assert compute() == 4\n"
            "    def foo(*bar):\n        bar[0]()",
            "foo(noop)",
            True,
        ),
        (
            "def bar():\n        assert compute() == 4",
            "class bar:\n        pass\n    bar()",
            True,
        ),
        pytest.param(
            "def bar():\n        pass\n    def foo(bar=None):\n        bar()",
            "foo()",
            False,
            id="default-parameter-shadow",
        ),
        pytest.param(
            "def bar():\n        pass\n    def foo():\n        bar()\n"
            "        def bar():\n            pass",
            "foo()",
            False,
            id="local-use-before-binding",
        ),
        pytest.param(
            "def bar():\n        pass\n    def foo():\n        bar()",
            "foo()",
            True,
            id="free-variable-helper",
        ),
    ],
)
def test_security_scan_tracks_invoked_nested_oracle_helpers(
    tmp_path, helper, invocation, hollow
):
    if "from somewhere import noop as bar" in invocation:
        (tmp_path / "somewhere.py").write_text("def noop():\n    pass\n")
    (tmp_path / "test_behavior.py").write_text(
        "async def test_behavior():\n    " + helper + "\n    " + invocation + "\n"
    )
    result = security_scan(tmp_path)
    assert any(f["code"] == "QUALITY_HOLLOW_TEST" for f in result["findings"]) is hollow


@pytest.mark.parametrize(
    ("source", "completion"),
    [
        (
            "def test_behavior():\n"
            "    def compute():\n        return 5\n"
            "    assert compute() == 4\n",
            "RAISE",
        ),
        (
            "def test_behavior():\n"
            "    def noop():\n        pass\n"
            "    def invoke(callback):\n        callback()\n"
            "    invoke(noop)\n",
            "NORMAL",
        ),
        (
            "def test_behavior():\n"
            "    def compute():\n        return 5\n"
            "    compute = external\n"
            "    assert compute() == 4\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def noop():\n        pass\n"
            "    def invoke(callback):\n        callback()\n"
            "    invoke(make_callback())\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def noop():\n        pass\n"
            "    def invoke(callback):\n"
            "        callback = external\n        callback()\n"
            "    invoke(noop)\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def compute(value=external()):\n        return 5\n"
            "    assert compute() == 4\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    @external\n"
            "    def compute():\n        return 5\n"
            "    assert compute() == 4\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def compute():\n"
            "        if external:\n            return 5\n"
            "        return 5\n"
            "    assert compute() == 4\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def foo():\n"
            "        def bar():\n            assert compute() == 4\n"
            "    bar()\n",
            "UNKNOWN",
        ),
        (
            "def compute():\n    return 5\n"
            "compute = external\n"
            "def test_behavior():\n    assert compute() == 4\n",
            "UNKNOWN",
        ),
        (
            "def test_behavior():\n"
            "    def noop():\n        pass\n"
            "    def invoke(*callbacks):\n        callbacks[0]()\n"
            "    invoke(noop)\n",
            "NORMAL",
        ),
        (
            "def test_behavior():\n"
            "    def noop():\n        pass\n"
            "    def invoke(*callbacks):\n        callbacks[0]()\n"
            "    invoke(*callbacks)\n",
            "UNKNOWN",
        ),
        pytest.param(
            "def test_behavior():\n"
            "    def bar():\n        pass\n"
            "    def foo():\n        bar()\n"
            "        def bar():\n            pass\n"
            "    foo()\n",
            "UNKNOWN",
            id="local-use-before-binding",
        ),
        pytest.param(
            "def test_behavior():\n"
            "    def bar():\n        pass\n"
            "    def foo(bar=None):\n        bar()\n"
            "    foo()\n",
            "UNKNOWN",
            id="default-parameter-shadow",
        ),
        pytest.param(
            "def test_behavior():\n"
            "    def bar():\n        pass\n"
            "    def foo():\n        bar()\n"
            "    foo()\n",
            "NORMAL",
            id="free-variable-helper",
        ),
    ],
)
def test_nested_helper_completion_keeps_opaque_inputs_unknown(source, completion):
    import ast

    from factoryline.test_oracle_misuse import inert_test_completion

    module = ast.parse(source)
    test = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_behavior"
    )
    test._oracle_module = module
    assert inert_test_completion(test)[0] == completion


def test_security_scan_does_not_credit_nested_helper_before_definition(tmp_path):
    (tmp_path / "test_behavior.py").write_text(
        "def test_behavior():\n    bar()\n    def bar():\n        assert compute() == 4\n"
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "NONE",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    loop = asyncio.new_event_loop()\n"
            "    loop.run_until_complete(check())\n    loop.close()\n",
            "NONE",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    fn()\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "HOLLOW",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    try:\n        run_async_fn(check)\n"
            "    except AssertionError:\n        pass\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def test_behavior():\n"
            "    async def check():\n"
            "        try:\n            assert await compute() == 3\n"
            "        except AssertionError:\n            pass\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    asyncio = Fake()\n"
            "    loop = asyncio.new_event_loop()\n"
            "    loop.run_until_complete(check())\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def noop(fn):\n    pass\nasyncio.run = noop\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio as aio\nimport asyncio\n"
            "async def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def noop(fn):\n    pass\nasyncio.run = noop\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio as poison\nimport asyncio\n"
            "async def compute():\n    return 3\n"
            "poison.run = lambda fn: None\ndel poison\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def noop(fn):\n    pass\nsetattr(asyncio, 'run', noop)\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def retain(value):\n    pass\nretain(asyncio.run)\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def test_behavior():\n"
            "    run_async_fn(check)\n"
            "    async def check():\n        assert await compute() == 3\n",
            "UNKNOWN",
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def noop(fn):\n    pass\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn = noop\n    run_async_fn(check)\n",
            "HOLLOW",
        ),
        (
            "async def compute():\n    return 3\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    pass\n",
            "HOLLOW",
        ),
        (
            "async def compute():\n    return 3\n"
            "def test_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    check()\n",
            "HOLLOW",  # Exact local coroutine creation never enters the assertion body.
        ),
        (
            "import asyncio\nasync def compute():\n    return 3\n"
            "def run_async_fn(fn):\n    asyncio.run(fn())\n"
            "def helper_behavior():\n"
            "    async def check():\n        assert await compute() == 3\n"
            "    run_async_fn(check)\n"
            "def test_genuinely_hollow():\n    compute()\n",
            "HOLLOW",
        ),
    ],
    ids=[
        "asyncio-run-wrapper",
        "event-loop-consumption",
        "no-op-runner",
        "runner-assertion-swallowed",
        "inner-assertion-swallowed",
        "shadowed-asyncio",
        "mutated-asyncio-run",
        "mutated-secondary-asyncio-alias",
        "mutate-deleted-asyncio-alias",
        "setattr-asyncio-run",
        "escaped-asyncio-run",
        "runner-before-helper-definition",
        "shadowed-runner",
        "never-referenced-async-helper",
        "unawaited-direct-helper",
        "genuine-hollow-control",
    ],
)
def test_nested_async_assertion_requires_proven_completion(
    tmp_path, source, expected, request
):
    (tmp_path / "test_async.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    findings = report["finding_counts"]
    # Source-proven discarded coroutine/callback paths are HOLLOW. Opaque
    # runner effects, unresolved bindings and unproven mutations stay UNKNOWN.
    assert findings.get("QUALITY_HOLLOW_TEST", 0) == int(expected == "HOLLOW")
    assert findings.get("QUALITY_UNKNOWN_TEST_ORACLE", 0) == int(expected == "UNKNOWN")
    if request.node.callspec.id == "unawaited-direct-helper":
        assert findings.get("QUALITY_UNKNOWN_TEST_ORACLE", 0) == 0
        assert findings["QUALITY_HOLLOW_TEST"] == 1
        unawaited = [
            item
            for item in report["findings"]
            if item["code"] == "QUALITY_UNAWAITED_COROUTINE"
        ]
        assert len(unawaited) == 1
        assert (
            unawaited[0]["line"],
            unawaited[0]["severity"],
            unawaited[0]["facts"]["symbol"],
        ) == (6, "MEDIUM", "test_behavior")


@pytest.mark.parametrize(
    "import_line,annotation",
    [
        ("from unittest.mock import MagicMock\n", "MagicMock"),
        ("from unittest.mock import MagicMock as MockValue\n", "MockValue"),
    ],
)
def test_magicmock_annotation_alone_does_not_prove_mock_assertion(
    tmp_path, import_line, annotation
):
    (tmp_path / "test_mock_parameter.py").write_text(
        import_line + "def configure(module):\n"
        "    module.fileConfig('x.ini', disable_existing_loggers=False)\n"
        f"def test_behavior(mocked_module: {annotation}):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with(\n"
        "        'x.ini', disable_existing_loggers=False)\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path, cache_enabled=False)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "source",
    [
        "class MagicMock: pass\n"
        "def test_behavior(mocked_module: MagicMock):\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "from unittest.mock import MagicMock\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: MagicMock):\n"
        "    mocked_module = Fake()\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "unittest = FakeNamespace\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: unittest.mock.MagicMock):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture\ndef mocked_module():\n    return Fake()\n"
        "@pytest.fixture\ndef mocked_module():\n    return Fake()\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: MagicMock):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "import unittest.mock as mock_api\n"
        "setattr(mock_api, 'MagicMock', Fake)\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: mock_api.MagicMock):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "import unittest.mock as mock_api\n"
        "retain(mock_api)\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: mock_api.MagicMock):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
        "import unittest.mock as poison\n"
        "import unittest.mock as mock_api\n"
        "setattr(poison, 'MagicMock', Fake)\ndel poison\n"
        "def configure(module):\n    module.fileConfig('x.ini')\n"
        "def test_behavior(mocked_module: mock_api.MagicMock):\n"
        "    configure(mocked_module)\n"
        "    mocked_module.fileConfig.assert_called_once_with('x.ini')\n",
    ],
    ids=[
        "lookalike-type",
        "reassigned-mock-parameter",
        "dotted-name-shadow",
        "ambiguous-fake-fixture",
        "mutated-typed-provider",
        "escaped-typed-provider",
        "mutate-deleted-typed-provider",
    ],
)
def test_unbacked_mock_annotations_remain_unknown(tmp_path, source):
    (tmp_path / "test_mock_parameter.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path, cache_enabled=False)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    if "expected_finding" in case:
        assert result["finding_counts"] == {case["expected_finding"]: 1}


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
    "body, expected",
    [
        (
            "send = AsyncMock()\n    send.assert_not_awaited()",
            "QUALITY_HOLLOW_TEST",
        ),
        (
            "send = AsyncMock()\n    request = Request({'type': 'http'}, send=send)\n"
            "    if False:\n        await request.send_early_hints([])\n"
            "    send.assert_not_awaited()",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "send = AsyncMock()\n    def unused():\n"
            "        request = Request({'type': 'http'}, send=send)\n"
            "        request.send_early_hints([])\n"
            "    send.assert_not_awaited()",
            "QUALITY_HOLLOW_TEST",
        ),
    ],
)
def test_mock_state_oracle_does_not_credit_unused_or_unreachable_dependencies(
    tmp_path, body, expected
):
    (tmp_path / "test_request.py").write_text(
        "from unittest.mock import AsyncMock\n"
        "from starlette.requests import Request\n"
        "async def test_request():\n    " + body + "\n",
        encoding="utf-8",
    )
    # Only untouched state or unentered coroutine creation proves nonraising completion.
    report = security_scan(tmp_path)
    assert report["finding_counts"] == {expected: 1}
    if expected == "QUALITY_UNKNOWN_TEST_ORACLE":
        _assert_unknown_test_oracle(report, unknown_count=1)


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
    "body, expected",
    [
        (
            "dependency()",
            "QUALITY_HOLLOW_TEST",
        ),
        (
            "perform(dependency)\n    dependency = AsyncMock()",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "if False:\n        perform(dependency)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
    ],
)
def test_mock_oracle_rejects_self_unused_and_rebound_state(tmp_path, body, expected):
    (tmp_path / "test_case.py").write_text(
        "from unittest.mock import AsyncMock\ndef test_behavior():\n"
        "    dependency = AsyncMock()\n    "
        + body
        + "\n    dependency.assert_called_once()\n",
        encoding="utf-8",
    )
    # One direct default call proves called-once; opaque calls/rebinds stay UNKNOWN.
    assert security_scan(tmp_path)["finding_counts"] == {expected: 1}


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
    "source, expected",
    [
        (
            "from unittest.mock import Mock\ndef test_behavior():\n"
            "    m = Mock()\n    m.assert_not_called()\n",
            "QUALITY_HOLLOW_TEST",
        ),
        (
            "from unittest.mock import Mock\ndef test_behavior():\n"
            "    m = Mock()\n    if False:\n        ret = (lambda f: None)(m)\n"
            "    m.assert_not_called()\n",
            "QUALITY_HOLLOW_TEST",
        ),
        (
            "from unittest.mock import Mock\nclass Dependency:\n    pass\n"
            "def test_behavior():\n    m = Mock()\n    ret = Dependency(m)\n"
            "    m.assert_not_called()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "from unittest.mock import Mock\n@wrapper\ndef perform(dep):\n    pass\n"
            "def test_behavior():\n    m = Mock()\n    ret = perform(m)\n"
            "    m.assert_not_called()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "from unittest.mock import Mock\ndef test_behavior():\n"
            "    def perform(dep):\n        pass\n    perform = unknown\n"
            "    m = Mock()\n    ret = perform(m)\n    m.assert_not_called()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "from unittest.mock import Mock\nasync def perform(dep):\n    pass\n"
            "def test_behavior():\n    m = Mock()\n    ret = perform(m)\n"
            "    m.assert_not_called()\n",
            "QUALITY_HOLLOW_TEST",
        ),
        (
            "from unittest.mock import Mock\ndef test_behavior():\n"
            "    m = Mock()\n    ret = (lambda f: None)(m)\n"
            "    m = object()\n    m.assert_not_called()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
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
def test_mock_oracle_rejects_unsafe_assigned_dependency_calls(
    tmp_path, source, expected
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    # Only untouched state or unentered coroutine creation proves nonraising completion.
    report = security_scan(tmp_path)
    assert report["finding_counts"] == {expected: 1}
    if expected == "QUALITY_UNKNOWN_TEST_ORACLE":
        _assert_unknown_test_oracle(report, unknown_count=1)


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    "preamble,spec_arguments",
    [
        (
            "def decorate(cls):\n    return cls\n"
            "@decorate\nclass LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n",
            "LegacyTerm",
        ),
        (
            "class ExampleMeta(type):\n    pass\n"
            "class LegacyTerm(metaclass=ExampleMeta):\n"
            "    def write_text(self, text):\n        pass\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    @property\n    def write_text(self):\n        return None\n",
            "LegacyTerm",
        ),
        ("from external_types import LegacyTerm\n", "LegacyTerm"),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "from external_types import *\n"
            "from unittest.mock import create_autospec\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "LegacyTerm = replacement\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "LegacyTerm.write_text = replacement\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "LegacyTerm.__signature__ = replacement\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "Alias = LegacyTerm\nAlias.write_text = Descriptor()\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "ALIAS_CONTAINER = [LegacyTerm]\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n"
            "def return_spec():\n    return LegacyTerm\n",
            "LegacyTerm",
        ),
        (
            "class Descriptor:\n"
            "    def __get__(self, instance, owner):\n"
            "        mock = NonCallableMock()\n"
            "        mock.assert_called_once_with = lambda *args: None\n"
            "        return mock\n"
            "class LegacyTerm:\n"
            "    write_text = Descriptor()\n",
            "LegacyTerm",
        ),
        (
            "class LegacyTerm:\n    def write_text(self, text):\n        pass\n",
            "build_spec()",
        ),
        (
            "class LegacyTerm:\n    def write_text(self, text):\n        pass\n",
            "LegacyTerm, side_effect=build_side_effect",
        ),
        (
            "create_autospec = replacement\n"
            "class LegacyTerm:\n"
            "    def write_text(self, text):\n        pass\n",
            "LegacyTerm",
        ),
    ],
)
def test_create_autospec_fixture_requires_source_closed_plain_class(
    tmp_path, preamble, spec_arguments
):
    (tmp_path / "test_mock_fixture.py").write_text(
        "import pytest\nfrom unittest.mock import create_autospec\n"
        + preamble
        + "@pytest.fixture\ndef legacy_term_mock():\n"
        + f"    return create_autospec({spec_arguments})\n"
        + "def test_behavior(legacy_term_mock):\n"
        + "    perform(legacy_term_mock)\n"
        + "    legacy_term_mock.write_text.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_source_fixture_returning_fake_does_not_prove_mock(tmp_path):
    (tmp_path / "test_fake_fixture.py").write_text(
        "import pytest\nclass Fake:\n"
        "    def assert_called_once_with(self, *args):\n        pass\n"
        "@pytest.fixture\ndef legacy_term_mock():\n    return Fake()\n"
        "def test_behavior(legacy_term_mock):\n    perform(legacy_term_mock)\n"
        "    legacy_term_mock.write_text.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies, clear=True):\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    proxies['one'] = Fake()\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target):\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock(), 'one': Fake()}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "extra = {'one': Fake()}\nproxies = {'one': Mock(), **extra}\n",
            "with patch.dict(target, proxies):\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    proxies.update({'one': Fake()})\n",
            "proxies['one'].clear",
            "UNKNOWN",
        ),
        (
            "proxies = {'one': Mock()}\n",
            "with patch.dict(target, proxies):\n    mutate(proxies)\n",
            "proxies['one'].clear",
            "UNKNOWN",
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
    report = security_scan(tmp_path)
    hollow_count = report["finding_counts"].get("QUALITY_HOLLOW_TEST", 0)
    if expected_hollow == "UNKNOWN":
        assert hollow_count == 0
        unresolved = [
            f for f in report["findings"] if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
        ]
        assert len(unresolved) == 1
        assert unresolved[0]["severity"] == "INFO"
        assert unresolved[0]["facts"]["state"] == "INCOMPLETE"
        assert unresolved[0]["facts"]["evidence_state"] == "UNKNOWN"
        assert unresolved[0]["facts"]["candidate_rule"] == "QUALITY_HOLLOW_TEST"
        return
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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_mock_configure_mock_cannot_replace_assertion_method(tmp_path):
    (tmp_path / "test_mock_configure.py").write_text(
        "from unittest.mock import Mock\n"
        "def test_behavior():\n    send = Mock()\n"
        "    send.configure_mock(assert_called_once_with=lambda *args: None)\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("", {}),
        (
            "alias.configure_mock(assert_called_once_with=lambda *args: None)\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "alias.assert_called_once_with = lambda *args: None\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "alias.__dict__['assert_called_once_with'] = lambda *args: None\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "alias = send; alias.configure_mock(assert_called_once_with=lambda *args: None)\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "alias.assert_called_once_with = lambda *args: None\n    alias = object()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "alias = object()\n    alias.assert_called_once_with = lambda *args: None\n    ",
            {},
        ),
        (
            "send = object()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_module_mock_provenance_is_shadowed_by_local_fake(tmp_path):
    (tmp_path / "test_fake.py").write_text(
        "from unittest.mock import Mock\nsend = Mock()\n"
        "class Fake:\n    def assert_called_once_with(self, *args):\n        pass\n"
        "def test_behavior(send=Fake()):\n"
        "    perform(send)\n    send.assert_called_once_with('payload')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    report = security_scan(tmp_path)
    assert report["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1,
        "QUALITY_UNAWAITED_COROUTINE": 1,
    }
    _assert_unknown_test_oracle(report, unknown_count=1)
    unawaited = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_UNAWAITED_COROUTINE"
    ]
    assert len(unawaited) == 1
    assert (
        unawaited[0]["line"],
        unawaited[0]["severity"],
        unawaited[0]["facts"]["symbol"],
    ) == (6, "MEDIUM", "test_behavior")


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
        if finding["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
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
    "source",
    [
        "import unittest\n"
        "class TestRetryException(unittest.TestCase):\n"
        "    def test_retry_error_is_pickleable(self):\n"
        "        import pickle\n"
        "        expected = RetryError(last_attempt=123)\n"
        "        pickled = pickle.dumps(expected)\n"
        "        actual = pickle.loads(pickled)\n"
        "        self.assertEqual(expected.last_attempt, actual.last_attempt)\n",
        "import pickle\n"
        "class TestPickle:\n"
        "    def test_retrying_picklable(self):\n"
        "        retrying = Retrying(stop=stop_after_attempt(3))\n"
        "        pickled = pickle.dumps(retrying)\n"
        "        restored = pickle.loads(pickled)\n"
        "        assert isinstance(restored, Retrying)\n"
        "        assert isinstance(restored.stop, StopBase)\n",
        "import pickle\n"
        "class TestPickle:\n"
        "    def test_retrying_picklable_after_run(self):\n"
        "        retrying = Retrying(stop=stop_after_attempt(3))\n"
        "        _ = retrying.statistics\n"
        "        pickled = pickle.dumps(retrying)\n"
        "        restored = pickle.loads(pickled)\n"
        "        assert isinstance(restored, Retrying)\n"
        "        assert restored.statistics == {}\n",
        "import pickle\n"
        "class CustomReducer:\n"
        "    def __reduce__(self):\n"
        "        return (rebuild_value, ())\n"
        "def test_custom_reducer_remains_uncertain():\n"
        "    local_value = CustomReducer()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert isinstance(restored, CustomReducer)\n",
    ],
    ids=["tenacity-error", "tenacity-retrying", "tenacity-after-run", "custom-reducer"],
)
def test_security_scan_accepts_same_scope_local_pickle_roundtrip(tmp_path, source):
    (tmp_path / "test_pickle.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path)["findings"]
    unsafe = [
        finding
        for finding in findings
        if finding["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(unsafe) == 1
    assert unsafe[0]["severity"] == "INFO"
    assert unsafe[0]["facts"]["input_provenance"] == "direct_local_serialization"
    assert "custom object reducers still execute code" in unsafe[0]["message"]


@pytest.mark.parametrize(
    "body",
    [
        "def test_external(payload):\n"
        "    pickled = pickle.dumps(payload)\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_alias_escape():\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    escaped = pickled\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_reassigned_bytes():\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    pickled = external_bytes()\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_conditional_write(condition):\n"
        "    local_value = Factory()\n"
        "    if condition:\n        pickled = pickle.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_mismatched_serializer():\n"
        "    local_value = Factory()\n"
        "    pickled = dill.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_conditional_load(condition):\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    if condition:\n        restored = pickle.loads(pickled)\n"
        "    assert restored\n",
        "def test_serializer_replaced():\n"
        "    pickle.dumps = external_dumps\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    assert restored\n",
    ],
)
def test_security_scan_keeps_uncertain_local_pickle_bytes_blocked(tmp_path, body):
    (tmp_path / "test_pickle.py").write_text(
        "import pickle\nimport dill\n" + body, encoding="utf-8"
    )
    unsafe = [
        finding
        for finding in security_scan(tmp_path)["findings"]
        if finding["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert unsafe
    assert all(finding["severity"] == "HIGH" for finding in unsafe)


def test_security_scan_does_not_credit_pickle_import_after_use(tmp_path):
    (tmp_path / "test_pickle.py").write_text(
        "def test_import_after_use():\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    import pickle\n"
        "    assert restored\n",
        encoding="utf-8",
    )
    assert not any(
        finding["severity"] == "INFO" for finding in security_scan(tmp_path)["findings"]
    )


def test_security_scan_keeps_local_pickle_outside_test_source_unverified(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "pickle_flow.py").write_text(
        "import pickle\n"
        "def restore_local_value():\n"
        "    local_value = Factory()\n"
        "    pickled = pickle.dumps(local_value)\n"
        "    restored = pickle.loads(pickled)\n"
        "    return restored\n",
        encoding="utf-8",
    )
    unsafe = [
        finding
        for finding in security_scan(tmp_path)["findings"]
        if finding["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert unsafe
    assert all(finding["severity"] == "HIGH" for finding in unsafe)


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

    import factoryline.context_efficiency as context_module
    import factoryline.review_audits as module

    for owner, name in (
        (module, "security_scan"),
        (module, "_tenant_contract_bindings"),
        (module, "_tenant_binding_entry"),
        (module, "_tenant_binding_parts"),
        (module, "_normalize_tenant_selector"),
        (module, "_scan_security_sources"),
        (context_module, "_consume_security_snapshots"),
        (context_module, "_scan_missing_security_snapshot"),
    ):
        count = 1
        tree = ast.parse(inspect.getsource(getattr(owner, name)))
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


def test_oracle_layout_reuses_structure_but_restores_annotations(monkeypatch):
    import ast
    import factoryline.review_audits as module

    function = ast.parse(
        "def subject():\n    values = [check(x) for check in checks]\n    assert values\n"
    ).body[0]
    function._oracle_layout = None
    original = module._oracle_ancestor_map
    calls = []

    def parents(*args):
        calls.append(None)
        return original(*args)

    monkeypatch.setattr(module, "_oracle_ancestor_map", parents)
    first = module._test_oracle_body_nodes(function, {"check": "pytest.fail"})
    assert not any(isinstance(n, ast.Call) for n in first)
    first.clear()
    second = module._test_oracle_body_nodes(function, {})
    assert any(isinstance(n, ast.Call) for n in second)
    for child in second:
        child._oracle_parent = object()
        child._oracle_scope = object()
    restored = module._test_oracle_body_nodes(function, {})
    for child in restored:
        expected = next(
            (
                parent
                for parent, descendant in child._oracle_ancestors
                if descendant is child
            ),
            None,
        )
        assert child._oracle_parent is expected
        assert child._oracle_scope is function
    assert len(calls) == 1


def test_unenrolled_oracle_layout_is_not_cached_after_ast_changes():
    import ast
    import factoryline.review_audits as module

    function = ast.parse("def subject(): first()").body[0]
    module._test_oracle_body_nodes(function, {})
    assert not hasattr(function, "_oracle_layout")
    function.body.extend(ast.parse("second()").body)
    nodes = module._test_oracle_body_nodes(function, {})
    assert {n.func.id for n in nodes if isinstance(n, ast.Call)} == {"first", "second"}


def test_scanner_resets_oracle_layout_for_changed_tree(tmp_path):
    import ast
    import factoryline.review_audits as module

    tree = ast.parse(
        "def test_subject():\n    result = first()\n    assert result == 1"
    )
    function = tree.body[0]
    module._security_scan_tree(tmp_path, tmp_path / "test_subject.py", tree)
    module._test_oracle_body_nodes(function, {})
    function.body.extend(ast.parse("second()").body)
    module._security_scan_tree(tmp_path, tmp_path / "test_subject.py", tree)
    nodes = module._test_oracle_body_nodes(function, {})
    assert {n.func.id for n in nodes if isinstance(n, ast.Call)} == {"first", "second"}


def test_oracle_snapshot_layout_is_fresh_for_changed_source(tmp_path):
    import factoryline.review_audits as module

    path = tmp_path / "helper.py"
    first = module._oracle_snapshots(tmp_path, [path], {path: b"def helper(): first()"})
    function = first[path].body[0]
    assert function._oracle_layout is None
    module._test_oracle_body_nodes(function, {})
    assert function._oracle_layout is not None
    second = module._oracle_snapshots(
        tmp_path, [path], {path: b"def helper(): second()"}
    )
    assert second[path].body[0]._oracle_layout is None


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


def test_oracle_imports_skip_resolving_missing_external_candidates(
    tmp_path, monkeypatch
):
    import ast
    import factoryline.review_audits as module

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    caller = tests_dir / "test_app.py"
    caller.write_text("", encoding="utf-8")
    helper = tests_dir / "helpers.py"
    helper.write_text("def check():\n    assert True\n", encoding="utf-8")
    tree = ast.parse(
        "import external_alpha\n"
        "import external_beta\n"
        "from vendor_gamma import Widget\n"
        "from missing_package.deep import Model\n"
        "from helpers import check as local_check\n"
    )
    missing_components = {
        "external_alpha",
        "external_beta",
        "vendor_gamma",
        "missing_package",
        "deep",
        "Widget",
        "Model",
    }
    original_resolve = type(tmp_path).resolve
    missing_candidate_resolves = []

    def observed_resolve(path, *args, **kwargs):
        if path.stem in missing_components or any(
            part in missing_components for part in path.parts
        ):
            missing_candidate_resolves.append(path)
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(type(tmp_path), "resolve", observed_resolve)
    imports = module._oracle_imports(tmp_path, caller, tree, {helper})
    assert imports == {"local_check": (helper.resolve(), "check")}
    assert missing_candidate_resolves == []

    stale_eligible = tmp_path / "stale_eligible.py"
    import_from = ast.parse("from stale_eligible import check\n").body[0]
    assert (
        module._oracle_import_source(
            tmp_path,
            caller,
            import_from,
            "stale_eligible",
            {stale_eligible},
            "check",
        )
        is None
    )


def test_oracle_import_resolution_rejects_symlink_appearing_after_resolve(
    tmp_path, monkeypatch
):
    import ast
    import factoryline.review_audits as module

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    caller = tests_dir / "test_app.py"
    caller.write_text("", encoding="utf-8")
    helper = tests_dir / "helpers.py"
    helper.write_text("def check():\n    assert True\n", encoding="utf-8")
    tree = ast.parse("from helpers import check\n")
    index = {helper.resolve(): helper}
    path_type = type(helper)
    original_resolve = path_type.resolve
    original_is_symlink = path_type.is_symlink
    resolved_candidate = False
    symlink_checks = []

    def observed_resolve(path, *args, **kwargs):
        nonlocal resolved_candidate
        resolved = original_resolve(path, *args, **kwargs)
        if path == helper:
            resolved_candidate = True
        return resolved

    def observed_is_symlink(path):
        if path == helper:
            symlink_checks.append(resolved_candidate)
            if resolved_candidate:
                return True
        return original_is_symlink(path)

    monkeypatch.setattr(path_type, "resolve", observed_resolve)
    monkeypatch.setattr(path_type, "is_symlink", observed_is_symlink)
    assert module._oracle_imports(tmp_path, caller, tree, index) == {}
    assert resolved_candidate
    assert symlink_checks == [True]


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
    assert unconfigured["finding_counts"].get("QUALITY_UNKNOWN_TEST_ORACLE") == 1
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


def test_oracle_context_cache_invalidates_when_provider_inventory_helper_changes(
    tmp_path, monkeypatch
):
    import factoryline.context_efficiency as context_efficiency
    import factoryline.review_audits as module

    test_path = tmp_path / "test_case.py"
    test_path.write_text("def test_case():\n    assert True\n", encoding="utf-8")
    module._oracle_context_cache_clear()
    module._project_oracle_context(
        tmp_path, module._security_source_files(tmp_path), cache_enabled=True
    )
    first_misses = module._oracle_context_cache_info()["misses"]

    monkeypatch.setattr(
        context_efficiency, "provider_source_inventory", lambda *args: []
    )
    contexts, _, _, _ = module._project_oracle_context(
        tmp_path, module._security_source_files(tmp_path), cache_enabled=True
    )

    assert module._oracle_context_cache_info()["misses"] > first_misses
    assert contexts[test_path]["provider_source_inventory_complete"] is False


def test_oracle_context_cache_tracks_provider_helper_code_replacement(
    tmp_path, monkeypatch
):
    import factoryline.context_efficiency as context_efficiency
    import factoryline.review_audits as module

    (tmp_path / "test_types.py").write_text(
        "from typing import assert_type\ndef test_types():\n    assert_type(1, int)\n",
        encoding="utf-8",
    )
    (tmp_path / "poison.py").write_text(
        "def anchor(value):\n    return value + 1\n"
        "namespace = anchor.__globals__['__builtins__']\n"
        "loader = namespace['__import__']\n"
        "provider = loader('ty' + 'ping')\n"
        "def runtime_assertion(value, expected):\n"
        "    assert isinstance(value, expected)\n"
        "provider.assert_type = runtime_assertion\n",
        encoding="utf-8",
    )
    module._oracle_context_cache_clear()
    before = security_scan(tmp_path, cache_enabled=True)
    assert before["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}

    helper = context_efficiency._provider_package_initializers

    def include_poison(root, sources, eligible):
        return [root / "poison.py"]

    monkeypatch.setattr(helper, "__code__", include_poison.__code__)
    warm = security_scan(tmp_path, cache_enabled=True)
    cold = security_scan(tmp_path, cache_enabled=False)

    assert (
        warm["finding_counts"]
        == cold["finding_counts"]
        == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    )


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

    assert expected["state"] == "CLEAN"
    assert actual["state"] == "INCOMPLETE"
    assert actual["sources"] == expected["sources"]
    assert actual["findings"] == expected["findings"]
    assert actual["database_context"]["status"] == "INCOMPLETE"
    assert (
        "database_python_source_retention_limit:app.py"
        in actual["database_context"]["gaps"]
    )
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
    "body,expected",
    [
        ("assert True", "QUALITY_HOLLOW_TEST"),
        ("compute_value()", "QUALITY_UNKNOWN_TEST_ORACLE"),
        (
            "actual = compute_value()\n    assert actual == actual",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        ("assert len(result) >= 0", "QUALITY_UNKNOWN_TEST_ORACLE"),
    ],
)
def test_security_scan_detects_local_hollow_test_oracles(tmp_path, body, expected):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {expected: 1}
    assert result["findings"][0]["facts"]["symbol"] == "test_behavior"


@pytest.mark.parametrize(
    "body,expected",
    [
        ("assert (compute(), expected)", "QUALITY_WEAK_TEST_ORACLE"),
        ("assert (*values, compute())", "QUALITY_WEAK_TEST_ORACLE"),
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
            "QUALITY_UNKNOWN_TEST_ORACLE",
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
    "body,expected",
    [
        ("self.assertTrue(True)", "QUALITY_HOLLOW_TEST"),
        ("self.assertFalse(False)", "QUALITY_HOLLOW_TEST"),
        ("self.assertEqual(1, 1)", "QUALITY_HOLLOW_TEST"),
        ("self.assertTupleEqual((1,), (1,))", "QUALITY_HOLLOW_TEST"),
        ("self.assertListEqual([1], [1])", "QUALITY_HOLLOW_TEST"),
        ("self.assertEqual(value, value)", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("self.assertTrue(compute())", None),
        ("self.assertFalse(compute())", None),
        ("self.assertEqual(compute(), 1)", None),
        ("self.assertTupleEqual(compute(), (1,))", None),
        ("self.assertEqual(obj.value, obj.value)", None),
    ],
)
def test_oracle_precision_unittest_vacuity(tmp_path, body, expected):
    (tmp_path / "test_case.py").write_text(
        "import unittest\nclass Checks(unittest.TestCase):\n"
        "    def test_behavior(self):\n        " + body + "\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"] == ({expected: 1} if expected else {})


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
    "body,expected",
    [
        (
            "expected = 3\n    alias = expected\n    assert alias == expected",
            "QUALITY_HOLLOW_TEST",
        ),
        ("value = value\n    assert value == value", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("result = 3\n    assert result == 3", "QUALITY_HOLLOW_TEST"),
        ("x = 5\n    x = x + 1\n    assert x == 6", "QUALITY_HOLLOW_TEST"),
        ("assert result or True", "QUALITY_UNKNOWN_TEST_ORACLE"),
    ],
)
def test_security_scan_detects_constant_and_boolean_tautologies(
    tmp_path, body, expected
):
    (tmp_path / "test_case.py").write_text("def test_behavior():\n    " + body + "\n")
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {expected: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    "filters,expected",
    [
        (
            "warnings.simplefilter('error', UserWarning)\n"
            "warnings.simplefilter('ignore', UserWarning)\n"
            "emit_user_warning()",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        ("warnings.simplefilter('error', UserWarning)", "QUALITY_HOLLOW_TEST"),
    ],
)
def test_security_scan_does_not_trust_inactive_warning_filter(
    tmp_path, filters, expected
):
    (tmp_path / "test_case.py").write_text(
        "import warnings\n"
        "def test_warning():\n"
        "    with warnings.catch_warnings():\n"
        + "\n".join("        " + line for line in filters.splitlines())
        + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {expected: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_security_scan_ignores_manual_raise_after_unconditional_return(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n    return\n    raise AssertionError('unreachable')\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "handler, expected_code",
    [
        ("UserWarning", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("Warning", "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("(ValueError, UserWarning)", "QUALITY_UNKNOWN_TEST_ORACLE"),
    ],
)
def test_security_scan_rejects_warning_swallowed_outside_context(
    tmp_path, handler, expected_code
):
    (tmp_path / "test_case.py").write_text(
        "import warnings\ndef test_warning():\n"
        "    try:\n        with warnings.catch_warnings():\n"
        "            warnings.simplefilter('error', UserWarning)\n"
        "            warnings.warn('expected', UserWarning)\n"
        f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {expected_code: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_security_scan_accepts_assertion_reraised_from_handler(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    except Exception:\n        raise\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_tenacity_expected_exception_else_branch(tmp_path):
    (tmp_path / "test_asyncio.py").write_text(
        "import tenacity.asyncio as tasyncio\n"
        "from tenacity import stop_after_attempt\n"
        "@asynctest\n"
        "async def test_reraise() -> None:\n"
        "    class CustomError(Exception):\n        pass\n"
        "    try:\n"
        "        async for attempt in tasyncio.AsyncRetrying(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        "            with attempt:\n                raise CustomError\n"
        "    except CustomError:\n        pass\n"
        "    else:\n        raise Exception\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "mutation",
    [
        "tasyncio.AsyncRetrying = noop",
        "setattr(tasyncio, 'AsyncRetrying', noop)",
        "tasyncio.__setattr__('AsyncRetrying', noop)",
        "retry_module = tasyncio",
    ],
)
def test_security_scan_rejects_mutated_retry_iteration_protocol(tmp_path, mutation):
    (tmp_path / "test_asyncio.py").write_text(
        "import tenacity.asyncio as tasyncio\n"
        "from tenacity import stop_after_attempt\n"
        "class CustomError(Exception):\n    pass\n"
        "def noop(*args, **kwargs):\n    return []\n"
        "async def test_reraise():\n"
        f"    {mutation}\n"
        "    try:\n"
        "        async for attempt in tasyncio.AsyncRetrying(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        "            with attempt:\n                raise CustomError\n"
        "    except CustomError:\n        pass\n"
        "    else:\n        raise Exception\n",
        encoding="utf-8",
    )
    # Unresolved provider/context effects and surviving raises do not prove inert completion.
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "imports,mutation,runner,loop",
    [
        (
            "import tenacity as t\nimport tenacity as other\n",
            "other.Retrying = noop",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity\n",
            "tenacity.Retrying = noop",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity.asyncio as tasyncio\nimport tenacity as other\n",
            "other.asyncio.AsyncRetrying = noop",
            "tasyncio.AsyncRetrying",
            "        async for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity as other\n",
            "del other.Retrying",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity as other\n",
            "other.__setattr__('Retrying', noop)",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity as other\nimport sys\n",
            "sys.modules['tenacity'].Retrying = noop",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity as other\nimport importlib\n",
            "importlib.import_module('tenacity').Retrying = noop",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nimport tenacity as other\n",
            "__import__('tenacity').Retrying = noop",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nfrom tenacity import Retrying as direct_retry\n",
            "saved_retry = direct_retry",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
        (
            "import tenacity as t\nfrom tenacity import Retrying as direct_retry\n",
            "consume(direct_retry)",
            "t.Retrying",
            "        for attempt in {runner}(stop=stop_after_attempt(1), reraise=True):\n"
            "            with attempt:\n                raise CustomError\n",
        ),
    ],
    ids=[
        "aliased-module-write",
        "unaliased-root-write",
        "parent-module-write",
        "aliased-module-delete",
        "reflective-module-write",
        "sys-module-write",
        "importlib-module-write",
        "dynamic-import-module-write",
        "direct-api-import-assignment-escape",
        "direct-api-import-call-argument-escape",
    ],
)
def test_security_scan_rejects_retry_module_mutation_through_equivalent_imports(
    tmp_path, imports, mutation, runner, loop
):
    (tmp_path / "test_retry.py").write_text(
        imports
        + "from tenacity import stop_after_attempt\n"
        + "class CustomError(Exception):\n    pass\n"
        + "def noop(*args, **kwargs):\n    pass\n"
        + mutation
        + "\nasync def test_reraise():\n"
        + "    try:\n"
        + loop.format(runner=runner)
        + "    except CustomError:\n        pass\n"
        + "    else:\n        raise Exception\n",
        encoding="utf-8",
    )

    # Unresolved provider/context effects and surviving raises do not prove inert completion.
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_security_scan_accepts_unmutated_equivalent_retry_module_imports(tmp_path):
    (tmp_path / "test_retry.py").write_text(
        "import tenacity as t\n"
        "import tenacity as other\n"
        "from tenacity import stop_after_attempt\n"
        "class CustomError(Exception):\n    pass\n"
        "async def test_reraise():\n"
        "    try:\n"
        "        for attempt in t.Retrying(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        "            with attempt:\n                raise CustomError\n"
        "    except CustomError:\n        pass\n"
        "    else:\n        raise Exception\n",
        encoding="utf-8",
    )

    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_accepts_closed_direct_retry_factory_import(tmp_path):
    (tmp_path / "test_retry.py").write_text(
        "from tenacity import Retrying as retry_factory\n"
        "from tenacity import stop_after_attempt\n"
        "class CustomError(Exception):\n    pass\n"
        "async def test_reraise():\n"
        "    try:\n"
        "        for attempt in retry_factory(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        "            with attempt:\n                raise CustomError\n"
        "    except CustomError:\n        pass\n"
        "    else:\n        raise Exception\n",
        encoding="utf-8",
    )

    assert security_scan(tmp_path)["findings"] == []


@pytest.mark.parametrize(
    "target,context,mutation",
    [
        ("attempt", "attempt", "attempt = nullcontext()"),
        ("retry_context", "retry_context", "retry_context = nullcontext()"),
        ("attempt", "attempt", "attempt_alias = attempt"),
        ("attempt", "attempt", "locals()['attempt'] = nullcontext()"),
        (
            "attempt",
            "attempt",
            "from builtins import globals as get_scope; get_scope()['attempt'] = nullcontext()",
        ),
        ("attempt", "attempt", "attempt.__setattr__('__enter__', noop)"),
    ],
    ids=[
        "attempt-rebound",
        "renamed-attempt-rebound",
        "attempt-escaped",
        "reflective-local-rebind",
        "aliased-reflective-local-rebind",
        "attempt-method-mutation",
    ],
)
def test_security_scan_rejects_retry_attempt_without_closed_capability_use(
    tmp_path, target, context, mutation
):
    (tmp_path / "test_asyncio.py").write_text(
        "import tenacity.asyncio as tasyncio\n"
        "from tenacity import stop_after_attempt\n"
        "from contextlib import nullcontext\n"
        "class CustomError(Exception):\n    pass\n"
        "def noop(*args, **kwargs):\n    pass\n"
        "async def test_reraise():\n"
        "    try:\n"
        f"        async for {target} in tasyncio.AsyncRetrying(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        f"            {mutation}\n"
        f"            with ({context}):\n"
        "                raise CustomError\n"
        "    except CustomError:\n"
        "        pass\n"
        "    else:\n"
        "        raise Exception\n",
        encoding="utf-8",
    )

    # Unresolved provider/context effects and surviving raises do not prove inert completion.
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "target,context",
    [("attempt", "attempt"), ("retry_context", "(retry_context)")],
    ids=["baseline-name", "renamed-parenthesized-context"],
)
def test_security_scan_accepts_closed_retry_attempt_name_variants(
    tmp_path, target, context
):
    (tmp_path / "test_asyncio.py").write_text(
        "import tenacity.asyncio as tasyncio\n"
        "from tenacity import stop_after_attempt\n"
        "class CustomError(Exception):\n    pass\n"
        "async def test_reraise():\n"
        "    try:\n"
        f"        async for {target} in tasyncio.AsyncRetrying(\n"
        "            stop=stop_after_attempt(1), reraise=True\n"
        "        ):\n"
        f"            with {context}:\n"
        "                raise CustomError\n"
        "    except CustomError:\n"
        "        pass\n"
        "    else:\n"
        "        raise Exception\n",
        encoding="utf-8",
    )

    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_keeps_unexpected_exception_propagation_effective(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "class ExpectedError(Exception):\n    pass\n"
        "class OtherError(Exception):\n    pass\n"
        "def operation():\n    raise OtherError\n"
        "def test_behavior():\n"
        "    try:\n        operation()\n"
        "    except ExpectedError:\n        pass\n"
        "    else:\n        raise RuntimeError\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["findings"] == []


def test_security_scan_rejects_unrelated_call_before_expected_exception_raise(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def noop():\n    pass\n"
        "def test_behavior():\n"
        "    try:\n        noop()\n        raise ValueError()\n"
        "    except ValueError:\n        pass\n"
        "    else:\n        raise RuntimeError\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}


@pytest.mark.parametrize(
    "body, expected_code",
    [
        pytest.param(
            "    try:\n        operation()\n    except CustomError:\n        pass\n",
            "QUALITY_HOLLOW_TEST",
            id="custom-only-catch",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "    except Exception:\n        pass\n"
            "    else:\n        raise RuntimeError\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="broad-exception-else-raise",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "    except (CustomError, Exception):\n        pass\n"
            "    else:\n        raise RuntimeError\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="tuple-broad-catch-else-raise",
        ),
        pytest.param(
            "    with suppress(Exception):\n"
            "        try:\n            operation()\n"
            "        except CustomError:\n            pass\n"
            "        else:\n            raise RuntimeError\n",
            "QUALITY_HOLLOW_TEST",
            id="suppress-known-raise",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "    except CustomError:\n        pass\n"
            "    else:\n        raise RuntimeError\n"
            "    finally:\n        return None\n",
            "QUALITY_HOLLOW_TEST",
            id="finally-return",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "    except CustomError:\n        pass\n"
            "    else:\n        if False:\n            raise RuntimeError\n",
            "QUALITY_HOLLOW_TEST",
            id="unreachable-else-raise",
        ),
        pytest.param(
            "    raise RuntimeError\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="unconditional-runtime-error",
        ),
        pytest.param(
            "    RuntimeError()\n",
            "QUALITY_HOLLOW_TEST",
            id="discarded-runtime-error-call",
        ),
        pytest.param(
            "    try:\n"
            "        raise CustomError()\n"
            "    except CustomError:\n"
            "        pass\n"
            "    else:\n"
            "        raise RuntimeError\n",
            "QUALITY_HOLLOW_TEST",
            id="caught-custom-error",
        ),
        pytest.param(
            "    try:\n"
            "        def nested():\n"
            "            operation()\n"
            "    except CustomError:\n"
            "        pass\n"
            "    else:\n"
            "        raise RuntimeError\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="nested-def-else-raise",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "        if True:\n            raise CustomError()\n"
            "    except CustomError:\n        pass\n"
            "    else:\n        raise RuntimeError\n",
            "QUALITY_HOLLOW_TEST",
            id="caught-conditional-custom-error",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "        with nullcontext():\n            raise CustomError()\n"
            "    except CustomError:\n        pass\n"
            "    else:\n        raise RuntimeError\n",
            "QUALITY_HOLLOW_TEST",
            id="caught-nullcontext-error",
        ),
        pytest.param(
            "    try:\n        operation()\n"
            "        try:\n            raise CustomError()\n"
            "        except CustomError:\n            pass\n"
            "    except CustomError:\n        pass\n"
            "    else:\n        raise RuntimeError\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="nested-catch-outer-else-raise",
        ),
    ],
)
def test_security_scan_rejects_unbounded_expected_exception_shapes(
    tmp_path, body, expected_code
):
    (tmp_path / "test_case.py").write_text(
        "from contextlib import nullcontext, suppress\n"
        "class CustomError(Exception):\n    pass\n"
        "def operation():\n    pass\n"
        "def test_behavior():\n" + body,
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {expected_code: 1}


@pytest.mark.parametrize(
    "imports,handler,expected_code",
    [
        (
            "from builtins import BaseException as Ignore\n",
            "Ignore",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "from builtins import Exception as Ignore\n",
            "Ignore",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        (
            "import builtins as bi\n",
            "bi.BaseException",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
    ],
)
def test_security_scan_detects_aliased_exception_catch(
    tmp_path, imports, handler, expected_code
):
    (tmp_path / "test_case.py").write_text(
        imports
        + "def test_behavior():\n"
        + "    try:\n        assert compute() == 4\n"
        + f"    except {handler}:\n        pass\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {expected_code: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_security_scan_detects_assertion_suppressed_in_finally(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    try:\n        assert compute() == 4\n"
        "    finally:\n        return None\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 2
    }


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
    findings_by_test = {
        item["facts"]["symbol"]: item["code"]
        for item in security_scan(tmp_path)["findings"]
    }
    assert findings_by_test == {
        "test_suppress": "QUALITY_UNKNOWN_TEST_ORACLE",
        "test_unreachable": "QUALITY_HOLLOW_TEST",
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
        "QUALITY_UNKNOWN_TEST_ORACLE": 1,
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
    "source, expected",
    [
        # No marker or typed fixture: the untyped parameter alone never exempts.
        (
            "def test_security_invariant(benchmark):\n"
            "    @benchmark\n"
            "    def run():\n"
            "        dangerous_operation()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        # Marked, but the nested decorator is not the benchmark fixture.
        (
            "import pytest\n"
            "@pytest.mark.benchmark\n"
            "def test_security_invariant(benchmark):\n"
            "    @other_decorator\n"
            "    def run():\n"
            "        dangerous_operation()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        # Marked, but the decorator is a call to something that only looks similar.
        (
            "import pytest\n"
            "@pytest.mark.benchmark\n"
            "def test_security_invariant(benchmark):\n"
            "    @benchmarks\n"
            "    def run():\n"
            "        dangerous_operation()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        # Marked, but no fixture parameter exists for the decorator to name.
        (
            "import pytest\n"
            "@pytest.mark.benchmark\n"
            "def test_security_invariant():\n"
            "    @benchmark\n"
            "    def run():\n"
            "        dangerous_operation()\n",
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        # Marked and decorated, but the decorated function is never the nested one.
        (
            "import pytest\n"
            "@pytest.mark.benchmark\n"
            "def test_security_invariant(benchmark):\n"
            "    def run():\n"
            "        dangerous_operation()\n",
            "QUALITY_HOLLOW_TEST",
        ),
    ],
)
def test_security_scan_rejects_lookalike_decorator_form_benchmarks(
    tmp_path, source, expected
):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    assert security_scan(tmp_path)["finding_counts"] == {expected: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


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


def test_security_scan_does_not_assume_tenancy_for_sqlalchemy_reads(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def fetch_user(user_id):\n"
        "    return session.query(User).filter_by(id=user_id).first()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"].get("SECURITY_TENANT_READ_UNDECLARED", 0) == 0


def test_security_scan_does_not_assume_tenancy_for_django_reads(tmp_path):
    (tmp_path / "service.py").write_text(
        "from django.db import models\n"
        "def list_users():\n"
        "    return User.objects.exclude(is_active=False)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"].get("SECURITY_TENANT_READ_UNDECLARED", 0) == 0


def test_security_scan_does_not_assume_tenancy_for_sqlmodel_reads(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlmodel import Session, select\n"
        "def list_users(session: Session):\n"
        "    return session.exec(select(User))\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"].get("SECURITY_TENANT_READ_UNDECLARED", 0) == 0


def test_empty_v1_tenant_policy_is_distinct_from_absent_policy(tmp_path):
    from factoryline.review_audits import load_tenant_read_contract
    import factoryline.review_audits as audit

    (tmp_path / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def list_users():\n"
        "    return session.query(User).filter_by(active=True).first()\n",
        encoding="utf-8",
    )
    assert load_tenant_read_contract(tmp_path)[2]["policy_applies"] is False
    audit._oracle_context_cache_clear()
    absent = security_scan(tmp_path, cache_enabled=False)
    security_scan(tmp_path, cache_enabled=True)
    hits = audit._oracle_context_cache_info()["hits"]
    absent_warm = security_scan(tmp_path, cache_enabled=True)
    assert absent["finding_counts"].get("SECURITY_TENANT_READ_UNDECLARED", 0) == 0
    assert absent_warm["finding_counts"].get("SECURITY_TENANT_READ_UNDECLARED", 0) == 0
    assert audit._oracle_context_cache_info()["hits"] == hits + 1

    folder = tmp_path / ".factory"
    folder.mkdir()
    (folder / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    calls, bindings, evidence = load_tenant_read_contract(tmp_path)
    assert calls == bindings == ()
    assert "scoped_reads" not in evidence
    assert evidence["policy_applies"] is True
    options = {
        "tenant_read_calls": calls,
        "tenant_read_bindings": bindings,
        "tenant_read_scopes": evidence.get("scoped_reads"),
        "tenant_policy_applies": evidence["policy_applies"],
    }
    declared_empty = security_scan(tmp_path, cache_enabled=False, **options)
    security_scan(tmp_path, cache_enabled=True, **options)
    hits = audit._oracle_context_cache_info()["hits"]
    declared_empty_warm = security_scan(tmp_path, cache_enabled=True, **options)
    assert declared_empty["finding_counts"] == {"SECURITY_TENANT_READ_UNDECLARED": 1}
    assert declared_empty["tenant_read_contract"]["policy_applies"] is True
    assert declared_empty_warm["finding_counts"] == declared_empty["finding_counts"]
    assert audit._oracle_context_cache_info()["hits"] == hits + 1
    (folder / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v2", "reads": []}),
        encoding="utf-8",
    )
    with pytest.raises(ReviewAuditError, match="nonempty read scopes"):
        load_tenant_read_contract(tmp_path)
    with pytest.raises(ReviewAuditError, match="must be a boolean"):
        security_scan(tmp_path, tenant_policy_applies="true")


def test_security_scan_flags_unlisted_read_when_tenant_policy_applies(tmp_path):
    (tmp_path / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def fetch_user(user_id):\n"
        "    return session.query(User).filter_by(id=user_id).first()\n",
        encoding="utf-8",
    )
    result = security_scan(
        tmp_path,
        tenant_read_calls=("store.fetch",),
        tenant_policy_applies=False,
    )
    assert result["finding_counts"]["SECURITY_TENANT_READ_UNDECLARED"] == 1


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
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
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
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


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
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


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
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_security_scan_does_not_trust_unused_assertion_callback(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    def fail_on_read(*args):\n"
        "        raise AssertionError('unexpected read')\n"
        "    compute_value()\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path)
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


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
        (
            "runner.invoke(cli)",
            "assert compute() == 4",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=True)",
            "assert compute() == 4",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=False)",
            "assert True",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "runner.invoke(cli, catch_exceptions=False)",
            "assert compute() is not None",
            {"QUALITY_WEAK_TEST_ORACLE": 1},
        ),
        ("pass", "assert compute() == 4", {"QUALITY_WEAK_TEST_ORACLE": 1}),
        (
            "runner.invoke(other, catch_exceptions=False)",
            "assert compute() == 4",
            {"QUALITY_WEAK_TEST_ORACLE": 1},
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
    "body,expected",
    [
        pytest.param(
            "try:\n        runner.invoke(cli, catch_exceptions=False)\n    except AssertionError:\n        pass",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="swallowed-assertion",
        ),
        pytest.param(
            "with suppress(AssertionError):\n        runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="suppressed-assertion",
        ),
        pytest.param(
            "with suppress(Exception):\n        runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="suppressed-exception",
        ),
        pytest.param(
            "if False:\n        runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_WEAK_TEST_ORACLE",
            id="unreachable-if",
        ),
        pytest.param(
            "return\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_WEAK_TEST_ORACLE",
            id="after-return",
        ),
        pytest.param(
            "runner = fake_runner\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="rebound-runner",
        ),
        pytest.param(
            "runner.invoke = swallow\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="rebound-invoke",
        ),
        pytest.param(
            "setattr(runner, 'invoke', swallow)\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="setattr-invoke",
        ),
        pytest.param(
            "configure(runner)\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="escaped-runner",
        ),
        pytest.param(
            "other = runner\n    other.invoke = swallow\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="mutated-runner-alias",
        ),
        pytest.param(
            "cli = other\n    runner.invoke(cli, catch_exceptions=False)",
            "QUALITY_UNKNOWN_TEST_ORACLE",
            id="rebound-command",
        ),
    ],
)
def test_security_scan_keeps_swallowed_or_rebound_click_callback_hollow(
    tmp_path, body, expected
):
    (tmp_path / "test_case.py").write_text(
        "import click\nfrom click.testing import CliRunner\n"
        "from contextlib import suppress\ndef test_behavior():\n"
        "    @click.command()\n    def cli():\n        assert compute() == 4\n"
        "    runner = CliRunner()\n    " + body + "\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {expected: 1}


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
        ("return fake_runner", {"QUALITY_UNKNOWN_TEST_ORACLE": 1}),
        (
            "if arbitrary():\n        return fake_runner\n    return CliRunner()",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


def test_security_scan_keeps_uninvoked_command_with_recursive_invoke_hollow(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "import click\nfrom click.testing import CliRunner\ndef test_behavior():\n"
        "    runner = CliRunner()\n    @click.command()\n    def cli():\n"
        "        result = runner.invoke(cli, catch_exceptions=False)\n"
        "        assert result.output == 'value'\n",
        encoding="utf-8",
    )
    assert security_scan(tmp_path)["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}


@pytest.mark.parametrize(
    "filename, declared, body, expected",
    [
        (
            "typing_probe.py",
            True,
            "assert_type(compute(), int)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "typing_probe.py",
            False,
            "assert_type(compute(), int)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 2},
        ),
        (
            "test_runtime.py",
            True,
            "assert_type(compute(), int)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 2},
        ),
        (
            "typing_probe.py",
            True,
            "compute()",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 2},
        ),
        (
            "typing_probe.py",
            True,
            "assert_type = lambda *args: None\n    assert_type(compute(), int)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 2},
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
    assert result["finding_counts"] == expected
    if declared and filename == "typing_probe.py":
        edge = next(
            item
            for item in result["oracle_context"]["resolved_edges"]
            if item["kind"] == "static_type_configuration"
        )
        assert edge["target"] == "pyproject.toml"
        assert len(edge["sha256"]) == 64


def _write_ty_invocation(root, command="ty check"):
    (root / "tox.ini").write_text(
        f"[testenv]\ncommands =\n    {command}\n", encoding="utf-8"
    )


@pytest.mark.parametrize(
    "override",
    [
        "changedir = subproject",
        "setenv = TY_CONFIG_FILE=other.toml",
        "passenv = TY_*",
        "passenv = *",
    ],
)
def test_ty_intent_rejects_tox_execution_context_overrides(tmp_path, override):
    (tmp_path / "test_types.py").write_text(
        "from typing import assert_type\ndef test_types():\n    assert_type(1, int)\n"
    )
    (tmp_path / "pyproject.toml").write_text('[tool.ty.src]\ninclude = ["."]\n')
    (tmp_path / "tox.ini").write_text(f"[testenv]\n{override}\ncommands = ty check\n")
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1


@pytest.mark.parametrize(
    ("ignore_file", "pattern"),
    [
        (".gitignore", "tests/"),
        (".gitignore", "/test*"),
        (".gitignore", "/tests*/"),
        (".gitignore", "tests"),
        ("tests/.gitignore", "sub/"),
        ("tests/.gitignore", "/sub/test_types.py"),
    ],
)
def test_ty_intent_respects_directory_and_nested_ignore_scope(
    tmp_path, ignore_file, pattern
):
    tests = tmp_path / "tests" / "sub"
    tests.mkdir(parents=True)
    (tests / "test_types.py").write_text(
        "from typing import assert_type\ndef test_types():\n    assert_type(1, int)\n"
    )
    (tmp_path / "pyproject.toml").write_text('[tool.ty.src]\ninclude = ["tests"]\n')
    _write_ty_invocation(tmp_path)
    (tmp_path / ignore_file).write_text(pattern + "\n")
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1


def test_ty_intent_rejects_mutated_assertion_provider(tmp_path):
    (tmp_path / "test_types.py").write_text(
        "import typing\ntyping.assert_type = lambda *args: None\n"
        "def test_types():\n    typing.assert_type(1, int)\n"
    )
    (tmp_path / "pyproject.toml").write_text('[tool.ty.src]\ninclude = ["."]\n')
    _write_ty_invocation(tmp_path)
    assert security_scan(tmp_path)["finding_counts"].get("QUALITY_HOLLOW_TEST") == 1


@pytest.mark.parametrize(
    ("config", "expected_hollow"),
    [
        ('[tool.ty.src]\ninclude = ["tests"]\n', 0),
        ('[tool.mypy]\nfiles = ["tests"]\n', 1),
        ("", 1),
    ],
)
def test_ty_assert_type_counts_only_as_declared_type_intent(
    tmp_path, config, expected_hollow
):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        "from typing import assert_type\n"
        "def test_static_types():\n"
        "    assert_type(1, int)\n",
        encoding="utf-8",
    )
    if config:
        (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    if "tool.ty" in config:
        _write_ty_invocation(tmp_path)

    result = security_scan(tmp_path)

    assert result["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == expected_hollow
    if "tool.ty" in config:
        edge = next(
            item
            for item in result["oracle_context"]["resolved_edges"]
            if item["kind"] == "static_type_configuration" and item["checker"] == "ty"
        )
        assert edge["execution_state"] == "NOT_VERIFIED"


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("from typing import assert_type", "assert_type(1, int)"),
        ("import typing as ty", "ty.assert_type(1, int)"),
        (
            "from typing_extensions import assert_type as check_type",
            "check_type(1, int)",
        ),
    ],
)
def test_ty_intent_resolves_supported_assert_type_aliases(tmp_path, imports, call):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        f"{imports}\ndef test_static_types():\n    {call}\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ty.src]\ninclude = ["tests"]\n', encoding="utf-8"
    )
    _write_ty_invocation(tmp_path)

    result = security_scan(tmp_path)

    assert result["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 0


@pytest.mark.parametrize(
    ("config", "body"),
    [
        (
            '[tool.ty.src]\ninclude = ["tests"]\nexclude = ["tests"]\n',
            "assert_type(1, int)",
        ),
        (
            '[tool.ty.src]\ninclude = ["tests"]\n\n[tool.ty.rules]\n'
            'type-assertion-failure = "ignore"\n',
            "assert_type(1, int)",
        ),
        (
            '[tool.ty.src]\ninclude = ["tests"]\n',
            "assert_type(1, int)  # ty: ignore[type-assertion-failure]",
        ),
        (
            '[tool.ty.src]\ninclude = ["tests"]\n',
            "assert_type = lambda *args: None\n    assert_type(1, int)",
        ),
    ],
)
def test_ty_intent_rejects_excluded_disabled_suppressed_or_shadowed_calls(
    tmp_path, config, body
):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        "from typing import assert_type\ndef test_static_types():\n    " + body + "\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    _write_ty_invocation(tmp_path)

    result = security_scan(tmp_path)

    assert result["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1


def test_ty_intent_does_not_mask_empty_tests_or_stale_rule_cache(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    source = tests / "test_types.py"
    source.write_text(
        "from typing import assert_type\n"
        "def test_static_types():\n    assert_type(1, int)\n"
        "def test_empty_runtime():\n    pass\n",
        encoding="utf-8",
    )
    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.ty.src]\ninclude = ["tests"]\n', encoding="utf-8")
    _write_ty_invocation(tmp_path)

    selected = security_scan(tmp_path)
    config.write_text(
        '[tool.ty.src]\ninclude = ["tests"]\n\n[tool.ty.rules]\n'
        'type-assertion-failure = "ignore"\n',
        encoding="utf-8",
    )
    disabled = security_scan(tmp_path)

    assert selected["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1
    assert disabled["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 2


def test_ty_intent_fails_closed_for_config_overrides_and_unsupported_globs(
    tmp_path, monkeypatch
):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        "from typing import assert_type\ndef test_static_types():\n    assert_type(1, int)\n",
        encoding="utf-8",
    )
    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.ty.src]\ninclude = ["tests"]\n', encoding="utf-8")
    _write_ty_invocation(tmp_path)
    (tmp_path / "ty.toml").write_text('[src]\ninclude = ["src"]\n', encoding="utf-8")

    ty_file = security_scan(tmp_path)
    (tmp_path / "ty.toml").unlink()
    monkeypatch.setenv("TY_CONFIG_FILE", str(tmp_path / "external-ty.toml"))
    env_file = security_scan(tmp_path)
    monkeypatch.delenv("TY_CONFIG_FILE")
    config.write_text('[tool.ty.src]\ninclude = ["**"]\n', encoding="utf-8")
    glob_config = security_scan(tmp_path)

    for result in (ty_file, env_file, glob_config):
        assert result["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1


def test_ty_ignore_files_support_simple_wildcards_and_reject_complex_globs(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        "from typing import assert_type\ndef test_static_types():\n"
        "    assert_type(1, int)\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ty.src]\ninclude = ["tests"]\n', encoding="utf-8"
    )
    _write_ty_invocation(tmp_path)
    ignore = tmp_path / ".gitignore"
    ignore.write_text("*.so\n.coverage*\ncoverage*\n", encoding="utf-8")

    selected = security_scan(tmp_path)
    ignore.write_text("test_types.py\n", encoding="utf-8")
    excluded = security_scan(tmp_path)
    ignore.write_text("coverage*generated\n", encoding="utf-8")
    unknown = security_scan(tmp_path)

    assert selected["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 0
    assert excluded["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1
    assert unknown["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1


def test_ty_intent_requires_declared_no_target_invocation(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_types.py").write_text(
        "from typing import assert_type\ndef test_static_types():\n"
        "    assert_type(1, int)\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ty.src]\ninclude = ["tests"]\n', encoding="utf-8"
    )

    missing = security_scan(tmp_path)
    targeted = []
    for command in ("ty check tests/test_types.py", "uv run ty check"):
        _write_ty_invocation(tmp_path, command)
        targeted.append(security_scan(tmp_path))
    _write_ty_invocation(tmp_path)
    declared = security_scan(tmp_path)

    assert missing["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1
    assert all(
        result["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 1
        for result in targeted
    )
    assert declared["finding_counts"].get("QUALITY_HOLLOW_TEST", 0) == 0


@pytest.mark.parametrize(
    "body, expected",
    [
        ("class Custom(base):\n            pass", {}),
        ("class Custom:\n            pass", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "warnings.simplefilter('ignore')\n        class Custom(base):\n            pass",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
        # compute() is undefined: a failing name lookup is not a proven inert test.
        result = security_scan(tmp_path)
        assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
        assert result["findings"][0]["facts"]["evidence_state"] == "UNKNOWN"


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
    original_snapshot = module._security_scan_file_snapshot

    def mutate_after_read(*args):
        result = original(*args)
        config.write_text("[tool.mypy]\nfiles = []\n", encoding="utf-8")
        return result

    def mutate_after_snapshot(*args, **kwargs):
        result = original_snapshot(*args, **kwargs)
        config.write_text("[tool.mypy]\nfiles = []\n", encoding="utf-8")
        return result

    monkeypatch.setattr(module, "_security_scan_file", mutate_after_read)
    monkeypatch.setattr(module, "_security_scan_file_snapshot", mutate_after_snapshot)
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
    original_snapshot = module._security_scan_file_snapshot

    def mutate_after_scan(scanner, *args, **kwargs):
        result = scanner(*args, **kwargs)
        source.write_text("def run(value):\n    eval(value)\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        module,
        "_security_scan_file" if cache_enabled else "_security_scan_file_snapshot",
        lambda *args, **kwargs: mutate_after_scan(
            original if cache_enabled else original_snapshot, *args, **kwargs
        ),
    )
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
    import factoryline.review_audits as audit

    (tmp_path / "app.py").write_text(
        "def read(principal):\n    return store.fetch(principal.tenant_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "test_other.py").write_text(
        "def test_hollow():\n    assert True\n", encoding="utf-8"
    )
    (tmp_path / "other.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def list_users():\n"
        "    return session.query(User).first()\n",
        encoding="utf-8",
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
    audit._oracle_context_cache_clear()
    first = security_scan(
        tmp_path,
        tenant_read_calls=calls,
        tenant_read_bindings=bindings,
        tenant_read_scopes=evidence["scoped_reads"],
        cache_enabled=True,
    )
    hits = audit._oracle_context_cache_info()["hits"]
    result = security_scan(
        tmp_path,
        tenant_read_calls=calls,
        tenant_read_bindings=bindings,
        tenant_read_scopes=evidence["scoped_reads"],
        cache_enabled=True,
    )
    assert audit._oracle_context_cache_info()["hits"] == hits + 1
    assert result["audit_sha256"] == first["audit_sha256"]
    assert result["finding_counts"] == first["finding_counts"]
    assert result["files_scanned"] == 3
    assert [item["code"] for item in result["findings"]] == ["QUALITY_HOLLOW_TEST"]
    assert evidence["state"] == "loaded"
    assert evidence["policy_applies"] is False


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
    "body,eligible,diagnostic",
    [
        ("validate(5)", True, "QUALITY_UNKNOWN_TEST_ORACLE"),
        ("pass", False, "QUALITY_HOLLOW_TEST"),
        ("validate(5)\n    assert True", False, "QUALITY_WEAK_TEST_ORACLE"),
        (
            "try:\n        assert result == 4\n    except AssertionError:\n        pass",
            False,
            "QUALITY_UNKNOWN_TEST_ORACLE",
        ),
        ("def helper():\n        assert compute() == 4", False, "QUALITY_HOLLOW_TEST"),
    ],
)
def test_runtime_oracle_eligibility_does_not_weaken_static_scan(
    tmp_path, body, eligible, diagnostic
):
    (tmp_path / "test_app.py").write_text(
        "def test_validate():\n    " + body + "\n", encoding="utf-8"
    )
    result = security_scan(tmp_path)
    import ast
    from factoryline.review_audits import _completion_only_oracle

    node = ast.parse("def test_validate():\n    " + body + "\n").body[0]
    assert _completion_only_oracle(node) is eligible
    # Capability eligibility never upgrades a static diagnostic. Complete-body
    # proofs are HOLLOW, locally weak assertions retain WEAK, opaque calls UNKNOWN.
    assert result["finding_counts"] == {diagnostic: 1}
    finding = result["findings"][0]
    assert "runtime_oracle_eligible" not in finding["facts"]
    assert finding["severity"] == (
        "INFO" if diagnostic == "QUALITY_UNKNOWN_TEST_ORACLE" else "MEDIUM"
    )
    if diagnostic == "QUALITY_UNKNOWN_TEST_ORACLE":
        assert finding["facts"]["candidate_rule"] == "QUALITY_HOLLOW_TEST"
        assert result["state"] == "INCOMPLETE"


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


def test_scan_retains_unknown_for_legacy_completion_oracle(tmp_path, monkeypatch):
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
    assert result["state"] == "INCOMPLETE"
    assert result["findings"] == initial["findings"]
    assert result["runtime_oracles"]["reconciled_count"] == 0
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
    # The constant assertion is locally weak; the imported call has no closed
    # completion proof. A signed exception-only receipt clears neither fact.
    assert result["finding_counts"] == {"QUALITY_WEAK_TEST_ORACLE": 1}
    assert result["findings"][0]["severity"] == "MEDIUM"
    assert result["runtime_oracles"]["reconciled_count"] == 0


@pytest.mark.parametrize("receipt_version", [None, 1, 2, 3])
def test_scan_keeps_parameterized_test_without_full_collection_catalog(
    tmp_path, monkeypatch, receipt_version
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
    verified = {"tests": [row]}
    if receipt_version is not None:
        verified["schema"] = f"factory.test-oracle-verification.v{receipt_version}"
    monkeypatch.setattr(
        attestation, "verify_signed_test_oracles", lambda *a, **k: verified
    )
    result = security_scan(tmp_path, **kwargs)
    # Incomplete collection cannot resolve the imported call's unknown oracle.
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0
    facts = result["findings"][0]["facts"]
    if receipt_version == 3:
        assert facts["runtime_case_coverage"]["eligible"] is False
    else:
        # Legacy receipts cannot authorize reconciliation of UNKNOWN findings.
        assert "runtime_case_coverage" not in facts


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
    assert ("QUALITY_UNKNOWN_TEST_ORACLE" in result["finding_counts"]) is not complete
    assert "QUALITY_HOLLOW_TEST" not in result["finding_counts"]
    if complete:
        original = result["runtime_oracles"]["reconciled"][0]["static_finding"]
        assert original["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    else:
        assert result["state"] == "INCOMPLETE"
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

    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    assert result["state"] == "INCOMPLETE"
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert result["findings"][0]["facts"]["runtime_case_coverage"]["eligible"] is False


@pytest.mark.parametrize("drift", [False, True])
def test_scan_keeps_finding_if_test_source_changes_after_oracle_binding(
    tmp_path, monkeypatch, drift
):
    import factoryline.review_audits as audit
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    core = security_scan(tmp_path)
    assert core["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    expected_counts = dict(core["finding_counts"])
    original_read = audit._security_source_bytes
    original_coverage = audit.integrity.runtime_callback_coverage
    test_reads = 0
    coverage_calls = 0

    def observe_coverage(*args, **kwargs):
        nonlocal coverage_calls
        coverage_calls += 1
        return original_coverage(*args, **kwargs)

    def drift_after_binding(workspace, relative):
        nonlocal test_reads
        if relative == row["path"]:
            test_reads += 1
            if drift and test_reads == 3:
                return b"def test_replaced():\n    pass\n"
        return original_read(workspace, relative)

    monkeypatch.setattr(audit, "_security_source_bytes", drift_after_binding)
    monkeypatch.setattr(audit.integrity, "runtime_callback_coverage", observe_coverage)
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V3,
            "tests": [row],
        },
    )

    result = audit._reconcile_runtime_oracles(tmp_path, core, tuple(kwargs.values()))

    # Source drift must retain the original finding; it cannot prove inertness.
    assert result["finding_counts"] == expected_counts
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert test_reads == 3
    assert coverage_calls == int(not drift)


@pytest.mark.parametrize("drift", [False, True])
def test_scan_keeps_finding_if_test_body_changes_after_oracle_binding(
    tmp_path, monkeypatch, drift
):
    import factoryline.review_audits as audit
    import factoryline.runtime_attestation as attestation

    _module, row, kwargs = _runtime_oracle_scan_fixture(tmp_path)
    core = security_scan(tmp_path)
    assert core["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    expected_counts = dict(core["finding_counts"])
    original_read = audit._security_source_bytes
    original_coverage = audit.integrity.runtime_callback_coverage
    test_reads = 0
    coverage_calls = 0

    def observe_coverage(*args, **kwargs):
        nonlocal coverage_calls
        coverage_calls += 1
        return original_coverage(*args, **kwargs)

    def drift_after_binding(workspace, relative):
        nonlocal test_reads
        if relative == row["path"]:
            test_reads += 1
            if drift and test_reads == 3:
                return (
                    b"from app import validate\ndef test_validate():\n    validate(6)\n"
                )
        return original_read(workspace, relative)

    monkeypatch.setattr(audit, "_security_source_bytes", drift_after_binding)
    monkeypatch.setattr(audit.integrity, "runtime_callback_coverage", observe_coverage)
    monkeypatch.setattr(
        attestation,
        "verify_signed_test_oracles",
        lambda *args, **values: {
            "schema": attestation.TEST_ORACLE_VERIFICATION_SCHEMA_V3,
            "tests": [row],
        },
    )

    result = audit._reconcile_runtime_oracles(tmp_path, core, tuple(kwargs.values()))

    # Body drift must retain the original finding; it cannot prove inertness.
    assert result["finding_counts"] == expected_counts
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert test_reads == 3
    assert coverage_calls == int(not drift)


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
def test_signed_completion_only_cli_receipt_does_not_clear_unknown(
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
    # Real exception failure proves invocation, not a matching output assertion.
    assert code == (1 if command_prefix[0] == "audit" else 0)
    if command_prefix[0] == "scan":
        assert result["state"] == "INCOMPLETE"
        result = result["static_security"]
    assert result["state"] == "INCOMPLETE"
    assert result["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}
    assert result["runtime_oracles"]["reconciled_count"] == 0
    assert result["runtime_oracles"]["signature"]["identity"] == "test-only@example"
    assert "not established" in result["runtime_oracles"]["claim_boundary"]
    assert result["runtime_oracles"]["reconciled"] == []


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
        # Disabled propagation leaves imported framework/lifecycle effects open.
        (False, "/checked", "", {"QUALITY_UNKNOWN_TEST_ORACLE": 1}),
        # Another path may invoke uncaptured routing and error handlers.
        (True, "/other", "", {"QUALITY_UNKNOWN_TEST_ORACLE": 1}),
        # A changed testing flag is not an absence proof for other hooks.
        (
            True,
            "/checked",
            "app.testing = False\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        # The replacement client's implementation is absent.
        (
            True,
            "/checked",
            "client = fake_client\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            True,
            "/checked",
            "app.view_functions['check'] = noop\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # noop is undefined in this fixture.
        ),
        (
            True,
            "/checked",
            "client.application.testing = False\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Imported client/config behavior.
        ),
        (
            True,
            "/checked",
            "views = app.view_functions\n    views.clear()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Routing/lifecycle remains open.
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions').clear()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Unmodeled reflective lookup.
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions').pop('check', None)\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Imported lookup/removal path.
        ),
        (
            True,
            "/checked",
            "views = getattr(app, 'view_functions')\n    views.clear()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Reflected alias lacks closure.
        ),
        (
            True,
            "/checked",
            "alias = app; getattr(alias, 'view_functions').clear()\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Imported receiver/lookup effects.
        ),
        (
            True,
            "/checked",
            "getattr(app, 'view_functions')['check'] = noop\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Replacement noop is undefined.
        ),
        (
            True,
            "/checked",
            "getattr(app, 'config')['TESTING'] = False\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Reflected config is unmodeled.
        ),
        (
            True,
            "/checked",
            "setattr(getattr(app, 'config'), 'TESTING', False)\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Descriptor effects not captured.
        ),
        (
            True,
            "/checked",
            "app.config.update(TESTING=False)\n    ",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},  # Imported mapping/lifecycle path.
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
    result = security_scan(tmp_path)
    assert result["finding_counts"] == expected
    if expected:
        assert result["state"] == "INCOMPLETE"
        assert result["findings"][0]["severity"] == "INFO"
        assert result["findings"][0]["facts"]["candidate_rule"] == "QUALITY_HOLLOW_TEST"


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("await send(scope)", {}),
        ("send(scope)", {"QUALITY_HOLLOW_TEST": 1}),
        ("if False:\n            await send(scope)", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "try:\n            await send(scope)\n        except AssertionError:\n            pass",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        ("send = noop\n        await send(scope)", {"QUALITY_UNKNOWN_TEST_ORACLE": 1}),
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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


@pytest.mark.parametrize(
    "setup,dispatch,expected",
    [
        ("run = partial(self.deliver, send)", "await run()", {}),
        ("run = partial(self.deliver, send)", "run()", {"QUALITY_HOLLOW_TEST": 1}),
        (
            "run = partial(self.deliver, send)\n        run: object = noop",
            "await run()",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "run = partial(self.deliver, send)\n        send = noop",
            "await self.deliver(send)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "",
            "await run()\n        run = partial(self.deliver, send)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "run = partial(self.deliver, send)",
            "try:\n            await run()\n        except AssertionError:\n            pass",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "async def wrapped(message):\n            send = noop\n            await send(message)",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "async def wrapped(message):\n            try:\n                await send(message)\n            except AssertionError:\n                pass",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
    assert security_scan(tmp_path)["finding_counts"] == {
        "QUALITY_UNKNOWN_TEST_ORACLE": 1
    }


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
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "await self.dispatch_func(scope)",
            "async def dispatch(self, value):\n            assert value == expected",
            "Application(None)",
            "app.dispatch_func = noop\n    await app({})",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
        {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
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
    "guard,operation,expected",
    [
        (
            "scope[b'type'] != b'http'",
            "await app({b'type': b'http'})",
            {"QUALITY_UNKNOWN_TEST_ORACLE": 1},
        ),
        (
            "scope['type'] != 'http'",
            "scope = {'type': 'http'}\n    scope['type'] = 'websocket'; await app(scope)",
            {"QUALITY_HOLLOW_TEST": 1},
        ),
    ],
)
def test_virtual_dispatch_unsupported_guard_and_same_line_mutation_fail_closed(
    tmp_path, guard, operation, expected
):
    test_inherited_virtual_dispatch_requires_default_binding_and_await(
        tmp_path,
        "if "
        + guard
        + ":\n            return\n        await self.dispatch_func(scope)",
        "async def dispatch(self, value):\n            assert value == expected",
        "Application(None)",
        operation,
        expected,
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


@pytest.mark.parametrize(
    "assignment",
    [
        'PASSWORD = "hunter2"',
        'password: str = "x"',
        'PASSWORD = API_KEY = "abc"',
    ],
)
def test_short_hardcoded_credentials_are_detected_without_disclosing_value(
    tmp_path, assignment
):
    (tmp_path / "app.py").write_text(assignment + "\n")
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["finding_counts"]["SECURITY_HARDCODED_SECRET"] >= 1
    findings = json.dumps(result["findings"])
    assert "hunter2" not in findings
    assert '"abc"' not in findings
    assert '"x"' not in findings


def test_config_fixture_secrets_are_exempt_without_hiding_credentials(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_config.py").write_text(
        'SECRET_KEY = "config"\nclass TestConfig:\n    SECRET_KEY = "config"\n',
        encoding="utf-8",
    )
    (tests / "test_credentials.py").write_text(
        'SECRET_KEY = "real-test-credential-8f1b"\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text('SECRET_KEY = "config"\n', encoding="utf-8")

    result = security_scan(tmp_path, cache_enabled=False)

    findings = [
        (item["path"], item["line"])
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert findings == [("app.py", 1), ("tests/test_credentials.py", 1)]
    serialized = json.dumps(result["findings"])
    assert "real-test-credential-8f1b" not in serialized
    assert '"config"' not in serialized


def _command_canary_source(
    value,
    extra="",
    call="subprocess.run",
    imports="import json\nimport subprocess\n",
):
    return (
        imports + "def test_canary(tmp_path):\n"
        f"    secret = {value!r}\n"
        f"    completed = {call}(['tool'], "
        'input=json.dumps({"tool_input": {"command": secret}}), '
        "check=False)\n"
        "    record = tmp_path / 'record.json'\n"
        "    text = record.read_text(encoding='utf-8')\n"
        "    assert secret not in text\n"
        f"{textwrap.indent(extra, '    ') if extra else ''}"
    )


def test_unbound_json_subprocess_and_unrelated_read_keep_secret_finding(tmp_path):
    source = _command_canary_source("opaque-command-marker-42")
    path = tmp_path / "tests" / "test_canary.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]


def test_stdlib_aliases_without_a_source_bound_consumer_keep_secret_finding(tmp_path):
    source = _command_canary_source(
        "opaque-command-marker-42",
        call="execute",
        imports="from json import dumps as serialize\n"
        "from subprocess import run as execute\n",
    ).replace("json.dumps(", "serialize(")
    path = tmp_path / "tests" / "test_canary.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    assert any(
        item["code"] == "SECURITY_HARDCODED_SECRET"
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
    )


def test_cached_security_scan_recomputes_canary_after_source_change(tmp_path):
    path = _write_reported_command_canary(tmp_path)
    first = security_scan(tmp_path, cache_enabled=True)
    assert not _reported_canary_findings(first)
    safe_source = path.read_bytes()
    changed_source = safe_source.replace(
        b'"tool_input_sha256": digest(tool_input)', b'"tool_input": tool_input'
    )
    assert changed_source != safe_source
    path.write_bytes(changed_source)
    second = security_scan(tmp_path, cache_enabled=True)
    assert _reported_canary_findings(second)


def test_non_secret_literal_findings_skip_canary_scope_walk(monkeypatch):
    import ast

    from factoryline import intent_quality

    node = ast.parse("value = 'ordinary'").body[0]
    monkeypatch.setattr(
        intent_quality,
        "_is_closed_command_canary",
        lambda *_args: pytest.fail("non-secret assignment entered the scope walk"),
    )
    assert intent_quality._literal_assignment_diagnostics("app.py", node, {}, []) == []


@pytest.mark.parametrize(
    "source",
    [
        _command_canary_source("hunter2").replace("secret =", "PASSWORD ="),
        _command_canary_source("hunter2"),
        _command_canary_source("bearer abcdefghijklmnopqrstuvwxyz012345"),
        _command_canary_source("short-marker").replace("secret =", "SECRET_KEY ="),
        _command_canary_source("short-marker").replace("secret =", "API_KEY ="),
        _command_canary_source("sk_live_abcdefghijklmnop1234"),
        _command_canary_source("sk-proj-abcdefghijklmnop123456"),
        _command_canary_source("AKIA1234567890ABCDEF"),
        _command_canary_source("ghp_abcdefgh1234567890"),
        _command_canary_source("short-marker", "print(secret)\n"),
        _command_canary_source("short-marker", "client.login(secret)\n"),
        _command_canary_source("short-marker", "headers = {'Authorization': secret}\n"),
        _command_canary_source("short-marker", "client = OpenAI(api_key=secret)\n"),
        _command_canary_source("short-marker").replace(
            "assert secret not in text", "assert secret in text"
        ),
        _command_canary_source("short-marker").replace(
            "check=False)", "check=False, shell=True)"
        ),
        _command_canary_source("short-marker").replace(
            "check=False)", "check=False, **options)"
        ),
        _command_canary_source("short-marker").replace(
            "import subprocess", "import subprocess\njson = object()"
        ),
        _command_canary_source(
            "short-marker", imports="from . import json\nfrom . import subprocess\n"
        ),
        _command_canary_source("short-marker").replace(
            "    secret = 'short-marker'\n",
            "    secret = 'short-marker'\n    subprocess = object()\n",
        ),
        _command_canary_source("short-marker").replace(
            "secret = 'short-marker'", "secret = 'short-marker'\n    secret = input()"
        ),
    ],
)
def test_canary_sabotage_and_credential_values_keep_secret_findings(tmp_path, source):
    path = tmp_path / "tests" / "test_canary.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(
        item["code"] == "SECURITY_HARDCODED_SECRET" for item in result["findings"]
    )


def test_reported_command_canary_file_is_unchanged_and_scans_without_finding(
    tmp_path,
):
    import hashlib

    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    assert hashlib.sha256(
        _canary_lf_text(original.decode("utf-8")).encode("utf-8")
    ).hexdigest() == (
        "d01fc1dd78021cb68893db24e1bc3e2d11f6c5818381058c071099c01c30d44f"
    )
    _write_reported_command_canary(tmp_path, original=original)
    result = security_scan(tmp_path, cache_enabled=False)
    assert not _reported_canary_findings(result)
    script_relative = "plugins/code-factory-session-recorder/scripts/record_hook.py"
    script_source = Path(__file__).parents[1] / script_relative
    import hashlib

    bound = {item["path"]: item["sha256"] for item in result["sources"]}
    assert (
        bound[script_relative] == hashlib.sha256(script_source.read_bytes()).hexdigest()
    )


def _write_reported_command_canary(tmp_path, original=None, recorder=None):
    """Copy the unchanged triggering test and its local recorder dependency."""
    source = (
        original
        or Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    )
    destination = tmp_path / "tests" / "test_evidence_supply_line.py"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source)
    consumer = (
        tmp_path
        / "plugins"
        / "code-factory-session-recorder"
        / "scripts"
        / "record_hook.py"
    )
    consumer.parent.mkdir(parents=True, exist_ok=True)
    consumer.write_bytes(
        recorder
        if recorder is not None
        else (
            Path(__file__).parents[1]
            / "plugins"
            / "code-factory-session-recorder"
            / "scripts"
            / "record_hook.py"
        ).read_bytes()
    )
    return consumer


def _reported_canary_findings(result):
    """Select only the original hardcoded-secret finding under review."""
    return [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
        and item["path"] == "tests/test_evidence_supply_line.py"
        and item["line"] == 222
    ]


def _canary_lf_text(value):
    """Normalize fixture text to the canary tests' explicit LF contract."""
    return value.replace("\r\n", "\n").replace("\r", "\n")


@pytest.mark.parametrize(
    "test_old,test_new,recorder_old,recorder_new",
    [
        ('"CLAUDE_PROJECT_DIR": str(tmp_path)', '"OTHER_ROOT": str(tmp_path)', "", ""),
        (
            'tmp_path / ".factory" / "session-recorder"',
            'tmp_path / "unrelated" / "session-recorder"',
            "",
            "",
        ),
        (
            'secret = "do-not-retain-this-command"',
            'secret = "do-not-retain-this-command"\n'
            '    (tmp_path / ".factory" / "session-recorder" / "claude-hooks" / "unrelated.json").write_text("unrelated")',
            "",
            "",
        ),
        ("Path(__file__).parents[1]", "Path(__file__).parents[2]", "", ""),
        ("Path(__file__).parents[1]", 'Path(__file__).parents[1] / ".."', "", ""),
        ("", "", '".factory" / "session-recorder"', '"unrelated" / "session-recorder"'),
        (
            "",
            "",
            "    if existing:",
            '    if existing:\n        Path(__file__).read_text(encoding="utf-8")',
        ),
    ],
)
def test_changed_readback_environment_or_escaping_source_path_keeps_finding(
    tmp_path, test_old, test_new, recorder_old, recorder_new
):
    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    recorder = (
        Path(__file__).parents[1]
        / "plugins"
        / "code-factory-session-recorder"
        / "scripts"
        / "record_hook.py"
    ).read_bytes()
    baseline = tmp_path / "baseline"
    _write_reported_command_canary(baseline, original, recorder)
    assert not _reported_canary_findings(security_scan(baseline, cache_enabled=False))
    test_text = original.decode("utf-8")
    recorder_text = recorder.decode("utf-8")
    if test_old:
        assert test_old in test_text
        test_text = test_text.replace(test_old, test_new)
    if recorder_old:
        assert recorder_old in recorder_text
        recorder_text = recorder_text.replace(recorder_old, recorder_new)
    test_source = test_text.encode("utf-8")
    recorder_source = recorder_text.encode("utf-8")
    _write_reported_command_canary(tmp_path, test_source, recorder_source)
    assert _reported_canary_findings(security_scan(tmp_path, cache_enabled=False))


def test_missing_or_malicious_local_recorder_keeps_original_finding(tmp_path):
    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    test_path = tmp_path / "tests" / "test_evidence_supply_line.py"
    test_path.parent.mkdir(parents=True)
    test_path.write_bytes(original)
    assert _reported_canary_findings(security_scan(tmp_path, cache_enabled=False))

    recorder = _write_reported_command_canary(tmp_path).read_text(encoding="utf-8")
    changed = recorder.replace(
        '        "tool_input_sha256": digest(tool_input),',
        '        "tool_input_sha256": digest(tool_input),\n'
        '        "raw_command": tool_input,',
    )
    assert changed != recorder
    _write_reported_command_canary(tmp_path, original, changed.encode("utf-8"))
    assert _reported_canary_findings(security_scan(tmp_path, cache_enabled=False))
    untrusted = recorder.replace(
        "import sys\n", "import sys\nimport urllib.request\n"
    ).replace(
        '    path.write_bytes(canonical(record) + b"\\n")',
        "    urllib.request.urlopen('https://example.invalid')\n"
        '    path.write_bytes(canonical(record) + b"\\n")',
    )
    assert untrusted != recorder
    _write_reported_command_canary(tmp_path, original, untrusted.encode("utf-8"))
    assert _reported_canary_findings(security_scan(tmp_path, cache_enabled=False))


@pytest.mark.parametrize(
    "old,new",
    [
        (
            "\ndef main() -> int:",
            "\ndef digest(value: object) -> str:\n    return value\n"
            "\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\nclass digest:\n    pass\n\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\nasync def digest(value):\n    return value\n\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\nfrom hashlib import sha256 as digest\n\ndef main() -> int:",
        ),
        (
            "def main() -> int:",
            "def main(digest=None) -> int:",
        ),
        (
            "        payload = json.load(sys.stdin)",
            "        json = object()\n        payload = json.load(sys.stdin)",
        ),
        (
            "        payload = json.load(sys.stdin)",
            "        try:\n            pass\n        except Exception as digest:\n"
            "            pass\n        payload = json.load(sys.stdin)",
        ),
        (
            "        payload = json.load(sys.stdin)",
            "        payload = json.load(sys.stdin)\n        match payload:\n"
            "            case {'digest': digest}:\n                pass",
        ),
        (
            "        payload = json.load(sys.stdin)",
            "        payload = json.load(sys.stdin)\n        print(payload)",
        ),
        (
            "def main() -> int:",
            "def main(sys=None) -> int:",
        ),
        (
            "def main() -> int:",
            "def main(os=None) -> int:",
        ),
        (
            "def main() -> int:",
            "def main() -> int:\n    sys = object()",
        ),
        (
            "def main() -> int:",
            "def main() -> int:\n    proxy = digest\n"
            "    proxy.__code__ = (lambda value: value).__code__",
        ),
        (
            '    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()',
            '    os = object()\n    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())).resolve()',
        ),
        (
            "\ndef main() -> int:",
            "\ndigest = lambda value: value\n\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\nhashlib.sha256 = lambda value: value\n\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\nglobals()['digest'] = None\n\ndef main() -> int:",
        ),
        (
            "\ndef main() -> int:",
            "\ndigest.__defaults__ = (None,)\n\ndef main() -> int:",
        ),
    ],
)
def test_reported_canary_consumer_mutations_keep_finding_after_admission(
    tmp_path, old, new
):
    """Prove each recorder mutation starts from the exact admitted positive."""
    import ast

    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    recorder_path = (
        Path(__file__).parents[1]
        / "plugins"
        / "code-factory-session-recorder"
        / "scripts"
        / "record_hook.py"
    )
    recorder = recorder_path.read_text(encoding="utf-8")
    baseline = tmp_path / "baseline"
    _write_reported_command_canary(baseline, original, recorder.encode("utf-8"))
    assert not _reported_canary_findings(security_scan(baseline, cache_enabled=False))
    assert old in recorder
    changed = recorder.replace(old, new, 1)
    assert changed != recorder
    ast.parse(changed, filename="mutated-record_hook.py")
    if "proxy = digest" in new:
        from factoryline.intent_quality import (
            _canary_digest_helpers,
            _canary_parse_consumer,
        )

        parsed = _canary_parse_consumer(
            Path("mutated-record_hook.py"), changed.encode()
        )
        assert parsed is not None
        assert _canary_digest_helpers(*parsed) is None
    mutated = tmp_path / "mutated"
    _write_reported_command_canary(mutated, original, changed.encode("utf-8"))
    assert _reported_canary_findings(security_scan(mutated, cache_enabled=False))


@pytest.mark.parametrize(
    "old,new,consumer",
    [
        (
            "import json\r\n",
            "import json; json.dumps = lambda value: value\r\n",
            None,
        ),
        (
            '[sys.executable, str(script), "pre-tool"]',
            '["curl", str(script), "pre-tool"]',
            None,
        ),
        (
            "def test_claude_hook_plugin_hashes_input_without_retaining_it(tmp_path: Path) -> None:",
            "def test_claude_hook_plugin_hashes_input_without_retaining_it(tmp_path: Path, sys: object) -> None:",
            None,
        ),
        (
            "def test_claude_hook_plugin_hashes_input_without_retaining_it(tmp_path: Path) -> None:",
            "def test_claude_hook_plugin_hashes_input_without_retaining_it(tmp_path: Path, os: object) -> None:",
            None,
        ),
        (
            "    completed = subprocess.run(\r\n",
            "    sys = object()\r\n    completed = subprocess.run(\r\n",
            None,
        ),
        (
            "    completed = subprocess.run(\r\n",
            "    setattr(sys, 'executable', 'python')\r\n"
            "    completed = subprocess.run(\r\n",
            None,
        ),
        (
            "    completed = subprocess.run(\r\n",
            "    sys.__setattr__('executable', 'python')\r\n"
            "    completed = subprocess.run(\r\n",
            None,
        ),
        (
            '    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)}',
            '    os = object()\r\n    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)}',
            None,
        ),
        ("record_hook.py", "alternate.py", "import urllib.request\n"),
    ],
)
def test_reported_canary_test_mutations_keep_finding_after_admission(
    tmp_path, old, new, consumer
):
    """Derive test-side changes from the byte-identical admitted fixture."""
    import ast

    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    recorder = (
        Path(__file__).parents[1]
        / "plugins"
        / "code-factory-session-recorder"
        / "scripts"
        / "record_hook.py"
    ).read_bytes()
    baseline = tmp_path / "baseline"
    _write_reported_command_canary(baseline, original, recorder)
    assert not _reported_canary_findings(security_scan(baseline, cache_enabled=False))
    source = original.decode("utf-8")
    source = _canary_lf_text(source)
    old, new = _canary_lf_text(old), _canary_lf_text(new)
    assert old in source
    changed = source.replace(old, new, 1).encode("utf-8")
    assert changed != original
    ast.parse(changed, filename="mutated-test_evidence_supply_line.py")
    root = tmp_path / "mutated"
    _write_reported_command_canary(root, changed, recorder)
    if consumer is not None:
        alternate = (
            root
            / "plugins"
            / "code-factory-session-recorder"
            / "scripts"
            / "alternate.py"
        )
        alternate.write_text(
            consumer
            + "\ndef main():\n"
            + "    urllib.request.urlopen('https://example.invalid')\n",
            encoding="utf-8",
        )
    assert _reported_canary_findings(security_scan(root, cache_enabled=False))


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_reported_canary_fixture_and_mutation_are_newline_portable(tmp_path, newline):
    """Keep raw fixture bytes while checking equivalent LF/CRLF source forms."""
    import ast

    original = Path(__file__).with_name("test_evidence_supply_line.py").read_bytes()
    recorder = (
        Path(__file__).parents[1]
        / "plugins"
        / "code-factory-session-recorder"
        / "scripts"
        / "record_hook.py"
    ).read_bytes()
    canonical = _canary_lf_text(original.decode("utf-8"))
    fixture = canonical.replace("\n", newline).encode("utf-8")
    suffix = "crlf" if "\r" in newline else "lf"
    baseline = tmp_path / f"baseline-{suffix}"
    _write_reported_command_canary(baseline, fixture, recorder)
    assert not _reported_canary_findings(security_scan(baseline, cache_enabled=False))

    old = _canary_lf_text("    completed = subprocess.run(\r\n")
    new = _canary_lf_text("    sys = object()\r\n    completed = subprocess.run(\r\n")
    assert old in canonical
    changed = canonical.replace(old, new, 1)
    assert changed != canonical
    ast.parse(changed, filename="mutated-test_evidence_supply_line.py")
    mutated = tmp_path / f"mutated-{suffix}"
    changed_fixture = changed.replace("\n", newline).encode("utf-8")
    _write_reported_command_canary(mutated, changed_fixture, recorder)
    assert _reported_canary_findings(security_scan(mutated, cache_enabled=False))


def test_canary_ast_index_reuses_one_capped_parent_type_inventory():
    """Verify one traversal supplies repeat typed and parent queries."""
    import ast

    from factoryline.intent_quality import (
        _canary_call_name,
        _canary_index,
        _canary_nodes,
        _canary_parent,
    )

    tree = ast.parse("def sample():\n    return emit({'value': 1})\n")
    index = _canary_index(tree)
    first_call = _canary_nodes(tree, ast.Call)[0]
    assert _canary_index(tree) is index
    assert _canary_nodes(tree, ast.Call) == (first_call,)
    assert _canary_parent(tree, first_call) is not None
    assert _canary_parent(tree, first_call) is not None
    aliases = {}
    _canary_call_name(first_call, aliases)
    _canary_call_name(first_call, aliases)
    assert index["call_resolution_count"] == 1
    aliases["emit"] = "changed"
    _canary_call_name(first_call, aliases)
    assert index["call_resolution_count"] == 2
    assert index["node_visits"] == len(index["nodes"])
    assert index["parent_lookups"] == 2


def test_consumer_index_cap_precedes_scope_binding(monkeypatch, tmp_path):
    """Reject oversized consumers before the recursive lexical binder runs."""
    from factoryline import intent_quality, review_integrity

    observations = []
    original_build = intent_quality._canary_build_index

    def observe_index(tree):
        result = original_build(tree)
        observations.append(result)
        return result

    monkeypatch.setattr(intent_quality, "_canary_build_index", observe_index)
    monkeypatch.setattr(
        review_integrity,
        "bind_security_call_scopes",
        lambda _tree: pytest.fail("oversized AST reached recursive scope binding"),
    )
    source = ("value = 1\n" * 40_000).encode("utf-8")
    assert intent_quality._canary_parse_consumer(tmp_path / "large.py", source) is None
    assert observations[0]["complete"] is False
    assert observations[0]["node_visits"] == 100_000


@pytest.mark.parametrize("value", ["", "   ", "changeme", "placeholder", "${PASSWORD}"])
def test_empty_or_declared_placeholder_credentials_remain_exempt(tmp_path, value):
    (tmp_path / "app.py").write_text("PASSWORD = " + repr(value) + "\n")
    assert (
        "SECURITY_HARDCODED_SECRET"
        not in security_scan(tmp_path, cache_enabled=False)["finding_counts"]
    )


def test_audit_log_source_findings_direct_contract_for_unsafe_and_sanitized_values():
    import ast

    from factoryline.audit_log_flow import audit_log_source_findings
    from factoryline.review_audits import _security_aliases
    from factoryline.review_integrity import bind_security_call_scopes

    unsafe_tree = ast.parse(
        "import logging\ndef record():\n    value = input()\n    logging.error(value)\n"
    )
    unsafe_nodes = list(ast.walk(unsafe_tree))
    bind_security_call_scopes(unsafe_tree)
    unsafe = audit_log_source_findings(
        "app.py", unsafe_tree, unsafe_nodes, _security_aliases(unsafe_nodes)
    )
    assert [finding["code"] for finding in unsafe] == ["SECURITY_LOG_INJECTION"]

    safe_tree = ast.parse(
        "import logging\ndef record():\n    value = input()\n"
        "    logging.error(value.replace('\\r', '').replace('\\n', ''))\n"
    )
    safe_nodes = list(ast.walk(safe_tree))
    bind_security_call_scopes(safe_tree)
    safe = audit_log_source_findings(
        "app.py", safe_tree, safe_nodes, _security_aliases(safe_nodes)
    )
    assert safe == []


def test_intentional_implementation_contract_recognizes_only_registered_click_group():
    import ast

    from factoryline.intent_quality import intentional_implementation_contract

    source = (
        "import click\n"
        "@click.group()\ndef cli():\n    pass\n"
        "@cli.command()\ndef child():\n    return 1\n"
    )
    tree = ast.parse(source)
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    cli = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    assert intentional_implementation_contract(cli, parents, {"click": "click"})

    unregistered_tree = ast.parse(
        "import click\n@cli.command()\ndef cli():\n    pass\n"
    )
    unregistered_parents = {
        child: node
        for node in ast.walk(unregistered_tree)
        for child in ast.iter_child_nodes(node)
    }
    unregistered = next(
        node for node in unregistered_tree.body if isinstance(node, ast.FunctionDef)
    )
    assert not intentional_implementation_contract(
        unregistered, unregistered_parents, {"click": "click"}
    )


def test_click_group_container_requires_a_real_registered_child_command():
    import ast

    from factoryline.intent_quality import click_group_container

    tree = ast.parse(
        "import click\n"
        "@click.group()\ndef cli():\n    pass\n"
        "@cli.command()\ndef child():\n    return 1\n"
    )
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    cli = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    assert click_group_container(cli, parents, {"click": "click"})

    bare_tree = ast.parse("import click\n@click.group()\ndef cli():\n    pass\n")
    bare_parents = {
        child: node
        for node in ast.walk(bare_tree)
        for child in ast.iter_child_nodes(node)
    }
    bare_cli = next(
        node for node in bare_tree.body if isinstance(node, ast.FunctionDef)
    )
    assert not click_group_container(bare_cli, bare_parents, {"click": "click"})


def test_implementation_findings_respects_only_declared_contract_lines():
    import ast

    from factoryline.intent_quality import implementation_findings

    source = "def execute():\n    pass\n"
    tree = ast.parse(source)
    findings = implementation_findings("service.py", tree, source, {})
    assert [finding["code"] for finding in findings] == ["QUALITY_EMPTY_IMPLEMENTATION"]

    contract_findings = implementation_findings(
        "service.py",
        ast.parse(source),
        source,
        {"implementation_contract_lines": {1}},
    )
    assert contract_findings == []


def test_project_contract_helpers_includes_every_resolver_used_for_cache_identity():
    from factoryline.intent_quality import (
        bind_project_contracts,
        bound_snapshots,
        project_contract_helpers,
    )

    helpers = project_contract_helpers()
    assert bind_project_contracts in helpers
    assert bound_snapshots in helpers
    assert len(helpers) == len(set(helpers))


def test_bind_project_contracts_emits_edge_for_stable_local_override(tmp_path):
    import ast

    from factoryline.intent_quality import bind_project_contracts

    base = tmp_path / "base.py"
    implementation = tmp_path / "impl.py"
    base_source = (
        "class Adapter:\n    def run(self):\n        raise NotImplementedError\n"
    )
    implementation_source = (
        "from base import Adapter\n"
        "class Concrete(Adapter):\n    def run(self):\n        return 1\n"
    )
    base.write_text(base_source, encoding="utf-8")
    implementation.write_text(implementation_source, encoding="utf-8")
    snapshots = {
        base: ast.parse(base_source),
        implementation: ast.parse(implementation_source),
    }
    contexts = {path: {} for path in snapshots}
    edges = []

    bind_project_contracts(tmp_path, snapshots, contexts, edges)

    assert contexts[base]["implementation_contract_lines"] == {2}
    assert edges == [
        {
            "caller": "impl.py",
            "target": "base.py",
            "kind": "implementation_contract",
            "symbol": "Adapter.run",
            "strength": "declared_override",
        }
    ]


def test_bound_snapshots_parses_only_hash_matching_source_bytes(tmp_path):
    import hashlib

    import pytest

    from factoryline.intent_quality import bound_snapshots
    from factoryline.review_audits import ReviewAuditError

    path = tmp_path / "source.py"
    source = b"def value():\n    return 7\n"
    bindings = [{"path": "source.py", "sha256": hashlib.sha256(source).hexdigest()}]
    snapshots = bound_snapshots(tmp_path, [path], {path: source}, bindings)
    assert snapshots[path].body[0].name == "value"

    with pytest.raises(ReviewAuditError, match="Source changed"):
        bound_snapshots(tmp_path, [path], {path: source + b"# changed\n"}, bindings)


def test_security_scan_source_phase_parity_and_dynamic_parse(tmp_path, monkeypatch):
    import factoryline.review_audits as audit
    from factoryline.ops_telemetry import _phase_telemetry

    source = "value = 1\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    baseline = security_scan(tmp_path, cache_enabled=False)
    parser = audit.ast.parse
    parsed = []

    def tracked_parse(*args, **kwargs):
        parsed.append((args, kwargs))
        return parser(*args, **kwargs)

    monkeypatch.setattr(audit.ast, "parse", tracked_parse)
    with _phase_telemetry(0) as telemetry:
        observed = security_scan(tmp_path, cache_enabled=False)

    assert observed["audit_sha256"] == baseline["audit_sha256"]
    assert observed["findings"] == baseline["findings"]
    phases = {item["phase"]: item for item in telemetry.snapshot()["phases"]}
    assert {
        "source_read",
        "source_hash",
        "source_parse",
        "source_index",
    } <= phases.keys()
    assert len(parsed) >= phases["source_parse"]["calls"]
    assert telemetry.snapshot()["source_attribution"]["status"] == "complete"
    assert str(tmp_path) not in str(telemetry.snapshot())


def test_security_scan_no_sources_reports_unobserved_attribution(tmp_path):
    from factoryline.ops_telemetry import _phase_telemetry

    with _phase_telemetry(0) as telemetry:
        result = security_scan(tmp_path, cache_enabled=False)

    assert result["state"] == "NO_SOURCES"
    assert telemetry.snapshot()["source_attribution"]["status"] == "not_observed"
    assert telemetry.snapshot()["source_attribution"]["observed_phases"] == []


def test_security_scan_source_read_failure_preserves_finding_and_marks_incomplete(
    tmp_path, monkeypatch
):
    import factoryline.review_audits as audit
    from factoryline.ops_telemetry import _phase_telemetry

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    original_open = audit.os.open

    def fail_read(path, *args, **kwargs):
        if Path(path).name == "app.py":
            raise OSError("PRIVATE SOURCE READ DETAIL")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(audit.os, "open", fail_read)
    with _phase_telemetry(0) as telemetry:
        result = security_scan(tmp_path, cache_enabled=False)

    assert "SECURITY_SOURCE_UNREADABLE" in result["finding_counts"]
    assert telemetry.snapshot()["source_attribution"]["status"] == "incomplete"
    assert "PRIVATE SOURCE READ DETAIL" not in str(telemetry.snapshot())


def _assert_unknown_test_oracle(report, *, unknown_count):
    unknown = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    ]
    assert len(unknown) == unknown_count
    assert report["state"] == "INCOMPLETE"
    assert all(item["severity"] == "INFO" for item in unknown)
    assert all(item["facts"]["state"] == "INCOMPLETE" for item in unknown)
    assert all(item["facts"]["evidence_state"] == "UNKNOWN" for item in unknown)
    assert all(
        item["facts"]["candidate_rule"] == "QUALITY_HOLLOW_TEST" for item in unknown
    )


def test_discarded_assertion_error_is_reported_as_local_weakness(tmp_path):
    # This is the extracted test function from pallets/flask tests/test_helpers.py.
    # Its full-file source hash and upstream line are retained in the ignored
    # adjudication artifact, while this local fixture stays available in CI.
    source = textwrap.dedent(
        """\
        def test_name_with_import_error(self, modules_tmp_path):
            (modules_tmp_path / "importerror.py").write_text("raise NotImplementedError()")
            try:
                flask.Flask("importerror")
            except NotImplementedError:
                AssertionError("Flask(import_name) is importing import_name.")
        """
    ).replace("\n", "\r\n")
    (tmp_path / "test_helpers.py").write_text(source, encoding="utf-8", newline="")

    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["line"] == 6
    assert finding["facts"]["symbol"] == "test_name_with_import_error"
    assert finding["facts"]["reasons"] == ["discarded AssertionError construction"]
    assert finding["facts"]["evidence_scope"] == "local_statement_semantics"
    assert finding["facts"]["execution_state"] == "NOT_ESTABLISHED"
    assert finding["facts"]["whole_test_oracle"] == "UNASSESSED"


@pytest.mark.parametrize(
    "source",
    [
        "def test_behavior():\n    try:\n        run()\n    except Error:\n        raise AssertionError('unexpected')\n",
        "def test_behavior():\n    try:\n        run()\n    except Error:\n        error = AssertionError('unexpected')\n",
        "def test_behavior():\n    try:\n        run()\n    except Error:\n        return AssertionError('unexpected')\n",
        "def test_behavior():\n    def nested():\n        try:\n            run()\n        except Error:\n            AssertionError('unexpected')\n",
        "AssertionError = Error\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "def test_behavior(AssertionError=Error):\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "from .provider import AssertionError\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "from dependency import *\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "import builtins\nbuiltins.AssertionError = Error\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "globals()['AssertionError'] = Error\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "import builtins\nbuiltins.__dict__['AssertionError'] = Error\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('unexpected')\n",
        "from builtins import AssertionError as BuiltinAssertionError\nsetattr(builtins, 'AssertionError', Error)\ndef test_behavior():\n    try:\n        run()\n    except Error:\n        BuiltinAssertionError('unexpected')\n",
        "def test_behavior():\n    try:\n        run()\n    except Error:\n        AssertionError('x')\n        raise\n",
        "def reject(*args):\n    raise RuntimeError('rejected')\n"
        "reject.__globals__['AssertionError'] = reject\n"
        "def test_case():\n    try: raise ValueError()\n"
        "    except ValueError:\n        AssertionError('must reject')\n",
        "def reject(*args):\n    raise RuntimeError('rejected')\n"
        "getattr(reject, '__globals__')['AssertionError'] = reject\n"
        "def test_case():\n    try: raise ValueError()\n"
        "    except ValueError:\n        AssertionError('must reject')\n",
        "def reject(*args):\n    raise RuntimeError('rejected')\n"
        "reject.__builtins__['AssertionError'] = reject\n"
        "def test_case():\n    try: raise ValueError()\n"
        "    except ValueError:\n        AssertionError('must reject')\n",
        "def reject(*args):\n    raise RuntimeError('rejected')\n"
        "def test_case(monkeypatch):\n    try: raise ValueError()\n"
        "    except ValueError:\n"
        "        monkeypatch.setattr('builtins.AssertionError', reject)\n"
        "        AssertionError('must reject')\n",
        "def test_behavior():\n    try:\n        run()\n    except Error:\n        inspect(AssertionError('unexpected'))\n",
    ],
    ids=[
        "raise-instead",
        "assigned",
        "returned",
        "uninvoked-nested-function",
        "module-shadow",
        "parameter-shadow",
        "relative-provider",
        "wildcard-provider",
        "builtin-mutation",
        "globals-mutation",
        "builtins-dict-mutation",
        "aliased-builtin-import-mutation",
        "handler-reraises",
        "direct-function-globals-mutation",
        "reflected-function-globals-mutation",
        "function-builtins-assertionerror-mutation",
        "monkeypatch-setattr-builtin-assertionerror",
        "argument-call",
    ],
)
def test_discarded_assertion_error_controls_are_not_overreported(tmp_path, source):
    (tmp_path / "test_controls.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def _protocol_integration_workspace(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_protocol.py").write_text(
        "from models import Widget\ndef test_representation():\n    repr(Widget())\n",
        encoding="utf-8",
    )
    model = tmp_path / "models.py"
    model.write_text(
        "class Widget:\n"
        "    def __init__(self):\n        self.value = 7\n"
        "    def __repr__(self):\n        return f'{self.value}'\n",
        encoding="utf-8",
    )
    return model


def _protocol_integration_finding(report):
    matches = [
        row
        for row in report["findings"]
        if row["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    ]
    assert len(matches) == 1
    assert report["state"] == "INCOMPLETE"
    assert matches[0]["facts"]["evidence_state"] == "UNKNOWN"
    return matches[0]


def test_protocol_observation_scanner_cold_warm_parity_without_oracle_credit(tmp_path):
    import factoryline.review_audits as module

    _protocol_integration_workspace(tmp_path)
    module._oracle_context_cache_clear()
    uncached = security_scan(tmp_path, cache_enabled=False)
    cold = security_scan(tmp_path, cache_enabled=True)
    warm = security_scan(tmp_path, cache_enabled=True)
    assert uncached == cold == warm
    assert module._oracle_context_cache_info()["hits"] >= 1
    finding = _protocol_integration_finding(warm)
    summary = finding["facts"]["protocol_observations"]["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert summary["output_checked"] is False
    assert summary["runtime_observed"] is False
    assert {item["source"] for item in summary["dependencies"]} == {
        "models.py",
        "tests/test_protocol.py",
    }


def test_protocol_observation_scanner_dependency_change_invalidates_cache(tmp_path):
    import factoryline.review_audits as module

    model = _protocol_integration_workspace(tmp_path)
    module._oracle_context_cache_clear()
    before = security_scan(tmp_path, cache_enabled=True)
    prior_misses = module._oracle_context_cache_info()["misses"]
    model.write_text(
        model.read_text().replace("f'{self.value}'", "'constant'"), encoding="utf-8"
    )
    after = security_scan(tmp_path, cache_enabled=True)
    assert module._oracle_context_cache_info()["misses"] > prior_misses
    original = _protocol_integration_finding(before)["facts"]["protocol_observations"][
        "summaries"
    ][0]
    changed = _protocol_integration_finding(after)["facts"]["protocol_observations"][
        "summaries"
    ][0]
    assert original["status"] == "WEAK_PROTOCOL"
    assert changed["status"] == "UNKNOWN"
    assert original["dependencies"] != changed["dependencies"]


def test_protocol_observation_scanner_producer_change_invalidates_cache(
    tmp_path, monkeypatch
):
    import factoryline.context_efficiency as context
    import factoryline.review_audits as module

    _protocol_integration_workspace(tmp_path)
    module._oracle_context_cache_clear()
    before = security_scan(tmp_path, cache_enabled=True)
    prior_misses = module._oracle_context_cache_info()["misses"]
    original = context.protocol_call_context

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(context, "protocol_call_context", replacement)
    after = security_scan(tmp_path, cache_enabled=True)
    assert module._oracle_context_cache_info()["misses"] > prior_misses
    assert before == after


def test_protocol_observation_scanner_does_not_credit_constant_computation(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_constant.py").write_text(
        "def compute():\n    return 3\ndef test_unchecked():\n    compute()\n",
        encoding="utf-8",
    )
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    hollow = [
        finding for finding in findings if finding["code"] == "QUALITY_HOLLOW_TEST"
    ]
    assert len(hollow) == 1
    finding = hollow[0]
    assert finding["severity"] == "MEDIUM"
    assert "protocol_observations" not in finding["facts"]


def test_protocol_observation_scanner_malformed_cache_cannot_clear_unknown(tmp_path):
    import json
    import factoryline.review_audits as module

    _protocol_integration_workspace(tmp_path)
    module._oracle_context_cache_clear()
    security_scan(tmp_path, cache_enabled=True)
    key = next(iter(module._ORACLE_CONTEXT_CACHE))
    payload, size, created = module._ORACLE_CONTEXT_CACHE[key]
    document = json.loads(payload)
    for row in document["contexts"]:
        row["protocol_observations"] = {
            "schema": "factory.protocol-context.v1",
            "summaries": [None, {"test": "test_representation", "dependencies": None}],
        }
    module._ORACLE_CONTEXT_CACHE[key] = (json.dumps(document), size, created)
    misses = module._oracle_context_cache_info()["misses"]
    finding = _protocol_integration_finding(security_scan(tmp_path, cache_enabled=True))
    assert finding["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    assert module._oracle_context_cache_info()["misses"] > misses
    summaries = finding["facts"]["protocol_observations"]["summaries"]
    assert summaries and all(isinstance(row, dict) for row in summaries)
    assert summaries[0]["dependencies"]
    assert module.integrity.NativeOraclePayload.valid(
        module._ORACLE_CONTEXT_CACHE[key][0], key
    )


@pytest.mark.parametrize("literal", ["//serser", "if:", "def broken("])
def test_literal_exec_rejected_syntax_retains_primitive_info(tmp_path, literal):
    (tmp_path / "app.py").write_text(f"def parse_case():\n    exec({literal!r})\n")
    findings = security_scan(tmp_path)["findings"]
    finding = next(f for f in findings if f["code"] == "SECURITY_DYNAMIC_EXECUTION")
    assert finding["severity"] == "INFO"
    assert finding["facts"]["primitive_present"] is True
    assert finding["facts"]["source_compilation"] == "REJECTED_SYNTAX"
    assert finding["facts"]["execution_of_literal_source"] is False
    assert finding["facts"]["evidence_scope"] == "exact_builtin_call_literal"
    assert "harmless" not in finding["message"]


@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    exec(\"import os; os.system('danger')\")\n",
        "def f():\n    exec(payload)\n",
        "def f():\n    exec('//bad', {})\n",
        "def f():\n    exec('//bad', globals={})\n",
        "import builtins\ndef f():\n    builtins.exec('//bad')\n",
        "from builtins import exec as invoke\ndef f():\n    invoke('//bad')\n",
        "import builtins as b\nb.exec = replacement\ndef f():\n    exec('//bad')\n",
        "import builtins as b\nalias = b\nalias.exec = replacement\ndef f():\n    exec('//bad')\n",
        "def f():\n    setattr(target, 'exec', replacement)\n    exec('//bad')\n",
        "def f():\n    mutate = getattr\n    exec('//bad')\n",
        "def f():\n    __builtins__['exec'] = replacement\n    exec('//bad')\n",
        "from unknown import *\ndef f():\n    exec('//bad')\n",
        "import sys\ndef f():\n    sys.modules['builtins'].exec = replacement\n    exec('//bad')\n",
        "def f():\n    exec('//other')\n    exec('//bad')\n",
        "def f():\n    exec(" + repr("//" + "x" * 4096) + ")\n",
    ],
)
def test_literal_exec_unsupported_does_not_receive_syntax_credit(tmp_path, source):
    (tmp_path / "app.py").write_text(source)
    findings = [
        f
        for f in security_scan(tmp_path)["findings"]
        if f["code"] == "SECURITY_DYNAMIC_EXECUTION"
    ]
    assert findings
    assert all(f["severity"] == "HIGH" for f in findings)
    assert all("source_compilation" not in f["facts"] for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "def f(exec):\n    exec('//bad')\n",
        "exec = custom\ndef f():\n    exec('//bad')\n",
        "def f():\n    exec('//bad')\n    exec = custom\n",
        "def outer(exec):\n    def inner():\n        exec('//bad')\n",
    ],
)
def test_literal_exec_shadowed_binding_never_receives_credit(source):
    import ast
    from factoryline import intent_quality, review_integrity

    tree = ast.parse(source)
    review_integrity.bind_security_call_scopes(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert intent_quality.literal_exec_rejected(call) == {}


def test_literal_exec_requires_native_scope_and_handles_parser_resource_failure(
    monkeypatch,
):
    import ast
    from factoryline import intent_quality, review_integrity

    tree = ast.parse("def f():\n    exec('//bad')\n")
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert intent_quality.literal_exec_rejected(call) == {}
    review_integrity.bind_security_call_scopes(tree)

    def exhausted(*args, **kwargs):
        raise MemoryError("bounded parser failure")

    monkeypatch.setattr(ast, "parse", exhausted)
    assert intent_quality.literal_exec_rejected(call) == {}


def test_literal_exec_cold_warm_and_source_change_invalidate_credit(tmp_path):
    from factoryline import review_audits as scanner

    source = tmp_path / "app.py"
    source.write_text("def f():\n    exec('//bad')\n")
    scanner._oracle_context_cache_clear()
    cold = scanner.security_scan(tmp_path)
    warm = scanner.security_scan(tmp_path)
    assert cold["findings"] == warm["findings"]
    assert cold["findings"][0]["severity"] == "INFO"
    source.write_text("def f():\n    exec('import os; os.system(command)')\n")
    changed = scanner.security_scan(tmp_path)
    assert changed["findings"][0]["severity"] == "HIGH"
    assert "source_compilation" not in changed["findings"][0]["facts"]


@pytest.mark.parametrize(
    "call,program",
    [
        pytest.param("eval", "[1, 2]", id="bare-eval-literal"),
        pytest.param("exec", "value = 7", id="bare-exec-literal"),
    ],
)
def test_security_scan_records_fixed_literal_program_without_agent_action(
    tmp_path, call, program
):
    import ast
    import hashlib
    from factoryline import review_audits as scanner

    source = tmp_path / "app.py"
    source_text = f"{call}({program!r})\n"
    source.write_text(source_text, encoding="utf-8")
    raw = source.read_bytes()
    scanner._oracle_context_cache_clear()
    cold = scanner.security_scan(tmp_path, cache_enabled=True)
    warm = scanner.security_scan(tmp_path, cache_enabled=True)

    assert cold["findings"] == []
    assert cold["finding_counts"] == {}
    assert cold["primitive_observation_count"] == 1
    assert len(cold["primitive_observations"]) == 1
    row = cold["primitive_observations"][0]
    facts = row["facts"]
    assert row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    assert row["severity"] == "INFO"
    assert row["path"] == "app.py"
    assert facts["schema"] == "factory.fixed-literal-program.v1"
    assert facts["disposition"] == "PROVEN_FIXED_LITERAL_PROGRAM"
    assert facts["source_path"] == "app.py"
    assert facts["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (
        facts["program_sha256"] == hashlib.sha256(program.encode("utf-8")).hexdigest()
    )
    literal = next(
        node
        for node in ast.walk(ast.parse(source_text))
        if isinstance(node, ast.Constant) and type(node.value) is str
    )
    assert facts["literal_span"] == {
        "line": literal.lineno,
        "column": literal.col_offset,
        "end_line": literal.end_lineno,
        "end_column": literal.end_col_offset,
    }
    assert facts["profile"]["call"] == f"builtins.{call}"
    assert facts["profile"]["target_execution"] == "not_performed"
    assert cold["state"] == "CLEAN"
    assert cold["agent_actions"] == []
    assert warm["primitive_observations"] == cold["primitive_observations"]
    assert warm["primitive_observation_count"] == 1
    assert warm["agent_actions"] == []
    assert warm["audit_sha256"] == cold["audit_sha256"]


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("exec(\"exec('pass')\")\n", id="nested-exec-string"),
        pytest.param("eval(\"int('1')\")\n", id="nested-eval-call"),
        pytest.param('exec("import os")\n', id="import-statement"),
        pytest.param('exec("value = 1 + 2")\n', id="binary-operation"),
        pytest.param('exec("value = item.field")\n', id="attribute-expression"),
        pytest.param('exec("value = item[0]")\n', id="subscript-expression"),
        pytest.param("exec('\\ud800')\n", id="lone-surrogate-literal"),
        pytest.param('eval("[item for item in items]")\n', id="comprehension"),
        pytest.param('exec("consume(*items)")\n', id="starred-call"),
        pytest.param('exec("value = 1", {})\n', id="custom-namespace"),
        pytest.param(
            'exec = custom\ndef f():\n    exec("value = 1")\n', id="module-shadow"
        ),
        pytest.param('globals()["eval"] = custom\neval("[1]")\n', id="namespace-write"),
        pytest.param('class Scope:\n    exec("value = 1")\n', id="class-scope"),
        pytest.param(
            'def reject():\n    pass\nreject.__builtins__["eval"] = reject\ndef f():\n    eval("[1]")\n',
            id="function-builtins-eval-mutation",
        ),
    ],
)
def test_literal_program_unsupported_shapes_remain_high_findings(tmp_path, source):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "SECURITY_DYNAMIC_EXECUTION"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert report.get("primitive_observations", []) == []
    assert report.get("primitive_observation_count", 0) == 0


@pytest.mark.parametrize(
    "program",
    [
        pytest.param("pass\n" * 1025, id="program-ast-node-cap"),
        pytest.param("x" * (16 * 1024 + 1), id="program-byte-cap"),
    ],
)
def test_fixed_literal_program_caps_remain_high_dynamic_execution(tmp_path, program):
    source = tmp_path / "app.py"
    source.write_text("exec(" + repr(program) + ")\n", encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "SECURITY_DYNAMIC_EXECUTION"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert report.get("primitive_observations", []) == []


def test_fixed_literal_program_helper_without_native_scope_returns_no_witness():
    import ast
    from factoryline import review_integrity

    call = next(
        node
        for node in ast.walk(ast.parse("eval('[1]')"))
        if isinstance(node, ast.Call)
    )
    assert review_integrity.fixed_program_witness("app.py", call, "eval") == {}


def test_security_scan_retains_same_module_fixed_and_unproven_rows_as_findings(
    tmp_path,
):
    source = tmp_path / "app.py"
    source.write_text('eval("[1]")\nexec(payload)\n', encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)

    findings = report["findings"]
    assert report.get("primitive_observations", []) == []
    assert report.get("primitive_observation_count", 0) == 0
    assert len(findings) == 2
    assert all(item["code"] == "SECURITY_DYNAMIC_EXECUTION" for item in findings)
    assert all(item["severity"] == "HIGH" for item in findings)
    assert [item["line"] for item in findings] == [1, 2]
    assert report["finding_counts"] == {"SECURITY_DYNAMIC_EXECUTION": 2}
    assert len(report["agent_actions"]) == 2
    assert [item["finding_context"] for item in report["agent_actions"]] == findings


def test_security_scan_separates_fixed_and_unproven_primitive_rows_and_actions(
    tmp_path,
):
    (tmp_path / "fixed.py").write_text('eval("[1]")\n', encoding="utf-8")
    (tmp_path / "unsafe.py").write_text(
        "import requests\nrequests.get(url, verify=False)\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)

    observations = report["primitive_observations"]
    findings = report["findings"]
    assert len(observations) == 1
    assert observations[0]["path"] == "fixed.py"
    assert len(findings) == 1
    assert findings[0]["code"] == "SECURITY_TLS_VERIFY_DISABLED"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["path"] == "unsafe.py"
    assert report["primitive_observation_count"] == 1
    assert report["finding_counts"] == {"SECURITY_TLS_VERIFY_DISABLED": 1}
    assert len(observations) + len(findings) == 2
    assert len(report["agent_actions"]) == 1
    assert report["agent_actions"][0]["finding_context"] == findings[0]


def test_security_scan_rejects_fixed_program_when_sibling_mutates_builtin(tmp_path):
    (tmp_path / "app.py").write_text('eval("[1]")\n', encoding="utf-8")
    (tmp_path / "mutator.py").write_text(
        "import builtins\nbuiltins.eval = replacement\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)

    assert report.get("primitive_observations", []) == []
    assert report.get("primitive_observation_count", 0) == 0
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["code"] == "SECURITY_DYNAMIC_EXECUTION"
    assert finding["severity"] == "HIGH"
    assert finding["path"] == "app.py"
    assert finding["line"] == 1
    assert report["finding_counts"] == {"SECURITY_DYNAMIC_EXECUTION": 1}
    assert len(report["agent_actions"]) == 1
    assert report["agent_actions"][0]["finding_context"] == finding


@pytest.mark.parametrize(
    "sibling_source, expected_finding_rows",
    [
        pytest.param(
            "exec(\"__builtins__['eval'] = replacement\")\n",
            [("app.py", 1), ("mutator.py", 1)],
            id="literal-exec-mutates-builtins",
        ),
        pytest.param(
            "runner = exec\nrunner(payload)\n",
            [("app.py", 1)],
            id="exec-alias-runs-unknown-payload",
        ),
    ],
)
def test_security_scan_rejects_fixed_program_for_sibling_exec_hazards(
    tmp_path, sibling_source, expected_finding_rows
):
    (tmp_path / "app.py").write_text('eval("[1]")\n', encoding="utf-8")
    (tmp_path / "mutator.py").write_text(sibling_source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)

    assert report.get("primitive_observations", []) == []
    assert report.get("primitive_observation_count", 0) == 0
    findings = report["findings"]
    assert len(findings) == len(expected_finding_rows)
    assert all(item["code"] == "SECURITY_DYNAMIC_EXECUTION" for item in findings)
    assert all(item["severity"] == "HIGH" for item in findings)
    assert [(item["path"], item["line"]) for item in findings] == (
        expected_finding_rows
    )
    assert report["finding_counts"] == {
        "SECURITY_DYNAMIC_EXECUTION": len(expected_finding_rows)
    }
    assert len(report["agent_actions"]) == len(findings)
    assert [item["finding_context"] for item in report["agent_actions"]] == findings


def test_security_scan_allows_fixed_program_with_clean_imported_sibling(tmp_path):
    (tmp_path / "app.py").write_text(
        'from helper import value\neval("[1]")\n', encoding="utf-8"
    )
    (tmp_path / "helper.py").write_text("value = 1\n", encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)

    observations = report["primitive_observations"]
    assert len(observations) == 1
    assert observations[0]["path"] == "app.py"
    assert observations[0]["line"] == 2
    assert report["primitive_observation_count"] == 1
    assert report["findings"] == []
    assert report["finding_counts"] == {}
    assert report["agent_actions"] == []


@pytest.mark.parametrize(
    "rejection",
    [
        "missing-hash",
        "no-source-binding",
        "stale-hash",
        "wrong-path",
        "duplicate-binding",
    ],
)
def test_partition_retains_unbound_fixed_program_findings(rejection):
    import copy
    from factoryline.review_integrity import partition_proven_primitive_observations

    digest = "a" * 64
    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "severity": "INFO",
        "path": "app.py",
        "line": 1,
        "message": "fixed literal program",
        "facts": {
            "schema": "factory.fixed-literal-program.v1",
            "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
            "source_path": "app.py",
            "source_sha256": digest,
            "program_sha256": "b" * 64,
        },
    }
    sources = [{"path": "app.py", "sha256": digest}]
    if rejection == "missing-hash":
        del finding["facts"]["source_sha256"]
    elif rejection == "no-source-binding":
        sources = []
    elif rejection == "stale-hash":
        finding["facts"]["source_sha256"] = "c" * 64
    elif rejection == "wrong-path":
        finding["facts"]["source_path"] = "other.py"
    elif rejection == "duplicate-binding":
        sources.append({"path": "app.py", "sha256": digest})

    original = copy.deepcopy(finding)
    core = {
        "sources": sources,
        "findings": [finding],
        "primitive_observations": [],
        "finding_counts": {"SECURITY_DYNAMIC_EXECUTION": 1},
        "state": "BLOCKED",
    }
    partition_proven_primitive_observations(core)

    assert core["primitive_observations"] == []
    assert core["primitive_observation_count"] == 0
    assert core["finding_counts"] == {"SECURITY_DYNAMIC_EXECUTION": 1}
    assert len(core["findings"]) == 1
    retained = core["findings"][0]
    assert retained["code"] == original["code"]
    assert retained["path"] == original["path"]
    assert retained["line"] == original["line"]
    assert retained["severity"] == "HIGH"
    assert retained["facts"]["disposition"] == "UNVERIFIED_FIXED_PROGRAM"
    assert retained["facts"]["state"] == "INCOMPLETE"
    assert retained["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"
    assert core["state"] == "BLOCKED"


def test_partition_revalidates_stale_existing_primitive_observation():
    from factoryline.review_integrity import partition_proven_primitive_observations

    observation = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "severity": "INFO",
        "path": "app.py",
        "line": 1,
        "message": "fixed literal program",
        "facts": {
            "schema": "factory.fixed-literal-program.v1",
            "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
            "source_path": "app.py",
            "source_sha256": "a" * 64,
            "program_sha256": "b" * 64,
        },
    }
    core = {
        "sources": [{"path": "app.py", "sha256": "c" * 64}],
        "findings": [],
        "primitive_observations": [observation],
        "finding_counts": {},
        "state": "CLEAN",
    }
    partition_proven_primitive_observations(core)

    assert core["primitive_observations"] == []
    assert core["primitive_observation_count"] == 0
    assert len(core["findings"]) == 1
    finding = core["findings"][0]
    assert finding["severity"] == "HIGH"
    assert finding["facts"]["disposition"] == "UNVERIFIED_FIXED_PROGRAM"
    assert finding["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"
    assert core["finding_counts"] == {"SECURITY_DYNAMIC_EXECUTION": 1}
    assert core["state"] == "BLOCKED"


def test_partition_and_reseal_are_idempotent_for_current_fixed_program():
    import hashlib
    import json
    from factoryline import review_audits

    digest = "a" * 64
    sources = [{"path": "app.py", "sha256": digest}]
    workspace_sources = hashlib.sha256(
        json.dumps([["app.py", digest]], separators=(",", ":")).encode()
    ).hexdigest()
    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "severity": "INFO",
        "path": "app.py",
        "line": 1,
        "message": "fixed literal program",
        "facts": {
            "schema": "factory.fixed-literal-program.v1",
            "disposition": "PROVEN_FIXED_LITERAL_PROGRAM",
            "source_path": "app.py",
            "source_sha256": digest,
            "workspace_sources_sha256": workspace_sources,
            "program_sha256": "b" * 64,
        },
    }
    core = {
        "sources": sources,
        "findings": [finding],
        "primitive_observations": [],
        "finding_counts": {"SECURITY_DYNAMIC_EXECUTION": 1},
        "state": "FINDINGS",
        "tenant_read_contract": {},
        "oracle_context": {},
        "database_context": {},
    }
    first = review_audits._seal_security_scan(core)
    first_hash = first["audit_sha256"]
    first_observations = json.dumps(first["primitive_observations"], sort_keys=True)
    second = review_audits._seal_security_scan(core)

    assert second["audit_sha256"] == first_hash
    assert (
        json.dumps(second["primitive_observations"], sort_keys=True)
        == first_observations
    )
    assert second["primitive_observation_count"] == 1
    assert second["findings"] == []
    assert second["finding_counts"] == {}
    assert second["agent_actions"] == []


@pytest.mark.parametrize(
    "source, expected",
    [
        pytest.param(
            'enum = custom_namespace\nclass Code(str, enum.Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
            id="unimported-enum",
        ),
        pytest.param(
            'import enum\nenum = custom_namespace\nclass Code(str, enum.Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
            id="rebound-module-enum",
        ),
        (
            'from enum import Enum\nclass Code(str, Enum):\n    INVALID_PASSWORD = "INVALID_PASSWORD"\n',
            True,
        ),
        (
            'from enum import Enum as E\nclass Code(str, E):\n    BAD_SECRET = "BAD_SECRET"\n',
            True,
        ),
        (
            'import enum as e\nclass Code(str, e.Enum):\n    ACCESS_TOKEN_ERROR = "ACCESS_TOKEN_ERROR"\n',
            True,
        ),
        (
            'from enum import Enum\nclass Code(str, Enum):\n    PASSWORD: str = "PASSWORD"\n',
            True,
        ),
        ('PASSWORD = "PASSWORD"\n', False),
        (
            'from enum import Enum\nclass Code(str, Enum):\n    PASSWORD = "hunter2"\n',
            False,
        ),
        (
            'from local_enum import Enum\nclass Code(str, Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
        ),
        (
            'from .enum import Enum\nclass Code(str, Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
        ),
        (
            'from enum import Enum\nEnum = custom_enum\nclass Code(str, Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
        ),
        (
            'from enum import Enum\n@custom\nclass Code(str, Enum):\n    PASSWORD = "PASSWORD"\n',
            False,
        ),
        (
            'from enum import Enum\nclass Code(str, Enum, metaclass=Meta):\n    PASSWORD = "PASSWORD"\n',
            False,
        ),
        (
            'from enum import Enum\nclass Code(str, Enum):\n    PASSWORD = OTHER_SECRET = "PASSWORD"\n',
            False,
        ),
    ],
)
def test_credential_role_witness_is_not_a_secret_exemption(tmp_path, source, expected):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = [
        f
        for f in security_scan(tmp_path)["findings"]
        if f["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert findings and all(f["severity"] == "CRITICAL" for f in findings)
    for finding in findings:
        facts = finding["facts"]
        assert (facts.get("role_candidate") == "symbolic_enum_identifier") is expected
        if expected:
            assert facts["credential_use"] == "UNVERIFIED"
            assert facts["role_evidence_scope"] == "source_declaration_only"
            assert facts["missing_evidence"] == [
                "complete_import_reexport_and_consumer_closure"
            ]


def test_symbolic_enum_used_as_signing_key_still_reports_critical(tmp_path):
    (tmp_path / "app.py").write_text(
        'from enum import Enum\nclass Code(str, Enum):\n    PASSWORD = "PASSWORD"\n'
        "key = Code.PASSWORD.value\nstrategy = JWTStrategy(secret=key)\n",
        encoding="utf-8",
    )
    findings = [
        f
        for f in security_scan(tmp_path)["findings"]
        if f["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(findings) == 1 and findings[0]["severity"] == "CRITICAL"
    assert findings[0]["facts"]["credential_use"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, True),
        ({"danger.py": "import defs\nunknown_signer(defs)\n"}, False),
        (
            {
                "bridge.py": "from defs import Signal\n",
                "danger.py": "import bridge\nunknown_signer(bridge)\n",
            },
            False,
        ),
        (
            {
                "danger.py": "def configure():\n    import defs\n    return unknown_signer(defs)\n"
            },
            False,
        ),
        (
            {
                "fastapi.py": "def HTTPException(**kwargs):\n    return sign(kwargs['detail'])\n"
            },
            False,
        ),
        ({"enum.py": "class Enum:\n    pass\n"}, False),
        (
            {
                "danger.py": "from defs import Signal\nsigner(secret=Signal.BAD_PASSWORD)\n"
            },
            False,
        ),
        (
            {
                "api.py": "import defs\nfrom fastapi import HTTPException\ndef handler():\n    raise HTTPException(detail=defs.Signal.BAD_PASSWORD)\n"
            },
            True,
        ),
    ],
    ids=[
        "public",
        "module-escape",
        "reexport-escape",
        "nested-escape",
        "local-fastapi",
        "local-enum",
        "signing",
        "qualified-public",
    ],
)
def test_credential_consumer_closure_rejects_namespace_and_provider_escapes(
    tmp_path, changes, expected
):
    import ast
    import hashlib
    from factoryline import review_audits as audit, review_integrity as integrity

    sources = {
        "defs.py": 'from enum import Enum\nclass Signal(str, Enum):\n    BAD_PASSWORD = "BAD_PASSWORD"\n',
        "api.py": "from defs import Signal\nfrom fastapi import HTTPException\ndef handler():\n    raise HTTPException(detail=Signal.BAD_PASSWORD)\n",
        **changes,
    }
    raw = {tmp_path / name: source.encode() for name, source in sources.items()}
    for path, data in raw.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    inventory = {path: hashlib.sha256(data).hexdigest() for path, data in raw.items()}
    trees = {path: ast.parse(data) for path, data in raw.items()}
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
    imports = {
        path: audit._oracle_imports(tmp_path, path, tree, set(trees))
        for path, tree in trees.items()
    }
    graph = integrity._LiteralConsumers(
        tmp_path,
        trees,
        imports,
        audit,
        integrity,
        source_bytes=raw,
        inventory=inventory,
    )
    witnesses = graph.witnesses()
    assert bool(witnesses) is expected
    if expected:
        assert (tmp_path / "defs.py", 3, "BAD_PASSWORD") in witnesses
        assert all(
            use["source_sha256"] == inventory[tmp_path / use["path"]]
            for uses in witnesses.values()
            for use in uses
        )


@pytest.mark.parametrize(
    "consumer,expected",
    [
        ('assert Signal.BAD_PASSWORD == "BAD_PASSWORD"', True),
        ("assert Signal.BAD_PASSWORD == signer", False),
        (
            'router = build_router()\nsigner(secret=router.routes[0].responses[400]["detail"])',
            False,
        ),
    ],
)
def test_credential_consumer_comparisons_and_returned_metadata(
    tmp_path, consumer, expected
):
    import ast
    import hashlib
    from factoryline import review_audits as audit, review_integrity as integrity

    sources = {
        "defs.py": 'from enum import Enum\nclass Signal(str, Enum):\n    BAD_PASSWORD = "BAD_PASSWORD"\n',
        "api.py": "from defs import Signal\nfrom fastapi import HTTPException\ndef handler():\n    raise HTTPException(detail=Signal.BAD_PASSWORD)\n",
        "test_consumer.py": "from defs import Signal\n" + consumer + "\n",
    }
    if "router =" in consumer:
        sources["api.py"] = (
            "from defs import Signal\nfrom fastapi import APIRouter\n"
            "def build_router():\n    router = APIRouter()\n"
            "    @router.get('/', responses={400: {'detail': Signal.BAD_PASSWORD}})\n"
            "    def handler():\n        pass\n    return router\n"
        )
        sources["test_consumer.py"] = "from api import build_router\n" + consumer + "\n"
    raw = {tmp_path / name: source.encode() for name, source in sources.items()}
    for path, data in raw.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    inventory = {path: hashlib.sha256(data).hexdigest() for path, data in raw.items()}
    trees = {path: ast.parse(data) for path, data in raw.items()}
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
    imports = {
        path: audit._oracle_imports(tmp_path, path, tree, set(trees))
        for path, tree in trees.items()
    }
    graph = integrity._LiteralConsumers(
        tmp_path,
        trees,
        imports,
        audit,
        integrity,
        source_bytes=raw,
        inventory=inventory,
    )
    assert bool(graph.witnesses()) is expected


@pytest.mark.parametrize(
    "body",
    [
        "pass",
        "...",
        "for x in []:\n    assert result == 3",
        "for x in ():\n    run_oracle()",
        "for x in {}:\n    run_oracle()",
        "for x in '':\n    run_oracle()",
        "while False:\n    run_oracle()",
        "if False:\n    run_oracle()",
        "if True:\n    pass\nelse:\n    run_oracle()",
        "def check():\n    assert result == 3",
        "async def check():\n    assert result == 3",
        "value = 1\nreturn\nrun_oracle()",
        "value: factory() = 1",
        "assert True",
        "assert (1,)",
        "value = 3\nassert value == value",
        "value = 3\nassert value == 3",
        "value = 3\nvalue: int\nassert value == 3",
        "def noop():\n    pass\nnoop()",
        "def noop():\n    assert True\nnoop()",
        "def noop():\n    return\n    run_oracle()\nnoop()",
        "True or run_oracle()",
        "False and run_oracle()",
        "run_oracle() if False else None",
        "None if True else run_oracle()",
        "assert True or run_oracle()",
        "async def check():\n    assert result == 3\ncheck()",
    ],
)
def test_proven_inert_body(body):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    node = ast.parse(
        "def test_case():\n" + "\n".join("    " + line for line in body.splitlines())
    ).body[0]
    assert inert_test_body(node)


@pytest.mark.parametrize(
    "body",
    [
        "run_oracle()",
        "assert result == 3",
        "for x in []:\n    pass\nelse:\n    run_oracle()",
        "while False:\n    pass\nelse:\n    run_oracle()",
        "for x in [1]:\n    run_oracle()",
        "for x in values:\n    run_oracle()",
        "if condition:\n    run_oracle()",
        "def check(x=run_oracle()):\n    pass",
        "@run_oracle\ndef check():\n    pass",
        "def check(x: run_oracle()):\n    pass",
        "class Check(Base):\n    pass",
        "obj.value = 1",
        "value = factory()",
        "return run_oracle()",
        "import checks",
        "global value\nvalue = 1",
        "raise AssertionError('failed')",
        "assert False",
        "def check():\n    assert result == 3\ncheck()",
        "def check(arg):\n    pass\ncheck()",
        "True and run_oracle()",
        "False or run_oracle()",
        "run_oracle() if True else None",
        "None if False else run_oracle()",
        "value or True or run_oracle()",
        "value and False and run_oracle()",
        "async def check(arg):\n    assert arg == 3\ncheck()",
        "async def check():\n    assert result == 3\nawait check()",
        "def check():\n    pass\ncheck = unknown\ncheck()",
        "value = 1\nif True:\n    value = 2\nassert value == 1",
        "value = 1\nvalue: int\nif value == None:\n    pass\nelse:\n    run_oracle()",
        "value = 1\nfor x in []:\n    pass\nelse:\n    value = 2\nassert value == 1",
    ],
)
def test_unknown_or_actual_execution_not_inert(body):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    node = ast.parse(
        "def test_case():\n" + "\n".join("    " + line for line in body.splitlines())
    ).body[0]
    assert not inert_test_body(node)


@pytest.mark.parametrize(
    "body",
    [
        "for _ in [1]: break; product()",
        "for _ in [*()]: product()",
        "for _ in range(0): product()",
        "range = lambda count: []\nfor _ in range(1): product()",
        "unused = (product() for _ in [])",
    ],
)
def test_proven_inert_bounded_control_flow_shapes(body):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(
        "def test_case():\n" + "\n".join("    " + line for line in body.splitlines())
    )
    node = module.body[0]
    node._oracle_module = module
    assert inert_test_body(node)


def test_inert_unique_module_constant_helper_with_pytestmark():
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(
        "pytestmark = pytest.mark.benchmark()\n"
        "def product():\n"
        "    return 1\n"
        "def test_case():\n"
        "    product()\n"
    )
    node = module.body[-1]
    node._oracle_module = module
    assert inert_test_body(node)


@pytest.mark.parametrize(
    "source",
    [
        "def product():\n    opaque()\n    return 1\ndef test_case():\n    product()\n",
        "def product():\n    return 1\nalias = product\ndef test_case():\n    product()\n",
        "def product():\n    return 1\ndef test_case():\n    product()\n    product = opaque\n",
        "def product():\n    return 1\ndef product():\n    return 2\ndef test_case():\n    product()\n",
    ],
)
def test_inert_module_constant_helper_requires_closed_direct_binding(source):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(source)
    node = module.body[-1]
    node._oracle_module = module
    assert not inert_test_body(node)


@pytest.mark.parametrize(
    "source",
    [
        "def product():\n    return 1\ndef actual():\n    assert observed() == expected()\nglobals()['product'] = actual\ndef test_case():\n    product()\n",
        "def actual(count):\n    assert observed() == expected()\n    return []\nglobals()['range'] = actual\ndef test_case():\n    for _ in range(0):\n        opaque()\n",
        "def product():\n    return 1\ndef actual():\n    assert observed() == expected()\nvars()['product'] = actual\ndef test_case():\n    product()\n",
        "def product():\n    return 1\ndef actual():\n    assert observed() == expected()\nimport sys\nmodule = sys.modules[__name__]\nmodule.__dict__['product'] = actual\ndef test_case():\n    product()\n",
        "def product():\n    return 1\ndef actual():\n    assert observed() == expected()\ndef mutate():\n    namespace = globals\n    namespace()['product'] = actual\nmutate()\ndef test_case():\n    product()\n",
        "def product():\n    return 1\ndef actual():\n    assert observed() == expected()\nactual.__globals__['product'] = actual\ndef test_case():\n    product()\n",
        "def actual(count):\n    assert observed() == expected()\n    return []\nactual.__globals__['range'] = actual\ndef test_case():\n    for _ in range(0):\n        opaque()\n",
        "def product():\n    pass\ndef actual():\n    assert observed() == expected()\nglobals()['product'] = actual\ndef test_case():\n    product()\n",
        "def actual(count):\n    assert observed() == expected()\n    return []\nactual.__globals__['__builtins__']['range'] = actual\ndef test_case():\n    for _ in range(0):\n        opaque()\n",
        "import builtins\ndef actual(count):\n    assert observed() == expected()\n    return []\nbuiltins.range = actual\ndef test_case():\n    for _ in range(0):\n        opaque()\n",
    ],
)
def test_inert_bindings_reject_reflective_module_mutation(source):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(source)
    node = module.body[-1]
    node._oracle_module = module
    assert not inert_test_body(node)


def test_module_pass_context_helper_code_change_invalidates_native_key(
    tmp_path, monkeypatch
):
    from factoryline import review_audits as scanner
    from factoryline import test_oracle_misuse as oracle_misuse

    helper = oracle_misuse._module_pass_context_closed
    first = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(module, namespace_closed):
        return bool(namespace_closed)

    monkeypatch.setattr(helper, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != first


@pytest.mark.parametrize(
    "attribute",
    [
        "__globals__",
        "__builtins__",
        "__dict__",
        "__closure__",
        "f_globals",
        "f_locals",
        "gi_frame",
        "cr_frame",
        "ag_frame",
    ],
)
def test_inert_namespace_guard_rejects_function_and_frame_capabilities(attribute):
    import ast
    from factoryline.test_oracle_misuse import _module_namespace_access_closed

    module = ast.parse(f"def test_case():\n    value.{attribute}\n")
    assert not _module_namespace_access_closed(module)


def test_security_scan_keeps_directly_rebound_builtin_range_unknown(tmp_path):
    source = (
        "import builtins\n"
        "def product():\n"
        "    pass\n"
        "def actual(count):\n"
        "    assert observed() == expected()\n"
        "    return []\n"
        "builtins.range = actual\n"
        "def test_case():\n"
        "    for _ in range(0):\n"
        "        opaque()\n"
    )
    (tmp_path / "test_sample.py").write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)

    _assert_unknown_test_oracle(report, unknown_count=1)


@pytest.mark.parametrize(
    "body",
    [
        "for _ in range(1): run_oracle()",
        "for _ in [*(1,)]: run_oracle()",
        "for _ in [1]: run_oracle(); break",
        "for _ in range(0, 1, 0): run_oracle()",
        "range = lambda count: [1]\nfor _ in range(1): run_oracle()",
        "range = lambda count: []\nfor _ in range(run_oracle()): run_oracle()",
        "unused = (run_oracle() for _ in run_oracle())",
        "unused = (run_oracle() for _ in [])\nlist(unused)",
    ],
)
def test_bounded_control_flow_keeps_active_or_unknown_work(body):
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(
        "def test_case():\n" + "\n".join("    " + line for line in body.splitlines())
    )
    node = module.body[0]
    node._oracle_module = module
    assert not inert_test_body(node)


def test_bounded_control_flow_rejects_module_shadowed_builtin_range():
    import ast
    from factoryline.test_oracle_misuse import inert_test_body

    module = ast.parse(
        "range = lambda count: [1]\n"
        "def test_case():\n"
        "    for _ in range(0): run_oracle()\n"
    )
    node = module.body[1]
    node._oracle_module = module
    assert not inert_test_body(node)


@pytest.mark.parametrize("mismatch", [None, "root", "tree", "inventory", "missing"])
def test_captured_import_resolver_is_generation_bound(tmp_path, mismatch):
    import ast
    from factoryline.context_efficiency import captured_import_resolver

    path = tmp_path / "test_sample.py"
    tree = ast.parse("pass")
    snapshots, eligible, calls = {path: tree}, {path: path}, []

    def original(root, source, captured, inventory):
        calls.append(source)
        return {"helper": (path, None)}

    resolve = captured_import_resolver(tmp_path, snapshots, eligible, original)
    for _ in range(4):
        result = resolve(tmp_path, path, tree, eligible)
        result.clear()
    assert calls == [path]
    assert resolve(tmp_path, path, tree, eligible) == {"helper": (path, None)}
    if mismatch:
        args = [tmp_path, path, tree, eligible]
        index, replacement = {
            "root": (0, Path(str(tmp_path))),
            "tree": (2, ast.parse("pass")),
            "inventory": (3, dict(eligible)),
            "missing": (1, tmp_path / "other.py"),
        }[mismatch]
        args[index] = replacement
        with pytest.raises(ValueError, match="captured generation"):
            resolve(*args)


@pytest.mark.parametrize(
    "mutation",
    ["replace_tree", "add_tree", "remove_tree", "replace_inventory", "add_inventory"],
)
def test_captured_import_resolver_rejects_mutated_generation(tmp_path, mutation):
    import ast
    from factoryline.context_efficiency import captured_import_resolver

    path = tmp_path / "sample.py"
    tree = ast.parse("pass")
    snapshots, eligible = {path: tree}, {path: path}
    resolve = captured_import_resolver(tmp_path, snapshots, eligible, lambda *args: {})
    if mutation == "replace_tree":
        tree = snapshots[path] = ast.parse("import changed")
    elif mutation == "add_tree":
        snapshots[tmp_path / "new.py"] = ast.parse("pass")
    elif mutation == "remove_tree":
        snapshots.clear()
    elif mutation == "replace_inventory":
        eligible[path] = tmp_path / "other.py"
    else:
        eligible[tmp_path / "new.py"] = tmp_path / "new.py"
    with pytest.raises(ValueError, match="captured generation"):
        resolve(tmp_path, path, tree, eligible)


def test_code_replacement_with_captured_assertion_is_not_proven_inert(tmp_path):
    source = """
def test_behavior():
    checks = []
    required = 42
    def register(fn):
        checks.append(fn)
        return fn
    @register
    def check(value):
        assert value == required
    check.__code__ = (lambda value: None).__code__
    for callback in checks:
        callback(42)
"""
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path)["findings"]
    assert not any(finding["code"] == "QUALITY_HOLLOW_TEST" for finding in findings)


@pytest.mark.parametrize(
    "name,source,code,line",
    [
        (
            "attrs-docstring",
            'def test_hash_deprecated():\n    """Retained dead-test regression shape."""\n',
            "QUALITY_HOLLOW_TEST",
            1,
        ),
        (
            "constant-assert",
            "def test_constant():\n    assert True\n",
            "QUALITY_HOLLOW_TEST",
            1,
        ),
        ("pass", "def test_empty():\n    pass\n", "QUALITY_HOLLOW_TEST", 1),
        (
            "rich-soft-wrap",
            "def test_soft_wrap():\n    assert result() == 1\ndef test_soft_wrap():\n    assert result() == 2\n",
            "QUALITY_SHADOWED_TEST",
            1,
        ),
        (
            "rich-force-color",
            "def test_force_color():\n    assert result() == 1\ndef test_force_color():\n    assert result() == 2\n",
            "QUALITY_SHADOWED_TEST",
            1,
        ),
        (
            "rich-reverse-style",
            "class TestConsole:\n    def test_write_styled_reverse(self):\n        assert result() == 1\n    def test_write_styled_reverse(self):\n        assert result() == 2\n",
            "QUALITY_SHADOWED_TEST",
            2,
        ),
    ],
    ids=lambda value: value if isinstance(value, str) and "\n" not in value else None,
)
def test_oracle_family_updates_retain_must_stay_flags(
    tmp_path, name, source, code, line
):
    # Reduced source shapes preserve the reported defects; they are regression
    # controls, not a fresh external precision measurement.
    (tmp_path / "test_positive.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    matches = [
        item for item in findings if item["code"] == code and item["line"] == line
    ]
    assert len(matches) == 1, (name, findings)
    assert matches[0]["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}


def test_tenant_read_contract_preserves_scanner_facade_hooks(tmp_path, monkeypatch):
    import factoryline.review_audits as module

    observed = []

    def scope_read(call, bindings):
        observed.append((call, bindings))
        return {"sentinel": call}

    monkeypatch.setattr(module, "_tenant_scope_read", scope_read)
    monkeypatch.setattr(module, "_tenant_scoped_entries", lambda workspace, rows: rows)
    scopes = {"app.py": {"calls": ["app.read"], "bindings": {}}}
    assert module._validate_tenant_scopes(tmp_path, scopes) == [
        {"path": "app.py", "reads": [{"sentinel": "app.read"}]}
    ]
    assert observed == [("app.read", {})]


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import yaml\nyaml.load(data, yaml.SafeLoader)\n", False),
        ("import yaml\nyaml.load(data, Loader=yaml.CSafeLoader)\n", False),
        ("import yaml\nyaml.load(data, Loader=yaml.BaseLoader)\n", False),
        ("import yaml\nyaml.load(data, yaml.CBaseLoader)\n", False),
        (
            "from yaml import SafeLoader as Safe\nimport yaml\nyaml.load(data, Safe)\n",
            False,
        ),
        (
            "from yaml.loader import SafeLoader\nimport yaml\nyaml.load(data, Loader=SafeLoader)\n",
            False,
        ),
        ("import yaml\nyaml.load(data, Loader=CustomLoader)\n", True),
        ("import yaml\nyaml.load(data, Loader=yaml.Loader)\n", True),
        ("import yaml\nyaml.load(data, yaml.UnsafeLoader)\n", True),
        ("import yaml\nyaml.load(data, Loader=LooksSafeLoader)\n", True),
        (
            "import yaml\nyaml.load(data, yaml.SafeLoader, Loader=yaml.SafeLoader)\n",
            True,
        ),
        ("import yaml\nyaml.load(data, Loader=yaml.SafeLoader, **options)\n", True),
        (
            "import yaml\nfrom yaml import SafeLoader as Safe\nSafe = CustomLoader\nyaml.load(data, Loader=Safe)\n",
            True,
        ),
        (
            "import yaml\ndef parse(data, SafeLoader):\n    return yaml.load(data, Loader=SafeLoader)\n",
            True,
        ),
    ],
)
def test_yaml_loader_argument_requires_canonical_safe_provider(
    tmp_path, source, expected
):
    (tmp_path / "parse_input.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert any(item["code"] == "SECURITY_UNSAFE_YAML" for item in findings) is expected


@pytest.mark.parametrize(
    "fixture,type_path",
    [
        ("jwt", "jwt.api_jwt.PyJWT"),
        ("jws", "jwt.api_jws.PyJWS"),
    ],
)
def test_protocol_fixture_fake_provider_does_not_clear_secret_finding(
    tmp_path, fixture, type_path
):
    type_name = type_path.rsplit(".", 1)[-1]
    module_name = type_path.rsplit(".", 1)[0]
    source = (
        "import pytest\n"
        f"from {module_name} import {type_name}\n"
        f"@pytest.fixture\ndef {fixture}() -> {type_name}:\n"
        f"    return {type_name}()\n"
        f"class Test{type_name}:\n"
        f"    def test_roundtrip(self, {fixture}: {type_name}):\n"
        '        secret = "secret"\n'
        f"        token = {fixture}.encode({{'sub': 'sample'}}, secret)\n"
        f"        assert {fixture}.decode(token, secret) == {{'sub': 'sample'}}\n"
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")
    provider_path = tmp_path / Path(*module_name.split(".")).with_suffix(".py")
    provider_path.parent.mkdir(parents=True, exist_ok=True)
    provider_path.write_text(
        "import hashlib\n"
        f"class {type_name}:\n"
        "    def encode(self, payload, key):\n"
        "        return hashlib.sha256(key).hexdigest()\n"
        "    def decode(self, token, key):\n        return token\n",
        encoding="utf-8",
    )

    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert report.get("primitive_observation_count", 0) == 0


@pytest.mark.parametrize(
    "middle",
    [
        "secret = 'replacement-test-key'",
        "token = 'provider-issued-token'",
        "payload = fetch_external_payload()",
        "payload = {'sub': fetch_external_subject()}",
        "payload = {'sub': 'local'}\npayload = fetch_external_payload()",
    ],
)
def test_jwt_operation_contract_rejects_reassignment_and_nested_external_data(middle):
    import ast
    from factoryline.mock_fixture_provenance import (
        _jwt_crypto_operation_witness,
        _jwt_local_literal_uses,
    )

    module = ast.parse(
        "def test_case(jwt):\n"
        "    secret = 'local-test-key'\n"
        "    payload = {'sub': 'local'}\n"
        "    token = jwt.encode(payload, secret)\n"
        + "\n".join(f"    {line}" for line in middle.splitlines())
        + "\n    jwt.decode(token, secret)\n"
    )
    owner = module.body[0]
    if middle.startswith("secret ="):
        node = owner.body[0]
        assert not _jwt_local_literal_uses(node, node.targets[0], owner, "jwt", module)
        return
    assert _jwt_crypto_operation_witness(owner, "secret", "jwt", module, {}) is None


def test_jwt_operation_contract_allows_repeated_closed_token_reads():
    import ast

    from factoryline.mock_fixture_provenance import _jwt_crypto_operation_witness

    same_key = ast.parse(
        "def test_case(jwt):\n"
        "    secret = 'local-test-key'\n"
        "    payload = {'sub': 'local'}\n"
        "    token = jwt.encode(payload, secret)\n"
        "    jwt.decode(token, secret)\n"
        "    jwt.decode(token, secret, options={'verify_signature': False})\n"
    )
    assert (
        _jwt_crypto_operation_witness(same_key.body[0], "secret", "jwt", same_key, {})
        is not None
    )

    mismatched_key = ast.parse(
        "def test_case(jwt):\n"
        "    secret = 'local-test-key'\n"
        "    bad_secret = 'different-test-key'\n"
        "    payload = {'sub': 'local'}\n"
        "    token = jwt.encode(payload, secret)\n"
        "    jwt.decode(token, secret)\n"
        "    jwt.decode(token, bad_secret)\n"
    )
    assert (
        _jwt_crypto_operation_witness(
            mismatched_key.body[0], "secret", "jwt", mismatched_key, {}
        )
        is not None
    )


@pytest.mark.parametrize(
    "imports,signature,body,expected_mutation",
    [
        (
            "import pytest",
            "",
            "pytest.raises(TypeError, PyJWS, options=object())",
            False,
        ),
        ("import pytest as pt", "", "pt.raises((TypeError, ValueError), PyJWS)", False),
        ("from pytest import raises as check", "", "check(TypeError, PyJWS)", False),
        ("import pytest", "", "unknown.raises(TypeError, PyJWS)", True),
        ("import pytest", "pytest", "pytest.raises(TypeError, PyJWS)", True),
        (
            "import pytest\npytest = external",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        ("import pytest", "", "pytest.raises(PyJWS, external)", True),
        ("import pytest", "", "pytest.raises(TypeError, callback=PyJWS)", True),
        ("import pytest", "", "pytest.raises(*exceptions, PyJWS)", True),
        ("import pytest", "", "pytest.raises(TypeError, PyJWS, **options)", True),
        (
            "import pytest\nimport builtins\ngetattr(builtins, 'exec')('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nimport builtins\nvars(builtins)['exec']('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nimport builtins as b\nrunner = getattr(b, 'eval')\nrunner('0')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nexec('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nfrom builtins import exec as execute\nexecute('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nimport builtins as b\nb.exec('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest\nexecute = exec\nexecute('pytest.raises = external')",
            "",
            "pytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest",
            "",
            "alias = pytest\nalias.raises = external\npytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest",
            "",
            "raiser = pytest.raises\nraiser.__code__ = external\npytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest",
            "",
            "pytest.raises = external\npytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest",
            "",
            "setattr(pytest, 'raises', external)\npytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "import pytest",
            "",
            "monkeypatch.setattr(pytest, 'raises', external)\npytest.raises(TypeError, PyJWS)",
            True,
        ),
        (
            "from pytest import raises as check",
            "",
            "check.__code__ = external\ncheck(TypeError, PyJWS)",
            True,
        ),
        (
            "from pytest import raises as check",
            "",
            "check = external\ncheck(TypeError, PyJWS)",
            True,
        ),
    ],
)
def test_jwt_provider_class_callback_requires_canonical_pytest_callable_form(
    imports, signature, body, expected_mutation
):
    import ast

    from factoryline import mock_fixture_provenance as proof
    from factoryline import review_audits as audit

    module = ast.parse(
        imports + "\nfrom jwt.api_jws import PyJWS\n"
        "def jws():\n    return PyJWS()\n"
        f"def test_constructor({signature}):\n" + textwrap.indent(body, "    ") + "\n"
    )
    for parent in ast.walk(module):
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    aliases = audit._scope_security_aliases(
        audit._module_security_aliases(module), module
    )
    fixture = next(item for item in module.body if getattr(item, "name", None) == "jws")
    assert (
        proof._jwt_provider_is_mutated(module, "PyJWS", aliases, fixture)
        is expected_mutation
    )


@pytest.mark.parametrize(
    ("payload_operation", "expected_witness"),
    [
        ("payload['sub'] = fetch_external_subject()", False),
        ("populate_from_provider(payload)", False),
        ("alias = payload", False),
        ("payload['aud'] = 'urn:local-test'", True),
    ],
)
def test_jwt_payload_root_lifetime_rejects_unknown_mutation_and_allows_literal_update(
    payload_operation, expected_witness
):
    import ast
    from factoryline.mock_fixture_provenance import _jwt_crypto_operation_witness

    module = ast.parse(
        "def test_case(jwt):\n"
        "    secret = 'local-test-key'\n"
        "    payload = {'sub': 'local'}\n"
        f"    {payload_operation}\n"
        "    token = jwt.encode(payload, secret)\n"
        "    jwt.decode(token, secret)\n"
    )

    witness = _jwt_crypto_operation_witness(module.body[0], "secret", "jwt", module, {})

    assert (witness is not None) is expected_witness


def test_jwt_timestamp_fixture_generator_uses_captured_source_identity(tmp_path):
    import ast
    from pathlib import Path

    from factoryline import review_audits
    from factoryline.mock_fixture_provenance import (
        _jwt_captured_test_timestamp_call,
        _jwt_timestamp_helper_is_source_bound,
    )

    root = Path(tmp_path)
    source = (
        "from calendar import timegm\n"
        "from datetime import datetime, timezone\n"
        "def tick():\n"
        "    return timegm(datetime.now(tz=timezone.utc).utctimetuple())\n"
    ).encode()
    helper_path = root / "tests" / "utils.py"
    helper_path.parent.mkdir()
    helper_path.write_bytes(source)
    module = ast.parse("from .utils import tick as generated_now\n")
    module._security_source_context = (root, {helper_path: source})
    module._security_oracle_context = {
        "captured_imports": {"generated_now": ("tests/utils.py", "tick")}
    }
    aliases = review_audits._module_security_aliases(module)
    call = ast.parse("generated_now()").body[0].value

    assert _jwt_captured_test_timestamp_call(call, module, aliases)

    shadowed = ast.parse(
        "from .utils import tick as generated_now\ngenerated_now = remote_clock\n"
    )
    shadowed._security_source_context = (root, {helper_path: source})
    shadowed._security_oracle_context = module._security_oracle_context
    assert not _jwt_captured_test_timestamp_call(
        call, shadowed, review_audits._module_security_aliases(shadowed)
    )

    helper = ast.parse(source)
    helper_function = next(
        item
        for item in helper.body
        if isinstance(item, ast.FunctionDef) and item.name == "tick"
    )
    assert _jwt_timestamp_helper_is_source_bound(helper_function, helper)

    rebound = ast.parse(source.decode() + "timegm = external_clock\n")
    rebound_function = next(
        item
        for item in rebound.body
        if isinstance(item, ast.FunctionDef) and item.name == "tick"
    )
    assert not _jwt_timestamp_helper_is_source_bound(rebound_function, rebound)

    mutated_attribute = ast.parse(source.decode() + "datetime.now = external_clock\n")
    mutated_function = next(
        item
        for item in mutated_attribute.body
        if isinstance(item, ast.FunctionDef) and item.name == "tick"
    )
    assert not _jwt_timestamp_helper_is_source_bound(
        mutated_function, mutated_attribute
    )

    for mutation in (
        "setattr(datetime, 'now', external_clock)",
        "delattr(datetime, 'now')",
    ):
        mutated_dependency = ast.parse(source.decode() + mutation + "\n")
        mutated_function = next(
            item
            for item in mutated_dependency.body
            if isinstance(item, ast.FunctionDef) and item.name == "tick"
        )
        assert not _jwt_timestamp_helper_is_source_bound(
            mutated_function, mutated_dependency
        )


def test_jwt_provider_mutation_detector_rejects_provider_rebinding():
    import ast
    from factoryline.mock_fixture_provenance import (
        _jwt_provider_aliases,
        _jwt_provider_write,
    )

    provider = ast.parse("from jwt.api_jwt import PyJWT\nPyJWT.encode = replacement\n")
    aliases = {"PyJWT": "jwt.api_jwt.PyJWT"}
    provider_aliases = _jwt_provider_aliases(provider, "PyJWT", aliases)
    assert any(
        _jwt_provider_write(item, "PyJWT", aliases, provider_aliases)
        for item in ast.walk(provider)
    )


def test_jwt_role_proof_stays_active_when_source_inventory_is_incomplete(
    monkeypatch,
):
    from factoryline import primitive_observation_binding as binding
    from factoryline import review_audits as scanner

    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "severity": "CRITICAL",
        "path": "tests/test_api_jwt.py",
        "line": 2,
        "column": 4,
        "message": "JWT role evidence requires complete source inventory.",
        "facts": {"disposition": "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE"},
    }
    core = {
        "findings": [finding],
        "primitive_observations": [],
        "sources": [],
        "audit_coverage": {"complete": False},
        "database_context": None,
    }
    monkeypatch.setattr(
        scanner, "_fixed_primitive_binding", lambda *args: True, raising=False
    )
    binding.partition_proven_primitive_observations(core, scanner)

    assert core["primitive_observations"] == []
    assert len(core["findings"]) == 1
    assert core["findings"][0]["severity"] == "CRITICAL"
    assert core["findings"][0]["facts"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize(
    "extra",
    [
        'requests.post("https://example.test", json={"password": secret})\n',
        "return secret\n",
        "consume(secret)\n",
        "def nested():\n            return secret\n",
        "jwt = external_provider()\n",
    ],
)
def test_protocol_fixture_secret_escapes_remain_findings(tmp_path, extra):
    source = (
        "import pytest\n"
        "from jwt.api_jwt import PyJWT\n"
        "@pytest.fixture\ndef jwt() -> PyJWT:\n"
        "    return PyJWT()\n"
        "class TestJWT:\n"
        "    def test_roundtrip(self, jwt: PyJWT):\n"
        '        secret = "secret"\n'
        "        token = jwt.encode({'sub': 'sample'}, secret)\n"
        "        assert jwt.decode(token, secret) == {'sub': 'sample'}\n"
        + textwrap.indent(extra, "        ")
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert [(item["path"], item["line"]) for item in findings] == [
        ("test_protocol.py", 8)
    ]


@pytest.mark.parametrize("provider", ["Other()", "make_jwt()"])
def test_protocol_fixture_requires_exact_local_provider(tmp_path, provider):
    (tmp_path / "test_protocol.py").write_text(
        "import pytest\n"
        "from jwt.api_jwt import PyJWT\n"
        "@pytest.fixture\ndef jwt() -> PyJWT:\n"
        f"    return {provider}\n"
        "class TestJWT:\n"
        "    def test_roundtrip(self, jwt: PyJWT):\n"
        '        secret = "secret"\n'
        "        token = jwt.encode({'sub': 'sample'}, secret)\n"
        "        assert jwt.decode(token, secret) == {'sub': 'sample'}\n",
        encoding="utf-8",
    )

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert [(item["path"], item["line"]) for item in findings] == [
        ("test_protocol.py", 8)
    ]


@pytest.mark.parametrize(
    "extra_import,mutation",
    [
        ("", "PyJWT.encode = external_encode"),
        ("import jwt.api_jwt\n", "jwt.api_jwt.PyJWT.decode = external_decode"),
        ("", 'setattr(PyJWT, "encode", external_encode)'),
        (
            "from unittest.mock import patch\n",
            'patch("jwt.api_jwt.PyJWT.encode", external_encode)',
        ),
    ],
)
def test_protocol_fixture_rejects_provider_method_mutation(
    tmp_path, extra_import, mutation
):
    (tmp_path / "test_protocol.py").write_text(
        "import pytest\n" + extra_import + "from jwt.api_jwt import PyJWT\n"
        "@pytest.fixture\ndef jwt() -> PyJWT:\n"
        "    return PyJWT()\n"
        f"{mutation}\n"
        "class TestJWT:\n"
        "    def test_roundtrip(self, jwt: PyJWT):\n"
        '        secret = "secret"\n'
        "        token = jwt.encode({'sub': 'sample'}, secret)\n"
        "        assert jwt.decode(token, secret) == {'sub': 'sample'}\n",
        encoding="utf-8",
    )

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert len(findings) == 1
    assert findings[0]["path"] == "test_protocol.py"
    assert findings[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "case",
    [
        "receiver_method_write",
        "receiver_opaque_escape",
        "encoded_token_http_auth_escape",
        "local_fake_jwt_provider",
        "provider_secondary_alias_write",
        "nearer_class_fixture_override",
        "auth_token_return_indirect",
        "global_token_export",
    ],
)
def test_jwt_fixture_family_adversarial_roles_remain_critical(tmp_path, case):
    before, after, class_override = "", "", ""
    provider = (
        "import hashlib\n"
        "class PyJWT:\n"
        "    def encode(self, payload, key):\n"
        "        return hashlib.sha256(key).hexdigest()\n"
        "    def decode(self, token, key):\n        return token\n"
    )
    module_extra = ""
    if case == "receiver_method_write":
        before = "jwt.encode = leak"
    elif case == "receiver_opaque_escape":
        before = "mutate(jwt)"
    elif case == "encoded_token_http_auth_escape":
        after = (
            'requests.post("https://service.invalid", headers={"Authorization": token})'
        )
    elif case == "local_fake_jwt_provider":
        provider = (
            "import requests\n"
            "class PyJWT:\n"
            "    def encode(self, payload, key):\n"
            '        requests.post("https://service.invalid", auth=("account", key))\n'
            "        return key\n"
            "    def decode(self, token, key):\n        return token\n"
        )
    elif case == "provider_secondary_alias_write":
        module_extra = "Alias = PyJWT\nAlias.encode = leak\n"
    elif case == "nearer_class_fixture_override":
        class_override = (
            "    @pytest.fixture\n"
            "    def jwt(self) -> PyJWT:\n        return External()\n"
        )
    elif case == "auth_token_return_indirect":
        after = "result = token\nreturn result"
    elif case == "global_token_export":
        after = "global published\npublished = token"
    source = (
        "import pytest\nimport requests\nfrom jwt.api_jwt import PyJWT\n"
        "@pytest.fixture\ndef jwt() -> PyJWT:\n    return PyJWT()\n"
        + module_extra
        + "class TestJWT:\n"
        + class_override
        + "    def test_roundtrip(self, jwt: PyJWT):\n"
        + textwrap.indent(before + "\n" if before else "", "        ")
        + '        secret = "fixed-local-test-key"\n'
        + "        token = jwt.encode({'sub':'account'}, secret)\n"
        + "        assert jwt.decode(token, secret) == {'sub':'account'}\n"
        + textwrap.indent(after + "\n" if after else "", "        ")
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")
    provider_path = tmp_path / "jwt" / "api_jwt.py"
    provider_path.parent.mkdir(parents=True)
    provider_path.write_text(provider, encoding="utf-8")

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_global_test_literal_remains_a_finding(tmp_path):
    (tmp_path / "test_protocol.py").write_text(
        "import pytest\n"
        "from jwt.api_jwt import PyJWT\n"
        "@pytest.fixture\ndef jwt() -> PyJWT:\n"
        "    return PyJWT()\n"
        "class TestJWT:\n"
        "    def test_roundtrip(self, jwt: PyJWT):\n"
        "        global secret\n"
        '        secret = "secret"\n'
        "        token = jwt.encode({'sub': 'sample'}, secret)\n"
        "        assert jwt.decode(token, secret) == {'sub': 'sample'}\n",
        encoding="utf-8",
    )

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert [(item["path"], item["line"]) for item in findings] == [
        ("test_protocol.py", 9)
    ]


def test_oauth_method_catalog_literals_stay_active_without_consumer_proof(tmp_path):
    (tmp_path / "models.py").write_text(
        "class Application:\n"
        '    TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"\n'
        '    TOKEN_AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post"\n'
        "    TOKEN_AUTH_METHODS = (\n"
        '        (TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC, "Basic"),\n'
        '        (TOKEN_AUTH_METHOD_CLIENT_SECRET_POST, "Post"),\n'
        "    )\n",
        encoding="utf-8",
    )

    findings = [
        item
        for item in security_scan(tmp_path, cache_enabled=False)["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]

    assert [(item["path"], item["line"]) for item in findings] == [
        ("models.py", 2),
        ("models.py", 3),
    ]


def test_jwt_fixture_proof_helper_code_change_invalidates_native_key(
    tmp_path, monkeypatch
):
    from factoryline import mock_fixture_provenance, review_audits as scanner

    helper = mock_fixture_provenance.closed_jwt_test_literal
    first = scanner._oracle_context_cache_key(tmp_path, [], {})

    def replacement(relative, node, target):
        return None

    monkeypatch.setattr(helper, "__code__", replacement.__code__)
    assert scanner._oracle_context_cache_key(tmp_path, [], {}) != first


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\ndef explode(name):\n    raise ValueError(name)\n"
                    "product.__getattr__ = explode\ndef test_public():\n    product.missing\n"
                ),
            },
            id="module-getter-replaced",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\nimport builtins\ndef explode():\n    raise RuntimeError()\n"
                    "builtins.object = explode\ndef test_public():\n    product.missing\n"
                ),
            },
            id="builtin-object-replaced",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\nimport pytest\ndef explode(name):\n    raise ValueError(name)\n"
                    "@pytest.fixture(autouse=True)\ndef install():\n    product.__getattr__ = explode\n"
                    "def test_public():\n    product.missing\n"
                ),
            },
            id="same-module-autouse-getter",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\nimport pytest\nimport builtins\ndef explode():\n    raise RuntimeError()\n"
                    "@pytest.fixture(autouse=True)\ndef install():\n    builtins.object = explode\n"
                    "def test_public():\n    product.missing\n"
                ),
            },
            id="same-module-autouse-builtin",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\nimport pytest\ndef explode(name):\n    raise ValueError(name)\n"
                    "@pytest.fixture\ndef install():\n    product.__getattr__ = explode\n"
                    "def test_public(install):\n    product.missing\n"
                ),
            },
            id="explicit-fixture-getter",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\nimport pytest\ndef explode(name):\n    raise ValueError(name)\n"
                    "@pytest.fixture\ndef install():\n    product.__getattr__ = explode\n"
                    "@pytest.mark.usefixtures('install')\ndef test_public():\n    product.missing\n"
                ),
            },
            id="marked-fixture-getter",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "conftest.py": (
                    "import pytest\nimport product\ndef explode(name):\n    raise ValueError(name)\n"
                    "@pytest.fixture(autouse=True)\ndef install():\n    product.__getattr__ = explode\n"
                ),
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="conftest-autouse-getter",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": (
                    "import product\ndef explode(name):\n    raise ValueError(name)\ndef replace(fn):\n"
                    "    product.__getattr__ = explode\n    return fn\n@replace\ndef test_public():\n"
                    "    product.missing\n"
                ),
            },
            id="effectful-test-decorator",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": "import product\ndef test_public():\n    product.__getattr__\n",
            },
            id="existing-module-getattr-attribute",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "test_product.py": "import product\ndef test_public():\n    product.__name__\n",
            },
            id="existing-module-name-attribute",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object()\n",
                "other.py": "raise ValueError()\n",
                "test_product.py": (
                    "import product\ndef test_public():\n    import other\n    product.missing\n"
                ),
            },
            id="test-body-eager-import",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object(1)\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="bad-arity-literal",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object(name)\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="bad-arity-name",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object(1, 2)\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="bad-arity-two-arguments",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    return object(x=1)\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="bad-arity-keyword",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(key, /):\n    return object()\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="getter-positional-only-binding",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(*name):\n    return object()\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="getter-variadic-binding",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    object = lambda: None\n    return object()\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="getter-local-object-rebinding",
        ),
        pytest.param(
            {
                "product.py": "def __getattr__(name):\n    raise AttributeError(name)\n",
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="getter-raises",
        ),
        pytest.param(
            {
                "product.py": (
                    "def __getattr__(name):\n    return object()\n"
                    "object = lambda: None\n"
                ),
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="module-builtin-rebinding",
        ),
        pytest.param(
            {
                "product.py": (
                    "def __getattr__(name):\n    return object()\n"
                    "__getattr__ = lambda name: object()\n"
                ),
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="module-getter-rebinding",
        ),
        pytest.param(
            {
                "product.py": (
                    "def __getattr__(name, seed=object()):\n    return object()\n"
                ),
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="getter-eager-default-effect",
        ),
        pytest.param(
            {
                "product.py": (
                    "events = []\nevents.append('loaded')\n"
                    "def __getattr__(name):\n    return object()\n"
                ),
                "test_product.py": "import product\ndef test_public():\n    product.missing\n",
            },
            id="module-eager-effect",
        ),
    ],
)
def test_dynamic_module_lookup_requires_current_binding_and_completion_proof(
    tmp_path, files
):
    """Unwitnessed runtime effects and invalid calls must remain exact UNKNOWN."""
    for name, source in files.items():
        (tmp_path / name).write_text(source)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_UNKNOWN_TEST_ORACLE": 1}


def test_malformed_dynamic_getter_source_reports_syntax_error(tmp_path):
    (tmp_path / "product.py").write_text("def __getattr__(name)\n    return object()\n")
    (tmp_path / "test_product.py").write_text(
        "import product\ndef test_public():\n    product.missing\n"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_SYNTAX_ERROR": 1}


@pytest.mark.parametrize(
    "decorator,signature,body,expected",
    [
        (
            '@pytest.mark.parametrize(("segment", "decoded"), '
            '[(b"Zg", b"f"), (b"Zm8=", b"fo")])',
            "self, segment: bytes, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            True,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(b"Zg", make_bytes())])',
            "self, segment: bytes, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize("segment", [b"Zg===", b"Z?=="])',
            "self, segment: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            True,
        ),
        (
            "",
            "self",
            'PyJWS._decode_base64url_segment(b"Zg", "crypto")',
            True,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), values)',
            "self, segment: bytes, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(make_bytes(), b"f")])',
            "self, segment: bytes, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), '
            '[(b"Zg", b"f")], indirect=True)',
            "self, segment: bytes, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(b"Zg", b"f")])',
            "self, segment, decoded: bytes",
            'PyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(b"Zg", b"f")])',
            "self, segment: bytes, decoded: bytes",
            'segment = b"other"\nPyJWS._decode_base64url_segment(segment, "crypto")',
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(b"Zg", b"f")])',
            "self, segment: bytes, decoded: bytes",
            "PyJWS._decode_base64url_segment(segment, encoding)",
            False,
        ),
        (
            '@pytest.mark.parametrize(("segment", "decoded"), [(b"Zg", b"f")])',
            "self, segment: bytes, decoded: bytes",
            'jws._decode_base64url_segment(segment, "crypto")',
            False,
        ),
    ],
)
def test_jwt_static_provider_call_requires_literal_bytes_domain(
    decorator, signature, body, expected
):
    import ast

    from factoryline import mock_fixture_provenance as proof

    source = (
        "import pytest\nfrom jwt.api_jws import PyJWS\n"
        "def jws():\n    return PyJWS()\n"
        "class TestDecode:\n"
        f"    {decorator}\n"
        if decorator
        else "import pytest\nfrom jwt.api_jws import PyJWS\n"
        "def jws():\n    return PyJWS()\n"
        "class TestDecode:\n"
    )
    source += (
        f"    def test_decode({signature}):\n"
        + textwrap.indent(body, "        ")
        + "\n"
    )
    module = ast.parse(source)
    for parent in ast.walk(module):
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    fixture = next(item for item in module.body if getattr(item, "name", None) == "jws")
    call = (
        next(
            item
            for item in ast.walk(module)
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr == "_decode_base64url_segment"
        )
        if "PyJWS._decode_base64url_segment" in source
        else None
    )
    if call is None:
        assert not expected
        return
    assert proof._jwt_provider_static_call_shape(
        call.func.value, call.func, fixture, {"PyJWS"}
    ) is (call if expected else None)


@pytest.mark.parametrize(
    "parameter,expected",
    [("", True), ("PyJWS", False)],
)
def test_jwt_static_provider_call_rejects_lexical_provider_shadow(
    monkeypatch, parameter, expected
):
    import ast

    from factoryline import mock_fixture_provenance as proof

    module = ast.parse(
        "from jwt.api_jws import PyJWS\n"
        "def jws():\n    return PyJWS()\n"
        f"def test_decode({parameter}):\n"
        "    PyJWS._decode_base64url_segment(b'Zg', 'crypto')\n"
    )
    for parent in ast.walk(module):
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    test = next(
        node for node in module.body if getattr(node, "name", None) == "test_decode"
    )
    name = next(
        node
        for node in ast.walk(test)
        if isinstance(node, ast.Name) and node.id == "PyJWS"
    )
    fixture = next(node for node in module.body if getattr(node, "name", None) == "jws")
    monkeypatch.setattr(proof, "module_for", lambda _node: module)
    monkeypatch.setattr(
        proof, "_jwt_captured_import_binding_is_stable", lambda *_: True
    )
    monkeypatch.setattr(proof, "_jwt_static_source_profile", lambda *_: True)

    assert (
        proof._jwt_provider_static_call_is_closed(
            name, name._security_parent, fixture, {"PyJWS"}
        )
        is expected
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "alias = pytest\nalias.mark.parametrize = external",
        "parametrize = pytest.mark.parametrize\nparametrize.__code__ = external",
    ],
)
def test_jwt_static_parametrize_rejects_escaped_callable_mutation(mutation):
    import ast

    from factoryline import mock_fixture_provenance as proof

    module = ast.parse(
        "import pytest\n"
        f"{mutation}\n"
        "@pytest.mark.parametrize('segment', [b'Zg'])\n"
        "def test_decode(segment: bytes):\n    pass\n"
    )
    for parent in ast.walk(module):
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    owner = next(
        node for node in module.body if getattr(node, "name", None) == "test_decode"
    )

    assert proof._jwt_static_parametrize_decorator(module, owner) is None
