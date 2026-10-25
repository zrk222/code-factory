import ast
import pytest
from factoryline.review_audits import _security_aliases
from factoryline.semantic_credential_sensor import (
    configuration_and_credential_findings,
    credential_findings,
)
from factoryline import review_audits as audit
from factoryline import semantic_credential_sensor as sensors


def _scan(source):
    tree = ast.parse(source)
    return credential_findings(
        tree, _security_aliases(list(ast.walk(tree))), "sample.py"
    )


def _premise_scan(source):
    from pathlib import Path

    return audit._security_scan_tree(
        Path("."), Path("application.py"), ast.parse(source)
    )


@pytest.mark.parametrize(
    "helper, invocation",
    [
        (
            "def identity(value):\n    alias = value\n    return alias\n",
            "identity(request.get_data(as_text=True))",
        ),
        (
            "def identity(value, /, *, extra=''):\n    alias = value\n    return alias\n",
            "identity(request.get_data(as_text=True), extra='')",
        ),
        (
            "def identity(value, fallback=''):\n    alias = value\n    return alias\n",
            "identity(value=request.get_data(as_text=True))",
        ),
    ],
)
def test_native_flow_helper_return_reaches_primary_verdict(helper, invocation):
    findings = _premise_scan(
        "from flask import request\n" + helper + f"eval({invocation})\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert dynamic[0]["facts"]["security_precondition"]["status"] == "SUPPORTED"


@pytest.mark.parametrize(
    "body, invocation",
    [
        ("alias = value\n    eval(alias)", "consume(request.get_data(as_text=True))"),
        ("eval(value)", "consume(value=request.get_data(as_text=True))"),
    ],
)
def test_native_flow_actual_argument_reaches_callee_sink(body, invocation):
    findings = _premise_scan(
        "from flask import request\ndef consume(value):\n    "
        + body
        + "\n"
        + invocation
        + "\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert dynamic[0]["facts"]["security_precondition"]["status"] == "SUPPORTED"


@pytest.mark.parametrize(
    "helper, invocation, mutation",
    [
        (
            "def identity(value):\n    value = '1'\n    return value\n",
            "identity(request.get_data(as_text=True))",
            "",
        ),
        (
            "def identity(value):\n    alias = opaque(value)\n    return alias\n",
            "identity(request.get_data(as_text=True))",
            "",
        ),
        ("def identity(value):\n    return value\n", "identity(*values)", ""),
        (
            "def identity(value='1'):\n    return value\n",
            "identity()",
            "value = request.get_data(as_text=True)\n",
        ),
        (
            "def identity(value):\n    return value\n",
            "identity(request.get_data(as_text=True))",
            "identity.__code__ = replacement\n",
        ),
        (
            "@decorate\ndef identity(value):\n    return value\n",
            "identity(request.get_data(as_text=True))",
            "",
        ),
        (
            "def identity(value):\n    return identity(value)\n",
            "identity(request.get_data(as_text=True))",
            "",
        ),
    ],
)
def test_native_flow_unproved_helpers_retain_raw_without_support(
    helper, invocation, mutation
):
    findings = _premise_scan(
        "from flask import request\n" + helper + mutation + f"eval({invocation})\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert "security_precondition" not in dynamic[0]["facts"]


@pytest.mark.parametrize(
    "body, suffix",
    [
        ("value = '1'\n    eval(value)", "consume(request.get_data(as_text=True))"),
        ("eval(value)", "consume(opaque(request.get_data(as_text=True)))"),
        ("return\n    eval(value)", "consume(request.get_data(as_text=True))"),
        (
            "eval(value)",
            "consume.__code__ = replacement\nconsume(request.get_data(as_text=True))",
        ),
    ],
)
def test_native_flow_callee_unknown_or_killed_flow_retains_raw(body, suffix):
    findings = _premise_scan(
        "from flask import request\ndef consume(value):\n    "
        + body
        + "\n"
        + suffix
        + "\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert "security_precondition" not in dynamic[0]["facts"]


@pytest.mark.parametrize("as_text, supported", [(False, True), (True, False)])
def test_native_flow_pickle_argument_kind_preserved(as_text, supported):
    findings = _premise_scan(
        "import pickle\nfrom flask import request\n"
        "def consume(value):\n    alias = value\n    return pickle.loads(alias)\n"
        f"consume(request.get_data(as_text={as_text!r}))\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_UNSAFE_DESERIALIZATION"]
    assert len(dynamic) == 1
    assert bool(dynamic[0]["facts"].get("security_precondition")) is supported


@pytest.mark.parametrize(
    "mutation",
    [
        "alias = identity\nalias.__code__ = replacement\n",
        "setattr(identity, '__code__', replacement)\n",
        "mutator(identity)\n",
        "identity.__defaults__ = (replacement,)\n",
    ],
)
def test_native_flow_provider_capability_mutation_abstains(mutation):
    findings = _premise_scan(
        "from flask import request\ndef identity(value):\n    alias = value\n    return alias\n"
        + mutation
        + "eval(identity(request.get_data(as_text=True)))\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert "security_precondition" not in dynamic[0]["facts"]


def test_native_flow_precondition_is_independently_recomputed():
    source = (
        "from flask import request\ndef identity(value):\n    alias = value\n    return alias\n"
        "eval(identity(request.get_data(as_text=True)))\n"
    )
    report = _private_key_auth_tiers(source)
    row = next(
        x
        for x in report["ledger"]
        if x["raw_finding"]["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    # Keep the claimed fact but replace the helper's actual implementation.
    changed = source.replace("alias = value", "alias = '1'")
    report = _private_key_auth_tiers(changed, findings=_premise_scan(source))
    row = next(
        x
        for x in report["ledger"]
        if x["raw_finding"]["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )
    assert row["tier"] == "NEEDS_CONTEXT"


@pytest.mark.parametrize(
    "source",
    [
        "def identity(value):\n    return value\n    yield None\neval(identity(request.get_data(as_text=True)))\n",
        "def consume(value):\n    yield None\n    eval(value)\nconsume(request.get_data(as_text=True))\n",
        "def consume(value):\n    opaque_effect()\n    eval(value)\nconsume(request.get_data(as_text=True))\n",
        "def identity(value, other=opaque_effect()):\n    return value\neval(identity(request.get_data(as_text=True)))\n",
        "def consume(value):\n    doomed = 1 / 0\n    eval(value)\nconsume(request.get_data(as_text=True))\n",
        "def identity(value: 1 / 0):\n    return value\neval(identity(request.get_data(as_text=True)))\n",
        "def consume(value):\n    alias: opaque_effect() = value\n    eval(alias)\nconsume(request.get_data(as_text=True))\n",
        "def consume(value):\n    doomed = value / 2\n    eval(value)\nconsume(request.get_data(as_text=True))\n",
        "def identity(value):\n    return value / 2\neval(identity(request.get_data(as_text=True)))\n",
        "def consume(value):\n    eval(value)\nconsume(request.get_data(as_text=True) / 2)\n",
        "def identity(value):\n    alias: opaque_effect() = value\n    return alias\neval(identity(request.get_data(as_text=True)))\n",
        "def identity(value=undefined_default):\n    return value\neval(identity(request.get_data(as_text=True)))\n",
    ],
)
def test_native_flow_generator_or_opaque_effect_does_not_certify(source):
    findings = _premise_scan("from flask import request\n" + source)
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert "security_precondition" not in dynamic[0]["facts"]


def test_native_flow_provider_guard_reuse_is_limited_to_one_source_scan(monkeypatch):
    from factoryline import intent_quality

    inspected = []
    original = intent_quality._sanitizer_provider_mutated

    def counted(module, call, aliases, expected, head, reader):
        if expected == "identity":
            inspected.append(id(module))
        return original(module, call, aliases, expected, head, reader)

    monkeypatch.setattr(intent_quality, "_sanitizer_provider_mutated", counted)
    source = (
        "from flask import request\ndef identity(value):\n    alias = value\n    return alias\n"
        "eval(identity(request.get_data(as_text=True)))\n"
        "eval(identity(request.get_data(as_text=True)))\n"
    )
    assert len(_premise_scan(source)) == 2
    assert len(inspected) == 1
    mutated = source.replace(
        "eval(identity", "identity.__code__ = replacement\neval(identity", 1
    )
    findings = _premise_scan(mutated)
    assert len(inspected) == 2
    assert all("security_precondition" not in finding["facts"] for finding in findings)


@pytest.mark.parametrize("length, supported", [(2, True), (10, False)])
def test_native_flow_helper_depth_cutoff_never_becomes_support(length, supported):
    functions = [
        f"def helper{i}(value):\n    return "
        + (f"helper{i + 1}(value)\n" if i + 1 < length else "value\n")
        for i in range(length)
    ]
    findings = _premise_scan(
        "from flask import request\n"
        + "".join(functions)
        + "eval(helper0(request.get_data(as_text=True)))\n"
    )
    dynamic = [x for x in findings if x["code"] == "SECURITY_DYNAMIC_EXECUTION"]
    assert len(dynamic) == 1
    assert bool(dynamic[0]["facts"].get("security_precondition")) is supported


def _configuration_tiers277(files, *, omit=()):
    from hashlib import sha256
    from pathlib import Path
    from factoryline.primitive_observation_binding import build_finding_tier_report

    sources = {name: value.encode() for name, value in files.items()}
    findings = audit._security_scan_tree(
        Path("."),
        Path("service/settings.py"),
        ast.parse(sources["service/settings.py"]),
    )
    assert any(item["code"] == "SECURITY_HARDCODED_SECRET" for item in findings)
    return build_finding_tier_report(
        findings,
        [],
        [
            {"path": name, "sha256": sha256(raw).hexdigest()}
            for name, raw in sources.items()
        ],
        {name: raw for name, raw in sources.items() if name not in omit},
        coverage_state=True,
        partition_state="VALIDATED",
    )


def _configuration_files277(runner):
    return {
        "service/__init__.py": "",
        "service/settings.py": 'SECRET_KEY = "published-weak-value"\n',
        "service/start.py": runner,
    }


_FLASK_AUTHORITY_SOURCE314 = """
from flask import Flask, redirect, request, session

ADMIN_PASSWORD = "source-bound-admin-password"
SECRET_KEY = "source-bound-session-secret"
app = Flask(__name__)
app.config.from_object(__name__)

def login_required(fn):
    def inner(*args, **kwargs):
        if session.get("logged_in"):
            return fn(*args, **kwargs)
        return redirect("/login")
    return inner

@app.route("/login", methods=["GET", "POST"])
def login():
    password = request.form.get("password")
    if password == app.config["ADMIN_PASSWORD"]:
        session["logged_in"] = True
        return redirect("/")
    return redirect("/login")

@app.route("/create")
@login_required
def create():
    return "created"
"""


def _flask_authority_tiers314(source=_FLASK_AUTHORITY_SOURCE314, extra_sources=None):
    from hashlib import sha256
    from pathlib import Path
    from factoryline.primitive_observation_binding import build_finding_tier_report

    path = "examples/blog/app.py"
    sources = {
        "examples/blog/__init__.py": b"",
        path: source.encode(),
    }
    sources.update(
        {name: value.encode() for name, value in (extra_sources or {}).items()}
    )
    findings = audit._security_scan_tree(Path("."), Path(path), ast.parse(source))
    selected = [
        finding
        for finding in findings
        if finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and (
            finding.get("facts", {}).get("name") == "SECRET_KEY"
            or "PASSWORD" in finding.get("facts", {}).get("name", "")
        )
    ]
    return build_finding_tier_report(
        selected,
        [],
        [
            {"path": name, "sha256": sha256(raw).hexdigest()}
            for name, raw in sources.items()
        ],
        sources,
        coverage_state=True,
        partition_state="VALIDATED",
    )


def test_tier314_flask_session_authority_preserves_both_source_diagnostics():
    report = _flask_authority_tiers314()
    rows = report["ledger"]
    assert len(rows) == 2
    assert {row["raw_finding"]["facts"]["name"] for row in rows} == {
        "ADMIN_PASSWORD",
        "SECRET_KEY",
    }
    assert {row["tier"] for row in rows} == {"SUPPORTED_DEFECT"}
    assert {row["evidence"] for row in rows} == {"source_bound_flask_session_authority"}
    for row in rows:
        observation = row["credential_authority_observation"]
        assert observation["proof_scope"] == "source_bound_flask_session_authority"
        assert observation["runtime_execution"] == "not_performed"
        assert observation["deployment"] == "UNASSESSED"
        expected_transfers = (
            9 if row["raw_finding"]["facts"]["name"] == "ADMIN_PASSWORD" else 8
        )
        assert len(observation["transfers"]) == expected_transfers
        assert all(
            transfer["sha256"] == row["source_identity"]["source_sha256"]
            for transfer in observation["transfers"]
        )


def test_tier314_flask_authority_tracks_renamed_password_configuration_key():
    source = _FLASK_AUTHORITY_SOURCE314.replace("ADMIN_PASSWORD", "DASHBOARD_PASSWORD")
    report = _flask_authority_tiers314(source)
    assert {row["raw_finding"]["facts"]["name"] for row in report["ledger"]} == {
        "DASHBOARD_PASSWORD",
        "SECRET_KEY",
    }
    assert {row["tier"] for row in report["ledger"]} == {"SUPPORTED_DEFECT"}


def _flask_authority_counterexample_source(replacement):
    source = _FLASK_AUTHORITY_SOURCE314

    def insert(text):
        return source.replace(
            "def login_required(fn):", text + "\n\ndef login_required(fn):"
        )

    return {
        'ADMIN_PASSWORD = "overwritten-admin-password"': lambda: insert(
            'ADMIN_PASSWORD = "overwritten-admin-password"'
        ),
        'app.config["ADMIN_PASSWORD"] = "overwritten-admin-password"': lambda: insert(
            'app.config["ADMIN_PASSWORD"] = "overwritten-admin-password"'
        ),
        'app.config.update(ADMIN_PASSWORD="overwritten-admin-password")': lambda: insert(
            'app.config.update(ADMIN_PASSWORD="overwritten-admin-password")'
        ),
        "app = object()": lambda: insert("app = object()"),
        "Flask = object": lambda: insert("Flask = object"),
        'app.config.from_object("other.settings")': lambda: source.replace(
            "app.config.from_object(__name__)",
            'app.config.from_object("other.settings")',
        ),
        'other = Flask(__name__)\n@other.route("/login", methods=["GET", "POST"])': lambda: source.replace(
            '@app.route("/login", methods=["GET", "POST"])', replacement
        ),
        "if password == app.config[config_key]:": lambda: source.replace(
            'if password == app.config["ADMIN_PASSWORD"]:', replacement
        ),
        'if password == app.config["ADMIN_PASSWORD"]:\n        pass': lambda: source.replace(
            'if password == app.config["ADMIN_PASSWORD"]:\n'
            '        session["logged_in"] = True',
            replacement,
        ),
        "dead_comparison": lambda: source.replace(
            '    if password == app.config["ADMIN_PASSWORD"]:\n'
            '        session["logged_in"] = True\n'
            '        return redirect("/")',
            "    if False:\n"
            '        if password == app.config["ADMIN_PASSWORD"]:\n'
            '            session["logged_in"] = True\n'
            '            return redirect("/")',
        ),
        "missing_login_consumer": lambda: source.replace("@login_required\n", ""),
    }[replacement]()


@pytest.mark.parametrize(
    "replacement",
    [
        'ADMIN_PASSWORD = "overwritten-admin-password"',
        'app.config["ADMIN_PASSWORD"] = "overwritten-admin-password"',
        'app.config.update(ADMIN_PASSWORD="overwritten-admin-password")',
        "app = object()",
        "Flask = object",
        'app.config.from_object("other.settings")',
        'other = Flask(__name__)\n@other.route("/login", methods=["GET", "POST"])',
        "if password == app.config[config_key]:",
        'if password == app.config["ADMIN_PASSWORD"]:\n        pass',
        "dead_comparison",
        "missing_login_consumer",
    ],
)
def test_tier314_flask_authority_counterexamples_abstain(replacement):
    report = _flask_authority_tiers314(
        _flask_authority_counterexample_source(replacement)
    )
    admin_rows = [
        row
        for row in report["ledger"]
        if row["raw_finding"].get("facts", {}).get("name") == "ADMIN_PASSWORD"
    ]
    assert admin_rows
    assert all(row["tier"] == "NEEDS_CONTEXT" for row in admin_rows)
    assert all("credential_authority_observation" not in row for row in admin_rows)


def test_tier314_flask_configuration_load_alone_does_not_promote_secret_key():
    source = """
from flask import Flask
SECRET_KEY = "published-weak-value"
app = Flask(__name__)
app.config.from_object(__name__)
"""
    report = _flask_authority_tiers314(source)
    assert report["ledger"]
    assert all(row["tier"] == "NEEDS_CONTEXT" for row in report["ledger"])


def test_tier314_flask_authority_proves_star_imports_only_from_closed_sources():
    safe = _flask_authority_tiers314(
        "from examples.safe_imports import *\n" + _FLASK_AUTHORITY_SOURCE314,
        {"examples/safe_imports.py": "PUBLIC_VALUE = 1\n"},
    )
    assert {row["tier"] for row in safe["ledger"]} == {"SUPPORTED_DEFECT"}

    shadowed = _flask_authority_tiers314(
        "from examples.shadow_imports import *\n" + _FLASK_AUTHORITY_SOURCE314,
        {"examples/shadow_imports.py": "Flask = object\n"},
    )
    assert {row["tier"] for row in shadowed["ledger"]} == {"NEEDS_CONTEXT"}

    opaque = _flask_authority_tiers314(
        "from missing_provider import *\n" + _FLASK_AUTHORITY_SOURCE314
    )
    assert {row["tier"] for row in opaque["ledger"]} == {"NEEDS_CONTEXT"}

    dynamic = _flask_authority_tiers314(
        "from examples.dynamic_exports import *\n" + _FLASK_AUTHORITY_SOURCE314,
        {
            "examples/dynamic_exports.py": "__all__ = ['SAFE_VALUE']\n"
            "__all__.append('Flask')\nSAFE_VALUE = 1\nFlask = object\n"
        },
    )
    assert {row["tier"] for row in dynamic["ledger"]} == {"NEEDS_CONTEXT"}


def _private_key_auth_tiers(source, findings=None):
    from hashlib import sha256
    from factoryline.primitive_observation_binding import build_finding_tier_report

    data = source.encode()
    findings = _premise_scan(source) if findings is None else findings
    return build_finding_tier_report(
        findings,
        [],
        [{"path": "application.py", "sha256": sha256(data).hexdigest()}],
        {"application.py": data},
        coverage_state=True,
        partition_state="VALIDATED",
    )


_PRIVATE_KEY_AUTH_SOURCE = """
from Crypto.PublicKey import RSA as KeyFactory
from Crypto.Cipher import PKCS1_v1_5 as Cipher
import base64
import json
from django.views.decorators.http import require_http_methods
from django.contrib.auth.hashers import check_password

credential_material = '-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQDPkDtDFKUZbN6vpevpgZIGc5DzH1UB9oK48MxNATjKPxqv+wsWsdxfWGI8awzXaKOB+Iq0LR+O4iM17fko0JHWTYSdUICSdOy28s/W4QKQh8mcPCum5gHak40QqA6tM842wra5tqO5fgP69lwgmSF7Y04xJhlPrx7MOTxBaqg1FwIDAQABAoGAan29afU1n43T0pp2Jx9rJBQ20gXJP3CSMQCaUQfHczxdHNzYG5S1U9Ws0QK7W+k7unsh7r8X6d7r4cduhho8N6KUY1mcXFUyEpx2PD4bQT89oxNKnawmr0BsXavIADNVwPZ9RLhvyEoJHOHsZn+vUky+k6+l+Dcitm4zFsfnXkECQQDnjFl75rz5vzqb6Zhx8NgfrbDYhAH9f/6KNx/tf5hsrn0TScpETLMlwqGt3t76AVJkeR8g/IHSGuul3iERVZ4zAkEA5Xt6eyDDQe97YEXdjkIl10a4hfbRgL8MChmYGu852I83fZ2TvD/Ah4KHjQCDAbFaDpndGooykVgSZGU2+/ahjQJBANbgJgKXQ/O4hJk/lBrY2Je9RgoHpxkq+HonYdeyuy7QVn3Z0nzDeNSn5AZId0AmjeFzjXG9InRqSxioJKPDgoUCQFgkOUMZrmWg6i5sJ1EArzAkhbNOveFJgAJRGk8eG4XGXHXvFFN12SkzRYUu8SKxT/nTt0z+T7XrsgTFq3zTmfECQGNtDLTWUcSJcXZjb/EhFDOec80nR5v/FmvpI1iYI8PoKODDFE31Wvr3r/62rINxXYHP+hahD2RV6FGrPCUCozA=\\n-----END RSA PRIVATE KEY-----\\n'

def decode_secret(ciphertext):
    key = KeyFactory.import_key(credential_material)
    cipher = Cipher.new(key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext), None)
    return plaintext.decode("utf-8")

@require_http_methods(["POST"])
def login(request):
    body_text = request.body.decode()
    payload = json.loads(body_text)
    encrypted = payload.get("password")
    password = decode_secret(encrypted)
    if check_password(password, stored_hash):
        return "ok"
    return "denied"
"""


def test_private_key_decryption_of_post_password_recomputes_authority():
    import copy

    report = _private_key_auth_tiers(_PRIVATE_KEY_AUTH_SOURCE)
    row = next(
        item
        for item in report["ledger"]
        if item["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["evidence"] == "source_bound_private_key_http_authentication_flow"
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert row["raw_finding"] == copy.deepcopy(
        _premise_scan(_PRIVATE_KEY_AUTH_SOURCE)[0]
    )
    observation = row["credential_authority_observation"]
    assert observation["source_role"] == "embedded_private_key"
    assert observation["consumer_role"] == "django_password_verifier"
    assert observation["runtime_execution"] == "not_performed"
    assert observation["deployment"] == "UNASSESSED"
    assert len(observation["transfers"]) >= 7


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace('@require_http_methods(["POST"])\n', ""),
            id="missing-post-route-guard",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "if check_password(password, stored_hash):", "if password:"
            ),
            id="crypto-flow-without-auth-consumer",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "\n\ndef decode_secret",
                "\ncredential_material = opaque_value\n\ndef decode_secret",
                1,
            ),
            id="mutated-private-key-binding",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "\n\ndef decode_secret",
                "\nKeyFactory = opaque_provider\n\ndef decode_secret",
                1,
            ),
            id="shadowed-crypto-provider",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "key = KeyFactory.import_key(credential_material)",
                "key = opaque_provider(credential_material)",
                1,
            ),
            id="opaque-crypto-provider",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.split('@require_http_methods(["POST"])', 1)[0],
            id="crypto-only-no-http-consumer",
        ),
    ],
)
def test_private_key_authority_requires_unmutated_crypto_request_and_auth_flow(source):
    report = _private_key_auth_tiers(source)
    row = next(
        item
        for item in report["ledger"]
        if item["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert row["tier"] == "NEEDS_CONTEXT"
    assert "credential_authority_observation" not in row


def test_private_key_authority_rejects_stale_string_finding_after_type_change():
    findings = _premise_scan(_PRIVATE_KEY_AUTH_SOURCE)
    wrong_type = _PRIVATE_KEY_AUTH_SOURCE.replace(
        "credential_material = '", "credential_material = b'", 1
    )
    report = _private_key_auth_tiers(wrong_type, findings)
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "runner",
    [
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\napplication=get_wsgi_application()\n',
        'from flask import Flask\napp=Flask(__name__)\napp.config.from_object("service.settings")\n',
        'from flask import Flask\ndef load(app):\n    app.config.from_object("service.settings")\n'
        "def create_app():\n    app=Flask(__name__)\n    load(app)\n    return app\n",
    ],
)
def test_signing277_framework_consumer_retains_weak_material(runner):
    report = _configuration_tiers277(_configuration_files277(runner))
    assert report["tier_counts"]["NEEDS_CONTEXT"] == 1
    row = report["ledger"][0]
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert row["static_consumer_observation"]["deployment"] == "UNASSESSED"
    assert row["static_consumer_observation"]["transfers"]
    assert "security_authority_binding" in row["missing_premises"]
    card = report["rule_scorecards"][0]
    assert card["measured_actionable_precision"] is None
    assert card["decided_labels"] == 0
    assert card["promotion_state"] == "EXPERIMENTAL_UNMEASURED"


@pytest.mark.parametrize(
    "runner",
    [
        'app.config.from_object("service.settings")\n',
        'from flask import Flask\nFlask = Fake\napp=Flask(__name__)\napp.config.from_object("service.settings")\n',
        'from flask import Flask\napp=Flask(__name__)\napp.config = fake\napp.config.from_object("service.settings")\n',
        'from flask import Flask\napp=Flask(__name__)\napp.config.from_object("service.settings")\napp.config["SECRET_KEY"] = secure_key\n',
        'from flask import Flask\ndef create():\n    app=Flask(__name__)\n    return app\n    app.config.from_object("service.settings")\n',
        'from flask import Flask\ndef load(app):\n    app.config.from_object("service.settings")\n'
        "def create():\n    app=Flask(__name__)\n    load(app, app=another)\n    return app\n",
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "other.settings")\napplication=get_wsgi_application()\n',
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
        'os.environ["DJANGO_SETTINGS_MODULE"] = "other.settings"\napplication=get_wsgi_application()\n',
    ],
)
def test_signing277_unproven_or_replaced_consumer_abstains(runner):
    report = _configuration_tiers277(_configuration_files277(runner))
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["ledger"][0]["tier"] == "NEEDS_CONTEXT"
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "change", ["missing_source", "guard", "literal_overwrite", "framework_shadow"]
)
def test_signing277_incomplete_or_conflicting_evidence_abstains(change):
    runner = (
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
        "application=get_wsgi_application()\n"
    )
    files = _configuration_files277(runner)
    if change == "guard":
        files["service/settings.py"] += (
            'if SECRET_KEY == "published-weak-value":\n    raise RuntimeError("configure key")\n'
        )
    elif change == "literal_overwrite":
        files["service/settings.py"] += "SECRET_KEY = secure_key\n"
    elif change == "framework_shadow":
        files["django/__init__.py"] = ""
        files["django/core/__init__.py"] = ""
        files["django/core/wsgi.py"] = "def get_wsgi_application():\n    return None\n"
    report = _configuration_tiers277(
        files, omit=("service/start.py",) if change == "missing_source" else ()
    )
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0


@pytest.mark.parametrize(
    "replacement",
    [
        "app.config.update(SECRET_KEY=secure_key)",
        'app.config.from_mapping({"SECRET_KEY": secure_key})',
        'app.config.from_object("secure.settings")',
        'alias=app; alias.config["SECRET_KEY"]=secure_key',
        'config=app.config; config["SECRET_KEY"]=secure_key',
        "app=Fake()",
    ],
)
def test_signing277_later_configuration_replacement_abstains(replacement):
    files = _configuration_files277(
        "from flask import Flask\napp=Flask(__name__)\n"
        'app.config.from_object("service.settings")\n' + replacement + "\n"
    )
    report = _configuration_tiers277(files)
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0


def test_signing277_imported_key_replacement_abstains():
    files = _configuration_files277(
        "from flask import Flask\napp=Flask(__name__)\n"
        'app.config.from_object("service.settings")\n'
    )
    files["service/__init__.py"] = (
        "from service import settings\nsettings.SECRET_KEY = secure_value\n"
    )
    report = _configuration_tiers277(files)
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0


@pytest.mark.parametrize(
    "change",
    ["dead_django", "invalid_constructor", "initializer_provider", "loader_replaced"],
)
def test_signing277_reviewed_admission_failures_abstain(change):
    runner = (
        "from flask import Flask\napp=Flask(__name__)\n"
        'app.config.from_object("service.settings")\n'
    )
    if change == "invalid_constructor":
        runner = runner.replace("Flask(__name__)", "Flask()")
    elif change == "loader_replaced":
        runner = runner.replace(
            'app.config.from_object("',
            'app.config.from_object=lambda *args: None\napp.config.from_object("',
        )
    elif change == "dead_django":
        runner = (
            'import os\nfrom django.core.wsgi import get_wsgi_application\nraise RuntimeError("stop")\n'
            'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\n'
            "application=get_wsgi_application()\n"
        )
    files = _configuration_files277(runner)
    if change == "initializer_provider":
        files["service/__init__.py"] = "import flask\nflask.Flask=Fake\n"
    report = _configuration_tiers277(files)
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "prefix",
    [
        "import flask\nflask.Flask=Fake\n",
        "from flask import Flask\nsaved=Flask\nmutate(saved)\n",
        "import flask\nmutate(flask)\n",
    ],
)
def test_signing277_selected_provider_replacement_abstains(prefix):
    report = _configuration_tiers277(
        _configuration_files277(
            prefix
            + 'from flask import Flask\napp=Flask(__name__)\napp.config.from_object("service.settings")\n'
        )
    )
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0


def test_signing277_unrelated_provider_use_and_nested_package_resolve():
    files = _configuration_files277(
        "from flask import Flask, request\n"
        "def ignored():\n    send(request.form)\n"
        'app=Flask(__name__)\napp.config.from_object("service.settings")\n'
    )
    report = _configuration_tiers277(files)
    assert report["tier_counts"]["NEEDS_CONTEXT"] == 1
    assert report["ledger"][0]["static_consumer_observation"]["transfers"]
    files = {
        "repo/backend/__init__.py": "",
        "repo/backend/service/__init__.py": "",
        "repo/backend/service/settings.py": 'SECRET_KEY="published-weak-value"\n',
        "repo/backend/service/start.py": "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\napplication=get_wsgi_application()\n',
    }
    from factoryline.semantic_credential_sensor import (
        signing_configuration_inventory,
        signing_configuration_evidence,
    )
    from pathlib import Path
    from hashlib import sha256

    captured = {name: source.encode() for name, source in files.items()}
    name = "repo/backend/service/settings.py"
    finding = audit._security_scan_tree(
        Path("."), Path(name), ast.parse(captured[name])
    )[0]
    index = signing_configuration_inventory(
        captured, {p: sha256(raw).hexdigest() for p, raw in captured.items()}
    )
    assert signing_configuration_evidence(finding, index) is not None


def _tiers275(source, findings=None, coverage=True):
    from hashlib import sha256
    from factoryline.primitive_observation_binding import build_finding_tier_report

    data = source.encode()
    return build_finding_tier_report(
        _premise_scan(source) if findings is None else findings,
        [],
        [{"path": "application.py", "sha256": sha256(data).hexdigest()}],
        {"application.py": data},
        coverage_state=coverage,
        partition_state="VALIDATED",
    )


def test_tier277_rebinding_decision_invalidates_native_epoch(tmp_path, monkeypatch):
    from factoryline import primitive_observation_binding as tiers

    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = tiers._decide_finding_tier

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(tiers, "_decide_finding_tier", replacement)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != before


def test_tier314_flask_authority_implementation_invalidates_native_epoch(
    tmp_path, monkeypatch
):
    from factoryline import primitive_observation_binding as tiers

    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = tiers._finding_flask_session_authority_evidence

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(tiers, "_finding_flask_session_authority_evidence", replacement)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != before


def test_tier275_recomputes_positive_preserves_raw_and_names_abstention():
    import copy

    source = "from flask import request\neval(request.data)\neval(other_data)\n"
    findings = _premise_scan(source)
    before = copy.deepcopy(findings)
    report = _tiers275(source, findings)
    assert findings == before
    assert [r["tier"] for r in report["ledger"]] == [
        "SUPPORTED_DEFECT",
        "NEEDS_CONTEXT",
    ]
    assert [r["raw_finding"] for r in report["ledger"]] == before
    assert report["abstention"] == {
        "count": 1,
        "denominator": 2,
        "fraction": 0.5,
        "scope": "this_run_raw_diagnostics",
    }
    assert report["ledger"][1]["missing_premises"]
    assert report["claim_policy"]["held_out_precision"] == "NOT_MEASURED"


def test_tier275_forged_premise_cannot_promote_constant():
    import copy

    source = 'eval("2+2")\n'
    findings = _premise_scan(source)
    forged = copy.deepcopy(findings)
    call = ast.parse(source).body[0].value
    forged[0]["facts"]["security_precondition"] = (
        sensors.supported_security_precondition(call, "untrusted_request", "eval")
    )
    report = _tiers275(source, forged)
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["tier_counts"]["NEEDS_CONTEXT"] == 1


@pytest.mark.parametrize("path", ["application.py", "tests/conftest.py"])
@pytest.mark.parametrize("name", ["ACCESS_TOKEN", "GITHUB_TOKEN", "value"])
def test_tier275_known_format_preserved_in_any_source_role(path, name):
    from hashlib import sha256
    from pathlib import Path
    from factoryline.primitive_observation_binding import build_finding_tier_report

    data = (name + ' = "ghp_' + "x" * 36 + '"\n').encode()
    findings = audit._security_scan_tree(Path("."), Path(path), ast.parse(data))
    report = build_finding_tier_report(
        findings,
        [],
        [{"path": path, "sha256": sha256(data).hexdigest()}],
        {path: data},
        coverage_state=True,
        partition_state="VALIDATED",
    )
    assert report["tier_counts"]["NEEDS_CONTEXT"] == 1
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"
    assert (
        report["ledger"][0]["material_observation"]["kind"] == "KNOWN_CREDENTIAL_FORMAT"
    )


@pytest.mark.parametrize(
    "value", ["ordinary-value", "ghp_", "ghp_short", "not-a-provider-token"]
)
def test_tier277_noncredential_names_need_known_format(value):
    source = f"value = {value!r}\n"
    assert not any(
        finding["code"] == "SECURITY_HARDCODED_SECRET"
        for finding in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "literal",
    [
        "ghp_" + "A" * 36,
        "-----BEGIN PRIVATE KEY-----\\npublic vector",
        "AKIA" + "A" * 16,
    ],
)
def test_tier279_known_material_is_not_authority(literal):
    source = f"ACCESS_TOKEN = {literal!r}\n"
    before = _premise_scan(source)
    report = _tiers275(source, before)
    assert len(report["ledger"]) == len(before) == 1
    row = report["ledger"][0]
    assert row["raw_finding"] == before[0]
    assert row["original_severity"] == "CRITICAL"
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["material_observation"]["kind"] == "KNOWN_CREDENTIAL_FORMAT"
    assert row["material_observation"]["credential_validity"] == "NOT_ESTABLISHED"
    assert "security_authority_binding" in row["missing_premises"]
    assert report["defect_gate"]["clean"] is False


@pytest.mark.parametrize(
    "runner",
    [
        'from flask import Flask\napp=Flask(__name__)\napp.config.from_object("service.settings")\n',
        "import os\nfrom django.core.wsgi import get_wsgi_application\n"
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "service.settings")\napplication=get_wsgi_application()\n',
    ],
)
def test_tier279_configuration_load_does_not_establish_authority(runner):
    report = _configuration_tiers277(_configuration_files277(runner))
    row = report["ledger"][0]
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert row["static_consumer_observation"]["deployment"] == "UNASSESSED"
    assert row["static_consumer_observation"]["transfers"]
    assert "security_authority_binding" in row["missing_premises"]


def test_tier275_unknown_is_not_defect_and_incomplete_coverage_cannot_clear():
    report = _tiers275("eval(payload)\n")
    assert report["defect_gate"]["state"] == "NO_SUPPORTED_DEFECTS_OBSERVED"
    assert report["defect_gate"]["blocks_on_supported_defects"] is False
    assert report["defect_gate"]["completeness_state"] == "INCOMPLETE"
    assert report["defect_gate"]["clean"] is False
    partial = _tiers275("eval(payload)\n", coverage=False)
    assert partial["defect_gate"]["state"] == "BLOCKED"


def test_tier275_changed_captured_bytes_abstain():
    from factoryline.primitive_observation_binding import build_finding_tier_report

    source = "from flask import request\neval(request.data)\n"
    report = build_finding_tier_report(
        _premise_scan(source),
        [],
        [{"path": "application.py", "sha256": "0" * 64}],
        {"application.py": source.encode()},
        coverage_state=True,
        partition_state="VALIDATED",
    )
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["ledger"][0]["missing_premises"] == ["source_byte_binding"]


@pytest.mark.parametrize(
    ("imports", "sink", "code"),
    [
        ("", "eval(payload)", "SECURITY_DYNAMIC_EXECUTION"),
        ("", "exec(payload)", "SECURITY_DYNAMIC_EXECUTION"),
        ("import os\n", "os.system(payload)", "SECURITY_OS_COMMAND"),
        (
            "import subprocess\n",
            "subprocess.run(payload, shell=True)",
            "SECURITY_SHELL_COMMAND",
        ),
        ("import pickle\n", "pickle.loads(payload)", "SECURITY_UNSAFE_DESERIALIZATION"),
        (
            "import yaml\n",
            "yaml.load(payload, Loader=yaml.Loader)",
            "SECURITY_UNSAFE_YAML",
        ),
    ],
)
def test_http_body275_supported_precondition_keeps_raw_sink(imports, sink, code):
    payload = "body" if code == "SECURITY_UNSAFE_DESERIALIZATION" else "body.decode()"
    source = (
        imports + "from django.views.decorators.http import require_http_methods\n"
        '@require_http_methods(["POST"])\n'
        "def view(request):\n"
        "    body = request.body\n"
        f"    payload = {payload}\n"
        f"    {sink}\n"
    )
    findings = [item for item in _premise_scan(source) if item["code"] == code]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    premise = finding["facts"]["security_precondition"]
    assert premise["status"] == "SUPPORTED"
    assert premise["source_role"] == "untrusted_request"
    assert premise["proof_scope"] == "local_static_wiring"
    assert premise["deployment"] == "UNASSESSED"
    assert premise["runtime_execution"] == "not_performed"
    assert premise["sink_span"][0] == finding["line"]


@pytest.mark.parametrize(
    "arguments,bytes_input",
    [
        ("", True),
        ("as_text=False", True),
        ("False, False", True),
        ("cache=False, parse_form_data=True", True),
        ("as_text=True", False),
    ],
)
@pytest.mark.parametrize("sink", ["pickle.loads(payload)", "eval(payload)"])
def test_sink_context_flask_body_method_preserves_source_kind(
    arguments, bytes_input, sink
):
    source = (
        "import pickle\nfrom flask import request\ndef view():\n"
        f"    payload = request.get_data({arguments})\n    {sink}\n"
    )
    findings = [
        row
        for row in _premise_scan(source)
        if row["code"]
        in {"SECURITY_UNSAFE_DESERIALIZATION", "SECURITY_DYNAMIC_EXECUTION"}
    ]
    assert len(findings) == 1
    expected = bytes_input or sink.startswith("eval")
    assert bool(findings[0]["facts"].get("security_precondition")) is expected


@pytest.mark.parametrize(
    "arguments",
    [
        "*values",
        "**options",
        "as_text=unknown",
        "as_text='yes'",
        "False, False, False, False",
        "False, cache=True",
        "other=True",
    ],
)
def test_sink_context_flask_body_ambiguous_call_is_not_a_source_certificate(arguments):
    source = f"from flask import request\ndef view():\n    eval(request.get_data({arguments}))\n"
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "request.get_data = replacement",
        "request = replacement",
    ],
)
def test_sink_context_flask_body_replaced_provider_is_not_certified(mutation):
    source = f"from flask import request\n{mutation}\ndef view():\n    eval(request.get_data())\n"
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "framework,expression",
    [
        ("flask", 'request.args["cmd"]'),
        ("flask", 'request.form.get("cmd")'),
        ("flask", 'request.json["cmd"]'),
        ("flask", 'request.get_json()["cmd"]'),
        ("django", 'request.GET["cmd"]'),
        ("django", 'request.POST.get("cmd", "")'),
    ],
)
@pytest.mark.parametrize(
    "sink", ["eval(payload)", "os.system(payload)", "pickle.loads(payload.encode())"]
)
def test_http279_mapping_value_reaches_modeled_sink(framework, expression, sink):
    imports = "import os\nimport pickle\n"
    if framework == "flask":
        source = imports + "from flask import request\ndef view():\n"
    else:
        source = (
            imports
            + "from django.views.decorators.http import require_POST\n@require_POST\ndef view(request):\n"
        )
    source += f"    payload = {expression}\n    {sink}\n"
    findings = _premise_scan(source)
    assert any(row.get("facts", {}).get("security_precondition") for row in findings)


@pytest.mark.parametrize(
    "expression",
    [
        "request.args.keys()",
        "request.form.items()",
        "request.args.getlist('cmd')",
        "request.args.get()",
        "request.args.get(*values)",
        "request.args.get('cmd', default='', **opts)",
        "request.get_json(*values)['cmd']",
        "request.get_json(silent=True)['cmd']",
    ],
)
def test_http279_nonvalue_or_ambiguous_access_cannot_support(expression):
    source = f"from flask import request\ndef view():\n    payload = {expression}\n    eval(payload)\n"
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'request.json = {"cmd": "2+2"}',
        "request.get_json = replacement",
        "request = replacement",
        "flask.request = replacement",
    ],
)
def test_http279_changed_request_provider_abstains(mutation):
    source = (
        "import flask\nfrom flask import request\n"
        + mutation
        + '\ndef view():\n    eval(request.get_json()["cmd"])\n'
    )
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "body",
    [
        'payload = request.POST.get("cmd"); payload = "2+2"; eval(payload)',
        'request.POST = {}; eval(request.POST["cmd"])',
        'request = replacement; eval(request.POST["cmd"])',
        'eval(request.POST.getlist("cmd"))',
        "eval(request.POST.keys())",
    ],
)
def test_http279_django_overwrite_or_nonvalue_abstains(body):
    source = (
        "from django.views.decorators.http import require_POST\n@require_POST\ndef view(request):\n    "
        + body
        + "\n"
    )
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'request.POST["cmd"] = "2+2"',
        'request.POST.update({"cmd": "2+2"})',
        'values = request.POST; values["cmd"] = "2+2"',
        'values = request.POST; values.update({"cmd": "2+2"})',
        "alter(request.POST)",
        "values = request.POST; alter(values)",
    ],
)
def test_http279_django_selected_mapping_mutation_abstains(mutation):
    source = (
        "from django.views.decorators.http import require_POST\n@require_POST\ndef view(request):\n    "
        + mutation
        + '\n    eval(request.POST.get("cmd"))\n'
    )
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


def test_http279_django_other_mapping_key_does_not_erase_input():
    source = 'from django.views.decorators.http import require_POST\n@require_POST\ndef view(request):\n    request.POST["other"] = "safe"\n    eval(request.POST.get("cmd"))\n'
    assert any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


def test_http279_cached_json_mapping_overwrite_abstains():
    source = 'from flask import request\ndef view():\n    values = request.get_json()\n    values["cmd"] = "2+2"\n    eval(request.get_json()["cmd"])\n'
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


def test_http279_text_request_does_not_satisfy_bytes_only_sink():
    source = 'import pickle\nfrom flask import request\ndef view():\n    payload=request.form.get("data")\n    pickle.loads(payload)\n'
    rows = _premise_scan(source)
    assert any(row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in rows)
    assert not any(row.get("facts", {}).get("security_precondition") for row in rows)


def test_http279_decoded_body_is_not_pickle_bytes():
    source = "import pickle\nfrom flask import request\ndef view():\n    payload=request.data.decode()\n    pickle.loads(payload)\n"
    rows = _premise_scan(source)
    assert any(row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in rows)
    assert not any(row.get("facts", {}).get("security_precondition") for row in rows)


def test_http279_bytes_type_evidence_requires_every_branch():
    source = 'import pickle\nfrom flask import request\ndef view(flag):\n    if flag:\n        payload=request.data\n    else:\n        payload=request.form.get("data")\n    pickle.loads(payload)\n'
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in _premise_scan(source)
    )


@pytest.mark.parametrize(
    "source",
    [
        "def view(payload):\n    eval(payload)\n",
        'from flask import request\npayload = request.data\npayload = "2+2"\neval(payload)\n',
        "from flask import request\nif False:\n    eval(request.data)\n",
        "from flask import request\ndef view():\n    return\n    eval(request.data)\n",
        "from flask import request\neval(request.data, **options)\n",
        "from flask import request\neval(request.data, *args)\n",
        "from flask import request\neval(request.data.decode(unknown_codec))\n",
        'from flask import request\neval(request.data.decode(errors="strict", **options))\n',
        'from flask import request\nrequest.data = b"2+2"\neval(request.data)\n',
        "from flask import request\ndef view(eval):\n    eval(request.data)\n",
        "from flask import request\nimport builtins\nbuiltins.eval = replacement\neval(request.data)\n",
        "from django.views.decorators.http import require_POST\n@require_POST\ndef view(request):\n    request = replacement\n    eval(request.body)\n",
    ],
)
def test_http_body275_missing_premises_cannot_claim_support(source):
    findings = _premise_scan(source)
    assert not any(
        item.get("facts", {}).get("security_precondition") for item in findings
    )


def test_http_body275_flask_alias_and_forged_ast_metadata():
    from pathlib import Path

    findings = _premise_scan(
        "from flask import request as incoming\neval(incoming.data)\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["security_precondition"]["status"] == "SUPPORTED"
    tree = ast.parse('eval("2+2")\n')
    call = tree.body[0].value
    call._security_supported_precondition = sensors.supported_security_precondition(
        call, "untrusted_request", "eval"
    )
    findings = audit._security_scan_tree(Path("."), Path("application.py"), tree)
    assert not any(
        item.get("facts", {}).get("security_precondition") for item in findings
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'request.body = b"1"',
        'alias = request; alias.body = b"1"',
        'setattr(request, "body", b"1")',
        "replace_body(request)",
    ],
)
def test_http_body275_receiver_write_or_escape_abstains(mutation):
    source = (
        "from django.views.decorators.http import require_POST\n"
        "@require_POST\ndef view(request):\n"
        f"    {mutation}\n"
        "    eval(request.body.decode())\n"
    )
    findings = _premise_scan(source)
    assert any(item["code"] == "SECURITY_DYNAMIC_EXECUTION" for item in findings)
    assert not any(
        item.get("facts", {}).get("security_precondition") for item in findings
    )


def test_http_body275_module_registry_replacement_abstains():
    source = (
        'import sys\nsys.modules["pickle"] = harmless_module\n'
        "import pickle\nfrom flask import request\n"
        'def run():\n    payload = request.args["data"]\n    pickle.loads(payload)\n'
    )
    findings = _premise_scan(source)
    assert any(item["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for item in findings)
    assert not any(
        item.get("facts", {}).get("security_precondition") for item in findings
    )


@pytest.mark.parametrize(
    "body",
    [
        "logging.warning(value)",
        "if False:\n        logging.warning(value)",
        "return\n    logging.warning(value)",
        "False and logging.warning(value)",
    ],
)
def test_log275_supported_premise_excludes_dead_paths(body):
    findings = _premise_scan(
        "import logging\ndef run():\n    value = input()\n    " + body + "\n"
    )
    logs = [item for item in findings if item["code"] == "SECURITY_LOG_INJECTION"]
    assert len(logs) == 1
    assert bool(logs[0]["facts"].get("security_precondition")) == (
        body == "logging.warning(value)"
    )


def test_log275_replaced_provider_preserves_raw_without_support():
    findings = _premise_scan(
        "import logging\nlogging.warning = lambda *args: None\n"
        "def run():\n    value=input()\n    logging.warning(value)\n"
    )
    logs = [item for item in findings if item["code"] == "SECURITY_LOG_INJECTION"]
    assert len(logs) == 1
    assert "security_precondition" not in logs[0]["facts"]


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import pickle\ndef decode(payload): return pickle.loads(payload)\n", True),
        ("import sys\nsys.modules['pickle'] = replacement\n", False),
    ],
)
def test_security_precondition_provider_identity_rejects_registry_replacement(
    source, expected
):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    assert (
        sensors.security_precondition_providers_stable(tree, aliases, nodes) is expected
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import logging\nlogging.warning('safe')\n", True),
        ("import logging\nlogging.warning = replacement\n", False),
    ],
)
def test_log_provider_identity_requires_unmodified_logging_provider(source, expected):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    assert sensors.log_security_provider_stable(tree, aliases, nodes) is expected


def test_log_percent_slots_exclude_escaped_percent_and_preserve_real_slots():
    assert sensors.log_percent_slots(
        "level=%(levelname)s escaped=%% payload=%s width=%*.*f"
    ) == ["s", "s", "f"]


def test_log_security_precondition_requires_stability_and_a_possible_sink_path():
    from types import SimpleNamespace

    stable = SimpleNamespace(_security_log_provider_stable=True)
    call = ast.parse("logging.warning(user_input)").body[0].value
    fact = sensors.log_security_precondition(stable, call)["security_precondition"]
    assert fact["status"] == "SUPPORTED"
    assert fact["source_role"] == "untrusted_input"
    assert fact["consumer_role"] == "log_message"

    unstable = SimpleNamespace(_security_log_provider_stable=False)
    assert sensors.log_security_precondition(unstable, call) == {}

    dead = ast.parse("if False:\n    logging.warning(user_input)\n")
    dead_if = dead.body[0]
    dead_statement = dead_if.body[0]
    dead_call = dead_statement.value
    dead_call._security_parent = dead_statement
    dead_statement._security_parent = dead_if
    assert sensors.log_security_precondition(stable, dead_call) == {}


@pytest.mark.parametrize("mutation", ["", "requests.get = replacement\n"])
@pytest.mark.parametrize("inventory", [list, tuple, iter])
def test_reused_inventory_preserves_credentials_and_provider_mutation(
    monkeypatch, mutation, inventory
):
    tree = ast.parse(
        "import requests\n"
        + mutation
        + "requests.get('https://api.test', auth=('name', 'actual-secret'))\n"
    )
    nodes = list(ast.walk(tree))
    aliases = _security_aliases(nodes)
    expected = credential_findings(tree, aliases, "sample.py")

    def forbidden_walk(_tree):
        raise AssertionError("reused inventory must avoid another AST walk")

    monkeypatch.setattr(ast, "walk", forbidden_walk)
    assert (
        credential_findings(tree, aliases, "sample.py", nodes=inventory(nodes))
        == expected
    )
    assert len(expected) == (0 if mutation else 1)


def test_reports_literal_http_auth_and_authorization_without_exposing_values():
    findings = _scan(
        "import requests as r\n"
        "import httpx\n"
        "r.get('https://api.example.test', auth=('name', 'p@ss-value'))\n"
        "httpx.Client().post('https://api.example.test', headers={'Authorization': 'Bearer abc-token'})\n"
        "r.get('https://api.example.test', headers={'authorization': 'Basic QWxwaGE='})\n"
    )
    assert len(findings) == 3
    assert {item["facts"]["consumer_role"] for item in findings} == {
        "http_auth",
        "http_header",
    }
    assert all(item["severity"] == "MEDIUM" for item in findings)
    assert all(
        item["facts"]["source_role"] == "credential_literal" for item in findings
    )
    assert all(
        item["facts"]["proof_scope"] == "local_static_wiring" for item in findings
    )
    assert all(
        "p@ss-value" not in repr(item) and "abc-token" not in repr(item)
        for item in findings
    )


def test_reports_direct_basic_auth_password_and_ignores_username_only():
    findings = _scan(
        "from requests.auth import HTTPBasicAuth as Basic\n"
        "Basic('user', 'direct-password')\n"
        "import requests\n"
        "requests.get('https://host.test', auth=('only-user', ''))\n"
        "requests.get('https://host.test', auth=('user', 'your-'))\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["credential_slot"] == "password"


def test_ignores_urls_schemes_placeholders_and_noncanonical_calls():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer '})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer ${TOKEN}'})\n"
        "fake.get('https://host.test', headers={'Authorization': 'Bearer abc-token'})\n"
        "def send(requests):\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    assert findings == []


def test_detects_http_url_userinfo_without_retaining_the_url_or_password():
    findings = _scan(
        "import requests\n"
        "requests.get('https://name:secret-value@host.test/path')\n"
        "requests.get('https://host.test/path')\n"
        "requests.get('https://name@host.test/path')\n"
        "requests.get('https://:secret-value@host.test/path')\n"
        "requests.get(dynamic_url)\n"
        "requests.post(ACCESS_TOKEN_URL)\n"
        "requests.get('http://[malformed')\n"
        "fake.get('https://name:secret-value@host.test/path')\n"
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["facts"]["consumer_role"] == "http_url_userinfo"
    assert finding["facts"]["credential_slot"] == "userinfo_password"
    assert "host.test" not in repr(finding)
    assert "secret-value" not in repr(finding)


def test_basic_auth_keyword_binding_requires_exact_valid_call_shape():
    findings = _scan(
        "from requests.auth import HTTPBasicAuth\n"
        "HTTPBasicAuth(username='name', password='keyword-password')\n"
        "HTTPBasicAuth('name', 'positional-password', password='invalid-duplicate')\n"
        "HTTPBasicAuth(username='name', password='placeholder')\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["credential_slot"] == "password"


def test_authorization_header_duplicates_use_python_last_value_and_unknown_expansions():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer old-token', 'authorization': 'Bearer live-token'})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-token', 'authorization': dynamic_value})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-token', **extra})\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["consumer_role"] == "http_header"
    assert "old-token" not in repr(findings[0])
    assert "live-token" not in repr(findings[0])


def test_authorization_headers_resolve_exact_dict_keys_before_casefold_merge():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer upper-old', 'authorization': 'Bearer lower-final'})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-exact', 'Authorization': dynamic_value})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-upper', 'authorization': dynamic_value, 'Authorization': 'Bearer hidden-final'})\n"
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert "upper-old" not in repr(findings[0])
    assert "lower-final" not in repr(findings[0])


def test_shadowed_import_and_parameter_are_not_canonical_http_sinks():
    findings = _scan(
        "import requests as client\n"
        "client = fake\n"
        "client.get('https://host.test', headers={'Authorization': 'Bearer literal-token'})\n"
        "def send(requests):\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    assert findings == []


@pytest.mark.parametrize(
    "mutation",
    [
        "requests.get = fake_get",
        "setattr(requests.auth, 'HTTPBasicAuth', fake_auth)",
        "saved_provider = requests",
        "requests.auth.HTTPBasicAuth = fake_auth",
        "httpx.Client = FakeClient",
    ],
)
def test_each_provider_mutation_vetoes_http_credential_proof(mutation):
    findings = _scan(
        "import requests\n"
        "import httpx\n"
        f"{mutation}\n"
        "def later():\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
        "    requests.auth.HTTPBasicAuth('user', 'literal-password')\n"
        "    httpx.Client().post('https://host.test', headers={'Authorization': 'Bearer token-value'})\n"
    )
    assert findings == []


def test_your_prefixed_literal_is_not_a_new_placeholder_waiver():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', auth=('user', 'your-password'))\n"
    )
    assert len(findings) == 1


def test_combined_sensor_returns_configuration_and_credential_findings():
    tree = ast.parse(
        "from jinja2 import Environment\n"
        "env = Environment(autoescape=False)\n"
        "env.get_template('page.html')\n"
        "import httpx\n"
        "httpx.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    findings = configuration_and_credential_findings(
        tree, _security_aliases(list(ast.walk(tree))), "sample.py"
    )
    assert {item["code"] for item in findings} == {
        "SECURITY_JINJA_AUTOESCAPE_DISABLED",
        "SECURITY_LITERAL_HTTP_CREDENTIAL",
    }


def test_provider_mutation_index_is_skipped_without_literal_candidate(monkeypatch):
    import factoryline.finite_capture as mutations

    calls = []
    original = mutations.finite_provider_mutation_index

    def counted(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(mutations, "finite_provider_mutation_index", counted)
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test')\n"
        "requests.get('https://host.test', auth=('user', dynamic_password))\n"
        "requests.get('https://host.test', auth=('user', ''))\n"
        "requests.get('https://host.test', auth=('user', 'placeholder'))\n"
    )
    assert findings == []
    assert calls == []


@pytest.mark.parametrize(
    "mutation, expected",
    [("", 1), ("requests.get = fake_get\n", 0)],
)
def test_provider_mutation_index_runs_once_for_literal_candidate(
    monkeypatch, mutation, expected
):
    import factoryline.finite_capture as mutations

    calls = []
    original = mutations.finite_provider_mutation_index

    def counted(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(mutations, "finite_provider_mutation_index", counted)
    findings = _scan(
        "import requests\n"
        + mutation
        + "requests.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    assert len(findings) == expected
    assert calls == [None]


"""Native semantic sensing preserves existing defects and separates source claims."""


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://identity.example.test/oauth/token",
        "https://api.telegram.org/bot123456789:AAEabcdefghijklmnopqrstuvwxyz0123456789/getMe",
        "https://user:fixed-value@id.example.test/token",
        "https://id.example.test/token?key=fixed-value",
    ],
)
def test_target_role_alone_never_suppresses_credential_warning(tmp_path, endpoint):
    (tmp_path / "config.py").write_text(f"ACCESS_TOKEN_URL = {endpoint!r}\n")
    (tmp_path / "client.py").write_text(
        "import requests\nfrom config import ACCESS_TOKEN_URL\nrequests.get(ACCESS_TOKEN_URL)\n"
    )
    report = audit.security_scan(tmp_path, cache_enabled=False)
    [secret] = [
        f for f in report["findings"] if f["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert secret["severity"] == "CRITICAL"
    assert not report.get("primitive_observations")


def test_native_unnamed_auth_literal_and_original_secret_survive_cold_warm(tmp_path):
    (tmp_path / "app.py").write_text(
        "import requests\nPASSWORD='hunter2'\n"
        "def send(url):\n"
        "    return requests.post(url, auth=('someone', 'literal-for-auth'))\n"
    )
    audit._oracle_context_cache_clear()
    cold = audit.security_scan(tmp_path)
    warm = audit.security_scan(tmp_path)
    assert cold["findings"] == warm["findings"]
    assert audit._oracle_context_cache_info()["hits"] >= 1
    by_code = {f["code"]: f for f in cold["findings"]}
    assert by_code["SECURITY_HARDCODED_SECRET"]["severity"] == "CRITICAL"
    sensor = by_code["SECURITY_LITERAL_HTTP_CREDENTIAL"]
    assert sensor["facts"]["consumer_role"] == "http_auth"
    assert sensor["facts"]["credential_validity"] == "not_established"
    assert sensor["facts"]["claim_boundary"] == "static_not_runtime"
    assert "literal-for-auth" not in repr(cold)
    assert "hunter2" not in repr(cold)


def test_native_public_url_target_and_unknown_runtime_auth_add_no_sensor_alert(
    tmp_path,
):
    (tmp_path / "app.py").write_text(
        "import httpx\n"
        "httpx.get('https://id.example.test/token')\n"
        "def send(url, supplied):\n"
        "    return httpx.get(url, auth=supplied)\n"
    )
    assert audit.security_scan(tmp_path, cache_enabled=False)["findings"] == []


@pytest.mark.parametrize("name", ["credential_findings", "_auth_literal_nodes"])
def test_semantic_validator_replacement_invalidates_native_cache(
    tmp_path, monkeypatch, name
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = getattr(sensors, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(sensors, name, replacement)
    assert before != audit._oracle_context_cache_key(tmp_path, [], {})


@pytest.mark.parametrize("explicit_scope", [False, True])
def test_django_request_parameter_passes_resolved_scope_to_alias_reader(explicit_scope):
    function = ast.parse("def view(request):\n    return request.GET\n").body[0]
    node = function.body[0].value
    function._security_parameter_names = {"request"}
    node._security_lexical_scope = function
    received = []

    def reader(scope, aliases, flow_statement):
        received.append((scope, aliases, flow_statement))
        return {"request": "django.http.HttpRequest"} if scope is function else {}

    assert (
        sensors.django_request_parameter(
            node, {}, function if explicit_scope else None, function.body[0], reader
        )
        is True
    )
    assert received == [(function, {}, function.body[0])]


def test_precision257_semantic_sensor_request_upload_and_password_comparison():
    import ast
    from factoryline import semantic_credential_sensor as sensor

    assert sensor.validation_modules() == (sensor,)
    scope = ast.parse(
        "from flask import request as req\nfiles = req.files\nfiles.get('upload')"
    )
    statement = scope.body[1]
    expression = ast.parse("req.files['upload']", mode="eval").body

    def collection(node, aliases, _scope, _statement, name):
        return (
            isinstance(node, ast.Attribute)
            and node.attr == name
            and aliases.get(node.value.id) == "flask.request"
        )

    assert (
        sensor.flask_upload_expression(
            expression, {"req": "flask.request"}, scope, statement, collection
        )
        is True
    )
    assert (
        sensor.flask_upload_expression(
            ast.parse("req.args['upload']", mode="eval").body,
            {"req": "flask.request"},
            scope,
            statement,
            collection,
        )
        is False
    )
    request_files = ast.parse("flask.request.files", mode="eval").body
    assert (
        sensor.flask_request_collection(
            request_files,
            {"flask": "flask"},
            scope,
            statement,
            "files",
            lambda *_: {"flask": "flask"},
        )
        is True
    )
    assert (
        sensor.flask_request_collection(
            ast.parse("flask.request.args", mode="eval").body,
            {"flask": "flask"},
            scope,
            statement,
            "files",
            lambda *_: {"flask": "flask"},
        )
        is False
    )
    comparison = ast.parse("password == 'hardcoded-secret'", mode="eval").body

    def password_source(node, _fields, *_):
        return isinstance(node, ast.Name) and node.id == "password"

    def literal_valid(node):
        return isinstance(node, ast.Constant) and node.value == "hardcoded-secret"

    finding = sensor.password_comparison_finding(
        "app.py",
        comparison,
        {"password"},
        {},
        scope,
        statement,
        password_source,
        literal_valid,
    )
    assert finding is not None and finding["severity"] == "CRITICAL"
    safe = ast.parse("password != 'hardcoded-secret'", mode="eval").body
    assert (
        sensor.password_comparison_finding(
            "app.py",
            safe,
            {"password"},
            {},
            scope,
            statement,
            password_source,
            literal_valid,
        )
        is None
    )
    assert (
        sensor.flask_request_collection(
            ast.parse("flask.request.files", mode="eval").body,
            {},
            scope,
            statement,
            "files",
            lambda *_: {},
        )
        is False
    )


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def login(request):", "def login(request, decode_secret=None):"
            ),
            id="decryptor-parameter-shadow",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                '@require_http_methods(["POST"])',
                'decode_secret = opaque_provider\n@require_http_methods(["POST"])',
            ),
            id="decryptor-module-rebind",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def login(request):", "def login(request, check_password=None):"
            ),
            id="verifier-parameter-shadow",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def decode_secret(ciphertext):",
                "def decode_secret(ciphertext, KeyFactory=None):",
            ),
            id="key-factory-parameter-shadow",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def decode_secret(ciphertext):",
                "def decode_secret(ciphertext, credential_material=None):",
            ),
            id="material-parameter-shadow",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "check_password(password, stored_hash)", "check_password(password)"
            ),
            id="missing-encoded-verifier-argument",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "check_password(password, stored_hash)",
                "check_password(password, stored_hash, *extra)",
            ),
            id="expanded-verifier-arguments",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def decode_secret(ciphertext):\n",
                "def decode_secret(ciphertext):\n    raise RuntimeError\n",
            ),
            id="unreachable-decryptor",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def login(request):\n", "def login(request):\n    raise RuntimeError\n"
            ),
            id="unreachable-endpoint-transfer",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def login(request):\n",
                "def login(request):\n    from opaque import decode_secret\n",
            ),
            id="function-import-shadows-decryptor",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def login(request):\n",
                "def login(request):\n    try:\n        opaque()\n    except Exception as decode_secret:\n        pass\n",
            ),
            id="except-alias-shadows-decryptor",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "def decode_secret(ciphertext):\n",
                "def decode_secret(ciphertext):\n    from opaque import KeyFactory\n",
            ),
            id="function-import-shadows-provider",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "    body_text = request.body.decode()\n    payload = json.loads(body_text)",
                "    payload = json.loads(body_text)\n    body_text = request.body.decode()",
            ),
            id="body-text-assignment-after-use",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                '    payload = json.loads(body_text)\n    encrypted = payload.get("password")\n    password = decode_secret(encrypted)',
                '    payload = json.loads(body_text)\n    password = decode_secret(encrypted)\n    encrypted = payload.get("password")',
            ),
            id="encrypted-assignment-after-use",
        ),
        pytest.param(
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "MIICXAIBAAKBgQDPkDtDFKUZbN6vpevpgZIGc5DzH1UB9oK48MxNATjKPxqv+wsW",
                "fixture-only",
            ),
            id="invalid-pem-material-never-imports",
        ),
    ],
)
def test_private_key_authority_reviewer_adversarial_controls(source):
    report = _private_key_auth_tiers(source)
    row = next(
        r
        for r in report["ledger"]
        if r["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert row["tier"] == "NEEDS_CONTEXT"


def test_private_key_authority_unrelated_zero_argument_call_does_not_crash():
    source = _PRIVATE_KEY_AUTH_SOURCE.replace(
        "def decode_secret(ciphertext):\n",
        "def decode_secret(ciphertext):\n    unused = opaque()\n",
    )
    report = _private_key_auth_tiers(source)
    assert any(
        r["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
        for r in report["ledger"]
    )


@pytest.mark.parametrize(
    "source, supported",
    [
        (
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                '    if check_password(password, stored_hash):\n        return "ok"',
                '    try:\n        if check_password(password, stored_hash):\n            return "ok"\n    except ValueError:\n        return "bad"',
            ),
            True,
        ),
        (
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                "    password = decode_secret(encrypted)\n",
                "    try:\n        password = decode_secret(encrypted)\n    except ValueError:\n        pass\n",
            ),
            False,
        ),
        (
            _PRIVATE_KEY_AUTH_SOURCE.replace(
                '    password = decode_secret(encrypted)\n    if check_password(password, stored_hash):\n        return "ok"',
                '    try:\n        password = decode_secret(encrypted)\n    except ValueError:\n        if check_password(password, stored_hash):\n            return "ok"',
            ),
            False,
        ),
    ],
    ids=["outer-to-try-body", "try-body-to-outside", "try-body-to-handler"],
)
def test_private_key_transfer_to_nested_try_body_requires_dominance(source, supported):
    report = _private_key_auth_tiers(source)
    row = next(
        r
        for r in report["ledger"]
        if r["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert (row["tier"] == "SUPPORTED_DEFECT") is supported


def test_private_key_authority_rejects_mismatched_pem_labels():
    source = _PRIVATE_KEY_AUTH_SOURCE.replace("END RSA PRIVATE KEY", "END PRIVATE KEY")
    report = _private_key_auth_tiers(source)
    assert all(r["tier"] != "SUPPORTED_DEFECT" for r in report["ledger"])


@pytest.mark.parametrize(
    "before, after",
    [
        ('    if password == app.config["ADMIN_PASSWORD"]:', '    password = "fixed-unrelated-value"\n    if password == app.config["ADMIN_PASSWORD"]:'),
        ('    password = request.form.get("password")', '    return "public-no-auth"\n    password = request.form.get("password")'),
        ('        session["logged_in"] = True', '        session["logged_in"] = True\n        session["logged_in"] = False'),
        ('@app.route("/create")\n@login_required', '@login_required\n@app.route("/create")'),
    ],
)
def test_flask_authority326_public_scanner_rejects_broken_custody(tmp_path, before, after):
    source = _FLASK_AUTHORITY_SOURCE314.replace(before, after)
    assert source != _FLASK_AUTHORITY_SOURCE314
    (tmp_path / "app.py").write_text(source)
    with audit._security_only_scan_context(True):
        report = audit.security_scan(tmp_path, cache_enabled=False, defect_policy="source-role-v1")
    assert report["audit_coverage"]["complete"] is True
    rows = report["finding_tier_report"]["ledger"]
    credentials = [row for row in rows if row["raw_finding"].get("code") == "SECURITY_HARDCODED_SECRET" and row["raw_finding"].get("facts", {}).get("name") in {"ADMIN_PASSWORD", "SECRET_KEY"}]
    assert {row["raw_finding"]["facts"]["name"] for row in credentials} == {"ADMIN_PASSWORD", "SECRET_KEY"}
    assert {row["tier"] for row in credentials} == {"NEEDS_CONTEXT"}
    assert all("credential_authority_observation" not in row for row in credentials)


@pytest.mark.parametrize(
    "before, after",
    [
        ('def login_required(fn):', 'def login_required(fn):\n    return fn'),
        ('        session["logged_in"] = True', '        session["logged_in"] = True\n        saved = session\n        saved.clear()'),
        ('    password = request.form.get("password")\n    if password == app.config["ADMIN_PASSWORD"]:\n        session["logged_in"] = True\n        return redirect("/")', '    password = request.form.get("password")\n    if False:\n        pass\n    else:\n        password = "fixed-unrelated-value"\n        if password == app.config["ADMIN_PASSWORD"]:\n            session["logged_in"] = True\n            return redirect("/")'),
        ('@app.route("/create")\n@login_required', 'def discard_guard(fn):\n    return lambda: "created"\n\n@app.route("/create")\n@discard_guard\n@login_required'),
    ],
)
def test_flask_authority326_public_scanner_rejects_adjacent_broken_custody(tmp_path, before, after):
    source = _FLASK_AUTHORITY_SOURCE314.replace(before, after)
    assert source != _FLASK_AUTHORITY_SOURCE314
    (tmp_path / "app.py").write_text(source)
    with audit._security_only_scan_context(True):
        report = audit.security_scan(tmp_path, cache_enabled=False, defect_policy="source-role-v1")
    assert report["audit_coverage"]["complete"] is True
    rows = report["finding_tier_report"]["ledger"]
    credentials = [row for row in rows if row["raw_finding"].get("facts", {}).get("name") in {"ADMIN_PASSWORD", "SECRET_KEY"}]
    assert {row["raw_finding"]["facts"]["name"] for row in credentials} == {"ADMIN_PASSWORD", "SECRET_KEY"}
    assert {row["tier"] for row in credentials} == {"NEEDS_CONTEXT"}
    assert all("credential_authority_observation" not in row for row in credentials)
