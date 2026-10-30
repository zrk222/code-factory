import ast
import hashlib
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


def _captured_log_scan(tmp_path, app_source, settings_source=None, *, startup=True):
    from pathlib import Path
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    files = {"app.py": app_source}
    if settings_source is not None:
        files["project/__init__.py"] = ""
        files["project/settings.py"] = settings_source
    if startup:
        files["manage.py"] = (
            "import os, sys\n"
            "from django.core.management import execute_from_command_line\n"
            "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')\n"
            "if __name__ == '__main__':\n"
            "    execute_from_command_line(sys.argv)\n"
        )
    snapshots, source_bytes, inventory = {}, {}, {}
    for relative, source in files.items():
        path = Path(tmp_path, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = source.encode("utf-8")
        path.write_bytes(raw)
        tree = ast.parse(raw, filename=str(path))
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path] = tree
        source_bytes[path] = raw
        inventory[path] = digest
    index = SourceSnapshotIndex(Path(tmp_path), snapshots, source_bytes, inventory)
    app_path = Path(tmp_path, "app.py")
    app_tree = snapshots[app_path]
    app_tree._security_source_model = index
    with audit._security_only_scan_context(True):
        return audit._security_scan_tree(Path(tmp_path), app_path, app_tree)


_PLAIN_DJANGO_LOGGING = (
    "LOGGING = {\n"
    " 'version': 1, 'disable_existing_loggers': False,\n"
    " 'formatters': {'plain': {'format': '%(levelname)s %(message)s'}},\n"
    " 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n"
    " 'root': {'handlers': ['console'], 'level': 'WARNING'},\n"
    "}\n"
)


@pytest.mark.parametrize("member", ["args", "form"])
def test_request_mapping_data_member_native_sink_admission(tmp_path, member):
    source = (
        "import subprocess\nfrom flask import request\n"
        "def view():\n"
        f"    value = request.{member}['cmd']\n"
        "    eval(value)\n"
        "    subprocess.call(value, shell=True)\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    with audit._security_only_scan_context(True):
        report = audit.security_scan(tmp_path, cache_enabled=False)
    selected = {
        row["raw_finding"]["code"]: row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"]
        in {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_SHELL_COMMAND"}
    }
    assert set(selected) == {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_SHELL_COMMAND"}
    for row in selected.values():
        assert row["tier"] == "SUPPORTED_DEFECT"
        assert row["evidence"] == "source_bound_native_security_precondition"
        assert (
            row["raw_finding"]["facts"]["security_precondition"]["status"]
            == "SUPPORTED"
        )


@pytest.mark.parametrize("member", ["args", "form"])
@pytest.mark.parametrize(
    "setup,expression",
    [
        ("request = replacement\n", "request.{member}['cmd']"),
        ("request.{member} = replacement\n", "request.{member}['cmd']"),
        ("request.{member}['cmd'] = replacement\n", "request.{member}['cmd']"),
        ("consume(request.{member})\n", "request.{member}['cmd']"),
        ("", "request.{member}[selector]"),
    ],
)
def test_request_mapping_data_member_preserves_uncertain_providers(
    member, setup, expression
):
    source = (
        "import subprocess\nfrom flask import request\ndef view():\n    "
        + setup.format(member=member).replace("\n", "\n    ")
        + "value = "
        + expression.format(member=member)
        + "\n    eval(value)\n    subprocess.call(value, shell=True)\n"
    )
    rows = _premise_scan(source)
    selected = [
        row
        for row in rows
        if row["code"] in {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_SHELL_COMMAND"}
    ]
    assert {row["code"] for row in selected} == {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_SHELL_COMMAND",
    }
    assert not any(
        row.get("facts", {}).get("security_precondition") for row in selected
    )


@pytest.mark.parametrize("member", ["args", "form"])
@pytest.mark.parametrize(
    "sibling_body",
    [
        "mapping['cmd'] = 'fixed'\n",
        "mutate(mapping)\n",
        "return mapping\n",
        "return mapping[selector]\n",
        "request.{member} = replacement\n",
        "flask.request = replacement\n",
    ],
)
def test_request_mapping_data_member_captured_sibling_risks_remain_visible(
    tmp_path, member, sibling_body
):
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom flask import request\n"
        "def view():\n"
        f"    value = request.{member}['cmd']\n"
        "    eval(value)\n    subprocess.call(value, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "sibling.py").write_text(
        "import flask\nfrom flask import request\ndef read_mapping():\n"
        f"    mapping = request.{member}\n"
        "    " + sibling_body.format(member=member),
        encoding="utf-8",
    )
    with audit._security_only_scan_context(True):
        report = audit.security_scan(tmp_path, cache_enabled=False)
    selected = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["path"] == "app.py"
        and row["raw_finding"]["code"]
        in {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_SHELL_COMMAND"}
    ]
    assert len(selected) == 2
    assert all(row["tier"] != "SUPPORTED_DEFECT" for row in selected)


@pytest.mark.parametrize("member", ["args", "form"])
def test_request_mapping_data_member_rejects_shadowed_parameter(member):
    rows = _premise_scan(
        "from flask import request\ndef view(request):\n"
        f"    value = request.{member}['cmd']\n    eval(value)\n"
    )
    assert not any(row.get("facts", {}).get("security_precondition") for row in rows)


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
    """Native precondition binding follows the exact request argument through one supported helper return."""
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
    """security_forward_helper_sources and bind_native_input_precondition map the request actual only to the callee's modeled sink."""
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
    """Independent binding recomputation preserves a source-bound helper alias and rejects changed code."""
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


@pytest.mark.parametrize("tamper", ["trace", "empty", "none", "extra"])
def test_native_flow_witness378_supplied_claims_are_not_discarded(tamper):
    from factoryline.primitive_observation_binding import _regenerate_native_findings

    source = (
        "from flask import request\ndef identity(value):\n    return value\n"
        "eval(identity(request.get_data(as_text=True)))\n"
    )
    findings = _regenerate_native_findings("application.py", source.encode())
    premise = findings[0]["facts"]["security_precondition"]
    assert "input_value_flow" in premise
    if tamper == "trace":
        premise["input_value_flow"]["trace_sha256"] = "0" * 64
    elif tamper == "empty":
        premise["input_value_flow"] = {}
    elif tamper == "none":
        premise["input_value_flow"] = None
    else:
        premise.pop("input_value_flow")
        premise["unverified_field"] = True
    report = _private_key_auth_tiers(source, findings=findings)
    assert report["ledger"][0]["tier"] == "NEEDS_CONTEXT"


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


def _captured_secret_tiers(files, secret_path, secret_name="SECRET_KEY"):
    from hashlib import sha256
    from pathlib import Path
    from factoryline.primitive_observation_binding import build_finding_tier_report

    sources = {name: value.encode() for name, value in files.items()}
    findings = audit._security_scan_tree(
        Path("."), Path(secret_path), ast.parse(sources[secret_path])
    )
    selected = [
        finding
        for finding in findings
        if finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("facts", {}).get("name") == secret_name
    ]
    assert selected
    return build_finding_tier_report(
        selected,
        [],
        [
            {"path": name, "sha256": sha256(raw).hexdigest()}
            for name, raw in sources.items()
            if name.endswith(".py")
        ],
        sources,
        coverage_state=True,
        partition_state="VALIDATED",
    )


def _operative_signing_default_sources(flow, mutation=None):
    if flow in {"settings-constructor", "settings-factory"}:
        factory = (
            "def build_settings():\n    return Settings()\n"
            if flow == "settings-factory"
            else ""
        )
        constructor = "build_settings()" if factory else "Settings()"
        files = {
            "config.py": "from pydantic_settings import BaseSettings\nclass Settings(BaseSettings):\n    secret_key: str = 'signing-seed-9873-product'\n",
            "signing.py": (
                "from jwt import encode, decode\nfrom config import Settings\n"
                + factory
                + f"key = {constructor}.secret_key\n"
                "def issue(subject):\n    return encode({'sub': subject}, key, algorithm='HS256')\n"
                "def verify(token: str):\n    return decode(token, key, algorithms=['HS256'])\n"
            ),
            "app.py": (
                "from fastapi import FastAPI, Depends, HTTPException\n"
                "from fastapi.security import OAuth2PasswordBearer\n"
                "from signing import verify\n"
                "app = FastAPI()\nbearer = OAuth2PasswordBearer(tokenUrl='/token')\n"
                "users = {'admin': {'private': 'account-data'}}\n"
                "@app.get('/profile')\n"
                "def profile(token: str = Depends(bearer)):\n"
                "    claims = verify(token)\n"
                "    if not claims:\n        raise HTTPException(status_code=401)\n"
                "    return users[claims['sub']]\n"
            ),
        }
        if mutation == "override":
            files["signing.py"] = files["signing.py"].replace(
                "Settings()", "Settings(secret_key=runtime_key)"
            )
        elif mutation == "wrong-origin":
            files["signing.py"] = files["signing.py"].replace(
                f"{constructor}.secret_key", "runtime_key"
            )
        elif mutation == "no-route":
            files["app.py"] = files["app.py"].replace("@app.get('/profile')\n", "")
        elif mutation == "verification-disabled":
            files["signing.py"] = files["signing.py"].replace(
                "algorithms=['HS256'])",
                "algorithms=['HS256'], options={'verify_signature': False})",
            )
        return files, "secret_key"
    files = {
        "config.py": "SECRET_KEY = 'signing-seed-9873-product'\n",
        "signing.py": (
            "from flask import current_app\nfrom itsdangerous import URLSafeTimedSerializer\n"
            "def get_signer():\n    key = current_app.config['SECRET_KEY']\n"
            "    signer = URLSafeTimedSerializer(key)\n    return signer\n"
        ),
        "routes.py": (
            "from flask import Blueprint, session\nfrom signing import get_signer\n"
            "api = Blueprint('accounts', __name__)\n"
            "@api.route('/confirm/<token>')\n"
            "def confirm(token):\n    signer = get_signer()\n"
            "    claims = signer.loads(token, max_age=300)\n"
            "    session['user_id'] = claims['sub']\n    return 'authenticated'\n"
        ),
        "app.py": (
            "from flask import Flask\nfrom routes import api\n"
            "app = Flask(__name__)\napp.config.from_object('config')\napp.register_blueprint(api)\n"
        ),
    }
    if mutation == "override":
        files["app.py"] = files["app.py"].replace(
            "app.register_blueprint(api)",
            "app.config['SECRET_KEY'] = runtime_key\napp.register_blueprint(api)",
        )
    elif mutation == "wrong-origin":
        files["signing.py"] = files["signing.py"].replace(
            "current_app.config['SECRET_KEY']", "runtime_key"
        )
    elif mutation == "no-route":
        files["app.py"] = files["app.py"].replace("app.register_blueprint(api)\n", "")
    elif mutation == "verification-disabled":
        files["routes.py"] = files["routes.py"].replace(
            "signer.loads(token, max_age=300)", "{'sub': token}"
        )
    return files, "SECRET_KEY"


@pytest.mark.parametrize("flow", ["settings-constructor", "settings-factory"])
def test_operative_signing_default_origin_family(flow):
    files, name = _operative_signing_default_sources(flow)
    row = _captured_secret_tiers(files, "config.py", name)["ledger"][0]
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert (
        row["credential_authority_observation"]["runtime_execution"] == "not_performed"
    )
    assert {
        item["path"] for item in row["credential_authority_observation"]["transfers"]
    } >= {"config.py", "signing.py", "app.py"}


def test_serializer_transfer_without_operative_identity_authority_stays_unresolved():
    files, name = _operative_signing_default_sources("serializer-helper")
    row = _captured_secret_tiers(files, "config.py", name)["ledger"][0]
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "owner_name,method",
    [
        ("CapturedOriginProjection", "expression"),
        ("CapturedOriginProjection", "conditional"),
        ("_OperativeCredentialOrigin", "boundary_inventory"),
        ("_OperativeCredentialOrigin", "witness"),
        ("_CredentialHandlerIndex", "boundaries"),
    ],
)
def test_shared_credential_method_replacement_changes_native_epoch(
    tmp_path, monkeypatch, owner_name, method
):
    from factoryline import credential_endpoint_admission as admission
    from factoryline.credential_role_method_use_getter_audit import (
        CapturedOriginProjection,
    )

    owner = (
        CapturedOriginProjection
        if owner_name == "CapturedOriginProjection"
        else getattr(admission, owner_name)
    )
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = getattr(owner, method)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, method, replacement)
    assert before != audit._oracle_context_cache_key(tmp_path, [], {})


def test_shared_origin_replacement_cannot_reuse_warm_admission(tmp_path, monkeypatch):
    from factoryline.credential_role_method_use_getter_audit import (
        CapturedOriginProjection,
    )

    files, _ = _operative_signing_default_sources("settings-factory")
    for path, source in files.items():
        (tmp_path / path).write_text(source, encoding="utf-8")
    first = audit.security_scan(
        tmp_path, security_only=True, defect_policy="source-role-v3"
    )
    monkeypatch.setattr(
        CapturedOriginProjection, "expression", lambda *args, **kwargs: (False, None)
    )
    second = audit.security_scan(
        tmp_path, security_only=True, defect_policy="source-role-v3"
    )

    def selected(report):
        return next(
            row
            for row in report["finding_tier_report"]["ledger"]
            if row["raw_finding"].get("facts", {}).get("name") == "secret_key"
        )

    assert selected(first)["tier"] == "SUPPORTED_DEFECT"
    assert selected(second)["tier"] == "NEEDS_CONTEXT"
    assert selected(first)["raw_finding"] == selected(second)["raw_finding"]


_REGISTERED_BEARER_MUTATIONS = {
    "unrelated-star-import": [
        ("models.py", "", "class Record: pass\n"),
        ("maintenance.py", "", "from models import *\n"),
    ],
    "bearer-star-import": [
        ("client.py", "", "from deps import *\nmutate(bearer)\n"),
    ],
    "status-401-scalar": [
        (
            "deps.py",
            "from fastapi import Depends",
            "from fastapi import status\nfrom fastapi import Depends",
        ),
        ("deps.py", "status_code=401", "status_code=status.HTTP_401_UNAUTHORIZED"),
    ],
    "status-403-scalar": [
        (
            "deps.py",
            "from fastapi import Depends",
            "from fastapi import status\nfrom fastapi import Depends",
        ),
        ("deps.py", "status_code=401", "status_code=status.HTTP_403_FORBIDDEN"),
    ],
    "signing-namespace-return": [
        (
            "client.py",
            "",
            "import signing\ndef exported_namespace():\n    return signing\nexported_namespace().key = runtime_key\n",
        ),
    ],
    "signing-scalar-return": [
        ("client.py", "", "from signing import key\ndef key_copy():\n    return key\n"),
    ],
    "helper-callable-reexport": [
        ("bridge.py", "", "from signing import verify\n"),
        (
            "client.py",
            "",
            "from bridge import verify\ndef reject(token):\n    return {}\nverify.__code__ = reject.__code__\n",
        ),
    ],
    "jwt-callable-reexport": [
        ("bridge.py", "", "from jwt import decode\n"),
        ("client.py", "", "from bridge import decode\nmutate(decode)\n"),
    ],
    "bearer-reexport-mutation": [
        ("bridge.py", "", "from deps import bearer\n"),
        ("client.py", "", "from bridge import bearer\nbearer.__class__ = RejectAll\n"),
    ],
    "bearer-reexport-alias-mutation": [
        ("bridge.py", "", "from deps import bearer as selected\nexported = selected\n"),
        ("client.py", "", "from bridge import exported\nmutate(exported)\n"),
    ],
    "bearer-reexport-readonly": [
        ("bridge.py", "", "from deps import bearer\n"),
    ],
    "starlette-route-without-di": [("routes.py", "@router.get(", "@router.route(")],
    "unrelated-dependency": [
        (
            "client.py",
            "",
            "from deps import connection, replacement\napp.dependency_overrides[connection] = replacement\n",
        )
    ],
    "auth-override": [
        (
            "client.py",
            "",
            "from deps import principal, replacement\napp.dependency_overrides[principal] = replacement\n",
        )
    ],
    "unknown-override": [
        (
            "client.py",
            "",
            "from deps import replacement\napp.dependency_overrides[runtime_selector] = replacement\n",
        )
    ],
    "app-escape": [("client.py", "", "mutate(app)\n")],
    "provider-replacement": [
        ("client.py", "", "import jwt\njwt.decode = replacement\n")
    ],
    "helper-replacement": [
        ("client.py", "", "from signing import verify\nverify.__code__ = replacement\n")
    ],
    "settings-mutation": [
        (
            "client.py",
            "",
            "from config import Settings\nSettings.model_fields['secret_key'].default = replacement\n",
        )
    ],
    "custom-settings-hook": [
        ("config.py", "", "    def custom_source(self):\n        return replacement\n")
    ],
    "wrong-type": [("config.py", "secret_key: str", "secret_key: bytes")],
    "claims-overwrite": [
        ("deps.py", "    if not claims:", "    claims = token\n    if not claims:")
    ],
    "effecting-guard": [("deps.py", "if not claims:", "if not mutate(claims):")],
    "unregistered": [("app.py", "app.include_router(router)\n", "")],
    "disabled": [
        (
            "signing.py",
            "algorithms=['HS256'])",
            "algorithms=['HS256'], options={'verify_signature': False})",
        )
    ],
    "clock-replacement": [("client.py", "", "import time\ntime.time = replacement\n")],
    "dependency-replacement": [
        (
            "client.py",
            "",
            "from deps import principal\nprincipal.__code__ = replacement\n",
        )
    ],
    "router-replacement": [
        ("client.py", "", "from routes import router\nrouter.get = replacement\n")
    ],
    "override-update": [
        (
            "client.py",
            "",
            "from deps import principal, replacement\napp.dependency_overrides.update({principal: replacement})\n",
        )
    ],
    "routes-clear": [("client.py", "", "app.routes.clear()\n")],
    "settings-dict-update": [
        (
            "client.py",
            "",
            "from config import Settings\nSettings.model_fields['secret_key'].__dict__.update({'default': replacement})\n",
        )
    ],
    "client-replacement": [
        (
            "client.py",
            "client = TestClient(app)",
            "TestClient = mutate\nclient = TestClient(app)",
        )
    ],
    "bearer-instance-class": [
        ("client.py", "", "from deps import bearer\nbearer.__class__ = RejectAll\n")
    ],
    "bearer-instance-escape": [
        ("client.py", "", "from deps import bearer\nmutate(bearer)\n")
    ],
    "bearer-instance-dictionary": [
        (
            "client.py",
            "",
            "from deps import bearer\nbearer.__dict__.update(runtime_overrides)\n",
        )
    ],
    "bearer-instance-alias": [
        ("client.py", "", "from deps import bearer\nalias = bearer\nmutate(alias)\n")
    ],
    "bearer-dependency-override": [
        (
            "client.py",
            "",
            "from deps import bearer, replacement\napp.dependency_overrides[bearer] = replacement\n",
        )
    ],
    "missing-token-url": [("deps.py", "tokenUrl='/token'", "")],
    "duplicate-algorithms": [
        (
            "signing.py",
            "algorithms=['HS256'])",
            "algorithms=['HS256'], algorithms=['HS256'])",
        )
    ],
    "status-replacement": [
        (
            "deps.py",
            "from fastapi import Depends",
            "from fastapi import status\nfrom fastapi import Depends",
        ),
        ("deps.py", "status_code=401", "status_code=status.HTTP_401_UNAUTHORIZED"),
        (
            "client.py",
            "",
            "from fastapi import status\nstatus.HTTP_401_UNAUTHORIZED = 200\n",
        ),
    ],
    "provider-dictionary": [
        ("client.py", "", "import jwt\njwt.__dict__.update({'decode': replacement})\n")
    ],
    "provider-vars": [
        (
            "client.py",
            "",
            "import jwt\nnamespace = vars(jwt)\nnamespace['decode'] = replacement\n",
        )
    ],
    "dynamic-provider-execution": [("client.py", "", "exec(runtime_program)\n")],
}


@pytest.mark.parametrize("mutation", [None, *_REGISTERED_BEARER_MUTATIONS])
def test_registered_bearer_rejection_preserves_source_and_selected_dependency_ownership(
    mutation,
):
    files, name = _operative_signing_default_sources("settings-factory")
    files["signing.py"] = "import time\n" + files["signing.py"].replace(
        "return decode(token, key, algorithms=['HS256'])",
        "claims = decode(token.encode(), key, algorithms=['HS256'])\n    return claims if claims['expires'] >= time.time() else {}",
    )
    files["deps.py"] = (
        "from fastapi import Depends, HTTPException\nfrom fastapi.security import OAuth2PasswordBearer\n"
        "from signing import verify\nbearer = OAuth2PasswordBearer(tokenUrl='/token')\n"
        "async def connection():\n    yield None\nasync def replacement():\n    yield None\n"
        "async def principal(token: str = Depends(bearer)):\n    claims = verify(token)\n"
        "    if not claims:\n        raise HTTPException(status_code=401)\n    return claims['sub']\n"
    )
    files["routes.py"] = (
        "from fastapi import APIRouter, Depends\nfrom deps import principal\nrouter = APIRouter()\n"
        "@router.get('/profile')\nasync def profile(identity = Depends(principal)):\n    return identity\n"
    )
    files["app.py"] = (
        "from fastapi import FastAPI\nfrom routes import router\napp = FastAPI()\napp.include_router(router)\n"
    )
    files["client.py"] = (
        "from fastapi.testclient import TestClient\nfrom app import app\nclient = TestClient(app)\n"
    )
    for path, before, after in _REGISTERED_BEARER_MUTATIONS.get(mutation, ()):
        if before:
            assert before in files[path]
            files[path] = files[path].replace(before, after)
        else:
            files[path] = files.get(path, "") + after
    row = _captured_secret_tiers(files, "config.py", name)["ledger"][0]
    assert row["tier"] == (
        "SUPPORTED_DEFECT"
        if mutation
        in {
            None,
            "unrelated-dependency",
            "bearer-reexport-readonly",
            "signing-scalar-return",
            "status-401-scalar",
            "status-403-scalar",
            "unrelated-star-import",
        }
        else "NEEDS_CONTEXT"
    )
    assert row["raw_finding"]["severity"] == "CRITICAL"
    if row["tier"] == "SUPPORTED_DEFECT":
        assert {
            item["path"]
            for item in row["credential_authority_observation"]["transfers"]
        } >= {"app.py", "config.py", "signing.py", "routes.py", "deps.py"}


@pytest.mark.parametrize("flow", ["settings-constructor", "settings-factory"])
@pytest.mark.parametrize("mutation", [None, "override", "wrong-origin"])
def test_shared_default_projection_preserves_conditional_origin_across_factories(
    flow, mutation
):
    from hashlib import sha256
    from pathlib import Path
    from factoryline.semantic_credential_sensor import signing_configuration_inventory
    from factoryline.credential_endpoint_admission import (
        _CredentialHandlerIndex,
        _OperativeCredentialOrigin,
    )

    files, name = _operative_signing_default_sources(flow, mutation)
    sources = {path: value.encode() for path, value in files.items()}
    context = signing_configuration_inventory(
        sources, {p: sha256(raw).hexdigest() for p, raw in sources.items()}
    )
    index = context["index"]
    index.validate(Path("config.py"))
    declaration = next(
        node
        for node in ast.walk(index.snapshots[Path("config.py")])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
    )
    finding = {"path": "config.py", "facts": {"name": name}}
    handler = _CredentialHandlerIndex(context).handlers[0]
    origin = _OperativeCredentialOrigin(context, finding, handler, declaration)
    path = Path("routes.py" if flow == "serializer-helper" else "signing.py")
    index.validate(path)
    assignment = next(
        n
        for n in ast.walk(index.snapshots[path])
        if isinstance(n, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == ("signer" if flow == "serializer-helper" else "key")
            for target in n.targets
        )
    )
    known, value = origin.projection.expression(path, assignment.value)
    assert known is (mutation is None)
    if known:
        assert value.roots == frozenset({origin.root})
        assert value._exact_scalar == () and value.inert_kind is None
        assert value.trace


@pytest.mark.parametrize(
    "flow", ["settings-constructor", "settings-factory", "serializer-helper"]
)
@pytest.mark.parametrize("mutation", [None, "no-route"])
def test_credential_route_registration_is_bound_to_captured_application(flow, mutation):
    from hashlib import sha256
    from factoryline.semantic_credential_sensor import signing_configuration_inventory
    from factoryline.credential_endpoint_admission import _CredentialHandlerIndex

    files, _ = _operative_signing_default_sources(flow, mutation)
    sources = {path: source.encode() for path, source in files.items()}
    context = signing_configuration_inventory(
        sources, {path: sha256(raw).hexdigest() for path, raw in sources.items()}
    )
    handlers = _CredentialHandlerIndex(context).handlers
    assert len(handlers) == (0 if mutation else 1)
    for handler in handlers:
        assert handler["application"]["path"].as_posix() == "app.py"
        assert handler["application"]["kind"] == "application"


@pytest.mark.parametrize(
    "flow", ["settings-constructor", "settings-factory", "serializer-helper"]
)
@pytest.mark.parametrize(
    "mutation", ["override", "wrong-origin", "no-route", "verification-disabled"]
)
def test_operative_signing_default_origin_family_requires_complete_authority(
    flow, mutation
):
    files, secret_name = _operative_signing_default_sources(flow, mutation)
    report = _captured_secret_tiers(files, "config.py", secret_name)
    assert report["ledger"][0]["tier"] == "NEEDS_CONTEXT"
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "evidence",
    [
        {},
        {"proof_scope": "future-origin-contract"},
        {"proof_scope": "captured_same_module_static_wiring"},
        {"proof_scope": "source_bound_flask_session_authority"},
        {
            "schema": "factory.security.private-key-auth-flow.v1",
            "proof_scope": "captured_same_module_static_wiring",
            "consumer_role": "metadata_only",
        },
        {
            "proof_scope": "source_bound_flask_session_authority",
            "framework": "flask",
            "credential_key": "SECRET_KEY",
            "consumer_role": "flask_login_session",
            "transfers": [None],
        },
        {
            "schema": "factory.security.private-key-auth-flow.v1",
            "proof_scope": "captured_same_module_static_wiring",
            "source_role": "embedded_private_key",
            "consumer_role": "django_password_verifier",
            "transfers": [None],
        },
        {
            "proof_scope": "future-origin-contract",
            "transfers": [
                {"path": "config.py", "sha256": "a" * 64, "span": [1, 0, 1, 12]}
            ],
        },
        "trusted",
        [],
    ],
)
def test_unrecognized_credential_witness_never_grants_admission(evidence):
    from factoryline.primitive_observation_binding import _decide_finding_tier

    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "config.py",
        "line": 1,
        "facts": {"name": "SECRET_KEY"},
    }
    assert _decide_finding_tier(
        finding, True, [], [], evidence, source_bindings={"config.py": "a" * 64}
    ) == ("NEEDS_CONTEXT", None, None)


@pytest.mark.parametrize("kind", ["flask", "private-key"])
@pytest.mark.parametrize(
    "mutation",
    [None, "stale-source", "wrong-origin", "unbound-transfer", "invalid-span"],
)
def test_recognized_credential_witness_binds_every_transfer_and_origin(kind, mutation):
    from factoryline.primitive_observation_binding import _decide_finding_tier

    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "config.py",
        "line": 1,
        "facts": {"name": "SECRET_KEY"},
    }
    transfers = [{"path": "config.py", "sha256": "a" * 64, "span": [1, 0, 1, 12]}]
    if kind == "flask":
        evidence = {
            "proof_scope": "source_bound_flask_session_authority",
            "framework": "flask",
            "credential_key": "SECRET_KEY",
            "consumer_role": "flask_login_session",
            "transfers": transfers,
        }
    else:
        evidence = {
            "schema": "factory.security.private-key-auth-flow.v1",
            "proof_scope": "captured_same_module_static_wiring",
            "source_role": "embedded_private_key",
            "consumer_role": "django_password_verifier",
            "transfers": transfers,
        }
    if mutation == "stale-source":
        transfers[0]["sha256"] = "b" * 64
    elif mutation == "wrong-origin":
        transfers[0]["span"] = [2, 0, 2, 12]
    elif mutation == "unbound-transfer":
        transfers.append(
            {"path": "missing.py", "sha256": "b" * 64, "span": [1, 0, 1, 12]}
        )
    elif mutation == "invalid-span":
        transfers[0]["span"] = [1, True, 1, 12]
    tier = _decide_finding_tier(
        finding, True, [], [], evidence, source_bindings={"config.py": "a" * 64}
    )[0]
    assert tier == ("SUPPORTED_DEFECT" if mutation is None else "NEEDS_CONTEXT")


def _flask_login_config_sources(*, target="config", include_login=True, overwrite=""):
    return {
        "requirements.txt": "flask\nflask-login\n",
        "config.py": 'SECRET_KEY = "source-bound-login-signing-key"\n',
        "app.py": (
            "from flask import *\n"
            "from flask_login import LoginManager, login_user, login_required\n"
            "app = Flask(__name__)\n"
            f"app.config.from_object('{target}')\n"
            + overwrite
            + "login_manager = LoginManager()\n"
            "login_manager.init_app(app)\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    if user.check_password(password):\n"
            "        login_user(user)\n"
            "        return 'ok'\n"
            "    return 'denied'\n"
            "@app.route('/profile')\n"
            + ("@login_required\n" if include_login else "")
            + "def profile():\n"
            "    return current_user.id\n"
        ),
    }


def test_tier314_flask_login_session_accepts_cross_module_signing_default():
    from hashlib import sha256

    files = _flask_login_config_sources()
    report = _captured_secret_tiers(files, "config.py")
    row = report["ledger"][0]
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["evidence"] == "source_bound_flask_session_authority"
    observation = row["credential_authority_observation"]
    assert observation["credential_key"] == "SECRET_KEY"
    assert observation["consumer_role"] == "flask_login_session"
    assert observation["runtime_execution"] == "not_performed"
    assert observation["deployment"] == "UNASSESSED"
    assert {transfer["path"] for transfer in observation["transfers"]} == {
        "config.py",
        "app.py",
    }
    assert all(
        transfer["sha256"] == sha256(files[transfer["path"]].encode()).hexdigest()
        for transfer in observation["transfers"]
    )


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            _flask_login_config_sources(include_login=False),
            id="no-protected-session-route",
        ),
        pytest.param(
            _flask_login_config_sources(overwrite='app.config["SECRET_KEY"] = other\n'),
            id="post-load-secret-overwrite",
        ),
        pytest.param(
            _flask_login_config_sources(target="other"),
            id="different-loaded-module",
        ),
    ],
)
def test_tier314_flask_login_requires_effective_config_and_session_consumers(files):
    report = _captured_secret_tiers(files, "config.py")
    assert report["tier_counts"]["SUPPORTED_DEFECT"] == 0
    assert report["ledger"][0]["tier"] == "NEEDS_CONTEXT"
    assert report["ledger"][0]["raw_finding"]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "mutation",
    [
        "manager-rebound",
        "init-method-replaced",
        "reverse-decorators",
        "later-env-config",
        "nested-env-config",
    ],
)
def test_flask_login_admission_rejects_broken_consumer_identity(mutation):
    files = _flask_login_config_sources()
    if mutation == "manager-rebound":
        files["app.py"] = files["app.py"].replace(
            "login_manager.init_app(app)",
            "login_manager = other\nlogin_manager.init_app(app)",
        )
    elif mutation == "init-method-replaced":
        files["app.py"] = files["app.py"].replace(
            "login_manager.init_app(app)",
            "login_manager.init_app = other\nlogin_manager.init_app(app)",
        )
    elif mutation == "reverse-decorators":
        files["app.py"] = files["app.py"].replace(
            "@app.route('/profile')\n@login_required",
            "@login_required\n@app.route('/profile')",
        )
    else:
        reload = "app.config.from_envvar('APP_CONFIG')\n"
        if mutation == "nested-env-config":
            reload = "if enabled:\n    " + reload
        files["app.py"] = files["app.py"].replace(
            "login_manager = LoginManager()", reload + "login_manager = LoginManager()"
        )
    assert (
        _captured_secret_tiers(files, "config.py")["tier_counts"]["SUPPORTED_DEFECT"]
        == 0
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "metadata",
        "bound-metadata",
        "unbound-python",
        "missing-python",
        "changed-python",
        "changed-bound-metadata",
    ],
)
def test_signing_inventory_preserves_python_binding_closure_with_metadata(mutation):
    from hashlib import sha256
    from factoryline.semantic_credential_sensor import signing_configuration_inventory

    sources = {"app.py": b"import flask\n", "requirements.txt": b"flask\n"}
    bindings = {"app.py": sha256(sources["app.py"]).hexdigest()}
    if mutation in {"bound-metadata", "changed-bound-metadata"}:
        bindings["requirements.txt"] = sha256(sources["requirements.txt"]).hexdigest()
    if mutation == "unbound-python":
        sources["flask.py"] = b""
    elif mutation == "missing-python":
        del sources["app.py"]
    elif mutation == "changed-python":
        sources["app.py"] += b"# changed\n"
    elif mutation == "changed-bound-metadata":
        sources["requirements.txt"] += b"changed\n"
    result = signing_configuration_inventory(sources, bindings)
    assert (result is not None) == (mutation in {"metadata", "bound-metadata"})


def test_flask_admission_validator_change_invalidates_warm_native_proof(
    tmp_path, monkeypatch
):
    from factoryline import credential_endpoint_admission as admission

    for name, source in _flask_login_config_sources().items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    with audit._security_only_scan_context(True):
        first = audit.security_scan(tmp_path, cache_enabled=True)
        monkeypatch.setattr(
            admission, "_flask_login_session_authority_witness", lambda *args: None
        )
        second = audit.security_scan(tmp_path, cache_enabled=True)

    def secret_row(report):
        return next(
            row
            for row in report["finding_tier_report"]["ledger"]
            if row["raw_finding"].get("facts", {}).get("name") == "SECRET_KEY"
        )

    assert first["sources"] == second["sources"]
    assert secret_row(first)["tier"] == "SUPPORTED_DEFECT"
    assert secret_row(second)["tier"] == "NEEDS_CONTEXT"
    assert secret_row(first)["raw_finding"] == secret_row(second)["raw_finding"]


def test_tier314_flask_session_authority_preserves_both_source_diagnostics():
    """flask_credential_authority_evidence ties both source diagnostics to complete captured session transfers."""
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
    """private_key_authentication_evidence requires captured decryption, POST routing, and password verification."""
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
    """bind_request_sink_precondition supports only the captured request-body path and retains its raw sink finding."""
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
    """bind_request_sink_precondition preserves bytes-versus-text source kind for the exact Flask body call shape."""
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
    """http_request_payload and request_payload_value_kind accept only selected Flask or Django mapping values with matching sink types."""
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
    opaque_json_codec = sink == "pickle.loads(payload.encode())" and expression in {
        'request.json["cmd"]',
        'request.get_json()["cmd"]',
    }
    supported = any(
        row.get("facts", {}).get("security_precondition") for row in findings
    )
    assert supported is not opaque_json_codec
    if opaque_json_codec:
        assert any(
            row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
            and row["severity"] == "HIGH"
            for row in findings
        )


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
    assert "security_precondition" not in logs[0]["facts"]


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


def test_log_security_precondition_requires_typed_effect_and_possible_sink_path():
    """Unknown log input domains do not receive a generic supported-effect premise."""
    from types import SimpleNamespace

    stable = SimpleNamespace(_security_log_provider_stable=True)
    call = ast.parse("logging.warning(user_input)").body[0].value
    assert sensors.log_security_precondition(stable, call) == {}

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


@pytest.mark.parametrize("value", ["placeholder", "example", "changeme", "replace-me"])
def test_literal_placeholder_is_reported_only_when_used_as_http_auth(value):
    findings = _scan(
        "import requests\n"
        f"PASSWORD = {value!r}\n"
        f"requests.get('https://host.test', auth=('user', {value!r}))\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["consumer_role"] == "http_auth"
    assert value not in repr(findings[0]["facts"])


def test_public_native_scan_keeps_auth_placeholder_separate_from_metadata_and_templates(
    tmp_path,
):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "PASSWORD = 'placeholder'\n"
        "requests.get('https://host.test', auth=('user', 'placeholder'))\n"
        "requests.get('https://host.test', auth=('user', '${PASSWORD}'))\n"
        "requests.get('https://host.test', headers={'X-Note': 'placeholder'})\n"
        "requests.get('https://host.test', headers={'Authorization': f'Bearer {PASSWORD}'})\n",
        encoding="utf-8",
    )
    report = audit.security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "SECURITY_LITERAL_HTTP_CREDENTIAL"
    ]
    assert len(findings) == 1
    assert findings[0]["line"] == 3
    assert findings[0]["facts"]["consumer_role"] == "http_auth"
    assert findings[0]["facts"]["credential_validity"] == "not_established"
    assert findings[0]["facts"]["proof_scope"] == "local_static_wiring"
    assert "placeholder" not in repr(findings[0]["facts"])


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
    assert len(findings) == 2
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
    "mutation, surviving_provider",
    [
        ("requests.get = fake_get", "httpx"),
        ("setattr(requests.auth, 'HTTPBasicAuth', fake_auth)", "httpx"),
        ("saved_provider = requests", "httpx"),
        ("requests.auth.HTTPBasicAuth = fake_auth", "httpx"),
        ("httpx.Client = FakeClient", "requests"),
    ],
)
def test_provider_mutation_only_vetoes_its_credential_proofs(
    mutation, surviving_provider
):
    findings = _scan(
        "import requests\n"
        "import httpx\n"
        f"{mutation}\n"
        "def later():\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
        "    requests.auth.HTTPBasicAuth('user', 'literal-password')\n"
        "    httpx.Client().post('https://host.test', headers={'Authorization': 'Bearer token-value'})\n"
    )
    assert len(findings) == (1 if surviving_provider == "httpx" else 2)
    expected_role = "http_header" if surviving_provider == "httpx" else "http_auth"
    assert all(item["facts"]["consumer_role"] == expected_role for item in findings)


@pytest.mark.parametrize("password", ["your-password", "your_password"])
def test_your_prefixed_literal_is_not_a_new_placeholder_waiver(password):
    findings = _scan(
        "import requests\n"
        f"requests.get('https://host.test', auth=('user', {password!r}))\n"
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
        "requests.get('https://host.test', auth=('user', '${PASSWORD}'))\n"
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


@pytest.mark.parametrize(
    "mutation",
    [
        "yaml.SafeLoader.yaml_constructors['tag'] = replacement",
        "del yaml.SafeLoader.yaml_constructors['tag']",
        "registry = yaml.SafeLoader.yaml_constructors\nregistry['tag'] = replacement",
    ],
)
def test_provider_mutation_index_tracks_subscript_writes_and_deletes(mutation):
    from types import SimpleNamespace

    from factoryline.finite_capture import finite_provider_mutation_index

    tree = ast.parse("import yaml\n" + mutation + "\n")
    nodes = tuple(ast.walk(tree))
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    mutations = finite_provider_mutation_index(
        nodes,
        _security_aliases(nodes),
        SimpleNamespace(_resolved_ast_name=audit._resolved_ast_name),
        parents,
    )
    assert ("yaml.SafeLoader.yaml_constructors", "*") in mutations


@pytest.mark.parametrize(
    "foreign_source",
    [
        "import yaml\nyaml.safe_load(other)\n",
        "import yaml\nyaml.dump(other, Dumper=yaml.SafeDumper)\n",
        "import yaml\nyaml.compose(other, Loader=yaml.SafeLoader)\n",
    ],
)
def test_yaml_safe_loader_survives_typed_sibling_consumers(tmp_path, foreign_source):
    (tmp_path / "parse.py").write_text(
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n", encoding="utf-8"
    )
    (tmp_path / "sibling.py").write_text(foreign_source, encoding="utf-8")

    findings = audit.security_scan(tmp_path, cache_enabled=False)["findings"]

    assert not any(item["code"] == "SECURITY_UNSAFE_YAML" for item in findings)


@pytest.mark.parametrize(
    "foreign_source",
    [
        "import yaml\nyaml.SafeLoader.yaml_constructors['tag'] = replacement\n",
        "import yaml\nyaml.load = wrapper\n",
        "import yaml\nyaml.compose = wrapper\n",
        "import yaml\nyaml.dump = wrapper\n",
        "from yaml import SafeLoader as Exported\nexported_loader = Exported\n",
        "import yaml\ncustom_consumer(yaml.SafeLoader)\n",
        "import yaml\nyaml.compose(other, Loader=yaml.SafeLoader, **options)\n",
    ],
)
def test_yaml_safe_loader_keeps_adversarial_sibling_events_unknown(
    tmp_path, foreign_source
):
    """yaml_loader_provider_uncertain retains unsafe findings when sibling consumers escape or mutate loader state."""
    (tmp_path / "parse.py").write_text(
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n", encoding="utf-8"
    )
    (tmp_path / "sibling.py").write_text(foreign_source, encoding="utf-8")

    findings = audit.security_scan(tmp_path, cache_enabled=False)["findings"]

    assert any(item["code"] == "SECURITY_UNSAFE_YAML" for item in findings)


def test_yaml_typed_consumer_filter_respects_foreign_scope_shadowing(tmp_path):
    """Typed YAML argument consumers reject a foreign-scope loader shadow."""
    (tmp_path / "parse.py").write_text(
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n", encoding="utf-8"
    )
    (tmp_path / "sibling.py").write_text(
        "from yaml import SafeLoader as SL\n"
        "import yaml\n"
        "def run(yaml):\n"
        "    yaml.compose(data, Loader=SL)\n",
        encoding="utf-8",
    )

    findings = audit.security_scan(tmp_path, cache_enabled=False)["findings"]

    assert any(item["code"] == "SECURITY_UNSAFE_YAML" for item in findings)


def test_yaml_load_signature_and_loader_consumer_use_exact_slots():
    """YAML call-shape validation binds one stream and loader slot and rejects duplicates."""
    valid = ast.parse("import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n")
    nodes = list(ast.walk(valid))
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    call = next(node for node in nodes if isinstance(node, ast.Call))
    loader = next(
        node
        for node in nodes
        if isinstance(node, ast.Attribute) and node.attr == "SafeLoader"
    )
    aliases = audit._security_aliases(nodes)
    assert sensors.yaml_load_call_signature(call)
    assert (
        sensors.yaml_loader_argument_consumer(loader, aliases, parents) == "yaml.load"
    )

    malformed = ast.parse(
        "import yaml\nyaml.load(data, stream=data, Loader=yaml.Loader)\n"
    )
    malformed_nodes = list(ast.walk(malformed))
    malformed_parents = {
        id(child): node
        for node in malformed_nodes
        for child in ast.iter_child_nodes(node)
    }
    malformed_call = next(
        node for node in malformed_nodes if isinstance(node, ast.Call)
    )
    malformed_loader = next(
        node
        for node in malformed_nodes
        if isinstance(node, ast.Attribute) and node.attr == "Loader"
    )
    assert not sensors.yaml_load_call_signature(malformed_call)
    assert (
        sensors.yaml_loader_argument_consumer(
            malformed_loader,
            audit._security_aliases(malformed_nodes),
            malformed_parents,
        )
        is None
    )


def test_security_precondition_call_shape_requires_one_modeled_argument():
    eval_call = ast.parse("eval(source)").body[0].value
    expanded_eval = ast.parse("eval(*values)").body[0].value
    shell_call = ast.parse("subprocess.run(command, shell=True)").body[0].value
    unsafe_shell = ast.parse("subprocess.run(command, shell=False)").body[0].value

    assert sensors.security_precondition_call_shape(eval_call, "eval")
    assert not sensors.security_precondition_call_shape(expanded_eval, "eval")
    assert sensors.security_precondition_call_shape(shell_call, "subprocess.run")
    assert not sensors.security_precondition_call_shape(unsafe_shell, "subprocess.run")


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
        (
            '    if password == app.config["ADMIN_PASSWORD"]:',
            '    password = "fixed-unrelated-value"\n    if password == app.config["ADMIN_PASSWORD"]:',
        ),
        (
            '    password = request.form.get("password")',
            '    return "public-no-auth"\n    password = request.form.get("password")',
        ),
        (
            '        session["logged_in"] = True',
            '        session["logged_in"] = True\n        session["logged_in"] = False',
        ),
        (
            '@app.route("/create")\n@login_required',
            '@login_required\n@app.route("/create")',
        ),
    ],
)
def test_flask_authority326_public_scanner_rejects_broken_custody(
    tmp_path, before, after
):
    source = _FLASK_AUTHORITY_SOURCE314.replace(before, after)
    assert source != _FLASK_AUTHORITY_SOURCE314
    (tmp_path / "app.py").write_text(source)
    with audit._security_only_scan_context(True):
        report = audit.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    assert report["audit_coverage"]["complete"] is True
    rows = report["finding_tier_report"]["ledger"]
    credentials = [
        row
        for row in rows
        if row["raw_finding"].get("code") == "SECURITY_HARDCODED_SECRET"
        and row["raw_finding"].get("facts", {}).get("name")
        in {"ADMIN_PASSWORD", "SECRET_KEY"}
    ]
    assert {row["raw_finding"]["facts"]["name"] for row in credentials} == {
        "ADMIN_PASSWORD",
        "SECRET_KEY",
    }
    assert {row["tier"] for row in credentials} == {"NEEDS_CONTEXT"}
    assert all("credential_authority_observation" not in row for row in credentials)


@pytest.mark.parametrize(
    "before, after",
    [
        ("def login_required(fn):", "def login_required(fn):\n    return fn"),
        (
            '        session["logged_in"] = True',
            '        session["logged_in"] = True\n        saved = session\n        saved.clear()',
        ),
        (
            '    password = request.form.get("password")\n    if password == app.config["ADMIN_PASSWORD"]:\n        session["logged_in"] = True\n        return redirect("/")',
            '    password = request.form.get("password")\n    if False:\n        pass\n    else:\n        password = "fixed-unrelated-value"\n        if password == app.config["ADMIN_PASSWORD"]:\n            session["logged_in"] = True\n            return redirect("/")',
        ),
        (
            '@app.route("/create")\n@login_required',
            'def discard_guard(fn):\n    return lambda: "created"\n\n@app.route("/create")\n@discard_guard\n@login_required',
        ),
    ],
)
def test_flask_authority326_public_scanner_rejects_adjacent_broken_custody(
    tmp_path, before, after
):
    source = _FLASK_AUTHORITY_SOURCE314.replace(before, after)
    assert source != _FLASK_AUTHORITY_SOURCE314
    (tmp_path / "app.py").write_text(source)
    with audit._security_only_scan_context(True):
        report = audit.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    assert report["audit_coverage"]["complete"] is True
    rows = report["finding_tier_report"]["ledger"]
    credentials = [
        row
        for row in rows
        if row["raw_finding"].get("facts", {}).get("name")
        in {"ADMIN_PASSWORD", "SECRET_KEY"}
    ]
    assert {row["raw_finding"]["facts"]["name"] for row in credentials} == {
        "ADMIN_PASSWORD",
        "SECRET_KEY",
    }
    assert {row["tier"] for row in credentials} == {"NEEDS_CONTEXT"}
    assert all("credential_authority_observation" not in row for row in credentials)


@pytest.mark.parametrize(
    "binding",
    [
        "for value in payload:\n        SINK",
        "with payload as value:\n        SINK",
        "match payload:\n        case value:\n            SINK",
    ],
)
@pytest.mark.parametrize("origin", ["parameter", "request", "safe-rebind"])
@pytest.mark.parametrize(
    "sink, code",
    [
        ("open(value)", "SECURITY_PATH_TRAVERSAL"),
        ("requests.get(value)", "SECURITY_SSRF"),
    ],
)
def test_control_binding_keeps_parameter_and_request_origins_distinct(
    binding, origin, sink, code
):
    setup = ""
    if origin == "request":
        setup = "    payload = request.args.get('path')\n"
    elif origin == "safe-rebind":
        setup = "    value = request.args.get('path')\n    payload = ('fixed',)\n"
    source = (
        "from flask import request\nimport requests\n"
        "def consume(payload):\n"
        + setup
        + "    "
        + binding.replace("SINK", sink)
        + "\n"
    )
    findings = _premise_scan(source)
    selected = [row for row in findings if row["code"] == code]
    assert bool(selected) is (origin == "request")


@pytest.mark.parametrize(
    "binding",
    [
        "for value in payload:\n        cursor.execute(f'SELECT * FROM records WHERE id={value}')",
        "with payload as value:\n        cursor.execute(f'SELECT * FROM records WHERE id={value}')",
        "match payload:\n        case value:\n            cursor.execute(f'SELECT * FROM records WHERE id={value}')",
    ],
)
def test_control_binding_keeps_generic_sql_parameter_candidates(binding):
    findings = _premise_scan(
        "import sqlite3\ndef consume(payload):\n"
        "    cursor = sqlite3.connect(':memory:').cursor()\n    " + binding + "\n"
    )
    assert any(row["code"] == "SECURITY_SQL_INJECTION" for row in findings)


@pytest.mark.parametrize(
    "source, expected",
    [
        ("request.args.get('path')", True),
        ("payload", False),
    ],
)
def test_multi_item_with_inspects_each_context_after_prior_binding(source, expected):
    # Static abstract-flow ordering only; captured target code is never executed.
    findings = _premise_scan(
        "from flask import request\nimport requests\ndef consume(payload):\n"
        f"    with {source} as first, requests.get(first) as second:\n"
        "        pass\n"
    )
    assert any(row["code"] == "SECURITY_SSRF" for row in findings) is expected


@pytest.mark.parametrize(
    "guard, body_possible",
    [
        ("False", False),
        ("True", True),
        ("not True", False),
        ("1 == 2", False),
        ("'x' in ['y']", False),
        ("True and False", False),
        ("False or True", True),
        ("unknown", None),
        ("check()", None),
        ("config.enabled", None),
        ("values[0]", None),
        ("0 is 1", None),
        ("unknown or True", None),
        ("unknown and False", None),
        ("{'x': 1} == {'x': 1}", True),
    ],
)
@pytest.mark.parametrize("source_in_body", [False, True])
@pytest.mark.parametrize(
    "sink, code",
    [
        ("requests.get(value)", "SECURITY_SSRF"),
        ("open(value)", "SECURITY_PATH_TRAVERSAL"),
        ("eval(value)", "SECURITY_DYNAMIC_EXECUTION"),
        ("cursor.execute('SELECT ' + value)", "SECURITY_SQL_INJECTION"),
    ],
)
def test_literal_branch_reaching_definitions_keep_only_possible_source_writes(
    guard, body_possible, source_in_body, sink, code
):
    dangerous = "value = request.args['url']"
    source = (
        "from flask import request\nimport requests, sqlite3\n"
        "def consume(unknown, config, values):\n"
        "    cursor = sqlite3.connect(':memory:').cursor()\n"
        "    value = 'fixed'\n"
        f"    if {guard}:\n        {dangerous if source_in_body else 'pass'}\n"
        f"    else:\n        {'pass' if source_in_body else dangerous}\n"
        f"    {sink}\n"
    )
    selected = [
        row
        for row in _premise_scan(source)
        if row["code"] == code
        and (
            code != "SECURITY_DYNAMIC_EXECUTION"
            or row.get("facts", {}).get("security_precondition", {}).get("status")
            == "SUPPORTED"
        )
    ]
    expected = body_possible is None or body_possible == source_in_body
    assert bool(selected) is expected


@pytest.mark.parametrize("guard", ["False", "True", "unknown", "check()"])
def test_literal_branch_overwrite_keeps_possible_taint_until_proven_killed(guard):
    source = (
        "from flask import request\nimport requests\ndef consume(unknown):\n"
        "    value = request.args['url']\n"
        f"    if {guard}:\n        value = 'fixed'\n"
        "    else:\n        value = 'also-fixed'\n"
        "    requests.get(value)\n"
    )
    assert not any(row["code"] == "SECURITY_SSRF" for row in _premise_scan(source))


@pytest.mark.parametrize(
    "guard", ["[*items]", "{**items}", "1 < 'x'", "[0] * 100", "(flag := False)"]
)
def test_literal_guard_unknown_syntax_never_removes_a_branch(guard):
    from factoryline.finite_capture import security_literal_branch_blocks

    branch = ast.parse(f"if {guard}:\n    dangerous()\nelse:\n    other()\n").body[0]
    assert security_literal_branch_blocks(branch) == (branch.body, branch.orelse)


def test_flask_file_storage_effect_requires_normalized_escape_and_raw_filename():
    findings = _premise_scan(
        "from flask import request\nfrom werkzeug.utils import safe_join\nimport os\n"
        "def upload():\n"
        "    item = request.files['file']\n"
        "    ignored = safe_join('/srv/uploads', 'fixed.csv')\n"
        "    destination = os.path.join('/srv/uploads', item.filename)\n"
        "    item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    witness = path["facts"]["security_precondition"]["effect_witness"]
    assert witness["schema"] == sensors.SECURITY_EFFECT_WITNESS_SCHEMA
    assert witness["source_role"] == "untrusted_request_filename"
    assert witness["consumer_role"] == "flask_file_storage_save"
    assert witness["effect_kind"] == "path_escape"
    assert witness["effect_facts"] == {
        "provider_id": "werkzeug.FileStorage.save",
        "path_composition": "os.path.join",
        "destination_relation": "escape_capable",
        "normalized_counterexample_relation": "outside_intended_base",
        "normalization_profile": "python_os_path",
        "intended_base_span": witness["effect_facts"]["intended_base_span"],
    }
    assert len(witness["effect_facts"]["intended_base_span"]) == 4


def test_flask_file_storage_raw_separator_concat_has_escape_witness():
    findings = _premise_scan(
        "from flask import request\ndef upload():\n"
        "    item = request.files['file']\n"
        "    destination = '/srv/uploads/' + item.filename\n"
        "    item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    witness = path["facts"]["security_precondition"]["effect_witness"]
    assert witness["effect_facts"]["path_composition"] == "raw_string_concat"


@pytest.mark.parametrize(
    "guard",
    [
        "if name:\n    pass\n",
        "if name:\n    print('observed')\n",
        "if os.path.splitext(name)[1] not in {'.csv', '.png'}:\n    abort(400)\n",
    ],
)
def test_flask_file_storage_unrelated_or_suffix_guards_keep_real_escape_witness(guard):
    source = (
        "from flask import request, abort\nimport os\n"
        "def upload():\n"
        "    item = request.files['file']\n"
        "    name = item.filename\n"
        + "    "
        + guard.replace("\n", "\n    ").rstrip()
        + "\n"
        + "    destination = os.path.join('/srv/uploads', name)\n"
        + "    item.save(destination)\n"
    )
    findings = _premise_scan(source)
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" in path["facts"]["security_precondition"]


def test_flask_file_storage_raw_concat_span_covers_full_intended_prefix():
    source = (
        "from flask import request\ndef upload(base):\n"
        "    item = request.files['file']\n"
        "    destination = base + '/uploads/ocr/' + item.filename\n"
        "    item.save(destination)\n"
    )
    findings = _premise_scan(source)
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    span = path["facts"]["security_precondition"]["effect_witness"]["effect_facts"][
        "intended_base_span"
    ]
    line = source.splitlines()[span[0] - 1]
    assert line[span[1] : span[3]] == "base + '/uploads/ocr/'"


def test_flask_file_storage_nested_sink_uses_actual_save_program_point():
    findings = _premise_scan(
        "from flask import request\nimport os\ndef upload():\n"
        "    if request.method == 'POST':\n"
        "        item = request.files['file']\n"
        "        filename = item.filename\n"
        "        destination = os.path.join('/srv/uploads', filename)\n"
        "        item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" in path["facts"]["security_precondition"]


def test_flask_file_storage_random_prefix_keeps_raw_without_escape_witness():
    findings = _premise_scan(
        "from flask import request\nimport os, random\n"
        "def upload():\n"
        "    item = request.files['file']\n"
        "    destination = os.path.join('/srv/uploads', str(random.randrange(1000)) + item.filename)\n"
        "    item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" not in path["facts"].get("security_precondition", {})


@pytest.mark.parametrize(
    "body, has_raw_finding",
    [
        (
            "filename = secure_filename(item.filename)\n"
            "    destination = os.path.join('/srv/uploads', filename)\n",
            False,
        ),
        (
            "destination = os.path.join('/srv/uploads', item.filename)\n"
            "    if os.path.commonpath(['/srv/uploads', destination]) == '/srv/uploads':\n"
            "        item.save(destination)\n",
            True,
        ),
        (
            "name = item.filename\n"
            "    if name not in {'ok.csv', 'image.png'}:\n"
            "        abort(400)\n"
            "    destination = os.path.join('/srv/uploads', name)\n"
            "    item.save(destination)\n",
            True,
        ),
        (
            "name = item.filename\n"
            "    if re.fullmatch(r'[a-z0-9_-]+\\.csv', name) is None:\n"
            "        abort(400)\n"
            "    destination = os.path.join('/srv/uploads', name)\n"
            "    item.save(destination)\n",
            True,
        ),
    ],
)
def test_flask_file_storage_safe_filename_or_containment_has_no_effect_witness(
    body, has_raw_finding
):
    findings = _premise_scan(
        "from flask import request\nfrom werkzeug.utils import secure_filename\n"
        "import os\ndef upload():\n"
        "    item = request.files['file']\n    "
        + body
        + ("    item.save(destination)\n" if "commonpath" not in body else "")
    )
    path_rows = [
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    ]
    assert bool(path_rows) is has_raw_finding
    if has_raw_finding:
        assert "effect_witness" not in path_rows[0]["facts"].get(
            "security_precondition", {}
        )


def test_flask_file_storage_full_path_component_guard_has_no_effect_witness():
    findings = _premise_scan(
        "from flask import request, abort\nimport os\ndef upload():\n"
        "    item = request.files['file']\n"
        "    name = item.filename\n"
        "    if '/' in name or '\\\\' in name or '..' in name or ':' in name:\n"
        "        abort(400)\n"
        "    destination = os.path.join('/srv/uploads', name)\n"
        "    item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" not in path["facts"].get("security_precondition", {})


@pytest.mark.parametrize(
    "mutation",
    [
        "item.filename = 'safe.csv'",
        "other = item\nother.filename = 'safe.csv'",
        "other = item\nsetattr(other, 'filename', 'safe.csv')",
        "item.filename = secure_filename(item.filename)",
        "setattr(item, 'filename', 'safe.csv')",
        "item.__dict__['filename'] = 'safe.csv'",
    ],
)
def test_flask_file_storage_filename_mutation_does_not_keep_raw_effect_witness(
    mutation,
):
    source = (
        "from flask import request\nfrom werkzeug.utils import secure_filename\n"
        "import os\ndef upload():\n"
        "    item = request.files['file']\n    "
        + mutation.replace("\n", "\n    ")
        + "\n    destination = os.path.join('/srv/uploads', item.filename)\n"
        "    item.save(destination)\n"
    )
    path = next(
        row
        for row in _premise_scan(source)
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" not in path["facts"].get("security_precondition", {})


def test_flask_file_storage_incompatible_conditional_destination_has_no_witness():
    findings = _premise_scan(
        "from flask import request\nimport os\ndef upload(flag):\n"
        "    item = request.files['file']\n"
        "    if flag:\n"
        "        destination = os.path.join('/srv/uploads', item.filename)\n"
        "    if not flag:\n"
        "        item.save(destination)\n"
    )
    path = next(
        row
        for row in findings
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" not in path["facts"].get("security_precondition", {})


@pytest.mark.parametrize("before_read", [True, False])
def test_flask_file_storage_same_line_field_write_respects_filename_read(before_read):
    statements = (
        "item.filename = 'safe.csv'; destination = os.path.join('/srv/uploads', item.filename); item.save(destination)"
        if before_read
        else "destination = os.path.join('/srv/uploads', item.filename); item.filename = 'safe.csv'; item.save(destination)"
    )
    path = next(
        row
        for row in _premise_scan(
            "from flask import request\nimport os\ndef upload():\n"
            "    item = request.files['file']\n"
            "    " + statements + "\n"
        )
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert (
        "effect_witness" in path["facts"].get("security_precondition", {})
    ) is not before_read


def test_flask_file_storage_unsafe_or_filename_guard_keeps_escape_witness():
    path = next(
        row
        for row in _premise_scan(
            "from flask import request\nimport os\ndef upload(flag):\n"
            "    item = request.files['file']\n"
            "    name = item.filename\n"
            "    if name in {'safe.csv'} or flag:\n"
            "        destination = os.path.join('/srv/uploads', name)\n"
            "        item.save(destination)\n"
        )
        if row["code"] == "SECURITY_PATH_TRAVERSAL"
        and row["facts"].get("call") == "flask.FileStorage.save"
    )
    assert "effect_witness" in path["facts"]["security_precondition"]


@pytest.mark.parametrize(
    "url, expected_transport",
    [
        ("'https://example.test/data'", "static_https"),
        ("url", None),
        ("'https://' + host", "https_capable"),
        ("f'https://{host}/data'", "https_capable"),
        ("'http://example.test/data'", None),
        ("'http://' + host", None),
    ],
)
def test_tls_peer_authentication_effect_requires_https_capability(
    url, expected_transport
):
    findings = _premise_scan(
        f"import requests\ndef fetch(url, host):\n    requests.get({url}, verify=False)\n"
    )
    finding = next(
        row for row in findings if row["code"] == "SECURITY_TLS_VERIFY_DISABLED"
    )
    witness = finding["facts"].get("security_precondition", {}).get("effect_witness")
    if expected_transport is None:
        assert witness is None
    else:
        assert witness["effect_kind"] == "tls_peer_authentication_bypass"
        assert witness["source_role"] == "tls_verification_configuration"
        assert witness["consumer_role"] == "known_tls_client_request"
        assert witness["effect_facts"]["verification_setting"] == "literal_false"
        assert witness["effect_facts"]["transport_relation"] == expected_transport
        assert len(witness["effect_facts"]["https_operation_span"]) == 4


def test_log_effect_requires_request_crlf_capability_not_line_input(tmp_path):
    request_rows = _captured_log_scan(
        tmp_path / "request",
        "import logging\nfrom flask import request\ndef record():\n"
        "    value = request.args.get('name', '')\n"
        "    logging.warning('page=%s', value)\n",
        _PLAIN_DJANGO_LOGGING,
    )
    request_log = next(
        row for row in request_rows if row["code"] == "SECURITY_LOG_INJECTION"
    )
    request_witness = request_log["facts"]["security_precondition"]["effect_witness"]
    assert request_witness["source_role"] == "newline_capable_untrusted_text"
    assert request_witness["consumer_role"] == "line_delimited_log"
    assert request_witness["effect_kind"] == "log_record_boundary_injection"
    facts = request_witness["effect_facts"]
    assert facts["provider_id"] == "logging.warning"
    assert facts["newline_capability"] == "CR_LF"
    assert facts["neutralization"] == "none"
    assert facts["consumer_format"] == "%(message)s"
    assert facts["consumer_config_path"] == "project/settings.py"
    assert len(facts["consumer_config_sha256"]) == 64
    assert facts["consumer_handler_id"] == "logging.StreamHandler"
    assert facts["consumer_logger_id"] == "root"
    assert facts["consumer_call_level"] == "warning"
    assert facts["consumer_effective_level"] == "WARNING"
    assert facts["activation_path"] == "manage.py"

    input_rows = _captured_log_scan(
        tmp_path / "input",
        "import logging\ndef record():\n"
        "    value = input()\n"
        "    logging.warning(value)\n",
        _PLAIN_DJANGO_LOGGING,
    )
    input_log = next(
        row for row in input_rows if row["code"] == "SECURITY_LOG_INJECTION"
    )
    assert "security_precondition" not in input_log["facts"]


@pytest.mark.parametrize(
    "sink_value",
    ["value", "message"],
)
def test_log_effect_preserves_single_request_trace_through_aliases(
    tmp_path, sink_value
):
    suffix = "    message = 'page=' + str(value)\n" if sink_value == "message" else ""
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record():\n    value = request.args.get('name', '')\n"
        + suffix
        + f"    logging.warning({sink_value})\n",
        _PLAIN_DJANGO_LOGGING,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    flow = finding["facts"]["security_precondition"]["input_value_flow"]
    operations = [step["operation"] for step in flow["steps"]]
    assert operations[0] == "REQUEST_SOURCE"
    assert "LOCAL_ASSIGN" in operations
    assert operations[-1] == "LOG_ARGUMENT"


def test_log_effect_does_not_join_ambiguous_or_input_sources(tmp_path):
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record(flag):\n"
        "    if flag:\n        value = request.args.get('name', '')\n"
        "    else:\n        value = request.form.get('name', '')\n"
        "    logging.warning(value)\n",
        _PLAIN_DJANGO_LOGGING,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    assert "security_precondition" not in finding["facts"]


def test_log_effect_keeps_newline_sanitizers_out_of_typed_evidence(tmp_path):
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record():\n"
        "    value = request.args.get('name', '').replace('\\r', '').replace('\\n', '')\n"
        "    logging.warning(value)\n",
        _PLAIN_DJANGO_LOGGING,
    )
    assert not any(
        row.get("facts", {}).get("security_precondition")
        for row in rows
        if row["code"] == "SECURITY_LOG_INJECTION"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "logger.level = 100\n",
        "other = logger\nother.level = 100\n",
        "logger.manager.disable = 100\n",
    ],
)
def test_log_effect_rejects_direct_selected_logger_state_mutation(tmp_path, mutation):
    source = (
        "import logging\nfrom flask import request\n"
        "logger = logging.getLogger('billing')\n"
        + mutation
        + "def record():\n    logger.warning(request.args.get('x'))\n"
    )
    settings = _PLAIN_DJANGO_LOGGING.replace(
        " 'root': {'handlers': ['console'], 'level': 'WARNING'},\n",
        " 'loggers': {'billing': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False}},\n",
    )
    rows = _captured_log_scan(tmp_path, source, settings)
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    assert "security_precondition" not in finding["facts"]


@pytest.mark.parametrize(
    "settings, startup, app_source, expect_witness",
    [
        (
            _PLAIN_DJANGO_LOGGING.replace(
                "LOGGING =", "LOGGING_CONFIG = None\nLOGGING ="
            ),
            True,
            "import logging\nfrom flask import request\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            False,
            "import logging\nfrom flask import request\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            True,
            "import logging\nfrom flask import request\nlogger = logging.getLogger('billing')\ndef run():\n    logger.warning(request.args.get('x'))\n",
            True,
        ),
        (
            _PLAIN_DJANGO_LOGGING.replace(
                " 'root': {'handlers': ['console'], 'level': 'WARNING'},\n",
                " 'loggers': {'billing': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False}},\n",
            ),
            True,
            "import logging\nfrom flask import request\nlogger = logging.getLogger('billing')\ndef run():\n    logger.warning(request.args.get('x'))\n",
            True,
        ),
        (
            _PLAIN_DJANGO_LOGGING.replace("%(levelname)s %(message)s", "%%(message)s"),
            True,
            "import logging\nfrom flask import request\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING.replace(
                "'formatter': 'plain', 'level': 'WARNING'",
                "'formatter': 'plain', 'level': 'WARNING', 'filters': ['redact']",
            ),
            True,
            "import logging\nfrom flask import request\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING.replace(
                "'%(levelname)s %(message)s'", "'%(message)r'"
            ),
            True,
            "import logging\nfrom flask import request\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            True,
            "import logging\nfrom flask import request\nif False:\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            True,
            "import logging\nfrom flask import request\nlogging.disable(logging.CRITICAL)\ndef run():\n    logging.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            True,
            "import logging\nfrom flask import request\nlogger = logging.getLogger('billing')\nlogger.disabled = True\ndef run():\n    logger.warning(request.args.get('x'))\n",
            False,
        ),
        (
            _PLAIN_DJANGO_LOGGING,
            True,
            "import logging\nfrom flask import request\ndef run():\n    logging.Logger.warning(logging.getLogger(), request.args.get('x'))\n",
            False,
        ),
    ],
)
def test_log_effect_requires_selected_unfiltered_standard_route(
    tmp_path, settings, startup, app_source, expect_witness
):
    rows = _captured_log_scan(
        tmp_path,
        app_source,
        settings,
        startup=startup,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    witness = finding["facts"].get("security_precondition", {}).get("effect_witness")
    assert bool(witness) is expect_witness
    if expect_witness and "logger = logging.getLogger('billing')" in app_source:
        assert witness["effect_facts"]["consumer_logger_id"] == "billing"


@pytest.mark.parametrize(
    "filter_class",
    [
        "django.utils.log.RequireDebugTrue",
        "django.utils.log.RequireDebugFalse",
    ],
)
def test_log_effect_allows_standard_django_gate_before_plain_sibling(
    tmp_path, filter_class
):
    settings = _PLAIN_DJANGO_LOGGING.replace(
        " 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
        " 'filters': {'gate': {'()': '" + filter_class + "'}},\n"
        " 'handlers': {"
        "'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING', 'filters': ['gate']}, "
        "'file': {'class': 'logging.FileHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
    ).replace("'handlers': ['console']", "'handlers': ['console', 'file']")
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record():\n    logging.warning(request.args.get('x'))\n",
        settings,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    witness = finding["facts"]["security_precondition"]["effect_witness"]
    assert witness["effect_facts"]["consumer_handler_key"] == "file"


def test_log_effect_keeps_unknown_mutating_filter_before_plain_sibling_unresolved(
    tmp_path,
):
    settings = _PLAIN_DJANGO_LOGGING.replace(
        " 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
        " 'filters': {'mask': {'()': 'custom.MutatingFilter'}},\n"
        " 'handlers': {"
        "'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING', 'filters': ['mask']}, "
        "'file': {'class': 'logging.FileHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
    ).replace("'handlers': ['console']", "'handlers': ['console', 'file']")
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record():\n    logging.warning(request.args.get('x'))\n",
        settings,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    assert "security_precondition" not in finding["facts"]


def test_log_effect_accepted_before_later_unknown_handler(tmp_path):
    settings = _PLAIN_DJANGO_LOGGING.replace(
        " 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
        " 'handlers': {"
        "'file': {'class': 'logging.FileHandler', 'formatter': 'plain', 'level': 'WARNING'}, "
        "'custom': {'class': 'custom.MutatingHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
    ).replace("'handlers': ['console']", "'handlers': ['file', 'custom']")
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nfrom flask import request\n"
        "def record():\n    logging.warning(request.args.get('x'))\n",
        settings,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    witness = finding["facts"]["security_precondition"]["effect_witness"]
    assert witness["effect_facts"]["consumer_handler_key"] == "file"


def test_log_effect_rejects_mutated_standard_django_filter_identity(tmp_path):
    settings = _PLAIN_DJANGO_LOGGING.replace(
        " 'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
        " 'filters': {'gate': {'()': 'django.utils.log.RequireDebugTrue'}},\n"
        " 'handlers': {"
        "'console': {'class': 'logging.StreamHandler', 'formatter': 'plain', 'level': 'WARNING', 'filters': ['gate']}, "
        "'file': {'class': 'logging.FileHandler', 'formatter': 'plain', 'level': 'WARNING'}},\n",
    ).replace("'handlers': ['console']", "'handlers': ['console', 'file']")
    rows = _captured_log_scan(
        tmp_path,
        "import logging\nimport django.utils.log as django_log\n"
        "from flask import request\n"
        "django_log.RequireDebugTrue = replacement\n"
        "def record():\n    logging.warning(request.args.get('x'))\n",
        settings,
    )
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    assert "security_precondition" not in finding["facts"]


def test_log_effect_direct_dictconfig_has_source_bound_config_without_startup(tmp_path):
    config = _PLAIN_DJANGO_LOGGING.removeprefix("LOGGING =")
    source = (
        "import logging.config\n"
        "from flask import request\n"
        "logging.config.dictConfig(" + config.rstrip() + ")\n"
        "def record():\n"
        "    logging.warning(request.args.get('name'))\n"
    )
    rows = _captured_log_scan(tmp_path, source, startup=False)
    finding = next(row for row in rows if row["code"] == "SECURITY_LOG_INJECTION")
    witness = finding["facts"]["security_precondition"]["effect_witness"]
    facts = witness["effect_facts"]
    assert facts["consumer_config_path"] == "app.py"
    assert facts["activation_path"] is None
    assert facts["activation_sha256"] is None
    assert facts["activation_span"] is None
