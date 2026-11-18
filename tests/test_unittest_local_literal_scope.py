"""Local literal routing uses closed unittest consumers, never fixture spelling."""

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from textwrap import dedent

import pytest

from factoryline import credential_role_identity_effects as effects
from factoryline import credential_role_method_use_getter_audit as scope
from factoryline.cli import _build_parser
from factoryline.cli_audit import prepare_bounded_security_report
from factoryline.mock_fixture_provenance import application_test_index


@pytest.mark.parametrize(
    "variant",
    ["rejected", "may-return", "unmodeled-effect", "eager-default", "descriptor"],
)
def test_native_scan_filters_only_configuration_rejected_before_authority(
    tmp_path, variant
):
    from factoryline.cli import _build_parser
    from factoryline.cli_audit import prepare_bounded_security_report

    expression = "app.config.get('SECRET_KEY', '')"
    if variant == "eager-default":
        expression = "app.config.get('SECRET_KEY', unknown_default())"
    prefix = "    inspect_receiver(app)\n" if variant == "unmodeled-effect" else ""
    comparison = "not in" if variant == "may-return" else "in"
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "def validate(app):\n"
        f"{prefix}"
        f"    setting = {expression}\n"
        f"    if setting.strip().lower() {comparison} {{'local-test-key'}}:\n"
        "        raise RuntimeError('invalid configuration')\n"
        "def make_app(configuration):\n"
        "    app = Flask(__name__)\n"
        "    app.config.from_object(configuration)\n"
        "    validate(app)\n"
        "    return app\n",
        encoding="utf-8",
    )
    descriptor = (
        "        @property\n        def OTHER(self):\n            return ignored()\n"
        if variant == "descriptor"
        else ""
    )
    (tmp_path / "test_app.py").write_text(
        "import pytest\n"
        "from app import make_app\n"
        "def test_rejected_configuration():\n"
        "    class Configuration:\n"
        "        SECRET_KEY = 'LOCAL-TEST-KEY'\n"
        f"{descriptor}"
        "    with pytest.raises(RuntimeError):\n"
        "        make_app(Configuration)\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "standalone.py").write_text(
        "OPERATIVE_PASSWORD = 'unrelated-control'\n", encoding="utf-8"
    )
    workflow = tmp_path / ".github/workflows/tests.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: tests\non: [push]\njobs:\n  tests:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: python -m pytest\n",
        encoding="utf-8",
    )
    args = _build_parser().parse_args(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    report = prepare_bounded_security_report(args)
    paths = [
        entry["raw_finding"]["path"]
        for entry in report["finding_tier_report"]["ledger"]
    ]
    assert paths == (
        ["standalone.py"] if variant == "rejected" else ["standalone.py", "test_app.py"]
    )
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["audit_coverage"]["complete"] is True


def _observe_literal_proof(monkeypatch, helper, literal_name):
    from factoryline import captured_security_audit

    original = getattr(captured_security_audit, helper)
    observed = []

    def observe(node, target, *args):
        proven = original(node, target, *args)
        if getattr(target, "id", None) == literal_name:
            observed.append(proven)
        return proven

    monkeypatch.setattr(captured_security_audit, helper, observe)
    return observed


@pytest.mark.parametrize(
    "variant",
    [
        "presentation",
        "mixed",
        "rebound",
        "caught",
        "caller-caught",
        "generator",
        "unknown-context",
        "finally-read",
    ],
)
def test_exit_message_needs_closed_diagnostic_consumer(tmp_path, variant):
    from factoryline.review_audits import security_scan

    extra = "    authenticate(PASSWORD_MESSAGE)\n" if variant == "mixed" else ""
    body = "    sys.exit(PASSWORD_MESSAGE)\n"
    if variant == "caught":
        body = "    try:\n        sys.exit(PASSWORD_MESSAGE)\n    except SystemExit as error:\n        authenticate(error.code)\n"
    invocation = "report()\n"
    if variant == "generator":
        body = "    yield None\n" + body
        invocation = "stream = report()\ntry:\n    list(stream)\nexcept SystemExit as error:\n    authenticate(error.code)\n"
    if variant == "unknown-context":
        body = "    with arbitrary_context():\n        sys.exit(PASSWORD_MESSAGE)\n"
    if variant == "finally-read":
        body = "    try:\n        sys.exit(PASSWORD_MESSAGE)\n    finally:\n        inspect_exception()\n"
    if variant == "caller-caught":
        invocation = "try:\n    report()\nexcept SystemExit as error:\n    authenticate(error.code)\n"
    source = (
        "import sys\nPASSWORD_MESSAGE = 'Server rejected the configured password.'\n"
        + ("sys.exit = arbitrary\n" if variant == "rebound" else "")
        + "def report():\n"
        + extra
        + body
        + invocation
    )
    (tmp_path / "app.py").write_text(source, encoding="utf8")
    report = security_scan(
        tmp_path,
        security_only=True,
        defect_policy="source-role-v3",
        cache_enabled=False,
    )
    raw = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    refuted = report.get("refuted_security_observations", [])
    assert (
        sum(row["code"] == "SECURITY_HARDCODED_SECRET" for row in raw),
        sum(row["code"] == "SECURITY_HARDCODED_SECRET" for row in refuted),
    ) == ((0, 1) if variant == "presentation" else (1, 0))


@pytest.mark.parametrize("extra", ["", "    enroll(SECRET_ENV)\n"])
def test_captured_public_registry_label_requires_closed_uses(
    tmp_path, monkeypatch, extra
):
    from factoryline.review_audits import security_scan

    observed = _observe_literal_proof(
        monkeypatch, "captured_public_registry_label", "SECRET_ENV"
    )
    (tmp_path / "app.py").write_text(
        "import os\nSECRET_ENV = 'SERVICE_SIGNING_KEY'\n"
        "def read():\n"
        "    value = os.getenv(SECRET_ENV)\n"
        + extra
        + "    if value is None:\n        raise RuntimeError(f'Missing {SECRET_ENV}')\n"
        "    return value\n",
        encoding="utf-8",
    )
    report = security_scan(
        tmp_path,
        cache_enabled=False,
        security_only=True,
        defect_policy="source-role-v3",
    )
    raw = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    assert (not extra) in observed
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in raw) is bool(extra)
    assert report["finding_conservation"]["state"] == "PASS"


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "legacy_policy",
        "credential_value",
        "request_escape",
        "response_escape",
        "provider_rebound",
        "provider_alias_rebound",
        "callback_called_from_source",
        "definition_time_use",
        "class_scope_use",
        "reflective_reference",
        "starlette_shadow",
    ],
)
def test_cookie_names_require_captured_http_receivers(tmp_path, variant):
    from factoryline.review_audits import security_scan

    before_cookie_read = (
        "    inspect_request(request)\n" if variant == "request_escape" else ""
    )
    if variant == "class_scope_use":
        before_cookie_read = (
            "    class Definition:\n"
            "        observed = request.cookies.get(API_KEY_NAME)\n"
        )
    before_cookie_write = (
        "    inspect_response(response)\n" if variant == "response_escape" else ""
    )
    credential = "API_KEY_NAME" if variant == "credential_value" else "token"
    provider_rebind = (
        "RedirectResponse = external_response\n"
        if variant == "provider_rebound"
        else ""
    )
    if variant == "provider_alias_rebound":
        provider_rebind = (
            "from fastapi.applications import FastAPI as Implementation\n"
            "Implementation.middleware = external_registration\n"
        )
    annotation = (
        " -> request.cookies.get(API_KEY_NAME)"
        if variant == "definition_time_use"
        else ""
    )
    external_request = (
        "request = external_request\n" if variant == "definition_time_use" else ""
    )
    callback_call = (
        "\nasync def custom_caller(value, consumer):\n"
        "    return await check(value, consumer)\n"
        if variant == "callback_called_from_source"
        else ""
    )
    reflection = (
        "\nread_key(globals()['API_KEY_NAME'])\n"
        if variant == "reflective_reference"
        else ""
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "from fastapi.responses import RedirectResponse\n"
        "from fastapi.security import APIKeyHeader\n"
        + provider_rebind
        + external_request
        + "API_KEY_NAME = 'X-App-Token'\n"
        "app = FastAPI()\n"
        "header = APIKeyHeader(name=API_KEY_NAME)\n"
        "@app.middleware('http')\n"
        f"async def check(request: Request, call_next){annotation}:\n"
        + before_cookie_read
        + "    observed = request.cookies.get(API_KEY_NAME)\n"
        "    if observed:\n"
        "        return await call_next(request)\n"
        "    return RedirectResponse('/login')\n"
        "@app.post('/session')\n"
        "async def session(token):\n"
        "    response = RedirectResponse('/')\n"
        + before_cookie_write
        + f"    response.set_cookie(key=API_KEY_NAME, value={credential})\n"
        "    return response\n"
        "@app.post('/logout')\n"
        "async def logout():\n"
        "    response = RedirectResponse('/')\n"
        "    response.delete_cookie(API_KEY_NAME)\n"
        "    return response\n" + callback_call + reflection,
        encoding="utf8",
    )
    if variant == "starlette_shadow":
        (tmp_path / "starlette.py").write_text("local = True\n", encoding="utf8")
    report = security_scan(
        tmp_path,
        cache_enabled=False,
        security_only=True,
        defect_policy="source-role-v2"
        if variant == "legacy_policy"
        else "source-role-v3",
    )
    raw = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    findings = [row for row in raw if row["code"] == "SECURITY_HARDCODED_SECRET"]
    assert [row["facts"]["name"] for row in findings] == (
        [] if variant == "closed" else ["API_KEY_NAME"]
    )
    assert report["audit_coverage"]["complete"] is True
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["finding_conservation"]["native_rows"] == "VERIFIED"
    refuted = report.get("refuted_security_observations", [])
    if variant == "closed":
        (row,) = refuted
        trace = row["facts"]["cookie_name_use_trace"]
        assert [(step["operation"], step["operand"]) for step in trace] == [
            ("fastapi.security.APIKeyHeader", "name"),
            ("get", 0),
            ("set_cookie", "key"),
            ("delete_cookie", 0),
        ]
        assert all(
            step["source_sha256"] == report["sources"][0]["sha256"] for step in trace
        )
    else:
        assert not refuted


@pytest.mark.parametrize("directory", ["service", "../outside"])
def test_capture_launch_configuration_binds_only_contained_build_files(
    tmp_path, directory
):
    from factoryline.captured_security_audit import capture_launch_configuration

    data = f"services:\n  app:\n    build:\n      context: {directory}\n      dockerfile: Dockerfile.custom\n".encode()
    sources = {"compose.yaml": data}

    def read_source(_root, name):
        if name == "docker-compose.yml":
            raise ValueError("unreadable selector")
        if name not in sources:
            raise FileNotFoundError(name)
        return sources[name]

    paths, read = capture_launch_configuration(
        tmp_path, read_source, 65_536, {"startup.py"}
    )
    builds = {
        "service/Dockerfile.custom",
        "service/.dockerignore",
        "service/Dockerfile.custom.dockerignore",
    }
    baseline = {"startup.py", "compose.yaml", "docker-compose.yml"}
    assert paths == (baseline | builds if directory == "service" else baseline)
    sources["compose.yaml"] = b"changed after capture"
    assert read(tmp_path, "compose.yaml") == data


@pytest.mark.parametrize("method", ["get", "post"])
def test_captured_test_derived_input_requires_exact_patch_boundary(
    tmp_path, monkeypatch, method
):
    from factoryline.review_audits import security_scan

    observed = _observe_literal_proof(
        monkeypatch, "captured_test_derived_input", "secret"
    )
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "checker.py").write_text(
        "import hashlib\nimport requests\nBASE = 'https://example.invalid/check/'\n"
        "def digest(value):\n    return hashlib.sha256(value.encode('utf-8')).hexdigest()\n"
        "def lookup(value):\n    hashed = digest(value)\n    front, tail = hashed[:4], hashed[4:]\n"
        "    reply = requests.get(BASE + front)\n    if reply.text == tail:\n        return 1\n    return 0\n",
        encoding="utf-8",
    )
    (tmp_path / "test_checker.py").write_text(
        "from unittest.mock import patch\nimport checker\ndef test_input():\n"
        "    secret = 'fixed-catalog-test-data'\n"
        f"    with patch.object(checker.requests, '{method}', return_value=None) as recorded:\n"
        "        checker.lookup(secret)\n    emitted = recorded.call_args.args[0]\n"
        "    assert secret not in emitted\n    assert checker.digest(secret)[:4] == emitted[-4:]\n",
        encoding="utf-8",
    )
    report = security_scan(
        tmp_path,
        cache_enabled=False,
        security_only=True,
        defect_policy="source-role-v3",
    )
    raw = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    assert (method == "get") in observed
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in raw) is (
        method == "post"
    )
    assert report["finding_conservation"]["state"] == "PASS"


@pytest.mark.parametrize("stable", [True, False])
def test_captured_builtin_copy_preserves_proven_values_only(stable):
    from types import SimpleNamespace

    from factoryline.captured_security_audit import captured_builtin_copy
    from factoryline.credential_role_identity_effects import _Value

    call = ast.parse("clone(data)", mode="eval").body
    witnessed = []
    scope = SimpleNamespace(
        canonical=lambda *_: "builtins.list",
        index={},
        audit=SimpleNamespace(
            _app_signing_terminal_stable=lambda _index, name: stable
            and name == "builtins.list"
        ),
        witness=lambda *args: witnessed.append(args),
    )
    flow = SimpleNamespace(
        allocate_container=lambda _path, _call, kind, items: _Value(
            inert_kind=kind, items=items, container_id="clone"
        )
    )
    original = _Value(
        inert_kind="tuple", container_id="source", roots=frozenset({"source-root"})
    )
    copied = captured_builtin_copy(scope, flow, "test_copy.py", call, [original], {})
    if stable:
        assert copied.inert_kind == "list" and copied.container_id == "clone"
        assert copied.roots == original.roots and witnessed
    else:
        assert copied is None and not witnessed


def captured_scope(tmp_path, source, filename="test_scope.py"):
    path = tmp_path / filename
    raw = source.encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = application_test_index(
        tmp_path,
        {path: tree},
        {path: raw},
        {path: digest},
        {"pytest.ini": b"[pytest]\n"},
    )
    assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )
    return index, path, assignment


def test_proof_inventory_binds_exact_scanner_consumers():
    from factoryline import audit_log_flow, captured_operand_audit, pickle_model_audit
    from factoryline.captured_security_audit import argument_role_proof_helpers
    from factoryline.django_class_fixture_audit import (
        application_class_account_evidence,
        class_fixture_helpers,
    )
    from factoryline.xonsh_program_audit import (
        stage_xonsh_program_refutation,
        xonsh_program_role_helpers,
    )

    argument_helpers = argument_role_proof_helpers()
    program_helpers = xonsh_program_role_helpers()
    assert audit_log_flow.captured_log_field_text_closed in argument_helpers
    assert captured_operand_audit.cookie_name_trace in argument_helpers
    assert captured_operand_audit.captured_command_operand_proof in argument_helpers
    assert (
        captured_operand_audit.captured_local_representation_proof in argument_helpers
    )
    assert pickle_model_audit.captured_local_serialization_proof in argument_helpers
    assert all(
        helper in argument_helpers
        for helpers in (
            captured_operand_audit.command_operand_proof_helpers(),
            captured_operand_audit.captured_local_representation_helpers(),
        )
        for helper in helpers
    )
    assert stage_xonsh_program_refutation in program_helpers
    assert all(helper in argument_helpers for helper in program_helpers)
    assert application_class_account_evidence in class_fixture_helpers()


def test_operand_refutation_rechecks_warm_source_snapshot(tmp_path):
    from factoryline.audit_action_refs import _bound_operand_refutation
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    raw = b"value = 1\n"
    digest = hashlib.sha256(raw).hexdigest()
    primary, peer = tmp_path / "primary.py", tmp_path / "peer.py"
    trees = {path: ast.parse(raw) for path in (primary, peer)}
    for tree in trees.values():
        tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path, trees, dict.fromkeys(trees, raw), dict.fromkeys(trees, digest)
    )
    point = ("DEVELOPMENT_RULE", "primary.py", 1, 0, 1, 9, "HIGH")

    def propose(_source, _path, _node):
        return {"hypothesis": "CLOSED_OPERAND"}

    node = trees[primary].body[0]
    assert _bound_operand_refutation(index, primary, node, point, propose)
    assert index.validate(peer)
    trees[peer].body[0].value.value = 2
    assert index.validate(peer)
    assert _bound_operand_refutation(index, primary, node, point, propose) is None


def test_representation_policy_changes_native_cache_key(tmp_path, monkeypatch):
    from factoryline import captured_operand_audit
    from factoryline.review_audits import _oracle_context_cache_key

    before = _oracle_context_cache_key(tmp_path, [], {}, captured=True)
    monkeypatch.setattr(captured_operand_audit, "_REPRESENTATION_METHODS", frozenset())
    assert _oracle_context_cache_key(tmp_path, [], {}, captured=True) != before


@pytest.mark.parametrize(
    "binding", ["_declaration_bindings", "_exact_source_call", "canonical_bytes"]
)
def test_program_proof_cache_changes_with_actual_import_binding(
    tmp_path, monkeypatch, binding
):
    from factoryline import xonsh_program_audit
    from factoryline.review_audits import _oracle_context_cache_key

    original = _oracle_context_cache_key(tmp_path, [], {})
    monkeypatch.setattr(xonsh_program_audit, binding, lambda *_args: None)
    first = _oracle_context_cache_key(tmp_path, [], {})
    monkeypatch.setattr(xonsh_program_audit, binding, lambda *_args: ())
    second = _oracle_context_cache_key(tmp_path, [], {})
    assert len({original, first, second}) == 3


def evidence(tmp_path, source, filename="test_scope.py"):
    index, path, assignment = captured_scope(tmp_path, source, filename)
    return scope._source_test_scope_evidence(index, path, assignment, "SECRET")


def unittest_source(body, extra="", method="test_value"):
    return (
        "from unittest import TestCase\n"
        "class Checks(TestCase):\n"
        f"    def {method}(self):\n"
        + "".join("        " + line + "\n" for line in body.splitlines())
        + extra
    )


@pytest.mark.parametrize("literal", ["fixture-marker-4791", "ordinary-value-9417"])
def test_closed_unittest_local_literal_has_source_scope_only(tmp_path, literal):
    result = evidence(
        tmp_path,
        unittest_source(f"SECRET = {literal!r}\nassert SECRET == SECRET"),
    )
    assert result is not None
    assert result["profile"] == "SOURCE_BOUND_TEST_SCOPE_ONLY"
    assert result["runtime_assurance"] == "INCOMPLETE"
    assert result["isolation_assurance"] == "UNASSESSED"
    assert result["target_execution"] == "not_performed"
    assert any(
        row["role"] == "declared_test_invocation" for row in result["witness_sources"]
    )


@pytest.mark.parametrize(
    ("body", "supported"),
    [
        ("observed = [SECRET] or external(SECRET)\nassert observed[0] == SECRET", True),
        ("observed = [] or [SECRET]\nassert observed[0] == SECRET", True),
        ("observed = [] and external(SECRET)\nassert SECRET == SECRET", True),
        ("observed = [] or external(SECRET)", False),
        ("observed = [unknown] or [SECRET]", False),
        (
            "if [SECRET]:\n    assert SECRET == SECRET\nelse:\n    external(SECRET)",
            True,
        ),
    ],
)
def test_fixture_identity_scope_short_circuits_exact_builtin_containers(
    tmp_path, body, supported
):
    result = evidence(
        tmp_path, unittest_source("SECRET = 'ordinary-value-9417'\n" + body)
    )
    assert (result is not None) is supported


@pytest.mark.parametrize(
    ("body", "supported"),
    [
        ("copy = list((SECRET,))\nassert copy[0] == SECRET", True),
        ("copy = tuple([SECRET])\nassert copy[0] == SECRET", True),
        ("copy = dict({'key': SECRET})\nassert copy['key'] == SECRET", True),
        ("copy = list() or [SECRET]\nassert copy[0] == SECRET", True),
        ("copy = list(external(SECRET))", False),
        ("copy = list({'key': SECRET})", False),
        ("copy = list(iterable=[SECRET])", False),
        ("list = external\ncopy = list([SECRET])", False),
    ],
)
def test_fixture_scope_copies_only_bound_exact_builtin_shapes(
    tmp_path, body, supported
):
    result = evidence(
        tmp_path, unittest_source("SECRET = 'ordinary-value-9417'\n" + body)
    )
    assert (result is not None) is supported


def test_captured_dict_copy_does_not_share_mutations(tmp_path):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\n"
        "original = {}\n"
        "cloned = dict(original)\n"
        "cloned['key'] = SECRET\n"
        "if original:\n"
        "    external(SECRET)\n"
        "assert cloned['key'] == SECRET"
    )
    assert evidence(tmp_path, source) is not None


def test_unknown_dictionary_shape_is_not_treated_as_empty():
    projected = effects._Value(roots=frozenset({"credential"}), inert_kind="dict")
    assert effects._validated_exact_scalar(projected, as_truth=True) == ()


@pytest.mark.parametrize("custom", ["run", "__getattribute__", "setUpClass"])
def test_custom_unittest_owner_cannot_obtain_local_scope_proof(tmp_path, custom):
    source = unittest_source(
        "SECRET = 'fixture-marker-4791'\nassert SECRET == SECRET",
        f"    def {custom}(self):\n        pass\n",
    )
    assert evidence(tmp_path, source) is None


@pytest.mark.parametrize("method", ["setUp", "test_value"])
def test_local_value_flows_through_setup_helper_and_teardown(tmp_path, method):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nself.value = self.echo(SECRET)",
        "    def echo(self, value):\n        return value\n"
        "    def tearDown(self):\n        self.value = None\n",
        method,
    )
    if method == "setUp":
        source += "    def test_value(self):\n        assert self.value == self.value\n"
    assert evidence(tmp_path, source) is not None


@pytest.mark.parametrize("filename", ["test_fixture.py", "consumer.py"])
@pytest.mark.parametrize(
    "suffix",
    [
        "        send(SECRET)\n",
        "    def tearDown(self):\n        send(self.value)\n",
    ],
)
def test_fixture_names_and_owner_do_not_close_unknown_consumers(
    tmp_path, filename, suffix
):
    source = unittest_source("SECRET = 'fixture-marker-4791'\nself.value = SECRET")
    assert evidence(tmp_path, source + suffix, filename) is None


@pytest.mark.parametrize(
    "body",
    [
        "SECRET = 'fixture-marker-4791'\nSECRET = supplied\nself.assertTrue(SECRET)",
        "SECRET = other = 'fixture-marker-4791'\nself.assertTrue(SECRET)",
        "if flag:\n    SECRET = 'fixture-marker-4791'\nself.assertTrue(SECRET)",
    ],
)
def test_unittest_route_retains_direct_single_binding_requirement(tmp_path, body):
    assert evidence(tmp_path, unittest_source(body)) is None


@pytest.mark.parametrize("method", ["helper", "setUpClass"])
def test_non_invocation_method_does_not_gain_owner_scope(tmp_path, method):
    source = unittest_source(
        "SECRET = 'fixture-marker-4791'\nassert SECRET == SECRET",
        "    def test_value(self):\n        pass\n",
        method,
    )
    assert evidence(tmp_path, source) is None


def test_existing_pytest_local_literal_route_is_preserved(tmp_path):
    source = (
        "def test_value():\n"
        "    SECRET = 'ordinary-value-9417'\n"
        "    assert SECRET == SECRET\n"
    )
    assert evidence(tmp_path, source) is not None


@pytest.mark.parametrize(
    "extra",
    [
        "    def setUp(self):\n        install_provider()\n",
        "    def tearDown(self):\n        install_provider()\n",
        "    def test_other(self):\n        install_provider()\n",
    ],
)
def test_all_owner_invocations_must_close(tmp_path, extra):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET", extra
    )
    assert evidence(tmp_path, source) is None


def test_existing_raw_unittest_assertion_contract_is_preserved(tmp_path):
    source = unittest_source(
        "SECRET = 'ordinary-value-9417'\nself.assertEqual(SECRET, SECRET)"
    )
    assert evidence(tmp_path, source) is None


def test_stale_captured_declaration_cannot_gain_scope_proof(tmp_path):
    source = unittest_source("SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET")
    index, path, assignment = captured_scope(tmp_path, source)
    index["source"].source_bytes[path] += b"\nmutate()\n"
    assert scope._source_test_scope_evidence(index, path, assignment, "SECRET") is None


def test_local_route_identity_tracks_actual_exercise_method(monkeypatch):
    original = scope._SourceTestScope.exercise
    before = effects.security_value_helper_epoch()
    assert original in before

    def replacement(self):
        return False

    monkeypatch.setattr(scope._SourceTestScope, "exercise", replacement)
    after = effects.security_value_helper_epoch()
    assert replacement in after and original not in after


def configured_authority_scope(tmp_path, configuration, extra=None):
    configuration = {
        "requirements.txt": b"pytest-django>=4.5,<5\n",
        **configuration,
    }
    sources = {
        "support/__init__.py": "",
        "support/configuration.py": "SECRET_KEY = 'local-signing-material-847263'\n",
        "checks/__init__.py": "",
        "checks/test_feature.py": "def test_feature():\n    assert True\n",
        **(extra or {}),
    }
    modules, raw_sources, inventory = {}, {}, {}
    for relative, text in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = text.encode()
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = digest
        modules[path], raw_sources[path], inventory[path] = tree, raw, digest
    for name, raw in configuration.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    index = application_test_index(
        tmp_path, modules, raw_sources, inventory, configuration
    )
    path = tmp_path / "support/configuration.py"
    assignment = modules[path].body[0]
    return index, path, assignment


@pytest.mark.parametrize(
    "tox,config,expected",
    [
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
            b"commands=pytest --ds=support.configuration\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n",
            "support.configuration",
        ),
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=support.configuration\n"
            b"commands=pytest\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n",
            "support.configuration",
        ),
        (
            b"[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
            b"commands=pytest\n",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=config.settings\n"
            b"addopts=--ds=support.configuration\n",
            "support.configuration",
        ),
    ],
)
def test_captured_tox_settings_authority_follows_effective_invocation(
    tmp_path, tox, config, expected
):
    index, path, assignment = configured_authority_scope(
        tmp_path, {"pytest.ini": config, "tox.ini": tox}
    )
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert result is not None
    selection = result["settings_selection"]
    from factoryline.pytest_collection_audit import (
        _pytest_captured_invocation_options,
        captured_pytest_configuration,
    )

    config_selection = captured_pytest_configuration({"pytest.ini": config})
    effective = _pytest_captured_invocation_options(
        {"pytest.ini": config, "tox.ini": tox}, config_selection["options"]
    )
    assert effective["DJANGO_SETTINGS_MODULE"] == expected
    assert selection["execution_status"] == "NOT_EXECUTED"
    assert selection["provider_activation"] == "NOT_OBSERVED"
    assert selection["invocation"]["profile"] == "CAPTURED_LITERAL_COMMANDS_ONLY"


@pytest.mark.parametrize(
    "tox",
    [
        # Named testenvs with distinct authorities leave selection ambiguous.
        b"[testenv:one]\ncommands=pytest --ds=support.configuration\n"
        b"[testenv:two]\ncommands=pytest --ds=other.settings\n",
        # Pass-through selectors can change pytest's runtime environment.
        b"[testenv]\npassenv=PYTEST_ADDOPTS\ncommands=pytest\n",
        b"[testenv]\npassenv=PYTEST_*\ncommands=pytest\n",
        b"[testenv]\npassenv=DJANGO_SETTINGS_*\ncommands=pytest\n",
        # Dynamic substitution and unmodeled command targets/selectors are open.
        b"[testenv]\ncommands=pytest --ds={env:SETTINGS}\n",
        b"[testenv]\ncommands=pytest checks/test_feature.py\n",
        b"[testenv]\ncommands=pytest -k feature\n",
        b"[testenv]\ncommands=pytest -m integration\n",
        # cwd and command hooks can affect imports or execute other setup.
        b"[testenv]\nchangedir=checks\ncommands=pytest\n",
        b"[testenv]\ncommands_pre=python prepare.py\ncommands=pytest\n",
        b"[testenv]\ncommands_post=python cleanup.py\ncommands=pytest\n",
        # Unmodeled install behavior and path replacement can change authority.
        b"[testenv]\ninstall_command=python -m pip install {opts} {packages}\ncommands=pytest\n",
        b"[testenv]\nsetenv=PATH=/custom/tools\ncommands=pytest\n",
        # Malformed settings options cannot prove the selected module.
        b"[testenv]\ncommands=pytest --ds\n",
        b"[testenv]\ncommands=pytest --ds=../settings\n",
        # Default positional arguments are caller-controlled and unresolved.
        b"[testenv]\ncommands=pytest {posargs}\n",
    ],
)
def test_captured_tox_settings_authority_rejects_unmodeled_invocations(tmp_path, tox):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
            "tox.ini": tox,
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize(
    "name,raw",
    [
        ("pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (".pytest.ini", b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (
            "tox.ini",
            b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
            b"[testenv]\ncommands=pytest\n",
        ),
        ("setup.cfg", b"[tool:pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"),
        (
            "pyproject.toml",
            b'[tool.pytest.ini_options]\nDJANGO_SETTINGS_MODULE="support.configuration"\n',
        ),
        ("pytest.toml", b'[pytest]\nDJANGO_SETTINGS_MODULE="support.configuration"\n'),
        (".pytest.toml", b'[pytest]\nDJANGO_SETTINGS_MODULE="support.configuration"\n'),
    ],
)
def test_configured_settings_authority_uses_shared_collection_parser(
    tmp_path, name, raw
):
    index, path, assignment = configured_authority_scope(tmp_path, {name: raw})
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert result is not None
    assert result["runtime_assurance"] == "INCOMPLETE"
    assert result["isolation_assurance"] == "UNASSESSED"
    assert {w["role"] for w in result["witness_sources"]} == {
        "configured_test_settings_binding",
        "declared_pytest_settings_invocation",
    }
    assert result["settings_selection"]["execution_status"] == "NOT_EXECUTED"
    assert result["settings_selection"]["provider_activation"] == "NOT_OBSERVED"


@pytest.mark.parametrize(
    "configuration",
    [
        {
            "pytest.ini": b"",
            "tox.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
        },
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=other.settings\n"},
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--ds=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-cother.ini\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-o DJANGO_SETTINGS_MODULE=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-oDJANGO_SETTINGS_MODULE=other.settings\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-k selected\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=-m integration\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--ignore=checks/private\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--deselect=checks/test_private.py::test_value\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\ntestpaths=other\n"
        },
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\nDJANGO_CONFIGURATION=Custom\n"
        },
    ],
)
def test_configured_settings_authority_preserves_unknown_selection(
    tmp_path, configuration
):
    index, path, assignment = configured_authority_scope(tmp_path, configuration)
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize(
    "extra",
    [
        {
            "runtime.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'support.configuration')\n"
        },
        {
            "runtime.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', selected)\n"
        },
        {"runtime.py": "import os\nos.environ['DJANGO_SETTINGS_MODULE'] = selected\n"},
        {"runtime.py": "import os\nos.environ.update(selected)\n"},
        {"runtime.py": "import os\nos.putenv('DJANGO_SETTINGS_MODULE', selected)\n"},
        {
            "runtime.py": "import os\nos.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'\n"
        },
        {"runtime.py": "import pytest\npytest.main(['--ds=other.settings'])\n"},
        {"pytest_django.py": "plugin_enabled = False\n"},
        {
            "runtime.py": "from django.conf import settings\nsettings.SECRET_KEY = selected\n"
        },
        {
            "runtime.py": "from support.configuration import SECRET_KEY\nsend(SECRET_KEY)\n"
        },
        {
            "checks/test_feature.py": "from support.configuration import SECRET_KEY\ndef test_feature():\n    send(SECRET_KEY)\n"
        },
        {
            "support/configuration.py": "SECRET_KEY = 'local-signing-material-847263'\nSECRET_KEY = supplied\n"
        },
        {
            "checks/test_feature.py": "__test__ = False\ndef test_feature():\n    assert True\n"
        },
        {
            "checks/conftest.py": "def pytest_collection_modifyitems(items):\n    items.clear()\n"
        },
        {
            "checks/test_feature.py": "from django.test import override_settings\n@override_settings(SECRET_KEY='other-test-material')\ndef test_feature():\n    assert True\n"
        },
        {
            "checks/test_feature.py": "from django.test import override_settings\n@override_settings(SECRET_KEY_FALLBACKS=[])\ndef test_feature():\n    assert True\n"
        },
    ],
)
def test_configured_settings_authority_cannot_clear_counteredges(tmp_path, extra):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"},
        extra,
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


def test_configured_settings_authority_reaches_scanner_primitive_endpoint(tmp_path):
    from factoryline.review_audits import security_scan

    configured_authority_scope(
        tmp_path,
        {"pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"},
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert not [
        r for r in result["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    observations = [
        r
        for r in result.get("primitive_observations", [])
        if r["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(observations) == 1
    assert observations[0]["path"] == "support/configuration.py"
    assert (
        observations[0]["facts"]["fixture_evidence"]["profile"]
        == "SOURCE_BOUND_TEST_SCOPE_ONLY"
    )
    (tmp_path / "runtime.py").write_text(
        "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'support.configuration')\n"
    )
    changed = security_scan(tmp_path, cache_enabled=False)
    assert (
        len(
            [r for r in changed["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"]
        )
        == 1
    )


@pytest.mark.parametrize(
    "dependency",
    [b"", b"pytest-django; platform_system=='Linux'\n", b"-r unknown.txt\n"],
)
def test_configured_settings_authority_needs_captured_provider(tmp_path, dependency):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n",
            "requirements.txt": dependency,
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


def test_pytest_effect_projection_shares_general_and_tox_reporting_grammar():
    import shlex

    from factoryline.pytest_collection_audit import (
        _pytest_effective_settings_options,
        _pytest_tox_arguments_closed,
    )

    addopts = "-ra -v --strict-markers --junitxml=reports/results.xml"
    effective = _pytest_effective_settings_options(
        {"DJANGO_SETTINGS_MODULE": "support.configuration", "addopts": addopts}
    )
    assert effective["DJANGO_SETTINGS_MODULE"] == "support.configuration"
    assert _pytest_tox_arguments_closed(shlex.split(addopts))


def captured_test_profile(
    tmp_path,
    *,
    workflow,
    script=None,
    extra_sources=None,
    other_workflows=None,
    reverse_inputs=False,
    extra_configs=None,
    unbound_config=None,
    verified_missing_configs=(),
):
    from factoryline.pytest_collection_audit import captured_test_invocation_profile

    workflow_path = ".github/workflows/ci.yml"
    workflow_inputs = {workflow_path: workflow.encode()}
    workflow_inputs.update(
        {name: text.encode() for name, text in (other_workflows or {}).items()}
    )
    if reverse_inputs:
        workflow_inputs = dict(reversed(list(workflow_inputs.items())))
    invocation_sources = dict(workflow_inputs)
    modules, source_bytes, inventory = {}, {}, {}
    configuration_bytes = {**workflow_inputs, **(extra_configs or {})}
    identities = {
        name: {
            "path": name,
            "state": "read",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        for name, raw in configuration_bytes.items()
        if name != unbound_config
    }
    identities.update(
        {name: {"path": name, "state": "missing"} for name in verified_missing_configs}
    )
    if script is not None:
        script_path = tmp_path / "runtests.py"
        raw = script.encode()
        script_path.write_bytes(raw)
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[script_path], source_bytes[script_path] = tree, raw
        inventory[script_path] = tree._oracle_source_sha256
        invocation_sources["runtests.py"] = raw
    if extra_sources:
        for name, text in extra_sources.items():
            path = tmp_path / name
            raw = text.encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            tree = ast.parse(raw)
            tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
            modules[path], source_bytes[path] = tree, raw
            inventory[path] = tree._oracle_source_sha256
    if not modules:
        path = tmp_path / "probe.py"
        raw = b""
        path.write_bytes(raw)
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], source_bytes[path] = tree, raw
        inventory[path] = tree._oracle_source_sha256
    index = application_test_index(
        tmp_path, modules, source_bytes, inventory, configuration_bytes
    )
    return captured_test_invocation_profile(
        index,
        configuration_bytes,
        invocation_sources,
        configuration_identities=identities,
    )


@pytest.mark.parametrize(
    ("complete", "source_has_explicit_config", "expected"),
    [
        (True, False, "DECLARED"),
        (False, False, "UNRESOLVED"),
        (True, True, "UNRESOLVED"),
    ],
)
def test_pytest_default_profile_requires_bound_configuration_precedence(
    tmp_path, complete, source_has_explicit_config, expected
):
    from factoryline.pytest_collection_audit import _PYTEST_CONFIG_SECTIONS

    absent = [name for name, _ in _PYTEST_CONFIG_SECTIONS] if complete else []
    configs = {}
    if source_has_explicit_config:
        absent.remove("pytest.ini")
        configs = {"pytest.ini": b"[pytest]\naddopts=-p unknown_collector\n"}
    evidence = captured_test_profile(
        tmp_path,
        workflow="jobs:\n  test:\n    steps:\n      - run: python -m pytest -q\n",
        verified_missing_configs=absent,
        extra_configs=configs,
    )
    assert evidence["status"] == expected
    if expected == "DECLARED":
        assert evidence["selector"]["configuration"] == {
            "path": None,
            "state": "missing",
        }
        assert set(evidence["selector"]["python_files"]) == {"test_*.py", "*_test.py"}
        assert set(absent) <= evidence["configuration_identities"].keys()
        assert evidence["execution_status"] == "NOT_EXECUTED"


@pytest.mark.parametrize(
    ("command", "shadow", "expected"),
    [
        ("python -m unittest discover -s tests -v", False, "DECLARED"),
        ("python -m unittest discover -s ../tests", False, "UNRESOLVED"),
        ("python -m unittest discover -s tests -p case.py", False, "UNRESOLVED"),
        ("python -m unittest discover -s tests", True, "UNRESOLVED"),
    ],
)
def test_captured_unittest_discovery_binds_standard_runner(
    tmp_path, command, shadow, expected
):
    sources = {"tests/test_scope.py": "from unittest import TestCase"}
    if shadow:
        sources["unittest.py"] = "def runtime_override(): pass"
    evidence = captured_test_profile(
        tmp_path,
        workflow=f"jobs:\n  test:\n    steps:\n      - run: {command}\n",
        extra_sources=sources,
    )
    assert evidence["status"] == expected
    if expected == "DECLARED":
        assert evidence["runner"] == "unittest"
        assert evidence["selector"]["start_directory"] == "tests"
        assert evidence["execution_status"] == "NOT_EXECUTED"


def test_unittest_profile_does_not_activate_pytest_django_settings():
    authority = scope._SourceTestScope.configured_settings_authority
    assert authority(object(), {"status": "DECLARED", "runner": "unittest"}) is None


_NATIVE_RUNNER_SOURCE = (
    "import os\n"
    "import django\n"
    "from django.test.runner import DiscoverRunner\n"
    'if __name__ == "__main__":\n'
    '    os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"\n'
    "    django.setup()\n"
    "    test_runner = DiscoverRunner(verbosity=2)\n"
    "    failures = test_runner.run_tests([])\n"
)


@pytest.mark.parametrize(
    "extra,expected",
    [
        ({}, True),
        (
            {
                "helper.py": "from django.conf import settings\nvalue = getattr(settings, 'UNRELATED_OPTION', {})\n"
            },
            True,
        ),
        ({"runtime.py": "import django\ndjango.setup()\n"}, False),
        (
            {
                "runtime.py": "from django import setup as boot\nloader = boot\nloader()\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.test.runner import DiscoverRunner\nDiscoverRunner.run_tests = replacement\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.test.runner import DiscoverRunner as Runner\nsetattr(Runner, 'run_tests', replacement)\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(settings.SECRET_KEY)\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, 'SECRET_KEY'))\n"
            },
            False,
        ),
        (
            {
                "runtime.py": "from django.conf import settings\nsend(settings.SECRET_KEY_FALLBACKS)\n"
            },
            False,
        ),
        (
            {"runtime.py": "from django.conf import settings\nsend(vars(settings))\n"},
            False,
        ),
        ({"checks/test_feature.py": "def test_feature():\n    assert True\n"}, False),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '__dict__')['SECRET_KEY'])\n"
            },
            False,
            id="copied-getter-dict",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '_wrapped').SECRET_KEY)\n"
            },
            False,
            id="copied-getter-wrapped",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(getattr(settings, '__getattribute__')('SECRET_KEY'))\n"
            },
            False,
            id="copied-getter-protocol",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsend(settings._wrapped.SECRET_KEY)\n"
            },
            False,
            id="copied-direct-wrapped",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n"
            },
            False,
            id="implicit-wsgi",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.asgi import get_asgi_application\napplication = get_asgi_application()\n"
            },
            False,
            id="implicit-asgi",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.management import execute_from_command_line\nexecute_from_command_line([])\n"
            },
            False,
            id="implicit-management",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core import signing\ntoken = signing.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-live-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core import signing\nemit = getattr(signing, 'dumps')\ntoken = emit({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.core.signing import dumps as emit\ntoken = emit({'user_id': 1})\n"
            },
            False,
            id="implicit-aliased-signing",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth.tokens import default_token_generator\ntoken = default_token_generator.make_token(user)\n"
            },
            False,
            id="implicit-reset-token",
        ),
        pytest.param(
            {"runtime.py": "token = user.get_session_auth_hash()\n"},
            False,
            id="implicit-session-hash",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth import get_user_model\nUser = get_user_model()\n"
            },
            True,
            id="unrelated-user-model",
        ),
        pytest.param(
            {
                "runtime.py": "mod = __import__('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-builtin-import",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import __import__ as load\nmod = load('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-import-alias",
        ),
        pytest.param(
            {
                "runtime.py": "import builtins\nload = getattr(builtins, '__import__')\nmod = load('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-import",
        ),
        pytest.param(
            {
                "runtime.py": "namespace = globals()['__builtins__']\nmod = namespace['__import__']('django.core.signing', fromlist=['dumps'])\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-import-from-globals",
        ),
        pytest.param(
            {
                "runtime.py": "import sys\nregistry = getattr(sys, 'modules')\nmod = registry['django.core.signing']\ntoken = mod.dumps({'user_id': 1})\n"
            },
            False,
            id="implicit-reflected-module-registry",
        ),
        pytest.param(
            {"runtime.py": "import sys\nversion = sys.version_info\n"},
            True,
            id="unrelated-version-metadata",
        ),
        pytest.param(
            {
                "runtime.py": "from django.utils.crypto import salted_hmac\ntoken = salted_hmac('scope', 'payload')\n"
            },
            False,
            id="implicit-default-hmac",
        ),
        pytest.param(
            {
                "runtime.py": "from django.utils.crypto import get_random_string\nvalue = get_random_string(12)\n"
            },
            True,
            id="unrelated-random-data",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ncfg = settings\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-namespace-alias",
        ),
        pytest.param(
            {"runtime.py": "from django.conf import settings\nconsume(settings)\n"},
            False,
            id="copied-namespace-argument",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ncfg = getattr(settings, 'MISSING_PUBLIC', settings)\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-namespace-default",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\nsettings.SIGNING_BACKEND = 'external.Signer'\n"
            },
            False,
            id="copied-settings-mutation",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import LazySettings\ncfg = LazySettings()\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-lazy-settings-factory",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import Settings\ncfg = Settings('support.configuration')\nsend(cfg.SECRET_KEY)\n"
            },
            False,
            id="copied-explicit-settings-factory",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ndef getattr(obj, name, default=None):\n    send(obj.SECRET_KEY)\nvalue = getattr(settings, 'PUBLIC_OPTION', {})\n"
            },
            False,
            id="shadowed-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from django.conf import settings\ndef consume(getattr):\n    return getattr(settings, 'PUBLIC_OPTION', {})\n"
            },
            False,
            id="parameter-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import getattr as read\nfrom django.conf import settings\nvalue = read(settings, 'PUBLIC_OPTION', {})\n"
            },
            True,
            id="qualified-settings-getter",
        ),
        pytest.param(
            {
                "runtime.py": "from django.contrib.auth import get_user_model\nnamespace = getattr(get_user_model, '__globals__')\nsend(namespace['settings'].SECRET_KEY)\n"
            },
            False,
            id="implicit-function-namespace",
        ),
        pytest.param(
            {
                "runtime.py": "from builtins import getattr as read\nfrom django.contrib.auth import get_user_model\nnamespace = read(get_user_model, '__globals__')\nsend(namespace['settings'].SECRET_KEY)\n"
            },
            False,
            id="implicit-aliased-function-namespace",
        ),
        pytest.param(
            {
                "poison.py": "import builtins\nbuiltins.getattr = replacement\n",
                "runtime.py": "import poison\nfrom django.conf import settings\nvalue = getattr(settings, 'PUBLIC_OPTION', {})\n",
            },
            False,
            id="cross-source-builtin-mutation",
        ),
    ],
)
def test_native_settings_scope_closes_all_captured_provider_effects(
    tmp_path, extra, expected
):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "requirements.txt": b"Django>=4.2\n",
            ".github/workflows/ci.yml": b"jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
        },
        {
            "runtests.py": _NATIVE_RUNNER_SOURCE.replace(
                "tests.settings", "support.configuration"
            ),
            "checks/test_feature.py": "from unittest import TestCase\nclass Checks(TestCase):\n    def test_feature(self):\n        assert True\n",
            **extra,
        },
    )
    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    assert (result is not None) is expected
    if expected:
        assert (
            result["settings_selection"]["invocation"]["runner"]
            == "django.DiscoverRunner"
        )
        assert any(
            w["role"] == "modeled_implicit_settings_load"
            for w in result["witness_sources"]
        )


@pytest.mark.parametrize(
    "ending", ["", "    sys.exit(failures)\n", "    sys.exit(bool(failures))\n"]
)
def test_captured_invocation_profile_binds_native_django_bootstrap(tmp_path, ending):
    workflow = (
        "jobs:\n  test:\n    steps:\n      - run: |\n          python runtests.py\n"
    )
    script = "import sys\n" + _NATIVE_RUNNER_SOURCE + ending
    profile = captured_test_profile(tmp_path, workflow=workflow, script=script)
    assert profile["status"] == "DECLARED"
    assert profile["execution_status"] == "NOT_EXECUTED"
    assert profile["runner"] == "django.DiscoverRunner"
    assert profile["selector"]["settings_module"] == "tests.settings"
    assert profile["selector"]["bootstrap_effect"] == "MODELED_IMPLICIT_SETTINGS_LOAD"
    assert profile["selector"]["setup_span"][0] < profile["selector"]["runner_span"][0]
    assert (
        profile["sources"]["runtests.py"]["sha256"]
        == hashlib.sha256(script.encode()).hexdigest()
    )
    profile = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=script,
        other_workflows={
            ".github/workflows/dependabot-auto-merge.yml": "jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
            ".github/workflows/update-hooks.yml": "jobs:\n  update:\n    steps:\n      - run: prek run --all-files\n",
        },
    )
    assert profile["status"] == "DECLARED"
    assert len(profile["sources"]) == 4
    assert [item["status"] for item in profile["workflow_dispositions"]] == [
        "DECLARED",
        "NO_TEST_INVOCATION",
        "NO_TEST_INVOCATION",
    ]


@pytest.mark.parametrize(
    "workflow,script,extra_sources",
    [
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py --tag smoke\n",
            _NATIVE_RUNNER_SOURCE,
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - working-directory: tests\n        run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE,
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE.replace(
                "    django.setup()\n", "    if False:\n        django.setup()\n"
            ),
            None,
        ),
        (
            "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n",
            _NATIVE_RUNNER_SOURCE,
            {"django.py": "# shadow provider\n"},
        ),
    ],
)
def test_captured_native_invocation_refuses_unbound_argv_cwd_or_bootstrap(
    tmp_path, workflow, script, extra_sources
):
    assert (
        captured_test_profile(
            tmp_path,
            workflow=workflow,
            script=script,
            extra_sources=extra_sources,
        )["status"]
        == "UNRESOLVED"
    )


@pytest.mark.parametrize(
    "workflow",
    [
        "jobs:\n  test:\n    steps:\n      - run: |\n          cd tests\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: |\n          if false; then\n            echo skip\n          fi\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: |\n          export PYTHONPATH=/outside && echo ready\n          python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - run: echo 'PYTHONPATH=/outside' >> $GITHUB_ENV\n"
        "      - run: python runtests.py\n",
        "jobs:\n  test:\n    steps:\n      - working-directory: C:\\\\outside\n        run: python runtests.py\n",
    ],
)
def test_captured_native_invocation_refuses_shell_selection_or_path_mutations(
    tmp_path, workflow
):
    assert (
        captured_test_profile(
            tmp_path, workflow=workflow, script=_NATIVE_RUNNER_SOURCE
        )["status"]
        == "UNRESOLVED"
    )


def test_captured_pytest_invocation_needs_bound_selector_or_absence(tmp_path):
    workflow = "jobs:\n  test:\n    steps:\n      - run: pytest -ra\n"
    assert captured_test_profile(tmp_path, workflow=workflow)["status"] == "UNRESOLVED"


@pytest.mark.parametrize(
    "config_in_tox,unbound",
    [(False, False), (True, False), (False, True)],
)
def test_captured_pytest_invocation_binds_config_without_borrowing_tox(
    tmp_path, config_in_tox, unbound
):
    workflow = "jobs:\n  test:\n    steps:\n      - run: pytest -ra\n"
    selector = b"[pytest]\nDJANGO_SETTINGS_MODULE = direct.settings\n"
    tox = b"[testenv]\ncommands = pytest --ds=tox.settings\n"
    configs = (
        {"tox.ini": selector + tox}
        if config_in_tox
        else {"pytest.ini": selector, "tox.ini": tox}
    )
    profile = captured_test_profile(
        tmp_path,
        workflow=workflow,
        extra_configs=configs,
        unbound_config="tox.ini" if unbound else None,
    )
    if unbound:
        assert profile["status"] == "UNRESOLVED"
    else:
        assert profile["status"] == "DECLARED"
        assert profile["selector"]["settings_module"] == "direct.settings"
        assert profile["selector"]["configuration"]["path"] == (
            "tox.ini" if config_in_tox else "pytest.ini"
        )
        assert profile["configuration_identities"]["tox.ini"]["sha256"] == (
            hashlib.sha256(configs["tox.ini"]).hexdigest()
        )


@pytest.mark.parametrize("direct_matches", [True, False])
def test_source_settings_role_uses_workflow_selector_and_receipt(
    tmp_path, direct_matches
):
    direct, tox = (
        ("support.configuration", "alternate.settings")
        if direct_matches
        else ("alternate.settings", "support.configuration")
    )
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pytest.ini": f"[pytest]\nDJANGO_SETTINGS_MODULE={direct}\n".encode(),
            "tox.ini": f"[testenv]\ncommands=pytest --ds={tox}\n".encode(),
            ".github/workflows/ci.yml": b"jobs:\n  test:\n    steps:\n      - run: pytest -ra\n",
        },
    )
    from factoryline.review_audits import security_scan

    result = scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY")
    report = security_scan(
        tmp_path, cache_enabled=False, defect_policy="source-role-v3"
    )
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["audit_coverage"]["complete"] is True
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert (
        len(rows) == 1 and rows[0]["raw_finding"]["path"] == "support/configuration.py"
    )
    assert rows[0]["tier"] == (
        "PROVEN_PRIMITIVE" if direct_matches else "NEEDS_CONTEXT"
    )
    if not direct_matches:
        assert result is None
        return
    assert result is not None
    invocation = result["settings_selection"]["invocation"]
    assert invocation["runner"] == "pytest"
    assert invocation["execution_status"] == "NOT_EXECUTED"
    assert invocation["selector"]["settings_module"] == direct
    assert invocation["invocations"][0]["argv"] == ["pytest", "-ra"]
    assert "sources" not in invocation
    workflow = index["configuration_bytes"][".github/workflows/ci.yml"]
    assert (
        invocation["configuration_identities"][".github/workflows/ci.yml"]["sha256"]
        == hashlib.sha256(workflow).hexdigest()
    )
    proved = next(
        row
        for row in report["primitive_observations"]
        if row["path"] == "support/configuration.py"
    )
    assert (
        proved["facts"]["fixture_evidence"]["settings_selection"]["invocation"]
        == invocation
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("gh pr view", "NO_TEST_INVOCATION"),
        ("python -V", "NO_TEST_INVOCATION"),
        ("python -m pip --version", "NO_TEST_INVOCATION"),
        ("python tests/*", "UNRESOLVED"),
        ("echo ready | python tests/*", "UNRESOLVED"),
        ("python './tests/*'", "UNRESOLVED"),
        ("python scripts/check", "UNRESOLVED"),
        ("python -", "UNRESOLVED"),
        ("python -v", "UNRESOLVED"),
    ],
)
def test_captured_workflows_claim_absence_only_for_known_noncontributors(
    tmp_path, command, expected
):
    profile = captured_test_profile(
        tmp_path,
        workflow=f"jobs:\n  update:\n    steps:\n      - run: {command}\n",
    )
    assert profile["status"] == expected
    assert profile["invocations"] == []
    if expected == "NO_TEST_INVOCATION":
        assert profile["workflows"] == [
            {"path": ".github/workflows/ci.yml", "status": expected}
        ]


@pytest.mark.parametrize(
    "external_workflow", [".travis.yml", ".gitlab-ci.yml", "azure-pipelines.yml"]
)
def test_unmodeled_workflow_prevents_false_test_invocation_absence(
    tmp_path, external_workflow
):
    from factoryline.import_context import application_profile_configuration

    raw = b"script: tox\n"
    (tmp_path / external_workflow).write_bytes(raw)
    rows, identities, valid = application_profile_configuration(
        tmp_path, lambda root, name: (root / name).read_bytes(), 1024
    )
    assert valid and identities[external_workflow]["state"] == "read"
    assert any(
        row["path"] == external_workflow
        and row["sha256"] == hashlib.sha256(raw).hexdigest()
        for row in rows
    )
    profile = captured_test_profile(
        tmp_path,
        workflow="jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
        extra_configs={external_workflow: raw},
    )
    assert profile["status"] == "UNRESOLVED" and profile["invocations"] == []
    assert profile["reason"] == "captured-workflow-dialect-unmodeled"
    assert {"path": external_workflow, "status": "UNRESOLVED"} in profile["workflows"]
    assert (
        profile["configuration_identities"][external_workflow]["sha256"]
        == identities[external_workflow]["sha256"]
    )


def test_captured_native_profile_is_independent_of_input_mapping_order(tmp_path):
    workflow = "jobs:\n  test:\n    steps:\n      - run: python runtests.py\n"
    extras = {
        ".github/workflows/z.yml": "jobs:\n  update:\n    steps:\n      - run: gh pr view\n",
        ".github/workflows/a.yml": "jobs:\n  update:\n    steps:\n      - run: echo update\n",
    }
    expected = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=_NATIVE_RUNNER_SOURCE,
        other_workflows=extras,
    )
    actual = captured_test_profile(
        tmp_path,
        workflow=workflow,
        script=_NATIVE_RUNNER_SOURCE,
        other_workflows=extras,
        reverse_inputs=True,
    )
    assert actual == expected


def test_captured_distribution_provider_binds_django_requirement_bytes():
    import hashlib

    from factoryline.pytest_collection_audit import captured_distribution_provider

    raw = b"Django>=3.2,<5\n"
    result = captured_distribution_provider({"requirements.txt": raw}, "Django")
    assert result == {
        "path": "requirements.txt",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "provider": "django",
        "declaration_only": True,
        "declarations": [
            {"group": "requirements.txt", "requirement": "Django>=3.2,<5"}
        ],
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"Django-extra>=3.2\n",
        b"Django[postgres]>=3.2\n",
        b"Django>=3.2; python_version<'3.12'\n",
        b"Django @ https://example.invalid/django.whl\n",
        b"Django>=3.2\n-r base.txt\n",
    ],
)
def test_captured_distribution_provider_rejects_non_exact_or_included_requirements(raw):
    from factoryline.pytest_collection_audit import captured_distribution_provider

    assert captured_distribution_provider({"requirements.txt": raw}, "django") is None


def test_captured_distribution_provider_reads_required_project_dependency_only():
    from factoryline.pytest_collection_audit import captured_distribution_provider

    raw = b'[project]\ndependencies = ["Django>=4,<6"]\n'
    result = captured_distribution_provider({"pyproject.toml": raw}, "django")
    assert result["provider"] == "django"
    assert result["declarations"] == [
        {"group": "project.dependencies", "requirement": "Django>=4,<6"}
    ]
    optional = (
        b"[project]\ndependencies = []\n"
        b'[project.optional-dependencies]\ntest = ["Django>=4"]\n'
    )
    assert (
        captured_distribution_provider({"pyproject.toml": optional}, "django") is None
    )


def test_generic_provider_keeps_legacy_pytest_django_receipt_shape():
    from factoryline.pytest_collection_audit import captured_pytest_django_provider

    result = captured_pytest_django_provider(
        {"requirements.txt": b"pytest_django>=4.5\n"}
    )
    assert result["provider"] == "pytest_django"
    assert result["declaration_only"] is True
    assert "declarations" not in result


@pytest.mark.parametrize("flag", ["-q", "-v", "-vv"])
def test_captured_tox_selection_accepts_legacy_report_flags(flag):
    from factoryline.pytest_collection_audit import (
        _pytest_captured_invocation_options,
    )

    tox = (
        "[testenv]\nsetenv=\n    DJANGO_SETTINGS_MODULE=environment.settings\n"
        f"commands=pytest {flag}\n"
    ).encode()
    selected = _pytest_captured_invocation_options(
        {"tox.ini": tox}, {"DJANGO_SETTINGS_MODULE": "config.settings"}
    )
    assert selected["DJANGO_SETTINGS_MODULE"] == "environment.settings"
    assert selected["captured_invocations"]["commands"] == [
        ("testenv", f"pytest {flag}")
    ]


@pytest.mark.parametrize(
    ("args", "addopts", "expected"),
    [
        ("-q", "-p no:cacheprovider", "DECLARED"),
        ("-p no:cacheprovider -q", "-q", "DECLARED"),
        ("-q", "-p external_plugin", "UNRESOLVED"),
        ("-p no:external_plugin", "-q", "UNRESOLVED"),
        ("-p", "-q", "UNRESOLVED"),
        ("--junitxml -p no:cacheprovider result.xml", "-q", "UNRESOLVED"),
    ],
)
def test_captured_invocation_respects_exact_cache_disable(
    tmp_path, args, addopts, expected
):
    raw = f"[pytest]\naddopts={addopts}\n".encode()
    result = captured_test_profile(
        tmp_path,
        workflow=f"jobs:\n  test:\n    steps:\n      - run: python -m pytest {args}\n",
        extra_configs={"pytest.ini": raw},
    )
    assert result["status"] == expected
    assert result["execution_status"] == "NOT_EXECUTED"
    if expected == "DECLARED":
        assert result["runner"] == "pytest"
        assert (
            result["selector"]["configuration"]["sha256"]
            == hashlib.sha256(raw).hexdigest()
        )
        assert result["invocations"][0]["selector_effects"] == {}


def test_pytest_coverage_flags_require_same_profile_provider():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    config = (
        b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
        b"addopts=--cov=package --cov-report=term-missing\n"
    )
    selected = captured_pytest_configuration(
        {"pytest.ini": config, "requirements.txt": b"pytest-cov>=5\n"}
    )
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "pyproject.toml": b'[project.optional-dependencies]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "pyproject.toml": b'[dependency-groups]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )


def test_malformed_project_dependencies_refuse_captured_provider_selection():
    from factoryline.pytest_collection_audit import (
        captured_pytest_configuration,
        captured_pytest_django_provider,
    )

    captured = {
        "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
        b"addopts=--cov=package\n",
        "pyproject.toml": b"[project]\ndependencies=1\n",
    }
    assert captured_pytest_configuration(captured) is None
    assert captured_pytest_django_provider(captured) is None


def test_pytest_coverage_accepts_default_poetry_dependency():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    raw = (
        b'[tool.poetry.dependencies]\npytest-cov="^5"\n'
        b"[tool.pytest.ini_options]\n"
        b'DJANGO_SETTINGS_MODULE="support.configuration"\n'
        b'addopts="--junitxml=report.xml --cov=package --cov-report=term-missing"\n'
    )
    selected = captured_pytest_configuration({"pyproject.toml": raw})
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"


def test_pytest_coverage_accepts_provider_in_same_tox_profile():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    selected = captured_pytest_configuration(
        {
            "pytest.ini": b"[pytest]\n"
            b"DJANGO_SETTINGS_MODULE=support.configuration\n"
            b"addopts=--cov=package\n",
            "tox.ini": b"[testenv]\ndeps=pytest-cov\ncommands=pytest\n",
        }
    )
    assert selected["options"]["DJANGO_SETTINGS_MODULE"] == "support.configuration"


def test_pytest_coverage_provider_cannot_be_borrowed_from_tox_sibling():
    from factoryline.pytest_collection_audit import captured_pytest_configuration

    config = b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\naddopts=--cov=package\n"
    tox = (
        b"[testenv:fast]\ndeps=pytest\ncommands=pytest\n"
        b"[testenv:coverage]\ndeps=pytest-cov\ncommands=pytest\n"
    )
    assert (
        captured_pytest_configuration(
            {
                "pytest.ini": config,
                "tox.ini": tox,
                "pyproject.toml": b'[project.optional-dependencies]\ntest=["pytest-cov"]\n',
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "addopts,coverage_provider",
    [
        ("--junitxml --ds=production.settings", False),
        ("--cov-report --ds=production.settings", True),
        ("--reuse-db", False),
        ("--nomigrations", False),
        ("--autocheck", False),
        ("-o DJANGO_SETTINGS_MODULE=other.settings", False),
    ],
)
def test_pytest_effect_projection_rejects_swallowed_and_unknown_effects(
    addopts, coverage_provider
):
    from factoryline.pytest_collection_audit import _pytest_effective_settings_options

    assert (
        _pytest_effective_settings_options(
            {"DJANGO_SETTINGS_MODULE": "support.configuration", "addopts": addopts},
            coverage_provider=coverage_provider,
        )
        is None
    )


@pytest.mark.parametrize(
    "step,tier",
    [
        ("", "PROVEN_PRIMITIVE"),
        ("- run: pytest -ra", "PROVEN_PRIMITIVE"),
        ("- run: python -m pytest -ra", "PROVEN_PRIMITIVE"),
        ("- run: pytest --ds=other.settings", "NEEDS_CONTEXT"),
        ("- run: python -m pytest --ds=other.settings", "NEEDS_CONTEXT"),
        ("- run: python -m pytest --ds=support.configuration", "PROVEN_PRIMITIVE"),
        ("- run: pytest\n        working-directory: checks", "NEEDS_CONTEXT"),
    ],
)
def test_configured_settings_public_cli_keeps_incomplete_source_conservation(
    tmp_path, capsys, step, tier
):
    import json

    from factoryline.cli import main

    configuration = {
        "pytest.ini": b"[pytest]\nDJANGO_SETTINGS_MODULE=support.configuration\n"
    }
    if step:
        configuration[".github/workflows/ci.yml"] = (
            f"jobs:\n  test:\n    steps:\n      {step}\n"
        ).encode()
    configured_authority_scope(tmp_path, configuration)
    code = main(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code in (0, 2)
    assert result["finding_conservation"]["state"] == "PASS"
    assert result["finding_conservation"]["native_rows"] == "VERIFIED"
    assert result["audit_coverage"]["complete"] is True
    alerts = [r for r in result["findings"] if r["code"] == "SECURITY_HARDCODED_SECRET"]
    assert len(alerts) == (tier == "NEEDS_CONTEXT")
    rows = result["finding_tier_report"]["ledger"]
    assert len(rows) == 1 and rows[0]["tier"] == tier
    assert rows[0]["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    assert result["defect_policy_decision"]["release_approved"] is False


def test_failed_configured_scope_does_not_pollute_legacy_scope(tmp_path, monkeypatch):
    def reject_with_partial_state(proof):
        proof.settings_selection = {"unaccepted": True}
        proof.witnesses[("ghost", (1, 0, 1, 1), "configured_test_settings_binding")] = {
            "role": "ghost"
        }
        proof.owners[("ghost", 1)] = ("ghost", None)
        return False

    monkeypatch.setattr(
        scope._SourceTestScope, "configured_settings_scope", reject_with_partial_state
    )
    result = evidence(
        tmp_path,
        unittest_source("SECRET = 'ordinary-value-9417'\nassert SECRET == SECRET"),
    )
    assert result is not None
    assert "settings_selection" not in result
    assert all(row["role"] != "ghost" for row in result["witness_sources"])


def test_configured_settings_cannot_credit_disabled_plugin(tmp_path):
    index, path, assignment = configured_authority_scope(
        tmp_path,
        {
            "pyproject.toml": b'[tool.pytest.ini_options]\nDJANGO_SETTINGS_MODULE="support.configuration"\naddopts="-p no:django"\n',
        },
    )
    assert (
        scope._source_test_scope_evidence(index, path, assignment, "SECRET_KEY") is None
    )


@pytest.mark.parametrize("identifier", ["ordinary", "API_TOKEN"])
@pytest.mark.parametrize("annotation", ["", ": str"])
@pytest.mark.parametrize(
    "literal",
    [
        "ghp_" + "a" * 20,
        "AKIA" + "A" * 16,
        "AIza" + "a" * 32,
        "sk-test-" + "a" * 16,
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_detected_literal_reaches_role_evidence_without_identifier_loss(
    identifier, annotation, literal, monkeypatch
):
    from factoryline import context_efficiency as context, review_audits as audit

    tree = ast.parse(f"{identifier}{annotation} = {literal!r}")
    node = tree.body[0]
    target = node.targets[0] if isinstance(node, ast.Assign) else node.target
    assert audit._literal_assignment_diagnostic("consumer.py", node, target) is not None

    def forbidden(*args, **kwargs):
        raise AssertionError("candidate routing must not construct a finding")

    monkeypatch.setattr(audit, "_credential_role_witness", forbidden)
    demands = context._fixture_literal_candidates(tree, audit)
    assert demands == [(node, target, literal)]
    seen = []

    def unresolved(assignment, value):
        seen.append((assignment, value))
        return {"eligible": False, "reason": "external authority unresolved"}

    assert context._fixture_literal_evidence(tree, audit, unresolved) == {}
    assert seen == [(node, literal)]


def test_literal_candidate_routing_preserves_boundaries_and_epoch():
    from factoryline import context_efficiency as context, review_audits as audit

    tree = ast.parse(
        "ordinary = 'inert-data'\n"
        "ordinary = get_value()\n"
        "API_TOKEN = get_value()\n"
        "one = two = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
        "holder.value = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
    )
    assert context._fixture_literal_candidates(tree, audit) == []
    assert (
        audit._literal_credential_candidate
        in context.provider_context_cache_helpers(audit.contracts)
    )


@pytest.mark.parametrize("collected", [False, True])
def test_recognizable_external_credential_remains_active_after_shared_routing(
    tmp_path, collected
):
    from factoryline.review_audits import security_scan

    body = (
        "ordinary = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
        "requests.get('https://example.invalid/private', "
        "headers={'Authorization': 'Bearer ' + ordinary})\n"
    )
    if collected:
        body = "def test_auth():\n" + "".join(
            "    " + line + "\n" for line in body.splitlines()
        )
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_consumer.py").write_text("import requests\n" + body)
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(findings) == 1 and findings[0]["facts"]["name"] == "ordinary"
    assert report["finding_conservation"]["state"] == "PASS"


@pytest.mark.parametrize("identifier", ["ordinary", "API_TOKEN"])
@pytest.mark.parametrize("annotation", ["", ": str"])
def test_test_scope_disposition_does_not_depend_on_credential_identifier(
    tmp_path, identifier, annotation
):
    from factoryline.review_audits import security_scan

    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_scope.py").write_text(
        unittest_source(
            f"{identifier}{annotation} = 'ghp_aaaaaaaaaaaaaaaaaaaa'\n"
            f"assert {identifier} == {identifier}"
        )
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert not [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(rows) == 1 and rows[0]["tier"] == "PROVEN_PRIMITIVE"
    assert report["finding_conservation"]["state"] == "PASS"


_DRF_FIXTURE_FILES = {
    "manage.py": """
        import os
        import sys
        from django.core.management import execute_from_command_line

        def main():
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
            execute_from_command_line(sys.argv)

        if __name__ == '__main__':
            main()
    """,
    "config/__init__.py": "",
    "config/settings.py": """
        import os
        INSTALLED_APPS = ['django.contrib.auth', 'rest_framework']
        MIDDLEWARE = []
        ROOT_URLCONF = 'config.urls'
        DATABASES = {'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'HOST': os.getenv('POSTGRES_HOST'),
            'PORT': os.getenv('POSTGRES_PORT', '5432'),
        }}
    """,
    "config/urls.py": """
        from django.urls import path
        from rest_framework_simplejwt.views import TokenObtainPairView
        urlpatterns = [path('auth/token/', TokenObtainPairView.as_view())]
    """,
    "tests/__init__.py": "",
    "tests/base.py": """
        from django.contrib.auth import get_user_model
        from rest_framework.test import APITestCase

        class AccountFixture(APITestCase):
            password = 'synthetic-test-account-value'

            @classmethod
            def setUpTestData(cls):
                cls.user = get_user_model().objects.create_user(
                    username='example', email='user@example.invalid', password=cls.password,
                )

            def setUp(self):
                self.client.force_authenticate(self.user)
    """,
    "tests/test_authentication.py": """
        from .base import AccountFixture

        class AccountTests(AccountFixture):
            def test_login(self):
                self.client.force_authenticate(user=None)
                response = self.client.post(
                    '/auth/token/', {'username': self.user.username, 'password': self.password},
                    format='json',
                )
                self.assertEqual(response.status_code, 200)
    """,
    ".github/workflows/ci.yml": """
        name: CI
        on: pull_request
        env:
          DJANGO_SETTINGS_MODULE: config.settings
          POSTGRES_HOST: 127.0.0.1
          POSTGRES_PORT: "5432"
          POSTGRES_DB: example_test
          POSTGRES_USER: example_test
          POSTGRES_PASSWORD: synthetic-ci-only
        jobs:
          test:
            runs-on: ubuntu-24.04
            services:
              postgres:
                image: postgres:17-alpine
                ports:
                  - 5432:5432
                env:
                  POSTGRES_DB: example_test
                  POSTGRES_USER: example_test
                  POSTGRES_PASSWORD: synthetic-ci-only
            steps:
              - run: python manage.py test
    """,
}


_DRF_FIXTURE_MUTATIONS = {
    "runtime-import": (
        ("runtime.py", lambda _source: "from tests.base import AccountFixture\n"),
    ),
    "external-request": (
        (
            "tests/test_authentication.py",
            lambda source: source.replace(
                "'/auth/token/'", "'https://example.invalid/auth/token/'"
            ),
        ),
    ),
    "database-route": (
        (
            "config/settings.py",
            lambda source: source.replace(
                "os.getenv('POSTGRES_HOST')", "'external-db.invalid'"
            ),
        ),
    ),
    "custom-signer": (
        (
            "config/settings.py",
            lambda source: source + "TEST_RUNNER = 'config.custom.DiscoverRunner'\n",
        ),
    ),
    "serializer-override": (
        (
            "config/settings.py",
            lambda source: source
            + "SIMPLE_JWT = {}\nSIMPLE_JWT['TOKEN_OBTAIN_SERIALIZER'] = 'config.custom.Serializer'\n",
        ),
    ),
    "parser-override": (
        (
            "config/settings.py",
            lambda source: source
            + "REST_FRAMEWORK = {'DEFAULT_PARSER_CLASSES': ['config.custom.Parser']}\n",
        ),
    ),
    "database-options": (
        (
            "config/settings.py",
            lambda source: source.replace(
                "'HOST':",
                "'OPTIONS': {'hostaddr': 'external-db.invalid'},\n    'HOST':",
            ),
        ),
    ),
    "aliased-receiver": (
        (
            "tests/test_authentication.py",
            lambda source: source
            + "\n    def test_other(account):\n        receive(account)\n",
        ),
    ),
    "route-list-mutation": (
        ("config/urls.py", lambda source: source + "\nreplace_routes(urlpatterns)\n"),
    ),
    "alternate-runner": (
        (
            ".github/workflows/other.yml",
            lambda _source: "jobs:\n  other:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python manage.py test --keepdb\n",
        ),
    ),
    "alternate-runner-same-job": (
        (
            ".github/workflows/ci.yml",
            lambda source: source + "      - run: python manage.py test --keepdb\n",
        ),
    ),
    "alternate-pytest": (
        (
            ".github/workflows/other.yml",
            lambda _source: "jobs:\n  verification:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python -m pytest\n",
        ),
    ),
    "alternate-py-test": (
        (".github/workflows/ci.yml", lambda source: source + "      - run: py.test\n"),
    ),
    "unproven-runner-script": (
        (
            ".github/workflows/ci.yml",
            lambda source: source + "      - run: bash ./ci/verify.sh\n",
        ),
    ),
    "quoted-runner-script": (
        (
            ".github/workflows/ci.yml",
            lambda source: source + '      - run: bash "./ci/verify.sh"\n',
        ),
    ),
    "uncaptured-reusable-job": (
        (
            ".github/workflows/other.yml",
            lambda _source: "jobs:\n  verification:\n    uses: ./.github/workflows/missing.yml\n",
        ),
    ),
    "root-include": (
        (
            "config/urls.py",
            lambda source: source.replace(
                "import path", "import include, path"
            ).replace(
                "urlpatterns = [", "urlpatterns = [path('', include('config.other')), "
            ),
        ),
    ),
    "definition-time-read": (
        (
            "tests/base.py",
            lambda source: source.replace(
                "    @classmethod",
                "    observed = observe(password)\n\n    @classmethod",
            ),
        ),
    ),
    "definition-time-namespace": (
        (
            "tests/base.py",
            lambda source: source.replace(
                "    @classmethod", "    observe(locals())\n\n    @classmethod"
            ),
        ),
    ),
    "middleware-mutation": (
        (
            "config/settings.py",
            lambda source: source
            + "\nactive = MIDDLEWARE\nactive.append('config.other.Custom')\n",
        ),
    ),
    "middleware-dispatch-hook": (
        (
            "config/settings.py",
            lambda source: source.replace(
                "MIDDLEWARE = []", "MIDDLEWARE = ['config.middleware.Logger']"
            ),
        ),
        (
            "config/middleware.py",
            lambda _source: "class Logger:\n    def __init__(self, get_response):\n        self.get_response = get_response\n    def __call__(self, request):\n        return self.get_response(request)\n    def process_view(self, request, view, args, kwargs):\n        record(request.body)\n",
        ),
    ),
    "assigned-setup": (
        (
            "tests/test_authentication.py",
            lambda source: source + "\n    setUp = replacement\n",
        ),
    ),
}


@pytest.mark.parametrize(
    "mutation",
    [
        "closed",
        "runtime-import",
        "external-request",
        "database-route",
        "custom-signer",
        "serializer-override",
        "parser-override",
        "database-options",
        "aliased-receiver",
        "route-list-mutation",
        "alternate-runner",
        "alternate-runner-same-job",
        "alternate-pytest",
        "alternate-py-test",
        "unproven-runner-script",
        "quoted-runner-script",
        "uncaptured-reusable-job",
        "root-include",
        "definition-time-read",
        "definition-time-namespace",
        "middleware-mutation",
        "middleware-dispatch-hook",
        "assigned-setup",
    ],
)
def test_drf_fixture_requires_replayed_account_and_consumer_closure(tmp_path, mutation):
    files = {
        name: dedent(source).lstrip() for name, source in _DRF_FIXTURE_FILES.items()
    }
    for name, update in _DRF_FIXTURE_MUTATIONS.get(mutation, ()):
        files[name] = update(files.get(name, ""))

    for relative, source in files.items():
        path = tmp_path / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    args = _build_parser().parse_args(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    report = prepare_bounded_security_report(args)
    assert report["audit_coverage"]["complete"] is True
    assert report["finding_conservation"]["state"] == "PASS"
    ledger = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    raw = [
        row
        for row in ledger
        if row["path"] == "tests/base.py" and row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    if mutation == "closed":
        assert not raw
        [refuted] = [
            row
            for row in report["refuted_security_observations"]
            if row["path"] == "tests/base.py"
        ]
        proof = refuted["facts"]["fixture_evidence"]
        assert proof["fixture_contract"] == "DRF_CLASS_ACCOUNT_LIFECYCLE"
        assert [row["role"] for row in proof["consumer_use_closure"]["uses"]] == [
            "fresh_account_password",
            "test_client_password",
        ]
    else:
        assert len(raw) == 1


def test_fixture_text_model_rejects_import_identity_as_runtime_text():
    from factoryline.credential_role_identity_effects import _Value
    from factoryline.fixture_scope_value_audit import _closed_text_binary

    template = _Value(inert_kind="scalar", scalar_kind="text", _exact_scalar=("%s",))
    provider = _Value(
        inert_kind="scope_namespace", _exact_scalar=("unittest.TestCase",)
    )
    assert _closed_text_binary(ast.Mod(), template, provider) is None


_RAC_CLIENT = """class Client(object):
    def __init__(self, host, password):
        self.host = host
        self.password = password

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.open_session()

    def read_marker(self, record):
        return self._extract(record, "MARK")

    def _extract(self, record, field):
        if record is None:
            return
        try:
            return record.split("<%s>" % field)[1].split("</%s>" % field)[0]
        except KeyError:
            raise Exception("missing %s" % field)

    def open_session(self):
        external_authentication(self.password)
"""

_RAC_TEST = """from unittest import TestCase
from client import Client

TEST_PASSWORD = "synthetic-fixture-marker-3927"

class Checks(TestCase):
    def setUp(self):
        self.client = Client("127.0.0.1", TEST_PASSWORD)

    def test_marker(self):
        self.assertEqual(self.client.read_marker("<MARK>yes</MARK>"), "yes")
"""


@pytest.mark.parametrize(
    "counterexample",
    [
        None,
        "authentication",
        "context_manager",
        "receiver_escape",
        "fixture_field_read",
        "production_import",
        "duplicate_literal",
        "unmodeled_loader",
        "custom_dispatch",
        "descriptor",
        "missing_host_proof",
        "teardown",
    ],
)
def test_unused_unittest_client_credential_is_refuted_by_cli(tmp_path, counterexample):
    test_source = _RAC_TEST
    extra = {
        "authentication": "        self.client.open_session()\n",
        "context_manager": "        with self.client:\n            pass\n",
        "receiver_escape": "        outside_fixture(self.client)\n",
        "fixture_field_read": "        self.assertTrue(self.client.password)\n",
        "teardown": "\n    def tearDown(self):\n        self.client.open_session()\n",
        "unmodeled_loader": "\ndef load_tests(loader, tests, pattern):\n    return tests\n",
        "custom_dispatch": "\n    def doCleanups(self):\n        self.client.open_session()\n",
    }
    test_source += extra.get(counterexample, "")
    if counterexample == "missing_host_proof":
        test_source = test_source.replace("127.0.0.1", "fixture.invalid")
    if counterexample == "production_import":
        (tmp_path / "production.py").write_text(
            "import test_client\n", encoding="utf-8"
        )
    if counterexample == "duplicate_literal":
        (tmp_path / "production.py").write_text(
            'VALUE = "synthetic-fixture-marker-3927"\n', encoding="utf-8"
        )
    client = _RAC_CLIENT
    if counterexample == "descriptor":
        client = (
            "from functools import cached_property\n\n"
            + client
            + "\n    @cached_property\n    def marker(self):\n"
            + '        captured = self.password\n        return "yes"\n'
        )
        test_source = test_source.replace(
            'self.client.read_marker("<MARK>yes</MARK>")', "self.client.marker"
        )
    (tmp_path / "client.py").write_text(client, encoding="utf-8")
    (tmp_path / "test_client.py").write_text(test_source, encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    report = json.loads(process.stdout)
    assert report["finding_conservation"]["state"] == "PASS"
    assert report["finding_conservation"]["native_rows"] == "VERIFIED"
    assert report["audit_coverage"]["complete"] is True
    assert bool(report["finding_tier_report"]["ledger"]) is bool(counterexample)
    refuted = report.get("refuted_security_observations", [])
    if counterexample is None:
        assert refuted[0]["facts"]["fixture_evidence"]["source_hypothesis"] == (
            "SOURCE_TEST_CLIENT_CREDENTIAL_UNUSED"
        )
    else:
        assert not refuted
