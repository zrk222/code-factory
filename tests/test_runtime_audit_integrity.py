import hashlib
import copy
from factoryline import review_audits
from factoryline import review_integrity
from factoryline import runtime_audit_integrity as runtime
from factoryline import primitive_observation_binding as primitive
import pytest
from factoryline.runtime_audit import evaluate_runtime_audit
from factoryline.runtime_audit_integrity import index_executions, repair_guidance
from factoryline.runtime_audit_common import RuntimeAuditError
from test_runtime_audit import _plan, _command
import ast
import json
from factoryline.runtime_audit_integrity import closed_declaration_input_witness
from factoryline.runtime_audit_integrity import finite_literal_eval_input_witness
from factoryline.runtime_audit_integrity import source_generated_eval_input_witness


@pytest.mark.parametrize(
    "codec, declaration", [("latin-1", b"# coding: latin-1\n"), ("utf-8-sig", b"")]
)
def test_python_source_encoding299_preserves_bytes_and_security(
    tmp_path, codec, declaration
):
    raw = declaration + (
        "# café\nfrom flask import request\neval(request.get_data(as_text=True))\n"
    ).encode(codec)
    path = tmp_path / "app.py"
    path.write_bytes(raw)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert report["audit_coverage"]["complete"] is True
    assert report["files_scanned"] == 1
    assert report["unreadable_sources"] == 0
    assert report["sources"][0]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert not any(
        row["code"] == "SECURITY_SOURCE_UNREADABLE" for row in report["findings"]
    )
    assert any(
        row["code"] == "SECURITY_DYNAMIC_EXECUTION" for row in report["findings"]
    )
    row = next(
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )
    assert row["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "raw",
    [
        b"# coding: nonexistent-codec\nx = 1\n",
        b"x = '\xff'\n",
        b"\xef\xbb\xbf# coding: latin-1\nx = 1\n",
    ],
)
def test_python_source_encoding299_invalid_source_remains_incomplete(tmp_path, raw):
    (tmp_path / "app.py").write_bytes(raw)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert report["audit_coverage"]["complete"] is False
    assert report["audit_coverage"]["files_audited"] == 0
    assert any(
        row["code"] in {"SECURITY_SOURCE_UNREADABLE", "QUALITY_SYNTAX_ERROR"}
        for row in report["findings"]
    )


@pytest.mark.parametrize("label", ["secret", "password_origin", "API_KEY_ORIGIN"])
def test_local_control_label301_retains_raw_but_not_defect(tmp_path, label):
    source = f"def choose(flag):\n    {label} = 'config'\n    if flag:\n        {label} = 'env'\n    return {label} != 'env'\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert rows and all(row["tier"] == "PROVEN_PRIMITIVE" for row in rows)
    assert all(row["raw_finding"]["severity"] == "CRITICAL" for row in rows)
    assert not any(
        row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
    )


@pytest.mark.parametrize(
    "body",
    [
        "return secret == supplied",
        "return 'env' == secret == supplied",
        "return secret",
        "send(secret)\n    return secret == 'env'",
        "alias = secret\n    return alias == 'env'",
        "box.secret = secret\n    return secret == 'env'",
        "secret = supplied\n    return secret == 'env'",
        "secret += 'suffix'\n    return secret == 'env'",
        "del secret\n    return secret == 'env'",
        "from provider import value as secret\n    return secret == 'env'",
        "if (secret := supplied):\n        pass\n    return secret == 'env'",
        "try:\n        work()\n    except Exception as secret:\n        pass\n    return secret == 'env'",
        "match supplied:\n        case {'value': secret}:\n            pass\n    return secret == 'env'",
        "def captured():\n        return secret\n    return secret == 'env'",
        "locals()\n    return secret == 'env'",
        "inspect.currentframe()\n    return secret == 'env'",
        "eval('secret')\n    return secret == 'env'",
    ],
)
def test_local_control_label301_unknown_and_authority_uses_stay_active(tmp_path, body):
    (tmp_path / "app.py").write_text(
        "def choose(supplied):\n    secret = 'config'\n    " + body + "\n",
        encoding="utf-8",
    )
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert any(
        row["code"] == "SECURITY_HARDCODED_SECRET"
        and row["line"] == 2
        and row["severity"] == "CRITICAL"
        for row in report["findings"]
    )


def test_local_control_label301_requires_independent_current_source_regeneration(
    tmp_path,
):
    import copy
    from factoryline.primitive_observation_binding import fixed_primitive_binding

    source = b"def choose():\n    secret = 'config'\n    return secret == 'env'\n"
    (tmp_path / "app.py").write_bytes(source)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    finding = next(
        row["raw_finding"]
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    bindings = {row["path"]: row["sha256"] for row in report["sources"]}
    assert fixed_primitive_binding(
        finding, report["sources"], bindings, None, {"app.py": source}
    )
    forged = copy.deepcopy(finding)
    forged["facts"]["scope_span"][-1] += 1
    assert not fixed_primitive_binding(
        forged, report["sources"], bindings, None, {"app.py": source}
    )
    changed = source.replace(b"return secret == 'env'", b"return secret == supplied")
    assert not fixed_primitive_binding(
        finding, report["sources"], bindings, None, {"app.py": changed}
    )


@pytest.mark.parametrize(
    "prefix, expected",
    [
        (
            "def unrelated(obj, option):\n    return getattr(obj, option)\n",
            "PROVEN_PRIMITIVE",
        ),
        ("lookup = getattr\n", "NEEDS_CONTEXT"),
        ("from builtins import getattr as lookup\n", "NEEDS_CONTEXT"),
        ("import sys\nframe = sys._getframe\n", "NEEDS_CONTEXT"),
    ],
)
def test_local_control_label301_unrelated_getter_and_capability_capture(
    tmp_path, prefix, expected
):
    source = (
        prefix + "def choose():\n    secret = 'config'\n    return secret == 'env'\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    row = next(
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert row["tier"] == expected


@pytest.mark.parametrize(
    "declaration, comparison",
    [
        ("ghp_0123456789abcdefghijklmnopqrstuv", "config"),
        ("config", "ghp_0123456789abcdefghijklmnopqrstuv"),
    ],
)
def test_local_control_label301_known_credential_material_stays_active(
    tmp_path, declaration, comparison
):
    source = f"def choose():\n    secret = {declaration!r}\n    return secret == {comparison!r}\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert any(
        row["code"] == "SECURITY_HARDCODED_SECRET" and row["severity"] == "CRITICAL"
        for row in report["findings"]
    )


def test_local_control_label301_regenerates_with_unrelated_repository_sources(tmp_path):
    (tmp_path / "app.py").write_text(
        "def choose():\n    secret = 'config'\n    return secret == 'env'\n",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.py").write_text(
        "def ordinary():\n    return 42\n", encoding="utf-8"
    )
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert report["audit_coverage"]["complete"]
    assert report["audit_coverage"]["files_audited"] == 2
    row = next(
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    assert row["tier"] == "PROVEN_PRIMITIVE"
    assert row["raw_finding"]["severity"] == "CRITICAL"


def test_local_control_label301_regeneration_avoids_unrelated_scanner_work(
    tmp_path, monkeypatch
):
    from factoryline.primitive_observation_binding import fixed_primitive_binding

    raw = b"def choose():\n    secret = 'config'\n    return secret == 'env'\n"
    (tmp_path / "app.py").write_bytes(raw)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    finding = next(
        row["raw_finding"]
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"
    )
    bindings = {row["path"]: row["sha256"] for row in report["sources"]}

    def unrelated_scan(*args, **kwargs):
        raise RuntimeError("A local role proof must not rerun every unrelated detector")

    monkeypatch.setattr(review_audits, "_security_scan_tree", unrelated_scan)
    assert fixed_primitive_binding(
        finding, report["sources"], bindings, None, {"app.py": raw}
    )


def _sink_context_index(tmp_path, source):
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    path = tmp_path / "sink.py"
    raw = source.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw, filename=str(path))
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    sink = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "loads"
    )
    return path, raw, digest, tree, index, sink


def _provider_profile_contract308(monkeypatch):
    from factoryline import finite_capture

    runtime_identity = {
        "implementation": "cpython",
        "version": "3.11.9",
        "executable_sha256": "1" * 64,
        "pickle_source_sha256": "2" * 64,
        "pickle_implementation_sha256": "3" * 64,
    }
    monkeypatch.setattr(
        finite_capture, "_provider_runtime_identity", lambda: dict(runtime_identity)
    )
    return {
        "schema": "factory.provider-contract.v1",
        "model": {"id": "builtin-exception-record-v1", "version": 1},
        "runtime": dict(runtime_identity),
        "artifacts": {"package/errors.py": "4" * 64, "package/__init__.py": "5" * 64},
        "export": {"path": "package/__init__.py", "symbol": "LocalError"},
        "classes": [
            {
                "path": "package/errors.py",
                "name": "LocalError",
                "class_ast_sha256": "6" * 64,
                "constructor_ast_sha256": "7" * 64,
            }
        ],
        "assumptions": [
            "CANONICAL_CPYTHON_PICKLE",
            "IMMUTABLE_PROVIDER_ARTIFACTS",
            "NO_RUNTIME_MONKEY_PATCHING",
            "TRUSTED_IMPORT_INITIALIZATION",
        ],
    }


def test_provider_profile308_default_has_no_runtime_or_contract_dependency(monkeypatch):
    from factoryline import finite_capture

    def unexpected_runtime_read():
        raise AssertionError(
            "default scan must not resolve conditional runtime artifacts"
        )

    monkeypatch.setattr(
        finite_capture, "_provider_runtime_identity", unexpected_runtime_read
    )
    profile = finite_capture.provider_analysis_profile()
    assert profile["analysis_profile"] == "source-closed-v1"
    assert profile["contracts"] == []
    assert profile["conditional"] is False


def test_provider_profile308_contract_identity_is_canonical_not_safety(monkeypatch):
    from factoryline import finite_capture

    contract = _provider_profile_contract308(monkeypatch)
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v1", (contract,)
    )
    reordered = {key: contract[key] for key in reversed(contract)}
    assert profile == finite_capture.provider_analysis_profile(
        "trusted-dependencies-v1", (reordered,)
    )
    assert profile["conditional"] is True
    assert profile["state"] == "CONTRACT_DECLARED_NOT_SOURCE_VALIDATED"
    assert len(profile["model_sha256"]) == 64
    assert len(profile["contract_sha256"]) == 64
    contract["artifacts"]["package/errors.py"] = "8" * 64
    assert profile["contracts"][0]["artifacts"]["package/errors.py"] == "4" * 64
    assert (
        profile["profile_sha256"]
        != finite_capture.provider_analysis_profile(
            "trusted-dependencies-v1", (contract,)
        )["profile_sha256"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_field",
        "caller_validated",
        "unknown_model",
        "model_bool_version",
        "wrong_runtime",
        "missing_assumption",
        "duplicate_assumption",
        "unknown_assumption",
        "absolute_artifact",
        "traversal_artifact",
        "alias_artifact",
        "bad_hash",
        "missing_export_artifact",
        "unknown_export_field",
        "missing_class_artifact",
        "bad_class_hash",
        "duplicate_class",
        "empty_classes",
        "too_many_artifacts",
        "callback",
    ],
)
def test_provider_profile308_invalid_contracts_are_rejected(monkeypatch, mutation):
    from factoryline import finite_capture

    contract = _provider_profile_contract308(monkeypatch)
    changes = {
        "unknown_field": (("extra",), True),
        "caller_validated": (("validated",), True),
        "unknown_model": (("model", "id"), "trust-all-v1"),
        "model_bool_version": (("model", "version"), True),
        "wrong_runtime": (("runtime", "version"), "3.12.0"),
        "missing_assumption": (("assumptions",), contract["assumptions"][:-1]),
        "duplicate_assumption": (
            ("assumptions",),
            [*contract["assumptions"], contract["assumptions"][0]],
        ),
        "unknown_assumption": (
            ("assumptions",),
            [*contract["assumptions"], "TRUST_TEST_FILES"],
        ),
        "absolute_artifact": (("artifacts", "/package/errors.py"), "4" * 64),
        "traversal_artifact": (("artifacts", "../errors.py"), "4" * 64),
        "alias_artifact": (("artifacts", "package/./errors.py"), "4" * 64),
        "bad_hash": (("artifacts", "package/errors.py"), "not-a-digest"),
        "missing_export_artifact": (("export", "path"), "missing.py"),
        "unknown_export_field": (("export", "trusted"), True),
        "missing_class_artifact": (("classes", 0, "path"), "missing.py"),
        "bad_class_hash": (("classes", 0, "class_ast_sha256"), "broken"),
        "duplicate_class": (
            ("classes",),
            [*contract["classes"], dict(contract["classes"][0])],
        ),
        "empty_classes": (("classes",), []),
        "too_many_artifacts": (
            ("artifacts",),
            {f"extra{i}.py": "4" * 64 for i in range(65)},
        ),
        "callback": (("model", "callback"), lambda: True),
    }
    path, replacement = changes[mutation]
    target = contract
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile("trusted-dependencies-v1", (contract,))


@pytest.mark.parametrize(
    "profile, contracts",
    [
        ("unknown", ()),
        ("source-closed-v1", ({},)),
        ("trusted-dependencies-v1", ()),
        ("trusted-dependencies-v1", ({}, {})),
    ],
)
def test_provider_profile308_invalid_selection_stops_before_runtime(
    monkeypatch, profile, contracts
):
    from factoryline import finite_capture

    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile(profile, contracts)


@pytest.mark.parametrize(
    "field, value",
    [
        ("model", []),
        ("runtime", []),
        ("artifacts", []),
        ("export", {"path": [], "symbol": "LocalError"}),
        ("classes", [None]),
        ("assumptions", None),
    ],
)
def test_provider_profile308_wrong_json_field_types_fail_closed(
    monkeypatch, field, value
):
    from factoryline import finite_capture

    contract = _provider_profile_contract308(monkeypatch)
    contract[field] = value
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile("trusted-dependencies-v1", (contract,))


def test_provider_profile308_fingerprints_real_local_interpreter():
    from factoryline import finite_capture

    identity = finite_capture._provider_runtime_identity()
    assert identity["implementation"] == "cpython"
    assert identity["version"] == "3.11.9"
    assert all(
        len(identity[key]) == 64
        for key in (
            "executable_sha256",
            "pickle_source_sha256",
            "pickle_implementation_sha256",
        )
    )


def _provider_record308(monkeypatch, constructor=None, base_body="pass", prefix=""):
    from factoryline import finite_capture

    body = (
        constructor
        or "def __init__(self, message=None):\n    if message is None:\n        message = 'disconnected'\n    self.args = (message,)\n    self.message = message\n"
    )
    source = (
        prefix
        + "class LocalBase(Exception):\n"
        + "\n".join("    " + line for line in base_body.splitlines())
        + "\nclass LocalError(LocalBase):\n"
        + "\n".join("    " + line for line in body.splitlines())
        + "\n"
    )
    raw = source.encode()
    tree = ast.parse(raw)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    contract = _provider_profile_contract308(monkeypatch)
    contract["artifacts"]["package/errors.py"] = hashlib.sha256(raw).hexdigest()
    contract["classes"] = [
        {
            "path": "package/errors.py",
            "name": cls.name,
            "class_ast_sha256": hashlib.sha256(
                ast.dump(cls, include_attributes=False).encode()
            ).hexdigest(),
            "constructor_ast_sha256": next(
                (
                    hashlib.sha256(
                        ast.dump(item, include_attributes=False).encode()
                    ).hexdigest()
                    for item in cls.body
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__"
                ),
                None,
            ),
        }
        for cls in reversed(classes)
    ]
    exported = b"from .errors import LocalError\n"
    contract["artifacts"]["package/__init__.py"] = hashlib.sha256(exported).hexdigest()
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v1", (contract,)
    )
    return profile, {"package/errors.py": raw, "package/__init__.py": exported}


def test_provider_profile308_reconstructs_closed_exception_record(monkeypatch):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch)
    state = finite_capture.provider_exception_record(
        profile, sources, ast.parse("LocalError(message='fixed')", mode="eval").body
    )
    assert state["args"] == ("fixed",)
    assert state["state"] == {"args": ("fixed",), "message": "fixed"}
    assert state["analysis_profile"] == "trusted-dependencies-v1"
    assert state["assurance"] == "CONDITIONAL_PROVIDER_CONTRACT"
    assert (
        finite_capture.provider_exception_record(
            finite_capture.provider_analysis_profile(),
            sources,
            ast.parse("LocalError('fixed')", mode="eval").body,
        )
        is None
    )


@pytest.mark.parametrize(
    "constructor",
    [
        "def __init__(self, message=None):\n    self.args = (message,)\n    eval(message)\n",
        "def __init__(self, message=None):\n    self.args = (message,)\n    self.__reduce__ = message\n",
        "def __init__(self, message=opaque()):\n    self.args = (message,)\n",
        "def __init__(self, message=None):\n    self.args = (message,)\ndef __setstate__(self, state):\n    execute(state)\n",
    ],
)
def test_provider_profile308_unsupported_constructor_and_hooks_stay_unknown(
    monkeypatch, constructor
):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch, constructor)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


def test_provider_profile308_source_and_argument_drift_stay_unknown(monkeypatch):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch)
    call = ast.parse("LocalError(external)", mode="eval").body
    assert finite_capture.provider_exception_record(profile, sources, call) is None
    sources["package/errors.py"] += b"# changed\n"
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


@pytest.mark.parametrize(
    "base_body",
    [
        "def __reduce__(self):\n    return (eval, ('payload',))",
        "__setstate__ = supplied",
    ],
)
def test_provider_profile308_ancestor_hooks_cannot_hide_as_absent_constructor(
    monkeypatch, base_body
):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch, base_body=base_body)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


def test_provider_profile308_definition_time_annotation_effect_is_rejected(monkeypatch):
    from factoryline import finite_capture

    constructor = "def __init__(self, message: effect() = None):\n    self.args = (message,)\n    self.message = message\n"
    profile, sources = _provider_record308(monkeypatch, constructor)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


def test_provider_profile308_unselected_yield_invalidates_whole_constructor(
    monkeypatch,
):
    from factoryline import finite_capture

    constructor = "def __init__(self, message=None):\n    if message is None:\n        yield message\n    self.args = (message,)\n    self.message = message\n"
    profile, sources = _provider_record308(monkeypatch, constructor)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


def test_provider_profile308_custom_annotation_subscription_is_unknown(monkeypatch):
    from factoryline import finite_capture

    constructor = "def __init__(self, message: Registry[LocalBase] = None):\n    self.args = (message,)\n    self.message = message\n"
    profile, sources = _provider_record308(monkeypatch, constructor)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


@pytest.mark.parametrize(
    "prefix, annotation, accepted",
    [
        ("", "'LocalBase' | str", False),
        ("", "None | None", False),
        ("tuple = None\n", "tuple[str]", False),
        ("str = supplied\n", "str | None", False),
        ("", "str | None", True),
        ("", "list['forward'] | None", True),
        ("", "'forward'", True),
        (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from remote import Message\nelse:\n    Message = None\n",
            "Message | str | None",
            True,
        ),
        (
            "from typing import TYPE_CHECKING\nTYPE_CHECKING = supplied\nif TYPE_CHECKING:\n    Message = None\nelse:\n    Message = None\n",
            "Message | str",
            False,
        ),
        ("Message = None\nMessage = supplied\n", "Message | str", False),
    ],
)
def test_provider_profile308_annotation_kinds_match_definition_semantics(
    monkeypatch, prefix, annotation, accepted
):
    from factoryline import finite_capture

    constructor = f"def __init__(self, message: {annotation} = None):\n    self.args = (message,)\n    self.message = message\n"
    profile, sources = _provider_record308(monkeypatch, constructor, prefix=prefix)
    result = finite_capture.provider_exception_record(
        profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
    )
    assert (result is not None) is accepted


def test_provider_profile308_positional_only_receiver_is_unsupported(monkeypatch):
    from factoryline import finite_capture

    constructor = "def __init__(self, /, message):\n    message.args = (self,)\n"
    profile, sources = _provider_record308(monkeypatch, constructor)
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


def test_provider_profile308_source_base_must_precede_derived_class(monkeypatch):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch)
    raw = sources["package/errors.py"]
    start = raw.index(b"class LocalError")
    raw = raw[start:] + raw[:start]
    sources["package/errors.py"] = raw
    contract = profile["contracts"][0]
    contract["artifacts"]["package/errors.py"] = hashlib.sha256(raw).hexdigest()
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v1", (contract,)
    )
    assert (
        finite_capture.provider_exception_record(
            profile, sources, ast.parse("LocalError('fixed')", mode="eval").body
        )
        is None
    )


@pytest.mark.parametrize(
    "source, accepted",
    [
        (
            "from package import LocalError\ndef run():\n    return LocalError('fixed')\n",
            True,
        ),
        (
            "from package import LocalError as E\ndef run():\n    return E('fixed')\n",
            True,
        ),
        ("import package as p\ndef run():\n    return p.LocalError('fixed')\n", True),
        (
            "import package as p\nclass Tests:\n    p = supplied\n    def run(self):\n        return p.LocalError('fixed')\n",
            True,
        ),
        (
            "import package as p\nclass Tests:\n    p = supplied\n    def run(self, item=p.LocalError('fixed')):\n        pass\n",
            False,
        ),
        (
            "import package as p\ndef outer(p):\n    def run():\n        return p.LocalError('fixed')\n",
            False,
        ),
        (
            "from package import LocalError\ndef run(LocalError):\n    return LocalError('fixed')\n",
            False,
        ),
        (
            "from package import LocalError\nLocalError = supplied\ndef run():\n    return LocalError('fixed')\n",
            False,
        ),
        (
            "from package import LocalError\ndef run():\n    LocalError = supplied\n    return LocalError('fixed')\n",
            False,
        ),
        (
            "from package import LocalError\nfrom remote import *\ndef run():\n    return LocalError('fixed')\n",
            False,
        ),
    ],
)
def test_provider_profile308_constructor_import_binding(monkeypatch, source, accepted):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch)
    call = next(
        node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
    )
    witness = finite_capture.provider_constructor_binding(
        profile, sources, source.encode(), call
    )
    assert (witness is not None) is accepted
    if witness:
        assert witness["mutation_assurance"] == "NOT_YET_QUALIFIED"


@pytest.mark.parametrize(
    "initializer, accepted",
    [
        (
            "from .errors import LocalError\ndef __getattr__(name):\n    return supplied\n",
            True,
        ),
        ("def __getattr__(name):\n    return supplied\n", False),
        ("from .errors import LocalError\nerrors = supplied\n", False),
        ("from .errors import LocalError\ndel errors\n", False),
        ("from .errors import *\n", False),
    ],
)
def test_provider_profile308_child_module_binding_requires_source_preload(
    monkeypatch, initializer, accepted
):
    from factoryline import finite_capture

    profile, sources = _provider_record308(monkeypatch)
    raw = initializer.encode()
    sources["package/__init__.py"] = raw
    contract = profile["contracts"][0]
    contract["artifacts"]["package/__init__.py"] = hashlib.sha256(raw).hexdigest()
    contract["export"] = {"path": "package/errors.py", "symbol": "LocalError"}
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v1", (contract,)
    )
    source = b"from package import errors\nclass Tests:\n    def run(self):\n        return errors.LocalError('fixed')\n"
    call = next(
        node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
    )
    assert (
        finite_capture.provider_constructor_binding(profile, sources, source, call)
        is not None
    ) is accepted


@pytest.mark.parametrize(
    "source, escaped",
    [
        ("consume(provider.Record)", True),
        ("consume(record=provider.Record)", True),
        ("consume(record={'selected': provider.Record})", True),
        ("provider.Record()", False),
    ],
)
def test_provider_profile308_mutation_index_tracks_keyword_escape(source, escaped):
    from factoryline import finite_capture

    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    facts = finite_capture.finite_provider_mutation_index(
        nodes, {"provider": "package.provider"}, review_audits, parents
    )
    assert (("package.provider.Record", "*") in facts) is escaped


def test_provider_profile308_security_only_seal_retains_outer_scope(monkeypatch):
    from factoryline import audit_action_refs

    observed = []

    def observe_seal(*args, **kwargs):
        observed.append(review_audits._SECURITY_ONLY_SCAN.get())
        return {}

    monkeypatch.setattr(audit_action_refs, "security_scan_report", observe_seal)
    with review_audits._security_only_scan_context(True):
        review_audits._security_scan_report([], [], [], {}, {}, (), {}, [], [])
    assert observed == [True]
    assert review_audits._SECURITY_ONLY_SCAN.get() is False


def _provider_workspace308(monkeypatch, tmp_path):
    profile, sources = _provider_record308(monkeypatch)
    caller = (
        "import pickle\nfrom package import LocalError\n"
        "def test_closed_record():\n    err = LocalError('fixed')\n    err.foo = 'bar'\n"
        "    for proto in range(pickle.HIGHEST_PROTOCOL + 1):\n"
        "        packed = pickle.dumps(err, proto)\n        result = pickle.loads(packed)\n"
        "        assert result.foo == 'bar'\n"
    ).encode()
    sources["test_roundtrip.py"] = caller
    for name, raw in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return profile, sources


def test_provider_profile308_public_api_rejects_before_source_inventory(
    monkeypatch, tmp_path
):
    def unexpected_inventory(_):
        raise AssertionError("invalid analysis profile must stop before scanning")

    monkeypatch.setattr(review_audits, "_security_source_files", unexpected_inventory)
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        review_audits.security_scan(tmp_path, analysis_profile="unknown")


@pytest.mark.parametrize(
    "source", [b"\x00", b"value = 'unclosed", b"# coding: unknown-codec\nvalue = 1\n"]
)
def test_source_diagnostic318_missing_coordinates_retains_parse_failure(
    tmp_path, source
):
    (tmp_path / "broken.py").write_bytes(source)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert report["parse_errors"] == 1
    assert report["audit_coverage"]["complete"] is False
    row = next(
        row for row in report["findings"] if row["code"] == "QUALITY_SYNTAX_ERROR"
    )
    assert row["severity"] == "HIGH"
    assert type(row["line"]) is int and type(row["column"]) is int


def test_source_diagnostic318_known_coordinates_are_preserved():
    node = ast.Pass(lineno=7, col_offset=3)
    row = review_audits._security_finding(
        "QUALITY_SYNTAX_ERROR", "broken.py", node, "Invalid syntax", "HIGH"
    )
    assert (row["line"], row["column"]) == (7, 3)


def test_provider_profile308_public_scan_preserves_raw_and_default(
    monkeypatch, tmp_path
):
    profile, sources = _provider_workspace308(monkeypatch, tmp_path)
    before = review_audits.security_scan(tmp_path, cache_enabled=False)
    conditional = review_audits.security_scan(
        tmp_path,
        analysis_profile="trusted-dependencies-v1",
        provider_contracts=tuple(profile["contracts"]),
    )
    after = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert before["findings"] == after["findings"]
    raw = [
        row
        for row in before["findings"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(raw) == 1
    proved = [
        row
        for row in conditional.get("primitive_observations", [])
        if row["facts"].get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT"
    ]
    assert len(proved) == 1
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in conditional["findings"]
    )
    assert proved[0]["severity"] == raw[0]["severity"]
    assert proved[0]["message"] == raw[0]["message"]
    ledger = conditional["finding_tier_report"]["ledger"]
    assert any(
        row["raw_finding"] == raw[0] and row["tier"] == "PROVEN_PRIMITIVE"
        for row in ledger
    )
    assert conditional["provider_analysis_profile"] == profile
    assert conditional["source_manifest_sha256"] != before["source_manifest_sha256"]
    assert set(dict(conditional._captured_sources)) >= set(sources)


def _pickle_reconstruction317_native_workspace(monkeypatch, tmp_path, prefix=b""):
    from factoryline.finite_capture import provider_analysis_profile

    old, sources = _provider_workspace308(monkeypatch, tmp_path)
    profile = provider_analysis_profile(
        "trusted-dependencies-v2", tuple(old["contracts"])
    )
    if prefix:
        (tmp_path / "test_roundtrip.py").write_bytes(
            prefix + b"\n" + sources["test_roundtrip.py"]
        )
    return profile


def test_pickle_reconstruction317_native_selected_contract_and_cached_identity(
    monkeypatch, tmp_path
):
    profile = _pickle_reconstruction317_native_workspace(monkeypatch, tmp_path)
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    proved = [
        row
        for row in report.get("primitive_observations", [])
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(proved) == 1
    witness = proved[0]["facts"]["provider_witness"]
    assert witness["schema"] == "factory.conditional-provider-pickle-witness.v2"
    assert (
        witness["initialized_provider"]["status"]
        == "CONDITIONAL_CACHED_GLOBAL_IDENTITY"
    )
    assert witness["initialized_provider"]["runtime_observation"] == "not_performed"
    assert witness["selected_contract_sha256"]
    assert witness["selected_model_sha256"]
    assert proved[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "provider_append,caller_prefix",
    [
        (
            b"",
            b"import copyreg\ncopyreg._extension_registry[('package.errors','LocalError')]=42\ncopyreg._inverted_registry[42]=('other','Other')",
        ),
        (
            b"class Replacement(Exception): pass\nglobals()['LocalError'] = Replacement\n",
            b"",
        ),
        (
            b"class Replacement(Exception): pass\nnamespace = globals\nnamespace()['LocalError'] = Replacement\n",
            b"",
        ),
        (
            b"import builtins\nclass Replacement(Exception): pass\nreflect = getattr\nnamespace = reflect(builtins, 'globals')\nnamespace()['LocalError'] = Replacement\n",
            b"",
        ),
        (
            b"def replacement(self, value):\n    self.args = (value,)\nLocalError.__init__.__code__ = replacement.__code__\n",
            b"",
        ),
        (b"LocalError.__init__.__defaults__ = ('changed',)\n", b""),
    ],
)
def test_pickle_reconstruction317_native_registry_namespace_and_method_mutations(
    monkeypatch, tmp_path, provider_append, caller_prefix
):
    import hashlib
    from factoryline.finite_capture import provider_analysis_profile

    profile = _pickle_reconstruction317_native_workspace(
        monkeypatch, tmp_path, caller_prefix
    )
    contracts = profile["contracts"]
    if provider_append:
        path = tmp_path / "package/errors.py"
        path.write_bytes(path.read_bytes() + b"\n" + provider_append)
        contracts[0]["artifacts"]["package/errors.py"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    profile = provider_analysis_profile("trusted-dependencies-v2", tuple(contracts))
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report.get("primitive_observations", [])
    )


def test_pickle_reconstruction317_native_unselected_package_file_collision_stays_active(
    monkeypatch, tmp_path
):
    profile = _pickle_reconstruction317_native_workspace(monkeypatch, tmp_path)
    path = tmp_path / "package/errors/__init__.py"
    path.parent.mkdir()
    path.write_text("class LocalError(Exception): pass\n", encoding="utf-8")
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report.get("primitive_observations", [])
    )


def test_pickle_reconstruction317_native_v1_artifact_declaration_compatibility(
    monkeypatch,
):
    import copy
    from factoryline.finite_capture import provider_analysis_profile

    old, _ = _provider_record308(monkeypatch)
    contract = copy.deepcopy(old["contracts"][0])
    contract["artifacts"]["package/errors/__init__.py"] = "1" * 64
    contract["artifacts"]["provider-metadata.txt"] = "2" * 64
    assert provider_analysis_profile("trusted-dependencies-v1", (contract,))[
        "conditional"
    ]
    with pytest.raises(RuntimeAuditError):
        provider_analysis_profile("trusted-dependencies-v2", (contract,))


@pytest.mark.parametrize(
    "prefix",
    [
        b"import sys\nsys.modules.pop('package.errors', None)",
        b"import sys\ndef hook(*args): pass\nsys.addaudithook(hook)",
        b"import copyreg\ncopyreg.add_extension('package.errors', 'LocalError', 1)",
        b"import importlib\nfrom package import errors\nimportlib.reload(errors)",
    ],
)
def test_pickle_reconstruction317_native_lookup_counterevidence_stays_active(
    monkeypatch, tmp_path, prefix
):
    profile = _pickle_reconstruction317_native_workspace(monkeypatch, tmp_path, prefix)
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report.get("primitive_observations", [])
    )


@pytest.mark.parametrize(
    "field",
    ["selected_contract_sha256", "selected_model_sha256", "initialized_provider"],
)
def test_pickle_reconstruction317_native_seal_rejects_changed_identity(
    monkeypatch, tmp_path, field
):
    import copy

    profile = _pickle_reconstruction317_native_workspace(monkeypatch, tmp_path)
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    core = copy.deepcopy(dict(report))
    core["_primitive_source_bytes"] = dict(report._captured_sources)
    row = next(
        row
        for row in core["primitive_observations"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    )
    row["facts"]["provider_witness"][field] = "forged"
    checked = review_audits._seal_security_scan(core)
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in checked.get("primitive_observations", [])
    )
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" and row["severity"] == "HIGH"
        for row in checked["findings"]
    )


@pytest.mark.parametrize(
    "field", ["args", "__reduce__", "__reduce_ex__", "__dict__", "__setstate__"]
)
def test_provider_profile308_reconstruction_control_writes_stay_active(
    monkeypatch, tmp_path, field
):
    profile, sources = _provider_workspace308(monkeypatch, tmp_path)
    caller = sources["test_roundtrip.py"].replace(
        b"err.foo = 'bar'", f"err.{field} = ('changed',)".encode()
    )
    (tmp_path / "test_roundtrip.py").write_bytes(caller)
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v1",
        provider_contracts=tuple(profile["contracts"]),
    )
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not any(
        row["facts"].get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT"
        for row in report.get("primitive_observations", [])
    )


@pytest.mark.parametrize(
    "tamper",
    ["witness", "profile", "source", "priority", "missing_profile", "unbound_provider"],
)
def test_provider_profile308_independent_seal_rejects_tampered_negative(
    monkeypatch, tmp_path, tamper
):
    import copy

    profile, _ = _provider_workspace308(monkeypatch, tmp_path)
    report = review_audits.security_scan(
        tmp_path,
        analysis_profile="trusted-dependencies-v1",
        provider_contracts=tuple(profile["contracts"]),
    )
    core = copy.deepcopy(dict(report))
    captured = dict(report._captured_sources)
    core["_primitive_source_bytes"] = captured
    row = next(
        row
        for row in core["primitive_observations"]
        if row["facts"].get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT"
    )
    if tamper == "witness":
        row["facts"]["provider_witness"]["forged"] = True
    elif tamper == "profile":
        core["provider_analysis_profile"]["profile_sha256"] = "0" * 64
    elif tamper == "source":
        captured["package/errors.py"] += b"\n# changed\n"
    elif tamper == "priority":
        row["severity"] = "MEDIUM"
    elif tamper == "unbound_provider":
        core["sources"] = [
            item for item in core["sources"] if item["path"] != "package/errors.py"
        ]
    else:
        core.pop("provider_analysis_profile")
    checked = review_audits._seal_security_scan(core)
    assert not any(
        row["facts"].get("disposition") == "CONDITIONAL_PROVIDER_CONTRACT"
        for row in checked.get("primitive_observations", [])
    )
    assert any(
        row["facts"].get("proof_rejection") == "PROFILE_OR_SOURCE_BINDING_MISMATCH"
        for row in checked["findings"]
    )


def _primitive_admission306_report(tmp_path):
    raw = b'exec("x = 1")\n'
    (tmp_path / "app.py").write_bytes(raw)
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert report["primitive_observations"]
    report["_primitive_source_bytes"] = {"app.py": raw}
    return raw, report


def _primitive_admission306_contradiction(finding):
    return {
        "schema": "factory.security.precondition.v1",
        "status": "SUPPORTED",
        "source_role": "untrusted_request",
        "consumer_role": "dynamic_execution",
        "proof_scope": "local_static_wiring",
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
        "sink_span": finding["facts"]["call_span"],
    }


def test_primitive_admission306_conflict_remains_active_not_primitive(tmp_path):
    raw, report = _primitive_admission306_report(tmp_path)
    finding = report["primitive_observations"][0]
    severity = finding["severity"]
    finding["facts"]["security_precondition"] = _primitive_admission306_contradiction(
        finding
    )
    review_integrity.partition_proven_primitive_observations(report)
    assert report["primitive_observations"] == []
    active = next(
        row for row in report["findings"] if row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )
    assert active["severity"] == severity
    assert active["facts"]["proof_rejection"] == "CONTRADICTORY_SECURITY_PREMISES"
    assert report["finding_tier_report"]["ledger"][0]["tier"] == "NEEDS_CONTEXT"
    assert report["_primitive_source_bytes"]["app.py"] == raw


def test_primitive_admission306_direct_validator_rejects_conflict(tmp_path):
    raw, report = _primitive_admission306_report(tmp_path)
    finding = report["primitive_observations"][0]
    bindings = {row["path"]: row["sha256"] for row in report["sources"]}
    assert review_integrity._fixed_primitive_binding(
        finding, report["sources"], bindings, {"app.py": raw}
    )
    finding["facts"]["security_precondition"] = _primitive_admission306_contradiction(
        finding
    )
    assert not review_integrity._fixed_primitive_binding(
        finding, report["sources"], bindings, {"app.py": raw}
    )


def test_primitive_admission306_valid_control_and_missing_source_are_distinct(tmp_path):
    raw, report = _primitive_admission306_report(tmp_path)
    control = copy.deepcopy(report)
    review_integrity.partition_proven_primitive_observations(control)
    assert control["primitive_observations"]
    assert control["findings"] == []
    assert control["finding_tier_report"]["ledger"][0]["tier"] == "PROVEN_PRIMITIVE"
    report["_primitive_source_bytes"] = {"app.py": raw + b"# changed\n"}
    review_integrity.partition_proven_primitive_observations(report)
    assert report["primitive_observations"] == []
    assert (
        report["findings"][0]["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"
    )


def test_sink_context_captures_exact_sink_scope_import_and_local_transfer(tmp_path):
    source = (
        "import pickle\n"
        "def invoke(raw):\n"
        "    return restore(raw)\n"
        "def restore(data):\n"
        "    payload = data\n"
        "    return pickle.loads(payload)\n"
    )
    path, raw, digest, tree, index, sink = _sink_context_index(tmp_path, source)

    evidence = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )
    supplied_tree = runtime.captured_sink_evidence(
        sink,
        source_path=path,
        source_sha256=digest,
        source_bytes=raw,
        tree=tree,
    )

    assert evidence["status"] == "COMPLETE"
    assert evidence["source"]["sha256"] == digest
    assert evidence["budget"]["states_used"] <= evidence["budget"]["states_limit"]
    assert evidence["budget"]["snapshot_index_reused"] is True
    assert (
        evidence["budget"]["source_ast_nodes_examined"]
        <= evidence["budget"]["source_ast_limit"]
    )
    assert evidence["sink"]["span"] == [6, 11, 6, 32]
    assert evidence["scope"]["name"] == "restore"
    assert evidence["imports"][0]["name"] == "pickle"
    payload = next(row for row in evidence["values"] if row["name"] == "payload")
    assert payload["status"] == "INFERRED"
    assert payload["definitions"][0]["expression"] == "data"
    data = next(row for row in evidence["values"] if row["name"] == "data")
    assert data["origin"] == "CALLABLE_PARAMETER"
    assert evidence["authority"]["status"] == "UNKNOWN"
    assert evidence["callers"] == {
        "status": "UNKNOWN",
        "reason": "caller_expansion_not_performed",
    }
    assert supplied_tree["status"] == "COMPLETE"
    assert supplied_tree["budget"]["snapshot_index_reused"] is False
    assert supplied_tree["budget"]["source_ast_nodes_examined"] > 0


@pytest.mark.parametrize(
    "replacement",
    [
        "    payload = other\n",
        "    from attacker import value as payload\n",
        "    def payload():\n        return data\n",
        "    try:\n        pass\n    except Exception as payload:\n        pass\n",
        "    match other:\n        case payload:\n            pass\n",
    ],
)
def test_sink_context_marks_replaced_local_bindings_unknown(tmp_path, replacement):
    source = (
        "import pickle\n"
        "def restore(data, other):\n"
        "    payload = data\n" + replacement + "    return pickle.loads(payload)\n"
    )
    path, _, digest, _, index, sink = _sink_context_index(tmp_path, source)

    evidence = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )

    payload = next(row for row in evidence["values"] if row["name"] == "payload")
    assert payload["status"] == "UNKNOWN"
    assert payload["replacements"]
    assert evidence["authority"]["status"] == "UNKNOWN"


def test_sink_context_rejects_stale_bytes_and_unresolved_location(tmp_path):
    path, _, digest, _, index, sink = _sink_context_index(
        tmp_path, "def restore(data):\n    return pickle.loads(data)\n"
    )
    stale = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256="0" * 64,
    )
    shifted = copy.deepcopy(sink)
    shifted.lineno += 1
    shifted.end_lineno += 1
    unresolved = runtime.captured_sink_evidence(
        shifted,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )

    assert stale["code"] == "SINK_SOURCE_STALE"
    assert unresolved["code"] == "SINK_LOCATION_UNRESOLVED"


def test_sink_context_revalidates_warm_index_after_sink_ast_mutation(tmp_path):
    path, _, digest, _, index, sink = _sink_context_index(
        tmp_path,
        "import pickle\ndef restore(data):\n    payload = data\n    return pickle.loads(payload)\n",
    )
    assert index._validation_inputs[path][0] is index.snapshots[path]

    sink.args[0].id = "forged"
    evidence = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )

    assert evidence["status"] == "INCOMPLETE"
    assert evidence["code"] == "SINK_SOURCE_STALE"
    assert evidence["truncation"] == ["source_snapshot_invalid"]


def test_sink_context_budget_exhaustion_is_incomplete_not_complete(tmp_path):
    path, _, digest, _, index, sink = _sink_context_index(
        tmp_path,
        "import pickle\ndef restore(data):\n    payload = data\n    return pickle.loads(payload)\n",
    )

    evidence = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
        max_states=1,
    )

    assert evidence["status"] == "INCOMPLETE"
    assert "max_states" in evidence["truncation"]


def test_sink_context_bounds_selected_scope_not_unrelated_module_nodes(tmp_path):
    source = (
        "import pickle\n"
        + "".join(f"module_value_{index} = {index}\n" for index in range(600))
        + "def restore(data):\n    return pickle.loads(data)\n"
    )
    path, _, digest, _, index, sink = _sink_context_index(tmp_path, source)

    evidence = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )

    assert evidence["status"] == "COMPLETE"
    assert evidence["scope"]["name"] == "restore"


def test_sink_context_follows_local_producer_definitions_to_parameter(tmp_path):
    source = (
        "import pickle\ndef restore(raw):\n"
        "    local = {'value': raw}\n"
        "    payload = pickle.dumps(local)\n"
        "    return pickle.loads(payload)\n"
    )
    path, _, digest, _, index, sink = _sink_context_index(tmp_path, source)

    evidence = runtime.captured_sink_evidence(
        sink, source_index=index, source_path=path, source_sha256=digest
    )

    payload = {row["name"]: row for row in evidence["values"]}
    assert payload["payload"]["definitions"][0]["expression"] == "pickle.dumps(local)"
    assert payload["local"]["definitions"][0]["expression"] == "{'value': raw}"
    assert payload["raw"]["origin"] == "CALLABLE_PARAMETER"
    assert payload["pickle"]["origin"] == "LEXICAL_IMPORT"
    assert evidence["provider"]["status"] == "UNKNOWN"
    assert evidence["effects"]["status"] == "UNKNOWN"


def test_sink_context_unknowns_reflection_and_wildcard_imports(tmp_path):
    reflected = (
        "import pickle\ndef restore(data, code):\n"
        "    payload = data\n    exec(code)\n    return pickle.loads(payload)\n"
    )
    path, _, digest, _, index, sink = _sink_context_index(tmp_path, reflected)
    evidence = runtime.captured_sink_evidence(
        sink, source_index=index, source_path=path, source_sha256=digest
    )
    payload = next(row for row in evidence["values"] if row["name"] == "payload")
    assert payload["status"] == "UNKNOWN"
    assert payload["reason"] == "reflective_binding_possible"

    wildcard = (
        "from attacker import *\ndef restore(data):\n    return pickle.loads(data)\n"
    )
    path, _, digest, _, index, sink = _sink_context_index(tmp_path, wildcard)
    evidence = runtime.captured_sink_evidence(
        sink, source_index=index, source_path=path, source_sha256=digest
    )
    assert evidence["callee_binding"]["status"] == "UNKNOWN"
    assert evidence["callee_binding"]["reason"] == "wildcard_import_may_bind_name"


def test_sink_context_rejects_disconnected_ast_and_invalid_source_encoding(tmp_path):
    path, raw, digest, _, index, sink = _sink_context_index(
        tmp_path, "import pickle\ndef restore(data):\n    return pickle.loads(data)\n"
    )
    disconnected = copy.deepcopy(sink)
    detached = runtime.captured_sink_evidence(
        disconnected,
        source_index=index,
        source_path=path,
        source_sha256=digest,
    )
    source_tree = ast.parse(raw, filename=str(path))
    detached_call = copy.deepcopy(
        next(
            item
            for item in ast.walk(source_tree)
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr == "loads"
        )
    )
    detached_without_index = runtime.captured_sink_evidence(
        detached_call,
        source_path=path,
        source_sha256=digest,
        source_bytes=raw,
        tree=source_tree,
    )
    invalid = runtime.captured_sink_evidence(
        sink,
        source_path=path,
        source_sha256=hashlib.sha256(b"\xff").hexdigest(),
        source_bytes=b"\xff",
    )

    assert detached["code"] == "SINK_LOCATION_UNRESOLVED"
    assert detached_without_index["code"] == "SINK_LOCATION_UNRESOLVED"
    assert invalid["code"] == "SINK_SOURCE_STALE"


def test_sink_context_stale_index_and_output_budget_fail_closed(tmp_path):
    path, raw, digest, _, index, sink = _sink_context_index(
        tmp_path, "import pickle\ndef restore(data):\n    return pickle.loads(data)\n"
    )
    index.source_bytes[path] = raw + b"# changed\n"
    stale = runtime.captured_sink_evidence(
        sink, source_index=index, source_path=path, source_sha256=digest
    )
    _, _, digest, _, index, sink = _sink_context_index(
        tmp_path, "import pickle\ndef restore(data):\n    return pickle.loads(data)\n"
    )
    limited = runtime.captured_sink_evidence(
        sink,
        source_index=index,
        source_path=path,
        source_sha256=digest,
        max_output_bytes=256,
    )

    assert stale["code"] == "SINK_SOURCE_STALE"
    assert limited["code"] == "SINK_BUDGET_EXHAUSTED"
    assert limited["truncation"] == ["max_output_bytes"]


@pytest.mark.parametrize(
    "replacement,closed",
    [
        ("", True),
        ("from attacker import blob as payload\n", False),
        ("import attacker as payload\n", False),
        ("def payload(): pass\n", False),
        ("class payload: pass\n", False),
        ("try:\n    operation()\nexcept Exception as payload:\n    pass\n", False),
        ("match external:\n    case {'body': payload}:\n        pass\n", False),
    ],
)
def test_pickle_sink_rejects_non_name_payload_rebindings(replacement, closed):
    source = (
        "def test_roundtrip():\n"
        "    payload = pickle.dumps(local)\n"
        + "".join("    " + line + "\n" for line in replacement.splitlines())
        + "    pickle.loads(payload)\n"
    )
    function = ast.parse(source).body[0]
    load = function.body[-1].value
    assert (
        runtime._single_local_pickle_bytes_flow(
            function, "payload", function.body[0], load
        )
        is closed
    )


def test_pickle_sink_import_rebinding_preserves_raw_security_alert(tmp_path):
    (tmp_path / "test_roundtrip.py").write_text(
        "import pickle\n"
        "def test_roundtrip():\n"
        "    local = {'value': 1}\n"
        "    payload = pickle.dumps(local)\n"
        "    from attacker import blob as payload\n"
        "    pickle.loads(payload)\n",
        encoding="utf-8",
    )
    findings = review_audits.security_scan(tmp_path)["findings"]
    sinks = [
        row for row in findings if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(sinks) == 1
    assert sinks[0]["severity"] == "HIGH"
    assert "input_provenance" not in sinks[0]["facts"]


def test_finding_tier_report_keeps_known_format_raw_severity_and_run_scope():
    source = b'GITHUB_TOKEN = "ghp_abcdefghijklmnop"\n'
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "severity": "CRITICAL",
        "path": "source.py",
        "line": 1,
        "column": 0,
        "message": "credential-like source literal",
        "facts": {"name": "GITHUB_TOKEN"},
    }
    report = primitive.build_finding_tier_report(
        [finding],
        [],
        [{"path": "source.py", "sha256": hashlib.sha256(source).hexdigest()}],
        {"source.py": source},
        coverage_state=True,
        partition_state="VALIDATED",
    )

    row = report["ledger"][0]
    # Declaration shape is an observation, not proof of operative credential authority.
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["evidence"] is None
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert report["raw_diagnostics"]["count"] == 1
    assert report["tier_counts"] == {
        "SUPPORTED_DEFECT": 0,
        "NEEDS_CONTEXT": 1,
        "PROVEN_PRIMITIVE": 0,
    }
    assert report["claim_policy"]["held_out_precision"] == "NOT_MEASURED"
    assert report["retention_metrics"]["known_true_positive_retention"].startswith(
        "NOT_MEASURED"
    )
    assert report["defect_gate"]["state"] == "NO_SUPPORTED_DEFECTS_OBSERVED"
    assert report["defect_gate"]["clean"] is False
    assert len(report["ledger_sha256"]) == 64
    assert len(report["report_sha256"]) == 64


def test_finding_tier_report_recomputes_precondition_from_captured_source():
    source = b"eval(user_data)\n"
    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "severity": "HIGH",
        "path": "source.py",
        "line": 1,
        "column": 0,
        "message": "dynamic execution",
        "facts": {
            "call": "eval",
            "security_precondition": {
                "schema": "factory.security.precondition.v1",
                "status": "SUPPORTED",
                "source_role": "untrusted_request",
                "consumer_role": "eval",
                "sink_span": [1, 0, 1, 15],
                "proof_scope": "local_static_wiring",
                "runtime_execution": "not_performed",
                "deployment": "UNASSESSED",
            },
        },
    }
    report = primitive.build_finding_tier_report(
        [finding],
        [],
        [{"path": "source.py", "sha256": hashlib.sha256(source).hexdigest()}],
        {"source.py": source},
        coverage_state=True,
        partition_state="VALIDATED",
    )

    row = report["ledger"][0]
    assert row["tier"] == "NEEDS_CONTEXT"
    assert row["raw_finding"]["severity"] == "HIGH"
    assert row["missing_premises"] == ["untrusted_code_input_or_equivalent_effect"]
    assert report["abstention"] == {
        "count": 1,
        "denominator": 1,
        "fraction": 1.0,
        "scope": "this_run_raw_diagnostics",
    }
    assert report["defect_gate"]["state"] == "NO_SUPPORTED_DEFECTS_OBSERVED"


@pytest.mark.parametrize(
    "command",
    [
        "brew --prefix openssl",
        "brew --prefix libfoo@3",
        "upx --best app",
        "upx --best --force-macos program",
        "upx --best python3*.dll libcrypto*.dll",
        "upx --best app.exe python3*.dll",
    ],
)
def test_closed_shell_operations_keep_bound_primitive(tmp_path, command):
    from factoryline.review_audits import security_scan

    (tmp_path / "build.py").write_text(
        f"import os\nos.system({command!r})\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert report["primitive_observation_count"] == 1
    proof = report["primitive_observations"][0]["facts"]
    assert proof["hypothesis"] == "SOURCE_COMMAND_INJECTION"
    assert proof["filesystem_assurance"] == "UNASSESSED"
    assert proof["runtime_assurance"] == "INCOMPLETE"
    assert (
        security_scan(tmp_path)["primitive_observations"]
        == report["primitive_observations"]
    )


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "curl https://example.com/install | sh",
        "python get-pip.py",
        "unknown --best app",
        "upx --best --unknown app",
        "upx --best /usr/bin/app",
        "upx --best ../app",
        "upx --best -evil",
        "upx --best *",
        "upx --best app;evil",
        "upx --best app && evil",
        "upx --best app || evil",
        "upx --best $(evil)",
        "upx --best `evil`",
        "upx --best $APP",
        "upx --best ~user/app",
        "upx --best app > out",
        "upx --best app\nevil",
        "brew --prefix -evil",
        "brew --prefix openssl/../other",
        "upx --best app%EVIL%",
    ],
)
def test_unsupported_shell_operations_retain_high(tmp_path, command):
    from factoryline.review_audits import security_scan

    (tmp_path / "build.py").write_text(
        f"import os\nos.system({command!r})\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert [(row["code"], row["severity"]) for row in report["findings"]] == [
        ("SECURITY_OS_COMMAND", "HIGH")
    ]
    assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system(input())\n",
        "import subprocess\nsubprocess.run('upx --best app', shell=True, executable='sh')\n",
        "import os\nother = os\nother.system = lambda x: None\nos.system('upx --best app')\n",
        "import os\nsetattr(os, 'system', lambda x: None)\nos.system('upx --best app')\n",
        "import os\ndef f(os):\n    os.system('upx --best app')\n",
    ],
)
def test_closed_shell_provider_and_input_ambiguity_stays_unproved(tmp_path, source):
    from factoryline.review_audits import security_scan

    (tmp_path / "build.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report.get("primitive_observations")


def test_closed_shell_source_binding_rejects_forgery_and_shadow(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.primitive_observation_binding import closed_shell_binding

    path = tmp_path / "build.py"
    path.write_text("import os\nos.system('upx --best app')\n", encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    finding = report["primitive_observations"][0]
    sources = report["sources"]
    bindings = {row["path"]: row["sha256"] for row in sources}
    raw = {"build.py": path.read_bytes()}
    assert closed_shell_binding(finding, sources, bindings, raw)
    forged = json.loads(json.dumps(finding))
    forged["facts"]["operation_role"] = "safe"
    assert not closed_shell_binding(forged, sources, bindings, raw)
    raw["build.py"] = b"import os\nos.system('rm -rf /')\n"
    assert not closed_shell_binding(finding, sources, bindings, raw)
    (tmp_path / "os.py").write_text("pass\n", encoding="utf-8")
    assert not security_scan(tmp_path, cache_enabled=False).get(
        "primitive_observations"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "os.__dict__['system'] = replacement",
        "lookup(os, '__dict__')['system'] = replacement",
        "mutate(os)",
        "os.system = replacement",
        "__import__('os').system = replacement",
        "loader = __import__; loader('os').system = replacement",
        "globals()['os'].system = replacement",
        "namespace = globals(); namespace['os'].system = replacement",
        "from importlib import import_module as load; load('os').system = replacement",
        "__import__('importlib').import_module('os').system = replacement",
        "os.system = replacement\ndef unused():\n    import harmless as os",
        "from importlib import import_module as loader\nloader('os').system = replacement\ndef unused():\n    import harmless as loader",
    ],
)
def test_closed_shell_imported_provider_changes_remain_findings(tmp_path, mutation):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(
        "import helper\nimport os\nos.system('upx --best app')\n", encoding="utf-8"
    )
    (tmp_path / "helper.py").write_text(
        "import os\nfrom builtins import getattr as lookup\n"
        "def replacement(value):\n    pass\n"
        "def mutate(value):\n    value.system = replacement\n" + mutation + "\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report.get("primitive_observations")
    assert any(
        row["code"] == "SECURITY_OS_COMMAND" and row["severity"] == "HIGH"
        for row in report["findings"]
    )


def test_closed_shell_cached_changes_cannot_reuse_proof(tmp_path):
    from factoryline.review_audits import security_scan

    path = tmp_path / "app.py"
    for command in ["upx --best app", "rm -rf /", "upx --best app"]:
        path.write_text(f"import os\nos.system({command!r})\n", encoding="utf-8")
        result = security_scan(tmp_path)
        if command.startswith("rm"):
            assert result["findings"][0]["severity"] == "HIGH"
            assert not result.get("primitive_observations")
        else:
            assert len(result["primitive_observations"]) == 1
            assert not result["findings"]


@pytest.mark.parametrize(
    "mutation", ["duplicate", "unknown", "kind", "malformed", "overflow"]
)
def test_ambiguous_join_is_rejected(tmp_path, mutation):
    lane = _plan()["lanes"][0]

    entry = {
        "id": lane["id"],
        "kind": lane["kind"],
        "target": _command(lane["kind"]),
        "known_bad": _command(lane["kind"], True),
    }

    rows = [entry]

    if mutation == "duplicate":
        rows.append(dict(entry))

    elif mutation == "unknown":
        entry["id"] = "unapproved"

    elif mutation == "kind":
        entry["kind"] = "tenant_isolation"

    elif mutation == "malformed":
        rows.append(None)

    else:
        rows *= 7

    with pytest.raises(RuntimeAuditError) as error:
        evaluate_runtime_audit(_plan(), {"executions": rows}, tmp_path)

    assert error.value.code == "E_AUDIT_EXECUTION_SET"


def test_missing_evidence_stays_incomplete(tmp_path):
    result = evaluate_runtime_audit(_plan(), {"executions": []}, tmp_path)

    assert result["decision"] == "BLOCKED"

    assert all(
        lane["repair_guidance"]["repair_target"] == "audit_evidence"
        for lane in result["lanes"]
    )


@pytest.mark.parametrize("lane", _plan()["lanes"])
def test_all_six_lanes_get_exact_replay_and_no_authority(lane):
    result = repair_guidance({"state": "FAIL", "finding": "REAL_DEFECT"}, lane)

    assert result["repair_target"] == "application_behavior"

    assert result["negative_argv"] == lane["known_bad_argv"]

    assert result["expected_negative_code"] == lane["expected_negative_code"]

    assert result["authority"] == "none"

    assert (
        repair_guidance({"state": "FAIL", "finding": "HOLLOW_RUNTIME_AUDIT"}, lane)[
            "repair_target"
        ]
        == "audit_evidence"
    )


def test_duplicate_plan_lane_cannot_claim_six_lane_coverage():
    plan = _plan()

    plan["lanes"][-1] = plan["lanes"][0]

    with pytest.raises(RuntimeAuditError):
        index_executions(plan, {"executions": []})


def _witness(source, source_bytes=None):
    tree = ast.parse(source)
    source_bytes = source.encode("utf-8") if source_bytes is None else source_bytes
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
        and len(node.args) == 3
    ]
    assert len(calls) == 1
    return closed_declaration_input_witness(
        calls[0],
        "exec",
        source_bytes=source_bytes,
        source_path="case.py",
    )


def test_closed_declaration_input_witness_accepts_exact_alias_declaration():
    witness = _witness(
        "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    )

    assert witness["schema"] == "factory.closed-declaration-input.v1"
    assert witness["disposition"] == "PROVEN_CLOSED_DECLARATION_INPUT"


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int\\nmarker = 1', ctx, None)\n",
            id="extra-statement",
        ),
        pytest.param(
            "def run():\n    ctx = {}\n    exec('type Alias = int\\n', ctx, None)\n",
            id="newline-in-input",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias[T] = list[T]', ctx, None)\n",
            id="type-parameters",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = build_type()', ctx, None)\n",
            id="computed-rhs",
        ),
        pytest.param(
            "def run(custom_ctx):\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', custom_ctx, None)\n",
            id="custom-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    ctx['extra'] = 1\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="precall-context-mutation",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    retain(ctx)\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="context-escape",
        ),
        pytest.param(
            "def run():\n"
            "    exec = replacement\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="shadowed-exec",
        ),
        pytest.param(
            "__builtins__['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutation",
        ),
        pytest.param(
            "import builtins\n"
            "builtins.__dict__['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-dict-exec-mutation",
        ),
        pytest.param(
            "import builtins\n"
            "mutate = setattr\n"
            "mutate(builtins, 'exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutated-through-setter-alias",
        ),
        pytest.param(
            "import builtins\n"
            "builtins.__setattr__('exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutated-through-module-setattr",
        ),
        pytest.param(
            "from builtins import setattr as mutate\n"
            "import builtins\n"
            "mutate(builtins, 'exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-setattr-mutates-builtins-exec",
        ),
        pytest.param(
            "from builtins import __dict__ as namespace\n"
            "namespace['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-builtins-dict-mutates-exec",
        ),
        pytest.param(
            "exec('exec = replacement')\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="exec-rebinds-exec-before-candidate",
        ),
        pytest.param(
            "from builtins import exec as rewrite\n"
            "rewrite('exec = replacement')\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-exec-rebinds-exec-before-candidate",
        ),
        pytest.param(
            "def run(value):\n"
            "    match value:\n"
            "        case exec:\n"
            "            pass\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="match-capture-binds-exec",
        ),
        pytest.param(
            "def run(value):\n"
            "    match value:\n"
            "        case ctx:\n"
            "            pass\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="match-capture-binds-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    import math as ctx\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="import-binds-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    try:\n"
            "        raise ValueError\n"
            "    except Exception as ctx:\n"
            "        pass\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="except-binds-namespace",
        ),
        pytest.param(
            "def run(source):\n    ctx = {}\n    exec(source, ctx, None)\n",
            id="nonliteral-input",
        ),
        pytest.param(
            "def run():\n    ctx = {}\n    exec('type __Alias = int', ctx, None)\n",
            id="dunder-identifier",
        ),
    ],
)
def test_closed_declaration_input_witness_rejects_unproven_variants(source):
    assert _witness(source) == {}


def test_closed_declaration_input_witness_rejects_stale_source_bytes():
    source = "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    changed = source.replace("type Alias = int", "type Alias = str")

    assert _witness(source, changed.encode("utf-8")) == {}


def test_security_scan_keeps_declaration_exec_as_hash_bound_incomplete_observation(
    tmp_path,
):
    import copy
    import hashlib

    from factoryline.review_integrity import partition_proven_primitive_observations
    from factoryline.review_audits import security_scan

    source = "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    source_path = tmp_path / "app.py"
    source_path.write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        row
        for row in report["primitive_observations"]
        if row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )

    assert finding["severity"] == "INFO"
    assert finding["facts"]["schema"] == "factory.closed-declaration-input.v1"
    assert finding["facts"]["disposition"] == "PROVEN_CLOSED_DECLARATION_INPUT"
    assert finding["facts"]["runtime_assurance"] == "INCOMPLETE"
    assert (
        finding["facts"]["source_sha256"]
        == hashlib.sha256(source_path.read_bytes()).hexdigest()
    )

    for mutate in (
        lambda facts: facts.__setitem__("source_sha256", "0" * 64),
        lambda facts: facts.__setitem__(
            "literal_span",
            [
                facts["call_span"][2],
                facts["call_span"][3] + 1,
                facts["call_span"][2],
                facts["call_span"][3] + 2,
            ],
        ),
    ):
        tampered = copy.deepcopy(report)
        tampered_finding = tampered["primitive_observations"][0]
        mutate(tampered_finding["facts"])
        partition_proven_primitive_observations(tampered)

        assert tampered["primitive_observations"] == []
        rejected = tampered["findings"][0]
        assert rejected["severity"] == "HIGH"
        assert rejected["facts"]["disposition"] == "UNVERIFIED_FIXED_PROGRAM"
        assert rejected["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"


SOURCE = 'types = [(eval(tp), expected) for tp, expected in [("list[Person]", True), ("tuple[Person, ...]", False)]]\n'


def witness(source, raw=None):
    tree = ast.parse(source)
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "eval"
    )
    return finite_literal_eval_input_witness(
        call, "eval", source_bytes=raw or source.encode(), source_path="case.py"
    )


def test_finite_eval_literal_domain_records_input_only():
    facts = witness(SOURCE)
    assert facts["domain_size"] == 2
    assert facts["runtime_assurance"] == "INCOMPLETE"
    assert facts["target_execution"] == "not_performed"


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace('"list[Person]"', "payload"),
        SOURCE.replace('"list[Person]"', '"factory()"'),
        SOURCE.replace('"list[Person]"', '"Person.attr"'),
        SOURCE.replace(
            "for tp, expected in", "for tp, expected in supplied for unused in"
        ),
        SOURCE.replace("eval(tp)", "eval(tp, supplied)"),
        SOURCE.replace("eval(tp)", "eval((tp := supplied))"),
        SOURCE.replace("eval(tp)", "eval(tp + supplied)"),
        SOURCE.replace("eval(tp)", "eval(tp) if expected else expose(tp)"),
        "eval = replacement\n" + SOURCE,
        'from builtins import exec as rewrite\nrewrite("eval = replacement")\n'
        + SOURCE,
        SOURCE.replace('"list[Person]"', '"[x for x in source]"'),
        SOURCE.replace('[("list[Person]", True), ("tuple[Person, ...]", False)]', "[]"),
    ],
)
def test_finite_eval_rejects_open_or_executable_inputs(source):
    assert witness(source) == {}


def test_finite_eval_rejects_stale_ast():
    assert witness(SOURCE, SOURCE.replace("eval(tp)", "eval(other)").encode()) == {}


def test_finite_eval_recomputes_changed_domain_from_current_bytes():
    old = witness(SOURCE)
    new = witness(SOURCE, SOURCE.replace("Person", "Other").encode())
    assert old["source_sha256"] != new["source_sha256"]
    assert old["program_sha256"] != new["program_sha256"]


def test_finite_eval_ignores_later_uninvoked_function_effects():
    assert (
        witness(SOURCE + '\ndef later():\n    delattr(NoParams, "__parameters__")\n')[
            "domain_size"
        ]
        == 2
    )


def test_finite_eval_rejects_prior_function_invocation():
    source = 'def rewrite():\n    globals()["eval"] = replacement\nrewrite()\n' + SOURCE
    assert witness(source) == {}


def test_finite_eval_native_scan_retains_primitive(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(SOURCE)
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert (
        report["primitive_observations"][0]["facts"]["disposition"]
        == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
    )


@pytest.mark.parametrize(
    "source",
    [
        'types = [(lambda tp: eval(tp)) for tp, expected in [("list[Person]", True)]]\n',
        "from arbitrary import eval\n" + SOURCE,
        "from arbitrary import replacement as eval\n" + SOURCE,
        SOURCE.replace('"list[Person]", True', '"list[Person]", rewrite()'),
    ],
)
def test_finite_eval_rejects_shadowed_or_effectful_table(source):
    assert witness(source) == {}


def test_finite_eval_partition_rejects_unrelated_domain_span(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(SOURCE)
    report = security_scan(tmp_path, cache_enabled=False)
    report["primitive_observations"][0]["facts"]["domain_span"] = [999, 0, 999, 1]
    partition_proven_primitive_observations(report)
    assert not report["primitive_observations"]
    assert report["findings"][0]["severity"] == "HIGH"


_SOURCE_GENERATED_TEMPLATE = """from sqlalchemy import Index
from sqlalchemy import text

def build(config):
    return [
        (
            eval(f'lambda t: Index("idx", text({conn!r}), _table=t)'),
            eval(f'lambda t: Index("idx", text({meta!r}), _table=t)'),
            config.requirements.reflects_indexes_column_sorting,
        )
        for meta, conn in __DOMAIN__
    ]
"""
_SOURCE_GENERATED_ROWS = """(
    ("z nulls first", "z nulls first"),
    ("z nulls last", "z"),
)"""
_SOURCE_GENERATED = _SOURCE_GENERATED_TEMPLATE.replace(
    "__DOMAIN__", _SOURCE_GENERATED_ROWS
)


def _source_generated_facts(source=_SOURCE_GENERATED, *, identity=True):
    tree = ast.parse(source)
    calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "eval"
    ]
    return [
        source_generated_eval_input_witness(
            call,
            "eval",
            source_bytes=source.encode(),
            source_path="tests/test_autogen_indexes.py",
            builtin_identity_proven=identity,
        )
        for call in calls
    ]


def test_source_generated_eval_proves_bounded_literal_rows_only():
    facts = _source_generated_facts()
    assert len(facts) == 2
    assert all(item["domain_size"] == 2 for item in facts)
    assert all(
        item["scope_profile"] == "single-comprehension-source-template"
        and item["input_effect"] == "CLOSED_SOURCE_GENERATED_STRINGS"
        and item["runtime_assurance"] == "INCOMPLETE"
        and item["target_execution"] == "not_performed"
        for item in facts
    )
    assert len({item["program_sha256"] for item in facts}) == 2
    assert _source_generated_facts(identity=False) == [{}, {}]


def test_source_generated_eval_obeys_domain_and_rendered_byte_caps():
    domain_overflow = (
        "(" + ",".join(f'("meta-{index}", "conn-{index}")' for index in range(65)) + ")"
    )
    value = "x" * 1100
    rendered_byte_overflow = (
        "(" + ",".join(f"({value!r}, {value!r})" for _ in range(9)) + ")"
    )
    assert _source_generated_facts(
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", domain_overflow)
    ) == [{}, {}]
    assert _source_generated_facts(
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", rendered_byte_overflow)
    ) == [{}, {}]


@pytest.mark.parametrize(
    "source",
    [
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", "supplied_rows"),
        _SOURCE_GENERATED_TEMPLATE.replace(
            "__DOMAIN__", "(" + _SOURCE_GENERATED_ROWS + " if config.enabled else ())"
        ),
        _SOURCE_GENERATED_TEMPLATE.replace(
            "__DOMAIN__", '((provider(), "z"), ("meta", "conn"))'
        ),
        _SOURCE_GENERATED.replace("{conn!r}", "{config.value!r}"),
        _SOURCE_GENERATED.replace("{conn!r}", "{(conn := config.value)!r}"),
    ],
)
def test_source_generated_eval_rejects_alias_branch_provider_and_external_values(
    source,
):
    assert _source_generated_facts(source) == [{}, {}]


def test_source_generated_eval_native_scan_keeps_builtin_alias_high(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text("eval = replacement\n" + _SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report.get("primitive_observations", []) == []
    assert len(report["findings"]) == 2
    assert all(item["severity"] == "HIGH" for item in report["findings"])


def test_source_generated_eval_native_scan_partitions_both_closed_calls(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert len(report["primitive_observations"]) == 2
    assert all(
        item["facts"]["disposition"] == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
        and item["facts"]["input_effect"] == "CLOSED_SOURCE_GENERATED_STRINGS"
        for item in report["primitive_observations"]
    )


def test_source_generated_eval_partition_rejects_tampered_effect(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    for item in report["primitive_observations"]:
        item["facts"]["input_effect"] = "USER_CONTROLLED"
    partition_proven_primitive_observations(report)
    assert report["primitive_observations"] == []
    assert len(report["findings"]) == 2
    assert all(item["severity"] == "HIGH" for item in report["findings"])


_JSON_ENUM = """from enum import Enum
class ErrorCode(str, Enum):
    REGISTER_INVALID_PASSWORD = "REGISTER_INVALID_PASSWORD"
"""
_JSON_CLIENT = """import pytest
import httpx
from asgi_lifespan import LifespanManager
@pytest.fixture
def get_test_client():
    async def make_client(app):
        async with LifespanManager(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
                yield client
    return make_client
"""
_JSON_TEST = """from typing import Any, cast
import pytest_asyncio
from fastapi import FastAPI
from common import ErrorCode
@pytest_asyncio.fixture
async def app_client(get_test_client):
    app = FastAPI()
    async for client in get_test_client(app):
        yield client
async def test_invalid_password(app_client):
    response = await app_client.post("/register", json={})
    assert response.status_code == 400
    data = cast(dict[str, Any], response.json())
    assert data["detail"] == {"code": ErrorCode.REGISTER_INVALID_PASSWORD}
"""


def _json_enum_graph(
    tmp_path,
    *,
    test_source=_JSON_TEST,
    client_source=_JSON_CLIENT,
    enum_source=_JSON_ENUM,
    extra_sources=None,
    reverse_sources=False,
    stale=False,
    consumer_type=None,
):
    import hashlib
    from factoryline import review_audits, review_integrity
    from factoryline.runtime_audit_integrity import _LiteralConsumers

    root = tmp_path.resolve()
    root.mkdir(parents=True, exist_ok=True)
    sources = {
        "common.py": enum_source,
        "conftest.py": client_source,
        "test_api.py": test_source,
    }
    sources.update(extra_sources or {})
    if reverse_sources:
        sources = dict(reversed(tuple(sources.items())))
    raw = {root / name: source.encode() for name, source in sources.items()}
    for path, source in raw.items():
        path.write_bytes(source)
    trees = {path: ast.parse(source) for path, source in raw.items()}
    inventory = {
        path: hashlib.sha256(source).hexdigest() for path, source in raw.items()
    }
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
    eligible = {path.resolve(): path for path in trees}
    imports = {
        path: review_audits._oracle_imports(root, path, tree, eligible)
        for path, tree in trees.items()
    }
    if stale:
        inventory[root / "common.py"] = "0" * 64
    return (consumer_type or _LiteralConsumers)(
        root,
        trees,
        imports,
        review_audits,
        review_integrity,
        source_bytes=raw,
        inventory=inventory,
    )


class _LegacyLiteralConsumers:
    def __new__(cls, *args, **kwargs):
        from factoryline.runtime_audit_integrity import _LiteralConsumers

        legacy_type = type(
            "LegacyLiteralConsumers",
            (_LiteralConsumers,),
            {
                "_walk": cls._walk,
                "_references": cls._references,
                "_provider_uses": cls._provider_uses,
            },
        )
        return legacy_type(*args, **kwargs)

    @staticmethod
    def _walk(self, node):
        for child in ast.walk(node):
            if not self._tick():
                return
            yield child

    @staticmethod
    def _references(self):
        for path, tree in self.trees.items():
            for node in self._walk(tree):
                if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                    continue
                if self._fixture_parameter_value(path, node.id, node):
                    continue
                end = node
                while (
                    isinstance(self.parents.get(id(end)), ast.Attribute)
                    and self._tick()
                ):
                    end = self.parents[id(end)]
                ref = self.resolve(path, tuple(self.audit._name(end).split(".")))
                if ref is not None:
                    if ref[0] == "module" and self._relevant_origin(ref[1], None):
                        self.complete = False
                    self.refs[ref[:3]].append((path, end, ref[3]))

    @staticmethod
    def _provider_uses(self):
        providers = {"enum.Enum", "fastapi.HTTPException", "fastapi.APIRouter"}
        for path, tree in self.trees.items():
            aliases = self.audit._module_security_aliases(
                ast.Module(
                    body=[
                        item
                        for item in self._walk(tree)
                        if isinstance(item, (ast.Import, ast.ImportFrom))
                    ],
                    type_ignores=[],
                )
            )
            for node in self._walk(tree):
                if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                    continue
                api = aliases.get(node.id, "")
                if api not in providers | {"enum", "fastapi"}:
                    continue
                end = node
                while (
                    isinstance(self.parents.get(id(end)), ast.Attribute)
                    and self._tick()
                ):
                    end = self.parents[id(end)]
                tail = self.audit._name(end).split(".")[1:]
                resolved = ".".join([api, *tail])
                parent = self.parents.get(id(end))
                valid = (
                    resolved == "enum.Enum"
                    and isinstance(parent, ast.ClassDef)
                    and end in parent.bases
                    or resolved in providers - {"enum.Enum"}
                    and isinstance(parent, ast.Call)
                    and parent.func is end
                    or resolved == "fastapi.APIRouter"
                    and isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and parent.returns is end
                )
                if not valid:
                    self.complete = False


def _literal_witness_rows(graph):
    return sorted(
        (
            path.relative_to(graph.root).as_posix(),
            line,
            member,
            json.dumps(rows, sort_keys=True, separators=(",", ":")),
        )
        for (path, line, member), rows in graph.witnesses().items()
    )


def _literal_reference_rows(graph):
    return sorted(
        (
            origin[0],
            origin[2],
            path.relative_to(graph.root).as_posix(),
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
            tail,
        )
        for origin, refs in graph.refs.items()
        for path, node, tail in refs
    )


def _literal_blocked_rows(graph):
    return sorted(
        (path.relative_to(graph.root).as_posix(), name) for path, name in graph.blocked
    )


def test_literal_consumer_owner_and_epoch_dependencies_follow_provenance(monkeypatch):
    from factoryline import provenance, review_integrity
    from factoryline.runtime_audit_integrity import _LiteralConsumers as runtime_owner

    owner = provenance._LiteralConsumers
    assert owner is runtime_owner is review_integrity._LiteralConsumers
    original = owner._walk

    def replacement(self, node):
        return original(self, node)

    monkeypatch.setattr(owner, "_walk", replacement)
    dependencies = provenance.credential_consumer_helpers(review_integrity)
    assert replacement in dependencies
    assert original not in dependencies


def test_literal_consumer_shared_index_matches_legacy_walk_below_caps(tmp_path):
    import hashlib

    optimized = _json_enum_graph(tmp_path / "optimized")
    legacy = _json_enum_graph(
        tmp_path / "legacy", consumer_type=_LegacyLiteralConsumers
    )

    assert optimized.snapshot_complete == legacy.snapshot_complete is True
    assert optimized.complete == legacy.complete is True
    assert _literal_witness_rows(optimized) == _literal_witness_rows(legacy)
    assert _literal_reference_rows(optimized) == _literal_reference_rows(legacy)
    assert _literal_blocked_rows(optimized) == _literal_blocked_rows(legacy)
    assert sorted(
        (path.relative_to(optimized.root).as_posix(), name)
        for path, name in optimized.unmodeled_imports
    ) == sorted(
        (path.relative_to(legacy.root).as_posix(), name)
        for path, name in legacy.unmodeled_imports
    )
    for path, (_, _, _, load_names, provider_imports) in optimized.file_indexes.items():
        assert all(isinstance(node.ctx, ast.Load) for node in load_names)
        assert all(
            isinstance(node, (ast.Import, ast.ImportFrom)) for node in provider_imports
        )
        assert (
            hashlib.sha256(optimized.source_bytes[path]).hexdigest()
            == (optimized.inventory[path])
        )


def test_literal_consumer_marker_filter_keeps_budget_exhaustion_fail_closed(
    tmp_path,
):
    import hashlib
    from factoryline import review_audits, review_integrity
    from factoryline.runtime_audit_integrity import _LiteralConsumers

    root = tmp_path.resolve()
    source = "x=foo.bar+foo.baz\n" * 30_000
    path = root / "large.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = source.encode()
    path.write_bytes(raw)
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    snapshots = {path: tree}
    source_bytes = {path: raw}
    inventory = {path: digest}
    imports = {path: {}}
    graph = _LiteralConsumers(
        root,
        snapshots,
        imports,
        review_audits,
        review_integrity,
        source_bytes=source_bytes,
        inventory=inventory,
    )

    assert not graph.complete
    assert not graph.snapshot_complete
    assert not graph.witnesses()


def test_public_enum_json_requires_actual_client_origin(tmp_path):
    graph = _json_enum_graph(tmp_path)
    result = graph.witnesses()
    assert graph.complete
    assert (tmp_path.resolve() / "common.py", 3, "REGISTER_INVALID_PASSWORD") in result


def test_provider_mutation_index_precedes_fixture_decisions(tmp_path):
    fixture = (
        "import pytest\n"
        "@pytest.fixture\ndef client(): pass\n"
        "def test_client(client): pass\n"
    )
    mutations = (
        "import pytest\npytest.fixture = supplied\n",
        "import pytest as pt\npt = supplied\n",
        "import pytest\npytest.fixture.__code__ = supplied\n",
        "import pytest\npytest.fixture.nested.attribute = supplied\n",
    )
    for reverse in (False, True):
        for index, mutation in enumerate(mutations):
            case = tmp_path / f"case_{reverse}_{index}"
            graph = _json_enum_graph(
                case,
                extra_sources={"a_fixture.py": fixture, "z_mutation.py": mutation},
                reverse_sources=reverse,
            )
            assert not graph._provider_is_unmodified("pytest", {"fixture"})
            assert not graph.witnesses()


def test_public_enum_witness_is_snapshot_order_independent(tmp_path):
    graph = _json_enum_graph(tmp_path, reverse_sources=True)
    assert graph.complete
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) in graph.witnesses()


def test_public_enum_json_accepts_scalar_detail_comparison(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) in graph.witnesses()


def test_public_enum_scalar_json_retains_signing_consumer(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    enum_source = (
        _JSON_ENUM + "\nsigned = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n"
    )
    graph = _json_enum_graph(tmp_path, test_source=source, enum_source=enum_source)
    assert graph.complete
    assert not graph.witnesses()


def test_public_enum_scalar_json_rejects_custom_equality(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    enum_source = _JSON_ENUM + "    def __eq__(self, other):\n        return True\n"
    graph = _json_enum_graph(tmp_path, test_source=source, enum_source=enum_source)
    assert graph.complete
    assert not graph.witnesses()


@pytest.mark.parametrize(
    "mutation",
    [
        "    __eq__ = replacement\n",
        "\nErrorCode.__eq__ = replacement\n",
    ],
)
def test_public_enum_scalar_json_rejects_equality_binding_mutation(tmp_path, mutation):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    graph = _json_enum_graph(
        tmp_path, test_source=source, enum_source=_JSON_ENUM + mutation
    )
    assert graph.complete
    assert not graph.witnesses()


def test_public_enum_scalar_json_native_observation_is_source_bound(tmp_path):
    from factoryline.review_audits import security_scan

    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    _json_enum_graph(tmp_path, test_source=source)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["audit_coverage"]["complete"]
    assert not any(
        row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
    )
    observations = report.get("primitive_observations", [])
    assert len(observations) == 1
    assert (
        observations[0]["facts"]["disposition"] == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
    )
    assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"


@pytest.mark.parametrize("escape", [None, "test_app", "schema"])
def test_returned_app_tracks_keyword_only_fixture_consumers(tmp_path, escape):
    source = _JSON_TEST.replace(
        "async def app_client(get_test_client):\n    app = FastAPI()",
        "def test_app():\n    app = FastAPI()\n    return app\n"
        "@pytest_asyncio.fixture\nasync def app_client(test_app, get_test_client):",
    ).replace("get_test_client(app):", "get_test_client(test_app):")
    source += (
        "\n@pytest_asyncio.fixture\ndef schema(test_app):\n    return test_app.openapi()\n"
        "def test_schema(schema):\n    route = schema['paths']['/register']['post']\n"
        "    assert list(route['responses'].keys()) == ['400']\n"
    )
    if escape:
        source += f"\ndef test_opaque(*, {escape}):\n    opaque({escape})\n"
    graph = _json_enum_graph(tmp_path, test_source=source)
    path = tmp_path.resolve() / "test_api.py"
    fixture = next(
        node
        for node in graph.trees[path].body
        if getattr(node, "name", None) == "test_app"
    )
    assert graph._returned_app_fixture_closed(path, fixture, "app") is (escape is None)


def test_public_enum_native_cold_warm_and_source_invalidation(tmp_path):
    from factoryline.review_audits import security_scan

    _json_enum_graph(tmp_path)
    for cache in (False, True, True):
        report = security_scan(tmp_path, cache_enabled=cache)
        assert not any(
            row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
        )
        observations = report.get("primitive_observations", [])
        assert len(observations) == 1
        assert (
            observations[0]["facts"]["disposition"]
            == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
        )
        assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"
    with (tmp_path / "common.py").open("a") as stream:
        stream.write("signed = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n")
    report = security_scan(tmp_path, cache_enabled=True)
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])
    assert not report.get("primitive_observations")


def test_public_enum_native_incomplete_source_denies_admission(tmp_path):
    from factoryline.review_audits import security_scan

    _json_enum_graph(tmp_path)
    (tmp_path / "missing_flow.py").write_text("def broken(:\n")
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])
    assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "field,value",
    [
        ("declaration_span", [3, 4, 999, 1]),
        ("name", "OTHER_PASSWORD"),
        ("source_profiles", [{"invocation": "invented"}]),
    ],
)
def test_public_enum_receipt_rejects_changed_facts(tmp_path, field, value):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    _json_enum_graph(tmp_path)
    report = security_scan(tmp_path, cache_enabled=False)
    report["primitive_observations"][0]["facts"][field] = value
    partition_proven_primitive_observations(report)
    assert not report["primitive_observations"]
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])


@pytest.mark.parametrize(
    "mutation",
    [
        "signing",
        "client_rebind",
        "data_rebind",
        "json_replacement",
        "client_hooks",
        "provider_rebind",
        "stale_source",
        "client_import",
        "client_except",
        "client_match",
        "client_method",
        "client_escape",
        "response_escape",
        "class_fixture_override",
        "helper_rebind",
        "yield_client_escape",
        "response_setattr",
        "module_fixture_alias",
        "provider_fixture_alias",
        "local_httpx_shadow",
        "local_manager_shadow",
    ],
)
def test_public_enum_json_retains_unproven_consumers(tmp_path, mutation):
    source, client, enum = _JSON_TEST, _JSON_CLIENT, _JSON_ENUM
    source_replacements = {
        "client_rebind": (
            "    response =",
            "    app_client = replacement\n    response =",
        ),
        "data_rebind": ("    assert data[", "    data = replacement\n    assert data["),
        "json_replacement": (
            "    data =",
            "    response.json = replacement\n    data =",
        ),
        "helper_rebind": ("    app =", "    get_test_client = replacement\n    app ="),
        "yield_client_escape": (
            "        yield client",
            "        opaque(client)\n        yield client",
        ),
        "response_setattr": (
            "    data =",
            "    response.__setattr__('json', replacement)\n    data =",
        ),
    }
    client_replacements = {
        "client_hooks": (
            'base_url="http://test"',
            'base_url="http://test", event_hooks={"response": [replacement]}',
        ),
        "local_httpx_shadow": (
            "        async with",
            "        httpx = replacement\n        async with",
        ),
        "local_manager_shadow": (
            "    async def make_client",
            "    LifespanManager = replacement\n    async def make_client",
        ),
    }
    client += {
        "provider_rebind": "httpx.AsyncClient = replacement\n",
        "provider_fixture_alias": "\n@pytest.fixture(name='get_test_client')\ndef override():\n    return replacement\n",
    }.get(mutation, "")
    source += {
        "module_fixture_alias": "\n@pytest_asyncio.fixture(name='app_client')\nasync def override():\n    yield replacement\n"
    }.get(mutation, "")
    enum += {"signing": "signed = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n"}.get(
        mutation, ""
    )
    if mutation in source_replacements:
        source = source.replace(*source_replacements[mutation])
    elif mutation in client_replacements:
        client = client.replace(*client_replacements[mutation], 1)
    elif mutation in {
        "client_import",
        "client_except",
        "client_match",
        "client_method",
        "client_escape",
        "response_escape",
    }:
        statements = {
            "client_import": "    import arbitrary as app_client\n",
            "client_except": "    try:\n        pass\n    except Exception as app_client:\n        pass\n",
            "client_match": '    match replacement:\n        case {"client": app_client}:\n            pass\n',
            "client_method": "    app_client.post = replacement\n",
            "client_escape": "    opaque(app_client)\n",
            "response_escape": "    opaque(response)\n",
        }
        anchor = "    data =" if mutation == "response_escape" else "    response ="
        source = source.replace(anchor, statements[mutation] + anchor)
    elif mutation == "class_fixture_override":
        prefix, body = source.split("async def test_invalid_password", 1)
        override = (
            "class TestOverride:\n    @pytest_asyncio.fixture\n"
            "    async def app_client(self):\n        yield replacement\n"
        )
        method = "async def test_invalid_password" + body
        method = method.replace(
            "test_invalid_password(app_client)",
            "test_invalid_password(self, app_client)",
        )
        source = (
            prefix + override + "\n".join("    " + line for line in method.splitlines())
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source=source,
        client_source=client,
        enum_source=enum,
        stale=mutation == "stale_source",
    )
    assert not graph.witnesses()
    if mutation != "stale_source":
        from factoryline.review_audits import security_scan

        report = security_scan(tmp_path, cache_enabled=False)
        assert any(
            row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
        )
        assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "target,domain",
    [
        ("value", "((1,),)"),
        ("(value,)", "(b'x',)"),
        ("(value,)", "('x',)"),
        ("(value,)", "(1,)"),
        ("(value,value)", "((1,2),)"),
    ],
)
def test_source_generated_eval_rejects_mismatched_unpacking(target, domain):
    source = f"items = [(eval(f'lambda: {{value!r}}'),) for {target} in {domain}]\n"
    assert _source_generated_facts(source) == [{}]


def test_source_generated_eval_receipt_hash_matches_exact_rendered_strings():
    import hashlib
    import json

    source = "items = [(eval(f'lambda: {value!r}'),) for value in ('a', 'b')]\n"
    facts = _source_generated_facts(source)[0]
    programs = ["lambda: 'a'", "lambda: 'b'"]
    assert (
        facts["program_sha256"]
        == hashlib.sha256(
            json.dumps(programs, separators=(",", ":")).encode()
        ).hexdigest()
    )


@pytest.mark.parametrize("field", ["scope_profile", "input_effect"])
@pytest.mark.parametrize("value", [[], {}, 3, None])
def test_source_generated_eval_partition_rejects_unhashable_or_wrong_fact_types(
    tmp_path, field, value
):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert len(report["primitive_observations"]) == 2
    report["primitive_observations"][0]["facts"][field] = value
    partition_proven_primitive_observations(report)
    assert len(report["primitive_observations"]) == 1
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "prefix",
    [
        "import builtins\nbuiltins.eval = replacement\n",
        "exec('eval = replacement')\n",
        "saved = eval\n",
    ],
)
def test_source_generated_eval_rejects_provider_mutation_or_escape(tmp_path, prefix):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(prefix + _SOURCE_GENERATED, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report.get("primitive_observations")
    assert (
        sum(
            item["code"] == "SECURITY_DYNAMIC_EXECUTION" and item["severity"] == "HIGH"
            for item in report["findings"]
        )
        >= 2
    )


def test_source_generated_helpers_are_included_in_verifier_source_identity():
    from factoryline import runtime_audit_integrity as runtime

    helpers = set(runtime.workspace_builtin_helpers())
    expected = {
        value
        for name, value in vars(runtime).items()
        if name.startswith("_source_eval_") and callable(value)
    }
    assert expected <= helpers
    assert runtime.finite_eval_binding in helpers


@pytest.mark.parametrize(
    "name",
    [
        "_exact_source_call",
        "_source_span",
        "_closed_declaration_source_call",
        "_fixed_program_call_context",
        "_fixed_program_literal_span",
        "_source_generated_eval_capture",
        "_source_eval_call_shape",
        "_source_eval_source_bound",
        "_finite_eval_profile",
        "_finite_eval_domain_digest",
        "_finite_eval_spans",
    ],
)
@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_extracted_runtime_helpers_invalidate_native_cache(
    tmp_path, monkeypatch, name, mutation
):
    from factoryline import review_audits as audit
    from factoryline import runtime_audit_integrity as runtime

    original = getattr(runtime, name)
    assert original in runtime.workspace_builtin_helpers()
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    with monkeypatch.context() as patch:
        if mutation == "binding":
            patch.setattr(runtime, name, replacement)
        else:
            patch.setattr(original, "__code__", replacement.__code__)
        assert audit._oracle_context_cache_key(tmp_path, [], {}) != before
    assert audit._oracle_context_cache_key(tmp_path, [], {}) == before


def test_tenant_scope_read_retains_unique_binding_and_rejects_ambiguity():
    row = runtime.tenant_scope_read(
        review_audits, "Tenant.get", {"Tenant.get": ["tenant_id"]}
    )
    assert row == {"call": "Tenant.get", "binding": "tenant_id"}
    assert runtime.tenant_scope_read(review_audits, "Tenant.list", {}) == {
        "call": "Tenant.list"
    }
    with pytest.raises(review_audits.ReviewAuditError, match="at most one binding"):
        runtime.tenant_scope_read(
            review_audits, "Tenant.get", {"Tenant.get": ["a", "b"]}
        )


def test_validate_tenant_scopes_revalidates_and_returns_scoped_reads(tmp_path):
    (tmp_path / "app.py").write_text(
        "class Tenant:\n    pass\ndef load(tenant_id):\n    return Tenant.get(tenant_id=tenant_id)\n",
        encoding="utf-8",
    )
    scopes = {
        "app.py": {
            "calls": ["Tenant.get"],
            "bindings": {"Tenant.get": ["keyword:tenant_id:tenant_id"]},
        }
    }
    result = runtime.validate_tenant_scopes(review_audits, tmp_path, scopes)
    assert result["app.py"]["calls"] == ("Tenant.get",)
    assert result["app.py"]["bindings"] == {
        "Tenant.get": ("keyword:tenant_id:tenant_id",)
    }
    with pytest.raises(review_audits.ReviewAuditError):
        runtime.validate_tenant_scopes(
            review_audits, tmp_path, {"../escape.py": scopes["app.py"]}
        )


def test_fixed_literal_program_witness_binds_literal_bytes_and_refuses_mutation():
    raw = b"exec('answer = 42')\n"
    call = next(node for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.Call))
    witness = runtime.fixed_literal_program_witness(
        call,
        "exec",
        source_bytes=raw,
        builtin_identity_proven=True,
        source_path="app.py",
        scope_profile="module",
    )
    assert witness["disposition"] == "PROVEN_FIXED_LITERAL_PROGRAM"
    assert witness["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert witness["profile"]["target_execution"] == "not_performed"
    dynamic = b"exec(input())\n"
    dynamic_call = next(
        node for node in ast.walk(ast.parse(dynamic)) if isinstance(node, ast.Call)
    )
    assert (
        runtime.fixed_literal_program_witness(
            dynamic_call,
            "exec",
            source_bytes=dynamic,
            builtin_identity_proven=True,
            source_path="app.py",
        )
        == {}
    )


def _local_eval_witness(source):
    raw = source if isinstance(source, bytes) else source.encode()
    tree = ast.parse(raw)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "eval"
    ]
    assert len(calls) == 1
    return (
        raw,
        calls[0],
        runtime.fixed_literal_program_witness(
            calls[0],
            "eval",
            source_bytes=raw,
            builtin_identity_proven=True,
            source_path="sample.py",
            scope_profile="function",
        ),
    )


def test_local_eval_overwrite_decode_witness_binds_full_chain_and_overwritten_input():
    raw, call, witness = _local_eval_witness(
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = body.decode()
    result = eval(text)
    return result
"""
    )
    proof = witness["def_use_witness"]
    assert witness["disposition"] == "PROVEN_FIXED_LITERAL_PROGRAM"
    assert witness["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert witness["call_span"] == [
        call.lineno,
        call.col_offset,
        call.end_lineno,
        call.end_col_offset,
    ]
    assert proof["schema"] == "factory.fixed-program-local-def-use.v1"
    assert proof["target_execution"] == "not_performed"
    assert [row["operation"] for row in proof["reaching_definitions"]] == [
        "LITERAL_ASSIGNMENT",
        "BUILTIN_BYTES_DECODE",
    ]
    assert [row["operation"] for row in proof["overwritten_definitions"]] == [
        "EXTERNAL_BODY_READ"
    ]
    assert proof["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert witness["profile"]["input_resolution"] == "ordered-local-strong-updates"


@pytest.mark.parametrize(
    "source",
    [
        b"""def handler(request):
    body = request.body
    text = body.decode()
    return eval(text)
""",
        b"""def handler(request, enabled):
    body = request.body
    if enabled:
        body = b"{'flag': 1}"
    text = body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    text = body.decode()
    result = eval(text)
    body = b"{'flag': 1}"
    return result
""",
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = body.decode()
    text = request.body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    body = b"__import__('os').system('whoami')"
    text = body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = request.body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = body.decode('ascii')
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = body.decode()
    eval = lambda value: value
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    for item in (1,):
        body = b"{'flag': 1}"
    text = body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = request.body
    try:
        body = b"{'flag': 1}"
    except Exception:
        pass
    text = body.decode()
    return eval(text)
""",
        b"""def handler(request):
    body = maybe_replace(request.body)
    body = b"{'flag': 1}"
    text = body.decode()
    return eval(text)
""",
    ],
)
def test_local_eval_unknown_or_executable_input_keeps_alert(source):
    _, _, witness = _local_eval_witness(source)
    assert witness == {}


def test_local_eval_def_use_binding_recomputes_source_and_rejects_stale_or_forged_chain():
    raw, call, witness = _local_eval_witness(
        b"""def handler(request):
    body = request.body
    body = b"{'flag': 1}"
    text = body.decode()
    return eval(text)
"""
    )
    source_hash = hashlib.sha256(raw).hexdigest()
    sources = [{"path": "sample.py", "sha256": source_hash}]
    workspace_hash = hashlib.sha256(
        json.dumps([("sample.py", source_hash)], separators=(",", ":")).encode()
    ).hexdigest()
    witness["workspace_sources_sha256"] = workspace_hash
    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "path": "sample.py",
        "line": call.lineno,
        "column": call.col_offset,
        "severity": "INFO",
        "facts": {"call": "eval", **witness},
    }
    source_bytes = {"sample.py": raw}
    bindings = {"sample.py": source_hash}
    assert primitive.fixed_primitive_binding(
        finding, sources, bindings, review_audits, source_bytes
    )
    assert not primitive.fixed_primitive_binding(
        finding, sources, bindings, review_audits
    )

    forged = json.loads(json.dumps(finding))
    forged["facts"]["def_use_witness"]["reaching_definitions"][0]["operation"] = (
        "LOCAL_ALIAS"
    )
    assert not primitive.fixed_primitive_binding(
        forged, sources, bindings, review_audits, source_bytes
    )
    stripped = json.loads(json.dumps(finding))
    stripped["facts"].pop("def_use_witness")
    assert not primitive.fixed_primitive_binding(
        stripped, sources, bindings, review_audits
    )
    assert not primitive.fixed_primitive_binding(
        stripped, sources, bindings, review_audits, source_bytes
    )

    changed = raw.replace(b"body = b\"{'flag': 1}\"", b"body = request.body")
    assert not primitive.fixed_primitive_binding(
        finding,
        sources,
        bindings,
        review_audits,
        {"sample.py": changed},
    )


def test_workspace_builtin_profile_requires_complete_hashable_snapshot(tmp_path):
    path = tmp_path / "a.py"
    tree = ast.parse("value = 1\n")
    tree._oracle_source_sha256 = hashlib.sha256(
        path.read_bytes() if path.exists() else b"value = 1\n"
    ).hexdigest()
    profile = runtime.workspace_builtin_profile({path: tree}, [path])
    assert profile["complete"] is True
    assert profile["namespace_mutation_risk"] is False
    shadowed = ast.parse("globals()['exec']('x=1')\n")
    shadowed._oracle_source_sha256 = tree._oracle_source_sha256
    assert (
        runtime.workspace_builtin_profile({path: shadowed}, [path])[
            "namespace_mutation_risk"
        ]
        is True
    )


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as bi\nbi.eval = replacement\n",
        "import builtins as bi\nsetattr(bi, 'eval', replacement)\n",
        "import builtins as bi\nalias = bi\nalias.eval = replacement\n",
        "import builtins as bi\nunknown_consumer(bi)\n",
        "from builtins import __import__ as load\nload('builtins').eval = replacement\n",
        "import sys\nsys.modules['builtins'].eval = replacement\n",
        "import sys as runtime\nruntime.modules['builtins'].__dict__['eval'] = replacement\n",
        "from sys import modules as registry\nregistry['builtins'].eval = replacement\n",
        "import sys\nprovider = sys.modules['builtins']\nprovider.eval = replacement\n",
        "from builtins import __dict__ as namespace\nnamespace['eval'] = replacement\n",
        "eval(\"setattr(__import__('builtins'), 'eval', replacement)\")\n",
        'exec("import builtins; builtins.eval = replacement")\n',
        "def mutate(payload):\n    eval(payload)\nmutate(\"setattr(__import__('builtins'), 'eval', replacement)\")\n",
        "def mutate(payload):\n    eval(payload)\nalias = mutate\nalias(payload)\n",
        "def mutate(payload):\n    eval(payload)\ncallbacks = [mutate]\ncallbacks[0](payload)\n",
        "def make(value=eval(payload)):\n    pass\n",
        "@eval(payload)\ndef make():\n    pass\n",
        "def make(value: eval(payload)):\n    pass\n",
        "class Installer:\n    def __init__(self, payload):\n        eval(payload)\nInstaller(payload)\n",
        "class Installer:\n    def __init__(self, payload):\n        eval(payload)\nAlias = Installer\nAlias(payload)\n",
        "class Installer(Base):\n    pass\nInstaller()\n",
        "eval(provider_code)\n",
        "exec(provider_code)\n",
        "import importlib as il\nil.import_module(module_name)\n",
        "from importlib import import_module as load\nload(module_name)\n",
        "__import__(module_name)\n",
    ],
)
def test_fixed_eval_provider_risk_fails_closed_for_mutation_aliases_and_imports(source):
    tree = ast.parse(source)
    assert runtime._fixed_eval_builtin_provider_risk(tree)


@pytest.mark.parametrize(
    "source",
    [
        "import sys\ninstall(sys.modules['builtins'])\n",
        "import sys\ninstall(sys.modules)\n",
        "import sys\ninstall(provider=sys.modules['builtins'])\n",
        "import sys\ninstall(registry=sys.modules)\n",
        "import sys\ninstall(**{'provider': sys.modules['builtins']})\n",
        "import sys\ninstall(*[sys.modules['builtins']])\n",
    ],
)
def test_fixed_eval_provider_namespace_call_escape_is_rejected(source):
    assert runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "import sys\nprovider = sys.__dict__['modules']['builtins']\nprovider.eval = replacement\n",
        "import sys\nprovider = sys.__getattribute__('modules')['builtins']\nprovider.eval = replacement\n",
        "import sys\nsys.__setattr__('modules', replacement)\n",
        "import importlib as il\nprovider = il.__dict__['import_module']('builtins')\nprovider.eval = replacement\n",
    ],
)
def test_fixed_eval_reflective_module_capability_escape_is_rejected(source):
    assert runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "__import__('importlib').import_module('builtins').eval = replacement\n",
        "__import__('importlib.util').import_module('builtins').eval = replacement\n",
        "from importlib import import_module as load\nload('importlib').import_module('builtins').eval = replacement\n",
    ],
)
def test_fixed_eval_dynamic_provider_namespace_import_is_rejected(source):
    assert runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "from sys import __dict__ as namespace\nnamespace['modules']['builtins'].eval = replacement\n",
        "from importlib import __dict__ as namespace\nnamespace['import_module']('builtins').eval = replacement\n",
        "def helper():\n    pass\nhelper.__globals__['__builtins__']['eval'] = replacement\n",
    ],
)
def test_fixed_eval_exported_global_namespace_capability_is_rejected(source):
    assert runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


def test_uninvoked_function_body_does_not_claim_module_init_provider_risk():
    tree = ast.parse("def deferred(payload):\n    eval(payload)\n")
    assert not runtime._fixed_eval_builtin_provider_risk(tree)


def test_fixed_eval_workspace_provider_binding_requires_complete_current_inventory():
    source = b"value = 1\n"
    digest = hashlib.sha256(source).hexdigest()
    rows = [{"path": "sample.py", "sha256": digest}]
    assert runtime.fixed_eval_workspace_provider_clear({"sample.py": source}, rows)
    assert not runtime.fixed_eval_workspace_provider_clear(
        {"sample.py": b"value = 2\n"}, rows
    )
    mutation = b"import builtins as bi\nbi.eval = replacement\n"
    mutation_rows = [
        {"path": "sample.py", "sha256": hashlib.sha256(mutation).hexdigest()}
    ]
    assert not runtime.fixed_eval_workspace_provider_clear(
        {"sample.py": mutation}, mutation_rows
    )


def test_full_repository_cli_context_binds_fixed_program_workspace(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from factoryline import context_efficiency, review_integrity

    relative = "app.py"
    path = tmp_path / relative
    raw = b"def render(request):\n    return request.body\n"
    digest = hashlib.sha256(raw).hexdigest()
    path.write_bytes(raw)
    tree = ast.parse(raw, filename=relative)
    tree._oracle_source_sha256 = digest
    snapshots = {path: tree}
    captured = {path: raw}
    bindings = [{"path": relative, "sha256": digest, "bytes": len(raw)}]

    class Engine:
        @staticmethod
        def _full_repository_configuration_binding(root, name):
            return {"path": name, "state": "absent"}

    audit = SimpleNamespace(
        MAX_BYTES=1_000_000,
        contracts=SimpleNamespace(
            bound_snapshots=lambda root, files, source_bytes, source_bindings: snapshots
        ),
        _oracle_source_inputs=lambda root, files: (captured, bindings, {}, True),
        _security_source_bytes=lambda root, name: b"",
        integrity=review_integrity,
    )
    monkeypatch.setattr(
        context_efficiency,
        "bind_application_fixture_context",
        lambda *args, **kwargs: None,
    )
    generation = {"root": tmp_path, "files": [path], "frame": {"candidates": []}}

    result = runtime._full_repository_workspace_security_context(
        Engine(), generation, audit
    )

    profile = result["contexts"][path]["fixed_program_workspace"]
    assert profile["complete"] is True
    assert profile["eval_provider_mutation_risk"] is False
    assert (
        profile["sources_sha256"]
        == hashlib.sha256(
            json.dumps([[relative, digest]], separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert result["source_bytes"] == captured


def test_workspace_eval_provider_risk_is_separate_from_unrelated_namespace_risk():
    source = "globals()['metadata'] = 'public'\n"
    tree = ast.parse(source)
    tree._oracle_source_sha256 = hashlib.sha256(source.encode()).hexdigest()
    profile = runtime.workspace_builtin_profile({"module.py": tree}, ["module.py"])
    assert profile["complete"] is True
    assert profile["namespace_mutation_risk"] is True
    assert profile["eval_provider_mutation_risk"] is False
    assert "runtime isolation unproven" in profile["eval_provider_scope"]


def test_module_init_opaque_eval_is_not_cleared_by_unrelated_function_boundary():
    source = "eval(provider_code)\ndef handler(request):\n    return request\n"
    assert runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


def test_uninvoked_function_eval_remains_an_independent_dynamic_alert():
    source = "def unsafe(request):\n    return eval(request.body)\n"
    assert not runtime._fixed_eval_builtin_provider_risk(ast.parse(source))


def test_oracle_bound_row_rejects_source_digest_and_test_identity_mismatch(tmp_path):
    test_path = tmp_path / "test_case.py"
    raw = b"def test_example():\n    assert 2 == 2\n"
    test_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    row = {
        "path": "test_case.py",
        "test_sha256": digest,
        "mutation": {"source_path": "app.py", "source_sha256": "source-digest"},
        "symbol": "test_example",
        "line": 1,
        "baseline": {"case_ids": ["test_case.py::test_example"]},
    }
    runtime.oracle_bound_row(
        review_audits,
        tmp_path,
        row,
        {"test_case.py": digest, "app.py": "source-digest"},
    )
    with pytest.raises(review_audits.ReviewAuditError, match="source binding"):
        runtime.oracle_bound_row(
            review_audits, tmp_path, row, {"test_case.py": digest, "app.py": "wrong"}
        )


def test_native_execution_helper_factory_drives_assertion_probe_from_ast():
    helpers = runtime.native_execution_helpers()
    probe_builder = next(
        helper for helper in helpers if helper.__name__ == "native_test_probe"
    )
    test_node = ast.parse(
        "def test_contract():\n    assert value == 3\n    invoke()\n"
    ).body[0]
    probe = probe_builder("tests/test_contract.py", test_node)
    assert probe["available"] is True
    assert probe["assertion_lines"] == [2]
    assert probe["call_available"] is True
    assert probe["call_lines"] == [3]
    empty = probe_builder(
        "tests/test_empty.py", ast.parse("def test_empty():\n    pass\n").body[0]
    )
    assert empty["available"] is False and empty["call_available"] is False


def test_credential_and_finite_template_helper_factories_return_working_validators():
    validators = runtime.credential_validation_helpers()
    operation_check = next(
        helper for helper in validators if helper.__name__ == "_closed_shell_operation"
    )
    assert operation_check("upx --best app") == "executable_packing"
    assert operation_check("upx --best app; rm -rf /") is None
    capture_helpers = runtime.finite_template_input_helpers()
    hash_builder = next(
        helper
        for helper in capture_helpers
        if helper.__name__ == "finite_template_program_hashes"
    )
    template = (
        ast.parse('f"async def run({name}) -> None:\\n    pass\\n"').body[0].value
    )
    assert hash_builder(template, "name", ["tenant_id"]) is not None
    assert hash_builder(template, "other", ["tenant_id"]) is None


def test_tenant_contract_helper_factory_loads_real_contract_and_preserves_evidence(
    tmp_path,
):
    (tmp_path / "app.py").write_text(
        "def read(store):\n    return store.get()\n", encoding="utf-8"
    )
    contract = {
        "schema": "factory.tenant-read-contract.v2",
        "reads": [
            {
                "path": "app.py",
                "reads": [{"call": "store.get", "binding": "position:0:tenant_id"}],
            }
        ],
    }
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps(contract), encoding="utf-8"
    )
    loader = runtime.tenant_contract_helpers(review_audits)[0]
    calls, bindings, evidence = loader(review_audits, tmp_path)
    assert calls == () and bindings == ()
    assert evidence["state"] == "loaded"
    assert evidence["scoped_reads"]["app.py"]["calls"] == ("store.get",)
    contract["extra"] = True
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps(contract), encoding="utf-8"
    )
    with pytest.raises(review_audits.ReviewAuditError):
        loader(review_audits, tmp_path)


def test_runtime_oracle_reconciliation_fails_closed_without_signed_evidence(tmp_path):
    core = {"audit_coverage": {"complete": True}}
    with pytest.raises(review_audits.ReviewAuditError, match="requires receipt"):
        runtime.reconcile_runtime_oracles(
            review_audits, tmp_path, core, (None, None, None, None)
        )


def test_repository_workspace_batch_enforces_deadline_before_consuming_state():
    class Expired(RuntimeError):
        pass

    class Engine:
        def _full_repository_check_soft_deadline(self, deadline):
            assert deadline == 0
            raise Expired("soft deadline reached")

    with pytest.raises(Expired, match="soft deadline"):
        runtime.full_repository_workspace_scan_batch(Engine(), {}, review_audits, [], 0)


def test_lowercase_enum_scalar_requires_typed_frozen_metadata_consumer(tmp_path):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

@dataclass(frozen=True, eq=False)
class FieldSpec:
    role: CredentialRole

def field_spec(*, role: CredentialRole) -> FieldSpec:
    return FieldSpec(role=role)

PASSWORD_FIELD = field_spec(role=CredentialRole.API_PASSWORD)
"""
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
    )
    rows = graph.witnesses().get((tmp_path.resolve() / "common.py", 5, "API_PASSWORD"))
    assert graph.complete
    assert rows
    assert {row["effect"] for row in rows} == {
        "ENUM_TYPE_ANNOTATION",
        "TYPED_METADATA_CONSTRUCTOR",
    }
    assert all(row["source_sha256"] and row["span"] for row in rows)


def test_lowercase_enum_scalar_rejects_untyped_or_mutable_consumer(tmp_path):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

@dataclass(frozen=True, eq=False)
class FieldSpec:
    role: CredentialRole

def field_spec(*, role: CredentialRole) -> FieldSpec:
    return FieldSpec(role=role)

consume(CredentialRole.API_PASSWORD)
"""
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
    )
    assert graph.complete
    assert not graph.witnesses()

    annotated_but_unconsumed = enum_source.replace(
        "consume(CredentialRole.API_PASSWORD)",
        "def annotated() -> CredentialRole:\n    raise RuntimeError()\n\n"
        "consume(CredentialRole.API_PASSWORD)",
    )
    graph = _json_enum_graph(
        tmp_path / "annotated_but_unconsumed",
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=annotated_but_unconsumed,
        client_source="",
    )
    assert graph.complete
    assert not graph.witnesses()
    mutable = enum_source.replace(
        "@dataclass(frozen=True, eq=False)", "@dataclass(eq=False)"
    ).replace(
        "consume(CredentialRole.API_PASSWORD)",
        "field_spec(role=CredentialRole.API_PASSWORD)",
    )
    graph = _json_enum_graph(
        tmp_path / "mutable",
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=mutable,
        client_source="",
    )
    assert graph.complete
    assert not graph.witnesses()

    mutable_container = enum_source.replace(
        "role: CredentialRole", "role: tuple[CredentialRole, ...]"
    ).replace(
        "PASSWORD_FIELD = field_spec(role=CredentialRole.API_PASSWORD)",
        "PASSWORD_FIELD = FieldSpec(role=[CredentialRole.API_PASSWORD])",
    )
    graph = _json_enum_graph(
        tmp_path / "mutable_container",
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=mutable_container,
        client_source="",
    )
    assert graph.complete
    assert not graph.witnesses()


def test_enum_metadata_cross_file_annotations_resolve_at_definition_path(tmp_path):
    consumer = """from dataclasses import dataclass
from other import ErrorCode

@dataclass(frozen=True, eq=False)
class FieldSpec:
    role: ErrorCode

def field_spec(*, role: ErrorCode) -> FieldSpec:
    return FieldSpec(role=role)
"""
    other = """from enum import Enum

class ErrorCode(str, Enum):
    REGISTER_INVALID_PASSWORD = "register_invalid_password"
"""
    test_source = """from common import ErrorCode
from consumer import field_spec

value = field_spec(role=ErrorCode.REGISTER_INVALID_PASSWORD)
"""
    graph = _json_enum_graph(
        tmp_path,
        test_source=test_source,
        client_source="",
        extra_sources={"consumer.py": consumer, "other.py": other},
    )
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 3, "REGISTER_INVALID_PASSWORD")
    )


def test_typed_enum_return_conversion_alone_is_not_a_consumer(tmp_path):
    enum_source = """from enum import Enum

class ErrorCode(str, Enum):
    REGISTER_INVALID_PASSWORD = "register_invalid_password"
    OTHER = "other"

def conversion(value: str) -> ErrorCode:
    if value == "password":
        return ErrorCode.REGISTER_INVALID_PASSWORD
    return ErrorCode.OTHER
"""
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
    )
    rows = graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 4, "REGISTER_INVALID_PASSWORD")
    )
    assert graph.complete
    assert not rows


def test_frozen_typed_enum_field_projected_to_authorization_retains_finding(
    tmp_path,
):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

@dataclass(frozen=True, eq=False)
class Holder:
    token: CredentialRole

holder = Holder(token=CredentialRole.API_PASSWORD)
requests.get(
    "https://example.test",
    headers={"Authorization": holder.token.value},
)
"""
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
    )
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 5, "API_PASSWORD")
    )


@pytest.mark.parametrize(
    "consumer_source",
    [
        'secret = holder.token.value\nrequests.get("https://example.test", headers={"Authorization": secret})\n',
        "authenticate(password=holder.token.value)\n",
        'requests.get("https://example.test", auth=("user", holder.token.value))\n',
        "transport.send(holder.token.value)\n",
        "def get_password():\n    return holder.token.value\n",
        "database.save(holder.token.value)\n",
        'value = getattr(holder, "token").value\n',
        "alias = holder\ntransport.send(alias.token.value)\n",
        "from common import holder\ndef get_password():\n    return holder.token.value\n",
        'from common import holder\neval("holder.token.value")\n',
        'from common import holder\n__all__ = ["holder"]\n',
    ],
    ids=[
        "scalar-alias-authorization",
        "password-authentication",
        "basic-authentication",
        "arbitrary-transport",
        "local-return",
        "persistence",
        "unknown-getter",
        "metadata-alias",
        "cross-file-return",
        "dynamic-reflection",
        "explicit-export",
    ],
)
@pytest.mark.parametrize("demand", [False, True], ids=["small", "demand"])
def test_tracked_metadata_field_use_closure_rejects_unclosed_consumers(
    tmp_path, consumer_source, demand
):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

@dataclass(frozen=True, eq=False)
class Holder:
    token: CredentialRole

holder = Holder(token=CredentialRole.API_PASSWORD)
"""
    extra_sources = {"consumer.py": consumer_source}
    if demand:
        extra_sources.update(
            {
                f"padding_{index}.py": "# unrelated captured source\n"
                for index in range(205)
            }
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
        extra_sources=extra_sources,
    )
    assert graph.enum_demand_only is demand
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 5, "API_PASSWORD")
    )


@pytest.mark.parametrize("demand", [False, True], ids=["small", "demand"])
@pytest.mark.parametrize(
    "metadata_change",
    [
        "    def __post_init__(self):\n        authenticate(password=self.token.value)\n",
        "",
    ],
    ids=["post-init-authentication", "inert-control"],
)
def test_tracked_metadata_constructor_hooks_are_closed(
    tmp_path, demand, metadata_change
):
    enum_source = """import dataclasses
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

@dataclasses.dataclass(frozen=True, eq=False)
class Holder:
    token: CredentialRole
METADATA_HOOK

holder = Holder(token=CredentialRole.API_PASSWORD)
""".replace("METADATA_HOOK\n", metadata_change)
    extra_sources = {}
    if demand:
        extra_sources.update(
            {
                f"padding_{index}.py": "# unrelated captured source\n"
                for index in range(205)
            }
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
        extra_sources=extra_sources,
    )
    assert graph.enum_demand_only is demand
    rows = graph.witnesses().get((tmp_path.resolve() / "common.py", 5, "API_PASSWORD"))
    if metadata_change:
        assert not rows
    else:
        assert rows
        assert all(row["source_sha256"] and row["span"] for row in rows)


@pytest.mark.parametrize("demand", [False, True], ids=["small", "demand"])
@pytest.mark.parametrize(
    "provider", ["dataclasses", "enum"], ids=["dataclass-provider", "enum-provider"]
)
def test_tracked_metadata_rejects_mutated_providers(tmp_path, demand, provider):
    enum_source = """import dataclasses
import enum

class CredentialRole(str, enum.Enum):
    API_PASSWORD = "api_password"

@dataclasses.dataclass(frozen=True, eq=False)
class Holder:
    token: CredentialRole

holder = Holder(token=CredentialRole.API_PASSWORD)
"""
    extra_sources = {}
    if provider == "dataclasses":
        extra_sources["mutation.py"] = (
            "import dataclasses\ndataclasses.dataclass = supplied\n"
        )
    else:
        enum_source += "\nenum.Enum = supplied\n"
    if demand:
        extra_sources.update(
            {
                f"padding_{index}.py": "# unrelated captured source\n"
                for index in range(205)
            }
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
        extra_sources=extra_sources,
    )
    assert graph.enum_demand_only is demand
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 5, "API_PASSWORD")
    )


@pytest.mark.parametrize("demand", [False, True], ids=["small", "demand"])
def test_tracked_metadata_rejects_unsummarized_bases(tmp_path, demand):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class CredentialRole(str, Enum):
    API_PASSWORD = "api_password"

class Parent:
    pass

@dataclass(frozen=True, eq=False)
class Holder(Parent):
    token: CredentialRole

holder = Holder(token=CredentialRole.API_PASSWORD)
"""
    extra_sources = {}
    if demand:
        extra_sources.update(
            {
                f"padding_{index}.py": "# unrelated captured source\n"
                for index in range(205)
            }
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
        extra_sources=extra_sources,
    )
    assert graph.enum_demand_only is demand
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 5, "API_PASSWORD")
    )


@pytest.mark.parametrize("demand", [False, True], ids=["small", "demand"])
def test_tracked_metadata_wrapper_resolves_constructor_at_definition_path(
    tmp_path, demand
):
    enum_source = """from dataclasses import dataclass
from enum import Enum

class ErrorCode(str, Enum):
    REGISTER_INVALID_PASSWORD = "register_invalid_password"

@dataclass(frozen=True, eq=False)
class FieldSpec:
    role: ErrorCode

from consumer import field_spec
value = field_spec(role=ErrorCode.REGISTER_INVALID_PASSWORD)
"""
    consumer_source = """from common import ErrorCode

class FieldSpec:
    def __init__(self, *, role):
        authenticate(password=role.value)

def field_spec(*, role: ErrorCode):
    return FieldSpec(role=role)
"""
    extra_sources = {"consumer.py": consumer_source}
    if demand:
        extra_sources.update(
            {
                f"padding_{index}.py": "# unrelated captured source\n"
                for index in range(205)
            }
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source="def test_no_public_route():\n    assert True\n",
        enum_source=enum_source,
        client_source="",
        extra_sources=extra_sources,
    )
    assert graph.enum_demand_only is demand
    assert not graph.witnesses().get(
        (tmp_path.resolve() / "common.py", 5, "REGISTER_INVALID_PASSWORD")
    )


def test_public_enum_receipt_rejects_changed_consumer_span(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    _json_enum_graph(tmp_path, test_source=source)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report.get("primitive_observations")
    report["primitive_observations"][0]["facts"]["consumers"][0]["span"][1] += 1
    partition_proven_primitive_observations(report)
    assert not report.get("primitive_observations")
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])


def test_full_repository_security_context_uses_native_integrity_owner(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace
    from factoryline import (
        context_efficiency,
        provenance,
        review_audits,
        review_integrity,
    )

    path = tmp_path / "app.py"
    raw = b"from enum import Enum\nclass Role(str, Enum):\n    PASSWORD = 'invalid_password'\n"
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    snapshots = {path: tree}
    captured = {path: raw}
    bindings = [{"path": "app.py", "sha256": digest, "bytes": len(raw)}]
    owners = []
    original = provenance.bind_credential_consumers

    def checked_binder(owner, *args, **kwargs):
        owners.append(owner)
        assert owner is review_integrity
        return original(owner, *args, **kwargs)

    monkeypatch.setattr(provenance, "bind_credential_consumers", checked_binder)
    monkeypatch.setattr(
        review_audits,
        "_oracle_source_inputs",
        lambda *args: (captured, bindings, {}, True),
    )
    monkeypatch.setattr(
        review_audits.contracts, "bound_snapshots", lambda *args: snapshots
    )
    monkeypatch.setattr(
        context_efficiency,
        "bind_application_fixture_context",
        lambda *args, **kwargs: None,
    )
    engine = SimpleNamespace(
        _full_repository_configuration_binding=lambda root, name: {
            "path": name,
            "state": "absent",
        }
    )
    generation = {"root": tmp_path, "files": [path], "frame": {"candidates": []}}
    result = runtime._full_repository_workspace_security_context(
        engine, generation, review_audits
    )
    assert owners == [review_integrity]
    assert set(result["symbolic_imports"]) == {path}
    assert result["contexts"][path]["fixed_program_workspace"]["complete"] is True


@pytest.mark.parametrize(
    "variant", ["captured", "uncaptured", "ambiguous", "nonpackage"]
)
def test_native269_symbolic_imports_use_only_captured_inventory(
    tmp_path, monkeypatch, variant
):
    from types import SimpleNamespace
    from factoryline import (
        context_efficiency,
        import_context,
        provenance,
        review_audits,
    )

    files = {"consumer.py": "from provider import Provider\n"}
    provider = "provider.py"
    if variant == "ambiguous":
        files["consumer.py"] = "from pkg import child\n"
        files.update(
            {"pkg/__init__.py": "child = supplied\n", "pkg/child.py": "pass\n"}
        )
    elif variant == "nonpackage":
        files["consumer.py"] = "import pkg.child\n"
        files.update({"pkg.py": "pass\n", "pkg/child.py": "pass\n"})
    else:
        files[provider] = "class Provider: pass\n"
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    captured = {
        tmp_path / name: text.encode()
        for name, text in files.items()
        if variant != "uncaptured" or name != provider
    }
    snapshots = {path: ast.parse(raw) for path, raw in captured.items()}
    bindings = [
        {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        for path, raw in captured.items()
    ]
    for path, tree in snapshots.items():
        tree._oracle_source_sha256 = hashlib.sha256(captured[path]).hexdigest()
    monkeypatch.setattr(
        review_audits,
        "_oracle_source_inputs",
        lambda *args: (captured, bindings, {}, True),
    )
    monkeypatch.setattr(
        review_audits.contracts, "bound_snapshots", lambda *args: snapshots
    )
    monkeypatch.setattr(
        context_efficiency,
        "bind_application_fixture_context",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        provenance, "bind_credential_consumers", lambda *args, **kwargs: None
    )

    def live_resolution_is_forbidden(*args):
        raise AssertionError("native symbolic imports must use the captured inventory")

    monkeypatch.setattr(
        import_context, "live_import_path", live_resolution_is_forbidden
    )
    engine = SimpleNamespace(
        _full_repository_configuration_binding=lambda root, name: {
            "path": name,
            "state": "absent",
        }
    )
    generation = {
        "root": tmp_path,
        "files": list(captured),
        "frame": {"candidates": []},
    }
    result = runtime._full_repository_workspace_security_context(
        engine, generation, review_audits
    )
    expected = (
        {"Provider": (tmp_path / provider, "Provider")} if variant == "captured" else {}
    )
    assert result["symbolic_imports"][tmp_path / "consumer.py"] == expected


def test_provenance_whole_class_replacement_changes_actual_callee_epoch(monkeypatch):
    from factoryline import provenance, review_integrity

    original = provenance._LiteralConsumers
    before = provenance.credential_consumer_helpers(review_integrity)

    class Replacement(original):
        def changed_member(self):
            return None

    monkeypatch.setattr(provenance, "_LiteralConsumers", Replacement)
    after = provenance.credential_consumer_helpers(review_integrity)
    assert before != after
    assert Replacement in after
    assert Replacement.changed_member in after
    assert runtime._LiteralConsumers is original


def test_pyflow_parity_native_literal_pickle_decision_reaches_real_partition(tmp_path):
    source = (
        "import pickle\n"
        "def direct_external():\n    return eval(input())\n"
        "def local_roundtrip():\n    return pickle.loads(pickle.dumps({'key': 2}))\n"
        "def external_pickle():\n    return pickle.loads(input().encode())\n"
        "def helper(value):\n    return eval(value)\n"
        "def cross_function():\n    return helper(input())\n"
    )
    (tmp_path / "control.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    active = [
        row
        for row in report["findings"]
        if row["code"]
        in {"SECURITY_DYNAMIC_EXECUTION", "SECURITY_UNSAFE_DESERIALIZATION"}
    ]
    assert len(active) == 3
    proved = report["primitive_observations"]
    assert len(proved) == 1
    assert proved[0]["line"] == 5
    assert proved[0]["facts"]["disposition"] == "PROVEN_CLOSED_LITERAL_PICKLE_BYTES"
    assert report["finding_tier_report"]["raw_diagnostics"]["count"] >= 4
    assert proved[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "expression,prefix",
    [
        ("pickle.loads(pickle.dumps(value))", ""),
        ("pickle.loads(pickle.dumps(make_value()))", ""),
        ("pickle.loads(pickle.dumps({'key': value}))", ""),
        ("pickle.loads(pickle.dumps({'key': 2}))", "pickle.dumps = replacement\n"),
        ("pickle.loads(pickle.dumps({'key': 2}))", "pickle.loads = replacement\n"),
        (
            "pickle.loads(pickle.dumps({'key': 2}))",
            "setattr(pickle, 'loads', replacement)\n",
        ),
        ("pickle.loads(pickle.dumps({'key': 2}))", "pickle = replacement\n"),
    ],
)
def test_pyflow_parity_nonliteral_or_replaced_provider_not_proven(
    tmp_path, expression, prefix
):
    (tmp_path / "control.py").write_text(
        f"import pickle\n{prefix}def decode(value):\n    return {expression}\n",
        encoding="utf-8",
    )
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    if prefix != "pickle = replacement\n":
        assert any(
            row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
            for row in report["findings"]
        )
    assert not any(
        row["facts"].get("disposition") == "PROVEN_CLOSED_LITERAL_PICKLE_BYTES"
        for row in report.get("primitive_observations", [])
    )


def test_pyflow_parity_literal_pickle_proof_is_independently_rebuilt(tmp_path):
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "control.py").write_text(
        "import pickle\ndef decode():\n    return pickle.loads(pickle.dumps({'key': 2}))\n",
        encoding="utf-8",
    )
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert len(report["primitive_observations"]) == 1
    report["primitive_observations"][0]["facts"]["literal_sha256"] = "0" * 64
    partition_proven_primitive_observations(report)
    assert not report["primitive_observations"]
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )


@pytest.mark.parametrize(
    "mutator",
    [
        "import pickle\nprovider = pickle\nprovider.loads = replacement\n",
        "import pickle\npickle.__dict__['loads'] = replacement\n",
        "import sys\nsys.modules['pickle'] = replacement\n",
        "import sys\nsys.modules[selected] = replacement\n",
        "import pickle\nmutate(pickle)\n",
    ],
)
def test_pyflow_parity_cross_source_provider_mutation_stays_active(tmp_path, mutator):
    (tmp_path / "control.py").write_text(
        "import pickle\nimport mutator\ndef decode():\n    return pickle.loads(pickle.dumps({'key': 2}))\n",
        encoding="utf-8",
    )
    (tmp_path / "mutator.py").write_text(mutator, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "provider,consumer",
    [
        (
            "import pickle\n",
            "from provider_patch import *\npickle.loads = replacement\n",
        ),
        (
            "import pickle as p\n",
            "from provider_patch import p\np.loads = replacement\n",
        ),
        (
            "import pickle as p\n",
            "import provider_patch\nprovider_patch.p.loads = replacement\n",
        ),
    ],
)
def test_pyflow_parity_provider_export_cannot_bypass_workspace_binding(
    tmp_path, provider, consumer
):
    (tmp_path / "control.py").write_text(
        "import pickle\nimport mutator\ndef decode():\n    return pickle.loads(pickle.dumps({'key': 2}))\n",
        encoding="utf-8",
    )
    (tmp_path / "provider_patch.py").write_text(provider, encoding="utf-8")
    (tmp_path / "mutator.py").write_text(consumer, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )
    assert not report.get("primitive_observations")


def _native_flow_expression(expression, environment):
    if isinstance(expression, ast.Constant):
        return True, expression.value
    if isinstance(expression, ast.Name):
        return (expression.id in environment, environment.get(expression.id))
    return False, None


def _native_flow_function(source):
    return next(
        node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
    )


def test_native_helper_flow_reassignment_kills_old_fact_and_aliases_reach_return():
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function(
        "def helper(value):\n    alias = value\n    value = 'fixed'\n    return alias\n"
    )
    result = evaluate_helper_flow(
        helper, {"value": "secret-taint"}, _native_flow_expression
    )
    assert result["status"] == "COMPLETE"
    assert result["return_values"] == ("secret-taint",)
    assert result["environment"]["value"] == "fixed"


def test_native_helper_flow_fixed_return_kills_prior_input_fact():
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function(
        "def helper(value):\n    value = 'safe'\n    return value\n"
    )
    result = evaluate_helper_flow(
        helper, {"value": "secret-taint"}, _native_flow_expression
    )
    assert result["status"] == "COMPLETE"
    assert result["return_values"] == ("safe",)


def test_native_helper_flow_reads_old_definition_before_strong_update():
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function(
        "def helper(value):\n    value = value\n    return value\n"
    )
    result = evaluate_helper_flow(
        helper, {"value": "prior-fact"}, _native_flow_expression
    )
    assert result["status"] == "COMPLETE"
    assert result["return_values"] == ("prior-fact",)


@pytest.mark.parametrize(
    "body",
    [
        "if value:\n        return value",
        "return value\n    return 'fixed'",
        "value.token = 'fixed'\n    return value",
        "value[0] = 'fixed'\n    return value",
        "transform(value)\n    return value",
        "return value.token",
        "return helper(value)",
        "pass",
    ],
    ids=[
        "conditional",
        "multiple-returns",
        "property-write",
        "subscript-write",
        "call",
        "property-read",
        "recursive-call",
        "no-return",
    ],
)
def test_native_helper_flow_unsupported_shapes_are_unknown(body):
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function(f"def helper(value):\n    {body}\n")
    result = evaluate_helper_flow(
        helper, {"value": "secret-taint"}, _native_flow_expression
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason"]
    assert result["states_used"] <= 512


def test_native_helper_flow_handles_docstring_pass_and_marks_budget_exhaustion():
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function(
        "def helper(value):\n    'doc'\n    pass\n    alias = value\n    return alias\n"
    )
    complete = evaluate_helper_flow(
        helper, {"value": "fact"}, _native_flow_expression, max_states=4
    )
    exhausted = evaluate_helper_flow(
        helper, {"value": "fact"}, _native_flow_expression, max_states=2
    )
    assert complete["status"] == "COMPLETE"
    assert complete["return_values"] == ("fact",)
    assert exhausted["status"] == "BUDGET_EXHAUSTED"
    assert exhausted["states_used"] == 0


def test_native_helper_flow_distinguishes_known_none_from_unknown():
    from factoryline.finite_capture import evaluate_helper_flow

    helper = _native_flow_function("def helper():\n    return None\n")
    result = evaluate_helper_flow(helper, {}, _native_flow_expression)
    assert result["status"] == "COMPLETE"
    assert result["return_values"] == (None,)


def test_workspace_v2_security_only_keeps_security_findings_without_oracle_analysis(
    tmp_path, monkeypatch
):
    from factoryline import review_audits
    from factoryline.deep_audit_io import full_repository_scan

    (tmp_path / "settings.py").write_text(
        'GITHUB_TOKEN = "ghp_abcdefghijklmnop"\n', encoding="utf-8"
    )
    quality_calls = []

    def forbidden_quality(*args, **kwargs):
        quality_calls.append(True)
        raise AssertionError("workspace-v2 must skip test-oracle analysis")

    monkeypatch.setattr(review_audits, "_test_oracle_findings", forbidden_quality)
    monkeypatch.setattr(
        review_audits.contracts, "implementation_findings", forbidden_quality
    )
    report = full_repository_scan(tmp_path, context_profile="workspace-v2")
    assert report["audit_coverage"]["complete"]
    assert any(
        row["code"] == "SECURITY_HARDCODED_SECRET"
        for row in report["workspace_evidence"]["raw_findings"]
    )
    counts = report["workspace_evidence"]["finding_tiers"]["raw_diagnostics"]
    assert counts["by_code"]["SECURITY_HARDCODED_SECRET"] == 1
    assert not any(code.startswith("QUALITY_") for code in counts["by_code"])
    assert quality_calls == []


def test_default_security_tree_keeps_test_oracle_analysis(tmp_path, monkeypatch):
    (tmp_path / "settings.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    calls = {"oracle": 0, "implementation": 0}
    original_oracle = review_audits._test_oracle_findings
    original_implementation = review_audits.contracts.implementation_findings

    def oracle(*args, **kwargs):
        calls["oracle"] += 1
        return original_oracle(*args, **kwargs)

    def implementation(*args, **kwargs):
        calls["implementation"] += 1
        return original_implementation(*args, **kwargs)

    monkeypatch.setattr(review_audits, "_test_oracle_findings", oracle)
    monkeypatch.setattr(
        review_audits.contracts, "implementation_findings", implementation
    )
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert calls["oracle"] and calls["implementation"]
    assert report["audit_coverage"]["complete"]


@pytest.mark.parametrize("flag", ["yes", 1], ids=["truthy-string", "integer"])
def test_non_boolean_security_only_flags_do_not_skip_quality(
    tmp_path, monkeypatch, flag
):
    path = tmp_path / "settings.py"
    path.write_text("value = 1\n", encoding="utf-8")
    calls = []

    def oracle(*args, **kwargs):
        calls.append(True)
        return []

    monkeypatch.setattr(review_audits, "_test_oracle_findings", oracle)
    review_audits._security_scan_tree(
        tmp_path,
        path,
        ast.parse(path.read_text(encoding="utf-8")),
        oracle_context={"_security_only": flag},
    )
    assert calls


def test_security_only_contextvar_restores_nested_success_and_failure():
    context = review_audits._security_only_scan_context
    assert review_audits._SECURITY_ONLY_SCAN.get() is False
    with context(True):
        assert review_audits._SECURITY_ONLY_SCAN.get() is True
        with context(False):
            assert review_audits._SECURITY_ONLY_SCAN.get() is False
        assert review_audits._SECURITY_ONLY_SCAN.get() is True
    assert review_audits._SECURITY_ONLY_SCAN.get() is False
    with pytest.raises(RuntimeError):
        with context(True):
            raise RuntimeError("exercise context cleanup")
    assert review_audits._SECURITY_ONLY_SCAN.get() is False


def _trusted_core_policy316_seal(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_bytes(source)
    return review_audits.security_scan(
        tmp_path, cache_enabled=False, defect_policy="trusted-core-v1"
    )


def test_trusted_core_policy316_supported_defect_is_recomputed_and_bound(tmp_path):
    report = _trusted_core_policy316_seal(
        tmp_path,
        b"from flask import request\neval(request.get_data(as_text=True))\n",
    )
    decision = report["defect_policy_decision"]
    assert decision["policy_id"] == "trusted-core-v1"
    assert decision["state"] == "DEFECTS_PRESENT"
    assert decision["exit_code"] == 1
    assert decision["supported_defect_count"] == 1
    assert decision["passed"] is False
    assert decision["clean"] is False
    assert decision["release_approved"] is False
    assert len(decision["policy_sha256"]) == 64
    assert len(decision["source_sha256"]) == 64
    assert len(decision["evidence_sha256"]) == 64
    assert report["finding_tier_report"]["raw_diagnostics"]["count"] == 1
    assert report["findings"][0]["severity"] == "HIGH"
    assert (
        report["finding_tier_report"]["ledger"][0]["raw_finding"]["severity"] == "HIGH"
    )


def test_trusted_core_policy316_review_queue_is_not_clean_or_approved(tmp_path):
    report = _trusted_core_policy316_seal(tmp_path, b"eval(user_data)\n")
    decision = report["defect_policy_decision"]
    assert decision["state"] == "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"
    assert decision["exit_code"] == 0
    assert decision["supported_defect_count"] == 0
    assert decision["needs_context_count"] == 1
    assert decision["passed"] is False
    assert decision["clean"] is False
    assert decision["release_approved"] is False
    assert "unresolved item(s) remain" in decision["action_summary"]


@pytest.mark.parametrize("tamper", ["tier", "removed_raw_row", "capture_hash"])
def test_trusted_core_policy316_forged_or_stale_evidence_blocks(tmp_path, tamper):
    path = tmp_path / "app.py"
    path.write_bytes(b'GITHUB_TOKEN = "ghp_abcdefghijklmnop"\n')
    scanned = review_audits.security_scan(
        tmp_path, cache_enabled=False, defect_policy="trusted-core-v1"
    )
    core = copy.deepcopy(dict(scanned))
    captured = dict(scanned._captured_sources)
    core["_primitive_source_bytes"] = captured
    if tamper == "tier":
        core["finding_tier_report"]["ledger"][0]["tier"] = "SUPPORTED_DEFECT"
    elif tamper == "removed_raw_row":
        core["finding_tier_report"]["ledger"].clear()
        core["finding_tier_report"]["tier_counts"] = {
            "SUPPORTED_DEFECT": 0,
            "NEEDS_CONTEXT": 0,
            "PROVEN_PRIMITIVE": 0,
        }
    else:
        captured["app.py"] = b'GITHUB_TOKEN = "ghp_changedvalue123"\n'
    checked = review_audits._seal_security_scan(core)
    assert checked["defect_policy_decision"]["state"] == "BLOCKED"
    assert checked["defect_policy_decision"]["exit_code"] == 2
    assert checked["defect_policy_decision"]["clean"] is False
    assert checked["defect_policy_decision"]["release_approved"] is False


def test_trusted_core_policy316_default_candidate_payload_is_unchanged(monkeypatch):
    from factoryline.audit_action_refs import _security_scan_report_candidate_payload
    from factoryline import primitive_observation_binding

    report = {
        "sources": [],
        "tenant_read_contract": {},
        "oracle_context": {},
        "database_context": {},
    }
    payload = _security_scan_report_candidate_payload(report)
    assert payload == {
        "sources": [],
        "tenant_read_contract": {},
        "oracle_context": {},
        "database_context": {},
    }
    report["selected_defect_policy"] = "trusted-core-v1"
    report["defect_policy_decision"] = {
        "policy_sha256": "a" * 64,
        "evidence_sha256": "b" * 64,
    }
    selected = _security_scan_report_candidate_payload(report)
    assert selected["selected_defect_policy"] == "trusted-core-v1"
    assert selected["defect_policy_sha256"] == "a" * 64
    assert selected["defect_policy_evidence_sha256"] == "b" * 64
    assert (
        selected["finding_tier_policy_sha256"] == primitive.finding_tier_policy_sha256()
    )
    report["defect_policy_decision"]["evidence_sha256"] = "c" * 64
    changed_evidence = _security_scan_report_candidate_payload(report)
    assert changed_evidence != selected
    monkeypatch.setattr(
        primitive_observation_binding, "finding_tier_policy_sha256", lambda: "d" * 64
    )
    assert _security_scan_report_candidate_payload(report) != changed_evidence


@pytest.mark.parametrize(
    "configuration", [None, {"state": "missing"}, {"state": "changed"}]
)
def test_trusted_core_policy316_cli_tenant_configuration_must_be_loaded(
    tmp_path, configuration
):
    report = _trusted_core_policy316_seal(tmp_path, b"eval(user_data)\n")
    core = copy.deepcopy(dict(report))
    core["_primitive_source_bytes"] = dict(report._captured_sources)
    core["oracle_context"]["pytest_collection"] = {"capture_state": "stable_pre_post"}
    if configuration is None:
        core["tenant_read_contract"].pop("configuration", None)
    else:
        core["tenant_read_contract"]["configuration"] = configuration
    checked = review_audits._seal_security_scan(core)
    assert checked["defect_policy_decision"]["state"] == "BLOCKED"
    assert checked["defect_policy_decision"]["exit_code"] == 2


def test_trusted_core_policy316_incomplete_database_context_blocks(tmp_path):
    report = _trusted_core_policy316_seal(tmp_path, b"eval(user_data)\n")
    core = copy.deepcopy(dict(report))
    core["_primitive_source_bytes"] = dict(report._captured_sources)
    core["database_context"] = {"status": "INCOMPLETE", "gaps": ["schema"]}
    checked = review_audits._seal_security_scan(core)
    assert checked["defect_policy_decision"]["state"] == "BLOCKED"
    assert checked["defect_policy_decision"]["exit_code"] == 2


def test_trusted_core_policy316_legacy_selector_drops_stale_decision(tmp_path):
    report = _trusted_core_policy316_seal(
        tmp_path,
        b"from flask import request\neval(request.get_data(as_text=True))\n",
    )
    core = copy.deepcopy(dict(report))
    core["_primitive_source_bytes"] = dict(report._captured_sources)
    core["selected_defect_policy"] = "legacy-v1"
    checked = review_audits._seal_security_scan(core)
    assert "defect_policy_decision" not in checked


@pytest.mark.parametrize(
    "tamper", ["missing_capture", "source_incomplete", "changed_collection"]
)
def test_trusted_core_policy316_incomplete_source_context_blocks(tmp_path, tamper):
    report = _trusted_core_policy316_seal(
        tmp_path,
        b"from flask import request\neval(request.get_data(as_text=True))\n",
    )
    core = copy.deepcopy(dict(report))
    captured = dict(report._captured_sources)
    if tamper == "missing_capture":
        captured.clear()
    elif tamper == "source_incomplete":
        core["state"] = "INCOMPLETE"
    else:
        core["oracle_context"]["pytest_collection"] = {
            "capture_state": "changed_during_scan"
        }
    core["_primitive_source_bytes"] = captured
    checked = review_audits._seal_security_scan(core)
    assert checked["defect_policy_decision"]["state"] == "BLOCKED"
    assert checked["defect_policy_decision"]["exit_code"] == 2


def test_trusted_core_policy316_replaces_serialized_decision_from_current_evidence(
    tmp_path,
):
    report = _trusted_core_policy316_seal(
        tmp_path,
        b"from flask import request\neval(request.get_data(as_text=True))\n",
    )
    expected = copy.deepcopy(report["defect_policy_decision"])
    core = copy.deepcopy(dict(report))
    core["_primitive_source_bytes"] = dict(report._captured_sources)
    core["defect_policy_decision"] = {
        **expected,
        "state": "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED",
        "exit_code": 0,
        "evidence_sha256": "0" * 64,
    }
    checked = review_audits._seal_security_scan(core)
    assert checked["defect_policy_decision"] == expected


@pytest.mark.parametrize("value", [None, "legacy", "trusted-core-v2", True, 1])
def test_trusted_core_policy316_rejects_unknown_selectors(value):
    with pytest.raises(ValueError, match="defect policy"):
        primitive.validate_security_defect_policy(value)
    assert primitive.validate_security_defect_policy("legacy-v1") == "legacy-v1"


def _pickle_reconstruction317_contract(
    monkeypatch, package, source, symbol, model_version=2
):
    from factoryline import finite_capture

    runtime = {
        "implementation": "cpython",
        "version": "3.11.9",
        "executable_sha256": "1" * 64,
        "pickle_source_sha256": "2" * 64,
        "pickle_implementation_sha256": "3" * 64,
    }
    monkeypatch.setattr(
        finite_capture, "_provider_runtime_identity", lambda: dict(runtime)
    )
    raw = source.encode()
    tree = ast.parse(raw)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    exported = f"from .errors import {symbol}\n".encode()
    return {
        "schema": "factory.provider-contract.v1",
        "model": {
            "id": f"builtin-exception-record-v{model_version}",
            "version": model_version,
        },
        "runtime": dict(runtime),
        "artifacts": {
            f"{package}/errors.py": hashlib.sha256(raw).hexdigest(),
            f"{package}/__init__.py": hashlib.sha256(exported).hexdigest(),
        },
        "export": {"path": f"{package}/__init__.py", "symbol": symbol},
        "classes": [
            {
                "path": f"{package}/errors.py",
                "name": cls.name,
                "class_ast_sha256": hashlib.sha256(
                    ast.dump(cls, include_attributes=False).encode()
                ).hexdigest(),
                "constructor_ast_sha256": next(
                    (
                        hashlib.sha256(
                            ast.dump(item, include_attributes=False).encode()
                        ).hexdigest()
                        for item in cls.body
                        if isinstance(item, ast.FunctionDef) and item.name == "__init__"
                    ),
                    None,
                ),
            }
            for cls in reversed(classes)
        ],
        "assumptions": [
            "CANONICAL_CPYTHON_PICKLE",
            "IMMUTABLE_PROVIDER_ARTIFACTS",
            "NO_RUNTIME_MONKEY_PATCHING",
            "TRUSTED_IMPORT_INITIALIZATION",
        ],
    }, {f"{package}/errors.py": raw, f"{package}/__init__.py": exported}


def test_pickle_reconstruction317_model_profile_set_is_canonical_and_views_are_exact(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    first, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "alpha",
        "class AlphaError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "AlphaError",
        1,
    )
    second, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "beta",
        "class BetaError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "BetaError",
        2,
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (second, first)
    )
    reordered = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (first, second)
    )
    assert profile == reordered
    assert profile["analysis_profile"] == "trusted-dependencies-v2"
    assert len(profile["contracts"]) == 2
    selected = next(
        hashlib.sha256(canonical_bytes(c)).hexdigest()
        for c in profile["contracts"]
        if c["export"]["symbol"] == "BetaError"
    )
    view = finite_capture.provider_contract_view(profile, selected)
    assert view is not None
    assert set(view) == {
        "profile_sha256",
        "contract_set_sha256",
        "selected_contract_sha256",
        "selected_model_sha256",
        "contract",
    }
    assert view["contract"]["export"]["symbol"] == "BetaError"
    assert view["contract_set_sha256"] == profile["contract_sha256"]
    assert finite_capture.provider_contract_view(profile, "0" * 64) is None
    assert (
        finite_capture.provider_contract_view(
            {**profile, "contracts": list(reversed(profile["contracts"]))}, selected
        )
        is None
    )


def test_pickle_reconstruction317_model_rejects_ambiguous_contract_sets(monkeypatch):
    from factoryline import finite_capture

    contract, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "alpha",
        "class AlphaError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "AlphaError",
    )
    duplicate = {
        **contract,
        "artifacts": dict(contract["artifacts"]),
        "classes": [dict(row) for row in contract["classes"]],
    }
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile(
            "trusted-dependencies-v2", (contract, duplicate)
        )
    collision = {
        **contract,
        "export": dict(contract["export"]),
        "artifacts": dict(contract["artifacts"]),
    }
    collision["artifacts"]["alpha/errors.py"] = "8" * 64
    collision["export"] = {"path": "alpha/__init__.py", "symbol": "OtherError"}
    collision["classes"] = [{**contract["classes"][0], "name": "OtherError"}]
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile(
            "trusted-dependencies-v2", (contract, collision)
        )


def test_pickle_reconstruction317_model_reconstructs_delegated_exception_and_build_state(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = (
        "class RootError(Exception):\n"
        "    unknown_annotation: NotEvaluatedDuringLoad\n"
        "    kind = 'root'\n"
        "    def __init__(self, message=None):\n"
        "        if message is None:\n"
        "            message = 'fallback'\n"
        "        self.message = message\n"
        "\n"
        "class MiddleError(RootError):\n"
        "    def __init__(self, message):\n"
        "        super().__init__(message)\n"
        "\n"
        "class LineError(MiddleError):\n"
        "    args: tuple[bytes, int]\n"
        "    def __init__(self, line: bytes, limit: int):\n"
        "        super().__init__(f'Got more than {limit} bytes when reading: {line!r}.')\n"
        "        self.args = (line, limit)\n"
        "    def __str__(self):\n"
        "        return self.message\n"
        "    def __repr__(self):\n"
        "        return self.message\n"
    )
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "LineError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("LineError(line=b'row', limit=4)", mode="eval").body
    result = finite_capture.provider_exception_record(
        profile,
        sources,
        call,
        selected_contract_view=view,
        instance_state={"extra": b"carried"},
    )
    assert result["args"] == (b"row", 4)
    assert result["state"] == {
        "message": "Got more than 4 bytes when reading: b'row'.",
        "extra": b"carried",
    }
    assert result["build_state"] == {
        "message": "Got more than 4 bytes when reading: b'row'.",
        "extra": b"carried",
    }
    assert result["reconstruction"] == {
        "kind": "BaseException_ARGS_THEN_BUILD",
        "args": (b"row", 4),
    }
    assert result["requires_initialized_provider_witness"] is True
    assert result["assurance"] == "PROVISIONAL_PROVIDER_RECONSTRUCTION"
    assert finite_capture.provider_exception_record(profile, sources, call) is None
    forged_view = {**view, "selected_model_sha256": "0" * 64}
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=forged_view
        )
        is None
    )
    positional = ast.parse("LineError(b'row', 4)", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, positional, selected_contract_view=view
        )["args"]
        == result["args"]
    )


@pytest.mark.parametrize(
    "call, instance_state",
    [
        ("LineError(dynamic, 4)", {}),
        ("LineError(b'row', 4)", {"args": (b"forged",)}),
        ("LineError(b'row', 4)", {"__class__": "changed"}),
    ],
)
def test_pickle_reconstruction317_model_rejects_dynamic_or_protected_values(
    monkeypatch, call, instance_state
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = "class LineError(Exception):\n    def __init__(self, line, limit):\n        self.args = (line, limit)\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "LineError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    assert (
        finite_capture.provider_exception_record(
            profile,
            sources,
            ast.parse(call, mode="eval").body,
            selected_contract_view=view,
            instance_state=instance_state,
        )
        is None
    )


def test_pickle_reconstruction317_model_rejects_unclosed_fstring_and_wrong_replay(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = (
        "class BaseError(Exception):\n"
        "    def __init__(self, message):\n"
        "        self.message = message\n"
        "class FormatError(BaseError):\n"
        "    def __init__(self, value):\n"
        "        super().__init__(f'{value!r:>4}')\n"
        "        self.args = (value, 'not-replayable')\n"
    )
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "FormatError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("FormatError('x')", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=view
        )
        is None
    )


def test_pickle_reconstruction317_model_constructor_binding_uses_only_selected_contract(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    alpha, alpha_sources = _pickle_reconstruction317_contract(
        monkeypatch,
        "alpha",
        "class AlphaError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "AlphaError",
    )
    beta, beta_sources = _pickle_reconstruction317_contract(
        monkeypatch,
        "beta",
        "class BetaError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "BetaError",
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (beta, alpha)
    )
    alpha_digest = next(
        hashlib.sha256(canonical_bytes(row)).hexdigest()
        for row in profile["contracts"]
        if row["export"]["symbol"] == "AlphaError"
    )
    beta_digest = next(
        hashlib.sha256(canonical_bytes(row)).hexdigest()
        for row in profile["contracts"]
        if row["export"]["symbol"] == "BetaError"
    )
    alpha_view = finite_capture.provider_contract_view(profile, alpha_digest)
    beta_view = finite_capture.provider_contract_view(profile, beta_digest)
    caller = b"from alpha import AlphaError\ndef run():\n    return AlphaError('x')\n"
    call = next(
        node for node in ast.walk(ast.parse(caller)) if isinstance(node, ast.Call)
    )
    assert (
        finite_capture.provider_constructor_binding(
            profile, alpha_sources, caller, call, selected_contract_view=alpha_view
        )
        is not None
    )
    assert (
        finite_capture.provider_constructor_binding(
            profile, beta_sources, caller, call, selected_contract_view=beta_view
        )
        is None
    )


@pytest.mark.parametrize(
    "initializer, intermediary, accepted",
    [
        (
            "from .http import HTTPThing\ndef __getattr__(name):\n    raise AttributeError(name)\n",
            "from .http_exceptions import LocalError\n",
            True,
        ),
        (
            "from .http import *\ndef __getattr__(name):\n    raise AttributeError(name)\n",
            "from .http_exceptions import LocalError\n",
            False,
        ),
        (
            "from .http import HTTPThing\ndef __getattr__(name):\n    raise AttributeError(name)\n",
            "import missing_module\n",
            False,
        ),
        (
            "from .http import HTTPThing\nhttp_exceptions = object()\ndef __getattr__(name):\n    raise AttributeError(name)\n",
            "from .http_exceptions import LocalError\n",
            False,
        ),
        (
            "from .http import HTTPThing\nfrom .evil import FakeModule as http_exceptions\ndef __getattr__(name):\n    raise AttributeError(name)\n",
            "from .http_exceptions import LocalError\n",
            False,
        ),
    ],
)
def test_pickle_reconstruction317_model_v2_import_binding_proves_transitive_cached_child(
    monkeypatch, initializer, intermediary, accepted
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    contract, source_map = _pickle_reconstruction317_contract(
        monkeypatch,
        "aiohttp",
        "class LocalError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "LocalError",
    )
    class_bytes = source_map.pop("aiohttp/errors.py")
    init_bytes = initializer.encode()
    http_bytes = intermediary.encode()
    source_map["aiohttp/__init__.py"] = init_bytes
    source_map["aiohttp/http.py"] = http_bytes
    source_map["aiohttp/http_exceptions.py"] = class_bytes
    contract["artifacts"] = {
        path: hashlib.sha256(raw).hexdigest() for path, raw in source_map.items()
    }
    contract["export"] = {"path": "aiohttp/http_exceptions.py", "symbol": "LocalError"}
    contract["classes"][0]["path"] = "aiohttp/http_exceptions.py"
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    caller = b"from aiohttp import http_exceptions\ndef run():\n    return http_exceptions.LocalError('x')\n"
    call = next(
        node for node in ast.walk(ast.parse(caller)) if isinstance(node, ast.Call)
    )
    witness = finite_capture.provider_constructor_binding(
        profile, source_map, caller, call, selected_contract_view=view
    )
    assert (witness is not None) is accepted


@pytest.mark.parametrize("count", [0, 33])
def test_pickle_reconstruction317_model_contract_set_size_is_bounded(
    monkeypatch, count
):
    from factoryline import finite_capture

    contract, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "pkg",
        "class LocalError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "LocalError",
    )
    contracts = (
        ()
        if count == 0
        else tuple(
            {
                **contract,
                "export": {
                    "path": f"pkg{index}/__init__.py",
                    "symbol": f"LocalError{index}",
                },
                "artifacts": {
                    f"pkg{index}/errors.py": contract["artifacts"]["pkg/errors.py"],
                    f"pkg{index}/__init__.py": contract["artifacts"]["pkg/__init__.py"],
                },
                "classes": [
                    {
                        **contract["classes"][0],
                        "path": f"pkg{index}/errors.py",
                        "name": f"LocalError{index}",
                    }
                ],
            }
            for index in range(count)
        )
    )
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile("trusted-dependencies-v2", contracts)


def test_pickle_reconstruction317_model_accepts_maximum_contract_set(monkeypatch):
    from factoryline import finite_capture

    contract, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "pkg",
        "class LocalError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n",
        "LocalError",
    )
    contracts = tuple(
        {
            **contract,
            "export": {
                "path": f"pkg{index}/__init__.py",
                "symbol": f"LocalError{index}",
            },
            "artifacts": {
                f"pkg{index}/errors.py": contract["artifacts"]["pkg/errors.py"],
                f"pkg{index}/__init__.py": contract["artifacts"]["pkg/__init__.py"],
            },
            "classes": [
                {
                    **contract["classes"][0],
                    "path": f"pkg{index}/errors.py",
                    "name": f"LocalError{index}",
                }
            ],
        }
        for index in range(32)
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", contracts
    )
    assert len(profile["contracts"]) == 32


@pytest.mark.parametrize(
    "member",
    [
        "    def __reduce__(self):\n        return execute, ()",
        "    @property\n    def __str__(self):\n        return 'dynamic'",
        "    state = []",
        "    args = ('class-shadow',)",
    ],
)
def test_pickle_reconstruction317_model_rejects_reducers_descriptors_and_dynamic_class_state(
    monkeypatch, member
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = (
        "class LocalError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n"
        + member
        + "\n"
    )
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "LocalError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("LocalError('x')", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=view
        )
        is None
    )


@pytest.mark.parametrize("container", ["list", "dict"])
def test_pickle_reconstruction317_model_rejects_oversized_mutable_noarg_state(
    monkeypatch, container
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    value = (
        "[" + ",".join("0" for _ in range(513)) + "]"
        if container == "list"
        else "{" + ",".join(f"{index}:0" for index in range(513)) + "}"
    )
    source = f"class NoArgError(Exception):\n    def __init__(self):\n        self.args = ()\n        self.payload = {value}\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "NoArgError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("NoArgError()", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=view
        )
        is None
    )


def test_pickle_reconstruction317_model_v2_profile_preserves_v1_replay_gate(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = "class LegacyError(Exception):\n    def __init__(self, value):\n        self.args = (value, 'different')\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "LegacyError", model_version=1
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("LegacyError('input')", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=view
        )
        is None
    )


@pytest.mark.parametrize("tuple_items, accepted", [(252, True), (253, False)])
def test_pickle_reconstruction317_model_enforces_shared_512_state_boundary(
    monkeypatch, tuple_items, accepted
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    payload = ",".join("0" for _ in range(tuple_items))
    source = f"class NoArgError(Exception):\n    def __init__(self):\n        self.args = ()\n        self.payload = ({payload},)\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "NoArgError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse("NoArgError()", mode="eval").body
    record = finite_capture.provider_exception_record(
        profile, sources, call, selected_contract_view=view
    )
    assert (record is not None) is accepted


def test_pickle_reconstruction317_model_rejects_duplicate_module_identities(
    monkeypatch,
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import RuntimeAuditError

    contract, _ = _pickle_reconstruction317_contract(
        monkeypatch,
        "alpha",
        "class LocalError(Exception):\n    pass\n",
        "LocalError",
    )
    contract["artifacts"]["alpha/errors/__init__.py"] = "4" * 64
    with pytest.raises(RuntimeAuditError, match="E_ANALYSIS_PROFILE"):
        finite_capture.provider_analysis_profile("trusted-dependencies-v2", (contract,))


@pytest.mark.parametrize("size, accepted", [(16_384, True), (16_385, False)])
def test_pickle_reconstruction317_model_bounds_scalar_bytes(
    monkeypatch, size, accepted
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = "class ScalarError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "ScalarError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse(f"ScalarError({('x' * size)!r})", mode="eval").body
    record = finite_capture.provider_exception_record(
        profile, sources, call, selected_contract_view=view
    )
    assert (record is not None) is accepted


@pytest.mark.parametrize("bits, accepted", [(4_096, True), (4_097, False)])
def test_pickle_reconstruction317_model_bounds_integer_bits(
    monkeypatch, bits, accepted
):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    source = "class ScalarError(Exception):\n    def __init__(self, value):\n        self.args = (value,)\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "ScalarError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    value = 1 << (bits - 1)
    call = ast.parse(f"ScalarError({value:#x})", mode="eval").body
    record = finite_capture.provider_exception_record(
        profile, sources, call, selected_contract_view=view
    )
    assert (record is not None) is accepted


def test_pickle_reconstruction317_model_rejects_exponential_fstring_growth(monkeypatch):
    from factoryline import finite_capture
    from factoryline.runtime_audit_common import canonical_bytes

    body = "\n".join("        self.text = f'{self.text}{self.text}'" for _ in range(10))
    source = f"class GrowthError(Exception):\n    def __init__(self, text):\n{body}\n        self.args = (self.text,)\n"
    contract, sources = _pickle_reconstruction317_contract(
        monkeypatch, "pkg", source, "GrowthError"
    )
    profile = finite_capture.provider_analysis_profile(
        "trusted-dependencies-v2", (contract,)
    )
    digest = hashlib.sha256(canonical_bytes(profile["contracts"][0])).hexdigest()
    view = finite_capture.provider_contract_view(profile, digest)
    call = ast.parse(f"GrowthError({'x' * 32!r})", mode="eval").body
    assert (
        finite_capture.provider_exception_record(
            profile, sources, call, selected_contract_view=view
        )
        is None
    )
