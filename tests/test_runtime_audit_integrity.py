import hashlib
from factoryline import review_audits
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
    assert row["tier"] == "SUPPORTED_DEFECT"
    assert row["evidence"] == "source_bound_known_format_declaration_value"
    assert row["raw_finding"]["severity"] == "CRITICAL"
    assert report["raw_diagnostics"]["count"] == 1
    assert report["tier_counts"] == {
        "SUPPORTED_DEFECT": 1,
        "NEEDS_CONTEXT": 0,
        "PROVEN_PRIMITIVE": 0,
    }
    assert report["claim_policy"]["held_out_precision"] == "NOT_MEASURED"
    assert report["retention_metrics"]["known_true_positive_retention"].startswith(
        "NOT_MEASURED"
    )
    assert report["defect_gate"]["state"] == "BLOCKED"
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
    assert report["defect_gate"]["state"] == "BLOCKED"


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
