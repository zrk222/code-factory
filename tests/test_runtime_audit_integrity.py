import pytest
from factoryline.runtime_audit import evaluate_runtime_audit
from factoryline.runtime_audit_integrity import index_executions, repair_guidance
from factoryline.runtime_audit_common import RuntimeAuditError
from test_runtime_audit import _plan, _command
import ast
from factoryline.runtime_audit_integrity import closed_declaration_input_witness
from factoryline.runtime_audit_integrity import finite_literal_eval_input_witness


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
