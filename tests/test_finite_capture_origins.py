"""Source-only finite-input admission must reject mutable capture origins."""

from factoryline import finite_capture as finite
from factoryline import review_audits
from factoryline import review_integrity
from factoryline import runtime_audit_integrity as runtime

import pytest
from test_runtime_audit_integrity import _json_enum_graph
import ast
import hashlib
import json
from factoryline.provenance import finite_template_binding, finite_template_witness
from factoryline.review_integrity import _fixed_primitive_binding
from datetime import datetime, timedelta, timezone
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.independent_execution import (
    ExecutionAttestationError,
    PAYLOAD_TYPE,
    SCHEMA,
    validate_execution_attestation,
    verify_signed_execution_attestation,
)


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("consume(django.utils.timezone.now)", {"django.utils.timezone.now"}),
        ("consume(default=django.utils.timezone.now)", {"django.utils.timezone.now"}),
        ("consume([django.utils.timezone.now])", {"django.utils.timezone.now"}),
        ("consume(django.utils)", {"django.utils"}),
        ("consume(django)", {"django"}),
        (
            "consume(django.utils.timezone.now.__globals__)",
            {
                "django",
                "django.utils",
                "django.utils.timezone",
                "django.utils.timezone.now",
                "django.utils.timezone.now.__globals__",
            },
        ),
    ],
)
def test_provider_value_escape_does_not_escape_implicit_receivers(expression, expected):
    tree = ast.parse("import django\n" + expression)
    nodes = list(ast.walk(tree))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    facts = finite.finite_provider_mutation_index(
        nodes, {"django": "django"}, review_audits, parents
    )
    assert {path for path, attribute in facts if attribute == "*"} == expected


def test_provider_value_escape_preserves_actual_namespace_writes():
    tree = ast.parse("import django\ndjango.utils.log.RequireDebugTrue = replacement\n")
    nodes = list(ast.walk(tree))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    facts = finite.finite_provider_mutation_index(
        nodes, {"django": "django"}, review_audits, parents
    )
    assert ("django.utils.log", "RequireDebugTrue") in facts


@pytest.mark.parametrize(
    "statement, uncertain",
    [
        ("consume(request.args.next)", False),
        ("consume(request.args['next'])", False),
        ("consume(request.args)", False),
        ("consume(request)", True),
        ("consume(request.args.__class__)", True),
        ("request.args.next = replacement", True),
        ("setattr(request, 'get_data', replacement)", True),
    ],
)
def test_request_data_projections_preserve_actual_provider_risks(statement, uncertain):
    from factoryline import semantic_credential_sensor as sensor

    tree = ast.parse("from flask import request\n" + statement)
    nodes = list(ast.walk(tree))
    aliases = {"request": "flask.request"}
    inventory = sensor._native_input_provider_inventory(tree, aliases, nodes)
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    assert (
        sensor._provider_identity_uncertain(
            tree, aliases, roots=("flask.request",), nodes=inventory, parents=parents
        )
        is uncertain
    )


def test_assignment_expression_reuses_one_projection_in_real_assignment(monkeypatch):
    from factoryline.credential_role_identity_effects import _Value

    statement = ast.parse("result = payload").body[0]
    requests = finite._SecurityFlowState(
        {"payload"}, {"payload": _Value(roots=frozenset({"request"}))}
    )
    original = finite.security_structural_value
    seen = []

    def counted(node, *args, **kwargs):
        if node is statement.value:
            seen.append(node)
        return original(node, *args, **kwargs)

    monkeypatch.setattr(finite, "security_structural_value", counted)
    review_integrity._security_flow_source_assignment(
        statement, {}, requests, set(), set(), set(), set(), {}
    )
    assert len(seen) == 1
    assert "result" in requests
    assert requests.values["result"].roots == frozenset({"request"})


@pytest.mark.parametrize("change", ["state", "aliases", "ast", "branch", "provider"])
def test_assignment_expression_never_reuses_stale_context(monkeypatch, change):
    from factoryline.credential_role_identity_effects import _Value

    statement = ast.parse("result = payload").body[0]
    aliases = {"provider": "original"}
    requests = finite._SecurityFlowState(
        values={"payload": _Value(roots=frozenset({"request"}))}
    )
    provider = ["original"]
    observations = []

    def project(expression, state, source_aliases):
        current = (
            expression.id == "payload"
            and bool(state.values["payload"].roots)
            and source_aliases["provider"] == "original"
            and provider[0] == "original"
        )
        observations.append(current)
        return _Value(roots=frozenset({"request" if current else "changed"}))

    monkeypatch.setattr(review_integrity, "_security_structural_expression", project)

    def assign(state):
        review_integrity._security_flow_source_assignment(
            statement, aliases, state, set(), set(), set(), set(), {}
        )

    assign(requests)
    assert requests.values["result"].roots == frozenset({"request"})
    if change in {"state", "branch"}:
        if change == "branch":
            requests = requests.copy()
        requests.values["payload"] = _Value()
    elif change == "aliases":
        aliases["provider"] = "changed"
    elif change == "ast":
        statement.value.id = "changed"
    else:
        provider[0] = "changed"
    assign(requests)
    assert requests.values["result"].roots == frozenset({"changed"})
    assert observations == [True, False]


def test_assignment_expression_unknown_keeps_payload_fallback(monkeypatch):
    from factoryline.credential_role_identity_effects import _Value
    from factoryline import semantic_credential_sensor

    statement = ast.parse("result = payload").body[0]
    requests = finite._SecurityFlowState()
    monkeypatch.setattr(
        review_integrity,
        "_security_structural_expression",
        lambda *_: _Value(unknown=True),
    )
    calls = []
    monkeypatch.setattr(
        semantic_credential_sensor,
        "request_payload_value_kind",
        lambda *args: calls.append(args[0]) or "text",
    )
    review_integrity._security_flow_source_assignment(
        statement, {}, requests, set(), set(), set(), set(), {}
    )
    assert calls == [statement.value]
    assert ("request-type:text", "result") in requests


@pytest.mark.parametrize(
    "sink,code",
    [
        ("eval(self.config)", "SECURITY_DYNAMIC_EXECUTION"),
        ("os.system(self.config)", "SECURITY_OS_COMMAND"),
        ("subprocess.call(self.config, shell=True)", "SECURITY_SHELL_COMMAND"),
    ],
)
def test_shared_storage376_request_writer_reaches_exact_declared_field(
    tmp_path, sink, code
):
    """persisted_field_input follows a request writer only to its exact declared model field and sink."""
    (tmp_path / "empty.py").write_bytes(b"")
    (tmp_path / "metadata.py").write_text(
        "import os\nfrom flask import request\n"
        "def metadata():\n    log(ip=request.remote_addr)\n"
        "    file = request.files['file']\n    filename = file.filename\n"
        "    log(filename)\n    return os.name\n",
        encoding="utf-8",
    )
    (tmp_path / "models.py").write_text(
        "import os, subprocess\nfrom sqlalchemy import Column, Text\n"
        "from sqlalchemy.orm import declarative_base\nBase = declarative_base()\n"
        "class Entry(Base):\n    __tablename__ = 'entry'\n"
        "    config = Column(Text)\n    def consume(self):\n"
        f"        return {sink}\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from flask import Flask, request\nfrom models import Entry\n"
        "app = Flask(__name__)\n@app.route('/set', methods=['POST'])\n"
        "def update():\n    value = request.form['code']\n"
        "    Entry.query.update({'config': value})\n",
        encoding="utf-8",
    )
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v3"
        )
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == code
    ]
    assert len(rows) == 1
    assert rows[0]["tier"] == "SUPPORTED_DEFECT"
    premise = rows[0]["raw_finding"]["facts"]["security_precondition"]
    witness = premise["persisted_input"]
    assert witness["field"]["attribute"] == "config"
    assert witness["model"]["class"] == "Entry"
    assert witness["writer"]["path"] == "routes.py"
    assert (
        witness["writer"]["sha256"]
        == hashlib.sha256((tmp_path / "routes.py").read_bytes()).hexdigest()
    )
    assert premise["runtime_execution"] == "not_performed"


@pytest.mark.parametrize(
    "case",
    [
        "dead_writer",
        "duplicate_key",
        "unpacked_key",
        "shadowed_str",
        "mutated_str",
        "alias_overwrite",
        "reflective_overwrite",
        "dict_overwrite",
        "custom_query",
        "empty_filter",
        "different_field",
        "constant_writer",
        "unsupported_pickle_kind",
        "inherited_query",
        "false_filter",
        "request_escape",
        "request_override",
        "request_module_override",
        "request_args_item_mutation",
        "request_args_escape",
        "request_local_override",
        "request_local_setattr",
        "request_foreign_escape",
        "request_foreign_override",
        "os_escape",
        "os_override",
        "selector_escape",
    ],
)
def test_shared_storage376_rejects_unsupported_persisted_premises(tmp_path, case):
    prefix = {
        "alias_overwrite": "        alias = self\n        alias.config = '1'\n",
        "reflective_overwrite": "        setattr(self, 'config', '1')\n",
        "dict_overwrite": "        self.__dict__['config'] = '1'\n",
    }.get(case, "")
    query = "    query = None\n" if case == "custom_query" else ""
    sink = (
        "pickle.loads(self.config)"
        if case == "unsupported_pickle_kind"
        else "eval(self.config)"
    )
    (tmp_path / "models.py").write_text(
        "import pickle\nfrom sqlalchemy import Column, Text\n"
        "from sqlalchemy.orm import declarative_base\nBase = declarative_base()\n"
        + ("Base.query = None\n" if case == "inherited_query" else "")
        + "class Entry(Base):\n    __tablename__ = 'entry'\n    config = Column(Text)\n"
        + query
        + "    def consume(self):\n"
        + prefix
        + f"        return {sink}\n",
        encoding="utf-8",
    )
    argument = "str=lambda value: '1'" if case == "shadowed_str" else ""
    dictionary = {
        "duplicate_key": "{'config': value, 'config': '1'}",
        "unpacked_key": "{'config': value, **{'config': '1'}}",
        "different_field": "{'other': value}",
        "constant_writer": "{'config': '1'}",
    }.get(case, "{'config': value}")
    if case in {"shadowed_str", "mutated_str"}:
        dictionary = "{'config': str(value)}"
    receiver = {
        "empty_filter": "Entry.query.filter(False)",
        "false_filter": "Entry.query.filter(1 == 2)",
    }.get(case, "Entry.query")
    write = f"    {receiver}.update({dictionary})\n"
    if case == "dead_writer":
        write = "    if False:\n    " + write
    mutation = {
        "mutated_str": "import builtins\nbuiltins.str = lambda value: '1'\n",
        "request_escape": "mutate(request)\n",
        "request_override": "request.form = fake\n",
        "request_module_override": "import flask\nflask.request = fake\n",
        "request_args_item_mutation": "request.args['code'] = fake\n",
        "request_args_escape": "mutate(request.args)\n",
        "os_escape": "import os\nmutate(os)\n",
        "os_override": "import os\nos.system = fake\n",
        "selector_escape": "import os\nrequest.files[mutate(os)]\n",
    }.get(case, "")
    local_mutation = {
        "request_local_override": "    request.form = fake\n",
        "request_local_setattr": "    setattr(request, 'form', fake)\n",
    }.get(case, "")
    (tmp_path / "routes.py").write_text(
        "from flask import request\nfrom models import Entry\n"
        + mutation
        + f"def update({argument}):\n"
        + local_mutation
        + "    value = request.form['code']\n"
        + write,
        encoding="utf-8",
    )
    if case in {"request_foreign_escape", "request_foreign_override"}:
        (tmp_path / "mutation.py").write_text(
            "from flask import request\n"
            + (
                "mutate(request)\n"
                if case.endswith("escape")
                else "request.form = fake\n"
            ),
            encoding="utf-8",
        )
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v3"
        )
    code = (
        "SECURITY_UNSAFE_DESERIALIZATION"
        if case == "unsupported_pickle_kind"
        else "SECURITY_DYNAMIC_EXECUTION"
    )
    rows = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == code
    ]
    assert len(rows) == 1
    assert rows[0]["tier"] != "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "source",
    [
        "def run():\n    return\n    eval(value)\n",
        "class Owner:\n    def run(self):\n        return\n        eval(value)\n",
    ],
)
def test_shared_storage376_lexical_parent_binding_preserves_dead_sink(source):
    tree = ast.parse(source)
    review_integrity.bind_security_call_scopes(tree)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    from factoryline.semantic_credential_sensor import (
        security_precondition_path_possible,
    )

    assert not security_precondition_path_possible(call)


_CAPTURE = (
    "import pytest\nfrom common import VALUES\n"
    "@pytest.mark.parametrize('field', sorted(VALUES))\n"
    "def test_generated(field):\n"
    "    exec(f'async def test_fn({field}: int) -> None: pass', {}, {})\n"
)


def test_canonical_capture_has_source_only_proof(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert graph.snapshot_complete
    assert len(graph.finite_template_inputs()) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "from builtins import globals as ns\nns()['sorted'] = altered_sort\n",
        "def poison():\n    globals()['sorted'] = altered_sort\npoison()\n",
        "def poison():\n    globals()['sorted'] = altered_sort\nalias = poison\nalias()\n",
    ],
)
def test_namespace_capture_mutations_keep_input_unknown(tmp_path, prefix):
    graph = _json_enum_graph(
        tmp_path,
        test_source=prefix + _CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()


def test_collection_hooks_keep_input_unknown(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="def pytest_collection_modifyitems(items): pass\n",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()


def _field_use_scope(node, parents):
    current = node
    while current is not None:
        current = parents.get(id(current))
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
    return None


def _field_use_chain(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return [node.id, *reversed(parts)]
    return []


def _owned_field_successors(function, value, parents):
    """Test resolver: expand one class-owned field into every captured read."""
    parent = parents.get(id(value))
    if isinstance(parent, ast.Assign) and parent.value is value:
        return _owned_field_assignment_successors(function, parent, parents)
    return _owned_field_read_successors(function, value, parents)


def _owned_field_assignment_successors(function, assignment, parents):
    targets = assignment.targets
    if len(targets) != 1 or _field_use_chain(targets[0]) != ["self", "account"]:
        return None
    owner = parents.get(id(function))
    if not isinstance(owner, ast.ClassDef):
        return ()
    stores = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Attribute)
        and _field_use_chain(node) == ["self", "account"]
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if stores != [targets[0]]:
        return ()
    reads = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Attribute)
        and _field_use_chain(node) == ["self", "account"]
        and isinstance(node.ctx, ast.Load)
    ]
    if not reads:
        return ()
    return [(_field_use_scope(read, parents), read) for read in reads]


def _owned_field_read_successors(function, value, parents):
    chain = _field_use_chain(value) if isinstance(value, ast.Attribute) else []
    if chain[:2] == ["self", "account"]:
        parent = parents.get(id(value))
        if isinstance(parent, ast.Attribute) and parent.value is value:
            return [(function, parent)]
        if isinstance(parent, ast.Call) and value in (
            *parent.args,
            *(kw.value for kw in parent.keywords),
        ):
            return [(function, parent)]
    if isinstance(value, ast.Name):
        parent = parents.get(id(value))
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "consume"
            and value in parent.args
        ):
            return [(function, parent)]
    return None


def _class_field_graph(source, terminal="consume"):
    tree = ast.parse(source)
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    owner = tree.body[0]
    setup = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "setUp"
    )
    creation = next(node for node in ast.walk(setup) if isinstance(node, ast.Call))

    def scope_of(node):
        return _field_use_scope(node, parents)

    def consumer(function, value):
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
            return None
        return value if value.func.id == terminal else None

    result = finite.captured_value_use_closure(
        setup,
        creation,
        parents,
        scope_of,
        lambda _function: None,
        consumer,
        field_successors=_owned_field_successors,
    )
    return result


def test_captured_value_use_closure_follows_source_resolved_owned_field_reads():
    result = _class_field_graph(
        "class Fixture:\n"
        " def setUp(self): self.account = build()\n"
        " def test_value(self): consume(self.account.pk)\n"
    )
    assert result is not None
    assert len(result["sinks"]) == 1


def test_captured_value_use_closure_follows_owned_field_local_alias_to_positional_sink():
    result = _class_field_graph(
        "class Fixture:\n"
        " def setUp(self): self.account = build()\n"
        " def test_value(self):\n"
        "  account = self.account\n"
        "  consume(account)\n"
    )
    assert result is not None
    assert len(result["sinks"]) == 1


def test_captured_value_use_closure_rejects_owned_field_escape_or_rebinding():
    escape = _class_field_graph(
        "class Fixture:\n"
        " def setUp(self): self.account = build()\n"
        " def test_value(self): leak(self.account)\n"
    )
    rebound = _class_field_graph(
        "class Fixture:\n"
        " def setUp(self): self.account = build()\n"
        " def test_value(self): self.account = other; consume(self.account)\n"
    )
    assert escape is None
    assert rebound is None


def test_captured_value_use_closure_does_not_assume_opaque_positional_calls_preserve_values():
    tree = ast.parse("def exercise():\n result = opaque(build())\n consume(result)\n")
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    function = tree.body[0]
    build = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "build"
    )

    def scope_of(node):
        return _field_use_scope(node, parents)

    def consumer(_function, value):
        return (
            value
            if isinstance(value, ast.Call) and ast.unparse(value.func) == "consume"
            else None
        )

    assert (
        finite.captured_value_use_closure(
            function, build, parents, scope_of, lambda _function: None, consumer
        )
        is None
    )


def test_captured_value_use_closure_bounds_caller_supplied_field_edges():
    tree = ast.parse("def exercise():\n    build()\n")
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    function = tree.body[0]
    call = next(node for node in ast.walk(function) if isinstance(node, ast.Call))
    produced = []

    def field_successors(scope, value, _parents):
        def edges():
            while True:
                produced.append(value)
                yield scope, value

        return edges()

    result = finite.captured_value_use_closure(
        function,
        call,
        parents,
        lambda node: function if node in ast.walk(function) else None,
        lambda _function: None,
        lambda _function, _value: None,
        field_successors=field_successors,
        max_states=3,
    )
    assert result is None
    assert len(produced) == 3


"""Envelope integrity tests; real native-source admission is measured separately."""


def _seal(facts):
    facts = {key: value for key, value in facts.items() if key != "proof_facts_sha256"}
    facts["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return facts


def _packet(tmp_path):
    code = (
        "@pytest.mark.parametrize('field', sorted(VALUES))\n"
        "def test_generated(field):\n"
        "    exec(f'async def test_fn({field}: int): pass', {}, {})\n"
    ).encode()
    domain = b"VALUES = {'request', 'socket'}\n"
    raw = {
        tmp_path / "tests/test_generated.py": code,
        tmp_path / "constants.py": domain,
    }
    rows = [
        {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for path, data in raw.items()
    ]
    bindings = {row["path"]: row["sha256"] for row in rows}
    tree = ast.parse(code)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    )

    def span(node):
        return [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ]

    facts = {
        "schema": "factory.finite-template-input.v1",
        "disposition": "PROVEN_FINITE_TEMPLATE_INPUT",
        "scope_profile": "pytest-collection-finite-parameter",
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "input_effect": "FINITE_SOURCE_TEMPLATE_INPUT",
        "runtime_assurance": "INCOMPLETE",
        "execution_effects": "UNASSESSED",
        "target_execution": "not_performed",
        "source_path": "tests/test_generated.py",
        "source_sha256": bindings["tests/test_generated.py"],
        "capture_path": "tests/test_generated.py",
        "capture_sha256": bindings["tests/test_generated.py"],
        "capture_span": span(tree.body[0].decorator_list[0]),
        "domain_path": "constants.py",
        "domain_sha256": bindings["constants.py"],
        "domain_span": span(ast.parse(domain).body[0].value),
        "call_span": span(call),
        "template_span": span(call.args[0]),
        "template_sha256": hashlib.sha256(ast.dump(call.args[0]).encode()).hexdigest(),
        "domain_size": 2,
        "program_hashes": [
            hashlib.sha256(name.encode()).hexdigest() for name in ("request", "socket")
        ],
        "workspace_sources_sha256": hashlib.sha256(
            json.dumps(sorted(bindings.items()), separators=(",", ":")).encode()
        ).hexdigest(),
    }
    finding = {
        "path": "tests/test_generated.py",
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "line": call.lineno,
        "column": call.col_offset,
        "facts": _seal(facts),
    }
    return finding, rows, bindings, call, raw


@pytest.mark.parametrize("changed", ["constants.py", "tests/test_generated.py"])
def test_finite_input_envelope_is_dispatched_and_source_bound(tmp_path, changed):
    finding, rows, bindings, call, raw = _packet(tmp_path)
    assert finite_template_binding(finding, rows, bindings)
    assert _fixed_primitive_binding(finding, rows, bindings)
    profile = {"finite_template_inputs": {"3:4": finding["facts"]}}
    assert (
        finite_template_witness(finding["path"], call, "exec", tmp_path, raw, profile)
        == finding["facts"]
    )
    raw[tmp_path / changed] += b"# stale source snapshot\n"
    assert not finite_template_witness(
        finding["path"], call, "exec", tmp_path, raw, profile
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_assurance", "COMPLETE"),
        ("execution_effects", "SAFE"),
        ("hypothesis", "SOFTWARE_CORRECT"),
        ("target_execution", "performed"),
        ("domain_size", True),
        ("domain_size", 65),
        ("program_hashes", []),
        ("program_hashes", ["not-a-hash", "not-a-hash"]),
        ("capture_path", "elsewhere.py"),
        ("domain_sha256", "0" * 64),
        ("source_sha256", "0" * 64),
        ("capture_sha256", "0" * 64),
        ("call_span", [4, 4, 4, 8]),
        ("template_span", [2, 0, 2, 8]),
        ("capture_span", [4, 0, 4, 8]),
        ("domain_span", [0, 0, 0, 1]),
        ("workspace_sources_sha256", "0" * 64),
        ("template_sha256", "invalid"),
    ],
)
def test_resealed_invalid_finite_input_is_not_admitted(tmp_path, field, value):
    finding, rows, bindings, _, _ = _packet(tmp_path)
    finding["facts"] = _seal({**finding["facts"], field: value})
    assert not finite_template_binding(finding, rows, bindings)
    assert not _fixed_primitive_binding(finding, rows, bindings)


def test_finite_input_rejects_unsealed_changes_and_duplicate_source_identity(tmp_path):
    finding, rows, bindings, _, _ = _packet(tmp_path)
    finding["facts"]["domain_size"] = 1
    assert not finite_template_binding(finding, rows, bindings)
    finding, rows, bindings, _, _ = _packet(tmp_path)
    assert not finite_template_binding(finding, rows + [rows[0]], bindings)


def test_native_finite_wrapper_rejects_stale_span_and_malformed_ledger(tmp_path):
    finding, _, _, call, raw = _packet(tmp_path)
    facts = {**finding["facts"], "call_span": [4, 0, 4, 20]}
    for ledger in ({"3:4": facts}, []):
        assert not finite_template_witness(
            finding["path"],
            call,
            "exec",
            tmp_path,
            raw,
            {"finite_template_inputs": ledger},
        )


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _payload(**overrides):
    now = datetime.now(timezone.utc)
    value = {
        "schema": SCHEMA,
        "attestation_id": "att-001",
        "candidate_sha256": _digest("a"),
        "plan_sha256": _digest("b"),
        "run_nonce": "nonce-001",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "assurance_level": "isolated_worker",
        "runner": {
            "id": "runner-1",
            "version": "1.0.0",
            "platform": "linux",
            "backend": "isolated_worker",
            "executable_sha256": _digest("c"),
        },
        "observations": {
            "target_artifact_sha256": _digest("d"),
            "known_bad_artifact_sha256": _digest("e"),
            "target_stdout_sha256": _digest("f"),
            "target_stderr_sha256": None,
            "cleanup_confirmed": True,
            "memory_peak_bytes": 128,
            "latency_ms": 7,
        },
        "authority": "none",
    }
    value.update(overrides)
    return value


def test_valid_attestation_normalizes_and_has_no_authority():
    result = validate_execution_attestation(_payload())
    assert result["schema"] == SCHEMA
    assert result["observations"]["memory_peak_bytes"] == 128
    assert result["authority"] == "none"


def test_supervised_local_is_rejected_for_independent_lane():
    payload = _payload(assurance_level="supervised_local")
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_ASSURANCE"):
        validate_execution_attestation(payload)


def test_independent_assurance_rejects_local_backend():
    payload = _payload()
    payload["runner"] = {**payload["runner"], "backend": "local_supervised"}
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BACKEND"):
        validate_execution_attestation(payload)


def test_binding_cleanup_expiry_replay_and_unknown_fields_fail_closed():
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BINDING"):
        validate_execution_attestation(_payload(), candidate_sha256=_digest("z"))
    incomplete = _payload()
    incomplete["observations"]["cleanup_confirmed"] = False
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_INCOMPLETE"):
        validate_execution_attestation(incomplete)
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_REPLAY"):
        validate_execution_attestation(_payload(), seen_nonces=["nonce-001"])
    unknown = _payload()
    unknown["unexpected"] = True
    with pytest.raises(ExecutionAttestationError, match="E_ARTIFACT_FIELDS"):
        validate_execution_attestation(unknown)


def test_signed_attestation_verifies_against_local_trust_root(tmp_path):
    keys = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="runner-key",
        identity="runner@example",
        issuer="local",
    )
    payload = _payload()
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=keys["private_key"],
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "attestation.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_signed_execution_attestation(
        receipt,
        keys["trust_root"],
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
    )
    assert result["state"] == "VERIFIED"
    assert result["release_approval"] is False
    other_root = tmp_path / "other-trust-root.json"
    other_root.write_text(
        json.dumps({"schema": "factory.trust.root.v1", "version": 1, "keys": []}),
        encoding="utf-8",
    )
    with pytest.raises(ExecutionAttestationError, match="E_UNKNOWN_KEY"):
        verify_signed_execution_attestation(receipt, other_root)


def test_shell_operation_witness_reconstructs_supported_command_and_rejects_shell_syntax():
    source = b"import os\nos.system('upx --best app')\n"
    tree = ast.parse(source)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    span = [call.lineno, call.col_offset, call.end_lineno, call.end_col_offset]
    witness = finite.closed_shell_operation_witness(
        source, "build.py", span, "os.system"
    )
    assert witness["operation_role"] == "executable_packing"
    assert witness["target_execution"] == "not_performed"
    unsafe = b"import os\nos.system('upx --best app; evil')\n"
    unsafe_call = next(
        node for node in ast.walk(ast.parse(unsafe)) if isinstance(node, ast.Call)
    )
    unsafe_span = [
        unsafe_call.lineno,
        unsafe_call.col_offset,
        unsafe_call.end_lineno,
        unsafe_call.end_col_offset,
    ]
    assert (
        finite.closed_shell_operation_witness(
            unsafe, "build.py", unsafe_span, "os.system"
        )
        == {}
    )


def test_closed_shell_workspace_hashes_clean_inventory_and_rejects_provider_shadow():
    clean = {"app.py": b"import os\nos.system('upx --best app')\n"}
    digest = finite.closed_shell_workspace(clean, "os")
    assert isinstance(digest, str) and len(digest) == 64
    assert digest == finite.closed_shell_workspace(clean, "os")
    assert (
        finite.closed_shell_workspace({"os.py": b"def system(x): pass\n"}, "os") is None
    )


def test_finite_scope_binding_and_blocked_prefixes_preserve_semantics():
    tree = ast.parse("def run(secret):\n    secret = None\n")
    args = next(node for node in ast.walk(tree) if isinstance(node, ast.arg))
    stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    ]
    assert finite.finite_scope_binding_candidate(args, {"secret"})
    assert finite.finite_scope_binding_candidate(stores[0], {"secret"})
    assert not finite.finite_scope_binding_candidate(stores[0], {"other"})
    prefixes = finite.finite_blocked_provider_prefixes(
        {("test.py", "client")}, {"test.py": {"client": "provider.api.client"}}
    )
    assert prefixes == {"provider", "provider.api", "provider.api.client"}


def test_finite_template_program_hashes_only_fixed_async_function_grammar():
    template = (
        ast.parse('f"async def run({parameter}) -> None:\\n    pass\\n"').body[0].value
    )
    result = finite.finite_template_program_hashes(
        template, "parameter", ["user_id", "tenant_id"]
    )
    assert result is not None
    skeleton_hash, rows = result
    assert len(skeleton_hash) == 64
    assert len(rows) == 2 and all(len(digest) == 64 for digest in rows)
    assert finite.finite_template_program_hashes(template, "other", ["user_id"]) is None


def test_shell_call_catalog_and_source_bound_finding_keep_safe_effect_unassessed(
    tmp_path,
):
    calls = finite.shell_execution_calls()
    assert {"os.system", "subprocess.run", "subprocess.Popen"}.issubset(calls)
    raw = b"import os\nos.system('upx --best app')\n"
    root = tmp_path
    path = root / "build.py"
    path.write_bytes(raw)
    module = ast.parse(raw)
    module._security_source_context = (root, {path: raw})
    module._oracle_source_sha256 = __import__("hashlib").sha256(raw).hexdigest()
    call = next(node for node in ast.walk(module) if isinstance(node, ast.Call))
    call._security_lexical_scope = module
    finding = finite.closed_shell_finding("os.system", "build.py", call)
    assert finding["code"] == "SECURITY_OS_COMMAND"
    assert finding["facts"]["operation_role"] == "executable_packing"
    assert finding["facts"]["target_execution"] == "not_performed"
    assert finite.closed_shell_finding("subprocess.run", "build.py", call) is None


def test_finite_domain_reference_rules_distinguish_capture_membership_and_tail():
    tree = ast.parse("selected = sorted(domain)\nvalid = value in domain\n")
    capture = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    captured_name = capture.args[0]
    references = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "domain"
    ]
    membership_use = references[-1]
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    assert finite.finite_domain_reference_allowed(
        "tests/test.py",
        captured_name,
        (),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )
    assert finite.finite_domain_reference_allowed(
        "tests/test.py",
        membership_use,
        (),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )
    assert not finite.finite_domain_reference_allowed(
        "tests/test.py",
        membership_use,
        ("child",),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )


def test_finite_provider_attribute_write_index_detects_alias_mutation():
    tree = ast.parse("client.token = replacement\n")
    nodes = list(ast.walk(tree))
    aliases = {"client": "provider.api.client"}
    writes = finite.finite_provider_attribute_write_index(nodes, aliases, review_audits)
    assert ("provider.api.client", "token") in writes
    assert (
        finite.finite_provider_attribute_write_index([], aliases, review_audits)
        == set()
    )


def test_finite_template_capture_shape_accepts_only_sorted_parametrize_capture():
    source = "@pytest.mark.parametrize('program', sorted(programs))\ndef test_program(program):\n    assert program\n"
    function = ast.parse(source).body[0]
    shape = finite.finite_template_capture_shape(
        function, {"pytest": "pytest"}, review_audits, review_integrity
    )
    assert shape[0] == "program"
    assert isinstance(shape[1], ast.Call) and shape[1].func.id == "sorted"
    wrong = ast.parse(source.replace("sorted(programs)", "programs")).body[0]
    assert (
        finite.finite_template_capture_shape(
            wrong, {"pytest": "pytest"}, review_audits, review_integrity
        )
        is None
    )


def _pickle_origin(source, aliases=None):
    module = ast.parse(source)
    runtime._conditional_provider_parents(module)
    aliases = aliases or {"pickle": "pickle"}
    load_name = next(iter(aliases.values())) + ".loads"
    loads = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, aliases) == load_name
    ]
    assert len(loads) == 1
    return runtime.closed_local_pickle_origin(
        loads[0], load_name, aliases, review_audits
    )


@pytest.mark.parametrize(
    "roundtrip, kind, protocol",
    [
        (
            "result = pickle.loads(pickle.dumps(obj))",
            "nested",
            {"kind": "default", "source": "omitted"},
        ),
        (
            "packed = pickle.dumps(obj, protocol=4)\nresult = pickle.loads(packed)",
            "named_payload",
            {"kind": "integer", "value": 4, "source": "keyword_literal"},
        ),
        (
            "packed = pickle.dumps(obj, None)\nresult = pickle.loads(packed)",
            "named_payload",
            {"kind": "default", "source": "explicit_none"},
        ),
    ],
)
def test_pickle_origin_normalizes_native_nested_and_named_roundtrips(
    roundtrip, kind, protocol
):
    source = f"import pickle\ndef run(obj):\n    {roundtrip.replace(chr(10), chr(10) + '    ')}\n"
    origin = _pickle_origin(source)
    assert origin is not None
    assert origin["status"] == "LOCAL_DIRECT_DUMPS_LOADS_ORIGIN"
    assert origin["origin_kind"] == kind
    assert origin["protocol"] == protocol
    assert isinstance(origin["dump_call"], ast.Call)
    assert isinstance(origin["object_expression"], ast.Name)


@pytest.mark.parametrize(
    "body",
    [
        "packed = pickle.dumps(obj)\nalias = packed\nresult = pickle.loads(packed)",
        "packed = pickle.dumps(obj)\n"
        "packed += b'changed'\n"
        "result = pickle.loads(packed)",
        "packed = pickle.dumps(obj)\n"
        "packed = replacement\n"
        "result = pickle.loads(packed)",
        "global packed\npacked = pickle.dumps(obj)\nresult = pickle.loads(packed)",
    ],
)
def test_pickle_named_origin_rejects_payload_alias_mutation_and_global_escape(body):
    source = "import pickle\ndef run(obj):\n    " + body.replace("\n", "\n    ") + "\n"
    assert _pickle_origin(source) is None


def test_pickle_nested_origin_is_separate_from_reconstruction_effect_proof():
    source = (
        "import pickle\n"
        "def run():\n"
        "    result = pickle.loads(pickle.dumps(make_unknown()))\n"
    )
    origin = _pickle_origin(source)
    assert origin is not None
    assert origin["object_expression"].func.id == "make_unknown"
    module = ast.parse(source)
    runtime._conditional_provider_parents(module)
    loads = next(
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, {"pickle": "pickle"})
        == "pickle.loads"
    )
    assert (
        runtime.closed_local_pickle_flow(
            loads, "pickle.loads", {"pickle": "pickle"}, review_audits
        )
        is None
    )


def test_pickle_origin_keeps_import_identity_and_rejects_local_serializer_rebinding():
    """pickle_serializer_imports_closed requires the captured serializer identity and rejects local rebinding."""
    source = (
        "import pickle as serializer\n"
        "def run(obj):\n"
        "    result = serializer.loads(serializer.dumps(obj))\n"
    )
    origin = _pickle_origin(source, {"serializer": "pickle"})
    assert origin is not None and origin["origin_kind"] == "nested"
    rebound = source.replace(
        "    result =",
        "    serializer = replacement\n    result =",
    )
    assert _pickle_origin(rebound, {"serializer": "pickle"}) is None


def test_pickle_origin_rejects_non_native_serializer_namespace():
    source = "import json\ndef run(obj):\n    result = json.loads(json.dumps(obj))\n"
    assert _pickle_origin(source, {"json": "json"}) is None


@pytest.mark.parametrize(
    "extra_import, write, expected_origin",
    [
        ("", "requests.get = replacement", True),
        ("", "pickle.loads = replacement", False),
        (
            "import sys as system\n",
            "system.modules['pickle'].loads = replacement",
            False,
        ),
        (
            "import sys as system\n",
            "setattr(getattr(system, 'modules')['pickle'], 'loads', replacement)",
            False,
        ),
        (
            "import importlib as loader\n",
            "loader.import_module('pickle').loads = replacement",
            False,
        ),
        ("", "other = pickle\n    other.loads = replacement", False),
        ("", "opaque(pickle)", False),
    ],
)
def test_pickle_direct_origin_ignores_unrelated_module_mutations(
    extra_import, write, expected_origin
):
    source = (
        "import pickle\nimport requests\n"
        + extra_import
        + "def roundtrip(value):\n    "
        + write
        + "\n    payload = pickle.dumps(value)\n    return pickle.loads(payload)\n"
    ).encode()
    caller = "test_case.py"
    tree = ast.parse(source)
    runtime._conditional_provider_parents(tree)
    # Resolve the selected call in EACH variant; import insertion changes its line.
    load = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "loads"
    )
    span = runtime._fixed_program_span(load)
    assert (
        runtime._conditional_provider_v2_direct_origin(
            {caller: source}, caller, span, review_audits
        )
        is None
    )
    origin = runtime._conditional_provider_v2_direct_origin(
        {caller: source}, caller, span, review_audits, serializer_namespace_only=True
    )
    assert (origin is not None) is expected_origin
    if origin is not None:
        assert origin["status"] == "LOCAL_DIRECT_DUMPS_LOADS_ORIGIN"
        assert origin["origin_kind"] == "named_payload"
        assert not {
            "typed_graph",
            "provider_witness",
            "negative_security_decision",
        }.intersection(origin)


def test_pickle_protocol_flow_rejects_serializer_alias_writes_and_escapes():
    prefix = [
        "import pickle",
        "import requests",
        "def roundtrip():",
        "    requests.get = replacement",
    ]
    suffix = [
        "    obj = ValueError('fixed')",
        "    for proto in range(pickle.HIGHEST_PROTOCOL + 1):",
        "        payload = pickle.dumps(obj, proto)",
        "        pickle.loads(payload)",
    ]
    programs = {
        "clean": prefix + suffix,
        "alias_write": prefix
        + ["    other = pickle", "    other.loads = replacement"]
        + suffix,
        "opaque_escape": prefix + ["    opaque(pickle)"] + suffix,
    }
    outcomes = {}
    for label, lines in programs.items():
        source = "\n".join(lines).encode()
        tree = ast.parse(source)
        runtime._conditional_provider_parents(tree)
        aliases = runtime._conditional_file_aliases(
            "test_case.py",
            tree,
            {"test_case.py": runtime._conditional_module_name("test_case.py")},
        )
        load_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and review_audits._normalized_call_name(node, aliases) == "pickle.loads"
        ]
        assert len(load_calls) == 1
        outcomes[label] = runtime.closed_local_pickle_flow(
            load_calls[0],
            "pickle.loads",
            aliases,
            review_audits,
            serializer_namespace_only=True,
        )

    assert outcomes["clean"] is not None
    assert outcomes["alias_write"] is None
    assert outcomes["opaque_escape"] is None


@pytest.mark.parametrize(
    "extra_source, expected_count",
    [
        ("", 1),
        ("import zlib as compression\ndef unrelated(compression):\n    pass\n", 1),
        ("def unrelated():\n    observe(LocalError)\n", 1),
        (
            "def poison():\n    alias = LocalError\n    alias.__init__ = replacement\n",
            0,
        ),
        ("pickle.loads = replacement\n", 0),
        (
            "other = pickle\nother.loads = lambda payload: print('unexpected effect')\n",
            0,
        ),
        (
            "def opaque(module):\n    module.loads = lambda payload: print('unexpected effect')\nopaque(pickle)\n",
            0,
        ),
        (
            "import sys\nversion = sys.version_info[:2]\nlimit = sys.maxsize\nexe = sys.executable\npresent = 'fixed' in sys.path\n",
            1,
        ),
        (
            "import sys\ndef opaque(module):\n    module.modules['pickle'].loads = lambda payload: None\nopaque(sys)\n",
            0,
        ),
        (
            "from sys import modules as mods\nother = mods['pickle']\nother.loads = lambda payload: None\n",
            0,
        ),
        (
            "from importlib import import_module as load\nother = load('pickle')\nother.loads = lambda payload: None\n",
            0,
        ),
    ],
)
def test_pickle_typed_v3_reuses_protocol_loop_origin_after_model_selection(
    tmp_path, extra_source, expected_count, monkeypatch
):
    from factoryline.finite_capture import provider_analysis_profile

    runtime_base = {
        "implementation": "cpython",
        "version": "3.11.9",
        "executable_sha256": "1" * 64,
        "pickle_source_sha256": "2" * 64,
        "pickle_implementation_sha256": "3" * 64,
    }
    runtime_v3 = {
        **runtime_base,
        "enum_source_sha256": "4" * 64,
        "typing_source_sha256": "5" * 64,
        "python_runtime_sha256": "6" * 64,
    }
    monkeypatch.setattr(
        finite, "_provider_runtime_identity", lambda: dict(runtime_base)
    )
    monkeypatch.setattr(
        finite, "provider_runtime_identity_v3", lambda: dict(runtime_v3)
    )

    provider_source = (
        "from enum import IntEnum\n"
        "class LocalError(Exception):\n"
        "    def __init__(self, message=None):\n"
        "        super().__init__(message)\n"
        "        self.message = message\n"
        "class WireCode(IntEnum):\n"
        "    PROTOCOL_ERROR = 7\n"
    ).encode()
    package_source = ("from .errors import LocalError, WireCode\n").encode()
    caller_source = (
        "import pickle\n"
        "from package import LocalError, WireCode\n"
        "def test_closed_record():\n"
        "    err = LocalError(WireCode.PROTOCOL_ERROR)\n"
        "    err.foo = 'bar'\n"
        "    for proto in range(pickle.HIGHEST_PROTOCOL + 1):\n"
        "        packed = pickle.dumps(err, proto)\n"
        "        result = pickle.loads(packed)\n"
        "        assert result.foo == 'bar'\n"
    ).encode() + extra_source.encode()
    sources = {
        "package/errors.py": provider_source,
        "package/__init__.py": package_source,
        "test_roundtrip.py": caller_source,
    }
    error_tree = ast.parse(provider_source)
    classes = [node for node in error_tree.body if isinstance(node, ast.ClassDef)]
    contract = {
        "schema": "factory.provider-contract.v1",
        "model": {"id": "typed-pickle-reconstruction-v3", "version": 3},
        "runtime": finite.provider_runtime_identity_v3(),
        "artifacts": {
            path: hashlib.sha256(value).hexdigest()
            for path, value in sources.items()
            if path != "test_roundtrip.py"
        },
        "export": {"path": "package/__init__.py", "symbol": "LocalError"},
        "classes": [
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
            for cls in classes
        ],
        "assumptions": list(finite._PROVIDER_ASSUMPTIONS),
    }
    for path, value in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    profile = provider_analysis_profile("trusted-dependencies-v2", (contract,))
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    witnesses = [
        row
        for row in report.get("primitive_observations", [])
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(witnesses) == expected_count
    if not expected_count:
        assert any(
            row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
            for row in report["findings"]
        )
        return
    witness = witnesses[0]["facts"]["provider_witness"]
    assert witness["selected_model_sha256"]
    assert witness["protocol"]["same_iteration"] is True


@pytest.mark.parametrize(
    "body, observed",
    [
        ("    return pickle.loads(pickle.dumps(value))\n", True),
        ("    blob = pickle.dumps(value)\n    return pickle.loads(blob)\n", True),
        (
            "    for p in range(2):\n        blob = pickle.dumps(value, p)\n        result = pickle.loads(blob)\n"
            "    for p in range(2):\n        blob = pickle.dumps(value, p)\n        result = pickle.loads(blob)\n",
            True,
        ),
        (
            "    global blob\n    blob = pickle.dumps(value)\n    return pickle.loads(blob)\n",
            False,
        ),
        (
            "    blob = pickle.dumps(value)\n    blob += supplied\n    return pickle.loads(blob)\n",
            False,
        ),
        (
            "    blob = pickle.dumps(value)\n    leak(blob)\n    return pickle.loads(blob)\n",
            False,
        ),
        ("    return pickle.loads(supplied)\n", False),
    ],
)
def test_pickle_family_byte_origin_is_type_independent_and_not_a_safety_decision(
    body, observed
):
    from factoryline import runtime_audit_integrity as runtime

    tree = ast.parse("import pickle\ndef work(value, supplied=None):\n" + body)
    runtime._conditional_provider_parents(tree)
    loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, {"pickle": "pickle"})
        == "pickle.loads"
    ]
    for load in loads:
        origin = runtime.local_pickle_byte_origin(
            load, "pickle.loads", {"pickle": "pickle"}, review_audits
        )
        assert (origin is not None) is observed
        if origin:
            assert origin["reconstruction_effects"] == "UNASSESSED"
            assert origin["negative_security_decision"] is False


def test_pickle_family_origin_observation_keeps_dangerous_reducer_diagnostic(tmp_path):
    source = (
        "import pickle\nclass Payload:\n"
        "    def __reduce__(self):\n        return eval, ('controlled_expression',)\n"
        "def work():\n    return pickle.loads(pickle.dumps(Payload()))\n"
    )
    (tmp_path / "consumer.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    findings = [
        row
        for row in report["findings"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(findings) == 1
    (ledger,) = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert ledger["raw_finding"] == findings[0]
    assert ledger["tier"] == "NEEDS_CONTEXT"
    assert ledger["byte_origin_observation"]["negative_security_decision"] is False
    assert ledger["byte_origin_observation"]["reconstruction_effects"] == "UNASSESSED"
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report.get("primitive_observations", [])
    )


def _pickle_role_report(root, source, extra=None, policy="source-role-v1"):
    path = root / "tests" / "test_roundtrip.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    for name, value in (extra or {}).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        return review_audits.security_scan(
            root, cache_enabled=False, defect_policy=policy
        )


_PICKLE_ROLE_TEST = "import pickle\ndef test_roundtrip():\n    result = pickle.loads(pickle.dumps(object()))\n    assert result\n"


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system('python setup.py sdist bdist_wheel')\n",
        "import os\nos.system('rm -rf dist build')\n",
        "import os\nos.system('twine upload -s dist/*')\n",
        "import subprocess\nsubprocess.check_call(['rmdir', '/s', '/q', 'node_modules'], cwd=selected_root, shell=True)\n",
        "import subprocess as runner\nrunner.run(('fixed-tool', 'fixed-argument'), shell=True, timeout=1)\n",
    ],
)
def test_authored_command352_v3_retains_raw_and_unassessed_effects(tmp_path, source):
    v2 = _pickle_role_report(tmp_path, source, policy="source-role-v2")
    v3 = _pickle_role_report(tmp_path, source, policy="source-role-v3")
    assert len(v2["findings"]) == 1 and not v2["context_reviews"]
    assert not v3["findings"] and len(v3["context_reviews"]) == 1
    assert v3["context_reviews"] == v2["findings"]
    row = v3["finding_tier_report"]["ledger"][0]
    assert row["raw_finding"] == v2["finding_tier_report"]["ledger"][0]["raw_finding"]
    assert row["tier"] == "NEEDS_CONTEXT"
    witness = row["source_role_review"]
    assert witness["role"] == "CAPTURED_LITERAL_PROCESS_COMMAND_INPUT"
    assert witness["safe_execution"] is False
    assert (
        witness["command_effects"]
        == witness["filesystem_and_cwd_authority"]
        == "UNASSESSED"
    )
    assert v3["defect_policy_decision"]["policy_id"] == "source-role-v3"
    assert v3["defect_policy_decision"]["clean"] is False


@pytest.mark.parametrize(
    "source,extra",
    [
        ("import os\nos.system(command)\n", {}),
        ("import os\nos.system('fixed ' + command)\n", {}),
        ("import os\nos.system(f'fixed {command}')\n", {}),
        ("import os\nos.system('first | second')\n", {}),
        ("import os\nos.system('first; second')\n", {}),
        ("import os\nos.system('first > output')\n", {}),
        ("import os\nos.system('tool $(other)')\n", {}),
        ("import os\nos.system('tool `other`')\n", {}),
        ("import os\nos.system('%WINDIR%/tool')\n", {}),
        ("import os\nos.system('python -cprint(42)')\n", {}),
        ('import os\nos.system(\'python "-c" "print(42)"\')\n', {}),
        ('import os\nos.system(\'python -""c "print(42)"\')\n', {}),
        ("import os\nos.system('cmd /\"\"c whoami')\n", {}),
        ("import os\nos.system('python -\\\\c \"print(42)\"')\n", {}),
        ("import os\nos.system('tool \\ud800')\n", {}),
        ("import os\nos.system('tool \\u2603')\n", {}),
        ("import subprocess\nsubprocess.run(['tool', argument], shell=True)\n", {}),
        ("import subprocess\nsubprocess.run(['tool', *arguments], shell=True)\n", {}),
        ("import subprocess\nsubprocess.run('tool', shell=enabled)\n", {}),
        ("import subprocess\nsubprocess.run('tool', shell=True, **options)\n", {}),
        (
            "import subprocess\nsubprocess.run('tool', shell=True, executable=other)\n",
            {},
        ),
        ("import subprocess\nsubprocess.run('tool', shell=True, env={})\n", {}),
        ("import os\nos.system = replacement\nos.system('tool')\n", {}),
        ("import os\ndef entry(os):\n    os.system('tool')\n", {}),
        ("import os\nos.system('tool')\n", {"os.py": "def system(value): pass\n"}),
        (
            "import os\nos.system('tool')\n",
            {"peer.py": "import os\nos.system = replacement\n"},
        ),
        (
            "import os\nos.system('tool')\n",
            {
                "peer.py": "import os as provider\nselected = provider\nselected.system = replacement\n"
            },
        ),
        ("from os import system as launch\nlaunch('fixed-tool --fixed-option')\n", {}),
        (
            "from flask import request\nimport os\ndef entry():\n    os.system(request.args['cmd'])\n",
            {},
        ),
    ],
)
def test_authored_command352_dynamic_and_provider_hazards_never_enter_context(
    tmp_path, source, extra
):
    prior = _pickle_role_report(tmp_path, source, extra, policy="source-role-v2")
    report = _pickle_role_report(tmp_path, source, extra, policy="source-role-v3")
    assert report["findings"] == prior["findings"]
    assert not report["context_reviews"]


def test_authored_command352_reseal_recomputes_witness_and_missing_capture_blocks(
    tmp_path,
):
    report = _pickle_role_report(
        tmp_path, "import os\nos.system('rm -rf fixed')\n", policy="source-role-v3"
    )
    report["finding_tier_report"]["ledger"][0]["source_role_review"][
        "safe_execution"
    ] = True
    report["_primitive_source_bytes"] = dict(report._captured_sources)
    rebuilt = review_audits._seal_security_scan(report)
    assert (
        rebuilt["finding_tier_report"]["ledger"][0]["source_role_review"][
            "safe_execution"
        ]
        is False
    )
    rebuilt["_primitive_source_bytes"] = {}
    blocked = review_audits._seal_security_scan(rebuilt)
    assert blocked["defect_policy_decision"]["state"] == "BLOCKED"
    assert not blocked["context_reviews"] and blocked["findings"]


@pytest.mark.parametrize(
    "binding,argument",
    [
        ("command = 'fixed-tool --fixed-option'", "command"),
        ("command = ['fixed-tool', 'fixed-argument']", "command"),
        (
            "payload = {'command': 'fixed-tool', 'other': supplied}\n    command = payload['command']",
            "command",
        ),
        ("command = fixed(supplied)", "command"),
        ("command = fixed(supplied)", "fixed(supplied)"),
    ],
)
def test_shared_command_value369_literal_result_role(tmp_path, binding, argument):
    source = (
        "import subprocess\ndef fixed(value):\n    return 'fixed-tool'\n"
        "def entry(supplied):\n    "
        + binding
        + "\n    subprocess.run("
        + argument
        + ", shell=True)\n"
    )
    report = _pickle_role_report(tmp_path, source, policy="source-role-v3")
    assert not report["findings"]
    assert len(report["context_reviews"]) == 1
    row = report["finding_tier_report"]["ledger"][0]
    assert row["source_role_review"]["safe_execution"] is False
    assert row["source_role_review"]["command_effects"] == "UNASSESSED"
    assert row["raw_finding"] == report["context_reviews"][0]
    rebuilt = review_audits._seal_security_scan(report.copy())
    assert rebuilt["context_reviews"] == report["context_reviews"]


@pytest.mark.parametrize(
    "operands",
    [
        "command, shell=True, cwd=holder.cwd",
        "command, shell=True, cwd=resolve()",
        "command, shell=True, cwd=base + 'suffix'",
        "command, shell=True, cwd={'path': holder.cwd}",
        "command, shell=True, cwd={key: 1}",
        "command, shell=True, cwd={**options}",
        "command, *args, shell=True",
        "command, shell=True, **options",
    ],
)
def test_current_call_operand_effects_cannot_restore_literal_container(
    tmp_path, operands
):
    source = (
        "import subprocess\n"
        "def entry(holder, resolve, base, options, args, key):\n"
        "    command = ['fixed-tool', 'fixed-argument']\n"
        f"    subprocess.run({operands})\n"
    )
    report = _pickle_role_report(tmp_path, source, policy="source-role-v3")
    assert [row["code"] for row in report["findings"]] == ["SECURITY_SHELL_COMMAND"]
    assert not report["context_reviews"]
    rebuilt = review_audits._seal_security_scan(report.copy())
    assert rebuilt["findings"] == report["findings"]


@pytest.mark.parametrize(
    "binding",
    [
        "command = supplied",
        "command = 'fixed ' + supplied",
        "command = f'fixed {supplied}'",
        "command = ['fixed-tool', supplied]",
        "command = {'value': supplied}['value']",
        "command = opaque(supplied)",
        "command = 'fixed | other'",
        "command = 'fixed-tool'\n    if supplied:\n        command = supplied",
        "command = ['fixed-tool']\n    peer = command\n    peer[0] = supplied",
        "command = ['fixed-tool']\n    opaque(command)",
    ],
)
def test_shared_command_value369_unknown_or_mutated_stays_active(tmp_path, binding):
    source = (
        "import subprocess\ndef entry(supplied):\n    "
        + binding
        + "\n    subprocess.run(command, shell=True)\n"
    )
    report = _pickle_role_report(tmp_path, source, policy="source-role-v3")
    assert any(row["code"] == "SECURITY_SHELL_COMMAND" for row in report["findings"])
    assert not report["context_reviews"]


@pytest.mark.parametrize(
    "observation,context",
    [
        ("assert payload", True),
        ("assert opaque(payload)", False),
        ("opaque(payload)", False),
        ("assert payload, opaque()", False),
        ("payload = external_bytes", False),
    ],
)
def test_pickle_byte_observation369_preserves_closed_edge(
    tmp_path, observation, context
):
    source = (
        "import pickle\ndef test_roundtrip():\n    payload = pickle.dumps(object())\n    "
        + observation
        + "\n    result = pickle.loads(payload)\n    assert result\n"
    )
    report = _pickle_role_report(tmp_path, source, policy="source-role-v3")
    assert bool(report["context_reviews"]) is context
    assert bool(report["findings"]) is not context
    if context:
        witness = report["finding_tier_report"]["ledger"][0]["source_role_review"]
        assert witness["safe_reconstruction"] is False
        assert witness["reconstruction_effects"] == "UNASSESSED"


@pytest.mark.parametrize(
    "peer,registered",
    [
        ("huey = object()\n", True),
        ("def unrelated():\n    huey = object()\n    return huey\n", True),
        ("import huey\nhuey.BaseTestCase = replacement\n", False),
        (
            "import huey as package\nsetattr(package, 'BaseTestCase', replacement)\n",
            False,
        ),
        (
            "import huey.base\nfrom opaque import *\nhuey.base.BaseTestCase.__bases__ = replacement\n",
            False,
        ),
        ("from bridge import BaseTestCase as B\nB.__bases__ = replacement\n", False),
    ],
)
def test_pickle_owner369_distinguishes_local_names_and_provider_writes(
    peer, registered
):
    import ast
    from factoryline.primitive_observation_binding import _pickle_role_unittest_graph

    trees = {
        "huey/base.py": ast.parse(
            "import unittest\nclass BaseTestCase(unittest.TestCase):\n    pass\n"
        ),
        "huey/tests/test_owner.py": ast.parse(
            "from huey.base import BaseTestCase\nclass TestQueue(BaseTestCase):\n    def test_value(self):\n        self.assertTrue(True)\n"
        ),
        "peer.py": ast.parse(
            peer.replace("huey.BaseTestCase", "huey.base.BaseTestCase").replace(
                "import huey as package", "import huey.base as package"
            )
        ),
        "bridge.py": ast.parse("from huey.base import BaseTestCase\n"),
    }
    owner = trees["huey/tests/test_owner.py"].body[1]
    assert (id(owner) in _pickle_role_unittest_graph(trees)) is registered


def test_pickle_owner369_conflicting_reexport_never_erases_direct_mutation():
    import ast
    from factoryline.primitive_observation_binding import _pickle_role_unittest_graph

    trees = {
        "huey/base.py": ast.parse(
            "import unittest\nfrom decoy import BaseTestCase\nclass BaseTestCase(unittest.TestCase):\n    pass\n"
        ),
        "huey/tests/test_owner.py": ast.parse(
            "from huey.base import BaseTestCase\nclass TestQueue(BaseTestCase):\n    pass\n"
        ),
        "peer.py": ast.parse(
            "import huey.base\nhuey.base.BaseTestCase.__bases__ = replacement\n"
        ),
    }
    owner = trees["huey/tests/test_owner.py"].body[1]
    assert id(owner) not in _pickle_role_unittest_graph(trees)


def test_pickle_role_review_preserves_raw_and_reseals(tmp_path):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (review,) = report["context_reviews"]
    assert not report["findings"]
    (raw,) = report["finding_tier_report"]["ledger"]
    assert raw["raw_finding"] == review
    assert raw["source_role_review"]["safe_reconstruction"] is False
    assert raw["source_role_review"]["reconstruction_effects"] == "UNASSESSED"
    assert report["state"] == "REVIEW_REQUIRED"
    assert report["defect_policy_decision"]["clean"] is False
    again = review_audits._seal_security_scan(report.copy())
    assert again["context_reviews"] == [review]
    assert again["audit_sha256"] == report["audit_sha256"]
    assert "_primitive_source_bytes" not in again


@pytest.mark.parametrize("policy", ["legacy-v1", "trusted-core-v1"])
def test_pickle_role_policy_switch_restores_diagnostics(tmp_path, policy):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (original,) = report["context_reviews"]
    report["selected_defect_policy"] = policy
    changed = review_audits._seal_security_scan(report)
    assert original in changed["findings"]
    assert not changed.get("context_reviews")
    assert all(
        "source_role_review" not in row
        for row in changed["finding_tier_report"]["ledger"]
    )


@pytest.mark.parametrize(
    "source,extra",
    [
        (
            "import pickle\ndef test_external(blob):\n    assert pickle.loads(blob)\n",
            {},
        ),
        (_PICKLE_ROLE_TEST.replace("def test_roundtrip", "def handler"), {}),
        (
            _PICKLE_ROLE_TEST.replace(
                "import pickle", "import pickle\npickle.loads = supplied"
            ),
            {},
        ),
        (_PICKLE_ROLE_TEST, {"app.py": "import tests.test_roundtrip\n"}),
        (_PICKLE_ROLE_TEST, {"app.py": "from .tests import test_roundtrip\n"}),
        (
            "import pytest\nimport pickle\nclass Handler:\n    def test_roundtrip(self):\n        assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            "import pickle\n__test__ = False\ndef test_roundtrip():\n    assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            "import pickle\nclass TestRoundtrip:\n    def __init__(self): pass\n    def test_roundtrip(self):\n        assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "model.py": 'import requests\nclass Payload:\n    def __getstate__(self):\n        requests.get("https://example.invalid")\n        return {}\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "model.py": 'def run(value):\n    return eval(value)\nclass Payload:\n    def __reduce__(self):\n        return run, ("x",)\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {"mutation.py": "import pickle\npickle.loads = attacker\n"},
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": 'import builtins, pickle\nbuiltins.setattr(pickle, "loads", attacker)\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": "import pickle\nprovider = pickle\nprovider.loads = attacker\n"
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": 'import pickle\npickle.__dict__.update({"loads": attacker})\n'
            },
        ),
        (_PICKLE_ROLE_TEST, {"pickle.py": "def loads(value): return value\n"}),
        (
            _PICKLE_ROLE_TEST
            + '\nfrom helper import restore\nclass Payload:\n    def __reduce__(self): return restore, ("x",)\n',
            {"helper.py": "def restore(value): return eval(value)\n"},
        ),
    ],
)
def test_pickle_role_counterevidence_keeps_alert(tmp_path, source, extra):
    report = _pickle_role_report(tmp_path, source, extra)
    assert not report.get("context_reviews")
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )


def test_pickle_role_stale_capture_restores_alert(tmp_path):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    report["_primitive_source_bytes"] = {}
    changed = review_audits._seal_security_scan(report)
    assert not changed["context_reviews"]
    assert changed["defect_policy_decision"]["state"] == "BLOCKED"
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in changed["findings"]
    )


def test_pickle_role_forged_severity_cannot_qualify(tmp_path):
    from factoryline import primitive_observation_binding as primitive

    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    original = report["context_reviews"][0]
    finding = dict(
        original, severity="CRITICAL" if original["severity"] != "CRITICAL" else "INFO"
    )
    inventory = primitive._pickle_role_inventory(
        {"tests/test_roundtrip.py": _PICKLE_ROLE_TEST.encode()}
    )
    assert primitive._pickle_test_role_witness(finding, inventory) is None


@pytest.mark.parametrize(
    "policy", ["source-role-v1", "source-role-v2", "source-role-v3"]
)
def test_pickle_role_cli_receipt_and_text(tmp_path, capsys, policy):
    from factoryline.cli import main

    _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (tmp_path / ".factory").mkdir(exist_ok=True)
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    argv = [
        "audit",
        "security",
        "--root",
        str(tmp_path),
        "--defect-policy",
        policy,
    ]
    assert main([*argv, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["context_reviews"]) == 1
    assert report["defect_policy_decision"]["clean"] is False
    receipt = json.loads(
        (tmp_path / ".factory/security-scan/latest.json").read_text(encoding="utf-8")
    )
    assert receipt["report"]["context_reviews"] == report["context_reviews"]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert "NEEDS_CONTEXT reviews: 1" in output
    assert "No clean security result" in output
    assert main([*argv, "--full-repository", "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "E_DEFECT_POLICY_SCOPE"


@pytest.mark.parametrize(
    "base,extra,qualified",
    [
        ("unittest.TestCase", {}, True),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import unittest\nclass ConnectingCase(unittest.TestCase): pass\n"
            },
            True,
        ),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import types, unittest\nclass ConnectingCase(unittest.TestCase): pass\ndef f():\n    types = []\n"
            },
            True,
        ),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import unittest\nunittest = supplied\nclass ConnectingCase(unittest.TestCase): pass\n"
            },
            False,
        ),
        ("ConnectingCase", {}, False),
        ("unittest.TestCase", {"unittest.py": "class TestCase: pass\n"}, False),
        ("ConnectingCase", {"tests/helper.py": "class ConnectingCase: pass\n"}, False),
    ],
)
def test_pickle_role_unittest_ancestry_is_source_bound(
    tmp_path, base, extra, qualified
):
    source = (
        "import unittest\nimport pickle\nfrom .helper import ConnectingCase\n"
        f"class CursorChecks({base}):\n"
        "    def test_roundtrip(self):\n"
        "        result = pickle.loads(pickle.dumps(object()))\n"
        "        self.assertTrue(result)\n"
    )
    report = _pickle_role_report(tmp_path, source, extra)
    assert bool(report.get("context_reviews")) is qualified
    assert bool(report["findings"]) is not qualified


_PICKLE_PIPE_WORKER = """import pickle
import subprocess
import sys
from runtime import open_process, BufferedByteReceiveStream
async def launch():
    command = [sys.executable, "-u", "-m", __name__]
    process = await open_process(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    buffered = BufferedByteReceiveStream(process.stdout)
    async def communicate():
        payload = await buffered.receive_exactly(10)
        return pickle.loads(payload)
    return await communicate()
def worker():
    stdin = sys.stdin
    value = pickle.load(stdin.buffer)
    encoded = pickle.dumps(value)
    return encoded
if __name__ == "__main__":
    worker()
"""


@pytest.mark.parametrize(
    "source,qualified",
    [
        (_PICKLE_PIPE_WORKER, True),
        (
            _PICKLE_PIPE_WORKER.replace(
                'sys.executable, "-u", "-m", __name__', '"remote-program"'
            ),
            False,
        ),
        (_PICKLE_PIPE_WORKER.replace("stdin=subprocess.PIPE", "stdin=external"), False),
        (
            _PICKLE_PIPE_WORKER.replace(
                "    buffered = BufferedByteReceiveStream(process.stdout)",
                "    buffered = external",
            ),
            False,
        ),
        (
            _PICKLE_PIPE_WORKER.replace(
                "    stdin = sys.stdin", "    stdin = external"
            ),
            False,
        ),
    ],
)
def test_pickle_role_worker_protocol_requires_source_bindings(
    tmp_path, source, qualified
):
    (tmp_path / "worker.py").write_text(source, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    reviews = report.get("context_reviews", [])
    if qualified:
        assert len(reviews) == 2
        assert not report["findings"]
        assert all(
            row["source_role_review"]["safe_reconstruction"] is False
            for row in report["finding_tier_report"]["ledger"]
        )
    else:
        assert report["findings"]
    assert len(report["findings"]) + len(reviews) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "ConnectingCase = object",
        "unittest.TestCase = object",
        'setattr(unittest, "TestCase", object)',
    ],
)
def test_pickle_role_rebound_testcase_cannot_qualify(tmp_path, mutation):
    source = (
        "import unittest\nimport pickle\nclass ConnectingCase(unittest.TestCase): pass\n"
        + mutation
        + "\nclass CursorChecks(ConnectingCase):\n"
        "    def test_roundtrip(self):\n"
        "        self.assertTrue(pickle.loads(pickle.dumps(object())))\n"
    )
    report = _pickle_role_report(tmp_path, source)
    assert not report.get("context_reviews")
    assert report["findings"]


@pytest.mark.parametrize(
    "source,expected_reviews",
    [
        (
            _PICKLE_PIPE_WORKER
            + "\nasync def external_read(buffered):\n    payload = await buffered.receive_exactly(10)\n    return pickle.loads(payload)\n",
            2,
        ),
        (
            _PICKLE_PIPE_WORKER.replace(
                "        return pickle.loads(payload)",
                "        payload = external\n        return pickle.loads(payload)",
            ),
            1,
        ),
    ],
)
def test_pickle_role_ipc_does_not_launder_external_receiver_or_rebound_bytes(
    tmp_path, source, expected_reviews
):
    (tmp_path / "worker.py").write_text(source, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    assert len(report["context_reviews"]) == expected_reviews
    assert any(row["facts"].get("call") == "pickle.loads" for row in report["findings"])


_REGISTERED_FLOW_SOURCE = """import yaml
import os
import sys
from network import fetch
def sample(path, verbose=False):
    with open(path, 'rb') as handle:
        data = handle.read()
    value = yaml.load(data, Loader=yaml.Loader)
    assert value == 1
"""


def _registered_flow(source):
    from factoryline import primitive_observation_binding as primitive

    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    sink = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "yaml.load"
    )
    return primitive._registered_fixture_flow(function, sink, ["path"], tree)


def test_registered_fixture_flow_binds_read_transform_and_oracle():
    flow = _registered_flow(_REGISTERED_FLOW_SOURCE)
    assert flow["registered_filename_parameters"] == ["path"]
    assert flow["read_spans"] and flow["transformations"] and flow["oracle_spans"]
    assert len(flow["sink_input_ast_sha256"]) == 64
    assert flow["effects"] == "UNASSESSED"


@pytest.mark.parametrize(
    "peer",
    [
        None,
        "from sample import *\n_load_code(external)\n",
        "from . import sample as mod\nmod._load_code(external)\n",
        "from .sample import _load_code as run\nrun(external)\n",
        "import sample as mod\nmod._load_code(external)\n",
        "import builtins\nbuiltins.eval = replacement\n",
    ],
)
def test_registered_fixture_helper_role_reuses_closed_fixture_flow(monkeypatch, peer):
    from factoryline import primitive_observation_binding as roles

    source = (
        "def _load_code(expression):\n    return eval(expression)\n"
        "def sample(filename, verbose=False):\n"
        "    value = _load_code(filename)\n    assert value == 'ok'\n"
        "sample.unittest = ['.fixture']\n"
    )
    raw = source.encode()
    tree = ast.parse(source)
    from factoryline.primitive_observation_binding import _pickle_role_inventory

    inventory = _pickle_role_inventory(
        {"tests/sample.py": raw, "tests/test_appliance.py": b"pass\n"}
    )
    if peer:
        inventory = _pickle_role_inventory(
            {**inventory["sources"], "tests/peer.py": peer.encode()}
        )
    sink = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "eval"
    )
    finding = {
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "path": "tests/sample.py",
        "line": sink.lineno,
        "column": sink.col_offset,
        "severity": "HIGH",
    }
    monkeypatch.setattr(roles, "_pickle_role_native_match", lambda *_: True)
    monkeypatch.setattr(roles, "_pickle_operational_importer", lambda *_: False)
    monkeypatch.setattr(
        roles,
        "_registered_fixture_entry",
        lambda *_: {
            "path": "tests/test_appliance.py",
            "entry_span": [1, 0, 1, 1],
            "recipe": {"profile": "test-double-attested"},
        },
    )
    monkeypatch.setattr(
        roles,
        "_registered_fixture_flow",
        lambda owner, call, *_: {
            "oracle_spans": [
                [call.lineno, call.col_offset, call.end_lineno, call.end_col_offset]
            ],
            "effects": "UNASSESSED",
        }
        if ast.unparse(call) == "eval(filename)"
        else None,
    )
    monkeypatch.setattr(roles, "_registered_fixture_module_clear", lambda *_: True)
    witness = finite.captured_registered_fixture_helper_role(finding, inventory)
    if peer:
        assert witness is None
        return
    assert witness["tier"] == "NEEDS_CONTEXT"
    assert witness["callers"][0]["input_flow"]["oracle_spans"]
    assert witness["safe_operation"] is False


@pytest.mark.parametrize(
    "changed",
    [
        _REGISTERED_FLOW_SOURCE.replace(
            "    with open", "    path = supplied\n    with open"
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    injected = fetch()\n    value ="
        ).replace("yaml.load(data,", "yaml.load(data + injected,"),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    data += supplied\n    value ="
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    for data in supplied:\n        pass\n    value ="
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    for data in ['fixed']:\n        pass\n    value ="
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =",
            "    with supplied as handle:\n        pass\n    data = handle.read()\n    value =",
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "yaml.load(data,", "yaml.load(data + os.environ['PAYLOAD'],"
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "yaml.load(data,", "yaml.load(data + sys.argv[1],"
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "import os", "from os import environ as environment"
        ).replace("yaml.load(data,", "yaml.load(data + environment['PAYLOAD'],"),
        _REGISTERED_FLOW_SOURCE.replace(
            "import sys", "from sys import argv as arguments"
        ).replace("yaml.load(data,", "yaml.load(data + arguments[1],"),
        _REGISTERED_FLOW_SOURCE.replace(
            "yaml.load(data,", "yaml.load(data + globals().copy()['PAYLOAD'],"
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =",
            "    if supplied:\n        data = supplied\n    else:\n        data = handle.read()\n    value =",
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =",
            "    try:\n        data = supplied\n    except Exception:\n        data = handle.read()\n    value =",
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    data = [data]\n    data[0] = supplied\n    value ="
        ).replace("yaml.load(data,", "yaml.load(data[0],"),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    data = [data]\n    data.append(supplied)\n    value ="
        ).replace("yaml.load(data,", "yaml.load(data[0],"),
        _REGISTERED_FLOW_SOURCE.replace("assert value == 1", "assert True"),
        _REGISTERED_FLOW_SOURCE.replace(
            "        data = handle.read()", "        data = supplied"
        ),
        _REGISTERED_FLOW_SOURCE.replace(
            "    value =", "    def nested():\n        pass\n    value ="
        ),
    ],
)
def test_registered_fixture_flow_rejects_unclosed_input_and_oracle(changed):
    assert _registered_flow(changed) is None


@pytest.mark.parametrize(
    "source",
    [
        "globals = replacement",
        "open = supplied",
        "__name__ = supplied",
        'namespace = globals(); namespace["sample"] = replacement',
        "globals().update(replacements)",
        "from provider import open",
        "external.mutate(globals())",
        "if __name__ == '__main__':\n    external.run(globals())",
    ],
)
def test_registered_fixture_module_rejects_entry_and_builtin_replacement(source):
    from factoryline import primitive_observation_binding as primitive

    assert primitive._registered_fixture_module_clear(ast.parse(source)) is False


def test_registered_fixture_policy_is_explicit_and_defaults_compatible(tmp_path):
    """security_defect_policy_decision, fixed_program_proof_dispositions, and apply_pickle_source_role_policy retain the raw finding under source-role policy."""
    source = "import yaml\ndef test_handler(data):\n    value = yaml.load(data, Loader=yaml.Loader)\n    assert value\n"
    v1 = _pickle_role_report(tmp_path, source)
    v2 = _pickle_role_report(tmp_path, source, policy="source-role-v2")
    assert v2["findings"] == v1["findings"]
    assert not v2["context_reviews"]
    assert v2["defect_policy_decision"]["policy_id"] == "source-role-v2"
    assert v2["defect_policy_decision"]["clean"] is False
    assert v2["finding_tier_report"]["ledger"][0]["tier"] == "NEEDS_CONTEXT"


def _shared_security_helper_index(tmp_path, source):
    from pathlib import Path
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    path = Path(tmp_path) / "shared_helper.py"
    raw = source.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw, filename=str(path))
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        Path(tmp_path), {path: tree}, {path: raw}, {path: digest}
    )
    tree._security_source_model = index
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "helper"
    )
    caller = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "caller"
    )
    helper._security_parent_scope = tree
    caller._security_parent_scope = tree
    call = next(node for node in ast.walk(caller) if isinstance(node, ast.Call))
    call._security_lexical_scope = caller
    call._security_flow_statement = caller.body[0]
    return path, tree, index, helper, caller, call


@pytest.mark.parametrize(
    "signature",
    [
        "value, extra=b'fixed'",
        "value, *, extra=None",
        "value, extra=b'fixed', *, flag=True",
    ],
)
def test_shared_defaults370_do_not_impersonate_caller_actuals(tmp_path, signature):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(" + signature + "):\n    return value\n"
        "def caller(raw):\n    return helper(raw)\n",
    )
    summary = finite.security_structural_helper_summary(
        call,
        helper,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
        path=path,
        index=index,
    )
    assert summary.return_status == "COMPLETE"
    assert summary.return_values[0].value.roots == frozenset({"request-body"})


@pytest.mark.parametrize(
    "signature,arguments,mapping,accepted",
    [
        ("first=None, second=None", "raw", {"second": 0}, False),
        ("first, second=None", "raw, None", {"first": 1, "second": 0}, False),
        (
            "first=None, second=None",
            "first=raw, first=None",
            {"first": 0, "second": 1},
            False,
        ),
        (
            "first, second=None",
            "second=None, first=raw",
            {"second": 0, "first": 1},
            True,
        ),
    ],
)
def test_shared_defaults370_exact_formals_required(
    signature, arguments, mapping, accepted
):
    from factoryline import credential_role_identity_effects as identity

    function = ast.parse("def helper(" + signature + "):\n    pass\n").body[0]
    call = ast.parse("helper(" + arguments + ")", mode="eval").body
    actuals = [*call.args, *(keyword.value for keyword in call.keywords)]
    resolved = identity.ResolvedIdentityCall(
        function, "captured.py", {key: actuals[pos] for key, pos in mapping.items()}
    )
    effects = identity._Effects()
    result = identity.mapped_call_values(
        call,
        {"raw": identity._Value(roots=frozenset({"request"}))},
        {"request"},
        resolved,
        effects,
        strict_calls=True,
    )
    assert (result is not None) is accepted
    if accepted:
        assert result["first"].roots == frozenset({"request"})
    else:
        assert effects.unknowns


@pytest.mark.parametrize(
    "expression",
    [
        "unknown",
        "backend.unknown",
        "backend.lookup()",
        "backend.__class__()",
        "backend + 1",
    ],
)
def test_shared_value_facets370_keep_material_uncertainty(expression):
    from factoryline import credential_role_identity_effects as identity

    node = ast.parse(expression, mode="eval").body
    aliases = {"backend": identity._Value(roots=frozenset({"backend"}))}
    material = identity.identity_value(
        node, aliases, strict_calls=True, material_values=True
    )
    assert material.unknown or material.content_unknown
    if "backend" in expression:
        assert "backend" in identity.tracked_roots(material)
    exact = identity.identity_value(node, aliases, strict_calls=True)
    if expression == "unknown":
        assert not identity.tracked_roots(exact)
    if expression == "backend.lookup()":
        assert exact.content_unknown
        assert not exact.roots


def test_shared_value_facets370_unknown_result_does_not_erase_known_escape(tmp_path):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, _helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n    pass\ndef caller(raw):\n    return opaque(raw)\n",
    )
    summary = identity.summarize_identity_call(
        call, path, index, {"raw": "request"}, resolve_call=lambda *_: None
    )
    assert summary.status == "ESCAPE"
    assert summary.escapes == ("request",)
    assert summary.return_status == "UNKNOWN"
    assert summary.return_values[0].value.unknown
    assert summary.return_values[0].value.roots == frozenset({"request"})


def test_shared_value_facets370_unknown_actual_keeps_origin_after_helper(tmp_path):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n    return value\ndef caller(raw):\n    return helper(raw.member)\n",
    )
    summary = finite.security_structural_helper_summary(
        call,
        helper,
        {"raw": identity._Value(roots=frozenset({"request"}))},
        path=path,
        index=index,
        request_aliases={},
    )
    returned = summary.return_values[0].value
    assert summary.return_status == "UNKNOWN"
    assert returned.unknown or returned.content_unknown
    assert returned.roots == frozenset({"request"})


def test_shared_call_result_selects_container_value_and_keeps_return_effect(tmp_path):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n"
        "    values = {'selected': value, 'fixed': b'fixed'}\n"
        "    return values\n"
        "def caller(raw):\n"
        "    return helper(raw)\n",
    )
    summary = finite.security_structural_helper_summary(
        call,
        helper,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
        path=path,
        index=index,
    )
    assert summary.return_status == "COMPLETE"
    assert len(summary.return_values) == 1
    result = summary.return_values[0].value
    assert result.inert_kind is None
    items = dict(result.items)
    assert items["selected"].roots == frozenset({"request-body"})
    assert items["fixed"].roots == frozenset()
    assert items["fixed"].scalar_kind == "bytes"
    assert "request-body" in summary.escapes
    assert summary.return_values[0].source_span[1] == 3
    selected = finite.security_structural_value(
        call,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
    )
    assert dict(selected.items)["selected"].roots == frozenset({"request-body"})


def test_captured_branch_transfer_binds_literal_caller_and_selected_field(tmp_path):
    """Scalar branch selection transfers only the source-bound actual assigned to the chosen field."""
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    source = (
        "class Entry:\n"
        "    def __init__(self, choice, primary, fallback):\n"
        "        if choice == 'primary':\n"
        "            self.token = primary\n"
        "        else:\n"
        "            self.token = fallback\n"
        "\n"
        "def caller(raw):\n"
        "    choice = 'primary'\n"
        "    fixed = 'safe'\n"
        "    return Entry(choice, raw, fixed)\n"
    )
    path = tmp_path / "branch.py"
    raw = source.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw, filename=str(path))
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    constructor = tree.body[0].body[0]
    caller = tree.body[1]
    call = caller.body[-1].value
    bound = dict(zip(("choice", "primary", "fallback"), call.args))

    assert finite.captured_call_scalar(index, path, caller, bound["choice"], path) == (
        "primary",
    )
    known = {"choice": "primary"}

    def guard(expression, values):
        return finite.captured_scalar_guard(expression, values, lambda _node: True)

    assert guard(constructor.body[0].test, known) is True
    selected = finite.captured_selected_field_assignments(
        constructor.body, "self", "token", known, guard, [32]
    )
    assert selected == [constructor.body[0].body[0]]

    transfer = finite.captured_literal_branch_field_transfer(
        index, path, constructor, bound, path, caller, "token", lambda _node: True
    )
    assert transfer["profile"] == "SOURCE_LITERAL_SELECTED_BRANCH"
    assert transfer["formal"] == "primary"
    assert transfer["actual"] is call.args[1]
    assert transfer["source_sha256"] == digest

    unknown_source = source.replace("choice = 'primary'", "choice = opaque()")
    unknown_raw = unknown_source.encode("utf-8")
    unknown_digest = hashlib.sha256(unknown_raw).hexdigest()
    unknown_tree = ast.parse(unknown_raw, filename=str(path))
    unknown_tree._oracle_source_sha256 = unknown_digest
    unknown_index = SourceSnapshotIndex(
        tmp_path, {path: unknown_tree}, {path: unknown_raw}, {path: unknown_digest}
    )
    unknown_constructor = unknown_tree.body[0].body[0]
    unknown_caller = unknown_tree.body[1]
    unknown_call = unknown_caller.body[-1].value
    unknown_bound = dict(zip(("choice", "primary", "fallback"), unknown_call.args))
    assert (
        finite.captured_literal_branch_field_transfer(
            unknown_index,
            path,
            unknown_constructor,
            unknown_bound,
            path,
            unknown_caller,
            "token",
            lambda _node: True,
        )
        is None
    )


def test_shared_constant_return_kills_value_but_retains_argument_effects(tmp_path):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n"
        "    return 'fixed'\n"
        "def mutate(value):\n"
        "    external(value)\n"
        "def caller(raw):\n"
        "    return helper(mutate(raw))\n",
    )
    summary = finite.security_structural_helper_summary(
        call,
        helper,
        {"raw": identity._Value(roots=frozenset({"request-body"}), scalar_kind="text")},
        path=path,
        index=index,
    )
    assert summary.return_status == "COMPLETE"
    result = summary.return_values[0].value
    assert result.scalar_kind == "text"
    assert not result.roots
    assert "request-body" in summary.escapes
    assert summary.unknowns


def test_shared_unknown_call_and_branch_keep_known_may_origins(tmp_path):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n"
        "    if value:\n"
        "        return value\n"
        "    return 'fixed'\n"
        "def caller(raw):\n"
        "    return helper(raw)\n",
    )
    summary = finite.security_structural_helper_summary(
        call,
        helper,
        {"raw": identity._Value(roots=frozenset({"request-body"}), scalar_kind="text")},
        path=path,
        index=index,
    )
    assert summary.return_status == "UNKNOWN"
    assert summary.return_values
    assert all(projection.value.unknown for projection in summary.return_values)
    joined = finite.security_structural_join(
        [projection.value for projection in summary.return_values]
    )
    assert joined.unknown
    assert "request-body" in joined.roots
    opaque = finite.security_structural_value(
        ast.parse("opaque(raw)", mode="eval").body,
        {"raw": identity._Value(roots=frozenset({"request-body"}), scalar_kind="text")},
    )
    assert opaque.unknown
    assert opaque.roots == frozenset({"request-body"})


def test_shared_import_reexport_return_uses_captured_symbol_binding(tmp_path):
    """Captured source lookup resolves an imported re-export and retains the helper's selected return items."""
    from pathlib import Path
    from factoryline import credential_role_identity_effects as identity
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    sources = {
        "sample.py": (
            "from middle import selected_helper as imported\n"
            "def caller(raw):\n"
            "    return imported(raw)\n"
        ),
        "middle.py": "from provider import choose as selected_helper\n",
        "provider.py": (
            "def choose(value):\n    return {'selected': value, 'fixed': b'fixed'}\n"
        ),
    }
    paths = {name: Path(tmp_path) / name for name in sources}
    raw = {paths[name]: source.encode("utf-8") for name, source in sources.items()}
    trees, inventory = {}, {}
    for path, data in raw.items():
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data, filename=str(path))
        tree._oracle_source_sha256 = digest
        trees[path] = tree
        inventory[path] = digest
    index = SourceSnapshotIndex(Path(tmp_path), trees, raw, inventory)
    sample = trees[paths["sample.py"]]
    sample._security_source_model = index
    caller = sample.body[1]
    caller._security_parent_scope = sample
    call = caller.body[0].value
    call._security_lexical_scope = caller
    call._security_flow_statement = caller.body[0]
    wrapper = identity.source_symbol_index(index)
    assert wrapper is identity.source_symbol_index(index)
    resolved = identity.resolve_source_identity_call(
        call, paths["sample.py"], index, lexical_scope=caller
    )
    assert resolved.path == paths["provider.py"]
    assert resolved.function is trees[paths["provider.py"]].body[0]
    assert resolved.arguments["value"] is call.args[0]
    from factoryline.semantic_credential_sensor import _security_flow_step

    roots = {
        "raw": identity._Value(
            roots=frozenset({"request-body"}),
            scalar_kind="bytes",
            trace=(_security_flow_step(call.args[0], "BOUND_EXPRESSION"),),
        )
    }
    summary = finite.security_structural_helper_summary(
        call,
        resolved.function,
        roots,
        path=paths["sample.py"],
        index=index,
        callee_path=resolved.path,
        source_resolved=True,
        negative_binding_closed=resolved.negative_binding_closed,
        negative_binding_check=resolved.negative_binding_check,
    )
    assert summary.return_status == "COMPLETE"
    summary_value = summary.return_values[0].value
    selected_trace = dict(summary_value.items)["selected"].trace
    structural_operations = {
        step[0] for step in (*summary_value.trace, *selected_trace)
    }
    assert {"BOUND_EXPRESSION", "HELPER_RETURN"} <= structural_operations
    assert "ACTUAL_TO_FORMAL" not in structural_operations
    captured = identity.captured_source_call_result(
        call,
        paths["sample.py"],
        index,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
    )
    assert captured is not None
    assert dict(captured["value"].items)["selected"].roots == frozenset(
        {"request-body"}
    )
    value = finite.security_structural_value(
        call,
        roots,
    )
    assert not value.unknown
    selected = dict(value.items)["selected"]
    fixed = dict(value.items)["fixed"]
    assert selected.roots == frozenset({"request-body"})
    assert fixed.roots == frozenset()
    assert fixed.scalar_kind == "bytes"


def test_shared_import_return_declines_changed_captured_source(tmp_path):
    from pathlib import Path
    from factoryline import credential_role_identity_effects as identity
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    sources = {
        "sample.py": "from provider import choose\ndef caller(raw):\n    return choose(raw)\n",
        "provider.py": "def choose(value):\n    return value\n",
    }
    paths = {name: Path(tmp_path) / name for name in sources}
    raw = {paths[name]: source.encode("utf-8") for name, source in sources.items()}
    trees, inventory = {}, {}
    for path, data in raw.items():
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data, filename=str(path))
        tree._oracle_source_sha256 = digest
        trees[path] = tree
        inventory[path] = digest
    index = SourceSnapshotIndex(Path(tmp_path), trees, raw, inventory)
    sample = trees[paths["sample.py"]]
    sample._security_source_model = index
    caller = sample.body[1]
    caller._security_parent_scope = sample
    call = caller.body[0].value
    call._security_lexical_scope = caller
    call._security_flow_statement = caller.body[0]
    raw[paths["provider.py"]] = b"def choose(value):\n    return 'changed'\n"
    value = finite.security_structural_value(
        call,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
    )
    assert value.unknown
    assert "request-body" in value.roots


def test_shared_import_call_declines_decorated_callable_identity(tmp_path):
    from pathlib import Path
    from factoryline import credential_role_identity_effects as identity
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    sources = {
        "sample.py": "from provider import choose\ndef caller(raw):\n    return choose(raw)\n",
        "provider.py": (
            "def replace(function):\n"
            "    def wrapped(value):\n"
            "        return {'selected': b'fixed'}\n"
            "    return wrapped\n"
            "@replace\n"
            "def choose(value):\n"
            "    return {'selected': value}\n"
        ),
    }
    paths = {name: Path(tmp_path) / name for name in sources}
    raw = {paths[name]: source.encode("utf-8") for name, source in sources.items()}
    trees, inventory = {}, {}
    for path, data in raw.items():
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data, filename=str(path))
        tree._oracle_source_sha256 = digest
        trees[path] = tree
        inventory[path] = digest
    index = SourceSnapshotIndex(Path(tmp_path), trees, raw, inventory)
    sample = trees[paths["sample.py"]]
    sample._security_source_model = index
    caller = sample.body[1]
    caller._security_parent_scope = sample
    call = caller.body[0].value
    call._security_lexical_scope = caller
    call._security_flow_statement = caller.body[0]
    value = finite.security_structural_value(
        call,
        {
            "raw": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
    )
    assert value.unknown
    assert "request-body" in value.roots


def _shared_mutable_container_state():
    from factoryline import credential_role_identity_effects as identity

    source = identity._Value(roots=frozenset({"request-body"}), scalar_kind="text")
    box_node = ast.parse("{'selected': payload, 'fixed': 'constant'}", mode="eval").body
    box = identity.identity_value(box_node, {"payload": source}, strict_calls=True)
    alias = identity.identity_value(ast.parse("box", mode="eval").body, {"box": box})
    return {"box": box, "alias": alias}


@pytest.mark.parametrize(
    "statement",
    [
        "alias['selected'] = 'fixed'",
        "del alias['selected']",
        "alias['selected'] += 'suffix'",
        "touch(box)",
    ],
)
def test_shared_mutation_invalidates_all_container_aliases(statement):
    from factoryline import credential_role_identity_effects as identity

    environment = _shared_mutable_container_state()
    assert environment["box"].container_id == environment["alias"].container_id
    changed = identity.invalidate_structural_statement(
        ast.parse(statement).body[0], environment
    )
    assert changed
    assert environment["box"].unknown
    assert environment["alias"].unknown
    assert "request-body" in identity.tracked_roots(environment["box"])
    selected = identity.identity_value(
        ast.parse("box['selected']", mode="eval").body,
        environment,
        strict_calls=True,
    )
    assert selected.unknown
    assert "request-body" in selected.roots


def test_shared_opaque_scalar_call_does_not_invalidate_unrelated_scalar():
    from factoryline import credential_role_identity_effects as identity

    secret = identity._Value(roots=frozenset({"request-body"}), scalar_kind="text")
    environment = {"secret": secret}
    assert not identity.invalidate_structural_statement(
        ast.parse("touch(secret)").body[0], environment
    )
    assert environment["secret"] is secret


def test_shared_nested_value_join_retains_origin_as_unknown():
    """Both identity join entry points preserve a nested may-origin while marking the selected value unknown."""
    from factoryline import credential_role_identity_effects as identity

    left = identity.identity_value(
        ast.parse("{'outer': {'selected': payload}}", mode="eval").body,
        {
            "payload": identity._Value(
                roots=frozenset({"request-body"}), scalar_kind="bytes"
            )
        },
    )
    right = identity.identity_value(
        ast.parse("{'outer': {'selected': b'fixed'}}", mode="eval").body,
        {},
    )
    joined = identity.join_identity_values([left, right])
    wrapped = identity.structural_value_join([left, right])
    assert wrapped == joined
    selected = dict(dict(joined.items)["outer"].items)["selected"]
    assert joined.unknown
    assert selected.unknown
    assert "request-body" in selected.roots


def test_shared_join_budget_exhaustion_keeps_may_origins():
    from factoryline import credential_role_identity_effects as identity

    values = [
        identity._Value(roots=frozenset({f"origin-{index}"})) for index in range(513)
    ]
    joined = finite.security_structural_join(values)
    assert joined.unknown
    assert joined.roots == frozenset(f"origin-{index}" for index in range(513))


@pytest.mark.parametrize(
    "expression, known",
    [
        ("'{}.{}'.format(payload, 42).encode()", True),
        ("'{0}:{1}'.format(42, payload)", True),
        ("'{0.secret}'.format(payload)", False),
        ("'{0!r}'.format(payload)", False),
        ("'{0:>9}'.format(payload)", False),
        ("'{9}'.format(payload)", False),
        ("'{} {0}'.format(payload)", False),
        ("'{}'.format(unknown)", False),
    ],
)
def test_shared_format372_material_origins_are_not_exact_identity(expression, known):
    from factoryline import credential_role_identity_effects as identity

    node = ast.parse(expression, mode="eval").body
    values = {
        "payload": identity._Value(roots=frozenset({"input"}), scalar_kind="text")
    }
    material = identity.identity_value(
        node, values, strict_calls=True, material_values=True
    )
    assert (not material.unknown and not material.content_unknown) is known
    if known:
        assert material.roots == frozenset({"input"})
        assert "TEXT_INTERPOLATION" in {step[0] for step in material.trace}
    exact = identity.identity_value(node, values, strict_calls=True)
    assert exact.unknown or exact.content_unknown


@pytest.mark.parametrize(
    "body, closed",
    [
        ("alias = secret\n    consume(alias)", True),
        ("alias: str = secret\n    consume(alias)", True),
        ("alias = secret.encode()\n    consume(alias)", True),
        ("first = secret\n    second = first\n    consume(second)", True),
        ("alias = secret\n    consume(alias)\n    publish(alias)", False),
        ("alias = opaque(secret)\n    consume(alias)", False),
        ("alias = secret\n    alias = 'new'\n    consume(alias)", False),
        ("consume(secret)\n    del secret", False),
        (
            "alias = secret\n    def hidden():\n        publish(alias)\n    consume(alias)",
            False,
        ),
    ],
)
def test_shared_consumer373_complete_graph_preserves_unknown_uses(body, closed):
    from factoryline import credential_role_identity_effects as identity

    tree = ast.parse("def owner():\n    secret = 'owned'\n    " + body + "\n")
    function = tree.body[0]
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    roots = [
        ("consumer", node.args[0])
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "consume"
    ]

    def shape(expression):
        return (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "encode"
            and not expression.args
            and not expression.keywords
        )

    result = identity._structural_closed_consumer_uses(
        function,
        "secret",
        roots,
        parents,
        lambda node: identity._enclosing_function(node, parents),
        shape,
    )
    assert (result is not None) is closed


def test_shared_import_alias_namespace_is_separate_from_value_roots():
    import ast
    from factoryline.finite_capture import security_structural_value

    value = security_structural_value(
        ast.parse("os.path.join(value)", mode="eval").body, {}, {"os": "os"}
    )
    assert value.unknown
    assert not value.roots


@pytest.mark.parametrize(
    "expression", ["module.member", "values[0]", "value", "42", "None"]
)
def test_shared_non_call_expression_declines_helper_return(expression):
    import ast
    from factoryline.finite_capture import security_helper_return_value

    node = ast.parse(expression, mode="eval").body
    assert security_helper_return_value(node, None, set(), set(), {}) is None


@pytest.mark.parametrize(
    "body, closed",
    [
        ("alias = secret\n    consume(alias)", True),
        ("alias = secret\n    consume(alias)\n    publish(alias)", False),
        (
            "alias = secret\n    def hidden():\n        nonlocal alias\n        alias = external\n    consume(alias)",
            False,
        ),
        (
            "alias = secret\n    def hidden():\n        nonlocal alias\n        del alias\n    consume(alias)",
            False,
        ),
        (
            "alias = secret\n    def hidden():\n        return alias\n    consume(alias)",
            False,
        ),
        ("global alias\n    alias = secret\n    consume(alias)", False),
        ("alias = secret\n    alias += external\n    consume(alias)", False),
        (
            "first = secret\n    second = first\n    def hidden():\n        nonlocal second\n        second = external\n    consume(second)",
            False,
        ),
        (
            "alias = secret\n    values = [alias]\n    publish(values)\n    consume(alias)",
            False,
        ),
        ("alias = secret.encode()\n    consume(alias)\n    alias = external", False),
    ],
)
def test_shared_consumer373_adversarial_store_and_capture_closure(body, closed):
    from factoryline import credential_role_identity_effects as identity

    tree = ast.parse("def owner():\n    secret = 'owned'\n    " + body + "\n")
    function = tree.body[0]
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    roots = [
        ("consumer", node.args[0])
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "consume"
    ]

    def transform(expression):
        return (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "encode"
            and not expression.args
            and not expression.keywords
        )

    result = identity._structural_closed_consumer_uses(
        function,
        "secret",
        roots,
        parents,
        lambda node: identity._enclosing_function(node, parents),
        transform,
    )
    assert (result is not None) is closed
    if result is not None:
        assignments, loads, roles = result
        assert set(assignments) == {"alias"}
        assert {node.id for node in loads} == {"secret", "alias"}
        assert set(roles) == {id(node) for node in loads}
        assert {roles[id(node)] for node in loads} == {"derived_value", "consumer"}


@pytest.mark.parametrize(
    "import_line,callee",
    [
        ("from values import constant", "constant"),
        ("import values as helper", "helper.constant"),
    ],
)
def test_shared_import375_native_source_to_independent_shell_review(
    tmp_path, import_line, callee
):
    folder = tmp_path / "scripts"
    folder.mkdir()
    (folder / "values.py").write_text("def constant(value):\n    return 'status'\n")
    (folder / "main.py").write_text(
        "import subprocess\nfrom flask import request\n" + import_line + "\n"
        "def endpoint():\n    incoming = request.args['q']\n"
        f"    command = {callee}(incoming)\n    subprocess.call(command, shell=True)\n"
    )
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v3"
        )
    raw = [
        r["raw_finding"]
        for r in report["finding_tier_report"]["ledger"]
        if r["raw_finding"]["code"] == "SECURITY_SHELL_COMMAND"
    ]
    assert len(raw) == 1 and raw[0]["severity"] == "HIGH"
    assert not [r for r in report["findings"] if r["code"] == "SECURITY_SHELL_COMMAND"]
    assert any(r["code"] == "SECURITY_SHELL_COMMAND" for r in report["context_reviews"])
    ledger = next(
        r
        for r in report["finding_tier_report"]["ledger"]
        if r["raw_finding"]["code"] == "SECURITY_SHELL_COMMAND"
    )
    assert ledger["source_role_review"]["safe_execution"] is False


@pytest.mark.parametrize(
    "source",
    [
        "def inspect(items):\n    for vars in items:\n        print(vars)\n",
        "def inspect(item):\n    vars = item\n    return vars.result\n",
    ],
)
def test_shared_namespace375_local_data_names_do_not_expose_builtin_namespace(source):
    assert finite._shell_source_provider_clear(source.encode(), "subprocess")


@pytest.mark.parametrize(
    "source",
    [
        "lookup = globals\n",
        "def inspect():\n    return vars()\n",
        "def inspect():\n    global vars\n    vars()['subprocess'].call = other\n",
        "import subprocess\nsubprocess.call = other\n",
    ],
)
def test_shared_namespace375_real_namespace_or_provider_escape_still_rejected(source):
    assert not finite._shell_source_provider_clear(source.encode(), "subprocess")


def test_imported_helper375_tainted_return_keeps_native_shell_finding(tmp_path):
    report = _pickle_role_report(
        tmp_path,
        "import subprocess\nfrom flask import request\nfrom helper import passthrough\n"
        "def test_command():\n    command = passthrough(request.args['command'])\n"
        "    subprocess.call(command, shell=True)\n",
        {"helper.py": "def passthrough(value):\n    return value\n"},
        policy="source-role-v3",
    )
    shell = [
        row for row in report["findings"] if row["code"] == "SECURITY_SHELL_COMMAND"
    ]
    assert len(shell) == 1 and shell[0]["severity"] == "HIGH"
    assert not [
        row
        for row in report["context_reviews"]
        if row["code"] == "SECURITY_SHELL_COMMAND"
    ]
    ledger = next(
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_SHELL_COMMAND"
    )
    assert ledger["raw_finding"] == shell[0]
    assert ledger.get("source_role_review") is None


def test_imported_helper375_pickle_bytes_keep_reconstruction_finding(tmp_path):
    report = _pickle_role_report(
        tmp_path,
        "import pickle\nfrom helper import pack\n"
        "def test_roundtrip(value):\n    payload = pack(value)\n"
        "    return pickle.loads(payload)\n",
        {
            "helper.py": "import pickle\ndef pack(value):\n    return pickle.dumps(value)\n"
        },
        policy="source-role-v3",
    )
    findings = [
        row
        for row in report["findings"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(findings) == 1 and findings[0]["severity"] == "HIGH"
    assert not [
        row
        for row in report["context_reviews"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    ledger = next(
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    )
    assert ledger["raw_finding"] == findings[0]
    assert ledger.get("source_role_review") is None


def test_imported_helper375_tainted_return_keeps_native_dynamic_exec_finding(tmp_path):
    folder = tmp_path / "scripts"
    folder.mkdir()
    (folder / "helper.py").write_text(
        "def passthrough(value):\n    return value\n", encoding="utf-8"
    )
    (folder / "test_dynamic.py").write_text(
        "from flask import request\nfrom helper import passthrough\n"
        "def test_dynamic():\n    exec(passthrough(request.args['code']))\n",
        encoding="utf-8",
    )
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v3"
        )
    dynamic = [
        row for row in report["findings"] if row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    ]
    assert len(dynamic) == 1 and dynamic[0]["severity"] == "HIGH"
    assert not [
        row
        for row in report["context_reviews"]
        if row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    ]


def test_imported_constant_helper375_shell_context_reseals_without_downgrade(tmp_path):
    report = _pickle_role_report(
        tmp_path,
        "import subprocess\nfrom helper import constant\n"
        "def test_command():\n    command = constant('ignored')\n"
        "    subprocess.call(command, shell=True)\n",
        {
            "helper.py": "def constant(value):\n    result = 'status'\n    return result\n"
        },
        policy="source-role-v3",
    )
    shell = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_SHELL_COMMAND"
    ]
    assert len(shell) == 1
    raw = shell[0]["raw_finding"]
    assert raw["severity"] == "HIGH"
    assert raw in report["context_reviews"]
    assert not [
        row for row in report["findings"] if row["code"] == "SECURITY_SHELL_COMMAND"
    ]
    assert shell[0]["source_role_review"]["safe_execution"] is False
    resealed = review_audits._seal_security_scan(report.copy())
    assert resealed["context_reviews"] == report["context_reviews"]
    assert resealed["findings"] == report["findings"]


def test_shared_import375_provider_closure_does_not_rescan_whole_context(
    tmp_path, monkeypatch
):
    from factoryline.credential_role_constructor_provider import (
        SourceSnapshotIndex,
        _captured_terminal_provider_mutation,
    )

    sources = {tmp_path / "helper.py": b"def fixed():\n    return 'constant'\n"}
    sources.update(
        {
            tmp_path
            / f"caller_{number}.py": b"import helper\ndef caller():\n    return helper.fixed()\n"
            for number in range(3)
        }
    )
    trees = {path: ast.parse(raw) for path, raw in sources.items()}
    digests = {path: hashlib.sha256(raw).hexdigest() for path, raw in sources.items()}
    for path, tree in trees.items():
        tree._oracle_source_sha256 = digests[path]
        tree._security_source_context = (tmp_path, sources)
    index = SourceSnapshotIndex(tmp_path, trees, sources, digests)
    foreign_visits = []
    original = finite._foreign_provider_inputs

    def counted(*args, **kwargs):
        foreign_visits.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(finite, "_foreign_provider_inputs", counted)
    assert not _captured_terminal_provider_mutation(
        index,
        review_audits,
        "helper.fixed",
        local_binding=(tmp_path / "helper.py", "fixed"),
    )
    assert len(foreign_visits) <= len(sources), (
        "Provider closure rescanned the full context per module"
    )


@pytest.mark.parametrize(
    "source, ambiguous",
    [
        ("import django.db.models.deletion\nimport django.utils.timezone\n", False),
        ("import django.db\nimport django\n", False),
        ("import django.db as provider\nimport django.utils as provider\n", True),
        ("import django.db\nimport unrelated as django\n", True),
        ("import django.db\nimport django.utils as django\n", True),
    ],
)
def test_shared_import375_namespace_binding_matches_python_import(source, ambiguous):
    aliases = finite._shell_import_aliases(
        tuple(ast.walk(ast.parse(source))), review_audits, "django"
    )
    assert (aliases is None) is ambiguous
    if not ambiguous:
        assert aliases["django"] == "django"


@pytest.mark.parametrize(
    "provider, ambiguous",
    [
        ("django.test.TestCase", False),
        ("django.db.models.Model", True),
    ],
)
def test_shared_import375_ambiguity_is_bound_to_selected_provider(provider, ambiguous):
    source = (
        "from django.db import models\ndef migrate():\n    from core import models\n"
    )
    aliases = finite._shell_import_aliases(
        tuple(ast.walk(ast.parse(source))), review_audits, provider
    )
    assert (aliases is None) is ambiguous


@pytest.mark.parametrize(
    "unknown, populated, expected_checks",
    [(True, False, 0), (False, False, 1), (True, True, 1)],
)
def test_shared_import375_unknown_leaf_does_not_demand_negative_proof(
    tmp_path, unknown, populated, expected_checks
):
    from factoryline import credential_role_identity_effects as identity

    path, _tree, index, helper, _caller, call = _shared_security_helper_index(
        tmp_path,
        "def helper(value):\n    return value\ndef caller(raw):\n    return helper(raw)\n",
    )
    checks = []

    def prove():
        checks.append(1)
        return True

    value = identity._Value(
        roots=frozenset() if populated else frozenset({"request"}),
        unknown=unknown,
        scalar_kind="text",
        items=((0, identity._Value(scalar_kind="text")),) if populated else (),
    )
    resolved = identity.ResolvedIdentityCall(
        helper, path, {"value": call.args[0]}, negative_binding_check=prove
    )
    summary = identity.summarize_identity_call(
        call, path, index, {"raw": value}, resolve_call=lambda *_: resolved
    )
    assert len(checks) == expected_checks
    returned = summary.return_values[0].value
    assert (
        returned.roots == value.roots
        and returned.unknown is unknown
        and returned.items == value.items
    )
    assert returned.scalar_kind == value.scalar_kind
    if not expected_checks:
        assert any("UNPROVED_HELPER_PROVIDER" in step for step in returned.trace)


def test_security_value_helper_epoch_tracks_actual_local_definition_binding(
    monkeypatch,
):
    from factoryline import credential_role_identity_effects as effects

    original = review_integrity._security_local_helper_definition
    assert original in effects.security_value_helper_epoch()

    def replacement(*args, **kwargs):
        return None

    monkeypatch.setattr(
        review_integrity, "_security_local_helper_definition", replacement
    )
    assert replacement in effects.security_value_helper_epoch()
