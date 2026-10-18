import ast

import pytest

from factoryline.runtime_audit_integrity import finite_literal_eval_input_witness


SOURCE = 'types = [(eval(tp), expected) for tp, expected in [("list[Person]", True), ("tuple[Person, ...]", False)]]\n'


def witness(source, raw=None):
    tree = ast.parse(source)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "eval")
    return finite_literal_eval_input_witness(call, "eval", source_bytes=raw or source.encode(), source_path="case.py")


def test_finite_eval_literal_domain_records_input_only():
    facts = witness(SOURCE)
    assert facts["domain_size"] == 2
    assert facts["runtime_assurance"] == "INCOMPLETE"
    assert facts["target_execution"] == "not_performed"


@pytest.mark.parametrize("source", [
    SOURCE.replace('"list[Person]"', 'payload'),
    SOURCE.replace('"list[Person]"', '"factory()"'),
    SOURCE.replace('"list[Person]"', '"Person.attr"'),
    SOURCE.replace('for tp, expected in', 'for tp, expected in supplied for unused in'),
    SOURCE.replace('eval(tp)', 'eval(tp, supplied)'),
    SOURCE.replace('eval(tp)', 'eval((tp := supplied))'),
    SOURCE.replace('eval(tp)', 'eval(tp + supplied)'),
    SOURCE.replace('eval(tp)', 'eval(tp) if expected else expose(tp)'),
    'eval = replacement\n' + SOURCE,
    'from builtins import exec as rewrite\nrewrite("eval = replacement")\n' + SOURCE,
    SOURCE.replace('"list[Person]"', '"[x for x in source]"'),
    SOURCE.replace('[("list[Person]", True), ("tuple[Person, ...]", False)]', '[]'),
])
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
    assert witness(SOURCE + '\ndef later():\n    delattr(NoParams, "__parameters__")\n')["domain_size"] == 2


def test_finite_eval_rejects_prior_function_invocation():
    source = 'def rewrite():\n    globals()["eval"] = replacement\nrewrite()\n' + SOURCE
    assert witness(source) == {}


def test_finite_eval_native_scan_retains_primitive(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(SOURCE)
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert report["primitive_observations"][0]["facts"]["disposition"] == "PROVEN_FINITE_LITERAL_EVAL_INPUT"


@pytest.mark.parametrize("source", [
    'types = [(lambda tp: eval(tp)) for tp, expected in [("list[Person]", True)]]\n',
    'from arbitrary import eval\n' + SOURCE,
    'from arbitrary import replacement as eval\n' + SOURCE,
    SOURCE.replace('"list[Person]", True', '"list[Person]", rewrite()'),
])
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
