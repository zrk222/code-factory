"""Regression tests for binary float artifacts in published savings receipts.

These fail on 0.24.3. A receipt is an auditable public artifact; emitting
0.060000000000000005 where the exact decimal answer is 0.06 undermines the
claim the receipt exists to make.

The existing suite cannot catch this: its two cost assertions use 2.0 and None,
both of which are float-exact by coincidence.
"""
import tempfile
import pathlib

import pytest
from factoryline.savings import record_savings_pair


def _rec(baseline_cost, factory_cost, **kw):
    root = pathlib.Path(tempfile.mkdtemp())
    ev = root / "e.txt"; ev.write_text("identical outcome")
    return record_savings_pair(
        root, "pair-x",
        {"elapsed_ms": 1000, "tokens": 500, "cost_usd": baseline_cost},
        {"elapsed_ms": 400, "tokens": 200, "cost_usd": factory_cost},
        equivalent_outcome=True, evidence=ev, **kw)["savings"]


def test_cost_saved_has_no_float_artifact():
    assert _rec(0.10, 0.04)["cost_saved_usd"] == 0.06


def test_cost_saved_repr_is_clean():
    # The receipt is serialized and read by humans; repr must not leak binary noise.
    assert repr(_rec(0.10, 0.04)["cost_saved_usd"]) == "0.06"


def test_micro_costs_survive():
    # LLM costs are frequently sub-cent. Fixing floats must not round them away.
    assert _rec(0.000015, 0.000009)["cost_saved_usd"] == 0.000006


def test_rate_has_no_float_artifact():
    assert _rec(0.30, 0.10)["cost_savings_rate"] == pytest.approx(2 / 3)
    assert repr(_rec(0.10, 0.04)["cost_savings_rate"]) == "0.6"


def test_negative_savings_preserved_exactly():
    s = _rec(0.04, 0.10)
    assert s["cost_saved_usd"] == -0.06
    assert repr(s["cost_saved_usd"]) == "-0.06"
