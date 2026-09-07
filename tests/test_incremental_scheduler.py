import pytest

from factoryline.incremental_scheduler import SchedulerError, SCHEMA, compare_shadow, plan_incremental, validate_schedule_manifest


def _manifest(**overrides):
    value = {"schema": SCHEMA, "plan_id": "plan-1", "assurance_level": "isolated_worker", "changed_paths": ["src/app.py"], "dependency_closure": {"lint": ["src/app.py"], "tests": ["src/app.py"]}, "gates": [{"id": "lint", "depends_on": [], "side_effects": False, "proof": None}, {"id": "tests", "depends_on": ["lint"], "side_effects": False, "proof": None}]}
    value.update(overrides)
    return value


def test_unknown_closure_fails_closed_to_run_and_preserves_topological_order():
    result = plan_incremental(__import__("pathlib").Path.cwd(), _manifest(dependency_closure={"lint": ["src/app.py"]}))
    assert result["order"] == ["lint", "tests"]
    assert result["findings"]["tests"]["disposition"] == "RUN"
    assert result["findings"]["tests"]["reason"] == "PROOF_RELEVANCE_FAIL_CLOSED"
    assert result["authority"] == "none"


def test_side_effect_block_propagates_to_dependents():
    manifest = _manifest(gates=[{"id": "lint", "depends_on": [], "side_effects": True, "proof": None}, {"id": "tests", "depends_on": ["lint"], "side_effects": False, "proof": None}])
    result = plan_incremental(__import__("pathlib").Path.cwd(), manifest)
    assert result["findings"]["lint"]["disposition"] == "BLOCK"
    assert result["findings"]["lint"]["reason"] == "PROOF_SIDE_EFFECT_REUSE_REFUSED"
    assert result["findings"]["tests"]["disposition"] == "BLOCK"
    assert result["findings"]["tests"]["reason"] == "SCHEDULER_DEPENDENCY_BLOCKED"


def test_cycle_and_unsafe_path_are_rejected():
    cyclic = _manifest(gates=[{"id": "a", "depends_on": ["b"], "side_effects": False, "proof": None}, {"id": "b", "depends_on": ["a"], "side_effects": False, "proof": None}], dependency_closure={"a": ["src/app.py"], "b": ["src/app.py"]})
    with pytest.raises(SchedulerError, match="E_SCHEDULE_CYCLE"):
        plan_incremental(__import__("pathlib").Path.cwd(), cyclic)
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=["../secrets.txt"]))


def test_shadow_comparison_exposes_differences_without_authority():
    incremental = {"assurance_level": "isolated_worker", "obligations": ["lint"], "findings": {"lint": {"disposition": "RUN"}}}
    full = {"assurance_level": "isolated_worker", "obligations": ["lint"], "findings": {"lint": {"disposition": "RUN"}}}
    assert compare_shadow(incremental, full)["shadow_equivalent"] is True
    full["findings"]["lint"]["disposition"] = "BLOCK"
    result = compare_shadow(incremental, full)
    assert result["shadow_equivalent"] is False
    assert "lint" in result["differences"]["findings_changed"]
    assert result["release_approval"] is False
