import pytest

from factoryline.proof_reuse import evaluate_proofs, record_proof
from factoryline.incremental_scheduler import (
    SchedulerError,
    SCHEMA,
    compare_shadow,
    paths_intersect,
    plan_incremental,
    validate_schedule_manifest,
)


def _manifest(**overrides):
    value = {
        "schema": SCHEMA,
        "plan_id": "plan-1",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/app.py"],
        "dependency_closure": {"lint": ["src/app.py"], "tests": ["src/app.py"]},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None},
            {
                "id": "tests",
                "depends_on": ["lint"],
                "side_effects": False,
                "proof": None,
            },
        ],
    }
    value.update(overrides)
    return value


def test_unknown_closure_fails_closed_to_run_and_preserves_topological_order():
    result = plan_incremental(
        __import__("pathlib").Path.cwd(),
        _manifest(dependency_closure={"lint": ["src/app.py"]}),
    )
    assert result["order"] == ["lint", "tests"]
    assert result["findings"]["tests"]["disposition"] == "RUN"
    assert result["findings"]["tests"]["reason"] == "PROOF_RELEVANCE_FAIL_CLOSED"
    assert result["authority"] == "none"


def test_changed_dependency_closure_forces_run_even_with_reusable_proof():
    manifest = _manifest(
        gates=[
            {
                "id": "lint",
                "depends_on": [],
                "side_effects": False,
                "proof": {"assurance_level": "isolated_worker"},
            }
        ],
        dependency_closure={"lint": ["src/app.py"]},
    )
    result = plan_incremental(__import__("pathlib").Path.cwd(), manifest)
    assert result["findings"]["lint"]["disposition"] == "RUN"
    assert result["findings"]["lint"]["reason"] == "DEPENDENCY_CLOSURE_CHANGED"


def test_side_effect_block_propagates_to_dependents():
    manifest = _manifest(
        gates=[
            {"id": "lint", "depends_on": [], "side_effects": True, "proof": None},
            {
                "id": "tests",
                "depends_on": ["lint"],
                "side_effects": False,
                "proof": None,
            },
        ]
    )
    result = plan_incremental(__import__("pathlib").Path.cwd(), manifest)
    assert result["findings"]["lint"]["disposition"] == "BLOCK"
    assert result["findings"]["lint"]["reason"] == "PROOF_SIDE_EFFECT_REUSE_REFUSED"
    assert result["findings"]["tests"]["disposition"] == "BLOCK"
    assert result["findings"]["tests"]["reason"] == "SCHEDULER_DEPENDENCY_BLOCKED"


def test_cycle_and_unsafe_path_are_rejected():
    cyclic = _manifest(
        gates=[
            {"id": "a", "depends_on": ["b"], "side_effects": False, "proof": None},
            {"id": "b", "depends_on": ["a"], "side_effects": False, "proof": None},
        ],
        dependency_closure={"a": ["src/app.py"], "b": ["src/app.py"]},
    )
    with pytest.raises(SchedulerError, match="E_SCHEDULE_CYCLE"):
        plan_incremental(__import__("pathlib").Path.cwd(), cyclic)
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=["../secrets.txt"]))
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=[".."]))
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=["C:\\secrets.txt"]))


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("src/app.py", "src", True),
        ("src/app.py", "src/app.py", True),
        ("src/app.py", "src/apply.py", False),
        ("Src\\App.py", "src", True),
        (".factory/receipts/run.json", ".factory/receipts", True),
        ("./.factory/run.json", "factory/run.json", False),
        ("", "src", False),
    ],
)
def test_paths_intersect_is_conservative_and_segment_aware(
    left: str, right: str, expected: bool
):
    assert paths_intersect(left, right) is expected


def test_shadow_comparison_exposes_differences_without_authority():
    incremental = {
        "assurance_level": "isolated_worker",
        "obligations": ["lint"],
        "findings": {"lint": {"disposition": "RUN"}},
    }
    full = {
        "assurance_level": "isolated_worker",
        "obligations": ["lint"],
        "findings": {"lint": {"disposition": "RUN"}},
    }
    assert compare_shadow(incremental, full)["shadow_equivalent"] is True
    full["findings"]["lint"]["disposition"] = "BLOCK"
    result = compare_shadow(incremental, full)
    assert result["shadow_equivalent"] is False
    assert "lint" in result["differences"]["findings_changed"]
    assert result["release_approval"] is False


def test_incremental_plan_batches_duplicate_proof_names_without_persistence(
    tmp_path, monkeypatch
):
    import factoryline.incremental_scheduler as scheduler
    import factoryline.proof_reuse as proof_reuse

    source = tmp_path / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('ok')\n", encoding="utf-8")
    outputs = []
    proofs = []
    for index in range(2):
        output = tmp_path / "dist" / f"result-{index}.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text('{"passed":true}\n', encoding="utf-8")
        outputs.append(output)
        proof = {
            "name": "same-proof-name",
            "command": ["python", "-m", f"check{index}"],
            "inputs": ["src/app.py"],
            "outputs": [output.relative_to(tmp_path).as_posix()],
            "relevant_paths": ["src"],
            "safe_to_skip": False,
            "read_only": True,
            "toolchain": {"python": "3.11.9"},
            "environment": {"os": "windows"},
        }
        record_proof(tmp_path, proof, elapsed_ms=1000)
        proofs.append(proof)

    manifest = _manifest(
        changed_paths=["docs/readme.md"],
        gates=[
            {
                "id": f"gate-{index}",
                "depends_on": [],
                "side_effects": False,
                "proof": proof,
            }
            for index, proof in enumerate(proofs)
        ],
        dependency_closure={f"gate-{index}": ["src/app.py"] for index in range(2)},
    )
    original_evaluate = scheduler.evaluate_proofs
    calls = []

    def count_batch(*args, **kwargs):
        calls.append(len(args[1]["gates"]))
        return original_evaluate(*args, **kwargs)

    writes = 0
    original_atomic = proof_reuse._atomic_json

    def count_atomic(*args, **kwargs):
        nonlocal writes
        writes += 1
        return original_atomic(*args, **kwargs)

    monkeypatch.setattr(scheduler, "evaluate_proofs", count_batch)
    monkeypatch.setattr(proof_reuse, "_atomic_json", count_atomic)
    monkeypatch.setattr(
        "tempfile.TemporaryDirectory",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("temp directory")),
    )
    destination = tmp_path / "incremental-plan.json"
    result = plan_incremental(tmp_path, manifest, out=destination)

    assert calls == [2]
    assert writes == 0
    assert destination.is_file()
    assert not (tmp_path / ".factory" / "proof-plans").exists()
    assert [row["disposition"] for row in result["items"]] == ["REUSE", "REUSE"]
    for row, proof in zip(result["items"], proofs, strict=True):
        single = evaluate_proofs(
            tmp_path,
            {"schema": "factory.proof-request.v1", "gates": [proof]},
            changed_paths=["docs/readme.md"],
        )["items"][0]
        assert row["proof"] == {
            "proof_key": single["proof_key"],
            "receipt_sha256": single["receipt_sha256"],
        }
        assert row["reason"] == single["reason"]
