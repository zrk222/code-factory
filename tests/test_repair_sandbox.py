from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.repair_sandbox import (
    RepairSandboxError,
    create_repair_scope,
    inspect_repair_candidate,
    verify_repair_scope,
    write_repair_candidate_artifacts,
    write_repair_scope_artifacts,
)


def _files(root: Path) -> dict[str, bytes]:
    return {item.relative_to(root).as_posix(): item.read_bytes() for item in root.rglob("*") if item.is_file()}


def _patch(root: Path, name: str, body: str) -> Path:
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def test_repair_scope_is_explicit_deterministic_and_does_not_write_by_default(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    before = _files(tmp_path)

    scope = create_repair_scope(tmp_path, "Checkout hardening", ["src/service.py"])

    assert scope["schema"] == "factory.repair_scope.v1"
    assert scope["change_list"] == "Checkout hardening"
    assert scope["scope_id"] == f"repair-scope-{scope['scope_sha256'][:12]}"
    measured_bytes = (tmp_path / "src" / "service.py").read_bytes()
    assert scope["paths"] == [{
        "path": "src/service.py", "exists": True, "size_bytes": len(measured_bytes), "sha256": scope["paths"][0]["sha256"],
    }]
    assert scope["context_budget"] == {
        "limit_bytes": 262144,
        "measured_bytes": len(measured_bytes),
        "file_count": 1,
        "missing_paths": 0,
        "decision": "within_budget",
        "scope_limits": "Measured bytes only; this is not a token, provider-credit, latency, or quality estimate.",
    }
    assert scope["review"]["changed_paths"] == ["src/service.py"]
    assert scope["candidate"]["state"] == "not_started"
    assert scope["authority"]["patch_apply"] is False
    assert [item["id"] for item in scope["verification"]["required_checks"]][-2:] == ["independent_verifier", "human_apply"]
    assert _files(tmp_path) == before
    assert create_repair_scope(tmp_path, "Checkout hardening", ["src/service.py"])["scope_sha256"] == scope["scope_sha256"]


def test_repair_scope_artifacts_are_explicit_local_and_hash_bound(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])

    artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")

    assert artifacts["marker"] == "REPAIR_SCOPE_ARTIFACTS_WRITTEN"
    assert all(Path(path).is_file() for path in artifacts["paths"].values())
    payload = json.loads(Path(artifacts["paths"]["json"]).read_text(encoding="utf-8"))
    assert payload["scope_sha256"] == scope["scope_sha256"]
    assert "scope_markdown" not in payload
    assert "Human diff review and apply" in Path(artifacts["paths"]["mermaid"]).read_text(encoding="utf-8")


def test_verify_repair_scope_requires_a_current_canonical_scope(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])

    assert verify_repair_scope(scope, tmp_path)["scope_id"] == scope["scope_id"]
    scope["paths"][0]["sha256"] = "0" * 64

    with pytest.raises(RepairSandboxError) as caught:
        verify_repair_scope(scope, tmp_path)

    assert caught.value.code == "REPAIR_SCOPE_TAMPERED"


def test_candidate_patch_is_scoped_and_never_applied(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "service.py"
    source.write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    scope_artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    patch = _patch(tmp_path, "candidate.patch", """diff --git a/src/service.py b/src/service.py
index 1111111..2222222 100644
--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-before
+after
""")

    candidate = inspect_repair_candidate(tmp_path, Path(scope_artifacts["paths"]["json"]), patch)

    assert candidate["schema"] == "factory.repair_candidate.v1"
    assert candidate["touched_paths"] == ["src/service.py"]
    assert candidate["patch"]["path"] == "candidate.patch"
    assert candidate["apply"]["state"] == "human_confirmation_required"
    assert candidate["authority"]["source_modify"] is False
    assert source.read_text(encoding="utf-8") == "before\n"
    artifacts = write_repair_candidate_artifacts(candidate, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    assert Path(artifacts["paths"]["json"]).is_file()


def test_scope_reports_measured_context_and_recommends_split_without_estimating_tokens(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("x" * 11, encoding="utf-8")

    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"], context_budget_bytes=10)

    assert scope["context_budget"]["measured_bytes"] == 11
    assert scope["context_budget"]["decision"] == "split_recommended"
    assert "token" not in json.dumps(scope["context_budget"]).lower().replace("not a token", "")


def test_candidate_rejects_outside_scope_before_any_apply(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    patch = _patch(tmp_path, "candidate.patch", """diff --git a/.github/workflows/publish.yml b/.github/workflows/publish.yml
index 1111111..2222222 100644
--- a/.github/workflows/publish.yml
+++ b/.github/workflows/publish.yml
@@ -1 +1 @@
-before
+after
""")

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_CANDIDATE_OUT_OF_SCOPE"
    assert (tmp_path / "src" / "service.py").read_text(encoding="utf-8") == "before\n"


@pytest.mark.parametrize("patch_body", [
    "diff --git a/src/service.py b/src/service.py\nGIT binary patch\n",
    'diff --git "a/src/service.py" "b/src/service.py"\n',
    "diff --combined src/service.py\n",
])
def test_candidate_rejects_unsupported_patch_forms(tmp_path: Path, patch_body: str) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    patch = _patch(tmp_path, "candidate.patch", patch_body)

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_PATCH_UNSUPPORTED"


def test_candidate_rejects_scope_drift(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "service.py"
    source.write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    source.write_text("drifted\n", encoding="utf-8")
    patch = _patch(tmp_path, "candidate.patch", "diff --git a/src/service.py b/src/service.py\n")

    with pytest.raises(RepairSandboxError) as caught:
        inspect_repair_candidate(tmp_path, Path(artifacts["paths"]["json"]), patch)

    assert caught.value.code == "REPAIR_SCOPE_DRIFT"


def test_repair_cli_outputs_machine_readable_scope_and_candidate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    out_dir = tmp_path / ".factory" / "repair-sandboxes"

    assert main([
        "repair", "scope", "--root", str(tmp_path), "--change-list", "Checkout", "--changed", "src/service.py",
        "--out-dir", str(out_dir), "--json",
    ]) == 0
    scope = json.loads(capsys.readouterr().out)
    patch = _patch(tmp_path, "candidate.patch", "diff --git a/src/service.py b/src/service.py\n")
    assert main([
        "repair", "candidate", "--root", str(tmp_path), "--scope", scope["artifacts"]["paths"]["json"],
        "--patch", str(patch), "--out-dir", str(out_dir), "--json",
    ]) == 0
    candidate = json.loads(capsys.readouterr().out)

    assert scope["artifacts"]["marker"] == "REPAIR_SCOPE_ARTIFACTS_WRITTEN"
    assert candidate["artifacts"]["marker"] == "REPAIR_CANDIDATE_ARTIFACTS_WRITTEN"
    assert candidate["scope_sha256"] == scope["scope_sha256"]


def test_repair_cli_marks_outside_candidate_path_machine_readably(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.py").write_text("before\n", encoding="utf-8")
    scope = create_repair_scope(tmp_path, "Checkout", ["src/service.py"])
    artifacts = write_repair_scope_artifacts(scope, tmp_path, tmp_path / ".factory" / "repair-sandboxes")
    patch = _patch(tmp_path, "candidate.patch", "diff --git a/outside.py b/outside.py\n")

    assert main([
        "repair", "candidate", "--root", str(tmp_path), "--scope", artifacts["paths"]["json"], "--patch", str(patch), "--json",
    ]) == 2
    failure = json.loads(capsys.readouterr().err)

    assert failure["schema"] == "factory.repair_candidate.error.v1"
    assert failure["marker"] == "REPAIR_SANDBOX_PATH_REJECTED"
    assert failure["code"] == "REPAIR_CANDIDATE_OUT_OF_SCOPE"
