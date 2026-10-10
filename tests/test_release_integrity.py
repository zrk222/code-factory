from __future__ import annotations

import json
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.release_integrity import (
    FORGELINE_REASSESSMENT_VERSION,
    REASSESSMENT_SCHEMA,
    _source_snapshot_digest,
    release_integrity,
    render_release_integrity,
    review_regression_audit,
    _fresh_reassessment_date,
)
from factoryline.release_route_integrity import release_route_checks


import factoryline.release_candidate as candidate
from scripts.verify_release_preflight import main as verify_release_preflight_main
from scripts.verify_release_preflight import verify as verify_release_preflight


ROOT = Path(__file__).parents[1]


def test_core_0481_exception_is_explicit_and_protected() -> None:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    option = triggers["workflow_dispatch"]["inputs"]["core_0481_cadence_exception"]
    assert option["type"] == "boolean" and option["default"] is False
    publish = workflow["jobs"]["publish"]
    assert publish["environment"] == "pypi"
    guard = next(
        step
        for step in workflow["jobs"]["guard"]["steps"]
        if step.get("name", "").startswith("Enforce cadence")
    )
    assert 'os.environ.get("RELEASE_TAG") != "v0.48.1"' in guard["run"]
    assert 'os.environ.get("GITHUB_ACTOR") != "zrk222"' in guard["run"]
    assert 'len(recent) >= policy["max_releases_30d"]' in guard["run"]
    preflight = next(
        step
        for step in publish["steps"]
        if step.get("name", "").startswith("Require sealed")
    )
    assert "timedelta(hours=1)" in preflight["run"]
    assert (
        "--cadence-exception .factory/core-0481-cadence-exception.json"
        in preflight["run"]
    )
    assert '"${exception_args[@]}"' in preflight["run"]


@pytest.mark.parametrize(
    ("enabled", "tag", "actor", "admitted"),
    [
        ("false", "v0.48.1", "zrk222", False),
        ("true", "v0.48.1", "zrk222", True),
        ("true", "v0.49.0", "zrk222", False),
        ("true", "v0.48.1", "other", False),
    ],
)
def test_actual_cadence_workflow_rejects_unapproved_dispatch(
    tmp_path: Path, monkeypatch, enabled, tag, actor, admitted
) -> None:
    import yaml
    from datetime import datetime, timezone

    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    step = next(
        s
        for s in workflow["jobs"]["guard"]["steps"]
        if s.get("name", "").startswith("Enforce cadence")
    )
    code = step["run"].split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    shutil.copy(ROOT / "release-train.json", tmp_path / "release-train.json")
    stamp = datetime.now(timezone.utc).isoformat()
    (tmp_path / "release-history.json").write_text(
        json.dumps([[{"draft": False, "published_at": stamp}]])
    )
    monkeypatch.chdir(tmp_path)
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "CORE_0481_EXCEPTION": enabled,
        "RELEASE_TAG": tag,
        "GITHUB_ACTOR": actor,
    }.items():
        monkeypatch.setenv(key, value)
    if admitted:
        exec(compile(code, "publish-cadence", "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(code, "publish-cadence", "exec"), {})


def _passing_reassessment() -> dict[str, object]:
    passed_unit = {
        "unit": "qa_audit:factoryline/release_integrity.py:review",
        "stage": "qa_audit",
        "passed": True,
        "evidence": "metrics within thresholds",
        "failure_class": None,
    }
    return {
        "grade": "A",
        "passed": True,
        "metrics": {
            "coverage_intent": 1.0,
            "max_complexity": 10,
            "security_score": 100,
            "doc_ratio": 1.0,
            "composite": 95.0,
            "complexity_policy": "hard",
            "coverage_assessment": "measured",
            "behavioral_proof_status": "available",
            "scope": {"kind": "repo_wide", "code_files": ["factoryline/a.py"]},
            "skipped_paths": [],
        },
        "findings": [],
        "attribution": {
            "stage": "qa_audit",
            "n_checked": 1,
            "n_passed": 1,
            "rate": 1.0,
            "units": [passed_unit],
        },
    }


def _reassessment_envelope(report: dict[str, object]) -> dict[str, object]:
    return {
        "schema": REASSESSMENT_SCHEMA,
        "tool": {
            "package": "code-factory-2-forge",
            "version": FORGELINE_REASSESSMENT_VERSION,
            "identity_complete": True,
        },
        "source_sha256": "a" * 64,
        "report": report,
    }


def test_source_snapshot_digest_binds_audited_code_and_policy(tmp_path: Path) -> None:
    source = tmp_path / "factoryline" / "a.py"
    source.parent.mkdir()
    source.write_text("def check(): return True\n", encoding="utf-8")
    for relative in (
        "architecture-policy.json",
        "architecture-boundaries.json",
        ".factory/repository-scope.json",
        "pyproject.toml",
        "CONTRIBUTING.md",
        "docs/RELEASE_CHANNELS.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding="utf-8")

    first = _source_snapshot_digest(tmp_path, ["factoryline/a.py"])
    assert first is not None
    source.write_bytes(b"def check(): return True\r\n")
    assert _source_snapshot_digest(tmp_path, ["factoryline/a.py"]) == first
    source.write_bytes(b"def check(): return True\n")
    assert _source_snapshot_digest(tmp_path, ["factoryline/a.py"]) == first
    source.write_text("def check(): return False\n", encoding="utf-8")
    second = _source_snapshot_digest(tmp_path, ["factoryline/a.py"])
    assert second is not None and second != first
    assert _source_snapshot_digest(tmp_path, ["../outside.py"]) is None


def test_container_publish_targets_exist_in_this_repository() -> None:
    workflow = ROOT / ".github/workflows/github-packages.yml"
    source = workflow.read_text(encoding="utf-8")

    contexts = re.findall(r"^\s+context:\s*(\S+)\s*$", source, re.MULTILINE)
    dockerfiles = re.findall(r"^\s+file:\s*(\S+)\s*$", source, re.MULTILINE)

    assert contexts
    assert len(contexts) == len(dockerfiles)
    assert all((ROOT / context).is_dir() for context in contexts)
    assert all((ROOT / dockerfile).is_file() for dockerfile in dockerfiles)


def test_container_publish_requires_the_canonical_release_and_verifies_digest() -> None:
    source = (ROOT / ".github/workflows/github-packages.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in source
    assert not re.search(r"^  push:", source, re.MULTILINE)
    assert '[[ "$GITHUB_REF" == refs/heads/main ]]' in source
    assert "actions/workflows/publish.yml/runs" in source
    assert 'run.get("head_sha")==sys.argv[2]' in source
    assert "steps.build.outputs.digest" in source
    assert 'docker buildx imagetools inspect "$IMAGE:$VERSION"' in source
    assert "registry inspection must return exactly one manifest digest" in source
    assert '[[ "$actual" == "$EXPECTED_DIGEST" ]]' in source


def test_review_regression_audit_catches_devin_failure_classes(tmp_path: Path) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.name", "Audit Test"],
        ["config", "user.email", "audit@example.invalid"],
    ):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    evidence = tmp_path / "evidence" / "self-audit" / "quality-2026-09-25.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"grade":"F"}\n', encoding="utf-8")
    channels = tmp_path / "docs" / "RELEASE_CHANNELS.md"
    channels.parent.mkdir()
    channels.write_text(
        "The owner selected a specialty AI reviewer.\n", encoding="utf-8"
    )
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("A specialty AI agent reviews source.\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "baseline"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    assert review_regression_audit(tmp_path, "HEAD")["state"] == "CLEAN"
    evidence.write_text('{"grade":"A"}\n', encoding="utf-8")
    history = review_regression_audit(tmp_path, "HEAD")
    assert history["state"] == "BLOCKED"
    assert history["findings"][0]["code"] == "HISTORICAL_EVIDENCE_MUTATED"
    evidence.write_text('{"grade":"F"}\n', encoding="utf-8")
    contributing.write_text(
        "Every public release requires approval by a human other than the initiator.\n",
        encoding="utf-8",
    )
    channels.write_text(
        "PyPI and Hugging Face no longer require a second human.\n", encoding="utf-8"
    )
    conflict = review_regression_audit(tmp_path, "HEAD")
    assert conflict["state"] == "BLOCKED"
    assert conflict["findings"][0]["code"] == "RELEASE_REVIEW_POLICY_CONFLICT"
    assert review_regression_audit(tmp_path, "missing-ref")["state"] == "INCOMPLETE"
    assert (
        review_regression_audit(tmp_path, "--output=unexpected")["state"]
        == "INCOMPLETE"
    )


def test_review_regression_audit_accepts_only_hash_verified_evidence_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.name", "Audit Test"],
        ["config", "user.email", "audit@example.invalid"],
    ):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    old_relative = "evidence/self-audit/quality-2026-09-25.json"
    old_evidence = tmp_path / old_relative
    old_evidence.parent.mkdir(parents=True)
    old_evidence.write_text('{"grade":"F"}\n', encoding="utf-8")
    channels = tmp_path / "docs" / "RELEASE_CHANNELS.md"
    channels.parent.mkdir()
    channels.write_text(
        "The owner selected a specialty AI reviewer.\n", encoding="utf-8"
    )
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("A specialty AI agent reviews source.\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "baseline"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    digest = hashlib.sha256(
        subprocess.check_output(["git", "show", f"HEAD:{old_relative}"], cwd=tmp_path)
    ).hexdigest()
    old_evidence.unlink()
    manifest = tmp_path / ".factory" / "evidence-retirement.json"
    manifest.parent.mkdir()
    entry = {
        "path": old_relative,
        "sha256": digest,
        "reason": "Superseded inventory replaced by a fresh dated reassessment.",
    }
    manifest.write_text(
        json.dumps(
            {"schema": "factory.evidence_retirement.v1", "retirements": [entry]}
        ),
        encoding="utf-8",
    )

    missing = review_regression_audit(tmp_path, "HEAD")
    assert missing["state"] == "BLOCKED"
    assert missing["findings"][0]["code"] == "EVIDENCE_RETIREMENT_WITHOUT_REASSESSMENT"

    fresh = tmp_path / "evidence" / "self-audit" / "quality-2026-09-26.json"
    report = _passing_reassessment()
    envelope = _reassessment_envelope(report)
    fresh.write_text(json.dumps(envelope), encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.release_integrity._run_forgeline_reassessment",
        lambda _root: report,
    )
    monkeypatch.setattr(
        "factoryline.release_integrity._source_snapshot_digest",
        lambda _root, _files: "a" * 64,
    )
    subprocess.run(
        ["git", "add", str(fresh.relative_to(tmp_path))],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    result = review_regression_audit(tmp_path, "HEAD")
    assert result["state"] == "CLEAN", result
    assert result["findings"] == []
    assert result["retired_evidence"] == [{"path": old_relative, "sha256": digest}]

    entry["sha256"] = "0" * 64
    manifest.write_text(
        json.dumps(
            {"schema": "factory.evidence_retirement.v1", "retirements": [entry]}
        ),
        encoding="utf-8",
    )
    rejected = review_regression_audit(tmp_path, "HEAD")
    assert rejected["state"] == "BLOCKED"
    assert rejected["findings"][0]["code"] == "EVIDENCE_RETIREMENT_DIGEST_MISMATCH"


def test_fresh_reassessment_requires_valid_date_and_matching_forgeline_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid_date = "evidence/self-audit/fake-9999-99-99.json"
    path = tmp_path / invalid_date
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_passing_reassessment()), encoding="utf-8")
    assert _fresh_reassessment_date(tmp_path, invalid_date) is None
    future_date = "evidence/self-audit/quality-2099-01-01.json"
    future_path = tmp_path / future_date
    future_path.write_text(
        json.dumps(_reassessment_envelope(_passing_reassessment())), encoding="utf-8"
    )
    assert _fresh_reassessment_date(tmp_path, future_date) is None

    shallow = "evidence/self-audit/quality-2026-09-26.json"
    path = tmp_path / shallow
    path.write_text(
        json.dumps(
            {
                "grade": "A",
                "passed": True,
                "metrics": {},
                "findings": [],
                "attribution": {},
            }
        ),
        encoding="utf-8",
    )
    assert _fresh_reassessment_date(tmp_path, shallow) is None

    report = _passing_reassessment()
    envelope = _reassessment_envelope(report)
    path.write_text(json.dumps(envelope), encoding="utf-8")
    monkeypatch.setattr(
        "factoryline.release_integrity._run_forgeline_reassessment",
        lambda _root: {**report, "metrics": {**report["metrics"], "composite": 100.0}},
    )
    monkeypatch.setattr(
        "factoryline.release_integrity._source_snapshot_digest",
        lambda _root, _files: "a" * 64,
    )
    assert _fresh_reassessment_date(tmp_path, shallow) is None

    monkeypatch.setattr(
        "factoryline.release_integrity._run_forgeline_reassessment",
        lambda _root: report,
    )
    assert _fresh_reassessment_date(tmp_path, shallow) == "2026-09-26"

    envelope["source_sha256"] = "b" * 64
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert _fresh_reassessment_date(tmp_path, shallow) is None


def test_forgeline_reassessment_requires_pinned_runtime_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from factoryline.release_integrity import _run_forgeline_reassessment

    calls: list[list[str]] = []
    report = _passing_reassessment()

    def run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        if command == ["forge", "--version", "--json"]:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "package": "code-factory-2-forge",
                        "version": FORGELINE_REASSESSMENT_VERSION,
                        "identity_complete": True,
                    }
                ),
                "",
            )
        return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

    monkeypatch.setattr("factoryline.release_integrity.subprocess.run", run)
    assert _run_forgeline_reassessment(tmp_path) == report
    assert calls == [
        ["forge", "--version", "--json"],
        ["forge", "qa", "--repo-wide", "--root", str(tmp_path), "--strict"],
    ]

    calls.clear()

    def wrong_version(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "package": "code-factory-2-forge",
                    "version": "0.10.7",
                    "identity_complete": True,
                }
            ),
            "",
        )

    monkeypatch.setattr("factoryline.release_integrity.subprocess.run", wrong_version)
    assert _run_forgeline_reassessment(tmp_path) is None
    assert calls == [["forge", "--version", "--json"]]


WORKFLOWS = (
    "publish.yml",
    "openvsx.yml",
    "vscode-marketplace.yml",
    "jetbrains-marketplace.yml",
    "intellij-plugin.yml",
    "huggingface-space.yml",
)
INTELLIJ_FILES = (
    "editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt",
    "editors/intellij/settings.gradle.kts",
    "editors/intellij/build.gradle.kts",
)
HUGGINGFACE_FILES = ("deploy/huggingface/README.md",)
PACKAGE_FILES = ("pyproject.toml",)


def _workflow_copy(tmp_path: Path) -> Path:
    destination = tmp_path / ".github" / "workflows"
    destination.mkdir(parents=True)
    for name in WORKFLOWS:
        shutil.copy2(ROOT / ".github" / "workflows" / name, destination / name)
    for relative in INTELLIJ_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    for relative in HUGGINGFACE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    for relative in PACKAGE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return tmp_path


def test_release_integrity_reports_exact_read_only_happy_path() -> None:
    before = {
        name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS
    }

    result = release_integrity(ROOT)

    assert result["schema"] == "factory.release_integrity.v1"
    assert result["marker"] == "RELEASE_INTEGRITY_READ_ONLY"
    assert result["ok"] is True
    assert [item["id"] for item in result["checks"]] == [
        "RELEASE_FAN_IN_EXACT",
        "RELEASE_CANDIDATE_PREFLIGHT_REQUIRED",
        "RELEASE_VALIDATION_PARTITIONED",
        "OPENVSX_AUTHORIZATION_EARLY",
        "VSCODE_MARKETPLACE_AUTHORIZATION_EARLY",
        "VSCODE_MARKETPLACE_CANDIDATE_SEALED",
        "JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY",
        "JETBRAINS_JDK21_EXACT",
        "HUGGINGFACE_AUTHORIZATION_EARLY",
        "PYPI_TRUSTED_PUBLISHING",
        "JETBRAINS_APPROVAL_GUARD",
        "INTELLIJ_COMPATIBILITY_DECLARED",
        "HUGGINGFACE_METADATA_PREFLIGHT",
        "PYTHON_PACKAGE_DATA_EXPLICIT",
    ]
    assert all(item["passed"] for item in result["checks"])
    assert not any(result["authority"].values())
    assert (
        "JetBrains publication still requires JETBRAINS_MARKETPLACE_TOKEN in the protected jetbrains-marketplace environment."
        in result["external_requirements"]
    )
    assert (
        "Hugging Face Space publication still requires the configured HF_TOKEN GitHub Actions secret."
        in result["external_requirements"]
    )
    assert {
        name: (ROOT / ".github" / "workflows" / name).read_bytes() for name in WORKFLOWS
    } == before


def test_release_route_checks_expose_the_huggingface_admission_boundary() -> None:
    checks = {item["id"]: item for item in release_route_checks(ROOT)}

    assert checks["HUGGINGFACE_AUTHORIZATION_EARLY"] == {
        "id": "HUGGINGFACE_AUTHORIZATION_EARLY",
        "passed": True,
        "evidence": "Hugging Face credential admission is declared before Space candidate work",
    }


def test_release_integrity_rejects_missing_artifact_fan_in(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    publish.write_text(
        publish.read_text(encoding="utf-8").replace(
            "needs: [guard, validate_python, validate_vscode, validate_intellij]",
            "needs: validate_python",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["marker"] == "RELEASE_INTEGRITY_FAILURE"
    assert result["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]
    assert result["next_action"]["action"] == "repair_release_workflow"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('[[ "$is_draft" == "true" ]]', '[[ "$is_draft" == "false" ]]'),
        (
            '[[ "$GITHUB_REF" == "refs/heads/main" ]]',
            '[[ "$GITHUB_REF" == "refs/heads/feature" ]]',
        ),
        ("--draft=false", "--draft=true"),
        ('== "$EXPECTED_COMMIT"', '!= "$EXPECTED_COMMIT"'),
        ("workflow_dispatch:", "release:\n    types: [published]"),
        (
            "ref: ${{ needs.guard.outputs.candidate_commit }}",
            "ref: ${{ github.event.release.tag_name }}",
        ),
        ('git merge-base --is-ancestor "$candidate_commit" origin/main', "true"),
        ('item["published_at"]', 'item["created_at"]'),
        ("group: publish-release-train", "group: publish-${{ inputs.release_tag }}"),
        ('git fetch --no-tags origin "refs/tags/${RELEASE_TAG}"', "true"),
        (
            "needs: [guard, validate_python, validate_vscode, validate_intellij]",
            "needs: [validate_python, validate_vscode, validate_intellij]",
        ),
    ],
)
def test_release_integrity_rejects_unsafe_or_unbound_publish_topology(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    original = publish.read_text(encoding="utf-8")
    assert old in original
    publish.write_text(original.replace(old, new, 1), encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["RELEASE_FAN_IN_EXACT"]


def test_release_integrity_rejects_late_openvsx_authorization(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "openvsx.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "needs: [authorize, attested-source]\n", "needs: [attested-source]\n"
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["OPENVSX_AUTHORIZATION_EARLY"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            'test "$RELEASE_REF" = vscode-v1.1.4+build.1 || { echo "The one-time exception is restricted to vscode-v1.1.4+build.1." >&2; exit 1; }',
            "true",
        ),
        (
            'test "$PUBLISH" = true || { echo "A cadence exception is valid only for an explicitly publishing run." >&2; exit 1; }',
            "true",
        ),
        (
            "exception_args=(--cadence-exception .factory/release-cadence-exception.json)",
            "exception_args=()",
        ),
        ("GITHUB_RUN_ATTEMPT: ${{ github.run_attempt }}", "GITHUB_RUN_ATTEMPT: 1"),
    ],
)
def test_release_integrity_rejects_weakened_openvsx_cadence_exception(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "openvsx.yml"
    original = workflow.read_text(encoding="utf-8")
    assert old in original
    workflow.write_text(original.replace(old, new, 1), encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["OPENVSX_AUTHORIZATION_EARLY"]


def test_release_integrity_rejects_vscode_candidate_validation_without_authorization(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "vscode-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "needs: [authorize, attested-source]\n", "needs: [attested-source]\n", 1
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["VSCODE_MARKETPLACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_publication_without_candidate_preflight(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    publish = root / ".github" / "workflows" / "publish.yml"
    content = publish.read_text(encoding="utf-8")
    start = content.index("      - name: Require sealed release candidate preflight")
    end = content.index("      - name: Attach distributions to GitHub release", start)
    publish.write_text(content[:start] + content[end:], encoding="utf-8")

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["RELEASE_CANDIDATE_PREFLIGHT_REQUIRED"]


def test_release_integrity_rejects_unsealed_vscode_candidate_identity(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "vscode-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "grep -Fx 'publisher=zrk222' manifest.txt", "true"
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["VSCODE_MARKETPLACE_CANDIDATE_SEALED"]


def test_release_integrity_rejects_java17_in_any_intellij_gradle_workflow(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "intellij-plugin.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            'java-version: "21"', 'java-version: "17"', 1
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["JETBRAINS_JDK21_EXACT"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("environment: jetbrains-marketplace", "environment: missing"),
        ('test -n "$PUBLISH_TOKEN"', "false"),
        ("needs: [authorize, attested-source]\n", "needs: [attested-source]\n"),
        (
            "needs: [authorize, validate, compatibility, attested-source]",
            "needs: [validate, compatibility, attested-source]",
        ),
    ],
)
def test_release_integrity_rejects_jetbrains_authorization_route_bypass(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "jetbrains-marketplace.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_intellij_compatibility_configuration_regression(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    settings = root / "editors" / "intellij" / "settings.gradle.kts"
    settings.write_text(
        settings.read_text(encoding="utf-8").replace(
            'version "2.4.10"', 'version "2.1.20"'
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["INTELLIJ_COMPATIBILITY_DECLARED"]


def test_release_integrity_rejects_missing_repair_scope_confirmation(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    actions = (
        root
        / "editors"
        / "intellij"
        / "src"
        / "main"
        / "kotlin"
        / "app"
        / "factoryline"
        / "intellij"
        / "FactoryLineActions.kt"
    )
    actions.write_text(
        actions.read_text(encoding="utf-8").replace(
            'FactoryLineExecutionConfirmation.confirm(project, "Prepare Repair Scope")',
            "true",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["INTELLIJ_COMPATIBILITY_DECLARED"]


def test_release_integrity_rejects_huggingface_metadata_that_would_fail_remotely(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    readme = root / "deploy" / "huggingface" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "short_description: Audit code, review evidence, and resolve defects.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_METADATA_PREFLIGHT"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('test -n "$HF_TOKEN"', "false"),
        ("HF_TOKEN: ${{ secrets.HF_TOKEN }}", "HF_TOKEN: missing"),
    ],
)
def test_release_integrity_rejects_missing_huggingface_authorization(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "huggingface-space.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_AUTHORIZATION_EARLY"]
    assert result["next_action"]["action"] == "repair_release_workflow"


def test_release_integrity_rejects_late_huggingface_authorization(
    tmp_path: Path,
) -> None:
    root = _workflow_copy(tmp_path)
    workflow = root / ".github" / "workflows" / "huggingface-space.yml"
    content = workflow.read_text(encoding="utf-8")
    authorizer = """      - name: Require Hugging Face token before candidate work
        shell: bash
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          set -euo pipefail
          test -n \"$HF_TOKEN\" || {
            echo \"HF_TOKEN is required before Hugging Face Space candidate work.\" >&2
            exit 1
          }
"""
    assert authorizer in content
    workflow.write_text(
        content.replace(authorizer, "").replace(
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            + authorizer,
            1,
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["HUGGINGFACE_AUTHORIZATION_EARLY"]


def test_release_integrity_rejects_implicit_python_package_data(tmp_path: Path) -> None:
    root = _workflow_copy(tmp_path)
    project = root / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            "include-package-data = false\n", ""
        ),
        encoding="utf-8",
    )

    result = release_integrity(root)

    assert result["ok"] is False
    assert result["failed_check_ids"] == ["PYTHON_PACKAGE_DATA_EXPLICIT"]


def test_release_integrity_cli_is_machine_readable(capsys) -> None:
    assert main(["release", "integrity", "--root", str(ROOT), "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["next_action"]["action"] == "review_external_publish_gates"


def test_release_integrity_text_render_keeps_authority_boundary() -> None:
    text = render_release_integrity(release_integrity(ROOT))

    assert "release integrity: ready for external-gate review" in text
    assert "PASS RELEASE_FAN_IN_EXACT" in text
    assert (
        "authority: no execution, publication, credential, or approval authority"
        in text
    )


@pytest.mark.parametrize(
    "ages,draft,admitted",
    [
        ([9], False, True),
        ([1], False, False),
        ([9, 10, 11, 12], False, False),
        ([0], True, True),
    ],
)
def test_publication_guard_uses_published_timestamps(tmp_path, ages, draft, admitted):
    import os
    import subprocess
    import sys
    from datetime import datetime, timedelta, timezone
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["guard"]["steps"]
        if item.get("name")
        == "Enforce cadence using actual GitHub publication timestamps"
    )
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    now = datetime.now(timezone.utc)
    (tmp_path / "release-train.json").write_text(
        json.dumps(
            {
                "cadence": {
                    "effective_at": (now - timedelta(days=60)).isoformat(),
                    "max_releases_30d": 4,
                    "minimum_days_between_releases": 7,
                }
            }
        )
    )
    history = [
        {
            "draft": draft,
            "created_at": "2000-01-01T00:00:00Z",
            "published_at": None if draft else (now - timedelta(days=age)).isoformat(),
        }
        for age in ages
    ]
    (tmp_path / "release-history.json").write_text(json.dumps([history]))
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is admitted, result.stderr


@pytest.mark.parametrize(
    "channel,tag,valid",
    [
        ("vscode", "vscode-v1.0.2+build.1", True),
        ("jetbrains", "jetbrains-v1.0.2+build.2", True),
        ("vscode", "vscode-v1.0.3+build.1", False),
        ("vscode", "vscode-v1.0.2+build.0", False),
        ("vscode", "vscode-v1.0.2+other.1", False),
        ("core", "v0.47.0+build.1", False),
    ],
)
def test_editor_build_revision_preserves_package_version(channel, tag, valid):
    source = {
        "version": "0.47.0",
        "platform_versions": {"vscode": "1.0.2", "intellij": "1.0.2"},
    }
    if valid:
        candidate._validate_channel_tag(source, channel, tag)
    else:
        with pytest.raises(ValueError, match="candidate tag must match"):
            candidate._validate_channel_tag(source, channel, tag)


def test_release_preflight_cli_writes_machine_receipt(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    source = tmp_path / "factoryline"
    source.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.46.3"\n', encoding="utf-8"
    )
    (source / "__init__.py").write_text('__version__ = "0.46.3"\n', encoding="utf-8")
    monkeypatch.setattr(candidate, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        candidate,
        "verify_release_contract",
        lambda *args: {"ok": True, "marker": "RELEASE_CONTRACT_VALID"},
    )
    monkeypatch.setattr(
        candidate,
        "release_cadence_status",
        lambda _root: {
            "available": True,
            "admission": True,
            "state": "eligible",
            "release_train_status": "valid",
            "reason": "fixture cadence admitted",
        },
    )
    monkeypatch.setattr(
        candidate,
        "evaluate_architecture_health",
        lambda _root, *, strict=False: {
            "decision": "HEALTHY",
            "regressions": [],
            "baseline_debt": [],
        },
    )
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps(
            {
                "schema": "factory.release-contract.v1",
                "feature": "release",
                "candidate": {"source_version": "0.46.3", "source_commit": "a" * 40},
            }
        ),
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "factoryline_code_factory-0.46.3.tar.gz").write_bytes(b"candidate")
    out = tmp_path / ".factory" / "preflight.json"

    assert (
        main(
            [
                "release",
                "preflight",
                "--root",
                str(tmp_path),
                "--contract",
                str(contract),
                "--artifact-dir",
                str(artifacts),
                "--out",
                str(out),
                "--json",
            ]
        )
        == 0
    )
    emitted = json.loads(capsys.readouterr().out)
    written = json.loads(out.read_text(encoding="utf-8"))

    assert emitted["marker"] == "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN"
    assert written["ok"] is True
    assert written["authority"]["publication"] is False
    assert len(written["receipt_sha256"]) == 64


def test_structured_ok_receipt_is_accepted(tmp_path):
    path = tmp_path / "release-preflight.json"
    path.write_text(
        json.dumps(
            {
                "ok": True,
                "schema": "factory.release-candidate-preflight.v1",
                "marker": "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN",
            }
        ),
        encoding="utf-8",
    )
    assert verify_release_preflight(path)["ok"] is True
    assert verify_release_preflight_main([str(path)]) == 0


def test_failed_or_malformed_receipt_is_rejected(tmp_path):
    failed = tmp_path / "failed.json"
    failed.write_text(json.dumps({"ok": False}), encoding="utf-8")
    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    assert verify_release_preflight_main([str(failed)]) == 1
    assert verify_release_preflight_main([str(malformed)]) == 1


@pytest.mark.parametrize(
    ("filename", "tag", "environment"),
    [
        ("openvsx.yml", "vscode-v1.1.4+build.1", "openvsx"),
        ("vscode-marketplace.yml", "vscode-v1.1.4+build.1", "vscode-marketplace"),
        ("jetbrains-marketplace.yml", "jetbrains-v1.1.4", "jetbrains-marketplace"),
    ],
)
def test_editor_exception_receipt_binds_protected_dispatch(
    tmp_path, monkeypatch, filename, tag, environment
):
    import yaml
    from datetime import datetime

    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert (
        triggers["workflow_dispatch"]["inputs"]["cadence_exception_reason"]["default"]
        == ""
    )
    step = next(
        s
        for s in workflow["jobs"]["validate"]["steps"]
        if s.get("name") == "Require the sealed candidate preflight"
    )
    assert any(
        f'test "$RELEASE_REF" = {tag}' in s.get("run", "")
        for s in workflow["jobs"]["validate"]["steps"]
    )
    assert any(
        'test "$GITHUB_ACTOR" = zrk222' in s.get("run", "")
        for s in workflow["jobs"]["validate"]["steps"]
    )
    assert '"${exception_args[@]}"' in step["run"]
    code = step["run"].split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    prepare_step = next(
        s
        for s in workflow["jobs"]["validate"]["steps"]
        if s.get("name") == "Prepare source-bound release contract"
    )
    assert prepare_step["env"]["APPROVED_BY"] == "${{ github.actor }}"
    assert '--approved-by "$APPROVED_BY"' in prepare_step["run"]
    approved_by = prepare_step["env"]["APPROVED_BY"].replace(
        "${{ github.actor }}", "zrk222"
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".factory").mkdir()
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({"approved_by": approved_by}))
    for key, value in {
        "RELEASE_CONTRACT_PATH": str(contract),
        "RELEASE_REF": tag,
        "PUBLISH": "true",
        "EXCEPTION_REASON": "Owner authorized this one release",
        "GITHUB_ACTOR": "zrk222",
        "GITHUB_ACTIONS": "true",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: "a" * 40)
    exec(compile(code, filename, "exec"), {})
    receipt = json.loads(
        (tmp_path / ".factory/release-cadence-exception.json").read_text()
    )
    assert receipt["candidate_tag"] == tag
    assert receipt.get("monthly_cap_exception", False) is (
        environment != "jetbrains-marketplace"
    )
    assert receipt["source_commit"] == "a" * 40
    assert receipt["environment"] == environment
    assert receipt["publish_enabled"] and receipt["environment_authorized"]
    assert (
        datetime.fromisoformat(receipt["expires_at"].replace("Z", "+00:00"))
        - datetime.fromisoformat(receipt["issued_at"].replace("Z", "+00:00"))
    ).total_seconds() == 1800
    from factoryline.release_candidate import (
        _cadence_admission,
        _cadence_exception_payload,
    )

    validated = _cadence_exception_payload(
        tmp_path,
        Path(".factory/release-cadence-exception.json"),
        {
            "version": "0.48.1",
            "commit": "a" * 40,
            "platform_versions": {"vscode": "1.1.4", "intellij": "1.1.4"},
        },
        "vscode" if environment != "jetbrains-marketplace" else "jetbrains",
        tag,
        {"approved_by": approved_by},
    )
    admitted, _, _ = _cadence_admission(
        {
            "release_train_status": "valid",
            "available": True,
            "admission": False,
            "state": "rate_limited",
            "max_releases_30d": 4,
            "recent_count": 5,
            "reason": "Five existing tags exceed the four-tag cap.",
        },
        validated,
    )
    assert admitted is (environment != "jetbrains-marketplace")
    if environment == "openvsx":
        with pytest.raises(ValueError, match="candidate identity"):
            _cadence_exception_payload(
                tmp_path,
                Path(".factory/release-cadence-exception.json"),
                {"commit": "a" * 40, "platform_versions": {"vscode": "1.1.4"}},
                "vscode",
                tag,
                {"approved_by": "other"},
            )
        return
    contract.write_text(json.dumps({"approved_by": "other"}))
    with pytest.raises(AssertionError):
        exec(compile(code, filename, "exec"), {})


def test_vscode_website_upload_defaults_to_no_cli_publication():
    import yaml

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/vscode-marketplace.yml").read_text()
    )
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["workflow_dispatch"]["inputs"]["web_upload"]["default"] is True
    assert "inputs.web_upload != true" in workflow["jobs"]["publish"]["if"]
    assert workflow["jobs"]["authorize"]["environment"] == "vscode-marketplace"
    assert "needs.authorize.result == 'success'" in workflow["jobs"]["validate"]["if"]
