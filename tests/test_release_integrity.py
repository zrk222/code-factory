"""Execute the protected publication cadence snippets without external effects."""

import json
import copy
import hashlib
import io
import subprocess
import textwrap
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from factoryline import release_candidate as candidate


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml"


def _snippet(marker):
    text = WORKFLOW.read_text(encoding="utf-8")
    section = text.split(marker, 1)[1]
    return textwrap.dedent(
        section.split("<<'PY'\n", 1)[1].split("\n          PY", 1)[0]
    )


@pytest.mark.parametrize(
    "tag,actor,opt_in,accepted",
    [
        ("v0.49.5", "zrk222", "true", True),
        ("v0.49.5", "zrk222", "false", False),
        ("v0.49.5", "other-user", "true", False),
        ("v0.49.6", "zrk222", "true", False),
        ("v0.49.4", "zrk222", "true", False),
    ],
)
@pytest.mark.parametrize("recent_count", [1, 4])
def test_publish_0495_guard_keeps_cooldown_cap_and_exact_owner(
    tmp_path, monkeypatch, tag, actor, opt_in, accepted, recent_count
):
    monkeypatch.chdir(tmp_path)
    now = datetime.now(timezone.utc)
    Path("release-train.json").write_text(
        json.dumps(
            {
                "cadence": {
                    "effective_at": (now - timedelta(days=31)).isoformat(),
                    "max_releases_30d": 4,
                    "minimum_days_between_releases": 7,
                }
            }
        )
    )
    Path("release-history.json").write_text(
        json.dumps(
            [
                [
                    {
                        "draft": False,
                        "published_at": (now - timedelta(days=1)).isoformat(),
                    }
                ]
                * recent_count
            ]
        )
    )
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "RELEASE_TAG": tag,
        "GITHUB_ACTOR": actor,
        "CORE_0481_EXCEPTION": "false",
        "CORE_0482_EXCEPTION": "false",
        "CORE_0495_EXCEPTION": opt_in,
    }.items():
        monkeypatch.setenv(key, value)
    code = _snippet(
        "- name: Enforce cadence using actual GitHub publication timestamps"
    )
    if accepted:
        exec(compile(code, str(WORKFLOW), "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(code, str(WORKFLOW), "exec"), {})


def test_publish_0495_protected_exception_round_trips_exact_source_run(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    Path(".factory").mkdir()
    Path("contract.json").write_text(json.dumps({"approved_by": "zrk222"}))
    Path("release-train.json").write_text(
        json.dumps({"cadence": {"exceptions_enabled": False}})
    )
    for key, value in {
        "RELEASE_CONTRACT_PATH": "contract.json",
        "RELEASE_TAG": "v0.49.5",
        "GITHUB_ACTOR": "zrk222",
        "GITHUB_ACTIONS": "true",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "CORE_0481_EXCEPTION": "false",
        "CORE_0482_EXCEPTION": "false",
        "CORE_0495_EXCEPTION": "true",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: "a" * 40)
    code = _snippet(
        "- name: Require sealed release candidate preflight before external publication"
    )
    exec(compile(code, str(WORKFLOW), "exec"), {})
    path = Path(".factory/core-0495-cadence-exception.json")
    result = candidate._cadence_exception_payload(
        tmp_path,
        path,
        {"version": "0.49.5", "commit": "a" * 40},
        "core",
        "v0.49.5",
        {"approved_by": "zrk222"},
    )
    assert result["monthly_cap_exception"] is True
    assert result["one_time_version_opt_in"] == "0.49.5"
    assert result["workflow_run_attempt"] == "2"
    assert result["source_commit"] == "a" * 40
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        '"$RELEASE_TAG" == "v0.49.5" ]]; then source_args=(--source CHANGELOG.md)'
        in text
    )
    assert "signed_receipts fetch-ci" in text
    assert "environment: pypi" in text
    assert (
        "default: false"
        in text.split("core_0495_cadence_exception:", 1)[1].split("permissions:", 1)[0]
    )


@pytest.fixture
def reuse_api(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run_id, commit = "41191118611", "a" * 40
    now = datetime.now(timezone.utc)
    started = (now - timedelta(hours=1)).isoformat()
    created = (now - timedelta(minutes=45)).isoformat()
    completed = (now - timedelta(minutes=30)).isoformat()
    run = {
        "id": int(run_id),
        "run_attempt": 1,
        "head_sha": commit,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ".github/workflows/publish.yml",
        "status": "completed",
        "repository": {"full_name": "owner/repo", "id": 123},
        "head_repository": {"full_name": "owner/repo", "id": 123},
    }
    names = [
        "require a draft release tag",
        "validate Python release artifacts",
        "validate VS Code release artifact",
        "validate JetBrains release artifact",
    ]
    jobs = [
        {
            "id": index + 1,
            "name": name,
            "run_id": int(run_id),
            "run_attempt": 1,
            "head_sha": commit,
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
            "started_at": started,
            "completed_at": completed,
        }
        for index, name in enumerate(names)
    ]
    artifacts = [
        {
            "id": index + 100,
            "name": f"release-{channel}-v0.49.5",
            "size_in_bytes": 100,
            "expired": False,
            "digest": "sha256:" + "b" * 64,
            "created_at": created,
            "expires_at": (now + timedelta(days=1)).isoformat(),
            "workflow_run": {
                "id": int(run_id),
                "head_sha": commit,
                "head_branch": "main",
                "repository_id": 123,
                "head_repository_id": 123,
            },
        }
        for index, channel in enumerate(("python", "vscode", "intellij"))
    ]
    data = {
        "run": run,
        "jobs": [{"total_count": 4, "jobs": jobs}],
        "artifacts": [{"total_count": 3, "artifacts": artifacts}],
    }
    for key, value in {
        "GITHUB_REPOSITORY": "owner/repo",
        "VALIDATED_RUN_ID": run_id,
        "CANDIDATE_COMMIT": commit,
        "RELEASE_TAG": "v0.49.5",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
    }.items():
        monkeypatch.setenv(key, value)

    def api(argv, **kwargs):
        assert argv[:2] == ["gh", "api"]
        endpoint = argv[-1]
        key = (
            "jobs"
            if "/jobs?" in endpoint
            else "artifacts"
            if "/artifacts?" in endpoint
            else "run"
        )
        return json.dumps(data[key])

    monkeypatch.setattr(subprocess, "check_output", api)
    return data


def test_exact_green_validation_run_can_be_reused(reuse_api, tmp_path):
    exec(_snippet("- name: Verify exact prior validation producers before reuse"), {})
    outputs = dict(
        line.split("=", 1) for line in (tmp_path / "outputs").read_text().splitlines()
    )
    assert outputs["run_id"] == "41191118611"
    receipt = json.loads(outputs["receipt"])
    digest = receipt.pop("receipt_sha256")
    assert (
        digest
        == hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert len(receipt["jobs"]) == 4
    assert len(receipt["artifacts"]) == 3
    assert receipt["source_commit"] == "a" * 40


@pytest.mark.parametrize(
    "fault",
    [
        "repository",
        "head-repository",
        "source",
        "branch",
        "event",
        "workflow",
        "status",
        "attempt",
        "failed-job",
        "running-job",
        "job-source",
        "job-attempt",
        "missing-job",
        "duplicate-job",
        "duplicate-job-id",
        "missing-artifact",
        "duplicate-artifact",
        "duplicate-artifact-id",
        "expired",
        "expires-at",
        "digest",
        "empty",
        "oversize",
        "artifact-source",
        "artifact-run",
        "before-producer",
        "after-producer",
        "jobs-pagination",
        "artifacts-pagination",
    ],
)
def test_reuse_rejects_unbound_or_incomplete_producers(reuse_api, fault):
    jobs, artifacts = (
        reuse_api["jobs"][0]["jobs"],
        reuse_api["artifacts"][0]["artifacts"],
    )
    changes = {
        "repository": (("run", "repository", "full_name"), "other/repo"),
        "head-repository": (("run", "head_repository", "full_name"), "fork/repo"),
        "source": (("run", "head_sha"), "c" * 40),
        "branch": (("run", "head_branch"), "feature"),
        "event": (("run", "event"), "pull_request"),
        "workflow": (("run", "path"), ".github/workflows/other.yml"),
        "status": (("run", "status"), "in_progress"),
        "attempt": (("run", "run_attempt"), 0),
        "failed-job": (("jobs", 0, "jobs", 1, "conclusion"), "failure"),
        "running-job": (("jobs", 0, "jobs", 1, "status"), "in_progress"),
        "job-source": (("jobs", 0, "jobs", 1, "head_sha"), "c" * 40),
        "job-attempt": (("jobs", 0, "jobs", 1, "run_attempt"), 2),
        "missing-job": (("jobs", 0, "jobs", 1, "name"), "missing"),
        "duplicate-job": (("jobs",), [{"total_count": 5, "jobs": [*jobs, jobs[1]]}]),
        "duplicate-job-id": (("jobs", 0, "jobs", 1, "id"), jobs[0]["id"]),
        "missing-artifact": (("artifacts", 0, "artifacts", 0, "name"), "missing"),
        "duplicate-artifact": (
            ("artifacts",),
            [{"total_count": 4, "artifacts": [*artifacts, artifacts[0]]}],
        ),
        "duplicate-artifact-id": (
            ("artifacts", 0, "artifacts", 1, "id"),
            artifacts[0]["id"],
        ),
        "expired": (("artifacts", 0, "artifacts", 0, "expired"), True),
        "expires-at": (
            ("artifacts", 0, "artifacts", 0, "expires_at"),
            "2000-01-01T00:00:00Z",
        ),
        "digest": (("artifacts", 0, "artifacts", 0, "digest"), ""),
        "empty": (("artifacts", 0, "artifacts", 0, "size_in_bytes"), 0),
        "oversize": (
            ("artifacts", 0, "artifacts", 0, "size_in_bytes"),
            512 * 1024 * 1024 + 1,
        ),
        "artifact-source": (
            ("artifacts", 0, "artifacts", 0, "workflow_run", "head_sha"),
            "c" * 40,
        ),
        "artifact-run": (("artifacts", 0, "artifacts", 0, "workflow_run", "id"), 999),
        "before-producer": (
            ("artifacts", 0, "artifacts", 0, "created_at"),
            "2000-01-01T00:00:00Z",
        ),
        "after-producer": (
            ("artifacts", 0, "artifacts", 0, "created_at"),
            "2099-01-01T00:00:00Z",
        ),
        "jobs-pagination": (("jobs", 0, "total_count"), 100),
        "artifacts-pagination": (("artifacts", 0, "total_count"), 100),
    }
    route, replacement = changes[fault]
    target = reuse_api
    for key in route[:-1]:
        target = target[key]
    target[route[-1]] = copy.deepcopy(replacement)
    with pytest.raises(SystemExit):
        exec(
            _snippet("- name: Verify exact prior validation producers before reuse"), {}
        )


@pytest.mark.parametrize("run_id", ["", "0", "1;exit", "../1", "-1", "123\n456"])
def test_reuse_rejects_invalid_run_id_before_api(reuse_api, monkeypatch, run_id):
    monkeypatch.setenv("VALIDATED_RUN_ID", run_id)
    monkeypatch.setattr(
        subprocess,
        "check_output",
        lambda *args, **kwargs: pytest.fail("API must not run"),
    )
    with pytest.raises(SystemExit):
        exec(
            _snippet("- name: Verify exact prior validation producers before reuse"), {}
        )


def test_reuse_wiring_preserves_protected_normal_and_isolated_recovery_paths():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for name in ("validate_python", "validate_vscode", "validate_intellij"):
        assert (
            jobs[name]["if"] == "${{ needs.guard.outputs.verified_reuse_run_id == '' }}"
        )
    publisher = jobs["publish"]
    assert publisher["environment"] == "pypi"
    assert (
        "!cancelled()" in publisher["if"]
        and "needs.guard.result == 'success'" in publisher["if"]
    )
    assert all(
        f"needs.{name}.result == 'success'" in publisher["if"]
        for name in ("validate_python", "validate_vscode", "validate_intellij")
    )
    downloads = [
        step
        for step in publisher["steps"]
        if "actions/download-artifact@" in step.get("uses", "")
    ]
    assert len(downloads) == 3
    assert all(
        step["with"]["run-id"]
        == "${{ needs.guard.outputs.verified_reuse_run_id || github.run_id }}"
        and step["with"]["github-token"] == "${{ github.token }}"
        for step in downloads
    )
    scripts = "\n".join(step.get("run", "") for step in publisher["steps"])
    assert 'git merge-base --is-ancestor "$TOOLING_SHA" origin/main' in scripts
    assert 'git archive "$TOOLING_SHA"' in scripts
    assert "python -m pip install ." in scripts
    assert "python -I -m factoryline.cli release preflight" in scripts
    assert "python -m factoryline.cli release preflight" in scripts
    assert "--metadata-path context/PROGRESS.md" in scripts
    assert scripts.index("Downloaded artifact files differ") < scripts.index(
        "preflight_args=("
    )


@pytest.fixture
def recovery_bytes(tmp_path, monkeypatch):
    from factoryline import codex_metadata

    workspace = tmp_path / "candidate"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    runner = tmp_path / "runner"
    tooling = runner / "release-tooling/factoryline/codex_metadata.py"
    tooling.parent.mkdir(parents=True)
    tooling.write_bytes(b"pinned checker source")
    installed = tmp_path / "installed/codex_metadata.py"
    installed.parent.mkdir()
    installed.write_bytes(tooling.read_bytes())
    monkeypatch.setattr(codex_metadata, "__file__", str(installed))
    receipt = {"repository": "owner/repo", "source_commit": "a" * 40, "artifacts": []}
    archives, metadata = {}, {}
    for index, (channel, name) in enumerate(
        (("python", "core.whl"), ("vscode", "editor.vsix"), ("intellij", "idea.zip"))
    ):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as bundle:
            bundle.writestr(name, b"validated package bytes")
        archives[index] = raw.getvalue()
        artifact = {
            "id": index,
            "name": channel,
            "channel": channel,
            "digest": "sha256:" + hashlib.sha256(archives[index]).hexdigest(),
            "size_in_bytes": len(archives[index]),
            "created_at": "created",
            "expires_at": "expires",
        }
        receipt["artifacts"].append(artifact)
        metadata[index] = {**artifact, "expired": False}
        destination = (
            workspace
            / "release-bundle"
            / ("python" if channel == "python" else "editors")
            / name
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"validated package bytes")
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for key, value in {
        "REUSE_RECEIPT": json.dumps(receipt),
        "CANDIDATE_COMMIT": "a" * 40,
        "GITHUB_REPOSITORY": "owner/repo",
        "RUNNER_TEMP": str(runner),
        "TOOLING_SHA": "c" * 40,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        subprocess,
        "check_output",
        lambda argv, **kwargs: json.dumps(metadata[int(argv[-1].rsplit("/", 1)[1])]),
    )

    def download(argv, *, stdout, check):
        assert check is True and argv[:2] == ["gh", "api"]
        stdout.write(archives[int(argv[-1].split("/")[-2])])

    monkeypatch.setattr(subprocess, "run", download)
    return workspace, installed, archives, metadata


@pytest.mark.parametrize(
    "fault", [None, "archive", "file", "tooling", "extra", "live-metadata", "expanded"]
)
def test_recovery_checks_actual_bytes_and_isolated_tooling(
    recovery_bytes, monkeypatch, fault
):
    workspace, installed, archives, metadata = recovery_bytes
    if fault == "archive":
        archives[0] = b"changed archive bytes"
    elif fault == "file":
        (workspace / "release-bundle/python/core.whl").write_bytes(
            b"changed file bytes"
        )
    elif fault == "tooling":
        installed.write_bytes(b"wrong checker")
    elif fault == "extra":
        (workspace / "release-bundle/python/extra.whl").write_bytes(b"unaccounted")
    elif fault == "live-metadata":
        metadata[0]["digest"] = "sha256:" + "f" * 64
    elif fault == "expanded":
        original = zipfile.ZipFile.infolist

        def oversized(bundle):
            rows = original(bundle)
            rows[0].file_size = 128 * 1024 * 1024 + 1
            return rows

        monkeypatch.setattr(zipfile.ZipFile, "infolist", oversized)
    code = _snippet(
        "- name: Bind recovered artifact bytes and installed tooling before preflight"
    )
    if fault is not None:
        with pytest.raises(SystemExit):
            exec(code, {})
    else:
        exec(code, {})
        receipt = json.loads(
            (workspace / "release-bundle/release-recovery.json").read_text()
        )
        assert receipt["tooling_commit"] == "c" * 40
        assert receipt["archive_bytes_and_extracted_files_verified"] is True
        assert (
            receipt["installed_metadata_sha256"]
            == hashlib.sha256(installed.read_bytes()).hexdigest()
        )
