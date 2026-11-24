"""Exercise the PR-readiness command and its provider evidence boundaries."""

import json
import subprocess

import pytest

from factoryline import cli
from factoryline.cli_github import (
    GitHubReadinessError,
    github_pr_readiness,
)

HEAD = "a" * 40


def _connection(*items, more=False):
    return {"nodes": list(items), "pageInfo": {"hasNextPage": more}}


def _pull(**changes):
    rollup = {
        "state": "SUCCESS",
        "contexts": _connection(
            {"name": "unit", "status": "COMPLETED", "conclusion": "SUCCESS"}
        ),
    }
    return {
        "state": "OPEN",
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "CLEAN",
        "reviewDecision": "APPROVED",
        "headRefOid": HEAD,
        "commits": _connection({"commit": {"oid": HEAD, "statusCheckRollup": rollup}}),
        "reviewThreads": _connection(),
        **changes,
    }


def _rollup(pull):
    return pull["commits"]["nodes"][0]["commit"]["statusCheckRollup"]


@pytest.fixture
def provider(tmp_path, monkeypatch):
    monkeypatch.setattr("factoryline.cli_github.shutil.which", lambda _: "gh")
    commands = []

    def read(pull, *, error=None, timed_out=False):
        def run(command, cwd, timeout):
            commands.append(command)
            assert cwd == tmp_path.resolve()
            if command[0] == "git":
                return subprocess.CompletedProcess(
                    command, 0, "https://github.com/example/project.git\n", ""
                )
            if timed_out:
                raise subprocess.TimeoutExpired(command, timeout)
            if error:
                return subprocess.CompletedProcess(command, 1, "", error)
            data = {"data": {"repository": {"pullRequest": pull}}}
            return subprocess.CompletedProcess(command, 0, json.dumps(data), "")

        return run

    return read, commands


def test_current_head_passes_with_one_query_and_no_write(tmp_path, provider):
    read, commands = provider
    result = github_pr_readiness(tmp_path, 5, expected_head=HEAD, runner=read(_pull()))
    assert result["head_sha"] == HEAD
    assert result["state"] == "NO_OBSERVED_BLOCKERS"
    assert result["checks"]["items"][0]["name"] == "unit"
    assert not any(result["authority"].values())
    assert len(commands) == 2  # origin read plus one provider request
    assert "number=5" in commands[1]
    assert "owner=example" in commands[1]
    query = next(arg for arg in commands[1] if arg.startswith("query="))
    assert query.split("=", 1)[1].lstrip().startswith("query Readiness")
    assert "mutation" not in query
    assert "body" not in query


def test_prioritizes_conflicts_then_unresolved_threads_and_ci(tmp_path, provider):
    read, _ = provider
    thread = {
        "id": "thread-1",
        "isOutdated": True,
        "path": "app.py",
        "line": None,
        "isResolved": False,
    }
    pull = _pull(
        mergeable="CONFLICTING",
        mergeStateStatus="DIRTY",
        reviewDecision="REVIEW_REQUIRED",
        reviewThreads=_connection(thread, {**thread, "isResolved": True}),
    )
    _rollup(pull)["state"] = "FAILURE"
    result = github_pr_readiness(tmp_path, 5, runner=read(pull))
    assert result["blockers"] == [
        "MERGE_CONFLICT",
        "REVIEW_THREADS_OPEN",
        "CHECKS_FAILED",
        "REVIEW_REQUIRED",
    ]
    assert result["review_threads"]["unresolved"] == [
        {key: value for key, value in thread.items() if key != "isResolved"}
    ]
    assert result["next_action"].startswith("Resolve")


@pytest.mark.parametrize(
    "issue,expected",
    [
        ("thread_page", "REVIEW_THREADS_TRUNCATED"),
        ("check_page", "CHECKS_TRUNCATED"),
        ("no_checks", "CHECKS_UNREPORTED"),
        ("unknown_merge", "MERGE_STATE_UNKNOWN"),
    ],
)
def test_incomplete_read_cannot_look_clear(tmp_path, provider, issue, expected):
    read, _ = provider
    pull = _pull()
    if issue == "thread_page":
        pull["reviewThreads"] = _connection(more=True)
    elif issue == "check_page":
        _rollup(pull)["contexts"]["pageInfo"]["hasNextPage"] = True
    elif issue == "no_checks":
        pull["commits"]["nodes"][0]["commit"]["statusCheckRollup"] = None
    else:
        pull["mergeable"] = "UNKNOWN"
    result = github_pr_readiness(tmp_path, 5, runner=read(pull))
    assert result["state"] == "INCOMPLETE"
    assert result["blockers"] == [expected]


def test_closed_pr_reports_terminal_state(tmp_path, provider):
    read, _ = provider
    result = github_pr_readiness(
        tmp_path, 5, runner=read(_pull(state="MERGED", isDraft=True))
    )
    assert result["pr_state"] == "MERGED"
    assert result["blockers"] == ["PR_NOT_OPEN"]


@pytest.mark.parametrize("different", ["actual", "expected"])
def test_head_drift_rejects_snapshot(tmp_path, provider, different):
    read, _ = provider
    pull = _pull(**({"headRefOid": "b" * 40} if different == "actual" else {}))
    expected = "c" * 40 if different == "expected" else None
    with pytest.raises(GitHubReadinessError, match="expected PR head") as raised:
        github_pr_readiness(tmp_path, 5, expected_head=expected, runner=read(pull))
    assert raised.value.code == "GH_HEAD_MISMATCH"


@pytest.mark.parametrize(
    "options", [{"error": "HTTP 403 private provider detail"}, {"timed_out": True}]
)
def test_provider_failures_are_bounded_and_redacted(tmp_path, provider, options):
    read, _ = provider
    with pytest.raises(GitHubReadinessError) as raised:
        github_pr_readiness(tmp_path, 5, runner=read(_pull(), **options))
    assert raised.value.code == "GH_READ_FAILED"
    assert "private provider detail" not in str(raised.value)


def test_failed_required_snapshot_exits_three(tmp_path, monkeypatch, capsys, provider):
    read, _ = provider
    monkeypatch.setattr(
        "factoryline.github_account_overview._default_runner", read(_pull(isDraft=True))
    )
    assert (
        cli.main(
            [
                "github",
                "pr-readiness",
                "5",
                "--root",
                str(tmp_path),
                "--require-clear",
                "--json",
            ]
        )
        == 3
    )
    assert json.loads(capsys.readouterr().out)["blockers"] == ["PR_DRAFT"]
