"""Validate ordering and real worker supervision for exposed precision replay."""

from contextlib import closing
from pathlib import Path
import subprocess
import sys
from threading import Event, get_ident
from time import monotonic
from unittest.mock import patch

import pytest

from scripts.precision_ranked_execution import (
    ordered_native_results,
    run_native_command,
)


def test_idle_slot_refills_before_earlier_scan_finishes():
    third_started = Event()
    owner = get_ident()

    def prepared():
        for rank in range(1, 7):
            assert get_ident() == owner
            yield rank, rank

    def native(rank):
        if rank == 1:
            assert third_started.wait(5), "free slot did not refill"
        elif rank == 3:
            third_started.set()
        return f"receipt-{rank}"

    assert list(ordered_native_results(prepared(), native)) == [
        (rank, f"receipt-{rank}") for rank in range(1, 7)
    ]


@pytest.mark.parametrize("bad_rank", [1, 3])
def test_missing_or_duplicate_rank_never_reaches_native(bad_rank):
    launched = []
    with pytest.raises(ValueError, match="NATIVE_RANK_GAP_OR_DUPLICATE"):
        list(ordered_native_results([(1, "first"), (bad_rank, "bad")], launched.append))
    assert launched == ["first"]


def test_close_does_not_consume_remainder_of_frame():
    prepared = []

    def frame():
        for rank in range(1, 100):
            prepared.append(rank)
            yield rank, rank

    with closing(ordered_native_results(frame(), lambda rank: rank)) as results:
        assert next(results) == (1, 1)
        prepared_at_stop = prepared.copy()
    assert prepared == prepared_at_stop
    assert len(prepared) <= 4


def test_native_deadline_is_enforced_while_next_capture_waits():
    timed_out = Event()

    def prepared():
        yield 1, True
        assert timed_out.wait(5), "native deadline depends on capture finishing"
        yield 2, False

    def native(should_timeout):
        if should_timeout:
            with pytest.raises(subprocess.TimeoutExpired):
                run_native_command(
                    [sys.executable, "-B", "-c", "from time import sleep; sleep(30)"],
                    cwd=Path.cwd(),
                    deadline=monotonic() + 5,
                    timeout=0.2,
                    kill_grace=2,
                )
            timed_out.set()
        return "incomplete" if should_timeout else "complete"

    assert list(ordered_native_results(prepared(), native)) == [
        (1, "incomplete"),
        (2, "complete"),
    ]


def test_short_invocation_window_does_not_spawn():
    with patch("scripts.precision_ranked_execution.subprocess.Popen") as spawn:
        with pytest.raises(TimeoutError, match="INVOCATION_LIMIT_NO_NATIVE_LAUNCH"):
            run_native_command(
                ["unused"],
                cwd=Path.cwd(),
                deadline=monotonic(),
                timeout=1,
                kill_grace=1,
            )
    spawn.assert_not_called()


def test_spawn_time_counts_toward_case_deadline():
    module = "scripts.precision_ranked_execution"
    with (
        patch(f"{module}.monotonic", side_effect=[10, 12]),
        patch(f"{module}.subprocess.Popen") as spawn,
    ):
        child = spawn.return_value
        child.poll.return_value = None
        with pytest.raises(subprocess.TimeoutExpired):
            run_native_command(
                ["unused"], cwd=Path.cwd(), deadline=100, timeout=1, kill_grace=1
            )
    child.kill.assert_called_once()
    child.wait.assert_called_once_with(timeout=1)
    assert child.wait.call_count == 1


def test_kill_grace_exhaustion_never_waits_without_a_deadline():
    module = "scripts.precision_ranked_execution"
    command = ["unused"]
    with (
        patch(f"{module}.monotonic", side_effect=[10, 10]),
        patch(f"{module}.subprocess.Popen") as spawn,
    ):
        child = spawn.return_value
        child.poll.return_value = None
        child.wait.side_effect = [
            subprocess.TimeoutExpired(command, 1),
            subprocess.TimeoutExpired(command, 2),
        ]
        with pytest.raises(subprocess.TimeoutExpired):
            run_native_command(
                command, cwd=Path.cwd(), deadline=100, timeout=1, kill_grace=2
            )
    assert [call.kwargs["timeout"] for call in child.wait.call_args_list] == [1, 2]
    child.__exit__.assert_not_called()


def test_declared_frame_cannot_end_early():
    with pytest.raises(ValueError, match="NATIVE_RANK_FRONTIER_INCOMPLETE"):
        list(ordered_native_results([(1, "complete")], str, last_rank=2))
