"""Bounded native execution for precision studies; selection remains rank ordered."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from math import isfinite
import subprocess
from time import monotonic


def ordered_native_results(prepared, invoke, *, first_rank=1, last_rank=None):
    """Prepare on the owner thread; launch at most two calls with one lookahead.

    The input must include every rank, including exclusions or earlier receipts.
    A consumer may close the iterator once its terminal prefix is sufficient.
    Closing drains already dispatched work without dispatching the staged item.
    """
    source = iter(prepared)
    next_input = next_output = first_rank
    active, ready = {}, {}
    staged, exhausted = None, False
    with ThreadPoolExecutor(max_workers=2) as pool:
        while active or ready or staged is not None or not exhausted:
            for future in tuple(active):
                if future.done():
                    ready[active.pop(future)] = future
            if next_output in ready:
                yield next_output, ready.pop(next_output).result()
                next_output += 1
            elif staged is not None and len(active) < 2:
                rank, job = staged
                active[pool.submit(invoke, job)] = rank
                staged = None
            elif staged is None and not exhausted and len(active) + len(ready) < 4:
                staged = _read_rank(source, next_input, last_rank)
                exhausted = staged is None
                next_input += not exhausted
            elif active:
                wait(active, return_when=FIRST_COMPLETED)
            else:
                raise ValueError("NATIVE_RANK_FRONTIER_INCOMPLETE")
    if last_rank is not None and next_output != last_rank + 1:
        raise ValueError("NATIVE_RANK_FRONTIER_INCOMPLETE")


def _read_rank(source, expected, last_rank):
    try:
        item = next(source)
    except StopIteration:
        return None
    if (
        not isinstance(item, tuple)
        or len(item) != 2
        or item[0] != expected
        or (last_rank is not None and expected > last_rank)
    ):
        raise ValueError("NATIVE_RANK_GAP_OR_DUPLICATE")
    return item


def run_native_command(
    command, *, cwd, deadline, timeout, kill_grace, stdout=subprocess.DEVNULL
):
    """Supervise a native child independently of capture, including spawn time."""
    if not isfinite(deadline) or not all(
        isfinite(value) and value > 0 for value in (timeout, kill_grace)
    ):
        raise ValueError("NATIVE_TIME_BUDGET_INVALID")
    started = monotonic()
    if deadline - started < timeout:
        raise TimeoutError("INVOCATION_LIMIT_NO_NATIVE_LAUNCH")
    child = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.DEVNULL,
    )
    try:
        remaining = started + timeout - monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        return child.wait(timeout=remaining)
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=kill_grace)
        raise
