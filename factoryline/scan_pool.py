"""Small, output-preserving accelerators for the static security scan."""

import ast
import hashlib
import multiprocessing
import os
import weakref

_DUMP_DIGESTS = weakref.WeakKeyDictionary()
_FORKED_JOB = None


def ast_dump_digest(node):
    """sha256 of ast.dump(node), computed once per node object; scanner trees are read-only."""
    digest = _DUMP_DIGESTS.get(node) if isinstance(node, ast.AST) else None
    if digest is None:
        try:
            dump = ast.dump(node, include_attributes=False)
            digest = hashlib.sha256(dump.encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            digest = ""
        if isinstance(node, ast.AST):
            _DUMP_DIGESTS[node] = digest
    return digest


def scan_workers(jobs):
    """Forked workers on Linux for four or more files; FACTORY_SCAN_WORKERS overrides the count."""
    if jobs < 4 or os.name != "posix" or os.uname().sysname != "Linux":
        return 1
    try:
        wanted = int(os.environ.get("FACTORY_SCAN_WORKERS", "0"))
    except ValueError:
        wanted = 0
    return max(1, min(wanted if wanted > 0 else min(8, os.cpu_count() or 1), jobs))


def _run_forked(index):
    return _FORKED_JOB(index)


def map_scan_jobs(jobs, scan):
    """Yield (job[0], scan(*job)) in input order; forked children inherit the parsed trees."""
    global _FORKED_JOB
    workers = scan_workers(len(jobs))
    if workers < 2:
        rows = [scan(*job) for job in jobs]
    else:
        _FORKED_JOB = lambda index: scan(*jobs[index])  # noqa: E731
        try:
            with multiprocessing.get_context("fork").Pool(workers) as pool:
                rows = pool.map(_run_forked, range(len(jobs)), chunksize=1)
        finally:
            _FORKED_JOB = None
    return [(job[0], row) for job, row in zip(jobs, rows)]
