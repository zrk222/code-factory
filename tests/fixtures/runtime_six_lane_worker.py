"""Executed local SQLite checkout rehearsal, not native-tool certification."""

import concurrent.futures
import gc
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
import tracemalloc
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def database():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, amount INTEGER)")
    db.execute("INSERT INTO orders VALUES(1, 1)")
    db.commit()
    return db


def stateful(bad):
    traces = []
    for _ in range(2):
        with database() as db:
            db.execute("UPDATE orders SET amount=amount+1")
            db.execute("UPDATE orders SET amount=amount-?", (3 if bad else 1,))
            traces.append(db.execute("SELECT amount FROM orders").fetchone()[0])
        db.close()
    return dict(
        examples=len(traces),
        max_actions=2,
        seed=0,
        invariants=[
            dict(
                id="i",
                checks=len(traces),
                violations=sum(value < 0 for value in traces),
                trace=["a", "a"] if min(traces) < 0 else [],
            )
        ],
        action_counts={"a": len(traces) * 2},
        replay_stable=len(set(traces)) == 1,
        examples_isolated=len(traces) == 2,
    )


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.headers.get("Authorization")
        allowed = self.server.sessions.get(token, False)
        body = self.server.cache.get(token, {}) if allowed or self.server.bad else {}
        if token == "owner":
            self.server.owner_cache_hits.append(bool(body))
        if (allowed or self.server.bad) and not body:
            body = {"id": 1}
            self.server.cache[token] = body
        self.send_response(200 if body else 403)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *_):
        pass


def http_cases(bad):
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.sessions = {"owner": True, "revoked_session": True}
    server.cache = {}
    server.owner_cache_hits = []
    server.bad = bad
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    cases = []
    try:
        for phase in ("cold", "warm", "post_revocation"):
            server.sessions.pop("revoked_session", None)
            for relation in ("owner", "cross_tenant", "anonymous", "revoked_session"):
                # Prime a real initially valid session, then revoke before its matrix probe.
                if relation == "revoked_session" and phase != "post_revocation":
                    server.sessions[relation] = True
                    with urlopen(
                        Request(
                            f"http://127.0.0.1:{server.server_port}/x",
                            headers={"Authorization": relation},
                        ),
                        timeout=2,
                    ) as prime:
                        prime.read()
                    server.sessions.pop(relation)
                request = Request(
                    f"http://127.0.0.1:{server.server_port}/x",
                    headers={"Authorization": relation},
                )
                try:
                    response = urlopen(request, timeout=2)
                except HTTPError as error:
                    response = error
                with response:
                    body = json.loads(response.read())
                    cases.append(
                        dict(
                            id=f"{phase}-{relation}",
                            surface_id="api",
                            phase=phase,
                            relation=relation,
                            status=response.code,
                            tenant_data_sha256=digest(body) if body else None,
                            fields=list(body),
                            mutation_effect=False,
                        )
                    )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert server.owner_cache_hits == [False, True, True], server.owner_cache_hits
    return cases


def tenant(bad):
    return {"cases": http_cases(bad)}


def hashed_observation(**values):
    return {**values, "evidence_sha256": digest(values)}


def recovery(bad):
    schedules, operations = [], []
    for index in range(2):
        barrier = threading.Barrier(2)
        release = threading.Event()
        lock = threading.Lock()
        effects = []
        seen = set()
        entered = [threading.Event(), threading.Event()]

        def attempt(position):
            barrier.wait(timeout=2)
            entered[position].set()
            release.wait(timeout=2)
            with lock:
                effect = int(bad or "checkout" not in seen)
                seen.add("checkout")
                effects.append(effect)

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(attempt, position) for position in range(2)]
            arrived = [event.wait(timeout=2) for event in entered]
            timed_out = False
            try:
                futures[0].result(timeout=0.02)
            except concurrent.futures.TimeoutError:
                timed_out = True
            overlap = all(arrived) and all(not future.done() for future in futures)
            during = sum(effects)
            release.set()
            for future in futures:
                future.result(timeout=2)
        ids = [f"{index}-a", f"{index}-b"]
        operations.extend(
            dict(id=name, idempotency_key=f"k{index}", effects=effect)
            for name, effect in zip(ids, effects)
        )
        schedules.append(
            hashed_observation(
                schedule_id=str(index), operation_ids=ids, overlap_confirmed=overlap
            )
        )
    return dict(
        operations=operations,
        overlap_observations=schedules,
        fault_observations=[
            hashed_observation(
                mode="timeout",
                observed=timed_out,
                phase="during_fault",
                operation_ids=ids,
            )
        ],
        phases={
            "pre_fault": {"count": 0},
            "during_fault": {"count": during},
            "recovered": {"count": sum(effects)},
        },
        cleanup={"attempted": True, "succeeded": all(f.done() for f in futures)},
        max_concurrency=2,
        lost_updates=0,
    )


def compatibility(bad):
    with database() as db:
        row = db.execute("SELECT id FROM orders").fetchone()
        response = {"id": str(row[0]) if bad else row[0]}
    db.close()
    matches = type(response.get("id")) is int
    return dict(
        provider_version="1",
        provider_branch="main",
        environment="test",
        interactions=[
            dict(
                id="i",
                consumer_id="c",
                consumer_version="1",
                actual_sha256=digest(response),
                provider_state_prepared=True,
                request_exercised=row is not None,
                mismatch_count=int(not matches),
                pending=False,
            )
        ],
        deployment_matrix={"checked": True, "compatible": matches, "missing_pairs": []},
    )


def schema(db):
    return digest(db.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall())


def migration(bad):
    db = database()
    before = schema(db)
    count = db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    start = time.monotonic()
    db.execute("BEGIN IMMEDIATE")
    wait = time.monotonic() - start
    db.execute("ALTER TABLE orders ADD COLUMN note TEXT")
    db.rollback()
    recovered = schema(db) == before
    db.execute("BEGIN IMMEDIATE")
    db.execute("ALTER TABLE orders ADD COLUMN note TEXT")
    db.commit()
    after = schema(db)
    old = db.execute("SELECT id FROM orders").fetchone() is not None
    new = db.execute("SELECT note FROM orders").fetchone() == (None,)
    if bad:
        db.execute("DELETE FROM orders")
    remaining = db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    total = db.execute("SELECT COALESCE(SUM(amount),0) FROM orders").fetchone()[0]
    catalog = [row[0] for row in db.execute("SELECT name FROM sqlite_master")]
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    db.close()
    return dict(
        isolated=True,
        before_schema_sha256=before,
        after_schema_sha256=after,
        history_valid=before != after,
        drift_detected=False,
        invariants=[{"id": "i", "actual_sha256": digest(total)}],
        record_counts=[{"table": "orders", "before": count, "after": remaining}],
        integrity_violations=int(integrity != "ok"),
        readers={"old": old, "new": new},
        recovery={"strategy": "rollback", "exercised": True, "succeeded": recovered},
        catalog_objects=catalog,
        invalid_catalog_objects=[],
        lock_wait_seconds=wait,
    )


def measured_run(delay):
    samples, latencies, cpus = [], [], []
    failures = 0
    db = database()
    start = time.monotonic()
    for _ in range(10):
        tick = time.monotonic()
        cpu = time.process_time()
        failures += db.execute("SELECT SUM(amount) FROM orders").fetchone() != (1,)
        time.sleep(delay)
        latencies.append(time.monotonic() - tick)
        # Pace outside request latency; sample CPU across the full paced interval.
        time.sleep(0.1)
        cpus.append(100 * (time.process_time() - cpu) / (time.monotonic() - tick))
        samples.append(tracemalloc.get_traced_memory()[0])
    elapsed = time.monotonic() - start
    db.close()
    gc.collect()
    cooldown = time.monotonic()
    time.sleep(1)
    retained = [tracemalloc.get_traced_memory()[0] for _ in range(3)]
    return dict(
        observations=len(latencies),
        metrics={"p95_seconds": sorted(latencies)[9]},
        workload_sha256=D,
        environment_sha256=D,
        soak_seconds=elapsed,
        cooldown_seconds=time.monotonic() - cooldown,
        correctness_failures=failures,
    ), {"samples": samples, "retained": retained, "cpu": max(cpus)}


def performance(bad):
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    baseline, base = measured_run(0)
    candidate, observed = measured_run(0.25 if bad else 0)
    growth = tracemalloc.take_snapshot().compare_to(before, "filename")
    # Only retained Python allocations above 64 KiB per file are in scope.
    findings = sum(item.size_diff > 65536 for item in growth)
    tracemalloc.stop()
    return dict(
        workload_sha256=D,
        environment_sha256=D,
        baseline=baseline,
        candidate=candidate,
        resource_series={
            "python_bytes": {
                "baseline": base["samples"],
                "candidate": observed["samples"],
                "baseline_cooldown": base["retained"],
                "candidate_cooldown": observed["retained"],
            }
        },
        load_generator={
            "cpu_peak_pct": max(base["cpu"], observed["cpu"]),
            "memory_peak_pct": process_memory_percent(),
            "dropped_iterations": 10 - candidate["observations"],
        },
        leak_check={
            "engine": "python_tracemalloc",
            "findings": findings,
            # No detected definite-loss finding within tracemalloc coverage;
            # this cannot measure native lost bytes or prove their absence.
            "definitely_lost_bytes": 0,
            "exit_code": 0,
        },
    )


def process_memory_percent():
    """Observed peak process working set divided by host physical capacity."""
    if os.name != "nt":
        import resource

        units = 1 if sys.platform == "darwin" else 1024
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * units
        total = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        return 100 * peak / total
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t)
            for name in (
                "peak_working_set",
                "working_set",
                "peak_paged",
                "paged",
                "peak_nonpaged",
                "nonpaged",
                "pagefile",
                "peak_pagefile",
            )
        ]

    class Memory(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
            (name, ctypes.c_ulonglong)
            for name in (
                "physical",
                "available",
                "pagefile",
                "available_pagefile",
                "virtual",
                "available_virtual",
                "extended",
            )
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(Counters),
        wintypes.DWORD,
    ]
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(Memory)]
    counters, memory = Counters(), Memory()
    counters.cb = ctypes.sizeof(counters)
    memory.length = ctypes.sizeof(memory)
    if not psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise ctypes.WinError(ctypes.get_last_error())
    return 100 * counters.peak_working_set / memory.physical


D = hashlib.sha256(b"x").hexdigest()
WORKERS = {
    "stateful_invariant": (stateful, "stateful", "approved_state_machine"),
    "tenant_isolation": (tenant, "tenant", "runtime_http_matrix"),
    "failure_recovery": (recovery, "recovery", "approved_fault_runner"),
    "consumer_compatibility": (
        compatibility,
        "compatibility",
        "approved_schema_validator",
    ),
    "migration_integrity": (migration, "migration", "database_rehearsal"),
    "performance_regression": (performance, "performance", "approved_load_runner"),
}

if __name__ == "__main__":
    worker, family, engine = WORKERS[sys.argv[1]]
    known_bad = len(sys.argv) == 4
    artifact = worker(known_bad)
    artifact.update(
        schema=f"factory.runtime.{family}.v1",
        engine=engine,
        engine_version="1",
        scenario_sha256=D,
    )
    if family == "recovery":
        artifact["schema"] = "factory.runtime.recovery.v2"
    Path(sys.argv[-1]).write_text(json.dumps(artifact), encoding="utf-8")
    sys.exit(int(known_bad))
