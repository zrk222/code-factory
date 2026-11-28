import ast

from factoryline import scan_pool


def test_ast_dump_digest_is_stable_and_cached():
    node = ast.parse("value = call(1)").body[0]
    first = scan_pool.ast_dump_digest(node)
    node._scanner_sidecar = "ignored"
    assert scan_pool.ast_dump_digest(node) == first
    assert scan_pool.ast_dump_digest(ast.parse("value = call(1)").body[0]) == first
    assert scan_pool.ast_dump_digest(object()) == ""


def test_map_scan_jobs_keeps_order_in_and_out_of_workers(monkeypatch):
    jobs = [(name, index) for index, name in enumerate("abcdef")]
    monkeypatch.setenv("FACTORY_SCAN_WORKERS", "1")
    serial = scan_pool.map_scan_jobs(jobs, lambda name, index: f"{name}{index * 2}")
    monkeypatch.setenv("FACTORY_SCAN_WORKERS", "3")
    pooled = scan_pool.map_scan_jobs(jobs, lambda name, index: f"{name}{index * 2}")
    assert serial == pooled == [(name, f"{name}{index * 2}") for name, index in jobs]
    assert scan_pool.scan_workers(3) == 1
