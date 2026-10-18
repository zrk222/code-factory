"""Hash-bound source-span helpers for method flow records."""

import ast
import hashlib


def source_current(index, path):
    memo = getattr(index, "class_chain_memo", None)
    checks = getattr(memo, "method_flow_source_checks", None)
    if memo is not None and callable(getattr(memo, "valid", None)):
        if checks is None:
            checks = {}
            memo.method_flow_source_checks = checks
        if path not in checks:
            checks[path] = _source_current(index, path)
        return checks[path]
    return _source_current(index, path)


def _source_current(index, path):
    if not index.validate(path):
        return False
    tree, raw = index.snapshots.get(path), index.source_bytes.get(path)
    digest = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
    if digest is None or index.inventory.get(path) != digest:
        return False
    if getattr(tree, "_oracle_source_sha256", None) != digest:
        return False
    try:
        return ast.dump(ast.parse(raw), include_attributes=True) == ast.dump(
            tree, include_attributes=True
        )
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return False


def source_span(index, path, node, role):
    return {
        "path": index.relative(path),
        "line": node.lineno,
        "column": node.col_offset,
        "end_line": getattr(node, "end_lineno", node.lineno),
        "end_column": getattr(node, "end_col_offset", node.col_offset),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "role": role,
    }
