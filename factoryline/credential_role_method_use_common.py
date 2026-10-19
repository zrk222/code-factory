"""Shared exact-span helpers for method-value use closure."""


def absolute_path(index, relative):
    def derive():
        rows = {}
        for path in index.snapshots:
            rows.setdefault(index.relative(path), []).append(path)
        return rows

    def epoch():
        relative_helper = index.relative
        return (
            absolute_path,
            getattr(relative_helper, "__func__", relative_helper),
            getattr(relative_helper, "__self__", None),
        )

    memo = getattr(index, "class_chain_memo", None)
    key = ("relative-source-paths", index.root, tuple(index.snapshots))
    rows = memo.source_model(key, derive, helper_epoch=epoch) if memo else derive()
    matches = rows.get(relative, ())
    return matches[0] if len(matches) == 1 and index.validate(matches[0]) else None


def ancestor(node, index, relative, types):
    path, current = absolute_path(index, relative), node
    while path and current:
        if isinstance(current, types):
            return current
        current = index.parents[path].get(id(current))
    return None


def coordinates(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def span_key(row):
    return tuple(
        row.get(key)
        for key in (
            "path",
            "line",
            "column",
            "end_line",
            "end_column",
            "source_sha256",
            "role",
        )
    )


def public_span(row):
    return dict(
        zip(
            (
                "path",
                "line",
                "column",
                "end_line",
                "end_column",
                "source_sha256",
                "role",
            ),
            span_key(row),
        )
    )
