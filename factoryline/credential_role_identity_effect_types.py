"""Data contracts shared by the source-only identity effect analyzer."""

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ResolvedIdentityCall:
    """Captured callee with an exact formal-to-call-expression mapping."""

    function: ast.FunctionDef | ast.AsyncFunctionDef
    path: object
    arguments: Mapping[str, ast.expr]


@dataclass(frozen=True)
class SourceFieldLiteral:
    """Captured literal; caller proves current contents, ownership and no escape."""

    path: object
    value: ast.expr


@dataclass(frozen=True)
class IdentityEffectSummary:
    """May-effects; field writes do not change class identity."""

    status: str
    class_writes: tuple[str, ...] = ()
    escapes: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    field_writes: tuple[str, ...] = ()

    @property
    def preserves_class_identity(self):
        """Report preserved class identity only for the no-class-effect summary status."""
        return self.status == "NO_CLASS_EFFECT"


@dataclass(frozen=True)
class _Value:
    roots: frozenset[str] = frozenset()
    items: tuple[tuple[object, "_Value"], ...] = ()
    class_roots: frozenset[str] = frozenset()
    unknown: bool = False
    content_unknown: bool = False
    inert_kind: str | None = None


@dataclass
class _Effects:
    class_writes: set[str] = field(default_factory=set)
    escapes: set[str] = field(default_factory=set)
    unknowns: set[str] = field(default_factory=set)
    field_writes: set[str] = field(default_factory=set)

    def merge(self, other):
        """Merge class writes, escapes, unknowns, and field writes from another effect accumulator."""
        for name in ("class_writes", "escapes", "unknowns", "field_writes"):
            getattr(self, name).update(getattr(other, name))

    def freeze(self):
        """Freeze effect sets into a deterministically sorted summary, prioritizing unknowns, then writes, then escapes."""
        status = (
            "UNKNOWN"
            if self.unknowns
            else "CLASS_WRITE"
            if self.class_writes
            else "ESCAPE"
            if self.escapes
            else "NO_CLASS_EFFECT"
        )
        fields = ("class_writes", "escapes", "unknowns", "field_writes")
        return IdentityEffectSummary(
            status, *(tuple(sorted(getattr(self, name))) for name in fields)
        )


CallResolver = Callable[[ast.Call, object], ResolvedIdentityCall | None]


def contains_tracked(value):
    """Report whether an identity value contains any tracked roots, uncertainty, or nested items."""
    return bool(
        value.roots
        or value.class_roots
        or value.unknown
        or value.content_unknown
        or value.items
    )


def tracked_roots(value):
    """Collect direct and recursively nested tracked roots from an identity value."""
    roots = set(value.roots | value.class_roots)
    for _, item in value.items:
        roots.update(tracked_roots(item))
    return roots


def _has_unknown_content(value):
    return bool(
        value.unknown
        or value.content_unknown
        or any(_has_unknown_content(item) for _, item in value.items)
    )


def maps_each_actual_once(actuals, arguments):
    """Confirm each resolved formal maps to one distinct actual expression by AST identity."""
    expressions = tuple(arguments.values())
    return all(isinstance(expr, ast.expr) for expr in expressions) and sorted(
        map(id, expressions)
    ) == sorted(map(id, actuals))
