"""Data contracts shared by the source-only identity effect analyzer."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import ast


@dataclass(frozen=True)
class ResolvedIdentityCall:
    """Captured callee with an exact formal-to-call-expression mapping."""

    function: ast.FunctionDef | ast.AsyncFunctionDef
    path: object
    arguments: Mapping[str, ast.expr]


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
        return self.status == "NO_CLASS_EFFECT"


@dataclass(frozen=True)
class _Value:
    roots: frozenset[str] = frozenset()
    items: tuple[tuple[object, "_Value"], ...] = ()
    class_roots: frozenset[str] = frozenset()
    unknown: bool = False


@dataclass
class _Effects:
    class_writes: set[str] = field(default_factory=set)
    escapes: set[str] = field(default_factory=set)
    unknowns: set[str] = field(default_factory=set)
    field_writes: set[str] = field(default_factory=set)

    def merge(self, other):
        for name in ("class_writes", "escapes", "unknowns", "field_writes"):
            getattr(self, name).update(getattr(other, name))

    def freeze(self):
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
