"""Bounded source-only identity-effect summaries for selected object roots."""

from collections.abc import Mapping
import ast

from .credential_role_identity_effect_types import (
    CallResolver,
    IdentityEffectSummary as IdentityEffectSummary,
    ResolvedIdentityCall,
    _Effects,
    _Value,
)
from .credential_role_identity_value_model import (
    call_argument_roots,
    call_has_unknown_value,
    call_tracked_roots,
    assignment_target,
    contains_tracked,
    identity_value,
    identity_fields,
    maps_each_actual_once,
    nested_capture_roots,
    record_escape,
    record_implicit_effects,
    record_write,
    tracked_roots,
)
from .credential_role_scope_bindings import binding_occurrences
from .credential_role_sources import SourceSnapshotIndex


def summarize_identity_effect(
    function,
    path,
    index: SourceSnapshotIndex,
    roots: Mapping[str, str],
    *,
    resolve_call: CallResolver | None = None,
    field_roots: Mapping[tuple[str, str], str] | None = None,
    max_depth=4,
    state_budget=512,
):
    """Summarize identity effects from captured ASTs; target code never runs.

    ``roots`` maps parameter names to labels. Unique aliases and literal
    container constant-index reads are followed. A trusted exact source binder
    supplies callees and formal mappings; its binding logic remains external.
    Heap capture is an escape; unknown field reads are UNKNOWN. Callers prove
    branch/truth guards, absence of effectful descriptors, and whether ordinary
    field setters can mutate class identity. Implicit Python protocol dispatch
    on roots is UNKNOWN.

    ``field_roots`` is a caller-proved, descriptor-free initial heap projection.
    This analyzer does not establish allocation or field ownership by itself.
    Overwriting a projected field invalidates the summary.
    """
    return (
        _Analyzer(index, resolve_call, max_depth, state_budget, field_roots)
        .run(function, path, dict(roots), 0, frozenset())
        .freeze()
    )


class _Analyzer:
    def __init__(self, index, resolver, depth_limit, budget, field_roots):
        self.index, self.resolver = index, resolver
        self.depth_limit, self.budget, self.states = depth_limit, budget, 0
        self.fields = identity_fields(field_roots)

    def run(self, function, path, roots, depth, active):
        out = _Effects()
        if self.fields is None:
            out.unknowns.add("invalid initial field identity graph")
            return out
        if depth > self.depth_limit or (path, id(function)) in active:
            out.unknowns.add("call depth or cycle limit")
            return out
        if not self._valid(function, path):
            out.unknowns.add("callee is not a validated captured function")
            return out
        nodes = self._own_nodes(function, path)
        self.states += len(nodes)
        if self.states > self.budget:
            out.unknowns.add("AST state budget exceeded")
            return out
        aliases = self._aliases(function, roots, nodes, out)
        active = active | {(path, id(function))}
        self._visit(nodes, function, path, aliases, depth, active, out)
        out.escapes.update(nested_capture_roots(function, path, aliases, self.index))
        return out

    def _visit(self, nodes, function, path, aliases, depth, active, out):
        for node in nodes:
            record_implicit_effects(node, function, aliases, out)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                self._assignment(node, aliases, function, out)
            elif isinstance(node, (ast.AugAssign, ast.Delete)):
                for target in (
                    node.targets if isinstance(node, ast.Delete) else [node.target]
                ):
                    record_write(target, _Value(), aliases, out)
            elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                record_escape(
                    getattr(node, "value", None), aliases, out, "return/yield"
                )
            elif isinstance(node, ast.Call):
                self._call(node, path, aliases, depth, active, out)

    def _valid(self, function, path):
        return bool(
            isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            and self.index.validate(path)
            and any(node is function for node in ast.walk(self.index.snapshots[path]))
        )

    def _own_nodes(self, function, path):
        parents, scopes, result = (
            self.index.parents[path],
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            [],
        )
        for node in ast.walk(function):
            parent, nested = parents.get(id(node)), False
            while parent is not None and parent is not function:
                if isinstance(parent, scopes):
                    nested = True
                    break
                parent = parents.get(id(parent))
            if not nested:
                result.append(node)
        return result

    def _aliases(self, function, roots, nodes, out):
        args = function.args
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [item for item in (args.vararg, args.kwarg) if item]
        env = {name: _Value(frozenset({root})) for name, root in roots.items()}
        env.update(self.fields)
        for param in params:
            if param.arg in roots and binding_occurrences(function.body, param.arg):
                out.unknowns.add(f"root parameter rebound: {param.arg}")
        assigns = [
            n
            for n in nodes
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        for _ in range(min(len(assigns) + 1, 32)):
            changed = False
            for node in assigns:
                target = assignment_target(node)
                if not isinstance(target, ast.Name) or binding_occurrences(
                    function.body, target.id
                ) != [target]:
                    continue
                value = identity_value(getattr(node, "value", None), env)
                if contains_tracked(value) and env.get(target.id) != value:
                    env[target.id], changed = value, True
            if not changed:
                break
        else:
            out.unknowns.add("alias fixed-point limit")
        return env

    def _assignment(self, node, aliases, function, out):
        if isinstance(node, ast.Assign) and len(node.targets) != 1:
            value = identity_value(node.value, aliases)
            if contains_tracked(value):
                out.unknowns.add("multi-target tracked assignment")
            return
        value, target = (
            identity_value(getattr(node, "value", None), aliases),
            assignment_target(node),
        )
        if isinstance(target, (ast.Tuple, ast.List)):
            if contains_tracked(value):
                out.unknowns.add("destructuring tracked object")
        elif isinstance(target, ast.Name):
            if contains_tracked(value) and binding_occurrences(
                function.body, target.id
            ) != [target]:
                out.unknowns.add(f"ambiguous alias binding: {target.id}")
            else:
                if value.items:
                    out.escapes.update(tracked_roots(value))
                if value.unknown:
                    out.unknowns.add("alias receives unresolved tracked expression")
        else:
            record_write(target, value, aliases, out)

    def _call(self, call, path, aliases, depth, active, out):
        if call_has_unknown_value(call, aliases):
            out.unknowns.add("call receives an unresolved tracked value")
            return
        involved = call_tracked_roots(call, aliases)
        if not involved:
            return
        resolved = self.resolver(call, path) if self.resolver else None
        if resolved is None:
            self._opaque_call(call, aliases, involved, out)
            return
        mapped = self._mapped_call_roots(call, aliases, involved, resolved, out)
        if mapped is None:
            return

        out.merge(self.run(resolved.function, resolved.path, mapped, depth + 1, active))

    def _opaque_call(self, call, aliases, involved, out):
        if call_argument_roots(call, aliases):
            out.escapes.update(involved)
        else:
            out.unknowns.add("unresolved method call on tracked object")

    def _mapped_call_roots(self, call, aliases, involved, resolved, out):
        if not isinstance(resolved, ResolvedIdentityCall):
            out.unknowns.add("invalid exact call binding")
            return None
        params = {
            arg.arg
            for arg in [
                *resolved.function.args.posonlyargs,
                *resolved.function.args.args,
                *resolved.function.args.kwonlyargs,
            ]
        }
        actuals = [*call.args, *(kw.value for kw in call.keywords)]
        if isinstance(call.func, ast.Attribute):
            actuals.append(call.func.value)
        if not maps_each_actual_once(actuals, resolved.arguments):
            out.unknowns.add("exact call mapping must cover each actual once")
            return None
        mapped = {}
        for formal, expr in resolved.arguments.items():
            if formal not in params or not any(expr is actual for actual in actuals):
                out.unknowns.add("call mapping is not an exact parameter binding")
                return
            value = identity_value(expr, aliases)
            roots = tracked_roots(value)
            if not isinstance(expr, ast.expr) or (
                contains_tracked(value) and len(roots) != 1
            ):
                out.unknowns.add("ambiguous exact call root mapping")
                return None
            elif roots:
                mapped[formal] = next(iter(roots))
        if set(mapped.values()) != involved:
            out.unknowns.add("exact call mapping omits a tracked root")
            return None
        return mapped
