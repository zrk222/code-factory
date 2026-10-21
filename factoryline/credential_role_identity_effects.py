"""Bounded source-only identity-effect summaries for selected object roots."""

import ast
from collections.abc import Mapping

from .credential_role_identity_call_model import (
    captured_function_valid,
    exported_names,
    identity_fields,
    literal_dict_update,
    mapped_call_values,
    own_function_nodes,
)
from .credential_role_identity_content_guard import (
    record_implicit_effects,
    record_opaque_call,
    strict_protocol_effects,
    strict_read_effects,
)
from .credential_role_identity_effect_types import (
    CallResolver,
    SourceFieldLiteral,
    _Effects,
    _Value,
)
from .credential_role_identity_effect_types import (
    IdentityEffectSummary as IdentityEffectSummary,
)
from .credential_role_identity_effect_types import (
    ResolvedIdentityCall as ResolvedIdentityCall,
)
from .credential_role_identity_value_model import (
    assignment_target,
    call_has_unknown_value,
    call_tracked_roots,
    contains_tracked,
    identity_value,
    nested_capture_roots,
    record_escape,
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
    field_roots: Mapping[tuple[str, str], str | SourceFieldLiteral] | None = None,
    strict_calls=False,
    max_depth=4,
    state_budget=512,
):
    """Summarize captured ASTs without executing target code.

    Callers prove exact bindings, branches, descriptors, allocation and current
    field ownership; initial field projections are not admission evidence.
    Unknown protocols, heap escapes and overwritten projections fail closed.
    Strict mode also rejects unresolved calls without explicit root arguments.
    """
    return (
        _Analyzer(
            index, resolve_call, max_depth, state_budget, field_roots, strict_calls
        )
        .run(function, path, dict(roots), 0, frozenset())
        .freeze()
    )


class _Analyzer:
    def __init__(self, index, resolver, depth_limit, budget, field_roots, strict_calls):
        self.index, self.resolver = index, resolver
        self.depth_limit, self.budget, self.states = depth_limit, budget, 0
        self.fields = identity_fields(field_roots, index)
        self.strict_calls = strict_calls

    def run(self, function, path, roots, depth, active):
        """Analyze a captured function within depth and state budgets; return explicit unknown effects when validation is incomplete."""
        out = _Effects()
        if self.fields is None:
            out.unknowns.add("invalid initial field identity graph")
            return out
        if depth > self.depth_limit or (path, id(function)) in active:
            out.unknowns.add("call depth or cycle limit")
            return out
        if not captured_function_valid(function, path, self.index):
            out.unknowns.add("callee is not a validated captured function")
            return out
        nodes = own_function_nodes(function, path, self.index)
        self.states += len(nodes)
        if self.states > self.budget:
            out.unknowns.add("AST state budget exceeded")
            return out
        aliases = self._aliases(function, roots, nodes, out)
        active = active | {(path, id(function))}
        self._visit(nodes, function, path, aliases, depth, active, out)
        out.escapes.update(
            nested_capture_roots(
                function,
                path,
                aliases,
                self.index,
                strict_calls=self.strict_calls,
                effects=out,
            )
        )
        return out

    def _visit(self, nodes, function, path, aliases, depth, active, out):
        exported = exported_names(nodes)
        for node in nodes:
            if self.strict_calls:
                strict_read_effects(node, aliases, self.index.parents[path], out)
                strict_protocol_effects(node, aliases, self.index.parents[path], out)
            record_implicit_effects(
                node, function, aliases, out, strict_calls=self.strict_calls
            )
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                self._assignment(node, aliases, function, out, exported)
            elif isinstance(node, (ast.AugAssign, ast.Delete)):
                for target in (
                    node.targets if isinstance(node, ast.Delete) else [node.target]
                ):
                    record_write(
                        target,
                        _Value(),
                        aliases,
                        out,
                        strict_calls=self.strict_calls,
                    )
            elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                record_escape(
                    getattr(node, "value", None),
                    aliases,
                    out,
                    "return/yield",
                    strict_calls=self.strict_calls,
                )
            elif isinstance(node, ast.Call):
                self._call(node, path, aliases, depth, active, out)

    def _aliases(self, function, roots, nodes, out):
        args = function.args
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [item for item in (args.vararg, args.kwarg) if item]
        env = {
            name: root if isinstance(root, _Value) else _Value(frozenset({root}))
            for name, root in roots.items()
        }
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
                value = identity_value(
                    getattr(node, "value", None),
                    env,
                    strict_calls=self.strict_calls,
                )
                if (
                    contains_tracked(value) or value.inert_kind is not None
                ) and env.get(target.id) != value:
                    env[target.id], changed = value, True
            if not changed:
                break
        else:
            out.unknowns.add("alias fixed-point limit")
        return env

    def _assignment(self, node, aliases, function, out, exported):
        if isinstance(node, ast.Assign) and len(node.targets) != 1:
            value = identity_value(node.value, aliases, strict_calls=self.strict_calls)
            if contains_tracked(value):
                out.unknowns.add("multi-target tracked assignment")
            return
        value, target = (
            identity_value(
                getattr(node, "value", None),
                aliases,
                strict_calls=self.strict_calls,
            ),
            assignment_target(node),
        )
        if isinstance(target, (ast.Tuple, ast.List)):
            if contains_tracked(value):
                out.unknowns.add("destructuring tracked object")
        elif isinstance(target, ast.Name):
            if target.id in exported:
                record_escape(
                    node.value,
                    aliases,
                    out,
                    "global/nonlocal assignment",
                    strict_calls=self.strict_calls,
                )
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
            record_write(target, value, aliases, out, strict_calls=self.strict_calls)

    def _call(self, call, path, aliases, depth, active, out):
        if literal_dict_update(call, aliases, strict_calls=self.strict_calls):
            return
        if call_has_unknown_value(call, aliases, strict_calls=self.strict_calls):
            out.unknowns.add("call receives an unresolved tracked value")
            return
        involved = call_tracked_roots(call, aliases, strict_calls=self.strict_calls)
        if not involved and not self.strict_calls:
            return
        resolved = self.resolver(call, path) if self.resolver else None
        if resolved is None:
            record_opaque_call(
                call, aliases, involved, out, strict_calls=self.strict_calls
            )
            return
        mapped = mapped_call_values(
            call,
            aliases,
            involved,
            resolved,
            out,
            strict_calls=self.strict_calls,
        )
        if mapped is None:
            return

        out.merge(self.run(resolved.function, resolved.path, mapped, depth + 1, active))
