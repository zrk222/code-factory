"""Narrow source proofs for hollow type-intent tests."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path

from . import type_intent_provider_provenance as provider


def _provider_context_metadata_closed(context, relative):
    if not isinstance(context, dict) or not _valid_relative(relative):
        return False
    if not context.get("provider_source_inventory_complete"):
        return False
    if not context.get("provider_source_closure_complete"):
        return False
    if not isinstance(context.get("provider_source_closure"), list):
        return False
    if not isinstance(context.get("provider_owner_local_imports"), list):
        return False
    if any(
        not isinstance(alias, str) for alias in context["provider_owner_local_imports"]
    ):
        return False
    return True


def _provider_source_tuple(source):
    return (
        isinstance(source, tuple)
        and len(source) == 2
        and isinstance(source[0], Path)
        and isinstance(source[1], dict)
    )


def _provider_context_source(module, relative):
    context = getattr(module, "_security_oracle_context", None)
    if not _provider_context_metadata_closed(context, relative):
        return None
    source = getattr(module, "_security_source_context", None)
    if not _provider_source_tuple(source):
        return None
    root, sources = source
    digest = getattr(module, "_oracle_source_sha256", None)
    raw = sources.get(root / relative)
    if not isinstance(digest, str) or len(digest) != 64:
        return None
    if not isinstance(raw, bytes) or sha256(raw).hexdigest() != digest:
        return None
    return context, root, sources


def captured_provider_context_closed(
    module, relative, selected_test, canonical, noop_write
) -> bool:
    """Confirm the owner source, imports, effects, and captured closure are complete."""
    source = _provider_context_source(module, relative)
    if source is None:
        return False
    context, root, sources = source
    if not provider.owner_module_effects_closed(
        module,
        selected_test,
        canonical,
        noop_write,
        context["provider_owner_local_imports"],
    ):
        return False
    return provider._captured_closure_closed(
        root, sources, context["provider_source_closure"]
    )


def _valid_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def _captured_unittest_source_closed(module):
    context = getattr(module, "_security_oracle_context", None)
    source = getattr(module, "_security_source_context", None)
    if (
        not isinstance(context, dict)
        or context.get("provider_source_inventory_complete") is not True
        or context.get("provider_source_closure_complete") is not True
        or context.get("provider_source_closure") != []
        or context.get("provider_owner_local_imports") != []
        or not isinstance(source, tuple)
        or len(source) != 2
        or not isinstance(source[0], Path)
        or not isinstance(source[1], dict)
    ):
        return False
    root, sources = source
    digest = getattr(module, "_oracle_source_sha256", None)
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    return _captured_unittest_source_ast_matches(module, root, sources, digest)


def _captured_unittest_source_ast_matches(module, root, sources, digest):
    lines = getattr(module, "_oracle_source_lines", None)
    if not isinstance(lines, list) or any(not isinstance(line, str) for line in lines):
        return False
    raw = _unique_captured_unittest_source(root, sources, digest)
    if raw is None:
        return False
    try:
        if raw.decode("utf-8").splitlines() != lines:
            return False
        reparsed = ast.parse(raw, type_comments=True)
        return ast.dump(module, include_attributes=True) == ast.dump(
            reparsed, include_attributes=True
        )
    except (RecursionError, SyntaxError, UnicodeDecodeError, ValueError):
        return False


def _unique_captured_unittest_source(root, sources, digest):
    if root / "unittest.py" in sources or root / "unittest" / "__init__.py" in sources:
        return None
    matching_source = None
    for path, raw in sources.items():
        if not isinstance(path, Path) or not isinstance(raw, bytes):
            return None
        try:
            relative = path.relative_to(root).as_posix().casefold()
        except ValueError:
            return None
        if relative == "unittest.py" or (
            relative.startswith("unittest/") and relative.endswith(".py")
        ):
            return None
        if sha256(raw).hexdigest() == digest:
            if matching_source is not None:
                return None
            matching_source = raw
    return matching_source


def _direct_unittest_owner(module, node):
    owners = [
        item
        for item in module.body
        if isinstance(item, ast.ClassDef) and node in item.body
    ]
    return owners[0] if len(owners) == 1 else None


def _closed_unittest_module(module, owner):
    alias = None
    seen_class = False
    for item in module.body:
        if item is owner:
            seen_class = True
        elif _ignorable(item):
            continue
        elif (
            seen_class
            or alias is not None
            or not isinstance(item, ast.Import)
            or len(item.names) != 1
            or item.names[0].name != "unittest"
        ):
            return None
        else:
            alias = item.names[0].asname or item.names[0].name
    return alias if seen_class else None


def _closed_unittest_testcase(owner, node, alias):
    if (
        owner.decorator_list
        or owner.keywords
        or len(owner.bases) != 1
        or getattr(owner, "type_params", ())
    ):
        return False
    base = owner.bases[0]
    if (
        not isinstance(base, ast.Attribute)
        or base.attr != "TestCase"
        or not isinstance(base.value, ast.Name)
        or base.value.id != alias
    ):
        return False
    return (
        all(item is node or _ignorable(item) for item in owner.body)
        and sum(item is node for item in owner.body) == 1
    )


def _closed_unittest_test_method(node):
    args = node.args
    if (
        node.decorator_list
        or node.returns is not None
        or node.type_comment is not None
        or getattr(node, "type_params", ())
        or args.posonlyargs
        or len(args.args) != 1
        or args.args[0].arg != "self"
        or args.args[0].annotation is not None
        or getattr(args.args[0], "type_comment", None) is not None
        or args.vararg is not None
        or args.kwarg is not None
        or args.kwonlyargs
        or args.defaults
        or args.kw_defaults
    ):
        return False
    calls = 0
    for item in node.body:
        if _ignorable(item):
            continue
        if not isinstance(item, ast.Expr) or not _vacuous_unittest_call(item.value):
            return False
        calls += 1
    return calls > 0


def _literal_unittest_value(node):
    if isinstance(node, ast.Constant):
        value = node.value
        allowed = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))
        return type(value) in allowed, value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = node.operand
        if isinstance(operand, ast.Constant) and type(operand.value) in (
            int,
            float,
            complex,
        ):
            value = operand.value
            return True, value if isinstance(node.op, ast.UAdd) else -value
        return False, None
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_literal_unittest_value(item) for item in node.elts]
        if not all(valid for valid, _value in values):
            return False, None
        result = [value for _valid, value in values]
        return True, tuple(result) if isinstance(node, ast.Tuple) else result
    return False, None


def _vacuous_unittest_call(node):
    if (
        not isinstance(node, ast.Call)
        or node.keywords
        or not isinstance(node.func, ast.Attribute)
        or not isinstance(node.func.value, ast.Name)
        or node.func.value.id != "self"
    ):
        return False
    name = node.func.attr
    if name in {"assertTrue", "assertFalse"}:
        if len(node.args) != 1:
            return False
        valid, value = _literal_unittest_value(node.args[0])
        return valid and type(value) is bool and value is (name == "assertTrue")
    if name not in {"assertEqual", "assertTupleEqual", "assertListEqual"}:
        return False
    if len(node.args) != 2:
        return False
    left_ok, left = _literal_unittest_value(node.args[0])
    right_ok, right = _literal_unittest_value(node.args[1])
    if not left_ok or not right_ok or type(left) is not type(right):
        return False
    if name == "assertTupleEqual" and type(left) is not tuple:
        return False
    if name == "assertListEqual" and type(left) is not list:
        return False
    try:
        return left == right
    except RecursionError:
        return False


def source_proven_unittest_vacuity(node):
    """Recognize unittest vacuity only for a test tied to a source-closed unittest.TestCase owner and method."""
    if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
        return False
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module) or not _captured_unittest_source_closed(
        module
    ):
        return False
    owner = _direct_unittest_owner(module, node)
    if owner is None:
        return False
    alias = _closed_unittest_module(module, owner)
    return bool(
        alias
        and _closed_unittest_testcase(owner, node, alias)
        and _closed_unittest_test_method(node)
    )


def obviously_empty_test_body(node: ast.AST) -> bool:
    """Combine inert-test, registered-callback, and source-proven unittest checks to identify an obviously empty test body."""
    from .test_callback_closure import inert_registered_callback_body
    from .test_oracle_misuse import inert_test_body

    return (
        inert_test_body(node)
        or inert_registered_callback_body(node)
        or source_proven_unittest_vacuity(node)
    )


def _type_assertion_oracle_call(node, aliases, module_aliases, scope_parameters):
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    module = getattr(node, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return None
    source_aliases = dict(module_aliases)
    source_aliases.update(aliases)
    body = [statement for statement in node.body if not _ignorable(statement)]
    call, local_assignment = _test_call(body, scope_parameters)
    if call is None or not provider._simple_type_call(call):
        return None
    canonical = provider._source_name(call.func, source_aliases)
    if canonical not in {"typing.assert_type", "typing_extensions.assert_type"}:
        return None
    lexical = provider._source_name(call.func, aliases)
    if lexical != canonical and local_assignment is None:
        return None
    if not _provider_references_are_closed(
        module, call, local_assignment, source_aliases, canonical
    ):
        return None
    return module, call, source_aliases, canonical


def inert_type_assertion_only_oracle(
    node,
    aliases,
    *,
    module_aliases,
    scope_parameters,
    provider_mutated,
    relative,
    provider_context_closed,
) -> bool:
    """Identify a sole closed typing.assert_type oracle without certifying execution."""
    candidate = _type_assertion_oracle_call(
        node, aliases, module_aliases, scope_parameters
    )
    if candidate is None:
        return False
    module, call, source_aliases, canonical = candidate
    noop_write = None
    if provider_mutated(module, source_aliases):
        noop_write = _single_noop_provider_write(
            module, source_aliases, canonical, call
        )
        if noop_write is None:
            return False
    return provider_context_closed(module, relative, node, canonical, noop_write)


def _ignorable(statement: ast.stmt, *, ellipsis: bool = False) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    if not isinstance(statement, ast.Expr) or not isinstance(
        statement.value, ast.Constant
    ):
        return False
    value = statement.value.value
    return isinstance(value, str) or ellipsis and value is Ellipsis


def _test_call(body: list[ast.stmt], parameters: set[str]):
    if len(body) == 1 and isinstance(body[0], ast.Expr):
        return body[0].value, None
    if (
        len(body) == 2
        and isinstance(body[0], ast.Assign)
        and isinstance(body[1], ast.Expr)
        and isinstance(body[1].value, ast.Call)
        and len(body[0].targets) == 1
        and isinstance(body[0].targets[0], ast.Name)
        and isinstance(body[1].value.func, ast.Name)
        and body[0].targets[0].id == body[1].value.func.id
        and body[0].lineno < body[1].lineno
        and body[0].targets[0].id not in parameters
        and _none_lambda(body[0].value)
    ):
        return body[1].value, body[0]
    return None, None


def _provider_references_are_closed(module, call, local_assignment, aliases, canonical):
    provider_name = canonical.split(".", 1)[0]
    parent = {
        child: current
        for current in ast.walk(module)
        for child in ast.iter_child_nodes(current)
    }
    for reference in (item for item in ast.walk(module) if isinstance(item, ast.Name)):
        target = aliases.get(reference.id)
        if target not in {provider_name, canonical}:
            continue
        if target == provider_name:
            attribute = parent.get(reference)
            if not (
                isinstance(attribute, ast.Attribute)
                and attribute.value is reference
                and attribute.attr == "assert_type"
                and _allowed_provider_attribute(
                    parent.get(attribute), call, aliases, canonical
                )
            ):
                return False
            continue
        use = parent.get(reference)
        if isinstance(use, ast.Call) and use.func is reference:
            if use is call or (
                provider._source_name(use.func, aliases) == canonical
                and provider._simple_type_call(use)
            ):
                continue
        if local_assignment is not None and reference is local_assignment.targets[0]:
            continue
        if _allowed_provider_attribute(use, call, aliases, canonical):
            continue
        return False
    return not any(
        isinstance(item, ast.Name) and item.id in {"exec", "eval"}
        for item in ast.walk(module)
    )


def _allowed_provider_attribute(
    parent: ast.AST | None, call: ast.Call, aliases: dict[str, str], canonical: str
) -> bool:
    if isinstance(parent, ast.Call):
        return parent is call or (
            provider._source_name(parent.func, aliases) == canonical
            and provider._simple_type_call(parent)
        )
    return isinstance(parent, ast.Assign) and any(
        isinstance(target, ast.Attribute) and target.attr == "assert_type"
        for target in parent.targets
    )


def _single_noop_provider_write(
    module: ast.Module, aliases: dict[str, str], canonical: str, call: ast.Call
):
    writes = [
        item
        for item in ast.walk(module)
        if isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and item.attr == "assert_type"
        and provider._source_name(item, aliases)
        in {"typing.assert_type", "typing_extensions.assert_type"}
    ]
    if len(writes) != 1 or provider._source_name(writes[0], aliases) != canonical:
        return None
    assignments = [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and statement.targets[0] is writes[0]
    ]
    if (
        len(assignments) == 1
        and assignments[0].lineno < call.lineno
        and _none_lambda(assignments[0].value)
    ):
        return assignments[0]
    return None


def _none_lambda(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Lambda)
        and isinstance(node.body, ast.Constant)
        and node.body.value is None
        and not node.args.defaults
        and not node.args.kw_defaults
    )


def bind_negative_checker_context(root, contexts, identity):
    """Keep declared negative-check scope inside the source/config cache identity."""
    selected = set(identity.get("negative_typecheck_selected", ()))
    for path, context in contexts.items():
        context["negative_typecheck"] = path.relative_to(root).as_posix() in selected


def _negative_type_ignore_comment(statement, lines):
    from io import StringIO
    import tokenize

    try:
        comments = [
            token
            for token in tokenize.generate_tokens(StringIO("\n".join(lines)).readline)
            if token.type == tokenize.COMMENT
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return False
    if any(
        token.string.lstrip("# ").startswith(("pyright:", "basedpyright:"))
        for token in comments
    ):
        return False
    return any(
        token.start[0] == statement.end_lineno
        and token.string.strip() == "# type: ignore"
        for token in comments
    )


def negative_type_expectation(node, context):
    """Recognize a declared negative typing check, without certifying its execution."""
    if not context.get("negative_typecheck") or not isinstance(node, ast.FunctionDef):
        return False
    module = getattr(node, "_oracle_module", None)
    lines = getattr(module, "_oracle_source_lines", None)
    if not isinstance(lines, list) or any(not isinstance(line, str) for line in lines):
        return False
    body = [item for item in node.body if not _ignorable(item)]
    if len(body) != 1 or not isinstance(body[0], ast.AnnAssign):
        return False
    statement = body[0]
    if not isinstance(statement.target, ast.Name) or statement.value is None:
        return False
    return _negative_type_ignore_comment(statement, lines)


CACHE_HELPERS = tuple(
    helper
    for helper in globals().values()
    if callable(helper)
    and getattr(helper, "__module__", None) == __name__
    and hasattr(helper, "__code__")
)
