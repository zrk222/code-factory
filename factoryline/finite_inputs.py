"""Bounded, source-only proofs for finite code-input profiles."""

import ast
import hashlib


def _fixed_literal_value(node):
    literal_types = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Constant):
            if type(current.value) not in literal_types:
                return False
        elif isinstance(current, ast.UnaryOp):
            if (
                not isinstance(current.op, (ast.UAdd, ast.USub))
                or not isinstance(current.operand, ast.Constant)
                or type(current.operand.value) not in {int, float, complex}
            ):
                return False
            stack.append(current.operand)
        elif isinstance(current, ast.Dict):
            if any(key is None for key in current.keys):
                return False
            stack.extend(ast.iter_child_nodes(current))
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set, ast.Load)):
            stack.extend(ast.iter_child_nodes(current))
        else:
            return False
    try:
        ast.literal_eval(node)
    except (
        ValueError,
        TypeError,
        SyntaxError,
        MemoryError,
        RecursionError,
        OverflowError,
    ):
        return False
    return True


def _finite_eval_comprehension(tree, call):
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    cursor = parents.get(call)
    while cursor is not None and not isinstance(cursor, ast.ListComp):
        if isinstance(
            cursor, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            return None
        cursor = parents.get(cursor)
    if cursor is None or len(cursor.generators) != 1:
        return None
    return cursor


def _finite_eval_domain(cursor, call):
    if cursor is None:
        return None
    generator = cursor.generators[0]
    if (
        generator.is_async
        or generator.ifs
        or not isinstance(generator.target, ast.Tuple)
        or not all(isinstance(n, ast.Name) for n in generator.target.elts)
        or not isinstance(generator.iter, (ast.List, ast.Tuple))
        or not 1 <= len(generator.iter.elts) <= 64
    ):
        return None
    names = [n.id for n in generator.target.elts]
    if len(set(names)) != len(names) or call.args[0].id not in names:
        return None
    target = generator.target.elts[names.index(call.args[0].id)]
    if any(
        n.id == target.id and n is not target and n is not call.args[0]
        for n in ast.walk(cursor)
        if isinstance(n, ast.Name)
    ):
        return None
    programs = []
    for row in generator.iter.elts:
        if (
            not isinstance(row, (ast.Tuple, ast.List))
            or len(row.elts) != len(names)
            or not _fixed_literal_value(row)
        ):
            return None
        value = row.elts[names.index(target.id)]
        if (
            not isinstance(value, ast.Constant)
            or type(value.value) is not str
            or len(value.value) > 4096
        ):
            return None
        try:
            expression = ast.parse(value.value, mode="eval")
        except (SyntaxError, ValueError, RecursionError):
            return None
        allowed = (
            ast.Expression,
            ast.Name,
            ast.Subscript,
            ast.Tuple,
            ast.List,
            ast.Load,
            ast.Constant,
            ast.BinOp,
            ast.BitOr,
        )
        if any(not isinstance(n, allowed) for n in ast.walk(expression)):
            return None
        programs.append(value.value)
    return generator.iter, programs


def _finite_eval_module_prefix(tree, comprehension):
    """Module initializer profile: later test bodies cannot run before this input."""
    prefix = []
    for statement in tree.body:
        if (
            isinstance(statement, (ast.Assign, ast.AnnAssign))
            and statement.value is comprehension
        ):
            return ast.Module(body=[*prefix, statement], type_ignores=[])
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            prefix.append(statement)
        elif isinstance(
            statement, (ast.Assign, ast.AnnAssign)
        ) and _fixed_literal_value(statement.value):
            prefix.append(statement)
        else:
            return None
    return None


def finite_literal_eval_input_witness(node, call_name, *, source_bytes, source_path):
    """Prove finite source input only, not the effects of resolving type objects."""
    if (
        call_name != "eval"
        or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "eval"
        or len(node.args) != 1
        or node.keywords
        or not isinstance(node.args[0], ast.Name)
        or not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
    ):
        return {}
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return {}

    def span(n):
        return [
            getattr(n, k, None)
            for k in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]

    matches = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and span(n) == span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return {}
    call = matches[0]
    comprehension = _finite_eval_comprehension(tree, call)
    domain = _finite_eval_domain(comprehension, call)
    if domain is None:
        return {}
    prefix = _finite_eval_module_prefix(tree, comprehension)
    if prefix is None:
        return {}
    from .runtime_audit_integrity import _closed_declaration_binding

    if not _closed_declaration_binding(prefix, call):
        return {}
    domain_node, programs = domain
    import json

    return {
        "schema": "factory.finite-eval-input.v1",
        "disposition": "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": span(call),
        "domain_span": span(domain_node),
        "comprehension_span": span(comprehension),
        "program_sha256": hashlib.sha256(
            json.dumps(programs, separators=(",", ":")).encode()
        ).hexdigest(),
        "domain_size": len(programs),
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "scope_profile": "module-initializer-literal-table",
        "input_effect": "CLOSED_LITERAL_TYPE_EXPRESSIONS",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def _finite_template_program_hash(program, value):
    import keyword

    if (
        not isinstance(value, str)
        or not value.isidentifier()
        or keyword.iskeyword(value)
    ):
        return None
    try:
        if len(program.encode("utf-8")) > 4096:
            return None
        tree = ast.parse(program, mode="exec")
    except (SyntaxError, ValueError, MemoryError, RecursionError, UnicodeError):
        return None
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.AsyncFunctionDef):
        return None
    function = tree.body[0]
    args = function.args
    if (
        function.decorator_list
        or args.posonlyargs
        or len(args.args) != 1
        or args.args[0].arg != value
        or args.vararg is not None
        or args.kwonlyargs
        or args.kwarg is not None
        or args.defaults
        or args.kw_defaults
        or not isinstance(function.returns, ast.Constant)
        or function.returns.value is not None
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Pass)
    ):
        return None
    args.args[0].arg = "FINITE_PARAMETER"
    return hashlib.sha256(program.encode("utf-8")).hexdigest(), ast.dump(
        tree, include_attributes=False
    )


def finite_template_program_hashes(template, parameter, values):
    """Hash every bounded rendering after checking one fixed async-function grammar."""
    if not isinstance(template, ast.JoinedStr) or not isinstance(parameter, str):
        return None
    pieces, holes = [], 0
    for item in template.values:
        if isinstance(item, ast.Constant) and type(item.value) is str:
            pieces.append(item.value)
        elif (
            isinstance(item, ast.FormattedValue)
            and isinstance(item.value, ast.Name)
            and item.value.id == parameter
            and item.conversion == -1
            and item.format_spec is None
        ):
            pieces.append(None)
            holes += 1
        else:
            return None
    if holes != 1 or not 1 <= len(values) <= 64:
        return None
    hashes, skeleton = [], None
    for value in values:
        program = "".join(value if part is None else part for part in pieces)
        result = _finite_template_program_hash(program, value)
        if result is None or (skeleton is not None and result[1] != skeleton):
            return None
        hashes.append(result[0])
        skeleton = result[1]
    return hashlib.sha256(skeleton.encode()).hexdigest(), hashes
