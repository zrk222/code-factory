"""Shared bounded native import policy and captured source views."""

from types import MappingProxyType
from dataclasses import dataclass
from pathlib import Path
import ast
import hashlib
from collections import defaultdict
from collections import OrderedDict


def structural_ast_fingerprint(tree):
    """Hash declared syntax with bounded per-call reuse, excluding sidecars."""
    memo, active = OrderedDict(), set()
    frames = [
        (iter((tree,)), hashlib.sha256(b"factory.structural-ast-digest.v3\0"), None)
    ]
    while frames:
        children, digest, identity = frames[-1]
        value = next(children, StopIteration)
        if value is StopIteration:
            result = digest.digest()
            frames.pop()
            active.discard(identity)
            memo[identity] = result
            if len(memo) > 512:
                memo.popitem(last=False)
            if frames:
                frames[-1][1].update(result)
            continue
        if isinstance(value, (ast.AST, list)):
            identity = id(value)
            if identity in memo:
                digest.update(memo[identity])
                continue
            if identity in active:
                raise ValueError("cyclic AST structural fields")
            leaf = _structural_ast_leaf_digest(value)
            if leaf is not None:
                digest.update(leaf)
                continue
            active.add(identity)
            children = (
                _structural_ast_fields(value)
                if isinstance(value, ast.AST)
                else iter(value)
            )
            frames.append(
                (
                    children,
                    hashlib.sha256(type(value).__name__.encode() + b"\0"),
                    identity,
                )
            )
        else:
            encoded = repr(value).encode("utf-8", "surrogatepass")
            digest.update(
                type(value).__name__.encode()
                + b":"
                + str(len(encoded)).encode()
                + b":"
                + encoded
            )
    return result.hex()


def _structural_ast_leaf_digest(value):
    """Use the compact stdlib encoding only for a bounded syntax subtree."""
    from itertools import islice

    if (
        not isinstance(value, ast.AST)
        or len(tuple(islice(_iter_ast_nodes(value), 129))) > 128
    ):
        return None
    return hashlib.sha256(
        b"BOUNDED_DUMP\0"
        + ast.dump(value, include_attributes=True).encode("utf-8", "surrogatepass")
    ).digest()


def _structural_ast_fields(node):
    """Enumerate canonical syntax fields, excluding mutable scanner sidecars."""
    for name in (*node._fields, *node._attributes):
        if hasattr(node, name):
            yield name
            yield getattr(node, name)


def _shell_import_aliases(nodes, audit, provider, *, package=None):
    """Retain import ambiguity and canonicalize source-owned relative providers."""
    from .mock_fixture_provenance import _django_import_rows

    origins, relative = defaultdict(set), {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                origins[alias.asname or root].add(alias.name if alias.asname else root)
        elif isinstance(node, ast.ImportFrom):
            rows = [
                (
                    alias.asname or alias.name,
                    "." * node.level + (node.module or "") + "." + alias.name,
                )
                for alias in node.names
            ]
            if node.level and package is not None:
                selected = _django_import_rows(node, package)
                if selected is not None:
                    rows = selected
                    relative.update(rows)
            for name, canonical in rows:
                origins[name].add(canonical)

    def protected(value):
        return (
            value.split(".")[0] in {"builtins", "importlib", "sys"}
            or value == provider
            or value.startswith(provider + ".")
            or provider.startswith(value + ".")
        )

    if any(
        len(values) > 1 and any(protected(value) for value in values)
        for values in origins.values()
    ):
        return None
    return {**audit._security_aliases(nodes), **relative}


def application_configuration_names():
    """Name bounded root inputs shared by capture, sealing and role rebuilding."""
    return frozenset(
        {
            "requirements.txt",
            "pyproject.toml",
            "tox.ini",
            "pytest.toml",
            ".pytest.toml",
            "pytest.ini",
            ".pytest.ini",
            "setup.cfg",
        }
    )


def application_profile_configuration(root, read_source, limit):
    """Capture unparsed selector bytes; neither presence nor content grants authority."""
    bindings, identities, valid = [], {}, True
    # The existing type-check configuration capture owns pyproject.toml/tox.ini.
    for name in sorted(
        application_configuration_names() - {"pyproject.toml", "tox.ini"}
    ):
        identity = {"path": name}
        try:
            raw = read_source(root, name)
        except (OSError, ValueError, RuntimeError) as exc:
            code = getattr(exc, "code", type(exc).__name__)
            missing = isinstance(exc, FileNotFoundError) or code == "E_SOURCE_MISSING"
            identity["state"] = "missing" if missing else code
            valid = valid and missing
        else:
            if len(raw) > limit:
                identity.update(state="oversized", bytes=len(raw))
                valid = False
            else:
                binding = {
                    "path": name,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
                bindings.append(binding)
                identity.update(binding, state="read")
        identities[name] = identity
    return bindings, identities, valid


@dataclass(frozen=True)
class CapturedImportInventory:
    """Own immutable lexical paths; source bytes and no-link capture are separate."""

    root: Path
    paths: object

    def __post_init__(self):
        """Copy a bounded canonical inventory without filesystem probes."""
        if (
            not isinstance(self.root, Path)
            or ".." in self.root.parts
            or not isinstance(self.paths, (list, tuple, set, frozenset))
            or len(self.paths) > 2000
        ):
            raise ValueError("invalid captured import inventory")
        owned = {}
        for path in self.paths:
            if not captured_import_path(self.root, path) or path in owned:
                raise ValueError("noncanonical captured import path")
            owned[path] = path
        object.__setattr__(self, "paths", MappingProxyType(owned))

    def __deepcopy__(self, memo):
        """Reuse this immutable path inventory when annotated syntax is copied."""
        memo[id(self)] = self
        return self


def captured_import_path(root, path):
    """Check lexical containment; no CWD resolution or source authority is added."""
    return (
        isinstance(path, Path)
        and path.is_relative_to(root)
        and path != root
        and ".." not in path.parts
        and ":" not in path.relative_to(root).as_posix()
    )


def import_source_choices(
    root, path, node, module, imported, *, captured_inventory=None
):
    """Generate the existing bounded live/captured candidates in one place."""
    parts = module.split(".") if module else []
    if any(not part.isidentifier() for part in parts):
        return []
    choices = []
    for base in import_source_bases(
        root, path, node, captured_inventory=captured_inventory
    ):
        target = base.joinpath(*parts)
        children = import_child_source_choices(target, node, imported)
        if children is None:
            return []
        choices.extend(children)
        values = (
            (target.with_suffix(".py"), target / "__init__.py")
            if parts
            else (target / "__init__.py",)
        )
        choices.extend((value, "package") for value in values)
    return choices


def import_source_bases(root, path, node, *, captured_inventory=None):
    """Share legacy bases and, for captured sources, their exact package root."""
    if isinstance(node, ast.ImportFrom) and node.level:
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
        return [base]
    bases = [path.parent, root, root / "src"]
    if captured_inventory is None:
        return bases
    package_root = _captured_regular_package_root(root, path, captured_inventory)
    if package_root is not None:
        bases.append(package_root)
        # A captured application may be launched from an inner regular package
        # directory. Keep every lexical package root as a candidate; the existing
        # unique-source resolver still rejects competing modules or shadows.
        paths = _captured_path_set(root, captured_inventory)
        directory = path.parent
        while directory != root and directory / "__init__.py" in paths:
            bases.append(directory)
            directory = directory.parent
    return list(
        dict.fromkeys(base for base in bases if _captured_import_base(root, base))
    )


def _captured_import_base(root, path):
    return path == root or captured_import_path(root, path)


def _captured_regular_package_root(root, path, inventory):
    """Return the outer root of the caller's contiguous captured regular package."""
    paths = _captured_path_set(root, inventory)
    if paths is None or path not in paths:
        return None
    directory = path.parent
    package_root = None
    while directory != root and directory / "__init__.py" in paths:
        package_root = directory.parent
        directory = directory.parent
    return package_root


def _script_statements(statements):
    """Ignore standalone string expressions when matching a startup script."""
    return [
        node
        for node in statements
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]


def _script_import_layout(program, plain_imports, provider_import):
    imported = tuple(sorted(ast.dump(node) for node in program))
    plain = tuple(sorted(plain_imports))
    with_provider = tuple(sorted((*plain_imports, provider_import)))
    if imported not in (plain, with_provider):
        return None
    return imported == with_provider


def _script_main_guard_matches(function, guard, empty_args):
    signature = (
        function.name,
        ast.dump(function.args),
        bool(function.decorator_list),
        function.returns is None,
        bool(getattr(function, "type_params", ())),
    )
    return signature == ("main", empty_args, False, True, False) and ast.dump(
        guard
    ) == ast.dump(
        ast.parse(f'if __name__ == "__main__":\n    {function.name}()').body[0]
    )


def _script_entry_setting(body):
    try:
        setting = body[0].value.args[1].value
    except (AttributeError, IndexError):
        return None
    return setting if isinstance(setting, str) else None


def _script_body_matches(body, module_provider, setting, provider):
    messages = [
        node.value
        for node in ast.walk(body[1])
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    statements = [f'os.environ.setdefault("DJANGO_SETTINGS_MODULE", {setting!r})']
    if not module_provider:
        statements.append(
            f"try:\n    {provider}\nexcept ImportError as exc:\n    raise ImportError({messages[0]!r}) from exc"
            if isinstance(body[1], ast.Try) and len(messages) == 1
            else provider
        )
    statements.append("execute_from_command_line(sys.argv)")
    expected = ast.parse("\n".join(statements)).body
    return [ast.dump(node) for node in body] == [ast.dump(node) for node in expected]


def _management_script_contract(
    tree, plain_imports, provider_import, empty_args, provider
):
    program = _script_statements(tree.body)
    if len(program) not in (4, 5):
        return None
    function, guard = program[-2:]
    if not isinstance(function, ast.FunctionDef):
        return None
    module_provider = _script_import_layout(
        program[:-2], plain_imports, provider_import
    )
    if module_provider is None:
        return None
    if not _script_main_guard_matches(function, guard, empty_args):
        return None
    body = _script_statements(function.body)
    if len(body) != (2 if module_provider else 3):
        return None
    setting = _script_entry_setting(body)
    if setting is None:
        return None
    return (
        (setting, body, module_provider)
        if _script_body_matches(body, module_provider, setting, provider)
        else None
    )


def _script_import_resolution_closed(context, resolved_ast_name):
    index = context["index"]
    return not any(
        isinstance(node, (ast.Name, ast.Attribute))
        and resolved_ast_name(node, context["aliases"][owner]).startswith(
            ("sys.path", "sys.modules", "importlib.")
        )
        for owner, source in index.snapshots.items()
        for node in ast.walk(source)
    )


def _captured_script_imports_safe(
    context, path, tree, builtin_identity_closed, signing_provider_clear
):
    index = context["index"]
    closure = eager_import_closure(index, (path,), {"django"})
    script_sources = {path, *(parent / "__init__.py" for parent in path.parents)}
    aliases = context["aliases"][path]
    return (
        index.validate(path)
        and builtin_identity_closed(tree, aliases, {"__name__", "ImportError"})
        and signing_provider_clear(tree, aliases, "django", context=context)
        and closure["closed"]
        and all(Path(row["path"]) in script_sources for row in closure["sources"])
    )


def _script_initializers(index, sources):
    return {
        parent / "__init__.py"
        for source in sources
        for parent in source.parents
        if parent / "__init__.py" in index.snapshots
    }


def _captured_initializer_is_safe(index, path):
    return index.validate(path) and all(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for node in index.snapshots[path].body
    )


def _captured_script_target(context, path, parts, origin, setting):
    index = context["index"]
    prefix = setting.split(".")
    settings = path.parent.joinpath(*prefix).with_suffix(".py")
    candidate = path.parent.joinpath(*parts).with_suffix(".py")
    selected_settings = context.get("selected_settings_path")
    if not (
        settings in index.snapshots
        and candidate in index.snapshots
        and (
            settings == selected_settings
            if selected_settings is not None
            else parts == prefix
        )
        and Path(origin).parent == settings.parent
    ):
        return None
    if not all(index.validate(item) for item in (settings, candidate)):
        return None
    initializers = _script_initializers(index, (path, settings, candidate))
    if not all(_captured_initializer_is_safe(index, item) for item in initializers):
        return None
    return candidate


def captured_script_module(context, parts, origin):
    """Resolve ambiguity only for a closed, ordered default management startup."""
    from .review_audits import _resolved_ast_name
    from .semantic_credential_sensor import (
        _security_builtin_identity_closed,
        _signing_provider_clear,
    )

    index = context["index"]
    if not _script_import_resolution_closed(context, _resolved_ast_name):
        return None
    plain_imports = [
        ast.dump(ast.parse(text).body[0]) for text in ("import os", "import sys")
    ]
    provider = "from django.core.management import execute_from_command_line"
    provider_import = ast.dump(ast.parse(provider).body[0])
    empty_args = ast.dump(ast.parse("def main(): pass").body[0].args)
    selected = set()
    for path, tree in index.snapshots.items():
        contract = _management_script_contract(
            tree, plain_imports, provider_import, empty_args, provider
        )
        if contract is None:
            continue
        setting, _body, _module_provider = contract
        if not _captured_script_imports_safe(
            context,
            path,
            tree,
            _security_builtin_identity_closed,
            _signing_provider_clear,
        ):
            continue
        candidate = _captured_script_target(context, path, parts, origin, setting)
        if candidate is not None:
            selected.add(candidate)
    return next(iter(selected)) if len(selected) == 1 else None


def _captured_path_set(root, inventory):
    if type(inventory) is CapturedImportInventory:
        return inventory.paths if inventory.root == root else None
    elif type(inventory) in (set, frozenset, tuple, list):
        paths = inventory
    else:
        return None
    try:
        if any(not captured_import_path(root, path) for path in paths):
            return None
        return frozenset(paths)
    except (TypeError, ValueError):
        return None


def import_child_source_choices(target, node, imported):
    """Generate an optional from-import child without accepting invalid names."""
    if not isinstance(node, ast.ImportFrom) or not imported or imported == "*":
        return []
    if not imported.isidentifier():
        return None
    child = target / imported
    return [(child.with_suffix(".py"), "child"), (child / "__init__.py", "child")]


def import_source_symbol(
    root, path, node, module, imported, source, *, captured, captured_inventory=None
):
    """Distinguish a captured child module from a symbol exported by a module."""
    if imported is None:
        return None
    if not captured:
        return imported
    children = {
        choice
        for choice, kind in import_source_choices(
            root,
            path,
            node,
            module,
            imported,
            captured_inventory=captured_inventory if captured else None,
        )
        if kind == "child"
    }
    return None if source in children else imported


def _captured_import_statement(node, name):
    if isinstance(node, ast.ImportFrom):
        return not node.level and node.module == name
    return isinstance(node, ast.Import) and any(
        alias.name == name for alias in node.names
    )


def captured_import_module(source, path, name):
    """Resolve an imported module through the same strict caller-relative search."""
    tree = source.snapshots.get(path)
    if not isinstance(tree, ast.Module) or not source.validate(path):
        return False, None
    parents = getattr(source, "parents", {}).get(path)
    nodes = (
        ast.walk(tree)
        if parents is None
        else {
            parent
            for parent in parents.values()
            if isinstance(parent, (ast.Import, ast.ImportFrom))
        }
    )
    statements = [node for node in nodes if _captured_import_statement(node, name)]
    if not statements:
        return False, None
    inventory = captured_import_inventory(source)
    targets = {
        resolve_import_source(
            source.root,
            path,
            node,
            name,
            inventory,
            captured=True,
            source_index=source,
        )
        for node in statements
    }
    if len(targets) != 1 or None in targets:
        return True, None
    target = next(iter(targets))
    return True, target if source.validate(target) else None


def captured_import_inventory(source):
    """Reuse immutable path validation while checking the exact current keyset."""
    paths = frozenset(source.snapshots)
    key = source.root, paths
    cached = getattr(source, "_captured_symbol_import_inventory", None)
    if cached is None or cached[0] != key:
        cached = key, CapturedImportInventory(source.root, paths)
        source._captured_symbol_import_inventory = cached
    return cached[1]


def resolve_import_source(
    root,
    path,
    node,
    module,
    eligible,
    imported=None,
    *,
    captured=False,
    source_index=None,
    package_binding_exclude=None,
):
    """Resolve one source candidate, retaining legacy live-path behavior."""
    if captured:
        if not captured_import_inventory_matches(root, path, node, module, eligible):
            return None
        root_abs, sources = root, eligible.paths
    else:
        root_abs = root.resolve()
        sources = (
            eligible
            if isinstance(eligible, dict)
            else {p.resolve(): p for p in eligible}
        )
    matches = {"child": set(), "package": set()}
    for choice, kind in import_source_choices(
        root,
        path,
        node,
        module,
        imported,
        captured_inventory=eligible if captured else None,
    ):
        selected = choice if captured else live_import_path(choice, root_abs)
        if selected in sources and captured_import_path(root_abs, selected):
            matches[kind].add(sources[selected])
    if (
        captured
        and imported
        and source_index is not None
        and len(matches["child"]) == len(matches["package"]) == 1
    ):
        child = next(iter(matches["child"]))
        package = next(iter(matches["package"]))
        if package.name == "__init__.py" and _captured_child_module_matches(
            source_index,
            package,
            child,
            imported,
            inventory=eligible,
            exclude=package_binding_exclude,
        ):
            return child
    if captured and imported and source_index and len(matches["package"]) == 1:
        package = next(iter(matches["package"]))
        if package.name == "__init__.py" and not matches["child"]:
            binding = _captured_package_binding(
                source_index,
                package,
                imported,
                eligible,
                exclude=package_binding_exclude,
            )
            return (
                package
                if isinstance(binding, ast.stmt)
                and not isinstance(binding, (ast.Import, ast.ImportFrom))
                else None
            )
    return unique_import_source(matches, strict=captured)


def _captured_child_module_matches(
    source_index, package, child, imported, *, inventory, exclude=None
):
    """Select a child only when its package initializer has no conflicting export."""
    binding = _captured_package_binding(
        source_index, package, imported, inventory, exclude=exclude
    )
    if not source_index.validate(child) or not _captured_child_module_identity_stable(
        source_index, child
    ):
        return False
    if binding is False:
        return True
    if not isinstance(binding, ast.stmt):
        return False
    statement = binding
    if isinstance(statement, ast.Import):
        aliases = [
            alias
            for alias in statement.names
            if (alias.asname or alias.name.split(".")[0]) == imported
        ]
        if len(aliases) != 1:
            return False
        target = resolve_import_source(
            source_index.root,
            package,
            statement,
            aliases[0].name,
            inventory,
            captured=True,
            source_index=source_index,
            package_binding_exclude=statement,
        )
        return target == child
    if not isinstance(statement, ast.ImportFrom):
        return False
    aliases = [
        alias
        for alias in statement.names
        if alias.name != "*" and (alias.asname or alias.name) == imported
    ]
    if len(aliases) != 1:
        return False
    alias = aliases[0]
    target = resolve_import_source(
        source_index.root,
        package,
        statement,
        statement.module or "",
        inventory,
        alias.name,
        captured=True,
        source_index=source_index,
        package_binding_exclude=statement,
    )
    return (
        target == child
        and import_source_symbol(
            source_index.root,
            package,
            statement,
            statement.module or "",
            alias.name,
            target,
            captured=True,
            captured_inventory=inventory,
        )
        is None
    )


def _captured_package_binding(source_index, package, imported, inventory, *, exclude):
    """Return one finite initializer binding, False for none, or None if uncertain."""
    from .credential_role_constructor_provider import (
        SourceSnapshotIndex,
        binding_statements,
    )
    from .credential_role_identity_effects import source_symbol_index

    if not isinstance(source_index, SourceSnapshotIndex):
        return None
    snapshots = source_index.snapshots
    paths = set(snapshots)
    if (
        source_index.root != inventory.root
        or paths != set(source_index.source_bytes)
        or paths != set(source_index.inventory)
        or set(inventory.paths) != paths
        or package not in paths
        or not source_index.bounded
    ):
        return None
    symbols = source_symbol_index(source_index)
    if (
        not isinstance(symbols, dict)
        or symbols.get("source") is not source_index
        or symbols.get("modules") is not snapshots
        or symbols.get("module_paths") != source_index.module_paths()
        or not source_index.validate(package)
    ):
        return None
    tree = snapshots[package]
    if not isinstance(tree, ast.Module) or package.name != "__init__.py":
        return None
    bindings = [
        statement
        for statement in binding_statements(tree.body, imported)
        if statement is not exclude
    ]
    if len(bindings) > 1:
        return None
    statement = bindings[0] if bindings else None
    all_bindings = binding_statements(tree.body, imported)
    allowed_import = None
    if (
        isinstance(exclude, (ast.Import, ast.ImportFrom))
        and exclude in tree.body
        and all_bindings == [exclude]
    ):
        allowed_import = exclude
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        allowed_import = statement
    if _captured_package_namespace_dynamic(tree, allowed_import=allowed_import):
        return None
    if not bindings:
        return False
    return statement


def _captured_package_namespace_dynamic(tree, *, allowed_import=None):
    """Reject initializer effects outside literal declarations and one checked re-export."""
    from .credential_role_identity_effects import (
        _definition_effects_unknown,
        _immutable_default,
    )

    return not isinstance(tree, ast.Module) or any(
        not _captured_package_statement_safe(
            statement,
            allowed_import,
            _definition_effects_unknown,
            _immutable_default,
        )
        for statement in tree.body
    )


def _captured_package_statement_safe(
    statement, allowed_import, definition_unknown, immutable_default
):
    protected = frozenset(
        (
            "__build_class__",
            "__builtins__",
            "__dir__",
            "__file__",
            "__getattr__",
            "__getattribute__",
            "__loader__",
            "__name__",
            "__package__",
            "__path__",
            "__spec__",
        )
    )
    protected_set = set(protected)
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return statement.name not in protected and not definition_unknown(statement)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        if statement is allowed_import:
            if len(statement.names) != 1:
                return False
            names = (
                [item.asname or item.name.split(".")[0] for item in statement.names]
                if isinstance(statement, ast.Import)
                else [item.asname or item.name for item in statement.names]
            )
            return "*" not in names and not (set(names) & protected_set)
        return (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "__future__"
            and all(item.name != "*" for item in statement.names)
            and not (
                {item.asname or item.name for item in statement.names} & protected_set
            )
        )
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Expr):
        return (
            isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        )
    if isinstance(statement, ast.Assign):
        return (
            bool(statement.targets)
            and all(
                isinstance(target, ast.Name) and target.id not in protected
                for target in statement.targets
            )
            and _captured_package_literal(statement.value, immutable_default)
        )
    return False


def _captured_package_literal(node, immutable_default):
    pending = [node]
    while pending:
        current = pending.pop()
        if immutable_default(current) or _captured_package_unary_literal(current):
            continue
        if isinstance(current, ast.Constant):
            if type(current.value) not in {
                type(None),
                bool,
                int,
                float,
                complex,
                str,
                bytes,
                type(Ellipsis),
            }:
                return False
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set)):
            if isinstance(current, ast.Set) and any(
                not _captured_package_hashable(item, immutable_default)
                for item in current.elts
            ):
                return False
            pending.extend(current.elts)
        elif isinstance(current, ast.Dict):
            if any(
                key is None or not _captured_package_hashable(key, immutable_default)
                for key in current.keys
            ):
                return False
            pending.extend(current.values)
        else:
            return False
    return True


def _captured_package_hashable(node, immutable_default):
    pending = [node]
    while pending:
        current = pending.pop()
        if immutable_default(current) or _captured_package_unary_literal(current):
            continue
        if isinstance(current, ast.Constant) and type(current.value) in {
            type(None),
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            type(Ellipsis),
        }:
            continue
        if isinstance(current, ast.Tuple):
            pending.extend(current.elts)
            continue
        return False
    return True


def _captured_package_unary_literal(node):
    if not isinstance(node, ast.UnaryOp) or not isinstance(node.operand, ast.Constant):
        return False
    value = node.operand.value
    return (
        isinstance(node.op, ast.Not)
        and type(value)
        in {type(None), bool, int, float, complex, str, bytes, type(Ellipsis)}
        or isinstance(node.op, (ast.UAdd, ast.USub))
        and type(value) in {int, float, complex}
        or isinstance(node.op, ast.Invert)
        and type(value) in {bool, int}
    )


def _captured_child_module_identity_stable(source_index, child):
    """Reject captured child modules that replace their own import identity."""
    from . import finite_capture, review_audits
    from .semantic_credential_sensor import _provider_path_conflicts

    tree = source_index.snapshots[child]
    nodes = tuple(ast.walk(tree))
    parents = {
        id(node): parent for parent in nodes for node in ast.iter_child_nodes(parent)
    }
    try:
        mutations = finite_capture.finite_provider_mutation_index(
            nodes,
            review_audits._security_aliases(nodes),
            review_audits,
            parents,
        )
    except (RecursionError, TypeError, ValueError):
        return False
    return not any(
        _provider_path_conflicts(path, attribute, "sys.modules")
        for path, attribute in mutations
    )


def captured_import_inventory_matches(root, path, node, module, inventory):
    """Require the captured caller and reject relative package-root underflow."""
    return (
        type(inventory) is CapturedImportInventory
        and inventory.root == root
        and path in inventory.paths
        and captured_relative_import(root, path, node)
        and captured_import_parent_modules(root, path, node, module, inventory)
    )


def captured_import_parent_modules(root, path, node, module, inventory):
    """Reject dotted imports whose ancestor resolves to a non-package module."""
    parts = module.split(".") if module else []
    for base in import_source_bases(root, path, node, captured_inventory=inventory):
        for length in range(1, len(parts)):
            if base.joinpath(*parts[:length]).with_suffix(".py") in inventory.paths:
                return False
    return True


def captured_relative_import(root, path, node):
    """Reject a relative import that leaves its lexical source/package root."""
    if not captured_import_path(root, path):
        return False
    if not isinstance(node, ast.ImportFrom) or not node.level:
        return True
    boundary = root / "src" if path.is_relative_to(root / "src") else root
    base = path.parent
    for _ in range(node.level - 1):
        base = base.parent
        if not base.is_relative_to(boundary) or base == boundary:
            return False
    return base != boundary


def live_import_path(choice, root):
    """Retain the existing bounded regular-file checks for live resolution."""
    if not choice.is_file():
        return None
    resolved = choice.resolve()
    return (
        resolved
        if resolved.is_relative_to(root)
        and choice.is_file()
        and not choice.is_symlink()
        else None
    )


def unique_import_source(matches, *, strict):
    """Reject ambiguity and cross-root child/package contradictions."""
    children, packages = matches["child"], matches["package"]
    if strict and len(packages) > 1:
        return None
    if children:
        if len(children) != 1:
            return None
        child = next(iter(children))
        if strict and packages:
            # Paths cannot establish which existing package attribute is exported.
            return None
        return child
    return next(iter(packages)) if len(packages) == 1 else None


def import_resolution_helpers():
    """Expose current resolver bindings/code to the existing native cache epoch."""
    from .credential_role_constructor_provider import (
        SourceSnapshotIndex,
        _binds,
        binding_occurrences,
        binding_statements,
    )
    from .credential_role_identity_effects import (
        _definition_effects_unknown,
        _immutable_default,
        source_symbol_index,
    )
    from .finite_capture import (
        _provider_alias_bindings,
        _provider_call_argument,
        _record_provider_capture,
        _provider_mutation_facts,
        _provider_mutation_for_node,
        _provider_paths,
        _record_provider_paths,
        _reflective_provider_write,
        _foreign_provider_mutation_facts,
        _foreign_provider_inputs,
        _project_provider_inventory,
        _foreign_provider_source_bytes,
        _foreign_provider_source_mutations,
        finite_provider_mutation_index,
    )
    from .review_audits import _resolved_ast_name, _security_aliases
    from .semantic_credential_sensor import _provider_path_conflicts

    return (
        application_configuration_names,
        application_profile_configuration,
        captured_import_module,
        _captured_import_statement,
        captured_import_inventory,
        captured_script_module,
        _script_statements,
        _script_import_layout,
        _script_main_guard_matches,
        _script_entry_setting,
        _script_body_matches,
        _management_script_contract,
        _script_import_resolution_closed,
        _captured_script_imports_safe,
        _script_initializers,
        _captured_initializer_is_safe,
        _captured_script_target,
        _full_repository_workspace_cached_source_entry,
        _full_repository_workspace_cache_load_source,
        _workspace_security_configuration,
        _full_repository_workspace_security_context,
        _shell_import_aliases,
        CapturedImportInventory,
        CapturedImportInventory.__init__,
        CapturedImportInventory.__post_init__,
        CapturedImportInventory.__deepcopy__,
        captured_import_path,
        _captured_import_base,
        _captured_path_set,
        _captured_regular_package_root,
        import_source_choices,
        import_source_bases,
        import_child_source_choices,
        import_source_symbol,
        binding_occurrences,
        binding_statements,
        _binds,
        source_symbol_index,
        _definition_effects_unknown,
        _immutable_default,
        _captured_child_module_matches,
        _captured_package_binding,
        _captured_package_namespace_dynamic,
        _captured_package_statement_safe,
        _captured_package_literal,
        _captured_package_hashable,
        _captured_package_unary_literal,
        _captured_child_module_identity_stable,
        finite_provider_mutation_index,
        _provider_alias_bindings,
        _provider_call_argument,
        _record_provider_capture,
        _provider_mutation_facts,
        _provider_mutation_for_node,
        _provider_paths,
        _record_provider_paths,
        _reflective_provider_write,
        _foreign_provider_mutation_facts,
        _foreign_provider_inputs,
        _project_provider_inventory,
        _foreign_provider_source_bytes,
        _foreign_provider_source_mutations,
        _resolved_ast_name,
        _security_aliases,
        _provider_path_conflicts,
        ast.walk,
        ast.iter_child_nodes,
        resolve_import_source,
        captured_import_inventory_matches,
        captured_import_parent_modules,
        live_import_path,
        captured_relative_import,
        unique_import_source,
        finite_key_reflection_reads,
        _finite_loop_reflection_reads,
        _finite_dictionary_key_domain,
        _finite_dictionary_key_use_closed,
        _finite_key_reflection_call,
        _finite_table_peers_closed,
        close_selected_import_sources,
        eager_import_closure,
        _eager_import_model_roots,
        _eager_import_edges,
        _eager_import_target,
        import_resolution_helpers,
        *(
            getattr(value, "__func__", value)
            for value in vars(SourceSnapshotIndex).values()
            if callable(value)
        ),
    )


def finite_key_reflection_reads(
    tree, aliases, roots, builtin_guard, *, index=None, path=None, evidence=None
):
    """Project only proved disjoint finite reflected fields; retain value effects."""
    if (
        index is None
        or not index.validate(path)
        or index.snapshots[path] is not tree
        or not builtin_guard(tree, aliases, {"list", "getattr", "hasattr", "setattr"})
    ):
        return set()
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    reads = set()
    for loop in (node for node in tree.body if isinstance(node, ast.For)):
        domain = _finite_dictionary_key_domain(tree, loop, parents, aliases)
        if domain is None:
            continue
        key, fields, declaration = domain
        if not _finite_table_peers_closed(index, path, declaration.targets[0].id):
            continue
        reads.update(
            _finite_loop_reflection_reads(
                loop, parents, aliases, roots, domain, index, path, evidence
            )
        )
    return reads


def _finite_loop_reflection_reads(
    loop, parents, aliases, roots, domain, index, path, evidence
):
    from .review_audits import _resolved_ast_name
    from .semantic_credential_sensor import _provider_path_conflicts

    key, fields, declaration = domain
    reads = set()
    for node in ast.walk(loop):
        if not _finite_key_reflection_call(node, loop, parents, aliases, key):
            continue
        receiver = _resolved_ast_name(node.args[0], aliases)
        if not receiver or any(
            _provider_path_conflicts(receiver + "." + field, "*", root)
            for field in fields
            for root in roots
        ):
            continue
        reads.add(id(node))
        reads.update(id(child) for child in ast.walk(node.args[0]))
        if evidence is not None:
            evidence.append(
                {
                    "path": path.as_posix(),
                    "sha256": index.inventory[path],
                    "span": [
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                    ],
                    "declaration_span": [
                        declaration.lineno,
                        declaration.col_offset,
                        declaration.end_lineno,
                        declaration.end_col_offset,
                    ],
                    "fields": sorted(fields),
                }
            )
    return reads


def _finite_dictionary_key_domain(tree, loop, parents, aliases):
    from .credential_role_constructor_provider import binding_occurrences
    from .review_audits import _resolved_ast_name

    if (
        not isinstance(loop.target, ast.Tuple)
        or len(loop.target.elts) != 2
        or not all(isinstance(n, ast.Name) for n in loop.target.elts)
    ):
        return None
    iterator = loop.iter
    if (
        not isinstance(iterator, ast.Call)
        or _resolved_ast_name(iterator.func, aliases) not in {"list", "builtins.list"}
        or len(iterator.args) != 1
        or iterator.keywords
    ):
        return None
    items = iterator.args[0]
    if (
        not isinstance(items, ast.Call)
        or items.args
        or items.keywords
        or not isinstance(items.func, ast.Attribute)
        or items.func.attr != "items"
        or not isinstance(items.func.value, ast.Name)
    ):
        return None
    name, key = items.func.value.id, loop.target.elts[0].id
    rows = binding_occurrences(tree.body, name)
    declaration = parents.get(id(rows[0])) if len(rows) == 1 else None
    if (
        not isinstance(declaration, ast.Assign)
        or len(declaration.targets) != 1
        or declaration not in tree.body
        or tree.body.index(loop) != tree.body.index(declaration) + 1
        or not isinstance(declaration.value, ast.Dict)
    ):
        return None
    fields = declaration.value.keys
    if not fields or not all(
        isinstance(field, ast.Constant)
        and isinstance(field.value, str)
        and not field.value.startswith("_")
        for field in fields
    ):
        return None
    if binding_occurrences(loop.body, key) or not _finite_dictionary_key_use_closed(
        tree, name, rows[0], items.func.value
    ):
        return None
    return key, frozenset(field.value for field in fields), declaration


def _finite_dictionary_key_use_closed(tree, name, declaration, receiver):
    """A unique literal table may have only the certified iterator receiver use."""
    return all(
        node is declaration or node is receiver
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == name
    )


def _finite_table_peers_closed(index, owner, name):
    from .mock_fixture_provenance import _django_name, _django_import_rows
    from .credential_role_identity_effects import source_symbol_index
    from .finite_capture import _provider_paths, _provider_alias_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain
    from . import review_audits as audit

    symbols = source_symbol_index(index)
    canonical = _django_name(symbols, owner) + "." + name
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return False
        nodes, aliases = list(ast.walk(tree)), {}
        package = _django_name(symbols, path).rpartition(".")[0]
        for node in nodes:
            rows = _django_import_rows(node, package)
            if rows is not None:
                aliases.update(rows)
            elif isinstance(node, ast.ImportFrom):
                selected = resolve_import_source(
                    index.root,
                    path,
                    node,
                    node.module or "",
                    captured_import_inventory(index),
                    captured=True,
                )
                if selected == owner:
                    return False
        if _provider_identity_uncertain(
            tree, aliases, roots=("builtins",), selected_paths=True
        ):
            return False
        if path != owner:
            bindings = _provider_alias_bindings(nodes)
            if (
                canonical in aliases.values()
                or _provider_identity_uncertain(
                    tree, aliases, roots=(canonical,), selected_paths=True
                )
                or any(
                    canonical in _provider_paths(node, aliases, audit, bindings)[0]
                    for node in nodes
                    if isinstance(node, (ast.Name, ast.Attribute))
                )
            ):
                return False
    return True


def _finite_key_reflection_call(node, loop, parents, aliases, key):
    from .review_audits import _resolved_ast_name

    if not isinstance(node, ast.Call) or node.keywords:
        return False
    name = _resolved_ast_name(node.func, aliases).removeprefix("builtins.")
    if name not in {"getattr", "hasattr", "setattr"} or len(node.args) not in (
        {3} if name == "setattr" else {2, 3} if name == "getattr" else {2}
    ):
        return False
    if not isinstance(node.args[1], ast.Name) or node.args[1].id != key:
        return False
    current = node
    while (parent := parents.get(id(current))) is not loop:
        if parent is None or isinstance(
            parent,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.For,
                ast.While,
                ast.Lambda,
            ),
        ):
            return False
        current = parent
    return True


def close_selected_import_sources(context, selection, sites, modeled_roots):
    """Record a captured import closure and retain sources only when it is complete."""
    if not sites:
        return sites
    proof = eager_import_closure(context["index"], sites, modeled_roots)
    context.setdefault("selected_import_closures", {})[selection.as_posix()] = proof
    return sites if proof["closed"] else None


def eager_import_closure(index, entries, modeled_roots):
    """Close captured import effects; external nonmodels remain explicit premises."""
    inventory = captured_import_inventory(index)
    pending, seen, unresolved, modeled = list(entries), set(), [], []
    standard = _eager_import_model_roots()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        if not index.validate(path):
            unresolved.append(
                {"path": path.as_posix(), "reason": "stale_import_source"}
            )
            continue
        seen.add(path)
        pending.extend(
            parent / "__init__.py"
            for parent in path.parents
            if parent / "__init__.py" in index.snapshots
        )
        for node in ast.walk(index.snapshots[path]):
            for module, imported in _eager_import_edges(node):
                result = _eager_import_target(
                    index,
                    inventory,
                    path,
                    node,
                    module,
                    imported,
                    standard,
                    modeled_roots,
                )
                event = {
                    "path": path.as_posix(),
                    "sha256": index.inventory[path],
                    "span": [
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                    ],
                    "module": "." * getattr(node, "level", 0) + module,
                }
                if result.get("source") is not None:
                    pending.append(result["source"])
                elif result.get("model") is not None:
                    modeled.append({**event, "model": result["model"]})
                else:
                    unresolved.append({**event, "reason": result["reason"]})
    return {
        "closed": not unresolved,
        "unresolved": unresolved,
        "modeled": modeled,
        "sources": [
            {"path": p.as_posix(), "sha256": index.inventory[p]} for p in sorted(seen)
        ],
    }


def _eager_import_model_roots():
    import sys

    return frozenset(sys.stdlib_module_names) | frozenset(sys.builtin_module_names)


def _eager_import_edges(node):
    if isinstance(node, ast.Import):
        return [(alias.name, None) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        return [
            (node.module or "", alias.name if alias.name != "*" else None)
            for alias in node.names
        ]
    return []


def _eager_import_target(
    index, inventory, path, node, module, imported, standard, models
):
    target = resolve_import_source(
        index.root,
        path,
        node,
        module,
        inventory,
        imported=imported,
        captured=True,
        source_index=index,
    )
    if target is not None:
        return {"source": target}
    choices = import_source_choices(
        index.root, path, node, module, imported, captured_inventory=inventory
    )
    if any(candidate in index.snapshots for candidate, _ in choices):
        return {"reason": "ambiguous_eager_import_source"}
    if getattr(node, "level", 0):
        return {"reason": "uncaptured_relative_import_effects"}
    prefixes = [
        module.split(".")[:length] for length in range(1, len(module.split(".")))
    ]
    if any(
        base.joinpath(*parts).with_suffix(".py") in index.snapshots
        or base.joinpath(*parts, "__init__.py") in index.snapshots
        for base in import_source_bases(
            index.root, path, node, captured_inventory=inventory
        )
        for parts in prefixes
    ):
        return {"reason": "captured_eager_import_parent_shadow"}
    root = module.partition(".")[0]
    if root in models:
        return {"model": "existing_framework_api_model"}
    if root in (standard or ()):
        return {"model": "python_standard_library_model"}
    return {"reason": "unmodeled_eager_import_effects"}


def native_import_profile(file_count):
    """Select a bounded static import profile or return an unsupported profile for invalid file counts."""
    if type(file_count) is not int or not 0 <= file_count <= 2000:
        return {"id": "unsupported", "bindings": 0, "characters": 0}
    expanded = file_count > 460
    return {
        "id": "expanded-static-v1" if expanded else "standard-static-v1",
        "bindings": 8192 if expanded else 4096,
        "characters": 2097152 if expanded else 1048576,
    }


def new_import_views(file_count):
    """Create an empty resolved-import view with counters and the profile selected for the source inventory size."""
    return {
        "resolved": {},
        "bindings": 0,
        "characters": 0,
        "profile": native_import_profile(file_count),
    }


def import_configuration(identity, collection, file_count):
    """Combine import identity and collection metadata with the selected native import-context profile."""
    return {
        **identity,
        "pytest_collection": collection or {"state": "default"},
        "native_import_context": native_import_profile(file_count),
    }


def import_context_metadata(files, edges, configuration):
    """Describe the one-hop AST import model, resolved edges, configuration sources, and inventory-sized profile."""
    return {
        "mode": "one_local_import_hop_ast_only",
        "resolved_edges": edges,
        "edge_count": len(edges),
        "configuration_sources": configuration,
        "import_context_profile": native_import_profile(len(files)),
    }


def capture_project_imports(views, path, imports, eligible):
    """Retain the whole immutable view or discard it on either hard limit."""
    if not views:
        return
    profile = views.get("profile", native_import_profile(0))
    if profile not in [native_import_profile(n) for n in (0, 461)]:
        views.clear()
        return
    views.setdefault("eligible", MappingProxyType(eligible))
    views["bindings"] += len(imports)
    views["characters"] += sum(
        len(alias) + len(str(source)) + len(symbol or "")
        for alias, (source, symbol) in imports.items()
    )
    if (
        views["bindings"] > profile["bindings"]
        or views["characters"] > profile["characters"]
    ):
        views.clear()
        return
    views["resolved"][path] = MappingProxyType(dict(imports))


def project_import_views(views, snapshots):
    """Require exactly the original complete resolver inventory."""
    if (
        views
        and views.get("profile", native_import_profile(0))
        == native_import_profile(len(snapshots))
        and views.get("eligible") == {p.resolve(): p for p in snapshots}
        and views["resolved"].keys() == snapshots.keys()
    ):
        return MappingProxyType(dict(views["resolved"]))
    return None


def _full_repository_workspace_cached_source_entry(generation):
    from . import context_efficiency as engine

    cached, key = (
        engine._FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE,
        generation.get("workspace_prefix_cache_key"),
    )
    valid_size = False
    if type(cached) is tuple and len(cached) == 8:
        try:
            valid_size = cached[7] == engine._full_repository_workspace_cache_size(
                cached
            )
        except Exception:
            pass
    if (
        not valid_size
        or key is None
        or type(key) is not tuple
        or len(key) != 3
        or cached[0] != key
        or cached[5] is None
        or cached[7] > engine.FULL_REPOSITORY_WORKSPACE_CACHE_MAX_BYTES
    ) or (
        cached[6] != engine._full_repository_workspace_cache_identity(generation, key)
    ):
        return None
    if not isinstance(cached[5], tuple) or len(cached[5]) != 2:
        return None
    return cached


def _full_repository_workspace_cache_load_source(generation):
    from copy import deepcopy
    import hashlib

    cached = _full_repository_workspace_cached_source_entry(generation)
    if cached is None:
        return None
    source_bytes, bindings = cached[5]
    if not isinstance(source_bytes, dict) or not isinstance(bindings, list):
        return None
    inventory = {row["path"]: row for row in generation["inventory"]}
    names = [item.get("path") for item in bindings if isinstance(item, dict)]
    if (
        len(names) != len(inventory)
        or set(names) != set(inventory)
        or set(source_bytes) != set(inventory)
    ):
        return None
    file_by_name = {
        path.relative_to(generation["root"]).as_posix(): path
        for path in generation["files"]
    }
    if (
        set(file_by_name) != set(inventory)
        or any(not isinstance(value, bytes) for value in source_bytes.values())
        or sum(map(len, source_bytes.values()))
        > generation["source_retention_limit_bytes"]
    ):
        return None
    captured = {}
    for binding in bindings:
        name, data = binding["path"], source_bytes.get(binding["path"])
        row = inventory[name]
        if (
            not isinstance(data, bytes)
            or len(data) != binding.get("bytes")
            or binding.get("sha256") != row.get("sha256")
            or hashlib.sha256(data).hexdigest() != row.get("sha256")
            or file_by_name[name].is_symlink()
        ):
            return None
        captured[file_by_name[name]] = data
    if len(captured) != len(generation["files"]):
        return None
    generation["workspace_source_capture_reuse"] = {
        "files": len(captured),
        "bytes": sum(map(len, captured.values())),
        "cache_accounted_bytes": cached[7],
    }
    return captured, deepcopy(bindings)


def _workspace_security_configuration(engine, generation, audit):
    from .runtime_audit_common import RuntimeAuditError

    root = generation["root"]
    config_bindings = []
    config_bytes = {}
    names = {row["path"] for row in generation["frame"]["candidates"]}
    names.add("requirements.txt")
    config_identity = []
    for name in sorted(names):
        row = engine._full_repository_configuration_binding(root, name)
        config_identity.append(row)
        if row.get("state") != "read":
            if row.get("state") != "absent":
                raise RuntimeAuditError(
                    "E_CONTEXT_CONFIG", "security config unavailable"
                )
            continue
        raw = audit._security_source_bytes(root, name)
        if len(raw) > audit.MAX_BYTES or engine.sha256_bytes(raw) != row["sha256"]:
            raise RuntimeAuditError("SOURCE_DRIFT", "captured security config changed")
        config_bytes[name] = raw
        config_bindings.append(
            {"path": name, "sha256": row["sha256"], "bytes": len(raw)}
        )

    return config_bindings, config_bytes, config_identity


def _full_repository_workspace_security_context(engine, generation, audit):
    from .context_efficiency import (
        _full_repository_workspace_cache_load_source,
        bind_application_fixture_context,
    )
    from .runtime_audit_common import RuntimeAuditError

    root, files = generation["root"], generation["files"]
    retention_limit = generation.get("source_retention_limit_bytes")
    capture_options = (
        {} if retention_limit is None else {"retention_limit": retention_limit}
    )
    reused = _full_repository_workspace_cache_load_source(generation)
    if reused is None:
        generation["workspace_source_capture_reuse"] = {"files": 0, "bytes": 0}
        captured, bindings, _manifest, _cacheable = audit._oracle_source_inputs(
            root, files, **capture_options
        )
    else:
        captured, bindings = reused
    inventory = {row["path"]: row for row in generation.get("inventory", ())}
    for binding in bindings:
        prior = inventory.get(binding["path"])
        if prior is not None and prior.get("sha256") != binding.get("sha256"):
            raise RuntimeAuditError(
                "SOURCE_DRIFT", "source changed between inventory and context capture"
            )
    if len(captured) < len(bindings):
        raise RuntimeAuditError(
            "E_SOURCE_RETENTION", "workspace source retention budget exhausted"
        )
    if len(captured) == len(files) == len(bindings):
        generation["workspace_source_capture_for_cache"] = (
            {
                path.relative_to(root).as_posix(): data
                for path, data in captured.items()
            },
            bindings,
        )
    snapshots = audit.contracts.bound_snapshots(root, files, captured, bindings)
    hashes = {root / row["path"]: row["sha256"] for row in bindings}
    contexts = {path: {} for path in snapshots}
    from .import_context import _workspace_security_configuration

    config_bindings, config_bytes, config_identity = _workspace_security_configuration(
        engine, generation, audit
    )

    def captured_config(_root, name):
        if name not in config_bytes:
            raise FileNotFoundError(name)
        return config_bytes[name]

    symbolic_imports = {}
    source_paths = set(snapshots)
    binding_paths = [root / row["path"] for row in bindings]
    symbolic_inputs_complete = (
        callable(getattr(audit, "_oracle_imports", None))
        and source_paths == set(captured) == set(hashes)
        and len(binding_paths) == len(set(binding_paths)) == len(source_paths)
        and all(
            isinstance(hashes[path], str)
            and len(hashes[path]) == 64
            and hashes[path] == hashlib.sha256(captured[path]).hexdigest()
            for path in source_paths
        )
    )
    if symbolic_inputs_complete:
        eligible = CapturedImportInventory(root, tuple(snapshots))
        symbolic_imports = {
            path: audit._oracle_imports(root, path, tree, eligible, captured=True)
            for path, tree in snapshots.items()
        }
        symbolic_inputs_complete = set(symbolic_imports) == source_paths
    if symbolic_inputs_complete:
        from .provenance import bind_credential_consumers

        bind_credential_consumers(
            audit.integrity,
            root,
            snapshots,
            symbolic_imports,
            contexts,
            captured,
            inventory=hashes,
        )
    bind_application_fixture_context(
        root,
        snapshots,
        contexts,
        config_bindings,
        captured_config,
        audit.MAX_BYTES,
        source_bytes=captured,
        source_inventory=hashes,
        imports=symbolic_imports if symbolic_inputs_complete else None,
    )
    audit.integrity.bind_fixed_program_workspace(
        root, contexts, snapshots, files, captured
    )
    return {
        "contexts": contexts,
        "source_bytes": captured,
        "bindings": bindings + config_bindings,
        "snapshots": snapshots,
        "symbolic_imports": symbolic_imports if symbolic_inputs_complete else {},
        "fingerprints": {},
        "config_identity": config_identity,
    }


_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


_STRUCTURAL_SET_FIELDS = (
    "module_rebindings",
    "dynamic_getattr_modules",
    "source_classes",
) + ("implementation_contract_lines",)
_STRUCTURAL_MAP_FIELDS = ("module_imports", "class_imports", "benchmark_constants")


def encode_structural_context(context):
    """Encode all structural oracle bindings for the bounded in-memory cache."""
    return {
        **{key: sorted(context.get(key, set())) for key in _STRUCTURAL_SET_FIELDS},
        **{key: context.get(key, {}) for key in _STRUCTURAL_MAP_FIELDS},
    }


def decode_structural_context(payload):
    """Restore structural oracle bindings without weakening their source identity."""
    return {
        **{key: set(payload.get(key, [])) for key in _STRUCTURAL_SET_FIELDS},
        **{key: payload.get(key, {}) for key in _STRUCTURAL_MAP_FIELDS},
    }


def bind_security_call_scopes(tree: ast.AST, nodes=None) -> None:
    """Retain lexical parameter shadowing for nested security call readers."""
    tree._security_sanitizer_provider_cache = {}
    tree._security_parent_scope = None
    tree._security_scope_kind = "module"
    tree._security_local_names = set()
    tree._security_nonlocal_names = set()
    tree._security_calls_by_statement = {}
    for parent in ast.walk(tree) if nodes is None else nodes:
        for child in ast.iter_child_nodes(parent):
            child._security_parent = parent
    _bind_security_scope_node(tree, tree, set(), tree)


def _security_ast_span_contains(node, container):
    return (container.lineno, container.col_offset) <= (
        node.lineno,
        node.col_offset,
    ) and (node.end_lineno, node.end_col_offset) <= (
        container.end_lineno,
        container.end_col_offset,
    )


def _bind_security_scope_node(node, scope, shadowed, tree, flow_statement=None):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        _bind_security_function(node, scope, shadowed, tree, flow_statement)
        return
    if isinstance(node, ast.ClassDef):
        _bind_security_class(node, scope, shadowed, tree, flow_statement)
        return
    if isinstance(node, ast.Call):
        node._security_shadowed_names = shadowed
        node._security_lexical_scope = scope
        node._security_flow_statement = flow_statement
        calls = getattr(scope, "_security_calls_by_statement", {})
        calls.setdefault(id(flow_statement), []).append(node)
        scope._security_calls_by_statement = calls
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        node._security_lexical_scope = scope
    if isinstance(node, ast.Attribute):
        node._security_lexical_scope = scope
        node._security_flow_statement = flow_statement
    for child in ast.iter_child_nodes(node):
        direct = child if node is scope else flow_statement
        _bind_security_scope_node(child, scope, shadowed, tree, direct)


def _bind_security_function(node, scope, shadowed, tree, flow_statement):
    arguments = node.args
    body = node.body if isinstance(node.body, list) else [node.body]
    definition_statement = flow_statement or node
    for decorator in getattr(node, "decorator_list", []):
        _bind_security_scope_node(
            decorator, scope, shadowed, tree, definition_statement
        )
    for default in [*arguments.defaults, *arguments.kw_defaults]:
        if default is not None:
            _bind_security_scope_node(
                default, scope, shadowed, tree, definition_statement
            )
    for annotation in _function_annotations(node):
        _bind_security_scope_node(
            annotation, scope, shadowed, tree, definition_statement
        )
    lexical_parent = (
        getattr(scope, "_security_parent_scope", tree)
        if isinstance(scope, ast.ClassDef)
        else scope
    )
    node._security_parent_scope = lexical_parent
    node._security_class_scope = scope if isinstance(scope, ast.ClassDef) else None
    arguments_names = {
        argument.arg
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *[arg for arg in (arguments.vararg, arguments.kwarg) if arg],
        ]
    }
    node._security_parameter_names = arguments_names
    node._security_local_names = _security_scope_local_names(node)
    node._security_nonlocal_names = _security_scope_nonlocal_names(node)
    node._security_scope_kind = "function"
    node._security_calls_by_statement = {}
    child_shadowed = shadowed | arguments_names | node._security_local_names
    for child in body:
        _bind_security_scope_node(child, node, child_shadowed, tree, child)


def _bind_security_class(node, scope, shadowed, tree, flow_statement):
    for child in [*node.decorator_list, *node.bases]:
        _bind_security_scope_node(child, scope, shadowed, tree, flow_statement or node)
    for keyword in node.keywords:
        _bind_security_scope_node(
            keyword.value, scope, shadowed, tree, flow_statement or node
        )
    node._security_parent_scope = scope
    node._security_scope_kind = "class"
    node._security_local_names = _security_scope_local_names(node)
    node._security_nonlocal_names = _security_scope_nonlocal_names(node)
    node._security_calls_by_statement = {}
    for child in node.body:
        _bind_security_scope_node(child, node, shadowed, tree, child)


def _function_annotations(node):
    args = node.args
    values = [
        arg.annotation for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
    ]
    values.extend(arg.annotation for arg in (args.vararg, args.kwarg) if arg)
    if getattr(node, "returns", None) is not None:
        values.append(node.returns)
    return [value for value in values if value is not None]


def _security_scope_local_names(scope):
    names = set()
    body = getattr(scope, "body", [])
    statements = body if isinstance(body, list) else [body]
    for statement in statements:
        if not isinstance(statement, ast.AST):
            continue
        names.update(_bound_names(statement))
    return (
        names
        - _security_scope_declared_names(scope, ast.Global)
        - (_security_scope_declared_names(scope, ast.Nonlocal))
    )


def _security_scope_nonlocal_names(scope):
    return _security_scope_declared_names(scope, ast.Nonlocal)


def _security_scope_declared_names(scope, declaration):
    body = getattr(scope, "body", [])
    statements = body if isinstance(body, list) else [body]
    names = set()
    pending = list(statements)
    while pending:
        node = pending.pop()
        if not isinstance(node, ast.AST):
            continue
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(node, declaration):
            names.update(node.names)
        pending.extend(ast.iter_child_nodes(node))
    return names


def _security_module_scope(scope):
    pending = [scope]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.Module):
            return current
        parent = getattr(current, "_security_parent_scope", None)
        if parent is not None:
            pending.append(parent)
        class_scope = getattr(current, "_security_class_scope", None)
        if class_scope is not None:
            pending.append(class_scope)
    return None


def _security_apply_import_bindings(body, resolved, stop, audit):
    for statement in body:
        if statement is stop:
            break
        imported = audit._security_aliases([statement])
        for name in audit._bound_names(statement):
            resolved.pop(name, None)
            if name in imported:
                resolved[name] = imported[name]
    return resolved


def _iter_ast_nodes(node: ast.AST):
    """Walk one AST without allocating or repeating ``ast.walk`` inventories."""
    pending = [node]
    while pending:
        child = pending.pop()
        yield child
        pending.extend(ast.iter_child_nodes(child))


def _binding_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return node.id
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _bound_names(statement: ast.AST) -> set[str]:
    if isinstance(statement, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
        return {statement.name} if hasattr(statement, "name") else set()
    if (cached := getattr(statement, "_scan_bound_names", None)) is not None:
        return set(cached)
    comprehension_targets = {
        id(target)
        for child in _iter_ast_nodes(statement)
        if isinstance(
            child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        )
        for generator in child.generators
        for target in _iter_ast_nodes(generator.target)
        if isinstance(target, ast.Name)
    }
    names: set[str] = set()
    pending = [statement]
    while pending:
        child = pending.pop()
        if isinstance(child, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(child))
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            if any(item.name == "*" for item in child.names):
                names.add("*")
            names.update(
                item.asname
                or (
                    item.name.split(".")[0]
                    if isinstance(child, ast.Import)
                    else item.name
                )
                for item in child.names
                if item.name != "*"
            )
            continue
        if id(child) in comprehension_targets:
            continue
        name = _binding_name(child)
        if name:
            names.add(name)
    if hasattr(statement, "_scan_bound_names"):
        statement._scan_bound_names = frozenset(names)
    return names


def _security_call_leaf(node):
    return node.func.attr if isinstance(node.func, ast.Attribute) else ""


class _SecurityFlowState(set):
    """Possible origins, proved origins and definite bindings on one captured path."""

    def __init__(
        self, tags=(), values=None, bound=(), proven=None, path_supported=True
    ):
        super().__init__(tags)
        self.values, self.bound = dict(values or {}), set(bound)
        self.proven = set(self if proven is None else proven)
        self.path_supported = path_supported

    def copy(self):
        """Clone possible and proven origins without sharing mutable containers."""
        return type(self)(
            self, self.values, self.bound, self.proven, self.path_supported
        )

    def unresolved(self):
        """Retain possible observations while withdrawing unproved path authority."""
        result = self.copy()
        result.path_supported = False
        result.proven.clear()
        return result

    def supported_view(self):
        """Project only origins supported by a proven continuing source path."""
        if not self.path_supported:
            return None
        if self.proven == set(self):
            return self
        values = {
            name: value
            for name, value in self.values.items()
            if name not in self or name in self.proven
        }
        return type(self)(self.proven, values, self.bound)

    def assign(self, statement, aliases, other_states, helpers, transfer):
        """Apply the canonical assignment transfer to possible and proven origins."""
        same = self.path_supported and self.proven == set(self)
        proven = set(self.proven)
        if self.path_supported and not same:
            transfer(
                statement,
                aliases,
                proven,
                *(values.copy() for values in other_states),
                helpers,
            )
        transfer(statement, aliases, self, *other_states, helpers)
        self.proven = set(self) if same else proven if self.path_supported else set()
        self.bound.update(_bound_names(statement))

    def difference_update(self, names):
        """Remove invalidated bindings from tags, proofs and captured values."""
        names = tuple(names)
        super().difference_update(names)
        self.proven.difference_update(names)
        for name in names:
            self.values.pop(name, None)

    def discard(self, name):
        """Discard one binding consistently across the captured flow state."""
        super().discard(name)
        self.proven.discard(name)
        self.values.pop(name, None)


def security_literal_branch_blocks(statement, values=None, *, singleton_identity=False):
    """Select only bounded, side-effect-free literal guards; unknown keeps both arms."""
    from .review_audits import _constant_truth_value

    from .credential_role_identity_effects import _validated_exact_scalar

    known = {
        name: scalar[0]
        for name, value in (values or {}).items()
        for scalar in (_validated_exact_scalar(value),)
        if all(
            (
                not value.unknown,
                not value.content_unknown,
                not value.roots,
                bool(scalar),
            )
        )
    }
    nodes = tuple(ast.walk(statement.test))
    allowed = (
        ast.Constant,
        ast.Name,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
        ast.Load,
        ast.UnaryOp,
        ast.Not,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        *((ast.Is,) if singleton_identity else ()),
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.In,
        ast.NotIn,
    )
    literal_budgets = {
        str: (len, 4096),
        bytes: (len, 4096),
        int: (int.bit_length, 1024),
    }
    measured_literals = (
        (node.value, literal_budgets[type(node.value)])
        for node in nodes
        if isinstance(node, ast.Constant)
        if type(node.value) in literal_budgets
    )
    if (
        len(nodes) > 128
        or any(not isinstance(node, allowed) for node in nodes)
        or any(isinstance(node, ast.Name) and node.id not in known for node in nodes)
        or any(measure(value) > limit for value, (measure, limit) in measured_literals)
    ):
        return statement.body, statement.orelse
    truth = _constant_truth_value(statement.test, known)
    return (
        (statement.body if truth else statement.orelse,)
        if truth is not None
        else (statement.body, statement.orelse)
    )


def _security_loop_block_findings(statement, flow, walk, inspect, bind_targets):
    from . import review_audits as audit

    expression = statement.test if isinstance(statement, ast.While) else statement.iter
    findings = inspect(expression, flow)
    if statement.body and audit._unreachable_constant_branch(
        statement, statement.body[0]
    ):
        emitted, exits = walk(statement.orelse, flow)
        return [*findings, *emitted], exits
    endless = (
        isinstance(statement, ast.While)
        and isinstance(statement.test, ast.Constant)
        and bool(statement.test.value)
    )
    targets = (
        audit._bound_names(statement.target)
        if isinstance(statement, (ast.For, ast.AsyncFor))
        else set()
    )
    # Exact inert ordered literals are walked once per element, not to a fixed point.
    items = None
    if isinstance(statement, ast.For) and isinstance(
        statement.iter, (ast.Tuple, ast.List)
    ):
        elements = statement.iter.elts
        if len(elements) <= 64 and all(
            isinstance(item, ast.Constant)
            and type(item.value) in {str, bytes, int, float, bool, type(None)}
            for item in elements
        ):
            items = elements
    runner = (
        _security_literal_loop_findings
        if items is not None
        else _security_fixpoint_loop_findings
    )
    emitted, exits = runner(
        statement,
        flow,
        walk,
        inspect,
        bind_targets,
        items,
        endless,
        expression,
        targets,
    )
    return [*findings, *emitted], exits


def _security_loop_outcomes(outgoing, exits):
    """Consume loop-local break/continue while preserving nonlocal abrupt exits."""
    from .finite_capture import _security_merge_exit_states

    _security_merge_exit_states(
        exits,
        {key: value for key, value in outgoing.items() if key in {"return", "raise"}},
    )
    if "break" in outgoing:
        _security_merge_exit_states(exits, {"normal": outgoing["break"]})
    feedback = {}
    for kind in ("normal", "continue"):
        if kind in outgoing:
            _security_merge_exit_states(feedback, {"normal": outgoing[kind]})
    return feedback


def _security_literal_loop_findings(
    statement, flow, walk, inspect, bind_targets, items, endless, expression, targets
):
    """Execute only the captured ordered literal's actual iteration predecessors."""
    from .finite_capture import _security_merge_exit_states

    findings, exits = [], {}
    head = [values.copy() for values in flow]
    for item in items:
        assignment = ast.copy_location(
            ast.Assign(targets=[statement.target], value=item), statement
        )
        emitted, outgoing = walk([assignment, *statement.body], head)
        findings.extend(emitted)
        feedback = _security_loop_outcomes(outgoing, exits)
        if not feedback:
            return findings, exits
        head = feedback["normal"]
    emitted, outgoing = walk(statement.orelse, head)
    findings.extend(emitted)
    _security_merge_exit_states(exits, outgoing)
    return findings, exits


def _security_fixpoint_loop_findings(
    statement, flow, walk, inspect, bind_targets, items, endless, expression, targets
):
    """Unknown iteration counts converge in the existing bounded abstract domain."""
    from . import review_audits as audit
    from .finite_capture import (
        _security_merge_branch_states,
        _security_merge_exit_states,
    )

    findings = []
    head = [values.copy() for values in flow]
    exits, exhausted = {}, {}
    if not endless:
        _security_merge_exit_states(exhausted, {"normal": flow})
    for _ in range(64):
        iteration = [values.copy() for values in head]
        if targets:
            bind_targets(expression, targets, iteration)
        emitted, outgoing = walk(statement.body, iteration)
        findings.extend(emitted)
        feedback = _security_loop_outcomes(outgoing, exits)
        if not feedback:
            break
        if not endless:
            _security_merge_exit_states(exhausted, feedback)
        next_head = [values.copy() for values in flow]
        _security_merge_branch_states(next_head, [head, feedback["normal"]])
        if all(
            left == right
            and getattr(left, "values", {}) == getattr(right, "values", {})
            and getattr(left, "bound", set()) == getattr(right, "bound", set())
            and getattr(left, "proven", set(left))
            == getattr(right, "proven", set(right))
            for left, right in zip(head, next_head)
        ):
            break
        head = next_head
    else:
        findings.append(
            audit._security_finding(
                "SECURITY_AUDIT_INCOMPLETE",
                "<control-flow>",
                statement,
                "Loop source-flow fixed point exceeded its bounded state iterations.",
                "HIGH",
                reason="loop_fixed_point_exhausted",
            )
        )
    if "normal" in exhausted:
        emitted, outgoing = walk(statement.orelse, exhausted["normal"])
        findings.extend(emitted)
        _security_merge_exit_states(exits, outgoing)
    return findings, exits
