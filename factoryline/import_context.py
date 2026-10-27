"""Shared bounded native import policy and captured source views."""

from types import MappingProxyType
from dataclasses import dataclass
from pathlib import Path
import ast
import hashlib
from collections import defaultdict


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
            rows = [(alias.asname or alias.name,
                     "." * node.level + (node.module or "") + "." + alias.name)
                    for alias in node.names]
            if node.level and package is not None:
                selected = _django_import_rows(node, package)
                if selected is not None:
                    rows = selected
                    relative.update(rows)
            for name, canonical in rows:
                origins[name].add(canonical)
    def protected(value):
        return (value.split(".")[0] in {"builtins", "importlib", "sys"}
                or value == provider or value.startswith(provider + ".") or provider.startswith(value + "."))

    if any(len(values) > 1 and any(protected(value) for value in values)
           for values in origins.values()):
        return None
    return {**audit._security_aliases(nodes), **relative}


def application_configuration_names():
    """Name bounded root inputs shared by capture, sealing and role rebuilding."""
    return frozenset({
        "requirements.txt", "pyproject.toml", "tox.ini",
        "pytest.ini", ".pytest.ini", "setup.cfg",
    })


def application_profile_configuration(root, read_source, limit):
    """Capture unparsed selector bytes; neither presence nor content grants authority."""
    bindings, identities, valid = [], {}, True
    # The existing type-check configuration capture owns pyproject.toml/tox.ini.
    for name in sorted(application_configuration_names() - {"pyproject.toml", "tox.ini"}):
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
                binding = {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
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


def captured_import_path(root, path):
    """Check lexical containment; no CWD resolution or source authority is added."""
    return (
        isinstance(path, Path)
        and path.is_relative_to(root)
        and path != root
        and ".." not in path.parts
        and ":" not in path.relative_to(root).as_posix()
    )


def import_source_choices(root, path, node, module, imported, *, captured_inventory=None):
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
    return list(dict.fromkeys(base for base in bases if _captured_import_base(root, base)))


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
            root, path, node, module, imported,
            captured_inventory=captured_inventory if captured else None,
        )
        if kind == "child"
    }
    return None if source in children else imported


def captured_import_module(source, path, name):
    """Resolve an imported module through the same strict caller-relative search."""
    tree = source.snapshots.get(path)
    if not isinstance(tree, ast.Module) or not source.validate(path):
        return False, None
    statements = [node for node in ast.walk(tree) if (
        isinstance(node, ast.ImportFrom) and not node.level and node.module == name
        or isinstance(node, ast.Import) and any(alias.name == name for alias in node.names)
    )]
    if not statements:
        return False, None
    paths = frozenset(source.snapshots)
    key = source.root, paths
    cached = getattr(source, "_captured_symbol_import_inventory", None)
    if cached is None or cached[0] != key:
        cached = key, CapturedImportInventory(source.root, paths)
        source._captured_symbol_import_inventory = cached
    targets = {resolve_import_source(source.root, path, node, name, cached[1], captured=True)
               for node in statements}
    if len(targets) != 1 or None in targets:
        return True, None
    target = next(iter(targets))
    return True, target if source.validate(target) else None


def resolve_import_source(
    root, path, node, module, eligible, imported=None, *, captured=False
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
        root, path, node, module, imported,
        captured_inventory=eligible if captured else None,
    ):
        selected = choice if captured else live_import_path(choice, root_abs)
        if selected in sources and captured_import_path(root_abs, selected):
            matches[kind].add(sources[selected])
    return unique_import_source(matches, strict=captured)


def captured_import_inventory_matches(root, path, node, module, inventory):
    """Require the captured caller and reject relative package-root underflow."""
    return (
        type(inventory) is CapturedImportInventory
        and inventory.root == root
        and path in inventory.paths
        and captured_relative_import(root, path, node)
        and captured_import_parent_modules(
            root, path, node, module, inventory
        )
    )


def captured_import_parent_modules(root, path, node, module, inventory):
    """Reject dotted imports whose ancestor resolves to a non-package module."""
    parts = module.split(".") if module else []
    for base in import_source_bases(
        root, path, node, captured_inventory=inventory
    ):
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
    return (
        application_configuration_names,
        application_profile_configuration,
        captured_import_module,
        _shell_import_aliases,
        CapturedImportInventory,
        CapturedImportInventory.__init__,
        CapturedImportInventory.__post_init__,
        captured_import_path,
        _captured_import_base,
        _captured_path_set,
        _captured_regular_package_root,
        import_source_choices,
        import_source_bases,
        import_child_source_choices,
        import_source_symbol,
        resolve_import_source,
        captured_import_inventory_matches,
        captured_import_parent_modules,
        live_import_path,
        captured_relative_import,
        unique_import_source,
        import_resolution_helpers,
    )


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
