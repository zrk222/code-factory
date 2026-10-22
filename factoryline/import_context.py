"""Shared bounded native import policy and captured source views."""

from types import MappingProxyType
from dataclasses import dataclass
from pathlib import Path
import ast


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


def import_source_choices(root, path, node, module, imported):
    """Generate the existing bounded live/captured candidates in one place."""
    parts = module.split(".") if module else []
    if any(not part.isidentifier() for part in parts):
        return []
    choices = []
    for base in import_source_bases(root, path, node):
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


def import_source_bases(root, path, node):
    """Share the legacy search bases with captured ancestor validation."""
    if isinstance(node, ast.ImportFrom) and node.level:
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
        return [base]
    return [path.parent, root, root / "src"]


def import_child_source_choices(target, node, imported):
    """Generate an optional from-import child without accepting invalid names."""
    if not isinstance(node, ast.ImportFrom) or not imported or imported == "*":
        return []
    if not imported.isidentifier():
        return None
    child = target / imported
    return [(child.with_suffix(".py"), "child"), (child / "__init__.py", "child")]


def import_source_symbol(root, path, node, module, imported, source, *, captured):
    """Distinguish a captured child module from a symbol exported by a module."""
    if imported is None:
        return None
    if not captured:
        return imported
    children = {
        choice
        for choice, kind in import_source_choices(root, path, node, module, imported)
        if kind == "child"
    }
    return None if source in children else imported


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
    for choice, kind in import_source_choices(root, path, node, module, imported):
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
        and captured_import_parent_modules(root, path, node, module, inventory)
    )


def captured_import_parent_modules(root, path, node, module, inventory):
    """Reject dotted imports whose ancestor resolves to a non-package module."""
    parts = module.split(".") if module else []
    for base in import_source_bases(root, path, node):
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
        CapturedImportInventory,
        CapturedImportInventory.__init__,
        CapturedImportInventory.__post_init__,
        captured_import_path,
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
