"""Shared bounded native import policy and captured source views."""

from types import MappingProxyType, SimpleNamespace
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from . import (
    _db_python_import_before_call,
    _db_python_self_or_field_mutated,
    _db_python_server_field_contexts,
)
import ast
import hashlib
import re
from copy import deepcopy
from collections import defaultdict
from collections import OrderedDict


_FINGERPRINT_EPOCH = ContextVar("factory_structural_fingerprint_epoch", default=None)


def structural_ast_fingerprint(tree):
    """Reuse whole-module digests only inside their owned, validated batch."""
    epoch = _FINGERPRINT_EPOCH.get()
    if epoch is None or not epoch.active or type(tree) is not ast.Module:
        return _uncached_structural_ast_fingerprint(tree)
    paths = epoch.owned.get(tree)
    if paths is None:
        return _uncached_structural_ast_fingerprint(tree)
    if tree not in epoch.fingerprints:
        if not all(epoch.index.validate(path) for path in paths):
            return _uncached_structural_ast_fingerprint(tree)
        epoch.fingerprints[tree] = _uncached_structural_ast_fingerprint(tree)
    return epoch.fingerprints[tree]


@contextmanager
def prepared_security_snapshot_batch(audit, workspace, model_out, inputs):
    """Repair stale derived trees before freezing shared source authority."""
    accepted = False
    try:
        source = (model_out or {}).get("source")
        if source is not None:
            _prepare_security_snapshot_owner(
                audit, workspace, model_out, source, inputs
            )
        with audit._security_snapshot_analysis_batch(model_out):
            yield
        accepted = True
    finally:
        if not accepted and model_out is not None:
            model_out["source"] = None


def _prepare_security_snapshot_owner(audit, workspace, model_out, source, inputs):
    from .credential_role_constructor_provider import (
        security_snapshot_model,
        verified_security_tree,
    )

    snapshots, fingerprints, retained = inputs
    inventory = _authenticated_snapshot_inventory(
        audit, workspace, source, snapshots, fingerprints, retained
    )
    original_trees, original_bytes = dict(snapshots), dict(source.source_bytes)
    original_fingerprints = dict(fingerprints)
    original_memo = getattr(source, "class_chain_memo", None)
    stale = [
        path
        for path, tree in snapshots.items()
        if getattr(tree, "_oracle_source_sha256", None) != inventory[path]
        or audit._oracle_tree_fingerprint(tree) != original_fingerprints[path]
    ]
    model = source
    if stale:
        audit._verify_security_bindings(
            workspace,
            [
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "sha256": value,
                    "bytes": len(retained[path]),
                }
                for path, value in inventory.items()
            ],
        )
        for path in stale:
            snapshots[path] = verified_security_tree(
                audit,
                workspace,
                path,
                retained[path],
                {"sha256": inventory[path]},
                snapshots[path],
                original_fingerprints[path],
                source_context={"_security_source_model": source},
            )
        model = security_snapshot_model(
            workspace, snapshots, retained, original_fingerprints
        )
    if not (
        model is not None
        and model_out.get("source") is source
        and fingerprints == original_fingerprints
        and source.source_bytes == original_bytes
        and getattr(source, "class_chain_memo", None) is original_memo
        and _authenticated_snapshot_inventory(
            audit, workspace, source, original_trees, original_fingerprints, retained
        )
        == inventory
    ):
        raise audit.RuntimeAuditError("E_INPUT_CHANGED", "Snapshot repair rejected.")
    model_out["source"] = model


def _authenticated_snapshot_inventory(
    audit, workspace, source, snapshots, fingerprints, retained
):
    from .credential_role_constructor_provider import (
        ClassChainMemo,
        SourceSnapshotIndex,
    )

    selected = {path: retained.get(path) for path in snapshots}
    if not (
        type(source) is SourceSnapshotIndex
        and source.root == workspace
        and source.bounded
        and source.source_bytes == selected
        and set(source.snapshots) == set(snapshots) == set(fingerprints)
        and source.producer_fingerprints == fingerprints
        and all(source.snapshots[path] is tree for path, tree in snapshots.items())
        and all(isinstance(raw, bytes) for raw in selected.values())
    ):
        raise audit.RuntimeAuditError("E_INPUT_CHANGED", "Snapshot owner changed.")
    inventory = {
        path: hashlib.sha256(raw).hexdigest() for path, raw in selected.items()
    }
    memo = getattr(source, "class_chain_memo", None)
    if source.inventory != inventory or (
        memo is not None
        and not (
            type(memo) is ClassChainMemo
            and memo.index is source
            and memo.audit is audit
            and memo.root == workspace
            and memo.inventory == inventory
            and memo.names is audit._name
            and memo._analysis_batch is None
        )
    ):
        raise audit.RuntimeAuditError("E_INPUT_CHANGED", "Snapshot evidence changed.")
    return inventory


@contextmanager
def fingerprint_epoch(memo, state):
    """Retire reuse before the producer independently validates batch exit."""
    from .credential_role_constructor_provider import _helper_snapshot

    if not state.started or memo._analysis_batch is not state:
        raise ValueError("fingerprint epoch requires a validated producer batch")
    index, owned = memo.index, {}
    for path, tree in index.snapshots.items():
        if type(tree) is ast.Module:
            owned.setdefault(tree, []).append(path)
    epoch = SimpleNamespace(
        index=index,
        state=state,
        owned=owned,
        fingerprints={},
        active=False,
        query_facts=None,
    )

    def helpers():
        return (
            *_fingerprint_epoch_helpers(),
            memo.index,
            index.root,
            index.snapshots,
            index.source_bytes,
            index.inventory,
            getattr(index, "class_chain_memo", None),
            *index.snapshots,
            *index.snapshots.values(),
            *index.source_bytes.values(),
            *index.inventory.values(),
        )

    state.helper_epoch[fingerprint_epoch] = (helpers, _helper_snapshot(helpers))
    token = _FINGERPRINT_EPOCH.set(epoch)
    try:
        epoch.active = True
        yield epoch
    finally:
        epoch.active = False
        _FINGERPRINT_EPOCH.reset(token)


def bind_fingerprint_epoch(check_binding):
    """Keep a deferred guard from borrowing another batch's cached digests."""
    epoch = _FINGERPRINT_EPOCH.get()

    def check():
        if epoch is not None:
            if not epoch.active and not epoch.state.accepted:
                return False
            if epoch.active and _FINGERPRINT_EPOCH.get() is epoch:
                return check_binding()
        token = _FINGERPRINT_EPOCH.set(None)
        try:
            return check_binding()
        finally:
            _FINGERPRINT_EPOCH.reset(token)

    if epoch is not None and epoch.active:
        from .credential_role_constructor_provider import _helper_snapshot

        def helpers():
            return check, check_binding

        epoch.state.helper_epoch[check] = (helpers, _helper_snapshot(helpers))
    return check


def _fingerprint_epoch_helpers():
    """Use the producer's existing callable identity/code epoch protocol."""
    from . import credential_role_constructor_provider as provider
    from . import credential_role_identity_effects as effects

    return (
        fingerprint_epoch,
        fingerprint_epoch.__wrapped__,
        bind_fingerprint_epoch,
        _fingerprint_epoch_helpers,
        structural_ast_fingerprint,
        _uncached_structural_ast_fingerprint,
        _structural_ast_leaf_digest,
        _structural_ast_fields,
        _iter_ast_nodes,
        _FINGERPRINT_EPOCH,
        SimpleNamespace,
        ast.Module,
        ast.AST,
        ast.dump,
        ast.parse,
        ast.iter_child_nodes,
        hashlib.sha256,
        OrderedDict,
        provider.SourceSnapshotIndex,
        provider.SourceSnapshotIndex.__init__,
        provider.SourceSnapshotIndex.validate,
        provider.SourceSnapshotIndex._matches_snapshot,
        provider._ast_matches_source,
        provider._view,
        provider.copy.deepcopy,
        provider.ast,
        provider.hashlib,
        effects.bind_fingerprint_epoch,
        provider.ClassChainMemo,
        getattr(provider.ClassChainMemo, "valid", None),
        getattr(provider.ClassChainMemo, "matches", None),
        getattr(provider.ClassChainMemo, "analysis_batch", None),
        getattr(
            getattr(provider.ClassChainMemo, "analysis_batch", None),
            "__wrapped__",
            None,
        ),
        provider._helper_snapshot,
        provider._helper_identity,
        provider._provider_snapshot,
        provider._same_helper_epoch,
        provider.helper_epochs_valid,
        epoch_binding_occurrences,
        binding_walker_epoch,
        _owned_ast_query_facts,
        _owned_ast_query_nodes,
        _captured_import_candidates,
        _raw_import_candidates,
        _bind_import_parent_mapping,
        _captured_import_statement,
        provider.binding_occurrences,
        provider._binding_occurrence_events,
        provider._binds,
        provider._SCOPES,
        provider._COMPREHENSIONS,
        ast.walk,
        ast.iter_fields,
    )


def _owned_ast_query_nodes(epoch):
    """Build strong node membership once, enrolling every owning module path."""
    nodes = {}
    for module, paths in epoch.owned.items():
        if not all(epoch.index.validate(path) for path in paths):
            continue
        pending = [module]
        while pending:
            node = pending.pop()
            row = nodes.get(id(node))
            owners = row[1:] if row is not None else ()
            if module in owners:
                continue
            nodes[id(node)] = (node, *owners, module)
            pending.extend(ast.iter_child_nodes(node))
    return nodes


def _owned_ast_query_facts(epoch, roots, *, source=None):
    """Accept exact owned root identities, never foreign source-index authority."""
    if (
        epoch is None
        or not epoch.active
        or source is not None
        and source is not epoch.index
    ):
        return None
    if epoch.query_facts is None:
        epoch.query_facts = SimpleNamespace(
            nodes=_owned_ast_query_nodes(epoch), bindings={}, imports={}
        )
    nodes = epoch.query_facts.nodes
    if not roots or any(nodes.get(id(node), (None,))[0] is not node for node in roots):
        return None
    try:
        hash(roots)
    except TypeError:
        return None
    return epoch.query_facts


def binding_walker_epoch():
    """Retain the existing explicit per-pass walker's dependency key semantics."""
    from . import credential_role_constructor_provider as provider

    return tuple(
        (
            helper,
            getattr(helper, "__code__", None),
            id(getattr(helper, "__defaults__", None)),
        )
        for helper in (
            provider.binding_occurrences,
            provider._binding_occurrence_events,
            provider._binds,
            provider.ast.walk,
            provider.ast.iter_child_nodes,
            provider.ast.iter_fields,
        )
    ) + (provider.ast.NamedExpr, provider._SCOPES, provider._COMPREHENSIONS)


def epoch_binding_occurrences(statements, name, per_pass_facts):
    """Share ordered owned roots and immutable name results only for default None."""
    epoch = _FINGERPRINT_EPOCH.get()
    if (
        per_pass_facts is not None
        or type(name) is not str
        or epoch is None
        or not epoch.active
    ):
        return statements, None
    roots = tuple(statements)
    facts = _owned_ast_query_facts(epoch, roots)
    if facts is None:
        return roots, None
    from .credential_role_constructor_provider import _binding_occurrence_events

    canonical, events, names = facts.bindings.setdefault(roots, (roots, {}, {}))
    if name not in names:
        names[name] = tuple(
            _binding_occurrence_events(canonical, name, per_pass_facts=events)
        )
    return roots, names[name]


def _uncached_structural_ast_fingerprint(tree):
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


def captured_django_management_contract(context, path):
    """Bind only a closed, invoked management bootstrap to its settings value."""
    from .semantic_credential_sensor import (
        _security_builtin_identity_closed,
        _signing_provider_clear,
    )

    tree = context["index"].snapshots[path]
    provider = "from django.core.management import execute_from_command_line"
    contract = _management_script_contract(
        tree,
        [ast.dump(ast.parse(s).body[0]) for s in ("import os", "import sys")],
        ast.dump(ast.parse(provider).body[0]),
        ast.dump(ast.parse("def main(): pass").body[0].args),
        provider,
    )
    if contract is not None and _captured_script_imports_safe(
        context, path, tree, _security_builtin_identity_closed, _signing_provider_clear
    ):
        setting, body, _module_provider = contract
        return {
            "settings": setting,
            "statements": [
                *_script_statements(tree.body)[:-2],
                *(
                    child
                    for node in body
                    for child in (node.body if isinstance(node, ast.Try) else [node])
                ),
            ],
        }
    return None


def captured_django_startup_statements(context, path):
    """Use the same invocation proof for consumer and settings-owner analysis."""
    from .intent_quality import _canary_main_guard_test

    contract = captured_django_management_contract(context, path)
    if contract is not None:
        return contract["statements"]
    tree = context["index"].snapshots[path]
    return [
        child
        for node in tree.body
        for child in (
            node.body
            if isinstance(node, ast.If) and _canary_main_guard_test(node.test)
            else [node]
        )
    ]


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
    statements = _captured_import_candidates(source, path, tree, name)
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


def _raw_import_candidates(source, path, tree, name):
    """Keep the original parent-map or AST-walk candidate selection semantics."""
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
    return tuple(node for node in nodes if _captured_import_statement(node, name))


def _bind_import_parent_mapping(epoch, source, path):
    """Reject cached candidate publication after parent-map sidecar drift."""
    from .credential_role_constructor_provider import _helper_snapshot

    key = (_bind_import_parent_mapping, source, path)
    if key not in epoch.state.helper_epoch:

        def parents():
            mapping = source.parents.get(path)
            return source.parents, mapping, *mapping, *mapping.values()

        epoch.state.helper_epoch[key] = (parents, _helper_snapshot(parents))


def _captured_import_candidates(source, path, tree, name):
    """Cache exact matcher candidates while resolving and validating targets fresh."""
    parents = getattr(source, "parents", None)
    if (
        type(name) is not str
        or type(parents) is not dict
        or type(parents.get(path)) is not dict
    ):
        return _raw_import_candidates(source, path, tree, name)
    epoch = _FINGERPRINT_EPOCH.get()
    facts = _owned_ast_query_facts(epoch, (tree,), source=source)
    if facts is None:
        return _raw_import_candidates(source, path, tree, name)
    key = tree, path, name
    if key not in facts.imports:
        _bind_import_parent_mapping(epoch, source, path)
        facts.imports[key] = _raw_import_candidates(source, path, tree, name)
    return facts.imports[key]


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
    return _select_resolved_import(
        matches, captured, imported, source_index, eligible, package_binding_exclude
    )


def _select_resolved_import(
    matches, captured, imported, source_index, inventory, exclude
):
    """Keep legacy selection separate from captured package-attribute checks."""
    if not captured:
        return unique_import_source(matches, strict=False)
    if not imported or source_index is None:
        return unique_import_source(matches, strict=True)
    return _captured_import_choice(matches, imported, source_index, inventory, exclude)


def _captured_import_choice(matches, imported, source_index, inventory, exclude):
    """Resolve one captured package binding without weakening ambiguity checks."""
    package = next(iter(matches["package"])) if len(matches["package"]) == 1 else None
    if package is None or package.name != "__init__.py":
        return unique_import_source(matches, strict=True)
    if len(matches["child"]) == 1:
        child = next(iter(matches["child"]))
        if _captured_child_module_matches(
            source_index, package, child, imported, inventory=inventory, exclude=exclude
        ):
            return child
    if matches["child"] or not source_index:
        return unique_import_source(matches, strict=True)
    binding = _captured_package_binding(
        source_index, package, imported, inventory, exclude=exclude
    )
    if not isinstance(binding, ast.stmt):
        return None
    return None if isinstance(binding, (ast.Import, ast.ImportFrom)) else package


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
        security_snapshot_model,
        verified_security_tree,
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
        *(
            helper
            for helper in _fingerprint_epoch_helpers()
            if hasattr(helper, "__name__")
        ),
        prepared_security_snapshot_batch,
        getattr(
            prepared_security_snapshot_batch,
            "__wrapped__",
            prepared_security_snapshot_batch,
        ),
        _prepare_security_snapshot_owner,
        _authenticated_snapshot_inventory,
        security_snapshot_model,
        verified_security_tree,
        application_configuration_names,
        application_profile_configuration,
        captured_import_module,
        _captured_import_statement,
        captured_import_inventory,
        captured_script_module,
        captured_django_management_contract,
        captured_django_startup_statements,
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
        _select_resolved_import,
        _captured_import_choice,
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
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.expr)):
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


def security_literal_branch_blocks(
    statement, values=None, *, singleton_identity=False, expression_values=None
):
    """Select only bounded, side-effect-free literal guards; unknown keeps both arms."""
    from .review_audits import _constant_truth_value

    from .credential_role_identity_effects import _validated_exact_scalar
    from itertools import islice

    nodes = tuple(islice(ast.walk(statement.test), 129))
    if len(nodes) > 128:
        return statement.body, statement.orelse
    known = {
        name: scalar[0]
        for kind, env in ((ast.Name, values), (ast.Attribute, expression_values))
        for node in nodes
        if isinstance(node, kind)
        for name in (node.id if kind is ast.Name else ast.dump(node),)
        for value in ((env or {}).get(name),)
        if value is not None
        for scalar in (_validated_exact_scalar(value),)
        if all((scalar, not value.unknown, not value.content_unknown, not value.roots))
    }
    projected = {
        id(child)
        for node in nodes
        if isinstance(node, ast.Attribute)
        if ast.dump(node) in known
        for child in ast.walk(node.value)
    }
    allowed = (
        ast.Constant,
        ast.Name,
        ast.Attribute,
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
    invalid_nodes = any(not isinstance(node, allowed) for node in nodes)
    unbound_reads = any(
        (node.id if isinstance(node, ast.Name) else ast.dump(node)) not in known
        for node in nodes
        if isinstance(node, (ast.Name, ast.Attribute))
        if id(node) not in projected
    )
    oversized_literals = any(
        measure(value) > limit for value, (measure, limit) in measured_literals
    )
    if any((invalid_nodes, unbound_reads, oversized_literals)):
        return statement.body, statement.orelse
    truth = _constant_truth_value(statement.test, known)
    return {True: (statement.body,), False: (statement.orelse,)}.get(
        truth, (statement.body, statement.orelse)
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


# Native database import, context and receiver proof helpers.


def _db_python_symbols(tree):
    nodes = tuple(ast.walk(tree))
    symbols, seen, import_counts = _db_python_initial_symbols(tree, nodes)
    bound = set()
    mutated_modules = set()
    if any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in nodes
    ):
        bound.update(symbols)
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif not _db_python_direct_module_effect(node, symbols, bound, mutated_modules):
            _db_python_reflective_module_effect(node, symbols, mutated_modules)
    bound.update(
        name for name, qualified in symbols.items() if qualified in mutated_modules
    )
    bound.update(
        name
        for name, qualified in symbols.items()
        if qualified
        in {
            module + "." + member
            for module, member in (
                ("sqlite3", "connect"),
                ("contextlib", "contextmanager"),
            )
            if module in mutated_modules
        }
    )
    return symbols, (
        bound
        | {name for name, count in seen.items() if count > 1}
        | {name for name, count in import_counts.items() if count > 1}
    ) & symbols.keys()


def _db_python_initial_symbols(tree, nodes):
    symbols, seen, import_counts = {}, {}, {}
    for node in tree.body:
        for local, qualified in _db_import_bindings(node):
            seen[local] = seen.get(local, 0) + 1
            symbols[local] = qualified
    for node in nodes:
        for local in _db_python_import_names(node):
            import_counts[local] = import_counts.get(local, 0) + 1
    return symbols, seen, import_counts


def _db_python_direct_module_effect(node, symbols, bound, mutated_modules):
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.value, ast.Name)
    ):
        if (symbols.get(node.value.id), node.attr) in {
            ("sqlite3", "connect"),
            ("sqlite3", "Row"),
            ("contextlib", "contextmanager"),
        }:
            bound.add(node.value.id)
            mutated_modules.add(symbols[node.value.id])
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"setattr", "delattr"}
        and node.args
        and isinstance(node.args[0], ast.Name)
    ):
        if symbols.get(node.args[0].id) in {"sqlite3", "contextlib"}:
            bound.add(node.args[0].id)
            mutated_modules.add(symbols[node.args[0].id])
    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        base = node.value
        if (
            isinstance(base, ast.Attribute)
            and base.attr == "__dict__"
            and isinstance(base.value, ast.Name)
            and symbols.get(base.value.id) in {"sqlite3", "contextlib"}
        ):
            bound.add(base.value.id)
            mutated_modules.add(symbols[base.value.id])
    elif (
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Name)
        and symbols.get(node.value.id) in {"sqlite3", "contextlib"}
    ):
        bound.add(node.value.id)
        mutated_modules.add(symbols[node.value.id])
    else:
        return False
    return True


def _db_python_reflective_module_effect(node, symbols, mutated_modules):
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval", "globals", "locals", "__import__"}
    ):
        mutated_modules.update({"sqlite3", "contextlib"})
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and not node.args
    ):
        mutated_modules.update({"sqlite3", "contextlib"})
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and node.args
        and isinstance(node.args[0], ast.Name)
        and symbols.get(node.args[0].id) in {"sqlite3", "contextlib"}
    ):
        mutated_modules.add(symbols[node.args[0].id])
    elif (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "modules"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "sys"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value in {"sqlite3", "contextlib"}
    ):
        mutated_modules.add(node.slice.value)


def _db_import_bindings(node):
    if isinstance(node, ast.Import):
        return [
            (
                alias.asname or alias.name.split(".")[0],
                alias.name if alias.asname else alias.name.split(".")[0],
            )
            for alias in node.names
            if alias.name
            in {"sqlalchemy", "sqlite3", "psycopg", "psycopg2", "contextlib"}
            or alias.name.startswith("sqlalchemy.")
        ]
    if not isinstance(node, ast.ImportFrom) or not node.module:
        return []
    if node.module == "flask_sqlalchemy":
        return [
            (alias.asname or alias.name, node.module + "." + alias.name)
            for alias in node.names
        ]
    if node.module.startswith("sqlalchemy") or node.module in {
        "sqlite3",
        "psycopg",
        "psycopg2",
        "contextlib",
    }:
        return [
            (alias.asname or alias.name, node.module + "." + alias.name)
            for alias in node.names
        ]
    if node.module in {"typing", "typing_extensions"}:
        return [
            (alias.asname or alias.name, "typing.Annotated")
            for alias in node.names
            if alias.name == "Annotated"
        ]
    return []


def _db_python_resolve(node, symbols, shadowed):
    if isinstance(node, ast.Name):
        return symbols.get(node.id) if node.id not in shadowed else None
    if isinstance(node, ast.Attribute):
        parent = _db_python_resolve(node.value, symbols, shadowed)
        return parent + "." + node.attr if parent else None
    return None


def _db_python_call(node, qualified, symbols, shadowed):
    return (
        isinstance(node, ast.Call)
        and _db_python_resolve(node.func, symbols, shadowed) == qualified
    )


def _db_python_sqlite_connect(node, symbols, shadowed):
    """Exclude sqlite connection factories and unpacked options with unknown provenance."""
    return (
        _db_python_call(node, "sqlite3.connect", symbols, shadowed)
        and 1 <= len(node.args) <= 5
        and all(not isinstance(arg, ast.Starred) for arg in node.args)
        and all(
            kw.arg
            in {
                "timeout",
                "detect_types",
                "isolation_level",
                "check_same_thread",
                "cached_statements",
                "uri",
            }
            for kw in node.keywords
        )
    )


def _db_python_private_memory(node):
    """Only the exact SQLite private in-memory database excludes external schema."""
    return bool(
        node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == ":memory:"
    )


def _db_python_sqlite_path_kind(value):
    """Distinguish a literal private DB, literal filename, and unknown target."""
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return "unknown"
    if value.value == ":memory:":
        return "memory"
    if value.value.startswith("file:"):
        return "unknown"
    return "file"


def _db_python_context_path_kind(call, marker):
    fields = marker.split(":")
    mode = fields[2]
    if mode == "fixed":
        return "memory"
    if not mode.isdigit() or len(fields) < 5:
        return "unknown"
    index = int(mode)
    name, default = fields[3:5]
    matches = [kw.value for kw in call.keywords if kw.arg == name]
    if any(kw.arg is None for kw in call.keywords) or len(matches) > 1:
        return "unknown"
    if len(call.args) > index:
        return "unknown" if matches else _db_python_sqlite_path_kind(call.args[index])
    if matches:
        return _db_python_sqlite_path_kind(matches[0])
    return default if default in {"memory", "file"} else "unknown"


def _db_context_traversal_refactor_helpers():
    """Bind all context traversal extraction helpers into database cache identity."""
    return (
        _db_context_traversal_refactor_helpers,
        _db_python_context_name_stable,
        _db_python_contextmanager_descriptor,
        _db_python_contextmanager_argument,
        _db_python_context_body,
        _db_python_guard_stable,
        _db_python_guard_passthrough,
        _db_python_guard_descriptor,
        _db_python_guard_mode,
        _db_python_scope_assignment,
        _db_python_nested_scope,
        _db_python_comprehension_scope,
        _db_python_call_effects,
        _db_python_call_target,
        _db_python_apply_evaluated_call,
        _db_python_evaluated_argument_escapes,
    )


def _db_python_context_name_stable(name, nodes):
    if (
        sum(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name == name
            for n in nodes
        )
        != 1
    ):
        return False
    return not any(
        isinstance(n, ast.Name)
        and n.id == name
        and isinstance(n.ctx, (ast.Store, ast.Del))
        or isinstance(n, ast.arg)
        and n.arg == name
        or isinstance(n, (ast.Import, ast.ImportFrom))
        and (
            name in _db_python_import_names(n)
            or isinstance(n, ast.ImportFrom)
            and any(a.name == "*" for a in n.names)
        )
        or isinstance(n, (ast.Global, ast.Nonlocal))
        and name in n.names
        or isinstance(n, ast.Attribute)
        and isinstance(n.ctx, (ast.Store, ast.Del))
        and isinstance(n.value, ast.Name)
        and n.value.id == name
        or isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in {"setattr", "delattr"}
        and n.args
        and isinstance(n.args[0], ast.Name)
        and n.args[0].id == name
        for n in nodes
    )


def _db_python_contextmanagers(tree, symbols, shadowed):
    """Prove only the fixed, nonescaping same-module SQLite yield wrapper."""
    definitions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and len(node.decorator_list) == 1
        and _db_python_resolve(node.decorator_list[0], symbols, shadowed)
        == "contextlib.contextmanager"
    ]
    result = {}
    if not definitions:
        return result
    nodes = tuple(ast.walk(tree))
    if any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in {"exec", "eval", "globals", "locals", "vars", "__import__"}
        for n in nodes
    ):
        return result
    for node in definitions:
        name = node.name
        if not _db_python_context_name_stable(name, nodes):
            continue
        value = _db_python_contextmanager_descriptor(node, symbols, shadowed)
        if value is not None:
            result[name] = value
    return result


def _db_python_contextmanager_descriptor(node, symbols, shadowed):
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if (
        len(body) not in {2, 4}
        or not isinstance(body[0], ast.Assign)
        or len(body[0].targets) != 1
        or not isinstance(body[0].targets[0], ast.Name)
    ):
        return None
    target = body[0].targets[0].id
    if not _db_python_sqlite_connect(
        body[0].value, symbols, shadowed
    ) or target in _db_python_argument_names(node.args):
        return None
    if len(body) == 4:
        setting, pragma = body[1:3]
        if not (
            isinstance(setting, ast.Assign)
            and len(setting.targets) == 1
            and isinstance(setting.targets[0], ast.Attribute)
            and isinstance(setting.targets[0].value, ast.Name)
            and setting.targets[0].value.id == target
            and setting.targets[0].attr == "row_factory"
            and _db_python_resolve(setting.value, symbols, shadowed) == "sqlite3.Row"
            and isinstance(pragma, ast.Expr)
            and isinstance(pragma.value, ast.Call)
            and isinstance(pragma.value.func, ast.Attribute)
            and isinstance(pragma.value.func.value, ast.Name)
            and pragma.value.func.value.id == target
            and pragma.value.func.attr == "execute"
            and len(pragma.value.args) == 1
            and not pragma.value.keywords
            and isinstance(pragma.value.args[0], ast.Constant)
            and pragma.value.args[0].value == "PRAGMA foreign_keys=ON"
        ):
            return None
    block = body[-1]
    if (
        not isinstance(block, ast.Try)
        or block.handlers
        or block.orelse
        or len(block.body) != 1
        or len(block.finalbody) != 1
    ):
        return None
    yielded = block.body[0]
    closed = block.finalbody[0]
    if not (
        isinstance(yielded, ast.Expr)
        and isinstance(yielded.value, ast.Yield)
        and isinstance(yielded.value.value, ast.Name)
        and yielded.value.value.id == target
        and isinstance(closed, ast.Expr)
        and isinstance(closed.value, ast.Call)
        and not closed.value.args
        and not closed.value.keywords
        and isinstance(closed.value.func, ast.Attribute)
        and closed.value.func.attr == "close"
        and isinstance(closed.value.func.value, ast.Name)
        and closed.value.func.value.id == target
    ):
        return None
    return _db_python_contextmanager_argument(node, body)


def _db_python_contextmanager_argument(node, body):
    argument = body[0].value.args[0]
    parameters = node.args.posonlyargs + node.args.args
    parameter_name, default = "-", "unknown"
    if isinstance(argument, ast.Constant) and argument.value == ":memory:":
        memory = "fixed"
    elif isinstance(argument, ast.Name) and argument.id in [
        arg.arg for arg in parameters
    ]:
        index = [arg.arg for arg in parameters].index(argument.id)
        memory = str(index)
        parameter_name = argument.id
        first_default = len(parameters) - len(node.args.defaults)
        if index >= first_default:
            default = _db_python_sqlite_path_kind(
                node.args.defaults[index - first_default]
            )
        else:
            default = "missing"
    else:
        memory = "unknown"
    return (
        f"__sqlite_contextmanager__:{node.lineno}:{memory}:{parameter_name}:{default}"
    )


def _db_python_guarded_contextmanagers(tree, symbols, shadowed):
    """Prove a simple session/guard/receiver chain, without proving its schema."""
    nodes = tuple(ast.walk(tree))
    if any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in {"exec", "eval", "globals", "locals", "vars", "__import__"}
        for n in nodes
    ):
        return {}

    definitions = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and _db_python_guard_stable(n, symbols, shadowed, nodes)
    ]
    passthrough = {}
    for node in definitions:
        index = _db_python_guard_passthrough(node)
        if index is not None:
            passthrough[node.name] = index

    result = {}
    for node in definitions:
        descriptor = _db_python_guard_descriptor(node, symbols, passthrough)
        if descriptor is not None:
            result[node.name] = descriptor
    return result


def _db_python_guard_passthrough(node):
    params = node.args.posonlyargs + node.args.args
    statements = _db_python_context_body(node)
    if (
        len(statements) != 1
        or not isinstance(statements[0], ast.With)
        or len(statements[0].items) != 1
    ):
        return None
    item = statements[0].items[0]
    if item.optional_vars is not None or not isinstance(item.context_expr, ast.Name):
        return None
    name = item.context_expr.id
    if name not in [p.arg for p in params]:
        return None
    yields = []
    for statement in statements[0].body:
        if isinstance(statement, ast.ImportFrom):
            continue
        if not isinstance(statement, ast.Expr):
            break
        if (
            isinstance(statement.value, ast.Yield)
            and isinstance(statement.value.value, ast.Name)
            and statement.value.value.id == name
        ):
            yields.append(statement)
            continue
        if not (
            isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and all(
                isinstance(a, (ast.Name, ast.Constant)) for a in statement.value.args
            )
            and all(
                k.arg and isinstance(k.value, (ast.Name, ast.Constant))
                for k in statement.value.keywords
            )
        ):
            break
    else:
        if len(yields) == 1 and not any(
            isinstance(n, ast.Name)
            and n.id == name
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for n in ast.walk(node)
        ):
            return [p.arg for p in params].index(name)

    return None


def _db_python_guard_descriptor(node, symbols, passthrough):
    statements = _db_python_context_body(node)
    if (
        len(statements) != 1
        or not isinstance(statements[0], ast.With)
        or len(statements[0].items) != 1
    ):
        return None
    outer = statements[0]
    item = outer.items[0]
    if not (
        isinstance(item.optional_vars, ast.Name)
        and isinstance(item.context_expr, ast.Call)
        and isinstance(item.context_expr.func, ast.Name)
    ):
        return None
    if item.context_expr.keywords or not all(
        isinstance(a, (ast.Name, ast.Constant)) for a in item.context_expr.args
    ):
        return None
    receiver = item.optional_vars.id
    session = symbols.get(item.context_expr.func.id, "")
    if (
        not isinstance(session, str)
        or not session.startswith("__sqlite_contextmanager__:")
        or len(outer.body) != 1
        or not isinstance(outer.body[0], ast.With)
    ):
        return None
    inner = outer.body[0]
    if (
        len(inner.items) != 1
        or inner.items[0].optional_vars is not None
        or not isinstance(inner.items[0].context_expr, ast.Call)
    ):
        return None
    call = inner.items[0].context_expr
    if not isinstance(call.func, ast.Name) or call.func.id not in passthrough:
        return None
    if call.keywords or not all(
        isinstance(a, (ast.Name, ast.Constant)) for a in call.args
    ):
        return None
    index = passthrough[call.func.id]
    if (
        len(call.args) <= index
        or not isinstance(call.args[index], ast.Name)
        or call.args[index].id != receiver
    ):
        return None
    if (
        len(inner.body) != 1
        or not isinstance(inner.body[0], ast.Expr)
        or not isinstance(inner.body[0].value, ast.Yield)
        or not isinstance(inner.body[0].value.value, ast.Name)
        or inner.body[0].value.value.id != receiver
    ):
        return None
    return _db_python_guard_mode(node, session, item)


def _db_python_guard_mode(node, session, item):
    mode, name, default = "unknown", "-", "unknown"
    parts = session.split(":")
    if parts[2] == "fixed":
        mode = "fixed"
    elif parts[2].isdigit() and len(item.context_expr.args) > int(parts[2]):
        value = item.context_expr.args[int(parts[2])]
        params = node.args.posonlyargs + node.args.args
        names = [p.arg for p in params]
        if isinstance(value, ast.Name) and value.id in names:
            index = names.index(value.id)
            mode, name = str(index), value.id
            first_default = len(params) - len(node.args.defaults)
            default = (
                _db_python_sqlite_path_kind(node.args.defaults[index - first_default])
                if index >= first_default
                else "missing"
            )
        elif _db_python_sqlite_path_kind(value) == "memory":
            mode = "fixed"
    return f"__sqlite_contextmanager__:{node.lineno}:{mode}:{name}:{default}:guarded"


def _db_python_context_body(node):
    statements = node.body
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        return statements[1:]
    return statements


def _db_python_guard_stable(node, symbols, shadowed, nodes):
    name = node.name
    if (
        len(node.decorator_list) != 1
        or _db_python_resolve(node.decorator_list[0], symbols, shadowed)
        != "contextlib.contextmanager"
    ):
        return False
    return _db_python_context_name_stable(name, nodes)


def _db_python_escaped_receivers(value, connections):
    """Find SQLite receiver, bound-method or cursor escapes in finite containers."""
    pending, escaped = [value], set()
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Name) and connections.get(node.id) in {
            "sqlite",
            "sqlite_memory",
            "sqlite_uncertain",
        }:
            escaped.add(node.id)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and connections.get(node.value.id)
            in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
        ):
            escaped.add(node.value.id)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "cursor"
            and isinstance(node.func.value, ast.Name)
            and connections.get(node.func.value.id)
            in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
        ):
            escaped.add(node.func.value.id)
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Starred)):
            pending.extend(ast.iter_child_nodes(node))
    return escaped


def _db_python_control_flow_branches(node):
    """Group uncertain control-flow paths so their binding facts stay isolated."""
    if isinstance(node, ast.If):
        return [[node.test], node.body, node.orelse]
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return [[node.iter], node.body, node.orelse]
    if isinstance(node, ast.While):
        return [[node.test], node.body, node.orelse]
    if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
        branches = [node.body]
        branches.extend(
            ([handler.type] if handler.type else []) + handler.body
            for handler in node.handlers
        )
        if node.orelse:
            branches.append(node.orelse)
        if node.finalbody:
            branches.append(node.finalbody)
        return branches
    if isinstance(node, ast.Match):
        branches = [[node.subject]]
        branches.extend(
            ([case.guard] if case.guard else []) + case.body for case in node.cases
        )
        return branches
    return None


def _db_python_invalidate_names(names, engines, connections, sql_bindings):
    """Forget tracked facts whenever a lexical name is rebound or shadowed."""
    names = tuple(names)
    scoped_key = ("sqlite_receiver_schemas",)
    schemas = dict(sql_bindings.get(scoped_key, {}))
    escaped_key = ("sqlite_escaped_receivers",)
    escaped = set(sql_bindings.get(escaped_key, set()))
    for name in names:
        engines.pop(name, None)
        connections.pop(name, None)
        sql_bindings.pop(name, None)
        schemas.pop(name, None)
        escaped.discard(name)
    if scoped_key in sql_bindings:
        sql_bindings[scoped_key] = schemas
    if escaped_key in sql_bindings:
        sql_bindings[escaped_key] = escaped


def _db_python_forget_escaped_schema(names, sql_bindings):
    """Forwarding cannot rebind the local receiver, but its schema may mutate."""
    schemas = dict(sql_bindings.get(("sqlite_receiver_schemas",), {}))
    escaped = set(sql_bindings.get(("sqlite_escaped_receivers",), set()))
    for name in names:
        schemas.pop(name, None)
        escaped.add(name)
    sql_bindings[("sqlite_receiver_schemas",)] = schemas
    sql_bindings[("sqlite_escaped_receivers",)] = escaped


def _db_python_invalidate_nested_bindings(node, engines, connections, sql_bindings):
    """Invalidate every same-scope write before evaluating uncertain control flow."""
    names, wildcard = _db_python_write_names(node)
    if wildcard:
        names.update(engines)
        names.update(connections)
        names.update(sql_bindings)
    _db_python_invalidate_names(names, engines, connections, sql_bindings)


def _db_python_write_names(node):
    """Collect same-scope writes while skipping nested execution scopes."""
    collector = _DBPythonWriteCollector()
    collector.visit(node)
    return collector.names, collector.wildcard


class _DBPythonWriteCollector(ast.NodeVisitor):
    """Visit binding writes without treating nested scopes as current locals."""

    def __init__(self):
        self.names = set()
        self.wildcard = False

    def visit_Name(self, node):
        """Record names written or deleted in this lexical scope."""
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        """Record local names introduced by a plain import statement."""
        self.names.update(_db_python_import_names(node))

    def visit_ImportFrom(self, node):
        """Record imported names and whether a wildcard obscures bindings."""
        self.names.update(_db_python_import_names(node))
        self.wildcard |= any(alias.name == "*" for alias in node.names)

    def visit_FunctionDef(self, node):
        """Inspect a function name and expressions evaluated in its outer scope."""
        self._visit_function_outer_expressions(node)

    def visit_AsyncFunctionDef(self, node):
        """Inspect an async function name and outer-scope expressions."""
        self._visit_function_outer_expressions(node)

    def _visit_function_outer_expressions(self, node):
        self.names.add(node.name)
        expressions = node.decorator_list + node.args.defaults
        expressions.extend(value for value in node.args.kw_defaults if value)
        arguments = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
            + ([node.args.vararg] if node.args.vararg else [])
            + ([node.args.kwarg] if node.args.kwarg else [])
        )
        expressions.extend(arg.annotation for arg in arguments if arg.annotation)
        if node.returns:
            expressions.append(node.returns)
        for expression in expressions:
            self.visit(expression)

    def visit_ClassDef(self, node):
        """Inspect a class name, decorators, bases, and keyword expressions."""
        self.names.add(node.name)
        expressions = node.decorator_list + node.bases
        expressions.extend(keyword.value for keyword in node.keywords)
        for expression in expressions:
            self.visit(expression)

    def visit_Lambda(self, node):
        """Inspect only lambda defaults evaluated in the surrounding scope."""
        expressions = node.args.defaults + node.args.kw_defaults
        for expression in expressions:
            if expression:
                self.visit(expression)

    def visit_ListComp(self, node):
        """Inspect list-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_SetComp(self, node):
        """Inspect set-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_DictComp(self, node):
        """Inspect dict-comprehension expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def visit_GeneratorExp(self, node):
        """Inspect generator expressions evaluated in this scope."""
        self._visit_comprehension_expressions(node)

    def _visit_comprehension_expressions(self, node):
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        expressions = (
            (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
        )
        for expression in expressions:
            self.visit(expression)

    def visit_ExceptHandler(self, node):
        """Record the exception target and inspect the handler's bound names."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        """Record a name captured by a structural pattern."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        """Record a name captured by a starred structural pattern."""
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchMapping(self, node):
        """Record the rest name captured by a mapping pattern."""
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)


def _db_python_argument_names(arguments):
    """Collect all parameter names that shadow module-level connection facts."""
    values = (
        arguments.posonlyargs
        + arguments.args
        + arguments.kwonlyargs
        + ([arguments.vararg] if arguments.vararg else [])
        + ([arguments.kwarg] if arguments.kwarg else [])
    )
    return {argument.arg for argument in values}


def _db_python_import_names(node):
    """Return names introduced by an import for conservative symbol shadowing."""
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names if alias.name != "*"}
    return set()


def _db_python_with_bindings(statement, symbols, shadowed, *, items=None):
    """Map simple with targets to drivers proven by their context expressions."""
    bindings = {}
    for item in statement.items if items is None else items:
        target = item.optional_vars
        names = _db_python_target_names(target)
        driver = None
        if (
            isinstance(statement, ast.With)
            and isinstance(target, ast.Name)
            and (
                _db_python_sqlite_connect(item.context_expr, symbols, shadowed)
                or (
                    isinstance(item.context_expr, ast.Call)
                    and isinstance(item.context_expr.func, ast.Name)
                    and isinstance(symbols.get(item.context_expr.func.id), str)
                    and symbols[item.context_expr.func.id].startswith(
                        "__sqlite_contextmanager__:"
                    )
                    and item.context_expr.func.id not in shadowed
                    and int(symbols[item.context_expr.func.id].split(":")[1])
                    < item.context_expr.lineno
                    and (
                        all(
                            isinstance(arg, ast.Name)
                            or isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)
                            or isinstance(arg, ast.Attribute)
                            and getattr(arg, "_db_proven_plain_field", False)
                            for arg in item.context_expr.args
                        )
                        and all(
                            keyword.arg is not None
                            and (
                                isinstance(keyword.value, ast.Name)
                                or isinstance(keyword.value, ast.Constant)
                                and isinstance(keyword.value.value, str)
                                or isinstance(keyword.value, ast.Attribute)
                                and getattr(
                                    keyword.value, "_db_proven_plain_field", False
                                )
                            )
                            for keyword in item.context_expr.keywords
                        )
                    )
                )
            )
        ):
            driver = "sqlite"
            if _db_python_sqlite_connect(item.context_expr, symbols, shadowed):
                if _db_python_private_memory(item.context_expr):
                    driver = "sqlite_memory"
            else:
                marker = symbols[item.context_expr.func.id]
                path_kind = _db_python_context_path_kind(item.context_expr, marker)
                if path_kind == "memory":
                    driver = "sqlite_memory"
                elif path_kind == "unknown":
                    driver = "sqlite_uncertain"
        for name in names:
            bindings[name] = driver
    return bindings


def _db_python_target_names(target):
    """Return local names assigned by a with optional target."""
    if target is None:
        return set()
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _db_python_register_assignment(
    statement, name, symbols, shadowed, engines, connections
):
    engines.pop(name, None)
    connections.pop(name, None)
    value = (
        statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign)) else None
    )
    if not isinstance(value, ast.Call):
        return
    if _db_python_call(value, "sqlalchemy.create_engine", symbols, shadowed):
        engines[name] = "sqlalchemy"
    elif _db_python_sqlite_connect(value, symbols, shadowed):
        connections[name] = (
            "sqlite_memory" if _db_python_private_memory(value) else "sqlite"
        )
    elif any(
        _db_python_call(value, driver + ".connect", symbols, shadowed)
        for driver in ("psycopg", "psycopg2")
    ):
        connections[name] = "psycopg"
    elif _db_python_connection_call(value, "connect", engines):
        connections[name] = "sqlalchemy"
    elif _db_python_connection_call(value, "cursor", connections):
        connections[name] = "psycopg"


def _db_python_connection_call(value, method, known):
    return (
        isinstance(value.func, ast.Attribute)
        and value.func.attr == method
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id in known
    )


def _db_assignment_targets(statement):
    if isinstance(statement, ast.Assign):
        targets = statement.targets
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets = [statement.target]
    else:
        return []
    return sorted(
        {name for target in targets for name in _db_python_target_names(target)}
    )


def _db_python_context_exports(unique, import_module):
    """Bind direct context imports only to unique, unmodified captured sources."""
    candidates = []
    for module, (_, tree, shadowed, exports) in unique.items():
        symbols, local_shadowed = _db_python_symbols(tree)
        summaries = _db_python_contextmanagers(tree, symbols, local_shadowed)
        symbols.update(summaries)
        summaries.update(
            _db_python_guarded_contextmanagers(tree, symbols, local_shadowed)
        )
        for name, marker in summaries.items():
            if name not in shadowed:
                candidates.append((module, name, marker, exports))
    trees = [(module, row[1]) for module, row in unique.items()]
    for provider, name, marker, exports in candidates:
        if not _db_python_context_export_stable(trees, provider, name, import_module):
            continue
        fields = marker.split(":")
        fields[1] = "0"  # A verified imported binding is available at module entry.
        exports[name] = ("symbol", ":".join(fields))
    _db_python_witnessed_field_contexts(unique, import_module)
    _db_python_server_field_contexts(unique, import_module)
    _db_python_call_contexts(unique, import_module)


def _db_python_witnessed_field_contexts(unique, import_module):
    from . import _db_python_witnessed_field_contexts_impl

    return _db_python_witnessed_field_contexts_impl(
        unique,
        import_module,
        _db_python_plain_path_fields,
        _db_python_context_export_stable,
        _db_python_class_witnesses,
        _db_python_constructor_called_methods,
        _db_python_self_or_field_mutated,
    )


def _db_python_call_contexts(unique, import_module):
    """Bind direct, unshadowed calls to captured resource-bearing functions."""
    functions = {}
    rows = [(module, *row[:2]) for module, row in unique.items()]
    project_trees = [(module, tree) for module, _, tree in rows]
    for module, path, tree in rows:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                node.__dict__.pop("_db_callee_context", None)
        digest = getattr(tree, "_db_source_sha256", None)
        if not isinstance(digest, str):
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                continue
            if not _db_python_resource_function(node, tree):
                continue
            functions[module, node.name] = (node, path, digest, tree, module)
    for module, path, tree in rows:
        digest = getattr(tree, "_db_source_sha256", None)
        if not isinstance(digest, str):
            continue
        _db_python_bind_tree_calls(
            module, path, tree, digest, functions, project_trees, import_module
        )


def _db_python_bind_tree_calls(
    module, path, tree, digest, functions, project_trees, import_module
):
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    imports = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    stability = {}
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        local = call.func.id
        options = _db_python_call_options(
            module, local, call, imports, parents, functions, import_module
        )
        if len(options) != 1:
            continue
        function, source, source_hash, provider_tree, provider_module = options[0]
        if not _db_python_call_stable(
            tree,
            module,
            local,
            function,
            provider_module,
            project_trees,
            import_module,
            stability,
        ):
            continue
        provider_symbols, provider_shadowed = _db_python_symbols(provider_tree)
        call._db_callee_context = {
            "function": function,
            "source": source,
            "source_sha256": source_hash,
            "callsite": path,
            "callsite_sha256": digest,
            "line": call.lineno,
            "symbols": provider_symbols,
            "shadowed": provider_shadowed,
        }


def _db_python_call_stable(
    tree,
    module,
    local,
    function,
    provider_module,
    project_trees,
    import_module,
    stability,
):
    caller_key = (module, local)
    if caller_key not in stability:
        stability[caller_key] = _db_python_context_export_stable(
            [(module, tree)], module, local, import_module
        )
    provider_key = (provider_module, function.name)
    if provider_key not in stability:
        stability[provider_key] = _db_python_context_export_stable(
            project_trees, provider_module, function.name, import_module
        )
    return (
        stability[caller_key]
        and stability[provider_key]
        and not any(
            isinstance(n, ast.Name)
            and n.id == local
            and isinstance(n.ctx, (ast.Store, ast.Del))
            or isinstance(n, ast.arg)
            and n.arg == local
            for n in ast.walk(tree)
        )
    )


def _db_python_resource_function(node, tree):
    parameters = _db_python_argument_names(node.args)
    return (
        any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "execute"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in parameters
            for n in ast.walk(node)
        )
        and sum(
            isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == node.name
            for n in ast.walk(tree)
        )
        == 1
    )


def _db_python_call_options(
    module, local, call, imports, parents, functions, import_module
):
    options = []
    if (module, local) in functions:
        options.append(functions[module, local])
    for node in imports:
        if not _db_python_import_before_call(node, call, parents):
            continue
        provider = import_module(module, node)
        for alias in node.names:
            if (alias.asname or alias.name) == local and (
                provider,
                alias.name,
            ) in functions:
                options.append(functions[provider, alias.name])
    return options


def _db_python_transfer_call(
    call,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    execute,
):
    """Analyze one captured callee with only caller-proven receiver bindings."""
    from . import _bind_source_call

    context = getattr(call, "_db_callee_context", None)
    if not isinstance(context, dict):
        return False, False
    # Sibling argument expressions run before the callee. Until their effects
    # are modeled in order, do not transfer a pre-evaluation receiver state.
    values = list(call.args) + [keyword.value for keyword in call.keywords]
    if any(not isinstance(value, (ast.Name, ast.Constant)) for value in values):
        return False, False
    try:
        bound = _bind_source_call(call, context["function"], apply_defaults=False)
    except ValueError:
        return False, False
    actuals = {
        formal: value.id
        for formal, value in bound.items()
        if isinstance(value, ast.Name)
        and connections.get(value.id) in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
    }
    if not actuals:
        return False, False
    if len(set(actuals.values())) != len(actuals):
        gaps.append("python_resource_alias_unresolved:" + context["callsite"])
        return False, False
    key = (context["source"], context["source_sha256"], context["function"].lineno)
    stack = tuple(sql_bindings.get(("sqlite_context_stack",), ()))
    budget = sql_bindings.setdefault(("sqlite_context_budget",), [0])
    if key in stack or len(stack) >= 16 or budget[0] >= 64:
        gaps.append("python_resource_context_limit:" + context["callsite"])
        return False, False
    budget[0] += 1
    local = dict(sql_bindings)
    local[("sqlite_context_stack",)] = stack + (key,)
    schemas = sql_bindings.get(("sqlite_receiver_schemas",), {})
    local[("sqlite_receiver_schemas",)] = {
        formal: deepcopy(schemas[actual])
        for formal, actual in actuals.items()
        if actual in schemas
    }
    escaped = sql_bindings.get(("sqlite_escaped_receivers",), set())
    local[("sqlite_escaped_receivers",)] = {
        formal for formal, actual in actuals.items() if actual in escaped
    }
    start = len(queries)
    _db_python_scope_native(
        context["function"].body,
        context["source"],
        context["source_sha256"],
        context["symbols"],
        context["shadowed"],
        dialect,
        sqlglot,
        exp,
        {},
        {formal: connections[actual] for formal, actual in actuals.items()},
        queries,
        gaps,
        local,
        execute=execute,
    )
    for query in queries[start:]:
        previous = query.get("source_context")
        query["source_context"] = {
            "source_path": context["source"],
            "source_sha256": context["source_sha256"],
            "callable": context["function"].name,
            "callsite_path": context["callsite"],
            "callsite_sha256": context["callsite_sha256"],
            "callsite_line": context["line"],
        }
        if previous:
            query["source_context"]["callee"] = previous
    table = _db_python_closed_select(context["function"], set(actuals))
    readonly = table == "<constant>" or bool(
        table and all(table in schemas.get(actual, {}) for actual in actuals.values())
    )
    if not readonly:
        _db_python_forget_escaped_schema(actuals.values(), sql_bindings)
    return True, readonly


def _db_python_closed_select(function, receiver_names):
    """Recognize only a single direct, literal SELECT with no resource escape."""
    if (
        len(receiver_names) != 1
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
    ):
        return None
    value = function.body[0].value
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr in {"fetchone", "fetchall"}
        and not value.args
        and not value.keywords
    ):
        value = value.func.value
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id in receiver_names
        and value.func.attr == "execute"
        and len(value.args) == 1
        and not value.keywords
        and isinstance(value.args[0], ast.Constant)
        and isinstance(value.args[0].value, str)
    ):
        return None
    words = value.args[0].value.strip().split()
    if len(words) == 2 and words[0].upper() == "SELECT" and words[1].isdigit():
        return "<constant>"
    if (
        len(words) == 4
        and words[0].upper() == "SELECT"
        and words[1].isidentifier()
        and words[2].upper() == "FROM"
        and words[3].isidentifier()
    ):
        return words[3].lower()
    return None


def _db_python_plain_path_fields(cls, init, path_name):
    fields = set()
    for statement in init.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target, value = statement.targets[0], statement.value
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == path_name
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Name)
            and not value.keywords
        ):
            fields.add(target.attr)
    for field in tuple(fields):
        if any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == field
            or isinstance(n, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(t, ast.Name) and t.id == field
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
            )
            for n in cls.body
        ):
            fields.remove(field)
            continue
        stores = [
            n
            for n in ast.walk(cls)
            if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == "self"
            and n.attr == field
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ]
        if len(stores) != 1:
            fields.remove(field)
    return fields


def _db_python_class_witnesses(rows, provider, class_name, import_module):
    """Accept direct captured constructors with effect-free argument expressions."""
    witnesses = []
    for module, path, tree in rows:
        digest = getattr(tree, "_db_source_sha256", None)
        if not isinstance(digest, str):
            continue
        aliases = {class_name} if module == provider else set()
        for node in tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and import_module(module, node) == provider
            ):
                aliases.update(
                    a.asname or a.name for a in node.names if a.name == class_name
                )
        if not aliases:
            continue
        if any(
            isinstance(n, ast.Name)
            and n.id in aliases
            and isinstance(n.ctx, (ast.Store, ast.Del))
            or isinstance(n, ast.arg)
            and n.arg in aliases
            for n in ast.walk(tree)
        ):
            continue
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for call in ast.walk(tree):
            if _db_python_class_witness_accepted(call, aliases, parents, tree):
                witnesses.append({"path": path, "sha256": digest, "call": call})
    return witnesses


def _db_python_class_witness_accepted(call, aliases, parents, tree):
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id in aliases
    ) or any(k.arg is None for k in call.keywords):
        return False
    scope = parents.get(call)
    while scope is not None and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
    ):
        scope = parents.get(scope)
    return all(
        _db_python_constructor_arg_safe(a, scope, tree) for a in call.args
    ) and all(
        _db_python_constructor_arg_safe(k.value, scope, tree) for k in call.keywords
    )


def _db_python_constructor_arg_safe(value, scope, tree):
    if isinstance(value, ast.Constant):
        return True
    if not (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return False
    namespace = value.value.id
    assignments = [
        n
        for n in ast.walk(scope)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == namespace
    ]
    if len(assignments) != 1:
        return False
    parsed = assignments[0].value
    if not (
        isinstance(parsed, ast.Call)
        and isinstance(parsed.func, ast.Attribute)
        and parsed.func.attr == "parse_args"
        and isinstance(parsed.func.value, ast.Name)
        and not parsed.args
        and not parsed.keywords
    ):
        return False
    parser = parsed.func.value.id
    definitions = [
        n
        for n in ast.walk(scope)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == parser
    ]
    if len(definitions) != 1:
        return False
    constructor = definitions[0].value
    if not (
        isinstance(constructor, ast.Call)
        and isinstance(constructor.func, ast.Attribute)
        and constructor.func.attr == "ArgumentParser"
        and isinstance(constructor.func.value, ast.Name)
    ):
        return False
    argparse_alias = constructor.func.value.id
    if (
        sum(
            isinstance(n, ast.Import)
            and any(
                a.name == "argparse" and (a.asname or a.name) == argparse_alias
                for a in n.names
            )
            for n in tree.body
        )
        != 1
    ):
        return False
    if not _db_python_argparse_proven(
        scope, tree, namespace, parser, argparse_alias, value
    ):
        return False
    return _db_python_argparse_option(
        scope, parser, value, definitions[0].lineno, assignments[0].lineno
    )


def _db_python_argparse_option(scope, parser, value, parser_line, parse_line):
    for n in ast.walk(scope):
        if not (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == parser
            and n.func.attr == "add_argument"
            and n.args
        ):
            continue
        flag = n.args[0]
        if (
            isinstance(flag, ast.Constant)
            and isinstance(flag.value, str)
            and flag.value.lstrip("-").replace("-", "_") == value.attr
            and parser_line < n.lineno < parse_line < value.lineno
        ):
            keywords = {k.arg: k.value for k in n.keywords}
            if len(keywords) != len(n.keywords) or "action" in keywords:
                return False
            if "dest" in keywords and not (
                isinstance(keywords["dest"], ast.Constant)
                and keywords["dest"].value == value.attr
            ):
                return False
            if "default" in keywords and not _db_python_safe_path_default(
                keywords["default"]
            ):
                return False
            return any(
                k.arg == "type"
                and isinstance(k.value, ast.Name)
                and k.value.id == "Path"
                for k in n.keywords
            )
    return False


def _db_python_argparse_proven(scope, tree, namespace, parser, argparse_alias, value):
    """Reject rebound/escaped argparse bindings and namespace field writes."""
    nodes = tuple(ast.walk(scope))
    parents = {
        child: parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    return (
        _db_python_argparse_origin_safe(tree, argparse_alias)
        and _db_python_argparse_locals_safe(nodes, namespace, parser)
        and _db_python_argparse_uses_safe(nodes, parents, namespace, parser)
    )


def _db_python_argparse_origin_safe(tree, argparse_alias):
    if (
        sum(
            isinstance(n, ast.ImportFrom)
            and n.module == "pathlib"
            and any(
                a.name == "Path" and (a.asname or a.name) == "Path" for a in n.names
            )
            for n in tree.body
        )
        != 1
    ):
        return False
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Name)
            and n.id in {"Path", argparse_alias}
            and isinstance(n.ctx, (ast.Store, ast.Del))
            or isinstance(n, ast.arg)
            and n.arg in {"Path", argparse_alias}
            or isinstance(n, (ast.FunctionDef, ast.ClassDef))
            and n.name in {"Path", argparse_alias}
        ):
            return False
    return True


def _db_python_argparse_locals_safe(nodes, namespace, parser):
    for name in (namespace, parser):
        if (
            sum(
                isinstance(n, ast.Name)
                and n.id == name
                and isinstance(n.ctx, ast.Store)
                for n in nodes
            )
            != 1
        ):
            return False
        if any(isinstance(n, ast.arg) and n.arg == name for n in nodes):
            return False
    return True


def _db_python_argparse_uses_safe(nodes, parents, namespace, parser):
    for n in nodes:
        if (
            not isinstance(n, ast.Name)
            or not isinstance(n.ctx, ast.Load)
            or n.id not in {namespace, parser}
        ):
            continue
        parent = parents.get(n)
        if (
            not isinstance(parent, ast.Attribute)
            or parent.value is not n
            or not isinstance(parent.ctx, ast.Load)
        ):
            return False
        if n.id == namespace and parent.attr == "__dict__":
            return False
        if n.id == parser:
            call = parents.get(parent)
            if parent.attr not in {"add_argument", "parse_args", "error"} or not (
                isinstance(call, ast.Call) and call.func is parent
            ):
                return False
    return True


def _db_python_safe_path_default(value):
    if isinstance(value, ast.Constant):
        return isinstance(value.value, str) or value.value is None
    if isinstance(value, ast.Name):
        return value.id == "__file__"
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
        return _db_python_safe_path_default(
            value.left
        ) and _db_python_safe_path_default(value.right)
    if isinstance(value, ast.Attribute) and value.attr == "parent":
        return _db_python_safe_path_default(value.value)
    if isinstance(value, ast.Call) and not value.keywords:
        if (
            isinstance(value.func, ast.Name)
            and value.func.id == "Path"
            and len(value.args) == 1
        ):
            return _db_python_safe_path_default(value.args[0])
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "resolve"
            and not value.args
        ):
            return _db_python_safe_path_default(value.func.value)
    return False


def _db_python_constructor_called_methods(init, call):
    params = init.args.posonlyargs + init.args.args
    defaults = (
        {
            p.arg: d.value
            for p, d in zip(params[-len(init.args.defaults) :], init.args.defaults)
            if isinstance(d, ast.Constant)
        }
        if init.args.defaults
        else {}
    )
    for index, value in enumerate(call.args, 1):
        if index < len(params):
            defaults[params[index].arg] = (
                value.value if isinstance(value, ast.Constant) else None
            )
    for keyword in call.keywords:
        defaults[keyword.arg] = (
            keyword.value.value if isinstance(keyword.value, ast.Constant) else None
        )
    called, pending = set(), list(init.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and defaults.get(node.test.id) is True:
                pending.extend(node.body)
            elif (
                isinstance(node.test, ast.Name) and defaults.get(node.test.id) is False
            ):
                pending.extend(node.orelse)
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "self"
            and not node.value.args
            and not node.value.keywords
        ):
            called.add(node.value.func.attr)
    return called


def _db_python_context_export_stable(trees, provider, name, import_module):
    """Reject reflection, possible module mutation, and imported function escapes."""
    for module, tree in trees:
        nodes = tuple(ast.walk(tree))
        imported = _db_python_export_aliases(
            nodes, module, provider, name, import_module
        )
        if imported is None:
            return False
        aliases, modules = imported
        parents = {
            child: parent for parent in nodes for child in ast.iter_child_nodes(parent)
        }
        scopes = {}
        if any(
            _db_python_export_scoped_node_unsafe(
                node, aliases, modules, name, parents, scopes
            )
            for node in nodes
        ):
            return False
    return True


def _db_python_export_scoped_node_unsafe(node, aliases, modules, name, parents, scopes):
    visible = _db_python_export_visible_names(node, aliases | modules, parents, scopes)
    return _db_python_export_node_unsafe(
        node, aliases & visible, modules & visible, name, parents
    )


def _db_python_export_visible_names(node, names, parents, scopes):
    """Resolve function locals without applying them to defaults or decorators."""
    if not names:
        return set()
    visible, unresolved = set(names), set(names)
    child = node
    while unresolved and (parent := parents.get(child)) is not None:
        if isinstance(parent, ast.ClassDef):
            # Class namespaces and their global directives are not function locals.
            break
        if (
            isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child in parent.body
        ):
            if parent not in scopes:
                scopes[parent] = _db_python_export_scope_bindings(parent)
            local, global_names = scopes[parent]
            visible.difference_update(unresolved & local)
            unresolved.difference_update(local | global_names)
        child = parent
    return visible


def _db_python_export_scope_bindings(function):
    body = ast.Module(body=function.body, type_ignores=[])
    written, _ = _db_python_write_names(body)
    local = written | _db_python_argument_names(function.args)
    globals_, nonlocals, imports = set(), set(), set()
    for node in _db_python_export_scope_nodes(body):
        if isinstance(node, ast.Global):
            globals_.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            nonlocals.update(node.names)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.update(_db_python_import_names(node))
    # Imported provider aliases still need escape checks in their local scope.
    return local - globals_ - nonlocals - imports, globals_ | imports


def _db_python_export_scope_nodes(node):
    yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            yield from _db_python_export_scope_nodes(child)


def _db_python_export_aliases(nodes, module, provider, name, import_module):
    aliases = {name} if module == provider else set()
    modules = set()
    for node in nodes:
        if isinstance(node, ast.ImportFrom):
            if import_module(module, node) == provider:
                aliases.update(a.asname or a.name for a in node.names if a.name == name)
            for alias in node.names:
                if import_module(module, node) + "." + alias.name == provider:
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            if not _db_python_export_module_aliases(node, provider, modules):
                return None
    return aliases, modules


def _db_python_export_module_aliases(node, provider, modules):
    for alias in node.names:
        if alias.name == provider:
            if not alias.asname:
                return False
            modules.add(alias.asname)
    return True


def _db_python_export_node_unsafe(node, aliases, modules, name, parents):
    if _db_python_export_call_unsafe(node, aliases, modules):
        return True
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        if isinstance(node.value, ast.Attribute) and node.value.attr in {
            "__dict__",
            "modules",
        }:
            return True
    if _db_python_export_attribute_unsafe(node, aliases, name):
        return True
    return _db_python_export_reference_unsafe(node, aliases, modules, name, parents)


def _db_python_export_call_unsafe(node, aliases, modules):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id in {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "__import__",
        "setattr",
        "delattr",
    }:
        return True
    return bool(
        node.func.id == "getattr"
        and node.args
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in aliases | modules
    )


def _db_python_export_attribute_unsafe(node, aliases, name):
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr in {
        name,
        "connect",
        "Row",
        "Path",
        "contextmanager",
        "ArgumentParser",
        "parse_args",
        "add_argument",
    } and isinstance(node.ctx, (ast.Store, ast.Del)):
        return True
    return (
        isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.value, ast.Name)
        and node.value.id in aliases
    )


def _db_python_export_reference_unsafe(node, aliases, modules, name, parents):
    if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
        return False
    parent = parents.get(node)
    if node.id in aliases:
        if not isinstance(parent, ast.Call) or parent.func is not node:
            return True
    if node.id in modules:
        outer = parents.get(parent)
        if not (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr == name
            and isinstance(outer, ast.Call)
            and outer.func is parent
        ):
            return True
    return False


def _db_python_export_identity_functions():
    return (
        _db_python_export_identity_functions,
        _db_python_export_scoped_node_unsafe,
        _db_python_export_visible_names,
        _db_python_export_scope_bindings,
        _db_python_export_scope_nodes,
        _db_python_export_aliases,
        _db_python_export_module_aliases,
        _db_python_export_node_unsafe,
        _db_python_export_call_unsafe,
        _db_python_export_attribute_unsafe,
        _db_python_export_reference_unsafe,
    )


# SQLite AST traversal uses a caller-supplied SQL execution callback.


def _db_python_query_native(
    tree,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    queries,
    gaps,
    *,
    execute,
):
    engines, connections = ({}, {})
    _db_python_scope_native(
        tree.body,
        path,
        digest,
        symbols,
        shadowed,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        queries,
        gaps,
        nested_scope_checks=False,
        execute=execute,
    )
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_names = _db_python_argument_names(node.args)
            local_connections = {
                key: value
                for key, value in connections.items()
                if key not in local_names
            }
            _db_python_scope_native(
                node.body,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                {
                    key: value
                    for key, value in engines.items()
                    if key not in local_names
                },
                local_connections,
                queries,
                gaps,
                execute=execute,
            )
        elif isinstance(node, ast.ClassDef):
            _db_python_query_class(
                node,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                queries,
                gaps,
                execute,
            )


def _db_python_query_class(
    node, path, digest, symbols, shadowed, dialect, sqlglot, exp, queries, gaps, execute
):
    for method in node.body:
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _db_python_scope_native(
                method.body,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                {},
                {},
                queries,
                gaps,
                execute=execute,
            )
            contexts = getattr(method, "_db_field_contexts", ())
            if len(contexts) > 64:
                gaps.append("python_resource_context_limit:" + path)
            for context in contexts[:64]:
                contextual = deepcopy(method)
                fields = set(context["plain_fields"])
                chains = {tuple(chain) for chain in context.get("plain_chains", ())}
                _db_python_mark_plain_fields(
                    contextual,
                    fields,
                    chains,
                    context.get("plain_before_line", 1 << 30),
                )
                first = len(queries)
                _db_python_scope_native(
                    contextual.body,
                    path,
                    digest,
                    symbols,
                    shadowed,
                    dialect,
                    sqlglot,
                    exp,
                    {},
                    {},
                    queries,
                    gaps,
                    execute=execute,
                )
                for query in queries[first:]:
                    previous = query.get("source_context")
                    query["source_context"] = {
                        k: v for k, v in context.items() if k != "plain_fields"
                    }
                    if previous:
                        query["source_context"]["callee"] = previous


def _db_python_mark_plain_fields(contextual, fields, chains, before):
    for node in ast.walk(contextual):
        if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
            continue
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr in fields
        ):
            node._db_proven_plain_field = True
        elif (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and (node.value.attr, node.attr) in chains
            and node.lineno < before
        ):
            node._db_proven_plain_field = True


def _db_python_local_refactor_identity_functions():
    from . import _db_witness_identity_functions, _db_server_graph_identity_functions

    return (
        *_db_witness_identity_functions(),
        *_db_server_graph_identity_functions(),
        _db_python_class_witness_accepted,
        _db_python_local_refactor_identity_functions,
        _db_python_bind_tree_calls,
        _db_python_call_stable,
        _db_python_resource_function,
        _db_python_call_options,
        _db_python_query_class,
        _db_python_mark_plain_fields,
    )


def _db_python_scope_native(
    statements,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    queries,
    gaps,
    sql_bindings=None,
    nested_scope_checks=True,
    *,
    execute,
):
    if sql_bindings is None:
        sql_bindings = {}
    for statement in statements:
        value = (
            statement.value
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        escaped = _db_python_escaped_receivers(value, connections)
        if escaped:
            _db_python_forget_escaped_schema(escaped, sql_bindings)
            gaps.append("python_connection_alias_unsupported:" + path)
        if not isinstance(statement, (ast.With, ast.AsyncWith)):
            _db_python_invalidate_nested_bindings(
                statement, engines, connections, sql_bindings
            )
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if nested_scope_checks:
                _db_python_scope_calls_native(
                    statement,
                    path,
                    digest,
                    symbols,
                    shadowed,
                    dialect,
                    sqlglot,
                    exp,
                    engines,
                    connections,
                    sql_bindings,
                    queries,
                    gaps,
                    execute=execute,
                )
            continue
        _db_python_scope_assignment(
            statement, symbols, shadowed, engines, connections, sql_bindings
        )
        _db_python_scope_calls_native(
            statement,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            engines,
            connections,
            sql_bindings,
            queries,
            gaps,
            execute=execute,
        )


def _db_python_scope_assignment(
    statement, symbols, shadowed, engines, connections, sql_bindings
):
    destructured = (
        isinstance(statement, ast.Assign)
        and not all(isinstance(target, ast.Name) for target in statement.targets)
        or isinstance(statement, ast.AnnAssign)
        and not isinstance(statement.target, ast.Name)
    )
    for name in _db_assignment_targets(statement):
        if destructured:
            _db_python_invalidate_names((name,), engines, connections, sql_bindings)
            continue
        _db_python_register_assignment(
            statement, name, symbols, shadowed, engines, connections
        )
        if isinstance(statement, ast.AugAssign):
            sql_bindings.pop(name, None)
            continue
        value = statement.value
        literal = _db_python_sql_literal(value, symbols, shadowed, sql_bindings)
        if literal is not None:
            sql_bindings[name] = (
                literal,
                _db_python_contains_text(value, symbols, shadowed, sql_bindings),
            )
        else:
            sql_bindings.pop(name, None)


def _db_python_scope_calls_native(
    node,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    *,
    execute,
):
    """Visit execute calls and nested manager scopes without crossing functions."""
    pending = [(node, False, None)]
    while pending:
        current, evaluated, target = pending.pop()
        if evaluated:
            _db_python_apply_evaluated_call(
                current,
                target,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                sql_bindings,
                queries,
                gaps,
                execute,
            )
            continue
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            _db_python_nested_scope(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                sql_bindings,
                queries,
                gaps,
                execute,
            )
            continue
        if _db_python_control_flow_branches(current) is not None:
            _db_python_isolated_control_flow_calls_native(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                sql_bindings,
                queries,
                gaps,
                execute=execute,
            )
            continue
        if isinstance(current, (ast.With, ast.AsyncWith)):
            _db_python_with_scope_native(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                queries,
                gaps,
                sql_bindings,
                execute=execute,
            )
            continue
        if isinstance(
            current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            _db_python_comprehension_scope(
                current,
                path,
                digest,
                symbols,
                shadowed,
                dialect,
                sqlglot,
                exp,
                engines,
                connections,
                sql_bindings,
                queries,
                gaps,
                execute,
            )
            continue
        if isinstance(current, ast.Call):
            pending.append(
                (current, True, _db_python_call_target(current, connections))
            )
        pending.extend(
            (child, False, None)
            for child in reversed(list(ast.iter_child_nodes(current)))
        )


def _db_python_call_target(call, connections):
    """Capture a direct execute receiver before evaluating its arguments."""
    target = None
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "execute"
        and isinstance(call.func.value, ast.Name)
    ):
        name = call.func.value.id
        target = name, connections.get(name)
    return target, dict(connections)


def _db_python_evaluated_argument_escapes(
    call, before, connections, bindings, gaps, path
):
    """Retain escaped argument provenance without reviving a closed receiver."""
    arguments = call.args + [keyword.value for keyword in call.keywords]
    escaped = set().union(
        *(_db_python_escaped_receivers(argument, before) for argument in arguments)
    )
    lost = escaped - connections.keys()
    if lost:
        _db_python_forget_escaped_schema(lost, bindings)
        gaps.append("python_connection_escape_schema_unknown:" + path)


def _db_python_apply_evaluated_call(
    call,
    target,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    execute,
):
    """Apply a call once, after its callee and argument expressions were visited."""
    target, before = target
    _db_python_evaluated_argument_escapes(
        call, before, connections, sql_bindings, gaps, path
    )
    _db_python_call_effects(
        call,
        path,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        sql_bindings,
        queries,
        gaps,
        execute,
    )
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "execute":
        return
    if target is not None:
        name, driver = target
        writes, _ = _db_python_write_names(call)
        if name in writes or connections.get(name) != driver:
            gaps.append("python_execute_target_changed_during_arguments:" + path)
            return
        arguments = call.args + [keyword.value for keyword in call.keywords]
        if driver in {"sqlite", "sqlite_memory", "sqlite_uncertain"} and any(
            isinstance(
                node, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.Starred)
            )
            for argument in arguments
            for node in ast.walk(argument)
        ):
            _db_python_forget_escaped_schema((name,), sql_bindings)
            gaps.append("python_execute_argument_effect_unproven:" + path)
            return
    execute(
        call,
        path,
        digest,
        symbols,
        shadowed,
        dialect,
        sqlglot,
        exp,
        connections,
        sql_bindings,
        queries,
        gaps,
    )


def _db_python_call_effects(
    current,
    path,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    execute,
):
    arguments = list(current.args) + [keyword.value for keyword in current.keywords]
    handled, readonly = _db_python_transfer_call(
        current,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        sql_bindings,
        queries,
        gaps,
        execute,
    )
    escaped = set().union(
        *(_db_python_escaped_receivers(arg, connections) for arg in arguments)
    )
    if escaped and not (handled and readonly):
        _db_python_forget_escaped_schema(escaped, sql_bindings)
        gaps.append("python_connection_escape_schema_unknown:" + path)
    if isinstance(current.func, ast.Attribute) and isinstance(
        current.func.value, ast.Name
    ):
        receiver = current.func.value.id
        if connections.get(receiver) in {
            "sqlite",
            "sqlite_memory",
            "sqlite_uncertain",
        } and current.func.attr in {"close", "executescript", "executemany"}:
            if current.func.attr == "close":
                _db_python_invalidate_names(
                    (receiver,), engines, connections, sql_bindings
                )
            else:
                gaps.append("python_connection_method_unsupported:" + path)
                _db_python_forget_escaped_schema((receiver,), sql_bindings)
        elif (
            connections.get(receiver) in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
            and current.func.attr == "rollback"
        ):
            schemas = dict(sql_bindings.get(("sqlite_receiver_schemas",), {}))
            schemas.pop(receiver, None)
            sql_bindings["sqlite_receiver_schemas",] = schemas


def _db_python_comprehension_scope(
    current,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    execute,
):
    escaped = set()
    first = current.generators[0].iter if current.generators else None
    first_nodes = set(ast.walk(first)) if first is not None else set()
    parents = {
        child: parent
        for parent in ast.walk(current)
        for child in ast.iter_child_nodes(parent)
    }
    for candidate in ast.walk(current):
        if (
            isinstance(candidate, ast.Name)
            and isinstance(candidate.ctx, ast.Load)
            and (candidate.id in connections)
        ):
            parent = parents.get(candidate)
            if not (
                candidate in first_nodes
                and isinstance(parent, ast.Attribute)
                and (parent.value is candidate)
                and (parent.attr == "execute")
            ):
                escaped.add(candidate.id)
        if isinstance(candidate, ast.Call):
            for argument in list(candidate.args) + [
                k.value for k in candidate.keywords
            ]:
                escaped.update(_db_python_escaped_receivers(argument, connections))
            func = candidate.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and (func.value.id in connections)
                and (func.attr != "execute" or candidate not in first_nodes)
            ):
                escaped.add(func.value.id)
    if escaped:
        _db_python_forget_escaped_schema(escaped, sql_bindings)
        gaps.append("python_connection_escape_schema_unknown:" + path)
    executes = [
        candidate
        for candidate in ast.walk(current)
        if isinstance(candidate, ast.Call)
        and isinstance(candidate.func, ast.Attribute)
        and (candidate.func.attr == "execute")
    ]
    first_executes = (
        [
            candidate
            for candidate in ast.walk(first)
            if isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and (candidate.func.attr == "execute")
        ]
        if first is not None
        else []
    )
    if executes and len(executes) == len(first_executes):
        _db_python_scope_calls_native(
            first,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            engines,
            connections,
            sql_bindings,
            queries,
            gaps,
            execute=execute,
        )
        return
    if any(
        (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and (candidate.func.attr == "execute")
            for candidate in ast.walk(current)
        )
    ):
        gaps.append("python_execute_comprehension_scope_unsupported:" + path)
    return


def _db_python_nested_scope(
    current,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    execute,
):
    captured = {
        n.id
        for n in ast.walk(current)
        if isinstance(n, ast.Name)
        and isinstance(n.ctx, ast.Load)
        and (connections.get(n.id) in {"sqlite", "sqlite_memory", "sqlite_uncertain"})
    }
    if captured:
        _db_python_forget_escaped_schema(captured, sql_bindings)
        gaps.append("python_connection_escape_schema_unknown:" + path)
    if (
        isinstance(current, ast.FunctionDef)
        and (not current.decorator_list)
        and (not current.args.defaults)
        and (not any(current.args.kw_defaults))
        and (not _db_python_argument_names(current.args) & set(symbols))
        and (
            not any(
                (
                    isinstance(n, (ast.Global, ast.Nonlocal, ast.Lambda, ast.ClassDef))
                    or (
                        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and n is not current
                    )
                    or (
                        isinstance(n, ast.Name)
                        and n.id in set(connections) | set(engines)
                    )
                    for n in ast.walk(current)
                )
            )
        )
    ):
        _db_python_scope_native(
            current.body,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            {},
            {},
            queries,
            gaps,
            execute=execute,
        )
        return
    if any(
        (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and (candidate.func.attr == "execute")
            for candidate in ast.walk(current)
        )
    ):
        gaps.append("python_execute_nested_scope_unsupported:" + path)
    return


def _db_python_isolated_control_flow_calls_native(
    node,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    sql_bindings,
    queries,
    gaps,
    *,
    execute,
):
    """Scan each alternative with a private copy of facts that cannot escape."""
    for branch in _db_python_control_flow_branches(node):
        branch_engines = dict(engines)
        branch_connections = dict(connections)
        branch_sql = dict(sql_bindings)
        _db_python_scope_native(
            branch,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            branch_engines,
            branch_connections,
            queries,
            gaps,
            branch_sql,
            execute=execute,
        )
    changed, escaped = (set(), set())
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        if (
            isinstance(candidate.func, ast.Attribute)
            and isinstance(candidate.func.value, ast.Name)
            and (
                connections.get(candidate.func.value.id)
                in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
            )
            and (
                candidate.func.attr
                in {"execute", "executemany", "executescript", "rollback", "close"}
            )
        ):
            changed.add(candidate.func.value.id)
        for argument in list(candidate.args) + [kw.value for kw in candidate.keywords]:
            escaped.update(_db_python_escaped_receivers(argument, connections))
    if escaped:
        _db_python_forget_escaped_schema(escaped, sql_bindings)
    schemas = dict(sql_bindings.get(("sqlite_receiver_schemas",), {}))
    for name in changed:
        schemas.pop(name, None)
    sql_bindings["sqlite_receiver_schemas",] = schemas


def _db_python_with_scope_native(
    statement,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    engines,
    connections,
    queries,
    gaps,
    sql_bindings,
    *,
    execute,
):
    """Analyze a with body using only statically proven SQLite aliases."""
    for item in statement.items:
        _db_python_invalidate_nested_bindings(
            item.context_expr, engines, connections, sql_bindings
        )
        _db_python_scope_calls_native(
            item.context_expr,
            path,
            digest,
            symbols,
            shadowed,
            dialect,
            sqlglot,
            exp,
            engines,
            connections,
            sql_bindings,
            queries,
            gaps,
            execute=execute,
        )
        item_bindings = _db_python_with_bindings(
            statement, symbols, shadowed, items=(item,)
        )
        _db_python_invalidate_names(item_bindings, engines, connections, sql_bindings)
        for name, driver in item_bindings.items():
            if driver:
                connections[name] = driver
                expression = item.context_expr
                marker = (
                    symbols.get(expression.func.id, "")
                    if isinstance(expression, ast.Call)
                    and isinstance(expression.func, ast.Name)
                    else ""
                )
                if isinstance(marker, str) and marker.endswith(":guarded"):
                    _db_python_forget_escaped_schema((name,), sql_bindings)
                    gaps.append("python_guarded_schema_effect_unknown:" + path)
    _db_python_scope_native(
        statement.body,
        path,
        digest,
        symbols,
        shadowed,
        dialect,
        sqlglot,
        exp,
        engines,
        connections,
        queries,
        gaps,
        sql_bindings,
        execute=execute,
    )


def _db_python_sql_literal(node, symbols, shadowed, bindings=None):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        return bindings[node.id][0]
    if (
        isinstance(node, ast.Call)
        and _db_python_is_text_call(node, symbols, shadowed)
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _db_python_is_text_call(node, symbols, shadowed):
    return _db_python_call(
        node, "sqlalchemy.text", symbols, shadowed
    ) or _db_python_call(node, "sqlalchemy.sql.text", symbols, shadowed)


def _db_python_contains_text(node, symbols, shadowed, bindings=None):
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        return bindings[node.id][1]
    return any(
        isinstance(child, ast.Call)
        and _db_python_is_text_call(child, symbols, shadowed)
        for child in ast.walk(node)
    )


def _db_python_module_name(path):
    parts = list(Path(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _db_python_import_module(current, node):
    if node.level:
        package = current.split(".")[:-1]
        keep = max(0, len(package) - node.level + 1)
        base = package[:keep]
        suffix = node.module.split(".") if node.module else []
        return ".".join(base + suffix)
    return node.module or ""


# SQLite statement execution uses explicit parser and projection callbacks.


def _db_python_execute_native(
    call,
    path,
    digest,
    symbols,
    shadowed,
    dialect,
    sqlglot,
    exp,
    connections,
    literal_texts,
    queries,
    gaps,
    *,
    parse_sql,
    query,
    read_statement,
):
    receiver = call.func.value
    name = receiver.id if isinstance(receiver, ast.Name) else None
    if not call.args:
        gaps.append("python_execute_sql_missing:" + path)
        return
    argument = call.args[0]
    query_text = _db_python_sql_literal(argument, symbols, shadowed, literal_texts)
    if name is None or name not in connections:
        gaps.append("python_execute_receiver_unproven:" + path)
        return
    driver = connections[name]
    if query_text is None or (
        driver == "sqlalchemy"
        and (not _db_python_contains_text(argument, symbols, shadowed, literal_texts))
    ):
        if driver in {"sqlite", "sqlite_memory", "sqlite_uncertain"}:
            _db_python_forget_escaped_schema((name,), literal_texts)
        gaps.append("python_dynamic_or_unwrapped_sql:" + path)
        return
    if driver in {"sqlite", "sqlite_memory", "sqlite_uncertain"} and re.fullmatch(
        "\\s*(?:PRAGMA\\s+foreign_keys\\s*=\\s*ON|PRAGMA\\s+journal_mode\\s*=\\s*WAL|PRAGMA\\s+table_info\\s*\\(\\s*[A-Za-z_][A-Za-z_0-9]*\\s*\\)|BEGIN\\s+IMMEDIATE)\\s*;?\\s*",
        query_text,
        re.IGNORECASE,
    ):
        return
    try:
        statements = parse_sql(sqlglot, query_text, dialect)
    except (sqlglot.errors.ParseError, sqlglot.errors.TokenError):
        gaps.append("python_sql_parse_error:" + path)
        return
    if (
        driver in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
        and len(statements) != 1
    ):
        gaps.append("python_sqlite_multiple_statements_unsupported:" + path)
        return
    for index, statement in enumerate(statements, 1):
        location = {
            "path": path,
            "sha256": digest,
            "line": call.lineno,
            "statement": index,
        }
        _db_python_executed_statement(
            statement,
            exp,
            dialect,
            driver,
            name,
            literal_texts,
            location,
            queries,
            gaps,
            parse_sql=parse_sql,
            query=query,
            read_statement=read_statement,
        )


def _db_python_executed_statement(
    statement,
    exp,
    dialect,
    driver,
    name,
    bindings,
    location,
    queries,
    gaps,
    *,
    parse_sql,
    query,
    read_statement,
):
    if isinstance(statement, (exp.Select, exp.Insert, exp.Update, exp.Delete)):
        _db_python_scoped_query(
            statement,
            exp,
            dialect,
            driver,
            name,
            bindings,
            location,
            queries,
            gaps,
            parse_sql=parse_sql,
            query=query,
            read_statement=read_statement,
        )
    elif (
        driver in {"sqlite", "sqlite_memory", "sqlite_uncertain"}
        and isinstance(statement, exp.Create)
        and (statement.kind == "TABLE")
        and isinstance(statement.this, exp.Schema)
        and (not statement.args.get("exists"))
    ):
        _db_python_scoped_create(
            statement,
            exp,
            dialect,
            name,
            bindings,
            location,
            queries,
            gaps,
            parse_sql=parse_sql,
            query=query,
            read_statement=read_statement,
        )
    else:
        schemas = dict(bindings.get(("sqlite_receiver_schemas",), {}))
        schemas.pop(name, None)
        bindings["sqlite_receiver_schemas",] = schemas
        gaps.append("python_executed_non_query_unsupported:" + location["path"])


def _db_python_scoped_query(
    statement,
    exp,
    dialect,
    driver,
    name,
    bindings,
    location,
    queries,
    gaps,
    *,
    parse_sql,
    query,
    read_statement,
):
    location["kind"] = (
        "sqlite" if driver in {"sqlite_memory", "sqlite_uncertain"} else driver
    ) + "_execute"
    query(statement, exp, dialect, location, queries, gaps)
    if driver == "sqlite_memory":
        queries[-1]["private_schema_only"] = True
    if driver == "sqlite_uncertain" or name in bindings.get(
        ("sqlite_escaped_receivers",), set()
    ):
        queries[-1]["schema_unknown"] = True
    scoped = bindings.get(("sqlite_receiver_schemas",), {}).get(name, {})
    relevant = {
        table: deepcopy(scoped[table])
        for table in queries[-1]["tables"]
        if table in scoped
    }
    if relevant:
        queries[-1]["scoped_tables"] = relevant


def _db_python_scoped_create(
    statement,
    exp,
    dialect,
    name,
    bindings,
    location,
    queries,
    gaps,
    *,
    parse_sql,
    query,
    read_statement,
):
    if name in bindings.get(("sqlite_escaped_receivers",), set()):
        gaps.append("python_connection_escaped_schema_unproven:" + location["path"])
        return
    key = ("sqlite_receiver_schemas",)
    schemas = dict(bindings.get(key, {}))
    local_tables = deepcopy(schemas.get(name, {}))
    read_statement(
        statement,
        exp,
        location["path"],
        location["sha256"],
        location["statement"],
        dialect,
        local_tables,
        [],
        queries,
        gaps,
        line=location["line"],
    )
    schemas[name] = local_tables
    bindings[key] = schemas
