"""One derivation's class-chain memo with final fresh-source validation."""

import copy
import ast
from contextlib import contextmanager
from types import SimpleNamespace

from .credential_role_sources import SourceSnapshotIndex
from .credential_role_source_models import helper_epochs_valid, source_model


def _view(imports, classes):
    return (copy.deepcopy(imports), {key: id(value) for key, value in classes.items()})


class ClassChainMemo:
    source_model = source_model

    def __init__(self, index, imports, classes, audit):
        self.index, self.imports, self.classes, self.audit = (
            index,
            imports,
            classes,
            audit,
        )
        self.view = _view(imports, classes)
        self.inventory = dict(index.inventory)
        self.root = index.root
        self.names = audit._name
        self.entries = {}
        self._analysis_batch = None
        self.getter_role_checks = {}
        self.source_models = {}

    def getter_role(self, node, path, audit, derive):
        """Memoize candidate-independent consumer checks within this derivation."""
        key = (
            path,
            id(node),
            id(self.index.snapshots.get(path)),
            self.index.inventory.get(path),
            derive,
            audit._module_security_aliases,
        )
        if audit is not self.audit:
            return derive(node, self.index, path, audit) is not None
        if key not in self.getter_role_checks:
            self.getter_role_checks[key] = (
                derive(node, self.index, path, audit) is not None
            )
        return self.getter_role_checks[key]

    @contextmanager
    def analysis_batch(self):
        """Defer repeated fresh checks until the producer's all-evidence exit."""
        if self._analysis_batch is not None:
            raise ValueError("nested analysis batch")
        state = SimpleNamespace(started=self.valid(), accepted=False, helper_epoch={})
        if not state.started:
            yield state
            return
        self._analysis_batch = state
        completed = False
        try:
            yield state
            completed = True
        finally:
            self._analysis_batch = None
            fresh = self.valid()
            state.accepted = (
                completed and fresh and helper_epochs_valid(state.helper_epoch)
            )

    def defers_validation(self, index, imports, classes, audit):
        return bool(
            self._analysis_batch is not None
            and index is self.index
            and self.matches(imports, classes, audit)
        )

    def matches(self, imports, classes, audit):
        return (
            imports is self.imports
            and classes is self.classes
            and audit is self.audit
            and audit._name is self.names
            and self.index.root == self.root
        )

    def resolve(self, path, name, resolver):
        key = path, name
        if key not in self.entries:
            result = resolver()
            self.entries[key] = tuple(result) if result else None
        return self.entries[key]

    def valid(self):
        if (
            not self.matches(self.imports, self.classes, self.audit)
            or _view(self.imports, self.classes) != self.view
            or self.index.inventory != self.inventory
        ):
            return False
        fresh = SourceSnapshotIndex(
            self.root,
            self.index.snapshots,
            self.index.source_bytes,
            self.index.inventory,
        )
        return bool(
            fresh.bounded and all(fresh.validate(path) for path in self.index.validated)
        )


def resolve_class_chain(index, path, name, imports, classes, audit):
    keys = _class_mro(index, (path, name), imports, classes, audit, set(), {})
    if keys is None:
        return None
    return [
        (class_path, class_name, classes[(class_path, class_name)])
        for class_path, class_name in keys
    ]


def _class_mro(index, key, imports, classes, audit, active, memo):
    from .credential_role_bindings import _class_ref

    if key in memo:
        return memo[key]
    if key in active or len(active) >= 16:
        return None
    path, name = key
    owner = classes.get(key)
    if not _class_binding_is_exact(index, path, name, owner):
        return None
    active.add(key)
    bases = []
    for expression in owner.bases:
        base = _class_ref(path, expression, imports, classes, audit, index)
        if base is None or base in bases:
            active.remove(key)
            return None
        bases.append(base)
    if not bases:
        result = [key]
    else:
        base_mros = [
            _class_mro(index, base, imports, classes, audit, active, memo)
            for base in bases
        ]
        if any(mro is None for mro in base_mros):
            active.remove(key)
            return None
        result = _c3_merge([[*mro] for mro in base_mros] + [[*bases]])
        if result is None:
            active.remove(key)
            return None
        result.insert(0, key)
    active.remove(key)
    if len(result) > 16:
        return None
    memo[key] = result
    return result


def _class_binding_is_exact(index, path, name, owner):
    if (
        owner is None
        or owner.decorator_list
        or owner.keywords
        or not index.validate(path)
    ):
        return False
    from .credential_role_scope_bindings import binding_occurrences

    definitions = binding_occurrences(index.snapshots[path].body, name)
    return len(definitions) == 1 and definitions[0] is owner


def _c3_merge(sequences):
    result = []
    while any(sequences):
        sequences = [sequence for sequence in sequences if sequence]
        candidate = next(
            (
                sequence[0]
                for sequence in sequences
                if all(sequence[0] not in other[1:] for other in sequences)
            ),
            None,
        )
        if candidate is None:
            return None
        result.append(candidate)
        for sequence in sequences:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)
        if len(result) >= 16 and any(sequences):
            return None
    return result


def _import_binding_is_exact(index, path, name, imported):
    if not index.validate(path):
        return False
    from .credential_role_scope_bindings import binding_occurrences

    definitions = binding_occurrences(index.snapshots[path].body, name)
    if len(definitions) != 1:
        return False
    binding = definitions[0]
    if isinstance(binding, ast.ImportFrom):
        rows = [
            alias for alias in binding.names if (alias.asname or alias.name) == name
        ]
        return bool(
            len(rows) == 1
            and imported[1] == rows[0].name
            and imported[0] in index.snapshots
        )
    if isinstance(binding, ast.Import):
        rows = [
            alias
            for alias in binding.names
            if (alias.asname or alias.name.split(".")[0]) == name
        ]
        return bool(
            len(rows) == 1
            and imported[1] is None
            and len(imported[0:1]) == 1
            and imported[0] in index.snapshots
        )
    return False
