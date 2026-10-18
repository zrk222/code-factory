"""One derivation's class-chain memo with final fresh-source validation."""

import copy

from .credential_role_sources import SourceSnapshotIndex


def _view(imports, classes):
    return (copy.deepcopy(imports), {key: id(value) for key, value in classes.items()})


class ClassChainMemo:
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
