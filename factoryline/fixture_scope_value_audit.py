"""Values and exact text operations for the source-bound fixture model."""

import ast


def _scope_value_roots(value):
    """Return all roots only for closed, non-escaping modeled values."""
    if value.unknown or value.content_unknown or value.class_roots:
        return None
    roots = set(value.roots)
    for _, item in value.items:
        nested = _scope_value_roots(item)
        if nested is None:
            return None
        roots.update(nested)
    return roots


def _scope_bind(arguments, keywords, names, required):
    if len(arguments) > len(names) or set(keywords) - set(names):
        return None
    bound = dict(zip(names, arguments))
    if set(bound) & set(keywords):
        return None
    bound.update(keywords)
    return bound if set(required) <= set(bound) else None


def _scope_closed(bound, tracked_roles):
    for role, value in bound.items():
        roots = _scope_value_roots(value)
        if roots is None or (roots and role not in tracked_roles):
            return False
    return True


def _scope_exact_text(value):
    scalar = value._exact_scalar
    if (
        value.inert_kind == "scalar"
        and value.scalar_kind == "text"
        and _scope_value_roots(value) == set()
        and len(scalar) == 1
    ):
        return scalar[0] if type(scalar[0]) is str else None
    return None


def _closed_text_binary(operator, left, right):
    """Interpret only bounded text operations with untracked, exact operands."""
    left, right = _scope_exact_text(left), _scope_exact_text(right)
    if left is None or right is None or len(left) + len(right) > 8192:
        return None
    if isinstance(operator, ast.Add):
        return left + right
    if left.count("%") == 1 and "%s" in left:
        return left.replace("%s", right)
    return None


class _TestScopeContractEpoch:
    """Retain actual immutable model bindings for role-cache generations."""

    __name__ = "test_scope_contract_epoch"

    @property
    def __code__(self):
        from . import credential_role_method_use_getter_audit as getter
        from .unittest_client_audit import _StoredTestClientCredential

        names = sorted(
            name
            for name in vars(getter)
            if name.startswith("_SCOPE_") or name == "SCOPE_API_CONTRACT_EPOCH"
        )
        values = (
            *(getattr(getter, name) for name in names),
            getter._source_test_scope_evidence,
            getter._closed_text_binary,
            getter._scope_exact_text,
            getter._scope_value_roots,
            *(
                getattr(owner, name)
                for owner in (
                    _StoredTestClientCredential,
                    getter._SourceTestScope,
                    getter._CredentialRoleFlow,
                )
                for name in sorted(vars(owner))
                if callable(getattr(owner, name))
            ),
        )
        key = tuple(
            (id(value), id(getattr(value, "__code__", None))) for value in values
        )
        current = getattr(self, "current", None)
        if current is None or current[0] != key:
            current = (key, object(), values)
            self.current = current
        return current[1]


_TEST_SCOPE_CONTRACT_EPOCH = _TestScopeContractEpoch()
