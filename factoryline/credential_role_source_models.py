"""Batch-local source model caching with helper identity freshness."""

from types import FunctionType, MethodType

_FUNCTION = object()
_BOUND_METHOD = object()
_PROVIDER = object()


def source_model(self, key, derive, *, helper_epoch=None):
    """Reuse a model only while its supplied helper identity epoch stays fixed."""
    if not self.defers_validation(self.index, self.imports, self.classes, self.audit):
        return derive()
    state = self._analysis_batch
    before = _helper_snapshot(helper_epoch) if helper_epoch is not None else ()
    cache_key = key if helper_epoch is None else (key, _helper_epoch_key(before or ()))
    if helper_epoch is not None:
        prior = state.helper_epoch.setdefault(key, (helper_epoch, before))
        if not _same_helper_epoch(prior[1], before) or before is None:
            state.helper_epoch[key] = (helper_epoch, None)
        if before is None:
            return derive()
    if cache_key not in self.source_models:
        self.source_models[cache_key] = (before, derive())
    if helper_epoch is not None and not _same_helper_epoch(
        before, _helper_snapshot(helper_epoch)
    ):
        state.helper_epoch[key] = (helper_epoch, None)
    return self.source_models[cache_key][1]


def _helper_snapshot(helper_epoch):
    """Code freshness; mutable defaults, globals and closures need explicit epochs."""
    try:
        provider = _provider_snapshot(helper_epoch)
        values = helper_epoch()
        if not isinstance(values, tuple):
            return None
        return (provider, *(_helper_identity(value) for value in values))
    except Exception:
        return None


def _provider_snapshot(provider):
    if isinstance(provider, MethodType):
        function = provider.__func__
        return (_PROVIDER, provider.__self__, function.__code__, function.__globals__)
    if isinstance(provider, FunctionType):
        return (_PROVIDER, provider.__code__, provider.__globals__)
    return (provider,)


def _helper_identity(value):
    if isinstance(value, MethodType):
        return (_BOUND_METHOD, value.__self__, value.__func__, value.__func__.__code__)
    if isinstance(value, FunctionType):
        return (_FUNCTION, value, value.__code__)
    return (value,)


def _same_helper_epoch(left, right):
    if left is None or right is None or len(left) != len(right):
        return False
    return all(
        len(a) == len(b) and all(x is y for x, y in zip(a, b))
        for a, b in zip(left, right)
    )


def _helper_epoch_key(epoch):
    return tuple(tuple(id(part) for part in value) for value in epoch)


def helper_epochs_valid(epochs):
    return all(
        snapshot is not None and _same_helper_epoch(_helper_snapshot(epoch), snapshot)
        for epoch, snapshot in epochs.values()
    )
