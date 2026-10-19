"""Batch-local source model caching with helper identity freshness."""

from types import MethodType

_BOUND_METHOD = object()


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
    try:
        values = helper_epoch()
    except Exception:
        return None
    if not isinstance(values, tuple):
        return None
    return tuple(
        (_BOUND_METHOD, value.__self__, value.__func__)
        if isinstance(value, MethodType)
        else value
        for value in values
    )


def _same_helper_epoch(left, right):
    if left is None or right is None or len(left) != len(right):
        return False
    return all(
        isinstance(b, tuple)
        and len(b) == 3
        and b[0] is _BOUND_METHOD
        and a[1] is b[1]
        and a[2] is b[2]
        if isinstance(a, tuple) and len(a) == 3 and a[0] is _BOUND_METHOD
        else a is b
        for a, b in zip(left, right)
    )


def _helper_epoch_key(epoch):
    return tuple(
        (id(value[1]), id(value[2]))
        if isinstance(value, tuple) and len(value) == 3 and value[0] is _BOUND_METHOD
        else id(value)
        for value in epoch
    )


def helper_epochs_valid(epochs):
    return all(
        snapshot is not None and _same_helper_epoch(_helper_snapshot(epoch), snapshot)
        for epoch, snapshot in epochs.values()
    )
