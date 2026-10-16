__version__ = "0.48.2"

import json as _json


def canonical_json_bytes(value: object) -> bytes:
    """Strict UTF-8 receipt encoding shared by byte-equivalent producers."""
    return _json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_compat_bytes(value: object) -> bytes:
    """Preserve existing UTF-8 receipt bytes, including legacy non-finite values."""
    return _json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


def canonical_ascii_json_compat_bytes(value: object) -> bytes:
    """Preserve existing ASCII-escaped receipt bytes and non-finite handling."""
    return _json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")
