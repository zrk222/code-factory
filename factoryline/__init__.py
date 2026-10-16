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
