"""Bounded literal keyword evidence for non-security MD5 checksums."""

import ast

def definite_compatibility_checksum(node):
    """Credit one literal false flag only when keyword expansion is unambiguous."""
    values = []
    for keyword in node.keywords:
        if keyword.arg == "usedforsecurity":
            values.append(keyword.value)
        elif keyword.arg is None:
            if not isinstance(keyword.value, ast.Dict):
                return False
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    return False
                if key.value == "usedforsecurity":
                    values.append(value)
    return (
        len(values) == 1
        and isinstance(values[0], ast.Constant)
        and values[0].value is False
    )
