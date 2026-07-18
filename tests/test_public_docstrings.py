from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "factoryline"


def _public_callables() -> list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef]]:
    result = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = list(tree.body)
        for owner in tree.body:
            if isinstance(owner, ast.ClassDef):
                nodes.extend(owner.body)
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                result.append((path, node))
    return result


def test_every_public_function_and_method_has_a_meaningful_docstring() -> None:
    missing = []
    for path, node in _public_callables():
        docstring = ast.get_docstring(node)
        if docstring is None or len(" ".join(docstring.split())) < 20:
            missing.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.name}")

    assert missing == [], "PUBLIC_API_DOCSTRINGS_COMPLETE missing:\n" + "\n".join(missing)


def test_fail_closed_public_surfaces_document_refusal_semantics() -> None:
    required = {
        "factoryline/enterprise_receipts.py": {
            "validate_receipt_v2": "EnterpriseReceiptError",
            "sign_payload": "EnterpriseReceiptError",
            "seal_receipt_v2": "EnterpriseReceiptError",
            "verify_receipt_v2": "EnterpriseReceiptError",
            "sign_policy_bundle": "EnterpriseReceiptError",
            "sign_revocations": "EnterpriseReceiptError",
            "generate_key_material": "EnterpriseReceiptError",
        },
        "factoryline/migration.py": {
            "assess_migration_readiness": "MigrationError",
            "verify_migration_readiness": "structured invalid",
            "build_repository_context": "MigrationError",
            "verify_repository_context": "structured invalid",
        },
        "factoryline/signed_receipts.py": {
            "validate_receipt": "SignedReceiptError",
            "resolve_sigstore_command": "SignedReceiptError",
            "sign_receipt": "SignedReceiptError",
            "verify_receipt": "SignedReceiptError",
        },
    }
    found = {
        path.relative_to(ROOT).as_posix(): {
            node.name: ast.get_docstring(node) or "" for candidate, node in _public_callables() if candidate == path
        }
        for path in PACKAGE.glob("*.py")
    }

    failures = []
    for path, callables in required.items():
        for name, phrase in callables.items():
            if phrase.lower() not in found[path][name].lower():
                failures.append(f"{path}:{name} must document {phrase}")

    assert failures == [], "\n".join(failures)
