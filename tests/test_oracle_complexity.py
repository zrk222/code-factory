import ast
from pathlib import Path


TARGETS = {
    "factoryline/codex_metadata.py": {"audit_metadata"},
    "factoryline/oracle_firewall.py": {
        "seal_oracle_contract", "compile_oracle_challenge", "validate_oracle_challenge_plan",
        "verify_oracle_challenge_result", "record_oracle_incident",
    },
}
BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.comprehension, ast.ExceptHandler, ast.Match)


def test_public_oracle_coordinators_stay_within_ten_branches() -> None:
    found = set()
    for filename, names in TARGETS.items():
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"), filename=filename)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
                found.add(node.name)
                assert sum(isinstance(item, BRANCHES) for item in ast.walk(node)) <= 10, node.name
    assert found == set().union(*TARGETS.values())
