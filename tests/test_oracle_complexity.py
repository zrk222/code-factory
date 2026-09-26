import ast
from pathlib import Path


TARGETS = {
    "factoryline/codex_metadata.py": {"audit_metadata"},
    "factoryline/oracle_firewall.py": {
        "seal_oracle_contract",
        "compile_oracle_challenge",
        "validate_oracle_challenge_plan",
        "verify_oracle_challenge_result",
        "record_oracle_incident",
    },
}
BRANCHES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.IfExp,
    ast.comprehension,
    ast.ExceptHandler,
    ast.Match,
)


def test_public_oracle_coordinators_stay_within_ten_branches() -> None:
    found = set()
    for filename, names in TARGETS.items():
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"), filename=filename)
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in names
            ):
                found.add(node.name)
                assert (
                    sum(isinstance(item, BRANCHES) for item in ast.walk(node)) <= 10
                ), node.name
    assert found == set().union(*TARGETS.values())


def test_a2a_validators_stay_within_forgeline_complexity_limit() -> None:
    """Preserve the measured refactor, including its extracted validators."""
    tree = ast.parse(Path("factoryline/agentic_control.py").read_text(encoding="utf-8"))
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and (node.name.startswith("_a2a_") or node.name == "audit_a2a_agent_card")
    ]
    assert len(functions) == 14
    for node in functions:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(
                child,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        assert complexity <= 10, (node.name, complexity)
