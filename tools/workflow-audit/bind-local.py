"""Bind source-hashed local test and ForgeLine evidence to the current bytes."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

PROFILE = "python-3.11-source-cli"

CANDIDATE_PATHS = (
    "factoryline/runtime_coverage.py",
    "factoryline/workflow_audit.py",
    "factoryline/graph_ops.py",
    "factoryline/graph_ops.html",
    "factoryline/studio.py",
    "factoryline/cli_audit.py",
    "tests/test_runtime_coverage.py",
    "tests/test_ci_runtime_coverage.py",
    "tests/test_graph_ops.py",
    "tests/test_studio.py",
    "tests/test_workflow_audit.py",
    "tests/test_attribution_io.py",
    "tests/test_runtime_audit_common_attribution.py",
    "tests/test_agent_license.py",
    "tests/test_enterprise_enforcement.py",
    "tests/test_intent_quality.py",
    "tests/test_jetbrains_handshake.py",
    "tests/test_attribution_security.py",
    "tests/test_attribution_workflows.py",
    "tests/test_attribution_binder.py",
    "tests/test_attribution_98.py",
    "tests/test_deep_audit_contract.py",
    "specs/universal-workflow-audit.md",
    "plans/universal-workflow-audit.md",
    "specs/pr-mutation-oracle-gate.md",
    "plans/pr-mutation-oracle-gate.md",
    "specs/attribution-rate-96.md",
    "plans/attribution-rate-96.md",
    "attribution-rate-96.ssat.yaml",
    "specs/runtime-coverage-panel.md",
    "plans/runtime-coverage-panel.md",
    "runtime-coverage-panel.ssat.yaml",
    "README.md",
    "deploy/huggingface/README.md",
    "deploy/huggingface/index.html",
    "pyproject.toml",
    ".github/workflows/ci.yml",
    "tools/workflow-audit/bind-local.py",
    "tools/workflow-audit/run-attribution-tests.ps1",
    "tools/workflow-audit/write-ci-runtime-coverage.py",
    "tools/workflow-audit/applicability-review.md",
)

CHECK_ROWS = (
    ("CLI_ROUTE", "happy_path", "Source CLI routing and project-neutral project profiles", ("tools/workflow-audit/final-tests.log", "tools/workflow-audit/final-tests.run.json", "tests/test_workflow_audit.py")),
    ("INVALID_INPUT", "validation", "Malformed schemas, missing or duplicate observations and invalid timestamps", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("CLOSED_FAILURE", "failure_recovery", "Incomplete evidence returns nonzero and no authority", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("HASH_BINDING", "state_consistency", "Candidate, contract, observation and receipt hashes reject drift", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("CONTAINMENT", "security_privacy", "Workspace containment, safe evidence paths and authority false", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("RESOURCE_LIMITS", "performance", "Input, artifact, aggregate-byte and profile budgets reject oversized work", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("JSON_INTERFACE", "accessibility", "Stable machine-readable states and nonzero invalid/incomplete exits", ("tools/workflow-audit/final-tests.log", "tests/test_workflow_audit.py")),
    ("FORGELINE_GRADE", "validation", "Strict repo-wide ForgeLine QA reports grade A and composite at least 95", ("tools/workflow-audit/attribution-doctor.json", "tools/workflow-audit/attribution-final.log", "tools/workflow-audit/attribution-final.run.json")),
    ("ATTRIBUTION_RATE", "validation", "Unchanged repo-wide ForgeLine inventory has at least 1,046 of 1,067 functions with behavior-test intent (at least 98%); this static intent metric is separate from runtime coverage", ("tools/workflow-audit/attribution-focused-tests.log", "tools/workflow-audit/attribution-focused-tests.run.json", "tools/workflow-audit/attribution-full-suite.log", "tools/workflow-audit/attribution-full-suite.run.json", "tools/workflow-audit/attribution-final.log", "tools/workflow-audit/attribution-final.run.json", "tools/workflow-audit/attribution-doctor.json")),
    ("ATTRIBUTION_SCOPE", "state_consistency", "ForgeLine scope stays repo-wide and the fixed function count remains 1,067", ("tools/workflow-audit/attribution-final.log",)),
    ("ARCHITECTURE_HEALTH", "state_consistency", "Strict architecture health passes without accepted debt", ("tools/workflow-audit/architecture-health-final.json",)),
    ("MUTATION_GATE_SPEC", "validation", "Mutation-oracle gate spec passes SpecLine strict validation and the spec gate", ("tools/workflow-audit/pr-mutation-spec.log", "specs/pr-mutation-oracle-gate.md", "plans/pr-mutation-oracle-gate.md")),
    ("RUNTIME_COVERAGE", "validation", "The passing full test run emits branch-aware statement and branch coverage, whose report timestamp, commit, test/source hashes and exact runner command match its explicitly unsigned receipt", ("tools/workflow-audit/attribution-full-suite.log", "tools/workflow-audit/attribution-full-suite.run.json", "tests/test_ci_runtime_coverage.py", ".factory/test-reports/coverage.json", ".factory/test-reports/coverage.xml", ".factory/test-reports/pytest.xml", ".factory/test-reports/coverage.run.json")),
)

EVIDENCE_KIND = {
    "tools/workflow-audit/final-tests.log": "terminal-log",
    "tools/workflow-audit/attribution-focused-tests.log": "terminal-log",
    "tools/workflow-audit/attribution-full-suite.log": "terminal-log",
    "tools/workflow-audit/attribution-final.log": "json-receipt",
    "tools/workflow-audit/attribution-doctor.json": "json-receipt",
    "tools/workflow-audit/architecture-health-final.json": "json-receipt",
    "tools/workflow-audit/pr-mutation-spec.log": "terminal-log",
    "tools/workflow-audit/final-tests.run.json": "json-receipt",
    "tools/workflow-audit/attribution-focused-tests.run.json": "json-receipt",
    "tools/workflow-audit/attribution-full-suite.run.json": "json-receipt",
    "tools/workflow-audit/attribution-final.run.json": "json-receipt",
    ".factory/test-reports/coverage.json": "json-receipt",
    ".factory/test-reports/coverage.xml": "xml-report",
    ".factory/test-reports/pytest.xml": "xml-report",
    ".factory/test-reports/coverage.run.json": "json-receipt",
    "tests/test_workflow_audit.py": "acceptance-test-source",
    "specs/pr-mutation-oracle-gate.md": "candidate-source",
    "plans/pr-mutation-oracle-gate.md": "candidate-source",
}


def artifact(path: str, kind: str) -> dict:
    target = ROOT / path
    return {"path": path, "sha256": sha256(target.read_bytes()).hexdigest(), "kind": kind}


def _candidate_hashes(root: Path, fixed_paths: tuple[str, ...] = ()) -> dict[str, str]:
    """Hash every ForgeLine-scanned source/test file plus explicit workflow inputs."""
    from forgeline.source_scope import SOURCE_SUFFIXES, iter_source_files

    workspace = Path(root).resolve()
    inventory = iter_source_files(
        workspace, suffixes=SOURCE_SUFFIXES, skipped=[]
    )
    relative_paths = {path.relative_to(workspace).as_posix() for path in inventory}
    relative_paths.update(fixed_paths)
    hashes = {}
    for relative in sorted(relative_paths):
        target = workspace / relative
        if not target.is_file():
            raise SystemExit(f"Cannot bind missing candidate source: {relative}")
        hashes[relative] = sha256(target.read_bytes()).hexdigest()
    return hashes


def valid_run_receipt(
    receipt_path: Path,
    root: Path,
    *,
    command: str,
    log_path: str,
    source_hashes: dict[str, str],
    commit: str,
    require_report_hash: bool = False,
) -> bool:
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
        if not isinstance(receipt, dict):
            return False
        started = datetime.fromisoformat(receipt["started_at"])
        ended = datetime.fromisoformat(receipt["finished_at"])
        actual_log_hash = sha256((root / log_path).read_bytes()).hexdigest()
        within_age = timedelta(0) <= datetime.now(timezone.utc) - ended <= timedelta(hours=24)
    except (OSError, ValueError, KeyError, TypeError):
        return False
    environment = receipt.get("environment")
    python_version = environment.get("python") if isinstance(environment, dict) else None
    checks = (
        receipt.get("schema") == "factory.local-test-run.v1",
        receipt.get("commit") == commit,
        receipt.get("command") == command,
        receipt.get("log_path") == log_path,
        receipt.get("exit_code") == 0,
        isinstance(receipt.get("dirty_tree"), bool),
        receipt.get("source_unchanged") is True,
        receipt.get("source_sha256_before") == source_hashes,
        receipt.get("source_sha256_after") == source_hashes,
        receipt.get("source_sha256") == source_hashes,
        receipt.get("log_sha256") == actual_log_hash,
        isinstance(python_version, str) and python_version.startswith("Python "),
        (receipt.get("report_sha256") == actual_log_hash) is require_report_hash,
    )
    return all(checks) and started.tzinfo is not None and ended >= started and within_age


def valid_runtime_coverage_evidence(
    root: Path, *, commit: str, command: str
) -> bool:
    """Require readable branch data and a matching, explicitly unsigned local receipt."""
    from factoryline.runtime_coverage import read_runtime_coverage_report

    try:
        receipt = json.loads(
            (root / ".factory/test-reports/coverage.run.json").read_text(
                encoding="utf-8"
            )
        )
        report = read_runtime_coverage_report(root)
    except (OSError, ValueError, TypeError):
        return False
    return all(
        (
            report.get("state") == "OBSERVED",
            report.get("candidate_binding") == "LOCAL_SOURCE_HASH_MATCH",
            report.get("receipt_status") == "MATCHED_UNAUTHENTICATED",
            receipt.get("runner") == "local-powershell",
            type(report.get("statements", {}).get("total")) is int,
            report.get("statements", {}).get("total", 0) > 0,
            type(report.get("branches", {}).get("total")) is int,
            receipt.get("schema") == "factory.runtime-coverage-run.v1",
            receipt.get("commit") == commit,
            receipt.get("command") == command,
            receipt.get("exit_code") == 0,
            receipt.get("dirty_tree") is True or receipt.get("dirty_tree") is False,
            receipt.get("environment", {}).get("pytest_plugin_autoload") == "disabled",
            isinstance(receipt.get("environment", {}).get("pytest_cov"), str)
            and receipt["environment"]["pytest_cov"].startswith("7."),
        )
    )


def main() -> int:
    from factoryline.journey_proof import _digest
    from factoryline.workflow_audit import CATEGORIES

    log_paths = {
        "scoped": "tools/workflow-audit/final-tests.log",
        "focused": "tools/workflow-audit/attribution-focused-tests.log",
        "full": "tools/workflow-audit/attribution-full-suite.log",
    }
    log_text = {name: (ROOT / path).read_text(encoding="utf-8") for name, path in log_paths.items()}
    summaries = {name: re.search(r"(\d+ passed[^\r\n]*)", text) for name, text in log_text.items()}
    log_failures = tuple(
        (summary is None, f"{name} test log has no pass summary")
        for name, summary in summaries.items()
    ) + tuple(
        (re.search(r"\d+ (?:failed|error)", log_text[name]) is not None, f"{name} test log reports failure")
        for name in log_paths
    )
    log_error = next((message for failed, message in log_failures if failed), None)
    if log_error:
        raise SystemExit(log_error)

    commit = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=ROOT, text=True).strip()
    run_specs = {
        "scoped": ("tools/workflow-audit/final-tests.run.json", "rtk proxy python -m pytest -p pytest_asyncio.plugin -q tests/test_workflow_audit.py tests/test_review_audits.py tests/test_journey_proof.py"),
        "focused": ("tools/workflow-audit/attribution-focused-tests.run.json", "rtk proxy python -m pytest -p pytest_asyncio.plugin -q tests/test_attribution_io.py tests/test_attribution_security.py tests/test_attribution_workflows.py tests/test_attribution_binder.py tests/test_attribution_98.py tests/test_deep_audit_contract.py tests/test_runtime_audit_common_attribution.py tests/test_agent_license.py tests/test_enterprise_enforcement.py tests/test_intent_quality.py tests/test_jetbrains_handshake.py tests/test_workflow_audit.py"),
        "full": ("tools/workflow-audit/attribution-full-suite.run.json", "rtk proxy python -m pytest -p pytest_asyncio.plugin -q -n 2 -p pytest_cov.plugin --junitxml=.factory/test-reports/pytest.xml --durations=20 --cov=factoryline --cov-branch --cov-report=json:.factory/test-reports/coverage.json --cov-report=xml:.factory/test-reports/coverage.xml"),
        "forge": ("tools/workflow-audit/attribution-final.run.json", "rtk proxy forge qa --repo-wide --root ."),
    }
    candidate_hashes = _candidate_hashes(ROOT, CANDIDATE_PATHS)
    for name, (receipt_path, command) in run_specs.items():
        log_path = log_paths.get(name, "tools/workflow-audit/attribution-final.log")
        if not valid_run_receipt(ROOT / receipt_path, ROOT, command=command, log_path=log_path, source_hashes=candidate_hashes, commit=commit, require_report_hash=name == "forge"):
            raise SystemExit(f"{name} test evidence is stale, failed, or not bound to current sources")

    if not valid_runtime_coverage_evidence(
        ROOT, commit=commit, command=run_specs["full"][1]
    ):
        raise SystemExit("Runtime coverage is missing, stale, mismatched or incomplete")

    attribution_report = json.loads((ROOT / "tools/workflow-audit/attribution-final.log").read_text(encoding="utf-8"))
    attribution = attribution_report.get("attribution", {})
    checked = attribution.get("n_checked")
    passed = attribution.get("n_passed")
    rate = attribution.get("rate")
    if not all((type(checked) is int, type(passed) is int, type(rate) in (int, float))):
        raise SystemExit("ForgeLine attribution fields have invalid types")
    if checked <= 0:
        raise SystemExit("ForgeLine attribution inventory is empty")
    attribution_checks = (
        attribution_report.get("grade") == "A",
        attribution_report.get("passed") is True,
        checked == 1067,
        passed >= 1046,
        rate >= 0.98,
        abs(rate - passed / checked) <= 1e-12,
        attribution_report.get("metrics", {}).get("coverage_assessment") == "measured",
        attribution_report.get("metrics", {}).get("max_complexity", 999) <= 10,
        attribution_report.get("metrics", {}).get("composite", 0) >= 95,
    )
    if not all(attribution_checks):
        raise SystemExit("ForgeLine attribution or quality report is below the fixed A/98% gate")

    doctor = json.loads((ROOT / "tools/workflow-audit/attribution-doctor.json").read_text(encoding="utf-8"))
    forge_module = next((item for item in doctor.get("modules", []) if item.get("module") == "forgeline"), None)
    doctor_checks = (
        doctor.get("ok") is True,
        forge_module is not None,
        forge_module.get("version") == "0.10.8",
        forge_module.get("provenance", {}).get("source_commit") == "218b61b5f73bee12579740a5dd244a0a4e8eff54",
    )
    if not all(doctor_checks):
        raise SystemExit("strict factory doctor lacks the required ForgeLine provenance")

    applicable = {row[1] for row in CHECK_ROWS}
    review = artifact("tools/workflow-audit/applicability-review.md", "review")
    contract = {
        "schema": "factory.workflow-audit.contract.v1",
        "project_id": "code-factory-universal-audit",
        "candidate": [artifact(path, "candidate-source") for path in candidate_hashes],
        "applicability": [
            {
                "category": category,
                "applicable": category in applicable,
                "reason": {True: "Covered by the scoped CLI regression checks", False: "This local evaluator has no external writes, provider calls, project execution or approvals"}[category in applicable],
                **({"review_evidence": review} if category not in applicable else {}),
            }
            for category in sorted(CATEGORIES)
        ],
        "checks": [
            {"id": row[0], "category": row[1], "requirement": row[2], "profiles": [PROFILE]}
            for row in CHECK_ROWS
        ],
    }
    raw = json.dumps(contract, ensure_ascii=False, indent=2).encode("utf-8")
    output = ROOT / ".factory"
    output.mkdir(exist_ok=True)
    (output / "workflow-audit-contract.json").write_bytes(raw)

    command = "$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; " + run_specs["scoped"][1] + "; " + summaries["scoped"].group(1)
    observed_at = datetime.now(timezone.utc).isoformat()
    identities = {row[0]: command for row in CHECK_ROWS[:7]}
    identities.update({
        "FORGELINE_GRADE": "factory doctor --strict --json",
        "ATTRIBUTION_RATE": "forge qa --repo-wide --root .",
        "ATTRIBUTION_SCOPE": "forge qa --repo-wide --root .",
        "ARCHITECTURE_HEALTH": "factory architecture health --root . --strict --json",
        "MUTATION_GATE_SPEC": "specline strict pr-mutation-oracle-gate --root .; specline gate spec pr-mutation-oracle-gate --root .",
        "RUNTIME_COVERAGE": run_specs["full"][1],
    })
    reasons = {row[0]: row[2] for row in CHECK_ROWS}
    reasons["ATTRIBUTION_RATE"] += f"; focused {summaries['focused'].group(1)}; full suite {summaries['full'].group(1)}; observed {passed}/{checked} ({rate:.4%}), grade A, composite {attribution_report['metrics']['composite']}"
    runtime_coverage = json.loads((ROOT / ".factory/test-reports/coverage.json").read_text(encoding="utf-8"))
    coverage_totals = runtime_coverage["totals"]
    reasons["RUNTIME_COVERAGE"] += (
        f"; runtime statements {coverage_totals['covered_lines']}/{coverage_totals['num_statements']} "
        f"({coverage_totals['percent_statements_covered']:.2f}%); branches "
        f"{coverage_totals['covered_branches']}/{coverage_totals['num_branches']} "
        f"({coverage_totals['percent_branches_covered']:.2f}%); local receipt is unsigned"
    )
    observations = {
        "schema": "factory.workflow-audit.observations.v1",
        "contract_sha256": sha256(raw).hexdigest(),
        "candidate_sha256": _digest(contract["candidate"]),
        "observations": [
            {
                "id": row[0],
                "profile": PROFILE,
                "status": "PASS",
                "reason": reasons[row[0]],
                "execution_identity": identities[row[0]],
                "observed_at": observed_at,
                "artifacts": [artifact(path, EVIDENCE_KIND.get(path, "candidate-source")) for path in row[3]],
            }
            for row in CHECK_ROWS
        ],
    }
    (output / "workflow-audit-observations.json").write_text(json.dumps(observations, ensure_ascii=False, indent=2), encoding="utf-8")
    print("LOCAL_WORKFLOW_EVIDENCE_BOUND")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
