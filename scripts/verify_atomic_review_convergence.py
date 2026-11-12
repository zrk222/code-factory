"""Reproduce the scoped upgrade checks and bind observations to candidate bytes.

Run with Python 3.11 from the repository root. uv provides isolated 3.10/3.12
test environments. Evidence stays in .factory; this script never commits or pushes.
"""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree
import yaml


SOURCES = [
    "factoryline/atomic_review_audit.py",
    "factoryline/cli_audit.py",
    "factoryline/graph_ops.py",
    "factoryline/graph_ops.html",
    "factoryline/mcp.py",
    "factoryline/webmcp.py",
    "factoryline/junie_taxonomy.py",
    "tests/test_mcp.py",
    "tests/test_webmcp.py",
    "tests/test_junie_taxonomy.py",
    "tests/test_deep_audit_surfaces.py",
    "tests/test_atomic_proof_adapter.py",
    "tests/test_context_efficiency.py",
    "tests/test_review_audits.py",
    "factoryline/review_audits.py",
    "tests/test_atomic_review_convergence.py",
    "specs/atomic-review-convergence-v1.ssat.yaml",
    ".github/workflows/factory-pr-proof-review.yml",
    "scripts/verify_atomic_review_convergence.py",
]
TESTS = [
    "tests/test_atomic_review_convergence.py",
    "tests/test_mcp.py",
    "tests/test_webmcp.py",
    "tests/test_junie_taxonomy.py",
    "tests/test_deep_audit_surfaces.py",
    "tests/test_atomic_proof_adapter.py",
]
ASSERTIONS = {
    "happy_path": (
        "test_a2a_message_round_trip_preserves_declared_identity_and_handoff",
        "test_graph_ops_reads_conventional_latest_receipt",
    ),
    "validation": (
        "test_missing_duplicated_unknown_or_malformed_cells_are_indeterminate",
        "test_duplicate_json_fields_are_rejected",
    ),
    "failure_recovery": (
        "test_rejects_prior_contract_drift_and_tampering",
        "test_rehashed_malformed_receipt_is_rejected",
    ),
    "state_consistency": (
        "test_agent_message_requires_context_and_replay_is_deterministic",
        "test_tracks_new_no_longer_reported_and_reopened_findings",
    ),
    "security_privacy": (
        "test_rejects_path_escape_and_source_overwrite",
        "test_complete_review_is_advisory_and_binds_exact_coverage",
    ),
    "performance": ("test_audit_convergence_engine_is_lazy_in_cli_process",),
    "external_effects": (
        "test_mcp_reads_convergence_and_exports_a2a_without_writing",
        "test_ci_convergence_executes_without_changing_main_proof",
    ),
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def main():
    root = Path.cwd().resolve()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = root / ".factory" / "review-convergence-verification" / run_id
    output.mkdir(parents=True)
    document = yaml.safe_load(
        (root / "specs/atomic-review-convergence-v1.ssat.yaml").read_text(
            encoding="utf-8"
        )
    )
    spec_context = output / "spec-context"
    for directory, field in (("specs", "spec_markdown"), ("plans", "plan_markdown")):
        target = spec_context / directory / "atomic-audit-convergence.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document[field], encoding="utf-8")

    def artifact(path, kind):
        return {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256(path.read_bytes()).hexdigest(),
            "kind": kind,
        }

    def write(path, value):
        path.write_bytes(canonical(value) + b"\n")

    candidate = [artifact(root / path, "source") for path in SOURCES]
    results = []
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")

    def run(name, argv, input_text=None):
        result = subprocess.run(
            argv,
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="backslashreplace",
            input=input_text,
            timeout=300,
        )
        log = output / f"{name}.json"
        record = {
            "command": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "execution_identity": f"{sys.executable}; {sys.version}; {sys.platform}",
        }
        write(log, record)
        results.append(
            {
                "name": name,
                "passed": result.returncode == 0,
                "artifact": artifact(log, "terminal_log"),
            }
        )
        print(f"{name}: exit {result.returncode}", flush=True)
        if result.returncode:
            print(result.stdout[-4000:] + result.stderr[-4000:])
        return result.returncode

    run("doctor", ["factory", "doctor", "--strict", "--json"])
    run(
        "architecture",
        [
            sys.executable,
            "-m",
            "factoryline.cli",
            "architecture",
            "health",
            "--strict",
            "--json",
        ],
    )
    for command in ("validate", "strict", "verify-validators", "challenge", "tasks"):
        run(
            f"spec-{command}",
            [
                "specline",
                command,
                "atomic-audit-convergence",
                "--root",
                str(spec_context),
            ],
        )
    python_files = [path for path in SOURCES if path.endswith(".py")]
    run("lint", [sys.executable, "-m", "ruff", "check", *python_files])
    run("diff", ["git", "diff", "--check"])
    run(
        "workflow-yaml",
        [
            sys.executable,
            "-c",
            "import yaml; yaml.safe_load(open('.github/workflows/factory-pr-proof-review.yml', encoding='utf-8')); print('YAML parsed')",
        ],
    )
    html = (root / "factoryline/graph_ops.html").read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    run("browser-script-syntax", ["node", "--check"], script)
    fixture_digests = []
    for version in ("3.10", "3.11", "3.12"):
        argv = (
            [sys.executable]
            if version == "3.11"
            else [
                "uv",
                "run",
                "--no-project",
                "--python",
                version,
                "--with",
                "pytest",
                "--with",
                "pytest-asyncio",
                "--with",
                "pyyaml",
                "--with",
                "reportlab",
                "--with",
                "cryptography",
                "--with",
                "mypy==2.1.0",
                "python",
            ]
        )
        junit = output / f"tests-{version}.xml"
        run(
            f"tests-{version}",
            [
                *argv,
                "-m",
                "pytest",
                "-q",
                "-p",
                "pytest_asyncio.plugin",
                "--junitxml",
                str(junit),
                *TESTS,
            ],
        )
        run(
            f"ast-mypy-{version}",
            [
                *argv,
                "-m",
                "pytest",
                "-q",
                "-p",
                "pytest_asyncio.plugin",
                "tests/test_context_efficiency.py::test_streaming_ast_fingerprint_keeps_structure_locations_and_ignores_sidecars",
                "tests/test_review_audits.py::test_security_scan_recognizes_individual_declared_static_type_oracle",
            ],
        )
        fixture_code = (
            "import runpy,tempfile; from pathlib import Path; "
            "f=runpy.run_path('tests/test_atomic_review_convergence.py'); "
            "c=f['_contract'](); "
            "\nwith tempfile.TemporaryDirectory() as d:\n"
            " print(f['_evaluate'](Path(d),c,f['_round'](c))['receipt_sha256'])"
        )
        name = f"canonical-{version}"
        run(name, [*argv, "-c", fixture_code])
        fixture_digests.append(
            json.loads((output / f"{name}.json").read_text())["stdout"].strip()
        )
    digest_log = output / "cross-version-digest.json"
    digest_match = len(set(fixture_digests)) == 1 and len(fixture_digests[0]) == 64
    write(
        digest_log,
        {
            "profiles": ["3.10", "3.11", "3.12"],
            "receipt_digests": fixture_digests,
            "match": digest_match,
        },
    )
    results.append(
        {
            "name": "cross-version-digest",
            "passed": digest_match,
            "artifact": artifact(digest_log, "terminal_log"),
        }
    )

    review = output / "applicability-review.json"
    write(
        review,
        {
            "scope": "Local review reconciliation, CLI/MCP/WebMCP projections and optional CI artifacts",
            "accessibility": "No layout, focus, ARIA, navigation or new interactive control changes. Only existing status text and agent tool registration change. Rendered accessibility of the existing Graph Ops page is outside this scoped claim.",
            "limits": "Local fixtures exercise parsing, receipt integrity, CLI/MCP round trips and script syntax; they do not authenticate external agents or prove remote task execution. Spec mutation checks validate requirement traceability. Supported Python tests run on 3.10, 3.11 and 3.12; Python 3.13 support is not declared.",
        },
    )
    categories = [
        "happy_path",
        "validation",
        "failure_recovery",
        "state_consistency",
        "security_privacy",
        "performance",
        "external_effects",
    ]
    requirements = {
        "happy_path": "Complete local round and CLI/MCP handoff return correlated advisory receipts.",
        "validation": "Malformed, duplicate and missing inputs are rejected or indeterminate.",
        "failure_recovery": "Tampering, contract drift and missing A2A context are rejected with stable errors.",
        "state_consistency": "Repeated messages preserve stable receipts and prior-round lineage.",
        "security_privacy": "Path escapes, input overwrites and authority escalation are rejected.",
        "performance": "Unrelated CLI imports leave the convergence engine unloaded; no latency improvement claimed.",
        "external_effects": "MCP reads preserve local files and CI convergence remains advisory; no remote sends.",
    }
    applicability = [
        {"category": c, "applicable": True, "reason": requirements[c]}
        for c in categories
    ]
    applicability.append(
        {
            "category": "accessibility",
            "applicable": False,
            "reason": "No interaction/layout/ARIA changes; existing status text only.",
            "review_evidence": artifact(review, "review"),
        }
    )
    profiles = [r["name"] for r in results if r["name"].startswith("tests-")]
    checks = [
        {"id": c, "requirement": requirements[c], "category": c, "profiles": profiles}
        for c in categories
    ]
    checks += [
        {
            "id": r["name"],
            "requirement": "The exact recorded governance or static verification command exits zero.",
            "category": "validation",
            "profiles": ["local-windows"],
        }
        for r in results
        if r["name"] not in profiles
    ]
    contract = {
        "schema": "factory.workflow-audit.contract.v1",
        "project_id": "atomic-review-convergence",
        "candidate": candidate,
        "applicability": applicability,
        "checks": checks,
    }
    contract_path = output / "contract.json"
    write(contract_path, contract)
    observations = []
    for check in checks:
        for profile in check["profiles"]:
            name = profile if profile in profiles else check["id"]
            result = next(r for r in results if r["name"] == name)
            status = "PASS" if result["passed"] else "FAIL"
            artifacts = [result["artifact"]]
            reason = check["requirement"]
            if profile in profiles:
                junit = output / f"{profile}.xml"
                selected = ASSERTIONS[check["id"]]
                reason += " Required pytest assertions: " + ", ".join(selected)
                if junit.is_file():
                    artifacts.append(artifact(junit, "junit"))
                    rows = list(ElementTree.parse(junit).iter("testcase"))
                    for assertion in selected:
                        matches = [
                            row
                            for row in rows
                            if row.get("name", "").split("[")[0] == assertion
                            and row.get("classname", "").endswith(
                                "test_atomic_review_convergence"
                            )
                        ]
                        if not matches or any(list(row) for row in matches):
                            status = "FAIL" if status == "FAIL" else "BLOCKED"
                else:
                    status = "BLOCKED"
            observations.append(
                {
                    "id": check["id"],
                    "profile": profile,
                    "status": status,
                    "reason": reason,
                    "execution_identity": f"{sys.executable}; {sys.platform}",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "artifacts": artifacts,
                }
            )
    observations_path = output / "observations.json"
    write(
        observations_path,
        {
            "schema": "factory.workflow-audit.observations.v1",
            "contract_sha256": sha256(contract_path.read_bytes()).hexdigest(),
            "candidate_sha256": sha256(canonical(candidate)).hexdigest(),
            "observations": observations,
        },
    )
    code = run(
        "workflow-evidence-gate",
        [
            "factory",
            "audit",
            "workflows",
            "--root",
            str(root),
            "--contract",
            contract_path.relative_to(root).as_posix(),
            "--observations",
            observations_path.relative_to(root).as_posix(),
            "--json",
        ],
    )
    write(
        output / "summary.json",
        {
            "candidate": candidate,
            "results": results,
            "evidence_directory": output.relative_to(root).as_posix(),
        },
    )
    print(f"Evidence: {output}")
    return 1 if code or any(not r["passed"] for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
