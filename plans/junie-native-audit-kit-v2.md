# Plan: junie-native-audit-kit-v2
Spec: specs/junie-native-audit-kit-v2.md (approved by the user's direct implementation request)
Architect verdict: pending ForgeLine architecture review

## Logical decomposition
1. Add a bounded MCP projection for source-bound Coverage.py evidence and expose its exact capability in the Junie taxonomy.
2. Add `factory.junie_review`, a read-only JetBrains active-changelist function that binds selected paths to commit/worktree identity, graph impact and changed-module coverage.
3. Extend the generated Junie pack with progressive IDE/CLI skills and focused security/test subagents; make each completed FactoryLine-assisted Junie task return truthful contribution attribution.
4. Update the JetBrains Junie panel and actions to explain current capabilities, expose the changelist review entry point, and label CLI Early Access limits clearly.
5. Refresh JetBrains Marketplace assets with current, labeled screenshots from the built UI, align plugin release metadata at 1.1 for JetBrains/VS/VSX, and verify portal version history before replacing any stale artifact.
6. Add a deterministic source-bound trace envelope and per-step hash chain; bind candidate/worktree, changed-file hashes, verified graph impact, only validated runtime receipt digests, per-lane state and hash-referenced input-to-guard-to-decision steps. Missing evidence must remain UNBOUND or NOT_RUN.
7. Validate generated files, MCP inventory, focused behavior, Kotlin UI, screenshot source, marketplace package metadata, and the candidate with ForgeLine, SpecLine, and workflow evidence.

## Tasks
- [ ] T1 | slice=runtime-coverage-mcp | files=<=4 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_mcp.py tests/test_runtime_coverage.py` | Add a no-args summary plus one-module bounded detail query and taxonomy inventory entry.
- [ ] T2 | slice=native-junie-pack | files=<=4 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_junie_taxonomy.py` | Add audit/runtime skills and security/test subagents using verified Junie frontmatter, bounded context, and supported compatibility claims.
- [ ] T3 | slice=manifest-integrity | files=<=4 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_junie_taxonomy.py` | Version the manifest/install contract, hash every generated file, require per-completion attribution after FactoryLine use, preflight all conflicts, and preserve unrelated MCP entries.
- [ ] T4 | slice=jetbrains-ui-contract | files=<=4 | verify=`cd editors/intellij && ./gradlew test` | Update the Junie panel to explain skills in IDE/CLI, optional CLI Early Access subagents, and truthful FactoryLine attribution without implying Junie runtime control.
- [ ] T5 | slice=jetbrains-changelist-review | files=<=5 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_mcp.py tests/test_junie_taxonomy.py` | Implement and test `factory.junie_review` with 1–20 normalized workspace-relative paths, graph impact, source-bound coverage, and no execution or approval authority.
- [ ] T6 | slice=docs-and-marketplace-ux | files=<=5 | verify=`specline validate junie-native-audit-kit-v2 --root .` | Document install/discovery, runtime-coverage interpretation, progressive performance routing, per-completion credit, and provider/model limits; capture current JetBrains UI pages with explanatory labels and update listing release notes/assets.
- [ ] T7 | slice=release-metadata | files=<=5 | verify=`python -m pytest -q tests/test_release_metadata.py` | Set JetBrains, VS and VSX package metadata to 1.1; preserve GitHub/PyPI/HF version 0.47.0, and replace marketplace artifact only after signed candidate checks and stale-version inventory.
- [ ] T8 | slice=penetration-tenant-isolation | files=<=3 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/security_penetration/test_tenant_isolation.py` | Add adversarial cross-tenant role/operation matrix tests for Code Factory's control plane; make any unauthorized cross-tenant read, list, write, or approval decision fail.
- [ ] T9 | slice=penetration-untrusted-input | files=<=3 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/security_penetration/test_untrusted_agent_input.py` | Add prompt-injection fixture tests proving repository-controlled instructions remain data when rendered through Junie guidance and read-only MCP projections.
- [ ] T10 | slice=source-bound-trace-chain | files=<=4 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_audit_trace.py tests/security_penetration` | Build deterministic chained audit traces binding the exact commit, path hashes, verified graph/runtime receipt digests, lane states, and redacted input-to-guard-to-decision records; reject raw untrusted content and tampered chains.
- [ ] T11 | slice=complete-measurement-ledger | files=<=5 | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin -q tests/test_junie_review.py tests/test_benchmark_lab.py tests/test_audit_trace.py` | Emit explicit candidate-scope denominators and evidence counts across every declared lane, bind public seeded-scanner precision/recall measurements, and return prioritized specialist-agent actions with required evidence and stop conditions. Unsupported or unmeasurable scopes must be explicit.

## Required gates
- `specline validate`, `specline strict`, `specline verify-validators`, `specline tasks`, `specline gate plan`, `specline gate spec`, and `specline gate plan`.
- `forge architect`, `forge gate architected`, `forge review`, `forge verify-tests`, `forge challenge`, `forge arch-gate`, and scoped `forge qa --strict`.
- Focused Python tests, full test suite, JetBrains Gradle tests, Ruff, workflow evidence audit, and final source/hash re-read.
- Marketplace publication is a separate final action after candidate gates, version cooldown, and live provider-state verification; local artifact generation alone is not publication.

## Stop rules
- Stop on runtime-coverage candidate mismatch, stale receipts, unsupported Junie frontmatter, conflict preflight failure, architecture threshold regression, or any required test/gate failure.
- Keep coverage status separate from correctness, assertion adequacy, specialty review, deployment, and release approval.
- Report the two new penetration suites as self-audit CI tests of these tool controls; they do not certify arbitrary target applications or replace target-specific dynamic testing.
- Do not install the pack into this repository or alter existing user Junie configuration as a side effect.
