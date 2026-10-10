# Nested-oracle and release-candidate review

Scope: generic direct lexical local helper invocation, not framework/repository
names. Calls must follow definitions, await async helpers, carry strong assertions
and propagate assertion failures. Duplicate/rebound/decorated/helper-shadowed
names, vacuous checks, dead Boolean/conditional branches and uncalled helpers
remain findings. Source is parsed, never executed by the scanner.

Independent agent review reproduced two candidate defects: Boolean short-circuit
reachability and inherited helper shadowing. Both were fixed; an additional
unknown-operand/constant-short-circuit case was fixed and retained in regressions.
Final bounded independent agent review PASS: four direct scanner reproductions
report QUALITY_HOLLOW_TEST; 29 isolated targeted tests pass. This is agent review,
not a second human reviewer or independent population accuracy measurement.

The upstream corpus contains31 public cases, selected after inspecting findings.
The new Rich recursive-exception case invokes bar(), whose assertion checks the
exception cause; it is legitimate. Three genuine missing-oracle controls remain.
The eight seeded benchmark cases remain separate, not an independent holdout.

Core0.48.1/editor1.1.4 are unpublished candidates. This scoped edit does not publish,
change credentials, loosen budgets or grant release approval. UI accessibility is
not applicable: no rendered UI behavior changed. External effects are not
applicable: only candidate version metadata/docs and local scanner behavior change.
Performance is checked by strict architecture limits and real-source observations;
no speedup or production precision/recall claim follows from these checks.

Reproduction: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1; python -m pytest -p
pytest_asyncio.plugin tests/test_review_audits.py tests/test_adoption.py
 tests/test_change_review.py tests/test_benchmark_lab.py
 tests/test_release_integrity.py tests/test_jetbrains_release_artifact.py
 tests/test_release_candidate.py -q. Final result: 555 passed. Ruff+C901 pass,
strict architecture HEALTHY,460 Python files; tracked-source Forge QA A98.8.
The isolated wheel's scanner bytes match current source; all31 upstream cases
pass through the installed wheel; guard-path/neutral-delivery smoke passes.
