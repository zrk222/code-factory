# Plan: jetbrains-proof-review
Spec: specs/jetbrains-proof-review.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Extend the analysis-only CLI scope to include an actual Git working tree
   without changing explicit path behavior.
2. Add a schema-bound Kotlin review model and command entry point.
3. Add an IntelliJ-native Proof Review tool-window tab with safe file
   navigation, focused-file review, and progressive detail disclosure.
4. Add an explicitly saved local Handoff Packet for a reviewable cross-session
   continuation without external persistence.
5. Validate contracts, plugin packaging, platform compatibility, and public
   documentation before release preparation.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=change-review-local-scope | files=<=3 | verify=`python -m pytest -q tests/test_change_review.py` | Include branch, staged, unstaged, and non-ignored untracked paths in implicit local Change Review scope and prove explicit paths bypass Git.
- [ ] T2 | slice=jetbrains-review-model | files=<=3 | verify=`cd editors/intellij; .\gradlew.bat test` | Add a schema-bound Kotlin Proof Review parser, direct command contract, and unit tests for valid and unavailable results.
- [ ] T3 | slice=jetbrains-proof-review-ui | files=<=4 | verify=`cd editors/intellij; .\gradlew.bat test` | Add the Proof Review tab, full-diff and active-file explicit-confirmed actions, bounded file navigation, attention-first summary, local copyable brief, and secondary raw details.
- [ ] T4 | slice=jetbrains-review-handoff | files=<=4 | verify=`cd editors/intellij; .\gradlew.bat test; python -m pytest -q tests/test_change_review.py` | Add a separate confirmed Save review handoff command that writes only hash-bound review artifacts under .factory/change-reviews and reports bounded local paths.
- [ ] T5 | slice=proof-review-docs | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the local review workflow and update public JetBrains copy without productivity or release claims.
- [ ] T6 | slice=release-proof | files=<=4 | verify=`python -m pytest -q; cd editors/intellij; .\gradlew.bat check buildPlugin marketplacePreflight` | Run strict/mutation gates, architecture checks, package verification, and record release readiness without publishing.
