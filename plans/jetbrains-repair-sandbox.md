# Plan: jetbrains-repair-sandbox
Spec: specs/jetbrains-repair-sandbox.md
Architect verdict: PASS

## Logical decomposition
1. Define a deterministic Scope Passport that captures only explicit Change List
   paths, current baselines, existing proof-review facts, and a human-owned
   authority boundary.
2. Add a fail-closed textual candidate-patch inspector that binds candidate
   bytes to the current Scope Passport and rejects out-of-scope paths.
3. Add a native JetBrains Change List selector, direct confirmed commands, and
   a Repair Sandbox tab with visible scope, candidate, verifier, and apply
   states.
4. Publish local-first professional-team documentation and Marketplace copy.
5. Validate strict/mutation contracts, deterministic Python tests, Kotlin tests,
   package metadata, and platform verification before any later release action.

## Tasks
- [ ] T1 | slice=repair-scope-contract | files=<=4 | verify=`python -m pytest -q tests/test_repair_sandbox.py` | Implement deterministic scope construction, drift checking, and opt-in artifacts.
- [ ] T2 | slice=repair-candidate-contract | files=<=3 | verify=`python -m pytest -q tests/test_repair_sandbox.py` | Bind only current scope-bound textual patches and fail closed on unsafe forms.
- [ ] T3 | slice=jetbrains-changelist-ui | files=<=5 | verify=`cd editors/intellij; .\gradlew.bat test` | Add native Change List selection, direct commands, schemas, and visible human-owned apply boundary.
- [ ] T4 | slice=professional-docs | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update professional-team surfaces without unsupported quality, autonomy, or download claims.
- [ ] T5 | slice=proof | files=<=5 | verify=`specline strict jetbrains-repair-sandbox --root .; forge verify-tests jetbrains-repair-sandbox jetbrains-repair-sandbox.ssat.yaml --root .; python -m pytest -q; cd editors/intellij; .\gradlew.bat check buildPlugin marketplacePreflight verifyPlugin` | Run gates and record outcomes locally.
