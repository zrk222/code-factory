# Plan: plan-to-proof-verifier
Spec: specs/plan-to-proof-verifier.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Define and validate the provider-neutral, approved agent-plan envelope.
2. Join exact plan alignment to existing Diff-to-Proof facts without executing
   a command or interpreting AI output.
3. Render the same facts as a GitHub-neutral Check/comment and make the
   existing workflow choose that path only when an envelope is present.
4. Document CodeRabbit coordination as GitHub Check interoperability, not a
   credentialed vendor integration.

## Tasks (atomic - each independently shippable)
- [x] T1 | slice=factoryline | files=factoryline/plan_proof_review.py | verify=`python -m pytest -q tests/test_plan_proof_review.py` | Add deterministic plan-envelope validation and Plan-to-Proof proof-debt rendering.
- [x] T2 | slice=factoryline | files=factoryline/github_plan_proof_review.py,factoryline/cli.py | verify=`python -m pytest -q tests/test_plan_proof_review.py` | Add the SHA-bound advisory GitHub renderer and CLI commands.
- [x] T3 | slice=tests | files=tests/test_plan_proof_review.py,tests/test_github_proof_review.py | verify=`python -m pytest -q tests/test_plan_proof_review.py tests/test_github_proof_review.py` | Prove plan rejection, exact debt derivation, SHA binding, and no-write default behavior.
- [x] T4 | slice=.github | files=.github/workflows/factory-pr-proof-review.yml | verify=`python -m pytest -q tests/test_plan_proof_review.py tests/test_github_proof_review.py` | Make the opt-in PR workflow use the plan-aware renderer only when the optional envelope exists.
- [x] T5 | slice=docs | files=docs/PLAN_TO_PROOF_REVIEW.md,docs/CODERABBIT_INTEROP.md,docs/ENTERPRISE_TEAMS_OPERATIONS.md,docs/OVERVIEW.md | verify=`python -m pytest -q tests/test_plan_proof_review.py tests/test_publication_metadata.py` | Publish exact provider-neutral, CodeRabbit, and teams operations guidance.
- [x] T6 | slice=examples | files=examples/agent-plan.json | verify=`python -m pytest -q tests/test_plan_proof_review.py` | Add a safe, schema-valid agent-plan example.
- [x] T7 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_plan_proof_review.py` | Link the public quick start to the plan-aware proof review.
- [x] T8 | slice=deploy/huggingface | files=deploy/huggingface/README.md,deploy/huggingface/index.html | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Update the Hugging Face proof-first CTA, teams operations path, and optional design-review lane.
- [x] T9 | slice=editors | files=editors/intellij/README.md,editors/intellij/src/main/resources/META-INF/plugin.xml,editors/vscode/README.md,editors/vscode/package.json | verify=`npm --prefix editors/vscode test` | Synchronize IDE public surfaces without claiming autonomous editor authority.
- [x] T10 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Update PyPI discovery metadata for the new review capability.
- [x] T11 | slice=docs | files=docs/PRESTIGE_DESIGN.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add the optional Prestige Design Review guide with exact non-claims and team handoff.
