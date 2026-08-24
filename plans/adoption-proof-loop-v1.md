# Plan: adoption-proof-loop-v1
Spec: specs/adoption-proof-loop-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal the first-proof, Proof Card, and activation contracts.
2. Implement the deterministic CLI and privacy boundaries.
3. Reframe onboarding and public surfaces around one demonstrable outcome.
4. Publish the adoption sprint, Proof Clinic, and distribution scorecard.
5. Validate the product, package, and public claims; release only with receipts.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=specs | files=2 | verify=`specline validate adoption-proof-loop-v1 --root .` | Seal EARS requirements and execution plan.
- [x] T2 | slice=factoryline | files=2 | verify=`pytest -q tests/test_adoption.py` | Add first-proof, Proof Card, and adoption CLI surfaces.
- [x] T3 | slice=tests | files=1 | verify=`pytest -q tests/test_adoption.py` | Prove hollow-test detection, redaction, tamper rejection, and honest aggregation.
- [x] T4 | slice=docs | files<=4 | verify=`python -m pytest -q tests/test_adoption.py tests/test_huggingface_surface.py tests/test_publication_metadata.py` | Make first proof the primary onboarding path and publish the sprint/clinic contracts.
- [x] T5 | slice=public-surfaces | files<=4 | verify=`prestige audit deploy/huggingface/index.html` | Use the same outcome-led demo and CTA on distribution surfaces.
- [ ] T6 | slice=release | files<=4 | verify=`python -m pytest -q` | Run native gates, commit, push, and obtain provider read-back receipts.
