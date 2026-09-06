# Plan: release-0.46.3-huggingface-admission-v1

Spec: specs/release-0.46.3-huggingface-admission-v1.md
Architect verdict: PASS

## Scope

Create one coherent, not-yet-published core `0.46.3` candidate. Add an
executable static admission boundary for the Hugging Face Space route, then
prove version coherence, ordering, mutation resistance, packaging, and
zero-authority provider boundaries locally.

## Atomic task packets

- [x] T1 | slice=core-version-0.46.3 | files=<=18 | verify=`python -m pytest -q tests/test_factoryline.py tests/test_mcp.py tests/test_publication_metadata.py tests/test_visual_listing.py tests/test_huggingface_surface.py` | Aligned current package, descriptor, discoverability references, candidate notes, and exact-version regression expectations; historical 0.46.2 records remain unchanged.
- [x] T2 | slice=huggingface-route-admission | files=<=5 | verify=`python -m pytest -q tests/test_release_integrity.py tests/test_release_decision.py tests/test_graph_ops.py` | Required `HF_TOKEN` before route candidate work and proved missing or late admission fails in the local static release check.
- [x] T3 | slice=core-0.46.3-release-proof | files=<=6 | verify=`python -m build; python -m twine check <temporary-artifact-directory>/*` | Completed strict SpecLine and 9/9 mutation checks, static release integrity, clean-wheel smoke, and scoped drift review; repaired the Windows timeout-cleanup race without weakening bounded process supervision; candidate remains local for later consolidated publication.
- [x] T4 | slice=envelopes | files=envelopes/release-0.46.3-huggingface-admission-v1.json | verify=`forge ship release-0.46.3-huggingface-admission-v1 --root .` | Bound the shipped local candidate to a hash-sealed release intent with two directly checkable assumptions and an explicit zero-authority boundary.

## Non-goals

- No provider contact, token retrieval, secret inspection, workflow dispatch,
  upload, tag, publication, deployment, or approval action.
- No claim that PyPI, the MCP Registry, Zenodo, Hugging Face, VS Code, Open
  VSX, JetBrains, or any other provider has accepted the candidate.
