# Plan: evidence-supply-line-v1
Spec: specs/evidence-supply-line-v1.md (approved)
Architect verdict: PASS

## Logical decomposition (phases)

1. Seal the observation, privacy, and authority contract.
2. Add the admitted generic session recorder and immutable ledger path.
3. Add deterministic inert Gauntlet drafting and target templates.
4. Add the bounded Claude Code hook plugin.
5. Expose CLI/docs/version metadata and run native evidence gates.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=specs | files=specs/evidence-supply-line-v1.md,specs/evidence-supply-line-v1.ssat.yaml | verify=`specline strict evidence-supply-line-v1 --root .` | Seal requirements and architecture invariants
- [x] T2 | slice=factoryline | files=factoryline/session_recorder.py,factoryline/agent_license.py,tests/test_evidence_supply_line.py | verify=`python -m pytest -q tests/test_evidence_supply_line.py tests/test_agent_license.py` | Record admitted, independently validated sessions
- [x] T3 | slice=factoryline | files=factoryline/gauntlet_draft.py,factoryline/data/gauntlet_target_promises.json,tests/test_gauntlet.py | verify=`python -m pytest -q tests/test_evidence_supply_line.py tests/test_gauntlet.py` | Draft inert structure-derived promises
- [x] T4 | slice=plugins | files=plugins/code-factory-session-recorder/**,tests/test_evidence_supply_line.py | verify=`python -m pytest -q tests/test_evidence_supply_line.py` | Add bounded Claude Code hooks
- [x] T5 | slice=.claude-plugin | files=.claude-plugin/marketplace.json,tests/test_langchain_plugin.py | verify=`python -m pytest -q tests/test_langchain_plugin.py` | Register the optional hook plugin
- [x] T6 | slice=factoryline | files=factoryline/cli.py,tests/test_evidence_supply_line.py | verify=`python -m pytest -q tests/test_evidence_supply_line.py` | Expose generic wrap and Gauntlet draft commands
- [x] T7 | slice=docs | files=docs/EVIDENCE_SUPPLY_LINE.md,docs/RELEASE_NOTES_0.43.0.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document boundaries and release value
- [x] T8 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add concise public discovery paths
- [x] T9 | slice=smoke | files=smoke/evidence-supply-line-v1.json | verify=`forge smoke evidence-supply-line-v1 --root .` | Run non-hollow smoke, full regression, package, and clean-install gates
