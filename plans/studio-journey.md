# Plan: studio-journey
Spec: specs/studio-journey.md
Architect verdict: PASS

## Implemented task records
- [x] T1 | slice=factoryline | files=factoryline/app_builder.py,tests/test_studio.py | verify=`python -m pytest -p no:cacheprovider tests/test_studio.py -k journey` | Connect current candidate bindings to bounded isolated execution, preview assets and retained receipts.
- [x] T2 | slice=factoryline | files=factoryline/studio.py,tests/test_studio.py | verify=`python -m pytest -p no:cacheprovider tests/test_studio.py -k journey` | Add beginner stage controls and exact action confirmations using existing mission and repair authority.
- [x] T3 | slice=factoryline | files=factoryline/data/junie_pack.json | verify=`python -m pytest -p no:cacheprovider tests/test_agent_contract.py -k studio` | Expose actual native journey inputs and evidence/recovery boundaries to agents and Junie.

## File admission
Measure normalized bytes and lines before each edit. Studio is2244lines/152078bytes; app_builder is690lines/23065bytes. Reserve at most500newlines in each existing module before writing. No new Python module, no raised architecture ceiling, no oversized intermediate file.

## Acceptance
Focused changed/failed tests only, actual isolated operator run and preview, negative controls, strict architecture, configured lint, separate AI review, hash-bound workflow gate and required CI. External empirical accuracy and production deployments remain separate evidence requirements, not synthetic passes.
