# Policy Drift Dossier v1 delivery plan

- [ ] T1 | slice=factoryline | files=factoryline/github_assurance_dossier.py,tests/test_github_assurance_dossier.py | verify=`python -m pytest tests/test_github_assurance_dossier.py -q` | validate snapshots, deterministic drift, and named expiring exceptions
- [ ] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/graph_ops.py,tests/test_graph_ops.py | verify=`python -m pytest tests/test_github_assurance_dossier.py tests/test_graph_ops.py -q` | expose local CLI and read-only Graph Ops projection
- [ ] T3 | slice=docs | files=docs/GITHUB_ASSURANCE_DOSSIER.md,docs/GITHUB_MONETIZATION_2026.md | verify=`python -m pytest tests/test_commercial_packaging.py -q` | document the proof and commercial boundaries
- [ ] T4 | slice=README | files=README.md | verify=`python -m pytest tests/test_commercial_packaging.py -q` | update concise public discoverability
- [ ] T5 | slice=deploy | files=deploy/huggingface/index.html | verify=`python -m pytest tests/test_commercial_packaging.py -q` | update hosted public summary

Architect verdict: PASS
