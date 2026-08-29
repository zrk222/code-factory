# Plan: revenueforge-v1

Spec: `specs/revenueforge-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=specs | files=specs/revenueforge-v1.md,specs/revenueforge-v1.ssat.yaml | verify=`specline strict revenueforge-v1 --root .` | Seal product, disclosure, privacy, growth, and authority contracts.
- [x] T2 | slice=factoryline | files=factoryline/revenueforge.py | verify=`python -m pytest -q tests/test_revenueforge.py` | Implement manifest validation, bundle generation, growth planning, and private benchmarks.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_revenueforge_cli.py` | Expose the bounded revenue command family.
- [x] T4 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`prestige audit factoryline/graph_ops.html` | Project verified readiness and human-control boundaries visually.
- [x] T5 | slice=docs | files=docs/REVENUEFORGE.md | verify=`python -m pytest -q tests/test_revenueforge.py` | Document the exact workflow and claim boundary.
- [x] T5a | slice=examples | files=examples/revenueforge/products.yaml,examples/revenueforge/growth.yaml | verify=`python -m factoryline.cli revenue validate --root . --products examples/revenueforge/products.yaml --json` | Provide approachable product and growth examples.
- [x] T6 | slice=tests | files=tests/test_revenueforge.py,tests/test_revenueforge_cli.py | verify=`python -m pytest -q tests/test_revenueforge.py tests/test_revenueforge_cli.py` | Challenge dark patterns, disclosure drift, duplicate products, path escape, experiment bounds, benchmark privacy, and receipt tampering.

## Release boundary

No App Store Connect write, offer send, experiment start, winner promotion, price change, review publication, deployment, or credential access is authorized.
