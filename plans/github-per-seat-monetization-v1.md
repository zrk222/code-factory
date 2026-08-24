# Plan: github-per-seat-monetization-v1

Spec: `specs/github-per-seat-monetization-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=specs | files=specs/github-per-seat-monetization-v1.md | verify=`specline strict github-per-seat-monetization-v1 --root .` | Lock the dates, price, and non-goals.
- [x] T2 | slice=docs | files=docs/GITHUB_MONETIZATION_2026.json,docs/GITHUB_MONETIZATION_2026.md | verify=`python -m pytest -q tests/test_commercial_packaging.py` | Add the human-controlled source of truth and customer notice.
- [x] T3 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_commercial_packaging.py` | Disclose the GitHub plan without implying live checkout.
- [x] T4 | slice=deploy/huggingface | files=deploy/huggingface/index.html | verify=`python -m pytest -q tests/test_publication_metadata.py` | Disclose both platform plans on the public static surface.
- [x] T5 | slice=docs | files=docs/COMMERCIAL_PACKAGING.md | verify=`python -m pytest -q tests/test_commercial_packaging.py` | Connect the commercial guide to the distinct GitHub plan.
- [x] T6 | slice=tests | files=tests/test_commercial_packaging.py | verify=`python -m pytest -q tests/test_commercial_packaging.py` | Bind dates, price, activation state, and plan separation to tests.

## Release boundary

This plan changes only source-controlled policy and public copy. It does not
publish an external page, change a Marketplace listing, create a payment system,
accept payment, or activate a paid entitlement.
