# Contributing

Code Factory accepts focused fixes, counterfactual challenges, workflow specs,
and integrations that preserve the proof contract.

## Local verification

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m build
python -m twine check dist/*
```

For cross-brick changes, also run `python scripts/prooflab_e2e.py` with the four
numbered packages installed from their matching source train.

## Doctrines

- Do not hand-copy metrics into public claims. Generate them from tests,
  receipts, CI, goldens, or a Factory Passport.
- Do not tune on public-claim fixture sets.
- Add a sabotage case whenever a new gate is added; a gate must prove it can
  reject a broken input before it certifies the real one.
- Preserve human authority for merge, publication, deployment, secrets, and
  production changes.

Open an issue before changing the receipt protocol or canonical stage order.
