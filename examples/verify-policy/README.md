# Verify Policy Examples

Both examples contain the same small release policy. Their evaluator accepts the
baseline only when `release.require_ci` and `quality.require_hollow_tests` are
both `true`.

Python:

```powershell
cd python
factory verify-policy --root . --challenge policy.challenge.json
```

TypeScript:

```powershell
cd typescript
factory verify-policy --root . --challenge policy.challenge.json
```

The `python/policy.challenge.hollow.json` file is deliberately broken. It exits
zero for every policy and is included to demonstrate a `HOLLOW_POLICY` result:

```powershell
cd python
factory verify-policy --root . --challenge policy.challenge.hollow.json
```
