# Content-addressed proof reuse

Code Factory 0.23 reuses verified read-only evidence without reusing commands
or external effects.

## Request manifest

```json
{
  "schema": "factory.proof-request.v1",
  "gates": [
    {
      "name": "python-tests",
      "command": ["python", "-m", "pytest", "-q"],
      "inputs": ["factoryline/proof_reuse.py", "tests/test_proof_reuse.py"],
      "outputs": ["dist/test-receipt.json"],
      "relevant_paths": ["factoryline", "tests"],
      "safe_to_skip": true,
      "read_only": true,
      "toolchain": {"python": "3.11.9", "pytest": "9.0.2"},
      "environment": {"os": "windows", "arch": "x64"}
    }
  ]
}
```

The command is hashed and omitted from compact plans. Inputs and outputs must
be regular files inside the workspace. Symlink or path traversal outside the
workspace is rejected.

## Record and route

```bash
factory proofs record proofs.json --gate python-tests --elapsed-ms 600000 --root .
factory proofs plan proofs.json --changed factoryline/proof_reuse.py --root . --json
```

- RUN: no exact verified green receipt exists.
- REUSE: the receipt and every bound hash verify.
- SKIP: reviewed relevance says the supplied changes are unaffected.
- BLOCK: the request is unsafe, malformed, missing inputs, or side-effecting.

The `factory.proof-plan.v1` receipt contains hashes, dispositions, compact
reasons, routing time, and markers. It omits source bodies, raw commands,
prompts, logs, credentials, and absolute workspace paths.

## Prove the verifier is non-hollow

```bash
factory proofs challenge .factory/proofs/<proof-key>.json --root . --json
```

The challenge copies declared evidence into an isolated temporary workspace,
changes one input, and requires the original receipt to fail verification. It
never mutates the working tree.

## Exact savings

`--auto-savings` records a `factory.savings-pair.v1` only after exact REUSE.
The original positive elapsed measurement is the baseline. Current routing
time is measured. The proof receipt is the hash-bound equivalent-outcome
evidence. Tokens remain null unless the baseline contains an exact token
observation; no tokenizer estimate is substituted.

## Authority

Proof reuse is supervised validation infrastructure. It may hash, read, and
write local receipts. It may not execute the requested gate, publish, deploy,
sign, approve, discover credentials, grant connectors, or send messages.
