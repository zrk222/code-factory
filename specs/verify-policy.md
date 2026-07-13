# Spec: verify-policy

## Intent

Prove that a repository's release-policy evaluator rejects every deleted or
inverted policy rule.

## Requirements

- The command shall require a reviewed JSON challenge manifest containing a
  non-empty argv command with a `{policy}` placeholder.
- The original policy shall pass before mutation results can be trusted.
- The command shall delete and invert every explicit rule, or every boolean
  setting when the policy uses nested settings.
- Every mutated policy shall make the evaluator return non-zero.
- A mutation that still passes shall return `HOLLOW_POLICY` and a non-zero
  command exit.
- Timeout, missing placeholder, shell string, failed baseline, and escaped
  working directory shall be errors, not evidence of enforcement.
- The command shall write a local receipt and shall not merge, publish, deploy,
  or grant approval authority.

