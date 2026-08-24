# Code Factory 0.23.0

Code Factory 0.23.0 adds content-addressed proof reuse for read-only validation.

- `factory proofs record|plan|verify|challenge`
- RUN, REUSE, SKIP, and BLOCK with fail-closed relevance
- SHA-256 binding for inputs, outputs, command, toolchain, and environment
- compact public-safe proof plans
- isolated mutation challenge
- exact automatic paired savings for verified reuse
- SHA-keyed IntelliJ workflow concurrency

The feature earned ForgeLine grade A with a 100/100 final feature score,
maximum complexity 9, security score 100, complete public-function test intent,
and complete public-function documentation.
That score is scoped to `factoryline/proof_reuse.py`, not the whole repository.

July contained 66 IntelliJ workflow launches for 42 unique head SHAs: 24
duplicate launches (36.4%), 216 duplicate jobs, and 1101.3 duplicate
runner-minutes measured from API timestamps. The user-supplied Actions UI job
averages imply an approximate 2567.5-minute matrix baseline, making the exact
duplicate minutes approximately 42.9% of that approximate baseline. These are
historical opportunity measurements, not realized or prospective savings.
Future savings remain unmeasured until prospective reuse receipts exist.
