# Precision-tier protocol

Amended 2026-11-27 before the 323-case reserve or the 10-case Q4 cohort is opened. Arm G (`prereg.json` → `arm_G_two_stage_triage`) is the only confirmatory arm: Haiku ≥ 2 of 3 verified REPORT votes, then Sonnet 3 of 3, with the same prompt and the model-free citation verifier.

The population is the recall harness's `review-alerts` export, which checks the score receipt, source captures, changed-file membership and retained spans. `precision_cohort_preflight.py arm-g packet` regenerates it from the verified score and writes the blinded packet and a key bound to the packet, score receipt, and scanner export digests. Reserve labels come from Opus and Fable, never from a triage model. `run-lock.json` lists every pin and the run steps; `precision_cohort_preflight.py arm-g verify-lock` must print `LOCK VERIFIED` before any reserve case is opened.

The earlier draft and prototype scripts are preserved at [c6457735](https://github.com/zrk222/code-factory/tree/c6457735c8d9eaf8d83c32c87fa8b5372cfe34ea/docs/evidence/precision-tier-prereg-20261127). Arms C and D (CodeQL corroboration) are not part of the confirmatory run.

## Observed exposed-development recall

The [exposed detector commit](https://github.com/zrk222/code-factory/commit/1db5beb87db6b749a9932e33b35ec1339892e962) found **78/161** registered cases by the strict old-side fix-hunk criterion. The replay scored 159 cases, left two unscored for source-scope reasons, and recorded zero timeouts. The OpenGrep rules digest is `5728dc60ff85393da9181f1f5d1e23fc18b0185434e3885e1fae69f9415cd033`. The pattern score receipt SHA-256 is `39930fe1e581d348bdd663c0025acb4ea888fd5c78aedfa942783258b260e426`.

The [paired native scorer](https://github.com/zrk222/code-factory/commit/1ff15b3aa6cb38260b23552e9b1c36abd28adc59) verified extraction on both sides of all seven supplemental Python CodeQL pairs. They contributed zero eligible strict hits. The paired receipt SHA-256 is `6cc18df842a37b275c2204862790e017d4e2ec7fa2a64caa3afeed5b3bb77c7f`. Arm G's reserve and Q4 inputs remain sealed.
