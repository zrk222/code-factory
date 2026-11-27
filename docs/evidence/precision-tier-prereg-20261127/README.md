# Precision-tier protocol

Amended 2026-11-27 before the 323-case reserve or the 10-case Q4 cohort is opened. Arm G (`prereg.json` → `arm_G_two_stage_triage`) is the only confirmatory arm: Haiku ≥ 2 of 3 verified REPORT votes, then Sonnet 3 of 3, with the same prompt and the model-free citation verifier.

The population is the recall harness's `review-alerts` export, which checks the score receipt, source captures, changed-file membership and retained spans. `build_packet.py` turns it into the blinded packet and a key bound to the packet digest. Reserve labels come from Opus and Fable, never from a triage model. `run-lock.json` lists every pin and the run steps; `verify_lock.py` must print `LOCK VERIFIED` before any reserve case is opened.

The earlier draft and prototype scripts are preserved at [c6457735](https://github.com/zrk222/code-factory/tree/c6457735c8d9eaf8d83c32c87fa8b5372cfe34ea/docs/evidence/precision-tier-prereg-20261127). Arms C and D (CodeQL corroboration) are not part of the confirmatory run.
