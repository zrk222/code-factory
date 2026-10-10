# 0.48.1 / 1.1.4 approver identity review

Review scope: the current VS Code and JetBrains `APPROVED_BY` workflow edits and the `test_release_integrity.py` receipt-binding assertion.

## Result

The identity producer and consumer now agree. Both workflows set `APPROVED_BY` to the exact `${{ github.actor }}` and pass it unchanged to `prepare_release_contract.py --approved-by`. When an exception is requested, each workflow requires actor `zrk222`, then checks the generated contract's `approved_by` equals `GITHUB_ACTOR` before writing the exception receipt. The receipt's `requesting_actor` is that same actor; the release-candidate validator compares it to the contract approver.

The integrity test now reads the `APPROVED_BY` expression from the prepare-contract step, verifies the CLI argument wiring, substitutes its controlled `zrk222` fixture identity, and uses that value in the contract receipt. It also retains the negative mismatched-approver case.

Protected controls remain in place: VS Code `authorize` still uses `vscode-marketplace` and is required for validation when `publish=true`; JetBrains `authorize` remains on `jetbrains-marketplace` with the scoped publisher token check. The review diff changes only the approver value formatting and test binding; it does not remove or weaken those gates.

No issue found in the requested identity flow. This is a static workflow/test review, not evidence of a live protected-environment approval or provider publication.
