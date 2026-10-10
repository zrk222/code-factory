# VS Code 1.1.4 monthly-cap exception review

## Scope and authorization

Reviewed current Open VSX, VS Code Marketplace, and JetBrains workflow exception wiring; release-candidate validation/admission; release-integrity checks; and workflow-emitted receipt tests. The user approved a one-time monthly-cap exception on October 10, 2026 for VS Code/Open VSX 1.1.4.

## Review result

The monthly-cap exception is restricted to the immutable tag `vscode-v1.1.4+build.1`, source version `1.1.4`, and environment `openvsx` or `vscode-marketplace`. Both workflow generators set `monthly_cap_exception: true` only behind exact tag/version, `zrk222` actor, reason-length, and `publish=true` checks. Both bind `source_commit` with `subprocess.check_output(["git", "rev-parse", "HEAD"])`; Open VSX now fails closed if that command fails. Candidate validation also checks the immutable tag against the approved commit.

Both workflows produce the `requesting_actor` from `${{ github.actor }}`. Open VSX prepares its release contract with that same actor; VS Code Marketplace additionally asserts `contract["approved_by"] == GITHUB_ACTOR`. The model checks contract actor and source commit, exact channel/version/tag, protected environment authorization, publish intent, current workflow run ID/attempt, timestamp validity, and the one-hour maximum receipt lifetime. The workflow receipts expire after 30 minutes. Publication requests still depend on the protected `openvsx` or `vscode-marketplace` authorization job succeeding.

Model admission permits a monthly-cap override only for a valid, available `rate_limited` state where the observed count meets the configured cap and the validated receipt has the exact VS Code identity and monthly-cap flag. Ordinary exceptions can override cooldown only while below the monthly cap. Core, JetBrains, other tags, invalid configuration, and unavailable or unknown cadence stay blocked.

`release-train.json` remains configured for four releases per rolling 30 days and a seven-day minimum interval. This exception is bound to the one immutable candidate; later tags continue to use the unchanged limits. Core publication retains its separate actual-publication max-four guard.

## Evidence and limits

- The current Open VSX, VS Code Marketplace, JetBrains, and core publication workflow YAML files parse with `yaml.safe_load`.
- `.factory/114-monthly-tests.log` records **96 passed**. The updated integration test executes the Open VSX and VS Code receipt generators, validates their emitted receipt through `_cadence_exception_payload`, and checks `_cadence_admission` against a synthetic cap-exceeded state; JetBrains remains a negative control. These are local workflow-code fixtures with live-shaped GitHub environment variables, not a live Actions execution.
- Static review and local tests do not establish protected-environment approval or provider publication.

## Python 3.10 expiry-test compatibility review

Reviewed the current two-line change in `tests/test_release_integrity.py`. It normalizes trailing `Z` to `+00:00` before calling `datetime.fromisoformat` for both receipt timestamps, allowing the expiry-duration assertion to run on Python 3.10 while retaining timezone-aware parsing and the exact 1,800-second assertion. The edit is test-only and does not change the release receipt or exception validation behavior. Per the reported CI evidence, Python 3.10's newly added expiry test was the only failure; the focused suite passed on Python 3.11. This review confirms the compatibility fix is narrowly scoped; it does not independently rerun the Python 3.10 CI matrix.
