# Code Factory commercial model: decision record

November 21, 2026. Status: recorded and implemented **disabled**. No
enforcement, billing, telemetry, checkout or license replacement is active.

## Published Python package licenses

The five current wheels declare `MIT OR Apache-2.0` in the SPDX
`License-Expression` field and include `LICENSE-MIT`, `LICENSE-APACHE` and
`NOTICE`. PyPI's JSON can return `null` in the legacy `license` field
when the SPDX field supplies the declaration. [Metadata standard](https://peps.python.org/pep-0639/#deprecate-license-field)

| Distribution | Version | SPDX expression | Python |
| --- | --- | --- | --- |
| [Code Factory](https://pypi.org/project/factoryline-code-factory/0.50.0/) | 0.50.0 | MIT OR Apache-2.0 | 3.10+ |
| [SpecLine](https://pypi.org/project/code-factory-1-spec/0.5.4/) | 0.5.4 | MIT OR Apache-2.0 | 3.11+ |
| [ForgeLine](https://pypi.org/project/code-factory-2-forge/0.10.8/) | 0.10.8 | MIT OR Apache-2.0 | 3.11+ |
| [HSF](https://pypi.org/project/code-factory-3-compile/0.5.5/) | 0.5.5 | MIT OR Apache-2.0 | 3.11+ |
| [Prestige](https://pypi.org/project/code-factory-4-design/0.8.0/) | 0.8.0 | MIT OR Apache-2.0 | 3.11+ |

The full `factoryline-code-factory[factory]` installation requires Python 3.11
or newer. The core-only installation supports Python 3.10 or newer.
The [November 21 commercial policy](../commercial-policy.v1.json) is a separate
source record with activation disabled.

## Approved model

Approved by the project owner on November 21, 2026 (WhatsApp, model proposal
accepted with "Yes"; implementation and commit requested with "Resolve and
commit"):

- **Free:** 5 complete proof workflows per person per calendar month (UTC).
- **Paid:** 100 workflows per named human seat per month at **US$12.95** per
  seat, starting **January 1, 2027**. Everything before that date is free.
- Each workflow includes its checks and **2 repair reruns for the same change
  within 7 days**.
- One seat covers that person's **agents and devices**. The seat subject is the
  human owner; an AI agent's declared identity is never proof of subscription.
- **Reading and exporting results stays free.** Rejected starts and internal
  tool errors never consume allowance. **No overage charges**: over allowance
  is a hard stop with an upgrade path, never a bill.
- Personal users keep the recurring 5-workflow free allowance and can upgrade
  for heavier use; the paid seat is available to individuals and businesses.

The allowance counts are approved starting policy, not usage-tested economics.
Promotion duration and any price lock are unspecified.

## What was built

All of it disabled by default (`FACTORY_COMMERCIAL_MODE=off`; `activation:
false` in `commercial-policy.v1.json`):

- `commercial-policy.v1.json` — the versioned, inert policy document above.
- `factoryline/enterprise_enforcement.py` — policy parsing and pure admission
  decisions: `PRELAUNCH_FREE`, `ALLOW`, `ALLOW_INCLUDED_RERUN`,
  `UPGRADE_REQUIRED`, `ENTITLEMENT_INVALID`.
- `factoryline/enterprise_ops.py` — atomic local reservation ledger in a
  user-level data directory (`~/.factoryline/commercial`, not any project's
  resettable `.factory` folder), with POSIX `flock` or a Windows byte-range
  lock plus per-home thread serialization around reserve/finalize/release.
  Unsupported or failed locking aborts the operation. It also provides
  idempotency keys, crash-expiry of stale reservations, period rollover,
  clock-rollback protection, read-only export and an explicit, visible reset.
- `factoryline/enterprise_receipts.py` — offline verification of
  issuer-signed DSSE Ed25519 entitlements against a separately configured
  commercial trust root. No embedded issuer private key, no credential
  collection, no network call. `covered_versions.max` is required: open-ended
  future-version grants are deliberately not issuable.
- `factoryline/enterprise_enforcement.py` — one admission boundary (`off` / `shadow`
  / `enforce`) combining policy, ledger and entitlements.
- `factoryline/cli_enterprise.py` — `factory commercial plan | usage | export |
  reset | import-entitlement | entitlements`. No purchase or activation path.
- `factoryline/runtime_audit.py` — the Proof Agent execution route now passes
  through the gate after safety preflight and before dispatch, settling once
  at the terminal result.

## Honest boundaries

- **Soft local enforcement only.** The ledger is a transparent local file. A
  determined user can reset it (`factory commercial reset --yes` is explicit
  and visible), and it cannot see other devices. Reliable cross-device limits
  require a separately approved account/entitlement service with its own
  privacy, retention, outage and billing design; that service is **not built
  or authorized** by this change.
- **Coverage is one route.** The gate is wired into the Proof Agent execution
  route (`cli_agent.run` -> `execute_proof_agent`). Other execution routes
  (direct runtime-audit commands, assembly/repair paths, IDE subprocesses, CI)
  are **not** wrapped; no global quota is claimed. Read-only MCP gains no
  execution authority.
- **Proof integrity is untouched.** Quota status never changes a finding,
  never skips a check or negative control, never interrupts an admitted run,
  and never hides existing receipts. Payment status never replaces signed-plan
  verification or human approval. `agent_license.py` remains about agent
  autonomy evidence, unrelated to paid access. `meter.py` remains a
  measurement log, not a billing meter.
- **Repair-rerun semantics, defined explicitly:** a rerun is the same change
  when scope and plan digests match the original finalized workflow. A new
  candidate digest alone never disqualifies a repair; expanded scope or a
  different plan is a new workflow. The Proof Agent route currently always
  admits as a new workflow; included reruns are supported by the gate API for
  callers that supply the original workflow reference.

## License route

Existing `LICENSE-MIT`, `LICENSE-APACHE`, `LICENSE`, `NOTICE` and packaging
metadata are **unchanged**. Prior releases remain usable under their granted
terms; no retroactive restriction is made or implied, and no contributor
rights (human or AI-authored) are adjudicated here. GitHub's contributor list
is an investigation input, not evidence of ownership, assignment or consent.

Unresolved before any future commercial license switch, kept explicit rather
than invented:

1. Exact future version/component scope after rights review (recommended: no
   retroactive restrictions, no automatic SpecLine/ForgeLine/CompileLine/
   Prestige changes; no license switch was approved for core 0.50.0 or plugins 1.3.6).
2. Promotion duration and renewal treatment.
3. Counsel review of final terms; refunds, taxes, cancellation, seat
   reassignment and shared CI use before any payment launch.

## Verification

Deterministic tests cover policy decisions, ledger concurrency and idempotent
retry, crash recovery, period rollover, clock rollback, rerun window/scope
rules, entitlement signature/window/version validation, gate modes, and the
Proof Agent wiring (refusal before dispatch, settlement on completion and on
internal error, and the invariant that quota state never alters a proof
result). See `tests/test_commercial_*.py`.
