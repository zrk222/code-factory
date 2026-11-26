# Qualification inputs for candidate 3b5b28ff

**Span reviews of the three loss items.** One session review plus two blinded arms (Opus 5.5 and Sonnet 5.5) labeled all 10 hunk alerts FP, unanimously. Packet and labels: `span-packet.json`, `span-arm*.json`.
- **GHSA-g4wm, 4 alerts:** the baseline flags calls to a test-suite `exec(name, fn)` helper, not child_process.
- **GHSA-3753, 1 alert:** the interpolated `label` is assigned from `escapeHtml(...)` two lines earlier.
- **GHSA-p849, 5 alerts:** the reference rules flag the server-side `userId` and identifier constants. The tainted `filter.latestMsgReceiveTimestamp.$lt` is not flagged.

**Loss plans.**
- `loss-plan-sepoct.json` → `self-816bbef3-sepoct.json`: 816bbef3 scored against itself on the Sep–Oct cohort 1e7a58f7, with spans. Adjudication: `span-adjudicated-losses-sepoct.json`.
- `gain-plan-fresh.json` → `qualification.json`, the retention checkpoint. This is the reference rules 6a3457b1 regenerated on the current harness and OpenGrep 2.1.0 with exact spans. It reproduces all 36 original reference gains plus GHSA-8mcc, and replaces the span-less 21299b0 checkpoint.

**Control plan.** `control-plan.json`, schema factory.recall-control-plan.v1. It excludes, on both arms, the build and vendored outputs that the scanner never targets:
- jquery: `dist/wrappers`, 2 files.
- laravel: renderer `dist`, 1 file.
- pdf.js: `external/dist` plus the generated jbig2 fallback, 4 files, with a 30 s timeout.
- rubygems: `lib/bundler/vendor`, 92 files.
- mastodon: generated annual-report model and migrations, 4 files. These were covered only on the candidate arm, which raised 0 alerts in them.

**Path-policy rebind (g4wm).** `loss-plan-sepoct-pathpolicy.json` → `self-816bbef3-sepoct-pathpolicy.json`: 816bbef3 against itself on 1e7a58f7 with `--scanner-path-policy true`, using the same engine (d6a68a84), profile (8ec08b71) and engine args as the full replay. The adjudication file is unchanged. With the policy, the 3,005,868-byte `.yarn/releases/yarn-4.14.1.cjs` is an `engine_target_ignore` exclusion on both arms, so the candidate g4wm row is a complete miss. The existing gate then records it as `lost_fp_only`, and `raw_lost_baseline_hits` keeps the strict loss.
- `recall-evaluation-8cd65488-pathpolicy.json`: ACCEPT for candidate 8cd65488 with the policy on both arms. 53 gains, retention 36/37 with p849 FP-only, all 18 controls complete at −4.
- `recall-evaluation-8cd65488-pathpolicy-run1.json`: first attempt, REJECT on four load-induced parse/timeout gaps, kept for the record.
- `control-plan-8cd65488.json`: the 1c60974c plan with only the candidate hash re-pinned.
- Summary: `../recall-g4wm-pathpolicy-rebind-8cd65488.json`.
- `recall-evaluation-b2a2800f-pathpolicy.json`: the same replay for the frozen candidate b2a2800f with `control-plan-b2a2800f.json`. ACCEPT: 54 gains, retention 36/37 with p849 FP-only, controls −4, g4wm and 3753 FP-only. `…-run1.json` is a REJECT on one load-induced trix.js parse partial in a miss-only case, kept for the record.
