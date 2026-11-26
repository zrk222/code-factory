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
