# Code Factory 0.21.0

Code Factory can now resume itself.

`factory continue [feature]` discovers the current feature state, runs the next
safe local stages, and stops at a clear human boundary instead of returning a
large report that the user must interpret. The same engine is available in the
new Factory Studio Assembly tab and in the VS Code and JetBrains integrations.

This release also makes measurement publishable without overstating results.
Each continuation creates an atomic run receipt. `factory metrics` exports only
privacy-safe aggregates, preserves unobserved token and cost fields as unknown,
and refuses to manufacture productivity savings without a measured baseline.

Highlights:

- state-aware continuation with distinct completed, waiting, and halted states;
- exact SSAT contract resolution and feature-selection safeguards;
- compact human output plus stable JSON;
- Studio, VS Code, and JetBrains entry points;
- atomic run receipts and privacy-safe public metric exports;
- synchronized Python package, hosted Space, editor bundles, citation, and
  archive metadata.
