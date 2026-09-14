# Full-Stack UX Harness contract

The checked-in [`full-stack-ux-harness-v1.ssat.yaml`](../full-stack-ux-harness-v1.ssat.yaml)
is the source contract for the full-stack UX workflow. Code Factory validates it
with `python -m factoryline.cli quality-harness spec-validate` before any downstream mobile
evidence is considered.

```text
python -m factoryline.cli quality-harness spec-validate full-stack-ux-harness-v1.ssat.yaml \
  --out .factory/quality-harness/full-stack-ux-harness.spec-receipt.json --json
python -m factoryline.cli quality-harness spec-verify \
  .factory/quality-harness/full-stack-ux-harness.spec-receipt.json --json
```

The parser is deliberately native to the Python package. It accepts the
repository's established SSAT envelope and the explicit
`code-factory.io/v1alpha1 / FullStackUXHarness` envelope from the integration
blueprint. Both normalize to the same six mobile evidence categories:

## First Lap is the AppForge entry boundary

Before AppForge accepts a mobile candidate for evidence normalization, the
operator can run `factory first-lap status --root .` (or call the equivalent
read-only `factory.first_lap_status` MCP/WebMCP tool). This adds the controls
introduced by the senior-engineering upgrade without turning AppForge into a
second authority plane:

- the mission and forbidden outcomes are explicit before a storyboard or
  device capture is reviewed;
- observable iPhone/iPad journeys are named before visual, privacy, or release
  evidence is considered;
- verifier-only negative cases remain hash-bound and contamination is a
  blocker, so a builder cannot quietly redefine what “ready” means; and
- calibration, human-observed sequencing, typed retry policy, and incident
  promotion are visible as prerequisites rather than hidden assumptions.

AppForge then binds its candidate, user design input, storyboard, six mobile
evidence categories, and final dossier to the same source-to-obligation chain.
The CLI, local MCP, WebMCP, and AppForge Mission Control all expose bounded
facts; none executes a device, opens a holdout, changes a gate, contacts Apple
or Google, or grants release authority.

1. visual media — snapshots, device frames, layout, contrast, accessibility,
   and store assets;
2. privacy-to-listing — permissions, privacy manifest, tracking disclosure,
   entitlements, runtime network, and listing metadata;
3. release chain — build/signing plus explicit upload, processing, tester,
   submission, and store-decision states;
4. design system — token and hierarchy conformance with the user's approved
   design input;
5. production signal — crash-free, ANR, hang, and startup observations; and
6. Android parity — Gradle/ADB, adaptive layout, accessibility, R8/permissions,
   and Play metadata.

The receipt is local, immutable, and bound to the source SHA-256. YAML duplicate
keys, unknown fields, unsafe paths, malformed hashes, unsupported categories,
and duplicate triage rules fail closed. A valid contract means only that the
requirements are structurally explicit; it is not a device test, accessibility
certification, signing proof, TestFlight result, store submission, or store
approval. `factory revenue appforge-mobile-evidence` remains the separate
source-bound evidence normalizer, and no command in this workflow accesses
credentials or writes to a provider.

## CI behavior

`.github/workflows/validate-ux-harness.yml` installs the package, validates the
checked-in contract, replays the receipt against the current source, and runs
the focused regression tests. It has `contents: read` only and does not post
GitHub checks, upload media, execute mobile toolchains, or approve releases.
