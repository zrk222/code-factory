# FactoryLine — post-release growth plan

**Status: prepared, not executed.** This plan contains no published outreach,
Marketplace edit, review, rating, download result, or causal-growth claim.
It is designed to grow legitimate installs and honest reviews without
fabrication, scraping, incentives, or spam.

Any future invitation must invite an **honest Marketplace review**, never a
requested rating, prefilled text, reward, or exchange for access.

## 1. Make the first minute useful

- Keep the Marketplace preview and first paragraph focused on one observable
  benefit: check local IDE observations and an AI or teammate diff before
  guessing or changing settings.
- Keep **Tools | FactoryLine | Run First Proof** as the zero-configuration
  starting action, then show Guardian Core as the first tool-window tab.
- Use only current IDE-native screenshots that show the actual Guardian,
  Proof Review, Graph Ops, and confirmation boundary. Retire stale concept art
  rather than implying an unshipped UI.
- Link the [reviewer summary](JETBRAINS_REVIEWER_SUMMARY.md) and this project’s
  public source so a skeptical developer can inspect boundaries before install.

## 2. Earn, do not solicit, feedback

An appropriate in-product invitation may be shown only after a user has
intentionally completed a successful, local proof-oriented action and has had
an opportunity to inspect its result. It must be:

- optional, dismissible, and at most once per plugin version;
- phrased as “If FactoryLine helped, you may leave an honest Marketplace
  review,” with no requested rating or sentiment;
- free of rewards, discounts, access changes, prefilled text, tracking, or
  repeated prompts;
- opened only after the user chooses it; no browser launch or data transfer
  occurs by default.

**Current implementation state:** 0.8.15 has no post-success browser prompt
and no Marketplace-review prompt. A Marketplace-review invitation has **not**
been shipped; it requires separate policy review, UX copy, and a tested
implementation before activation.

## 3. Measure only what the product or Marketplace exposes

| Signal | Source | Meaning | Boundary |
| --- | --- | --- | --- |
| Approved/listed version and public download total | `scripts/jetbrains_marketplace_status.py` | Public listing state and absolute install/download count. | Downloads are not unique people, satisfaction, conversion, or causal lift. |
| Delta from the recorded public baseline | `scripts/jetbrains_marketplace_measurement.py` | Observed download change. | Do not attribute change to a screenshot, release note, post, or prompt without a controlled measurement. |
| Rating count/average and review themes | Marketplace vendor analytics or public listing, when available | Voluntary public feedback. | Never manufacture, selectively suppress, or infer sentiment from installs. |
| First-proof / Guardian activation | Not collected by default | Privacy-preserving product boundary. | There is no central activation funnel while the plugin remains local-first and telemetry-free. |
| Support/issue resolution | Public issue tracker or user-initiated support channel | Qualitative friction signal. | Do not scrape IDE users or turn local workspace data into analytics. |

Record these at approval, day 7, and day 30. If a signal is unavailable, keep
it unavailable; do not substitute GitHub traffic or CI runs.

## 4. Trust compounds adoption

- Publish a release note that distinguishes **candidate**, **uploaded**,
  **approved**, and **publicly listed** states.
- Respond to real support issues with a reproducible local command, a scope
  boundary, and a release receipt—not a promise of automatic repair.
- Keep Marketplace copy factual: Guardian observes a bounded local window; it
  does not diagnose root cause, improve performance, or fix the IDE.
- Use the [0.8.15 compliance checklist](JETBRAINS_MARKETPLACE_COMPLIANCE_0_8_15.md)
  before each update so adoption work never becomes a way to bypass review.

## Non-goals

This plan does not authorize paid campaigns, compensation for reviews,
incentives tied to ratings, bulk messaging, private outreach, user scraping,
telemetry collection, unverifiable performance claims, or fabricated download
or review evidence.
