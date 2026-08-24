# Spec: visual-listing-v0172
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Publish a truthful, accessible current-product visual set for Code Factory
across the GitHub README, Hugging Face Space, release attachment workflow, and
the prepared Product Hunt gallery. Developers and technical evaluators must see
real product surfaces, not an illustration, recreated dashboard, or a retired
recording.

### Requirements (EARS)

- The system shall store exactly one current FactoryLine identity PNG at
  `docs/assets/factoryline-logo-480.png` with dimensions 480 by 480, and exact
  Factory Studio PNG captures at `docs/assets/marketplace/factory-studio-mvp-1280x800.png`
  and `docs/assets/marketplace/graph-ops-studio-1280x800.png`, each with
  dimensions 1280 by 800. [REQ-VIS-CURRENT-ASSETS]
- The system shall publish `docs/PRODUCT_VISUALS.md` as the canonical visual
  policy; it shall describe the capture purpose, placement, and evidence
  boundary for each current asset. [REQ-VIS-POLICY]
- The system shall reject a public visual surface containing
  `code-factory-quickstart-v0171.mp4`, `code-factory-quickstart-cover-v0171.png`,
  `factory-studio-control-room-1080.png`, `factory-studio-control-room.png`,
  `how-it-works/`, or `HOW_IT_WORKS_VISUAL.md` with
  `RETIRED_VISUAL_REFERENCE`. [REQ-VIS-RETIREMENT]
- The system shall reject public visual surfaces containing the unsupported
  strings `2.6 hrs`, `$14.37`, or `82%`, or the incorrect project URL
  `github.com/code-factory`. [REQ-VIS-CLAIMS]
- The system shall store Product Hunt gallery instructions. The Product Hunt
  gallery instructions shall order the FactoryLine logo, outcome-first MVP
  capture, and Graph Ops capture. The Product Hunt gallery instructions shall
  state that at least two images are required and FactoryLine captures retain
  native proof and authority text. [REQ-VIS-PH]
- The system shall attach only the current product visual set to future GitHub
  releases without adding stored PyPI credentials; failed release gates shall
  still block a tag. [REQ-VIS-RELEASE]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Render current product media
  Given the canonical FactoryLine logo and two exact Studio captures
  When publication metadata tests inspect the public visual set
  Then the logo is 480 by 480 and each product capture is 1280 by 800
  And the visual policy describes the capture boundary
  And the README and Hugging Face Space use the current visual set
  And a retired visual reference fails the publication test

Scenario: Prepare the existing Product Hunt gallery without inventing a launch
  Given the current product media and official Product Hunt guidance
  When the gallery guide is reviewed
  Then it lists the logo, MVP capture, and Graph Ops capture in order
  And it records the at-least-two-images and 1270 by 760 guidance
  And it does not claim that a new Product Hunt post was published
```

## SHOULD - Technical and structural

- Data model: `docs/PRODUCT_VISUALS.md` is the canonical placement and
  evidence-boundary document.
- Interface: README and Markdown documents use portable Markdown/HTML accepted
  by GitHub and the PyPI renderer.
- JetBrains Marketplace uses its own native IDE capture policy and must not use
  the Studio images as a substitute.

## SHOULD NOT - Implementation details

- Do not manufacture an empty-but-green dashboard, live metric, or simulated
  IDE screenshot.
- Do not use concept art to stand in for a current product surface.
- Do not create or schedule a new Product Hunt launch without an existing
  authenticated listing or draft.

## Claim and evidence boundary

- Images show product behavior only; they do not prove time, token, cost,
  productivity, conversion, Marketplace approval, or production readiness.
- Existing product behavior remains supported by tests and receipts, not by the
  visual assets.
- Product Hunt's current gallery guidance is sourced from
  `https://www.producthunt.com/launch/preparing-for-launch`.
