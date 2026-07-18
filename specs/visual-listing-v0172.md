# Spec: visual-listing-v0172
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Publish a truthful, accessible visual walkthrough of Code Factory across the
GitHub README, the PyPI long description, the next Zenodo software archive, and
the prepared Product Hunt gallery. The walkthrough is for developers and
technical evaluators who need to understand the proof-first workflow before
installing the package.

### User roles

- Project maintainer preparing a public release.
- Developer evaluating Code Factory from GitHub or PyPI.
- Product Hunt visitor scanning the product gallery.
- Research-software evaluator opening the Zenodo archive.

### Requirements (EARS)

- The system shall store exactly nine unique owner-supplied PNG concept illustrations under `docs/assets/how-it-works/`, each with a stable semantic filename, SHA-256 provenance, dimensions of 1122 by 1402 pixels, and descriptive alt text; when any digest or dimension differs, the system shall reject the release with `ASSET_DRIFT`. [REQ-VIS-ASSETS]
- The system shall emit `VISUAL_STORY_ORDERED` only when the nine illustrations are ordered as idea intake, product shaping, deterministic compilation, security contracts, governed access, proof by sabotage, failure feedback, signed proof chain, and verified release. [REQ-VIS-STORY]
- The system shall emit the exact label "Concept illustrations" once immediately before the README preview and once in each gallery document, shall emit "Exact shipped UI" once for the existing quick-start video, and shall reject a missing label with `CONCEPT_BOUNDARY_MISSING`. [REQ-VIS-BOUNDARY]
- The system shall reject public visual surfaces containing the unsupported strings `2.6 hrs`, `$14.37`, or `82%`, or the incorrect project URL `github.com/code-factory`. [REQ-VIS-CLAIMS]
- The system shall emit `GITHUB_VISUAL_PREVIEW` only when three representative illustrations appear in the GitHub README above the long-form documentation and link to the complete visual walkthrough. [REQ-VIS-GITHUB]
- The system shall use absolute HTTPS URLs for README images used by the PyPI long description, shall reject a relative URL with `RELATIVE_PYPI_IMAGE`, and shall pass `twine check` in the built wheel and source distribution. [REQ-VIS-PYPI]
- The system shall store the label "conceptual visual walkthrough" in `.zenodo.json`, bind version `0.17.2`, and store the gallery document, SHA-256 manifest, and all nine illustrations in the source distribution. [REQ-VIS-ZENODO]
- The system shall emit `PRODUCT_HUNT_GALLERY_READY` only when the Product Hunt instructions specify at least two images, preserve the exact nine-image order, record the official 1270 by 760 recommendation, and state that video entries require a full YouTube URL. [REQ-VIS-PH]
- The system shall attach all nine illustrations to the GitHub `v0.17.2` release without using stored PyPI credentials; when any repository, package, or pull-request release gate fails, the system shall return `RELEASE_GATE_FAILED` and shall not tag the release. [REQ-VIS-RELEASE]
- The system shall emit `VERSION_METADATA_SYNCED` only when `pyproject.toml`, `factoryline.__version__`, `CITATION.cff`, the changelog, and publication tests are synchronized on version `0.17.2` and release date `2026-07-18`. [REQ-VIS-VERSION]
- When authenticated live listings exist, the maintainer shall update them only after the repository tests, package build, and pull-request checks pass; if no listing exists, the system shall emit `LISTING_NOT_FOUND` and store one copy-ready gallery manifest. [REQ-VIS-LIVE]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Render a truthful public visual story
  Given the nine approved owner-supplied concept illustrations
  When the publication metadata tests inspect the gallery
  Then all nine files have the expected SHA-256 digest and 1122 by 1402 dimensions
  And the files are stored under `docs/assets/how-it-works/`
  And the result emits `VISUAL_STORY_ORDERED`
  And the public copy contains "Concept illustrations" and "Exact shipped UI"
  And a missing label returns `CONCEPT_BOUNDARY_MISSING`
  And the README exposes three absolute HTTPS image URLs
  And the result emits `GITHUB_VISUAL_PREVIEW`
  And a relative PyPI image returns `RELATIVE_PYPI_IMAGE`
  And unsupported metrics and the incorrect repository URL are absent
  And the unsupported strings include `2.6 hrs`, `$14.37`, and `82%`
  And asset drift returns `ASSET_DRIFT`

Scenario: Build a PyPI and Zenodo-ready release
  Given version 0.17.2 metadata and the complete visual walkthrough
  When the wheel and source distribution are built and checked
  Then twine reports both artifacts valid
  And the source distribution contains the gallery document, SHA-256 manifest, and nine illustrations
  And `.zenodo.json` contains "conceptual visual walkthrough"
  And the result emits `VERSION_METADATA_SYNCED`
  And the GitHub release tag is `v0.17.2`
  And a failed release gate returns `RELEASE_GATE_FAILED`

Scenario: Prepare the Product Hunt gallery without inventing a launch
  Given the official Product Hunt media requirements
  When the gallery manifest is reviewed
  Then it lists all nine concept illustrations in deterministic order
  And it emits `PRODUCT_HUNT_GALLERY_READY`
  And it records the 1270 by 760 recommendation
  And it requires a full YouTube URL for a video
  And a missing authenticated listing returns `LISTING_NOT_FOUND`
  And it does not claim that a new Product Hunt post was published
```

## SHOULD - Technical and structural

- ADR references: `adr/0011-composable-capability-pack-catalog.md` for public capability boundaries.
- Data model: `docs/assets/how-it-works/manifest.json` is the canonical ordered asset manifest.
- Interface: README and Markdown documents use portable Markdown/HTML accepted by GitHub and the PyPI renderer.

## SHOULD NOT - Implementation details

- Do not regenerate or alter the owner-supplied concept artwork.
- Do not publish the supplied infographic that contains unsupported outcome metrics.
- Do not replace the exact Factory Studio quick-start video with concept art.
- Do not create or schedule a new Product Hunt launch without an existing authenticated listing or draft.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `ASSET_DRIFT` | reject the release |
| 2 | `CONCEPT_BOUNDARY_MISSING` | reject the release |
| 3 | `RELATIVE_PYPI_IMAGE` | fail the publication test |
| 4 | `LISTING_NOT_FOUND` | store one copy-ready gallery manifest |
| 5 | `RELEASE_GATE_FAILED` | block version 0.17.2 release |

## Claim and evidence boundary

- The artwork is illustrative and carries no measured product outcome claim.
- Existing product behavior remains supported by tests and receipts, not by the images.
- Product Hunt's current gallery guidance is sourced from
  `https://www.producthunt.com/launch/preparing-for-launch`.
- Zenodo's GitHub metadata behavior is sourced from
  `https://help.zenodo.org/docs/github/describe-software/`.
