# Plan: github-star-growth-v1

Spec: `specs/github-star-growth-v1.md`

Architect verdict: PASS

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=editors/vscode | files=editors/vscode/src/extension.ts,editors/vscode/src/star_prompt.ts,editors/vscode/src/test/receipt.test.ts | verify=`npm test` | Add a version-scoped post-success star prompt.
- [ ] T2 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/README.md | verify=`npm test` | Add an outcome-first VS Code and Open VSX CTA.
- [ ] T3 | slice=editors/intellij | files=editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt,editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineGitHubStarPrompt.kt,editors/intellij/src/main/resources/META-INF/plugin.xml,editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt | verify=`gradlew.bat test` | Add a version-scoped notification and listing CTA.
- [ ] T4 | slice=editors/intellij | files=editors/intellij/README.md | verify=`gradlew.bat test` | Document the JetBrains first-run and star-action boundary.
- [ ] T5 | slice=factoryline | files=factoryline/output_map.py | verify=`python -m pytest -q tests/test_target_compiler.py` | Add a static opt-in share snippet to output maps without project mutation or transmission.
- [ ] T6 | slice=tests | files=tests/test_target_compiler.py,tests/test_publication_metadata.py,tests/test_huggingface_surface.py | verify=`python -m pytest -q tests/test_target_compiler.py tests/test_publication_metadata.py tests/test_huggingface_surface.py` | Pin all new source-copy, image, and privacy boundaries.
- [ ] T7 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Put the value message, first run, demo, and optional GitHub CTA before deep reference material.
- [ ] T8 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m pytest -q tests/test_publication_metadata.py` | Make PyPI metadata match the outcome-first promise.
- [ ] T9 | slice=docs | files=docs/GITHUB_DISCOVERY.md,docs/assets/github-social-preview-1280x640.png,docs/JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Prepare the social asset, manual upload handoff, ethical sharing loop, and community launch drafts.
- [ ] T10 | slice=deploy/huggingface | files=deploy/huggingface/README.md,deploy/huggingface/index.html | verify=`python -m pytest -q tests/test_huggingface_surface.py` | Apply the same proof-aware CTA to the Hugging Face public surface.
- [ ] T11 | slice=smoke | files=smoke/github-star-growth-v1.json | verify=`forge verify-tests github-star-growth-v1 specs/github-star-growth-v1.forge.yaml --root .` | Declare non-hollow runtime checks for the ForgeLine-supported scope.

## Release boundary

Source and tests may be committed to the existing draft PR. GitHub topics are a
separate repository-metadata change, verified after source validation. Uploading
a social preview and submitting Hacker News or Indie Hackers posts are
owner-visible, account-side actions; this change only supplies reviewed source
assets and drafts.

## Architecture enforcement scope

`specs/github-star-growth-v1.forge.yaml` is ForgeLine's executable TypeScript
scope. ForgeLine 0.4.0 does not scaffold Kotlin modules or Python keyword-only
signatures; JetBrains Gradle and Python tests are the authoritative enforcement
gates for those two modules. The broader `github-star-growth-v1.ssat.yaml`
remains the review contract for all three languages.
