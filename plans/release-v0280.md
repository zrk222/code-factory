# Plan: release-v0280
Spec: specs/release-v0280.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Update versioned release notes and all checked-in public summaries.
2. Run package, editor, metadata, and full regression gates.
3. Commit, push, tag, and create the GitHub release.
4. Dispatch protected marketplace workflows and observe each public result.
5. Query authoritative download counters and publish a channel report.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=metadata | files=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | bump core/editor versions and add 0.28 release notes
- [ ] T2 | slice=surfaces | files=4 | verify=`python -m pytest -q tests/test_huggingface_surface.py tests/test_publication_metadata.py` | update README, Hugging Face, Open VSX, and release-channel summaries
- [ ] T3 | slice=build | files=4 | verify=`python -m pytest -q && python -m build && python -m twine check dist/*` | run full regression, build artifacts, and clean wheel smoke
- [ ] T4 | slice=release | files=4 | verify=`gh release view v0.28.0 --repo zrk222/code-factory` | push immutable commit, create tag/release, and verify GitHub/PyPI workflow receipts
- [ ] T5 | slice=channels | files=4 | verify=`python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --json` | dispatch protected JetBrains/Open VSX/Hugging Face lanes and report only observed public states
