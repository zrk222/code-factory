# Contributing

Code Factory accepts focused fixes, counterfactual challenges, workflow specs,
and integrations that preserve the proof contract.

## Local verification

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m build
python -m twine check dist/*
```

For cross-brick changes, also run `python scripts/prooflab_e2e.py` with the four
numbered packages installed from their matching source train.

## Doctrines

- Do not hand-copy metrics into public claims. Generate them from tests,
  receipts, CI, goldens, or a Factory Passport.
- Do not tune on public-claim fixture sets.
- Add a sabotage case whenever a new gate is added; a gate must prove it can
  reject a broken input before it certifies the real one.
- Preserve human authority for merge, publication, deployment, secrets, and
  production changes.

Open an issue before changing the receipt protocol or canonical stage order.

## Maintainer handoff

1. In a clean clone at the candidate commit, install the [public toolchain](https://github.com/zrk222/code-factory/releases/tag/v0.49.7#install-the-complete-factory),
   install the candidate with `python -m pip install .`, and run `factory doctor --strict --json` and
   `python -I scripts/prooflab_e2e.py`. No publisher credentials are needed.
2. Read the current required checks with `gh pr checks <number> --required`.
   Record the candidate SHA, commands, failed or skipped checks, and disposition
   in the PR. Review AI findings separately from human signoff.
3. Rehearse the review with a second maintainer using their own account.
   That maintainer verifies the candidate and [release gates](docs/RELEASE_CHANNELS.md)
   independently. Grant only the repository or publishing access their role
   needs, and use provider-managed credentials or trusted publishing. Do not
   share the owner's login, tokens, or local workspace.

Entries in `context/PROGRESS.md` record pipeline activity. `GATE`, `PROOF`, and
`DONE` entries do not establish human authorship or independent review.

## Product boundary checks

Pull request CI checks added, modified, and renamed paths against
`.factory/repository-scope.json`. Keep unrelated products in their own
repositories; deleting an out-of-scope path is allowed so accidental additions
can be cleaned up. The protected `repository-scope-guard` workflow reads the
policy and checker from the base commit, fetches the pull request head as Git
objects, and never executes candidate files. Require its status check in main
branch protection. Run the local report with
`factory change scope-check --root . --base origin/main`.

## Generated audit evidence

Keep run JSON, terminal logs, local evaluation receipts and screenshots out of
Git source history. `.factory/` is ignored except for the repository scope policy,
scope decision records and tenant read contract. The trusted repository-scope CI
guard rejects any other tracked `.factory/` path, including force-added files.
Publish reproducible run evidence through CI artifact uploads or release assets;
include the source commit, exact command, environment and SHA-256 in the asset
manifest. Existing historical receipts remain available in their original Git
commits; removing them from the current tree does not change their claims.
Golden regression fixtures belong in `evals/` or `tests/`; they are source inputs,
not generated run output. Never include credentials or private evaluation cases
in public assets.
