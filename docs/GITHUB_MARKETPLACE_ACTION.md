# GitHub Marketplace action

The repository root now exposes a composite action in `action.yml`:

```yaml
- uses: zrk222/code-factory@main
  with:
    feature: my-feature
```

Pin `uses` to an immutable release tag once the marketplace-ready branch has
been merged; the `main` example is intentionally the review-stage reference.

The action installs the published `factoryline-code-factory` package, runs
`factory verify <feature> --json`, uploads the JSON decision and its manifest,
and returns the verifier's exit code. A failed or incomplete proof therefore
fails the workflow instead of becoming a green-but-empty badge.

## Listing boundary

The repository is technically Marketplace-ready because the action metadata is
at the root and the repository is public. A Marketplace listing still requires
an owner-controlled GitHub release/tag and the Marketplace publication review
checkbox. Those are deliberately kept as an action-time human step; pushing a
tag alone is not evidence that the listing is live.

Official guidance: [Publishing actions in GitHub Marketplace](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace).

## Local contract

The action is intentionally narrow: it verifies existing Code Factory evidence
and does not mutate the caller's source tree. Use the `factory-proof` artifact
to inspect the exact decision when a gate fails.
