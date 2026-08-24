# CodeRabbit interoperability

CodeRabbit and Code Factory are complementary. CodeRabbit’s review surface can
analyze pull requests and, when its GitHub Checks integration is enabled, read
completed GitHub Check output. Code Factory creates a local, deterministic,
neutral `FactoryLine / Proof Review` Check request that contains changed scope,
Plan-to-Proof findings, and explicit proof debt. That lets CodeRabbit discuss
the same pull request context without Code Factory calling a CodeRabbit API or
treating CodeRabbit output as evidence.

## Recommended ordering

1. A human approves a small `factory.agent_plan.v1` envelope.
2. A coding system changes only the declared paths and tests.
3. Code Factory compiles Plan-to-Proof and Diff-to-Proof facts into the neutral
   Check/comment.
4. CodeRabbit and human reviewers read the diff and those facts in the pull
   request.
5. The team—not either tool—decides whether to merge or ask for refinement.

Code Factory deliberately does **not**:

- install, configure, or authenticate CodeRabbit;
- read CodeRabbit comments, summaries, internal reasoning, or credentials;
- call a CodeRabbit API, use an MCP connection, or claim a partnership;
- auto-approve, request changes, merge, close, label, or assign a pull request;
- convert a changed test path or agent claim into executed test evidence.

## Optional CodeRabbit configuration

CodeRabbit documents GitHub Checks as enabled by default and configurable from
its own settings or `.coderabbit.yaml`. A team that wants CodeRabbit to consume
the FactoryLine Check can keep that documented integration enabled:

```yaml
reviews:
  tools:
    github-checks:
      enabled: true
```

This is an illustrative CodeRabbit setting maintained by CodeRabbit, not a file
that Code Factory writes. Keep any new CodeRabbit custom checks in warning mode
until the team has reviewed real pull requests and decided its branch-protection
policy.

For Code Factory’s supervised workflow and permissions, see
[GitHub Proof Review](GITHUB_PROOF_REVIEW.md). For the strict plan contract,
read [Plan-to-Proof Review](PLAN_TO_PROOF_REVIEW.md).
