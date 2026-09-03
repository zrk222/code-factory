# Three complementary checks, not one green test

Your tests pass. That leaves two other questions unanswered:

1. **Test sensitivity:** Would the check notice a broken implementation? CF's existing hollow-test and mutation checks challenge that.
2. **Pattern consistency:** Does this implementation omit a guard or reliability call required for its peers? The new pattern audit shows the difference and peer evidence.
3. **Guard-path ordering:** Is the guard on every analyzed branch before a sensitive operation? The new guard-path audit produces a branch witness when call presence alone hides a bypass.

These checks complement code review. None proves the application correct.

## A bug a call search would miss

```python
def safe():
    require_auth()
    store.delete()

def candidate():
    if permitted:
        require_auth()
    store.delete()
```

Both functions contain `require_auth` and `store.delete`. The pattern audit finds no missing call. The guard-path audit points to the false branch: the delete operation has no preceding guard statement on that structural path. A reviewer decides whether that branch is feasible and whether the declared guard enforces the intended rule.

If `candidate` omits `require_auth` entirely, the pattern audit also shows which peer contains it. If all peers omit it, the required-call finding remains; majority agreement never becomes correctness.

## Set up a reviewed policy

Save the Python example above as `app.py`, then save this policy as `.factory/review-audits.json`. For real use, choose sensitive operations, peer functions and required guards with a human reviewer. Start with one security-critical flow rather than a long generated checklist.

```json
{
  "schema": "factory.review-audit-policy.v1",
  "pattern_groups": [
    {
      "id": "peer-guards",
      "origin": "agent_proposed",
      "members": [
        {"path": "app.py", "symbol": "safe"},
        {"path": "app.py", "symbol": "candidate"}
      ],
      "required_calls": ["require_auth", "store.delete"]
    }
  ],
  "effect_rules": [
    {
      "id": "delete-guard",
      "origin": "agent_proposed",
      "target": {"path": "app.py", "symbol": "candidate"},
      "guard_call": "require_auth",
      "effect_call": "store.delete"
    }
  ]
}
```

`origin` records a declaration, not an authenticated signature. Changing it to `human_confirmed` does not grant authority. To use findings in a release gate, bind the reviewed policy digest through your existing approved intent/Oracle Firewall process. These tools cannot approve or release anything.

## Run the audits

```sh
factory audit patterns --json
factory audit guard-paths --json
factory audit all --json
factory change review --changed app.py --out-dir .factory/reviews --json
```

Individual audit commands return exit 0 only for `no_structural_findings` within their declared scope. Findings, incomplete analysis and invalid inputs return exit 2. An `all` audit requires rules for both tools. Missing configuration is never a passed audit.

`factory change review` automatically loads the default policy when it exists. `--audit-policy path/to/policy.json` selects another workspace-contained file. Existing stale-proof, coverage and unmatched-path findings keep their priority. Added findings, hashes, gaps and branch witnesses travel in the review JSON, with summaries in Markdown and finding nodes in Mermaid. IDE and agent integrations calling the shared change-review API receive the same lane without separate analysis logic.

## Receipt boundaries

- SHA-256 binds the policy and inspected source. Changing either changes the audit digest. Source changes during analysis reject the result.
- Code is parsed, never imported or executed; no models, network calls or credentials are needed. The implementation uses CF's cross-platform Python runtime; this change was tested locally on Windows.
- Scope: declared Python functions and qualified class methods, up to 128 rules, 64 files, 1 MB per file and 10,000 AST nodes per file. No whole-repository coverage claim.
- Guard-path analysis supports sequential statements, branches, early returns/raises and direct awaited guard statements. Exploration is bounded to 64 live paths, 32 nesting levels and 4,096 statement-path steps.
- Loops, exception handlers, context managers, decorators, identity rebinding, short-circuit expressions and other unsupported semantics remain `incomplete`. An absent expected effect is incomplete, not a pass.
- A guard counts only as an unconditional standalone call statement on a path. Its declared semantics must be “raise on denial.” This assumption needs review; a function name does not prove authorization.
- Aliases, helper-function behavior, dynamic dispatch, concurrency and runtime branch feasibility are not proven. Use runtime tests, independent validators and human review for those boundaries.
- Receipts are content-addressed, not signed approvals. `no_structural_findings` means only that these checks found no issue in the declared, supported scope.

For solo developers: catch an omitted check and see where it belongs. For teams: make the convention and unsafe branch inspectable. For enterprise reviewers: retain exact policy/source bindings and explicit coverage gaps rather than another unexplained green badge.
