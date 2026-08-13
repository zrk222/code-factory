# The approval signal decays when AI-written code becomes routine

AI-assisted code review has an uncomfortable failure mode: a team can keep
approving changes while doing less of the work that makes an approval meaningful.
Nothing necessarily looks wrong. Pull requests merge, test suites stay green, and
the reviewer may sincerely believe that they are still checking the work.

The risk is habituation, not bad intent. When a task becomes repetitive, people
learn to process it quickly. A fast review might mean expertise, a tiny safe diff,
or a reviewer who no longer has time to inspect the change. A duration alone is
not evidence of any one of those things.

That distinction matters. A tool that calls a reviewer inattentive because they
finished quickly will be wrong often enough to become another source of noise. A
tool that ignores the trend entirely leaves a useful safety signal on the table.

## Treat it as a hypothesis, not a verdict

Code Factory's local `habituation` commands record only the review facts a team
chooses to supply: reviewer pseudonym, author kind, elapsed review time, changed
lines, verdict, and later blind-spot checks. The status view compares each
reviewer's agent-authored review pattern with that same reviewer's human-authored
baseline. It does not rank people, compare teams, transmit observations, or infer
attention from a single fast approval.

The result has a deliberately limited job: surface an observable pattern and ask
for a better signal.

```powershell
factory habituation record pr-4482 `
  --reviewer reviewer-a `
  --author-kind agent `
  --review-seconds 8 `
  --changed-lines 100 `
  --approved

factory habituation status
```

If the supplied data indicates an unusual approval pattern, the gate can suggest
a second reviewer. It cannot responsibly block on that pattern alone. Before a
blocking policy is even eligible, the workflow requires a sampled re-review:

```powershell
factory habituation sample --rate 10
factory habituation resample pr-4482 --reviewer reviewer-b
```

The sample gives the team a ground-truth correction: did the original approval
miss something material, or was the quick review justified? Until that check
exists, the signal stays a hypothesis. It cannot become a hard claim merely
because a dashboard makes it look precise.

## The verifier cannot be the author

This is the same design rule we use for generated code. A worker should not be
the only system deciding whether its work is acceptable; a reviewer should not
be reduced to a click that quietly validates the worker's own story. The useful
question is not "did the model say its code is good?" It is "what independent,
reviewable evidence supports the next decision?"

For Code Factory, the answer is intentionally modest:

- local, explicit observations rather than surveillance;
- a bounded suggestion before any escalation;
- sampled human re-review before a policy can block;
- receipts that make the basis of a decision inspectable; and
- no automatic merge, release, message, credential, or publishing authority.

The mechanism will not prove that someone read code. It can help a team notice
when its approval process has stopped producing enough evidence to deserve the
trust placed in it. The right response is then more evidence and a second set of
eyes—not a louder AI verdict.

## Try it, challenge it, improve it

The feature is local-first and deliberately conservative. Read the
[habituation release notes](RELEASE_NOTES_0.26.0.md), inspect the
[proof and policy boundary](VERIFY_POLICY.md), or run it against a small,
non-sensitive review sample. If its assumptions are wrong for your team, that is
the useful feedback: the goal is a falsifiable safety control, not a story about
perfect AI governance.
