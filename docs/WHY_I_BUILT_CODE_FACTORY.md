# I built Code Factory because too many tests passed—and the product still failed

I did not build Code Factory because I thought the world needed one more AI
coding tool.

I built it because I kept falling into the same trap. A coding assistant would
write the code, write the tests, and leave me with a nice clean wall of green
checks. I would think I had made real progress. Then I would actually use the
feature, or let somebody else try it, and the thing I cared about would fail.

The tests had passed. The thing had still failed.

That got old fast.

The annoying part was not just fixing the bug. I had already mentally moved on.
I had trusted the green check, started the next thing, and then had to backtrack
through the code and tests to figure out what they had really checked. It wasted
time, killed momentum, and made every “looks good” result feel less useful.

Eventually I stopped asking whether the test suite was green. I started asking:
could this test have caught the actual thing that broke?

## What was going wrong

Usually, nothing was dramatically broken in the test framework. The test just
was not proving what I thought it was proving.

Sometimes a test checked that a function returned *something*, not that it
returned the right thing. Sometimes a mock made an integration look healthy
while the real path was never exercised. Sometimes the asserted condition was
so broad that an obviously broken implementation could still satisfy it.

AI makes this easier to miss because it can produce the code, the tests, and a
very confident explanation all at once. It looks finished. The output is neat.
The test run is green. That is exactly when it is easy to stop looking.

I was not trying to make an assistant sound smarter. I wanted a way to keep
myself from confusing a lot of activity with actual proof.

## So I started building Code Factory for myself

The first part is intentionally simple: take a plain-English outcome and turn
it into a local, app-shaped starting point that I can inspect and build on.

The first command is intentionally simple:

```powershell
factory mvp "Build an approval tracker" --root .
```

It is useful, but it is not automatically “done” just because a scaffold
exists.

The other part is the bit I wanted most. Code Factory keeps asking:

- What requirement is this change trying to satisfy?
- Which declared checks support that claim?
- What evidence is missing or stale?
- What should be verified next?

![Code Factory operational proof loop: start with the work, scope the proof, find gaps, bind evidence, and give the reviewer one next action](assets/operational-proof-loop-1600x900.png)

The diagram is intentionally a workflow, not a dashboard full of invented
success metrics. Code Factory can create and inspect local artifacts, but the
human reviewer remains responsible for the release decision.

Graph Ops makes that evidence path visible. Proof Review gives me a concrete
handoff for a diff. The Verifier Plane keeps a worker's claim separate from the
evidence used to check it.

And there is one idea I care about a lot: if a control is supposed to protect a
change, try breaking the control. Delete it. Invert it. Corrupt it. If the
evaluator still passes, the control was not doing enough work to deserve my
trust.

If it does not, I would rather know before I rely on the result.

## What it is not

Code Factory does not run around on its own, decide it is finished, and publish
things. It does not look for credentials, upload source, deploy a service, or
approve its own work. It does not tell you that a generated MVP is ready for
production just because it has files and a passing test run.

That is deliberate.

I still want the human decision in the loop. I just want that decision to have a
better paper trail: what changed, what was checked, what was challenged, and
what is still an assumption.

It is local-first because I wanted to use it on my own work without handing over
a working tree. If it is useful, the same receipt and proof model can grow with
a team. If it is not useful, it should be easy to ignore.

## Why I am sharing it for free

Honestly, I built this to save myself time and aggravation. I was tired of
getting a reassuring test result and then discovering later that it had not
covered the part that mattered.

I do not think I am the only person dealing with that now that assistants can
produce so much code so quickly. So Code Factory is free and open source under
MIT or Apache-2.0. Use all of it, use one piece, read the receipts, or tell me I
am adding too much ceremony.

I would genuinely like blunt feedback from people who maintain real codebases or
review AI-assisted changes:

- Where would this save you time?
- Where would it be overkill?
- What would you need a test to prove before you trusted it?

If you have been burned by a passing test that did not mean what it seemed to
mean, I made this for that feeling.

Start with the source and a local command:

```powershell
pip install factoryline-code-factory==0.45.1
factory mvp "Build an approval tracker" --root .
factory studio --root .\my-mvp
```

Source: <https://github.com/zrk222/code-factory>
