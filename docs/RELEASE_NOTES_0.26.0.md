# Code Factory 0.26.0

## The short version

Code Factory checks a lot of things before it lets code through. Until now it
never checked the most important one: whether the person approving the work is
still really looking at it.

People get used to approving machine-written code. The same reviewer, over the
same few months, starts approving more of it and commenting on it less. Nothing
looks wrong — the approvals keep arriving and the receipts keep saying approved.
That is what makes it dangerous.

0.26 measures that.

## What you can do now

```bash
# after someone reviews a change, record what happened
factory habituation record pr-4482 --reviewer alice@corp.com \
  --author-kind agent --review-seconds 8 --changed-lines 100 --approved

# ask how the review gate is holding up
factory habituation status
```

It compares how long someone spends on machine-written code against how long
**that same person** spends on human-written code. Not against their colleagues.
If you spend 55 seconds per 100 lines on your teammate's work and 8 seconds on
the agent's, that gap is the thing worth knowing.

Depending on the gap it will do one of three things: show you the comparison,
ask for a second reviewer, or stop the merge.

## Three promises it keeps

**It won't guess.** Fewer than five reviews on either side and it reports
nothing at all, because a number from three reviews isn't a measurement.

**It won't blame anyone.** There's no per-person leaderboard, and none is
exported. Getting used to something is a normal human response to repetition,
not a character flaw, and a tool that treats it as one deserves to be uninstalled.

**It won't stop your merge on a hunch.** Time spent reading is a rough stand-in
for attention — a quick expert looks exactly like a bored reviewer from the
outside. So before it's allowed to block anything, you have to spot-check some
approvals for real:

```bash
factory habituation sample --rate 10     # picks a few to look at again
factory habituation resample pr-4482 --reviewer bob@corp.com
```

Until those spot-checks exist, asking it to block gets you a refusal and an
explanation. That's deliberate.

## Also in this release

`factory update-check` tells you when a newer version is out. It only tells you.
It doesn't download anything, doesn't install anything, and doesn't send us
anything about you — it reads one public page and prints a line. Given this
product's whole argument is that nothing important should happen without your
say-so, software that quietly rewrites itself would be a strange thing for us to
ship.

## Where the numbers come from

Review time, comment counts, and approval rates are real measurements taken from
what you record.

Whether low scrutiny actually *causes* bugs to slip through is a much weaker
claim, so it's switched off by default, needs at least twenty spot-checks before
it will say anything, and always ships with the reasons you shouldn't lean on it
too hard. It will never tell you a specific person would have caught a specific
bug. Nobody can know that.

Reviewer names are stored as scrambled digests. The shareable report contains
counts and nothing else.
