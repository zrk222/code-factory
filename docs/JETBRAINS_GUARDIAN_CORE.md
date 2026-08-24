# Guardian Core for JetBrains

FactoryLine Guardian Core answers two practical questions before a developer
changes a cache, a plugin setting, or an AI-authored diff:

1. **What did the local IDE window actually observe?**
2. **What is the smallest safe thing to review next?**

Open **Tools | FactoryLine | Open Guardian Core**. It is the first tab in the
FactoryLine tool window.

## The short path

1. Start a 60-second local recording.
2. Read the observed heap, available process CPU, indexing state, and EDT
   dispatch signals alongside a small threshold-and-transition timeline.
3. Follow a navigation-only route to the relevant review surface:
   IDE Health, Index Continuity, Workspace Advisor, Proof Review, or Intent
   Ledger.

Guardian is deliberately useful before the local `factory` executable is
configured. Native health observation works on its own; proof and workspace
commands remain explicit, confirmed local actions in their own tabs.

## What Guardian can and cannot say

It can say that an observation occurred in the current bounded window:

- EDT dispatch delay reached 250 ms or more.
- Available process CPU reached 80 percent or more.
- Heap use reached 85 percent or more.
- Indexing was active, began, or became idle.

It cannot say that a particular plugin, cache, index, setting, or project file
caused the symptom. It does not predict reindex duration, create a health
score, rank plugins, alter settings, invalidate caches, disable plugins, or
apply a repair.

## Privacy and control

The recorder retains at most 20 aggregate samples in memory for the current
project session. It does not collect source content, file paths, plugin lists,
credentials, or network data. Nothing is sent anywhere. The navigation buttons
open existing tabs only; they do not execute a FactoryLine command.

When a next step needs a command, FactoryLine still shows the existing local
workspace confirmation before it runs it.
