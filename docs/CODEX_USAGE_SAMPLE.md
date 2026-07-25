# Codex usage sample

This sample reports observed Code Factory usage from eight local Codex history
files reviewed on 2026-07-24. It is descriptive evidence, not a causal
productivity study.

The sample found 19 Assembly invocations: ten real runs, seven help calls, and
two dry runs. Of the real runs, six paused, two halted, two lacked a terminal
classification, and none supplied evidence of end-to-end completion. Real runs
used 23.2 seconds of observed wall time in total with a 2.35-second median.
Help discovery used another 15.1 seconds. Paused reports averaged 14,327
characters, demonstrating interpretation burden but not proving how long a
person spent reading.

Across the broader parsed history, 1,851 shell payloads contained Factory-family
strings, 184 represented help discovery, 672 contained at least three commands,
and the largest payload chained 17 commands.

Four sessions exposed token counters totaling 3,216,785,227 tokens. Of the input
tokens, 97.28% were cached. Those counters cover complete Codex sessions and
cannot be attributed to Code Factory, so actual token savings, time savings, and
productivity gain remain unknown. The machine-readable sample preserves those
values as `null`.

Code Factory 0.22 supplies the missing measurement layer: atomic continuation
receipts and aggregate-safe exports. A future causal claim still requires a
declared paired or controlled baseline. See
[the machine-readable sample](CODEX_USAGE_SAMPLE.json) and
[Assembly continuation](ASSEMBLY_CONTINUE.md).
