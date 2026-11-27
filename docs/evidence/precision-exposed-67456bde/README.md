# Exposed precision review, candidate 67456bde

- **Packet:** `packet.json`, sha 354929bd. 208 blinded candidate alerts with no prior verdict, seed 20261126, cap 40 per rule.
  - Context supplement: `context.json`, 70a93a92.
  - Answer key: `key.json`, published after adjudication.
- **Reviewers:**
  - Arm 1: four fresh Claude Opus 5.5 agents at high effort. Labels in `labels-claude-exposed-67456bde.json`.
  - Arm 2: four fresh Claude Sonnet 5.5 agents at high effort. Labels in `labels-sonnet-exposed-67456bde.json`. This arm stands in for the Codex arm, which was not yet available. Codex labels can be added later as a separate arm.
  - The arms agreed on 169/208 items.
- **Judge:** Fable 5.2 at high effort judged the 39 disagreements, seeing only `judge-packet.json` (308b511a). Verdicts in `judge-fable.json`.
- **Final:** `precision-adjudicated-exposed-67456bde.json`, digest 861e8a5a: 93 TP / 111 FP / 4 UNCLEAR.
- **Context v2 test** (`context-v2-test/`):
  - 24 of the 39 disagreements cited code that wasn't shown: callers, or helper definitions.
  - The v2 supplement adds the enclosing function, definitions of helpers called near the marked line, and non-test call sites, from the repository at the old-side commit.
  - On the same 39 items, fresh Opus and Sonnet arms with v2 context agreed on 20 (0 before), and UNCLEARs mostly disappeared.
