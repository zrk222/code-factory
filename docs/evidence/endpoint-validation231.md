# Endpoint validation decomposition231

Two existing validation functions now use four named validation phases in their
existing source owner. Independent ECC inlined the final helpers and checked
local-variable capture, operand order, short-circuiting and exception boundaries.
An initial private omitted-digest draft was rejected before production edits.

| Native complexity finding | Before | After |
|---|---:|---:|
| endpoint_binding | 22 | 5 |
| reviewed_excerpt_fact | 21 | 9 |

All four helper implementations are included in native cache identity. In an
isolated scanner process, mutating each helper invalidated its native key;
restoring each helper restored that key. Target source was not executed.

The unchanged native quality audit reports **92→90 findings, no additions**;
global quality remains **FAIL, grade C**. Architecture is **HEALTHY,429 files /
133 core modules**, with unchanged caps. Ruff lint/format pass. Net source change
is48 lines; no module, authority predicate or test expectation added.

Passing unit suites were not rerun. Prior nine-job CI success applies to exact
`f03ef2c1` source; final changed bytes still require CI qualification. Fresh
Study225 precision remains **0/49 decided,8 unclear**. This refactor establishes
no detector precision improvement, merge qualification or release approval.
