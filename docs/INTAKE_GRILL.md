# Intake Grill

`factory intake` resolves the four decisions that should be explicit before a
product mission starts:

1. the first delivery framework or surface;
2. the exact user or operator intent, stated by a human rather than inferred;
3. the observable acceptance evidence; and
4. whether the work is local-only or contains externally visible effects that
   stay human-controlled.

It is a native Code Factory intake stage. It creates a source-bound decision
worksheet and then a separate named-human confirmation. It is not an agent,
does not call a model, and does not generate code.

## Recommended sequence

```powershell
# 1. Produce a local decision tree from the exact PRD bytes.
factory intake grill PRD.md --root . --json

# 2. Read the worksheet, then record the actual human decisions.
factory intake confirm .factory/intake-grills/<project>/<prd-sha>.json `
  --root . `
  --framework python-service `
  --intent "A reviewer can record a visible local approval decision." `
  --acceptance "A Given/When/Then scenario emits one hash-bound receipt." `
  --external-effects local_only `
  --approved-by "named-owner" `
  --rationale "The first delivery surface is the existing Python CLI." `
  --re-evaluate-when "The delivery surface or acceptance scenario changes." `
  --json

# 3. Bind the confirmation to the Product Graph, then require it for the mission.
factory product compile PRD.md --root . --intake .factory/intake-confirmations/<project>/<prd-sha>.json --json
factory product slices .factory/products/<project>/product_graph.json --root . --json
factory mission create .factory/products/<project>/value_slices.json <slice-id> `
  --root . --owner "named-owner" --require-intake --json
```

The worksheet provides a deterministic shortlist from explicit terms already in
the PRD. That shortlist is only a review aid. It is not a recommendation,
architecture evaluation, or an implicit framework choice. A confirmation must
select a listed option and supplies the intent and acceptance evidence in the
human's own words.

## What is bound

An Intake Grill receipt captures the PRD SHA-256, a stable decision tree, and
the source-derived shortlist. A confirmation captures the worksheet hash, PRD
SHA-256, framework id, intent, acceptance statement, external-effects posture,
named approver, rationale, and optional re-evaluation condition. `factory
product compile --intake` rejects a confirmation from different PRD bytes.

The Product Graph records only the hashes and selected framework needed to
validate the binding. A mission created with `--require-intake` fails closed if
the graph has no verified confirmation or the confirmation has drifted.

## Graph Ops and MCP

Unified Graph Ops projects a read-only **intake** lane when a Product Graph
contains an intake confirmation. It shows the selected framework, evidence
binding state, external-effects posture, and whether a re-evaluation condition
was recorded. It does not expose the human's intent text or add execution
controls.

The local MCP adapter exposes `factory.intake_status`. It can report a scoped
confirmation status to any stdio MCP client, but cannot create worksheets,
confirm decisions, create missions, select a framework, or authorize work.

## Boundary

Intake Grill does not prove the selected framework is best, that the intent is
complete, that the acceptance statement will pass, or that a product is ready
for implementation. It does not override SpecLine clarification, CDTE
contradiction checks, independent verification, named mission approval, or
external-effect controls. The receipt only proves exactly which source-bound
decisions a named human recorded.
