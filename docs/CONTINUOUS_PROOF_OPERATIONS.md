# Continuous Proof Operations

For advanced teams, this answers one operational question:

> What changed, what evidence exists for it, and what must a human do next?

It composes existing local Code Factory evidence. It does not add a hosted agent, connector, merge bot, or release authority.

## First record

Start with a human-authored intent file and the exact changed paths. If an admitted agent run was already captured with `factory wrap`, bind its session receipt:

```bash
factory proof-ops assess \
  --workflow-id approval-api \
  --intent specs/approval-api.md \
  --changed src/approval.py \
  --changed tests/test_approval.py \
  --session .factory/session-recorder/approval-api/session.json
```

The command writes JSON, Markdown, and Mermaid under `.factory/continuous-proof/approval-api/`. It returns exactly one route:

- `evidence_required`: capture an independently validated observed session.
- `human_required`: evidence failed, drifted, or a deterministic proof gap remains.
- `reverification_required`: a scoped repair still needs fresh evidence.
- `review_ready`: evidence is current; a human still owns final approval.

## Repair follow-up

Prepare and inspect repairs through the existing Repair Sandbox. The first operations record remains `reverification_required`. After a human applies the reviewed patch outside Code Factory, bind a fresh post-repair session to that prior record:

```bash
factory proof-ops assess \
  --workflow-id approval-api-reverified \
  --intent specs/approval-api.md \
  --changed src/approval.py \
  --session .factory/session-recorder/approval-api-reverify/session.json \
  --session-phase post_repair \
  --prior-receipt .factory/continuous-proof/approval-api/continuous-proof-RECEIPT.json
```

Code Factory requires every prior repair path in the follow-up change set and requires the session's recorded after-hashes to equal current repaired bytes. It still does not apply or approve the patch.

## Verify and inspect history

```bash
factory proof-ops verify .factory/continuous-proof/approval-api/continuous-proof-RECEIPT.json
factory proof-ops history --root .
factory graph ops --root .
```

History keeps integrity-valid past records separate from currently valid evidence. Counts are records, not unique users. No time, token, cost, quality, or productivity savings are inferred.
