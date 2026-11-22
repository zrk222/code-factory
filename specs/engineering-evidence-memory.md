# Spec: Engineering Evidence Memory
Status: approved for implementation under user request

## MUST - Functional core
### Requirements (EARS)
- When `REQ_HANDOFF` transfers knowledge between registered assembly modules, it shall emit a versioned digest-only packet and require the receiver to repeat exact-scope recall; altered, misrouted or stale packets shall block without execution authority. [R5]
- When `REQ_SCOPE` recalls memory, it shall require exact tenant, purpose and repository scope authorization, use 1 read-only SQLite snapshot, and inspect at most 1000 records; overflow shall block. [R1]
- When `REQ_EVIDENCE` admits a record, it shall require independent promotion, non-expiry, a valid content digest, and 1 or more local SHA-256-bound evidence references; missing, changed or malformed evidence shall exclude the record. [R2]
- When `REQ_WITHDRAW` changes a verified record, it shall require promoter authorization, prohibit its creator from withdrawing it, and atomically record status superseded, contradicted or revoked with 1 audit event; supersession shall require a verified replacement with exact matching tenant, purpose and scope. [R3]
- When `REQ_INFLUENCE` returns recall, it shall include record and evidence digests, exclusions without summary text, a deterministic influence digest and zero approval or execution authority. [R4]
- When `REQ_TOPIC_RECALL` receives 1..8 explicit topics and a limit of at least 1 and at most 20 records, it shall rank only admitted records, allocate each topic its next distinct candidate before another round, report unmatched and budget-exhausted topics separately, and preserve full-scope handoffs and read-only authority. [R6]
- When `REQ_BATCH_RANKING` scores 1..8 topics, it shall prepare exactly 8 search fields per admitted document once per request, reuse integer document frequencies and length statistics, and preserve every existing rounded score, ranking, selected record, gap and receipt digest without retaining validation results between requests. [R7]

### Acceptance criteria
```gherkin
Scenario: Receiver revalidates knowledge
 Given REQ_HANDOFF emits a packet before evidence changes
 When REQ_HANDOFF receives the packet after evidence changes
 Then REQ_HANDOFF blocks the stale packet
Scenario: Scope and evidence govern recall
 Given REQ_SCOPE selects an exact authorized scope with 1 promoted record
 When REQ_EVIDENCE finds changed evidence
 Then REQ_INFLUENCE excludes the summary and returns zero approval authority
Scenario: Independent withdrawal
 Given REQ_WITHDRAW receives 1 creator request to revoke a record
 When REQ_WITHDRAW authorizes the request
 Then REQ_WITHDRAW rejects self withdrawal
Scenario: Bounded snapshot
 Given REQ_SCOPE encounters more than 1000 records
 When REQ_SCOPE reads the snapshot
 Then REQ_SCOPE blocks the recall
Scenario: Shared preparation preserves recall
 Given REQ_BATCH_RANKING receives 8 topics over 1000 admitted records
 When REQ_BATCH_RANKING scores the topics
 Then REQ_BATCH_RANKING tokenizes exactly 8008 field and query inputs and returns the original scores and selection digest
Scenario: Topics retain separate gaps
 Given REQ_TOPIC_RECALL receives 3 topics and a limit of 1 record
 When REQ_TOPIC_RECALL finds matches for the first 2 topics but none for the third
 Then REQ_TOPIC_RECALL reports budget_exhausted for the second and no_admissible_lexical_match for the third
```

## SHOULD - Structural
- Reuse ContinuityStore, its role authorization and transaction/audit boundary.
- Evidence references consist of sha256, a 64-character lowercase hex digest and a canonical workspace path, separated by colons.
- Parse the reference using at most 2 colon splits to preserve the path component for canonical path validation.
- Read at most 1001 rows to detect overflow. Use existing 10,000,000-byte file bound.
- Verify at most 10000 tenant audit events in the same snapshot, probing 10001 for overflow. Require the latest event to match promotion before recall.
- Local principal strings and unsigned hashes do not authenticate people or prove truth.
- Recalled summaries are untrusted data, never instructions or approved gate changes.
- No embedding, hosted service, neural model, automatic promotion or release action.

## Bounded topic recall (WizeMe Memory Spine pattern)

The existing evidence-memory command accepts repeatable `--query` and optional
`--limit`; the Python API adds keyword-only `queries=None, limit=None` to
`recall_engineering_memory`. Omitting both preserves the exact legacy output
and handoff behavior. Query selection is forbidden with --accept/--sender/
--receiver so digest-only knowledge handoffs always revalidate the full scope.
No new model, provider, store, module, auto-promotion or execution authority.

Queries must be a list of1..8 strings, each1..512 characters, without ASCII
control characters and with at least one existing ASCII alphanumeric tokenizer
term. Strip outer whitespace. A supplied limit must be a non-boolean integer
1..20; query mode defaults to5. A limit without queries rejects. Validate after
principal authorization and before database I/O. CLI validation errors retain
the existing blocked/non-authoritative response and exit1; parser errors exit2.
The character bound is checked before stripping; ranking and hashing use the
stripped query. ASCII controls mean code points below32 plus DEL127.

Read and validate the original bounded authorized snapshot before ranking.
Expired, withdrawn, unpromoted, hash-invalid and source-invalid records never
enter the ranker. Reuse existing audit_rule_search._bm25_scores(fielded=True),
including its current tokenizer, field weights, rounding and tie behavior.
Project record_id into ruleId/name, summary into description and evidence paths
joined by spaces into sourceModule; other rule fields are empty. Do not read or
index evidence contents. Every query ranks positive-score records descending,
then record_id ascending. Each query is a caller-declared topic, not a semantic
decomposition inferred by a model. Records can match on any query term except
the fixed filler words in engineering_memory._FILLER (articles, auxiliaries and
question words, after WizeMe's hop stopwords): a record ranks for a topic only
with a positive score and at least 1 shared non-filler term. Filler terms still
contribute to the unchanged score. A topic phrased "how is the cache invalidated"
therefore reports no_admissible_lexical_match instead of matching every summary
containing "the". A hit is lexical evidence, not proof all terms or semantic
requirements are satisfied.
Exact BM25F: lowercase and tokenize with `[a-z0-9]+`, using sorted unique query
terms (repetition adds no weight). N is the admitted document count. df counts
documents containing a term in any field. For each active field, count=tf;
normalizer=1-b+b*field_length/mean_field_length (or1 when mean is0). Add
boost*tf/normalizer into weighted_tf. Active(boost,b): name(2.8,0.55),
description(1.0,0.80), sourceModule(0.6,0.65); empty fields contribute0. For each
term with df>0, add ln(1+(N-df+0.5)/(df+0.5))*2.2*weighted_tf/(2.2+weighted_tf).
Round total score to8 decimal places before filtering positive scores. Empty
inventories yield empty rankings. Scores are selection inputs, not probabilities.

Allocate unique records in round-robin query order: each query selects its next
unselected ranked ID in the same turn, preferring the first whose evidence-path
set is not yet cited by a selected record (admitted evidence is hash-current, so
equal paths mean equal bytes) and otherwise its next unselected ID. This adapts
WizeMe's source-diversity term without its weights: duplicates citing the same
evidence cannot fill the budget while new evidence is ranked. Stop at limit or
exhausted rankings.
Thus another topic gets its first slot before one topic's second candidate.
A selected record can support multiple query traces. Return only selected
records and their existing influence edges. Excluded records remain content-free
under the existing exclusion field. No retrieval field is added in legacy mode.

Query mode adds retrieval schema factory.evidence-recall-selection.v1, method
trust-first-bm25f-round-robin, limit, admissible count, matched unique-record
count, queries array, status, authority none, claim_boundary and selection_sha256.
Each query entry contains query_sha256 (existing _sha on the stripped string),
matched count, selected_record_ids in global selection order, and gap null,
budget_exhausted (a match exists but no slot) or no_admissible_lexical_match.
Raw query text and excluded summaries are absent. Empty topics remain visible;
status is PARTIAL_CONTEXT if any gap exists, else MATCHED_CONTEXT. Neither state
means semantic completeness, universal recall or current-code proof. Hash the
trace before adding selection_sha256, and include it in the existing result
influence digest. Query hashes are integrity/privacy minimization, not secrecy
against dictionary attacks. No new disk write or index/cache is introduced.

Patterns were studied in WizeMe's source-bound graph selector, per-hop allocation
and retrieval-miss analysis. This independently implemented adapter retains CF
authorization, expiry, withdrawal and exact evidence checks; it does not copy
the TS orchestrator, probabilistic graph scores, ANN or personalized weights.
Ranking cannot repair a detector which never emitted a finding. The historical
0/161 advisory-detection result is not changed by evidence retrieval tests.

### Request-local corpus preparation

The ranking adapter uses one shared batch scorer in audit_rule_search; the
existing single-query scorer delegates to the same implementation. Prepare
field tokens, integer document frequencies and average lengths once for the
batch. Query terms remain sorted unique tokens; document frequency
is computed once for the union of query terms. Preserve field iteration and
floating-point operation order, constants and final 8-decimal rounding. Flat
BM25 and fielded BM25F retain their distinct formulas. Empty queries return zero
scores; empty corpora and duplicate identifiers retain existing behavior. No
global cache, persisted index, metadata-only evidence check, SQL pre-truncation,
new dependency, scope expansion or untrusted evidence-body indexing is allowed.

Accuracy acceptance compares the unchanged independent baseline with candidate
scores and complete selections/traces, including reordered documents, ties,
repeated and missing terms, punctuation, Unicode and overlapping topics. The
baseline is retained before editing; it must not call the candidate wrapper.
Performance acceptance uses 11 alternating baseline/candidate pairs at 1, 4 and
8 topics over the same 1000 synthetic metadata records, on the same interpreter.
At 4 and 8 topics require a lower candidate median and at least 9 paired wins;
at 1 topic require no median regression above 5 percent. Publish raw pairs,
input/source hashes, score/trace parity and measured scope. These are retrieval
measurements, not full-scan latency, detector accuracy or production throughput.
Retain rejection tests for changed evidence, withdrawals, authorization and
audit-chain corruption across consecutive requests; preparation never caches
trust or grants authority. Missing-topic traces guide a caller's next explicit
query, not an automatic model loop or invented semantic expansion.

Acceptance: multi-topic distractors cannot crowd out a matching second topic
when budget permits; report budget loss separately from no lexical match;
invalid/withdrawn/high-scoring records stay excluded, tenant/scope filtering
precedes ranking, legacy handoffs stay byte-identical, bounds reject before I/O,
results and hashes repeat deterministically, and SQLite bytes remain unchanged.

### Exact retained metadata and legacy handoff contract

_sha(value) is SHA256 over UTF8 JSON: sorted object keys, compact comma/colon
separators and ensure_ascii=False. It retains Python json.dumps defaults
(including allow_nan=True); query/trace inputs here contain no floating values.
Query_sha256 hashes
the JSON string including its canonical quotes; it is not SHA256 of raw text.
Record fields are record_id, record_type, summary, record_sha256, evidence
([{path,sha256} in original reference order]), usage equal to
untrusted_reference_not_instruction, and influence_sha256=_sha({record:
record_sha256,evidence:bindings}). No retrievalScore is emitted in records.

Base result contains schema=factory.engineering-evidence-memory.v1, records,
excluded, influence_edges, scope_sha256, authority=none, governance=
human_controlled, action_summary, limits and influence_sha256. Query mode alone
adds retrieval. Edges are {source:evidence.sha256,target:record.record_sha256,
relation:supports_recalled_reference}, iterating selected records then evidence.
scope_sha256 hashes {tenant:tenant_id,purpose:purpose_ref,scope:scope_ref}.
Each excluded entry is {record_id,reason:
not_current_independently_promoted_or_evidence_invalid}; no excluded summary.
action_summary is "Recheck promoted memory evidence and expose its influence; never change a gate."
limits is "Local unsigned ledger and declared identities; hashes do not establish truth or authentication. Evidence is checked at read time, not locked afterward."
Hash the entire base result before adding influence_sha256. Retrieval fields are
schema,method,limit,admissible,matched,queries,status,authority,claim_boundary,
selection_sha256. Its exact claim_boundary is "Lexical context matches, not semantic completeness, defect recall or proof authority."

The audit reader probes10001 events ordered by sequence for the exact tenant,
blocking above10000 with E_MEMORY_LIMIT. Malformed JSON, previous-hash mismatch
or event-hash mismatch abort the whole recall as E_MEMORY_AUDIT. The latest
event for each row must be continuity.promote, with actor=promoted_by and
payload.record_sha256 matching; per-record failures instead cause exclusion.
Scope rows ordered by record_id probe1001, blocking above1000. Existing valid
empty-scope reads return no records; query mode then reports per-topic misses.

Handoff routes must be distinct members of MODULES or reject E_HANDOFF_ROUTE.
create_knowledge_handoff calls full recall and emits schema
factory.knowledge-handoff.v1, sender,receiver,scope_sha256,influence_sha256,
record_digests (sorted unique recalled record_sha256), evidence_digests (sorted
unique evidence.sha256), excluded, authority=none and action_summary=
"Transfer reference fingerprints; receiving module must revalidate locally."
packet_sha256 hashes this packet before its own addition. No summaries travel.
receive_knowledge_handoff recomputes that full packet and requires exact equality,
else E_HANDOFF_STALE_OR_INVALID. Success returns schema
factory.knowledge-received.v1,sender,receiver,packet_sha256,memory (full current
recall),authority=none,action_summary="Revalidated local references; no execution or gate approval granted."
CLI maps caught ValueError/OSError/KeyError/TypeError/ContinuityError/sqlite3.Error
to {state:blocked,code:exception.code or E_MEMORY_INVALID,authority:none}, exit1.
