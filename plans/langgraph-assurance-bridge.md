# Plan: langgraph-assurance-bridge
Spec: specs/langgraph-assurance-bridge.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Add a stdlib-only hash-only transition recorder and parity verifier built on
   sealed Graph Forensics lineages. Keep all execution and checkpoint authority
   false, and emit a privacy-safe shareable incident capsule only for a
   verified divergence.
2. Expose the exact same parity result through a bounded CLI and read-only MCP
   tool.
3. Add a standalone, opt-in GitHub composite Action that writes an advisory
   LangGraph Proof Card from local assurance receipts. Keep the GitHub delivery
   workflow supervised, fork-safe, and merge-neutral.
4. Document the small LangGraph harness integration, free GitHub workflow,
   future authenticated team-ledger boundary, scope limits, and the distinction
   between a parity receipt and a production-resilience claim.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=core | files=<=4 | verify=`python -m pytest -q tests/test_langgraph_assurance.py` | Implement recorder, sealed receipt validation, parity verdicts, and mutation-resistant tests.
- [ ] T2 | slice=interfaces | files=<=4 | verify=`python -m pytest -q tests/test_langgraph_assurance.py tests/test_mcp.py` | Add CLI and MCP read-only access with path and authority boundaries.
- [ ] T3 | slice=docs | files=<=4 | verify=`python -m pytest -q tests/test_ai_client_docs.py tests/test_publication_metadata.py` | Add LangGraph integration guide and public tool inventory references without unsupported savings claims.
- [ ] T4 | slice=github | files=<=4 | verify=`python -m pytest -q tests/test_github_proof_review.py` | Add an opt-in LangGraph proof-gate Action that writes an advisory Proof Card without creating merge, repair, graph, or credential authority.
