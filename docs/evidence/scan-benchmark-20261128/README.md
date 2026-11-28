# Static scan benchmark, 2026-11-28

Corpus: these 30 files copied unchanged from `factoryline/` (40,762 lines, corpus digest in each receipt). Host: 2 CPUs, Linux, Python 3.13.

Reproduce: copy the files into an empty directory, then run `node scripts/scan_benchmark.mjs DIR OUT.json --runs 3` from each checkout.

| Receipt | Median | Runs |
| --- | --- | --- |
| main e68f3871 ([main-e68f3871.json](main-e68f3871.json)) | 116.424 s | 115.512, 116.424, 116.511 |
| this branch ([branch.json](branch.json)) | 70.931 s | 68.569, 70.931, 71.074 |

Both receipts carry the same output digest: the scan JSON is byte-identical.

Workers carry their batch freshness and validated paths back to the parent, so the batch exit re-checks the same paths and helper epochs as a serial scan (6 and 7 on a 6-file probe, both modes). A failing job reruns serially in the parent, a dead worker or unpicklable result reruns the whole scan serially, and a threaded process stays serial.

Files:

- __init__.py
- agent_contract.py
- agent_proof_bridge.py
- app_review_gate.py
- appforge_store_media.py
- appforge_surface_matrix.py
- capability_evidence.py
- capability_packs.py
- captured_operand_audit.py
- captured_security_audit.py
- cli_app.py
- cli_deep_audit.py
- cli_domain.py
- cli_ide.py
- cli_verifier.py
- django_class_fixture_audit.py
- engineering_memory.py
- failure_guidance.py
- habituation.py
- jetbrains_handshake.py
- mission_graph.py
- ops_telemetry.py
- product_missions.py
- proof.py
- proof_reuse.py
- runtime_audit_compatibility.py
- runtime_audit_tenant.py
- semantic_credential_sensor.py
- test_callback_closure.py
- verification.py
