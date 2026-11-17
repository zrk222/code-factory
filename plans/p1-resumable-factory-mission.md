# Plan: p1-resumable-factory-mission
Spec: specs/p1-resumable-factory-mission.md (approved before implementation)
Architect verdict: PASS

## Logical decomposition (phases)
1. Bind the mission, native intent and normalized source in the existing stores.
2. Reconcile and drive registered execution; attach the resulting proof before completing.
3. Run resource-admitted proof waves and show the same timeline through the operator CLI.
4. Verify restart recovery, drift, parity and throughput; release from the verified main commit.

## Tasks (atomic — each independently verifiable)
- [ ] T1 | slice=factoryline | files=factoryline/agentic_control.py,factoryline/mission_graph.py,factoryline/specforge_promotion.py | verify=`ruff check factoryline/agentic_control.py factoryline/mission_graph.py factoryline/specforge_promotion.py` | Bind an opted-in local mission source to the existing stores and check current intent and owner authority before dispatch.
- [ ] T2 | slice=factoryline | files=factoryline/specforge_promotion.py,factoryline/assembly.py,factoryline/proof_reuse.py,factoryline/verification.py | verify=`ruff check factoryline/specforge_promotion.py factoryline/assembly.py factoryline/proof_reuse.py factoryline/verification.py` | Reconcile the registered ForgeLine action and bind native trace, candidate proof and proof reuse to the same job.
- [ ] T3 | slice=factoryline | files=factoryline/specforge_promotion.py,factoryline/incremental_scheduler.py,factoryline/cli_domain.py,factoryline/cli.py | verify=`ruff check factoryline/specforge_promotion.py factoryline/incremental_scheduler.py factoryline/cli_domain.py` | Admit independent read-only waves and project one verified operator timeline.
- [ ] T4 | slice=tests | files=tests/test_specforge_promotion.py,tests/test_agentic_control.py,tests/test_continuity.py | verify=`python -m pytest -q tests/test_specforge_promotion.py tests/test_agentic_control.py tests/test_continuity.py` | Exercise native handoff, restart after a local effect, blocked ambiguity, proof drift, competing workers, parity and intervention measurements.
- [ ] T5 | slice=docs | files=docs/LANGGRAPH_OPS.md,docs/RELEASE_CHANNELS.md | verify=`git diff --check` | Document the verified operator flow and the single-candidate release for core 0.49.7 and editors 1.3.5.
