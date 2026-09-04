# Runtime audit condition inventory

Code Factory's senior-engineering runtime-assurance path has:

**6 mandatory audit lanes. 136 coded rejection conditions. One human-owned release decision.**

The source inventory comprises **81 lane-specific and 55 cross-cutting** conditions:

| Audit area | Coded rejection conditions |
| --- | ---: |
| Stateful workflows and business invariants | 12 |
| Authorization and tenant isolation | 11 |
| Failure, concurrency, retries and recovery | 16 |
| API and consumer compatibility | 10 |
| Database migration and data integrity | 12 |
| Performance, memory and resource regression | 20 |
| Cross-cutting contract, policy, provenance, evidence and execution integrity | 55 |
| **Total** | **136** |

Run `python scripts/audit_condition_inventory.py` to recompute the inventory
from the implementation. CI requires the public totals to match that output.

This is a source inventory, not a claim that every project executes 136 tests.
The six lanes are mandatory for a complete runtime-assurance decision, while
the observations within each lane scale with the approved invariants, tenant
surfaces, fault modes, consumers, tables, thresholds and evidence supplied for
that project. Missing tooling or evidence remains incomplete rather than pass.

Oracle Firewall, SpecLine, Deep Defect Mesh, AppForge and other conditional
modules add checks outside this narrowly defined runtime-assurance inventory.
