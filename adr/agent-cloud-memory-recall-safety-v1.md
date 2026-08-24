# ADR — Filter persistent memory before ranking

## Decision

Agent Cloud will derive the workspace and agent boundary from AgentSpec, then apply exact normalized subject and purpose filters and quarantine exclusion before it ranks recall candidates. Persistent instruction-like content is retained as quarantined evidence. Recall explanations expose provenance, never authority.

## Why

Ranking first can allow a high-confidence record from the wrong purpose or a poisoned record to influence a result. Filtering first makes the security boundary deterministic and testable. Retaining quarantined records preserves auditability while preventing their operational use.

## Consequences

The first release is intentionally lexical and conservative. It may quarantine benign prose containing one of five reviewed phrases, and it does not claim to detect all prompt injection. Operators can append a corrected successor; the classifier runs again.
