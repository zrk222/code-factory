# ADR: Server-owned production readiness

## Status

Accepted.

## Decision

Evaluate deployment readiness inside Convex from server environment presence and contract validation. Return only a fixed catalog of human labels, categorical status, and next actions to authorized workspace administrators. Keep configured names, references, values, and identity claims outside the browser response.

## Consequences

- A live control plane can be represented honestly as a pilot while billing, email, worker, backup, or security operations remain blocked.
- A missing or malformed dependency fails closed and remains actionable for novice operators.
- The query cannot prove that an opaque secret reference resolves or that an external worker is healthy; those require separate activation receipts.
