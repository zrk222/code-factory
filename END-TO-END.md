# End-to-End Journeys

Observable journeys used to calibrate and review the factory:

- [ ] Happy path: an approved candidate produces the intended result and its evidence is bound to the exact candidate.
- [ ] Forbidden access: a cross-tenant or unauthorized request is rejected without leaking data or leaving partial state.
- [ ] Failure recovery: a transient provider fault retries within policy and resumes from the last durable checkpoint; non-transient faults stop.
- [ ] Compatibility and migration: a schema or consumer change preserves representative data and supported clients, or blocks with actionable proof debt.

Each journey must name its expected result, forbidden result, and evidence producer before activation.
