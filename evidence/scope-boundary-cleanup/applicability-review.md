# Scope boundary audit applicability

This change narrows only the repository-scope policy and its regression fixtures.
The repository `products/` root remains blocked, and generic external-product,
external-memory-core, and external-trust-core path segments remain reserved.

- Accessibility is not applicable: no user interface or user-facing interaction changed.
- Performance is not applicable: no matching algorithm, traversal, or runtime path changed.
- External effects are not applicable: this change makes no network, provider, deployment, or credential calls.

The applicable path-validation, blocked-scope, fixture-consistency, and regression
checks are recorded in the accompanying workflow audit contract and observations.
