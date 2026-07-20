# Deployment Guide

Factory Studio shows these routes in the live dashboard. A route is guidance,
not deployment authority: provider credentials, registry pushes, store
submissions, external changes, and spend require a separate explicit approval.

Discover the route ids with `factory targets --json`, select one in Factory
Studio, or bind it at the CLI with `factory create ... --deployment-profile
<route-id>`. The generated `target_manifest.json` and
`docs/TARGET_WORKFLOW.md` preserve the exact selection.

| Target | Fast local route | External route | Required approval |
| --- | --- | --- | --- |
| Worker | Local supervised process | Container host | Registry push and host deployment |
| Web | Local frontend and API | Managed frontend plus API host | Credentials and both deployments |
| Mobile | Expo device preview | EAS store release | Build spend, credentials, store submission |
| Agent UI | Local supervised operator | Private container host | Identity, registry, and host deployment |

## Worker

Route ids: `local-supervised`, `container-host`.

Install with `python -m pip install -e .`, verify with `python -m pytest -q`,
then run `python -m worker.main`. A container release remains blocked until a
reviewed Dockerfile, registry, host adapter, smoke input, and rollback route are
present.

## Web application

Route ids: `local-split`, `split-hosting`.

Install backend requirements and frontend packages, run Python tests and the
frontend production build, then start the two reviewed local services. Managed
hosting is a split deployment: select a frontend provider and a Python API
provider, then verify health, browser, and cross-origin flows before approval.

## Mobile application

Route ids: `expo-preview`, `eas-store`.

Run `npm --prefix mobile install`, verify with
`npm --prefix mobile exec expo-doctor`, and start the Expo preview with
`npm --prefix mobile start`. Store release requires reviewed EAS configuration,
an Expo account, store credentials, a signed-device smoke, and explicit approval
before `eas build --platform all` or `eas submit --platform all`.

## Agent UI

Route ids: `local-operator`, `private-container-host`.

Install the frontend and backend, run approval-boundary tests plus browser smoke,
and start both services on loopback. Private hosting requires reviewed container
manifests, TLS, identity-provider integration, a private registry, approval and
receipt canaries, and a tested rollback.

## Selection rule

Use the local or preview route for first proof. Select an external route only
after all listed prerequisites exist and Studio shows no unresolved mission or
verification failures. Code Factory does not infer credentials or silently
convert a local approval into release authority.

## Provider and IDE routing

`factory provider` adds a selection layer before a governed runtime invokes a
model. Policies allow exactly `cli`, `studio`, `vscode`, and `jetbrains`, bind
provider/model allowlists, quality tiers, price metadata, budget ceilings, and
cache-continuity hints, and reference BYOK credentials only by environment
variable name. `factory provider route` returns a deterministic recommendation;
it performs no provider call and grants no spend or credential authority. See
[Multi-Provider BYOK Routing](PROVIDER_ROUTING.md).
