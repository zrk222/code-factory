# Team Pilot launch: a bounded, customer-managed reference workflow

The Free Core remains the available product. The proposed Team Proof Hub is
still **design-partner only and not purchasable**. This guide does not enroll a
customer or start a service. It makes the internal readiness review repeatable
when the product owner has already selected up to three potential partners.

## What this gate proves

`factory team-pilot readiness` reads a local manifest and five locally stored,
hash-bound decision files. If they are complete and the commercial contract
still says the Team Proof Hub is human-controlled, design-partner-only, and not
purchasable, it writes `TEAM_PILOT_READY_FOR_OWNER_REVIEW`.

That marker means **review the evidence next**. It does not mean “customer
accepted,” “paid,” “provisioned,” “launched,” “secure,” or “managed.” The only
delivery mode it accepts is `customer_managed_reference`.

## 1. Prepare non-secret evidence

Create one small local file for each required decision. The files should state
the decision and its owner, not source code, credentials, access tokens,
customer data, incident details, or private receipts.

| Required kind | What the local evidence should name |
| --- | --- |
| `design_partner_selection` | the human selection decision and why this partner fits the bounded pilot |
| `deployment_security_review` | the approved customer-managed deployment boundary and unresolved risks |
| `data_retention_decision` | where the partner keeps evidence and who owns retention/deletion decisions |
| `support_and_incident_owner` | the named owner, support route, and escalation boundary |
| `commercial_terms_review` | confirmation that terms require separate human/company approval |

On Windows, calculate each exact digest after finalizing the file:

```powershell
certutil -hashfile .\pilot-evidence\design-partner-selection.json SHA256
```

## 2. Write the local manifest

Use only relative paths, record the digest for each file, and keep the count at
three or below. Replace every placeholder before running the command.

```json
{
  "schema": "factory.team-pilot-launch.v1",
  "pilot_id": "team-alpha",
  "owner": "named-pilot-owner",
  "partner_count": 1,
  "governance": "human_controlled",
  "delivery_mode": "customer_managed_reference",
  "evidence": [
    {"kind": "design_partner_selection", "path": "pilot-evidence/design-partner-selection.json", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
    {"kind": "deployment_security_review", "path": "pilot-evidence/deployment-security-review.json", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
    {"kind": "data_retention_decision", "path": "pilot-evidence/data-retention-decision.json", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
    {"kind": "support_and_incident_owner", "path": "pilot-evidence/support-and-incident-owner.json", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"},
    {"kind": "commercial_terms_review", "path": "pilot-evidence/commercial-terms-review.json", "sha256": "REPLACE_WITH_64_LOWERCASE_HEX"}
  ]
}
```

## 3. Compile and review the receipt

```powershell
factory team-pilot readiness --root . --manifest .\team-pilot.json --out-dir .\.factory\team-pilot --json
factory team-pilot verify .\.factory\team-pilot\team-pilot-<receipt-prefix>.json --json
```

The first command refuses a missing file, path escape, duplicate or unknown
kind, digest drift, a fourth partner, non-human governance, managed delivery,
or a commercial contract that was quietly widened into a sellable offer.

The output folder contains a JSON receipt, a one-page Markdown summary, and a
Mermaid flow map. Store it according to the partner's own retention policy; it
is not uploaded or retained by Code Factory.

## 4. The external handoff remains human-owned

After a green receipt, the named owner—not this command—must decide whether to
continue through the organization’s approved partner, legal, security,
procurement, support, and billing processes. This repository does not contain
a checkout, contract, entitlement system, customer onboarding, managed tenant,
Marketplace price activation, or launch mechanism.

If a pilot needs a managed runner or hosted Team Proof Hub, stop. That requires
a separate operating design with environment isolation, credential and network
boundaries, service support, incident response, retention, commercial terms,
and independently reviewed evidence.

For package positioning, see [Commercial packaging](COMMERCIAL_PACKAGING.md).
For the broader team workflow, see the [Teams and Enterprise Operations Manual]
(ENTERPRISE_TEAMS_OPERATIONS.md).
