# Regulated property, legal, and civic agent templates

## Product boundary

Agent Oven offers three separate property/planning recipes because their permissions and users differ:

1. **Broker MLS Intelligence** is a broker-sponsored product. It can use only the markets, resources, fields, and purposes approved by the broker and data licensor. A licensed professional approves outreach, disclosure, negotiation, and transaction actions.
2. **Homebuyer & Seller Guide** is a consumer product. It uses public or consumer-display-permitted data, explains uncertainty, prepares comparisons and checklists, and hands regulated decisions to a professional selected by the user. It does not form an agency relationship.
3. **Civic Planning Intelligence** is a parcel and jurisdiction research product. It traces enacted rules and pending changes across municipal, regional/county, provincial/state, and federal authorities. It produces a feasibility brief for professional review, not a permit, code opinion, title opinion, appraisal, or legal conclusion.

The **Legal Research Workbench** is also separate. It prepares jurisdiction-aware cited research for supervised legal teams. It does not provide unsupervised legal advice or file documents.

## Why one universal feed is not credible

RESO defines transport and dictionary standards; it does not distribute MLS data. Credentials come from an MLS after the applicable data-use and licensing agreements are approved. The standard exposes both common and local fields, so an adapter must retain originating-system metadata and local-field mappings. See [RESO Web API](https://www.reso.org/reso-web-api/) and [RESO certification](https://www.reso.org/certification/).

MLS Grid demonstrates the operational model: one normalized feed and licensing process for participating MLSs, but only for data a broker is entitled to receive. Its service is replication-oriented rather than guaranteed real-time access, media must be copied or appropriately cached, and usage can trigger suspension. See the [MLS Grid API overview](https://docs.mlsgrid.com/) and [licensing FAQ](https://www.mlsgrid.com/faq).

In Canada, REALTOR.ca DDF is a controlled distribution service in which broker owners manage listing-sharing permissions. It is not a universal back-office MLS feed. See [REALTOR.ca DDF](https://www.crea.ca/technology/realtor-ca-for-realtors/realtor-ca-tools/realtor-ca-ddf/).

Municipal planning is even more fragmented. A city may publish zoning geometry through ArcGIS, a dataset through CKAN or another portal, a bylaw as HTML/PDF, amendments in council records, and permits in a separate vendor system. ArcGIS Feature Services support geometry and attribute queries, while CKAN exposes versioned catalog APIs; neither proves a document is current or legally operative. See [ArcGIS Feature Service](https://developers.arcgis.com/rest/services-reference/enterprise/feature-service/) and the [CKAN API guide](https://docs.ckan.org/en/latest/api/).

## Common evidence contract

Every sourced fact must retain:

- jurisdiction and authority level;
- source owner and canonical URL;
- source type: enacted law, adopted plan, official GIS, permit record, pending notice, meeting record, or third-party aid;
- adoption, effective, amendment, repeal, and retrieval dates when available;
- parcel/listing identity and geometry or record-key digest;
- original field, normalized field, and transformation lineage;
- permitted-use class and display restrictions;
- content digest, freshness state, and conflict state.

An enacted-rule conclusion cannot be supported only by a draft plan, staff report, meeting agenda, unofficial map, model code, or search snippet. Conflicting zoning geometry and text must produce **conflict — professional review required**, not a guessed resolution.

## Broker MLS Intelligence innovations

- **Delta radar:** detect price, status, remarks, media, open-house, and material field changes and explain why a client or seller may care.
- **Explainable fit dossier:** compare a property against explicit client constraints, show disqualifiers and unknowns, and avoid opaque desirability scores.
- **Inventory-gap mining:** summarize where qualified, consented buyer demand is underserved without exposing client identity or enabling steering.
- **Seller launch simulator:** model timing, competitive set, showing readiness, and marketing scenarios using observed data; label every forecast and keep pricing advice with the licensee.
- **Transaction readiness:** assemble disclosure, showing, financing, condition, and deadline checklists with local-policy versioning and human ownership.
- **Civic-change overlay:** combine listing data with the Civic Planning Intelligence output to flag pending transit, zoning, development, hazard, heritage, and permit changes with source status.

## Homebuyer & Seller Guide innovations

- A persistent, consented **home decision record** that separates needs, preferences, deal-breakers, and later corrections.
- Side-by-side property dossiers that expose missing facts, stale listing status, source time, recurring-cost assumptions, and questions to ask at a showing.
- A seller preparation room for evidence inventory, improvement history, disclosure questions, and professional handoffs.
- Scenario tools for cash flow, closing-cost categories, commute, renovation questions, and offer preparation. Outputs are educational and never represented as lending, tax, appraisal, inspection, engineering, zoning, or legal determinations.
- A representation-status gate before tours or brokerage actions. In the U.S., current NAR practice changes require written buyer agreements before touring for covered MLS participants and prohibit offers of compensation on the MLS. See [NAR practice changes](https://www.nar.realtor/press-releases/national-association-of-realtors-reminds-members-and-consumers-of-real-estate-practice-change) and the current [VOW policy](https://www.nar.realtor/handbook-on-multiple-listing-policy/virtual-office-websites-policy-governing-use-of-mls-data-in-connection-with-internet-brokerage).

## Civic Planning Intelligence innovations

- **Address-to-authority resolver:** geocode once, resolve parcel and every governing layer, and name the municipality, county/region, state/province, and relevant special districts.
- **As-of-date zoning answer:** answer both “what applies now?” and “what was in force on the requested date?” from an amendment chain.
- **Buildability matrix:** translate permitted uses, setbacks, height, density/FAR, lot coverage, parking, overlays, heritage, flood/environmental constraints, and approval paths into a structured matrix with unknowns.
- **Future-change radar:** watch official-plan amendments, zoning cases, variances, site plans, permits, capital plans, environmental notices, and council/planning agendas around a parcel or portfolio.
- **Rural resolver:** include township/county rules, agricultural and conservation authority constraints, wells/septic, access, shoreline/flood, and provincial/state overlays rather than assuming a city zoning stack.
- **Pre-application packet:** generate the questions, maps, source extracts, and contradiction list a planner, architect, attorney, or building official needs to verify quickly.

Ontario illustrates the hierarchy: official plans set future land-use policy, zoning bylaws implement that policy with enforceable use and dimensional rules, and municipalities enforce the Building Code Act and Code. See Ontario's [zoning bylaw guide](https://www.ontario.ca/document/citizens-guide-land-use-planning/zoning-bylaws) and [building regulation guide](https://www.ontario.ca/document/ontario-municipal-councillors-guide/12-building-regulation). Open-data availability varies materially even within a province, as the federal catalog's [Gatineau zoning dataset](https://open.canada.ca/data/en/dataset/f8d74126-72ab-4303-ad91-9285a7f7772f) demonstrates.

## Mandatory safety controls

- No protected-class inference, proxy targeting, steering, discriminatory ranking, or exclusionary advertising. HUD expressly applies the Fair Housing Act to automated housing advertising and screening. See [HUD AI guidance](https://archives.hud.gov/news/2024/pr24-098.cfm).
- No automated appraisal claim. Where an AVM is used in a covered U.S. mortgage context, quality controls include confidence, manipulation protection, conflict avoidance, sample testing/review, and nondiscrimination. See the [CFPB AVM rule summary](https://www.consumerfinance.gov/archive/newsroom/agencies-issue-final-rule-to-help-ensure-credibility-and-integrity-of-automated-valuation-models/).
- No silent fallback from official to unofficial authority.
- No action with expired data entitlement or failed freshness SLA.
- All outbound or binding actions require a named human owner and an exact digest approval.

## Rollout

Start with one U.S. MLS/market and one Canadian board/market plus five municipalities that expose representative ArcGIS, open-data, HTML, and PDF patterns. Measure field coverage, change-detection latency, citation accuracy, stale-source refusal, conflict detection, and professional correction rate. Add markets only after their source registry, license, policy mapping, and golden parcel/listing fixtures pass.
