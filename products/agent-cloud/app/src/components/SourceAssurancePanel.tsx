import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { AlertTriangle, CheckCircle2, Clock3, RadioTower, ShieldCheck } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import type { SourceAuthorityCategory } from "../../runtime/sourceAssurance";

type Props = { agentSpec: Doc<"agentSpecs"> };
type SourceRole = "primary" | "fallback" | "corroboration";

const categories: { value: SourceAuthorityCategory; label: string }[] = [
  { value: "primary-law", label: "Primary law" },
  { value: "official-regulator", label: "Official regulator" },
  { value: "official-registry", label: "Official registry" },
  { value: "licensed-system-of-record", label: "Licensed system of record" },
  { value: "secondary-corroboration", label: "Secondary corroboration" },
];

function ageLabel(seconds: number | null) {
  if (seconds === null) return "never verified";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

export function SourceAssurancePanel({ agentSpec }: Props) {
  const readiness = useQuery(api.authoritativeSources.listReadiness, { agentSpecId: agentSpec._id });
  const configure = useMutation(api.authoritativeSources.configure);
  const [label, setLabel] = useState("Official operating source");
  const [publisher, setPublisher] = useState("");
  const [jurisdiction, setJurisdiction] = useState("");
  const [sourceGroup, setSourceGroup] = useState("core-authority");
  const [category, setCategory] = useState<SourceAuthorityCategory>("official-regulator");
  const [role, setRole] = useState<SourceRole>("primary");
  const [locator, setLocator] = useState("");
  const [endpointRef, setEndpointRef] = useState("");
  const [licenseRef, setLicenseRef] = useState("");
  const [freshnessHours, setFreshnessHours] = useState(24);
  const [maximumAgeHours, setMaximumAgeHours] = useState(72);
  const [minimumSources, setMinimumSources] = useState(1);
  const [required, setRequired] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const sources = readiness?.sources ?? [];
  const groups = readiness?.groups ?? [];

  async function save() {
    setBusy(true); setNotice(null);
    try {
      const sourceKey = `${sourceGroup}-${label}`.toLocaleLowerCase("en-US").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 120);
      await configure({ agentSpecId: agentSpec._id, sourceKey, label, publisher, jurisdiction, sourceGroup, authorityCategory: category, sourceRole: category === "secondary-corroboration" ? "corroboration" : role, canonicalLocator: locator, endpointRef: endpointRef.trim() || undefined, licenseRef: licenseRef.trim() || undefined, freshnessSloSeconds: Math.round(freshnessHours * 3_600), maximumAgeSeconds: Math.round(maximumAgeHours * 3_600), minimumAuthoritativeSources: minimumSources, requiredForRuns: required });
      setNotice("Source saved. A trusted worker must verify it before it can admit regulated runs.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Source configuration failed."); }
    finally { setBusy(false); }
  }

  return (
    <section className="source-assurance" aria-labelledby="source-assurance-title">
      <header className="source-assurance-header">
        <div><p className="kicker">Authoritative Source Control Plane</p><h3 id="source-assurance-title">Keep regulated answers current—or stop safely.</h3><p>Official and licensed sources form redundancy groups. Secondary material can corroborate, but can never unlock a run.</p></div>
        <span className="assurance-governance"><ShieldCheck size={15} /> supervised source assurance</span>
      </header>

      {groups.length > 0 && <div className="source-groups" aria-label="Authoritative source group readiness">{groups.map((group) => <article className={group.state} key={group.sourceGroup}>
        {group.state === "ready" ? <CheckCircle2 size={19} /> : <AlertTriangle size={19} />}
        <div><strong>{group.sourceGroup}</strong><small>{group.qualifyingAuthoritativeSources}/{group.minimumAuthoritativeSources} authoritative current · {group.healthyAuthoritativeSources} healthy</small></div>
        <span>{group.state}</span><code>{group.reason}</code>
      </article>)}</div>}

      <div className="source-assurance-config">
        <label>Source name<input value={label} onChange={(event) => setLabel(event.target.value)} /></label>
        <label>Publisher<input value={publisher} onChange={(event) => setPublisher(event.target.value)} placeholder="Government or licensed publisher" /></label>
        <label>Jurisdiction<input value={jurisdiction} onChange={(event) => setJurisdiction(event.target.value)} placeholder="Canada · US · Ontario" /></label>
        <label>Redundancy group<input value={sourceGroup} onChange={(event) => setSourceGroup(event.target.value)} /></label>
        <label>Authority class<select value={category} onChange={(event) => { const next = event.target.value as SourceAuthorityCategory; setCategory(next); if (next === "secondary-corroboration") setRole("corroboration"); }}>{categories.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
        <label>Role<select disabled={category === "secondary-corroboration"} value={category === "secondary-corroboration" ? "corroboration" : role} onChange={(event) => setRole(event.target.value as SourceRole)}><option value="primary">Primary</option><option value="fallback">Fallback</option><option value="corroboration">Corroboration</option></select></label>
        <label className="wide">Canonical public HTTPS page<input value={locator} onChange={(event) => setLocator(event.target.value)} placeholder="https://official.example.gov/source" /></label>
        <label>Endpoint reference (optional)<input value={endpointRef} onChange={(event) => setEndpointRef(event.target.value)} placeholder="env:SOURCE_ENDPOINT_OFFICIAL" /></label>
        <label>License reference (optional)<input value={licenseRef} onChange={(event) => setLicenseRef(event.target.value)} placeholder="vault:licenses/source" /></label>
        <label>Freshness SLO (hours)<input type="number" min="1" max="720" value={freshnessHours} onChange={(event) => setFreshnessHours(Number(event.target.value))} /></label>
        <label>Maximum age (hours)<input type="number" min={freshnessHours} max="2160" value={maximumAgeHours} onChange={(event) => setMaximumAgeHours(Number(event.target.value))} /></label>
        <label>Minimum authoritative sources<input type="number" min="1" max="5" value={minimumSources} onChange={(event) => setMinimumSources(Number(event.target.value))} /></label>
        <label className="source-required"><input type="checkbox" checked={required} onChange={(event) => setRequired(event.target.checked)} /> Block runs when this group is not ready</label>
        <button className="button secondary" disabled={busy || !label.trim() || !publisher.trim() || !jurisdiction.trim() || !sourceGroup.trim() || !locator.trim() || maximumAgeHours < freshnessHours} onClick={() => void save()}><RadioTower size={15} /> Save authority source</button>
      </div>
      {notice && <p className="knowledge-notice" role="status">{notice}</p>}

      <div className="source-assurance-list">{sources.length === 0 ? <div className="source-assurance-empty"><RadioTower size={20} /><strong>No authoritative sources configured</strong><p>Agents can use the Knowledge Wall as context, but regulated workflows have no current-source gate yet.</p></div> : sources.map((source) => <article key={source._id}>
        <span className={`source-state ${source.assurance.state}`}>{source.assurance.state}</span>
        <div><strong>{source.label}</strong><small>{source.publisher} · {source.jurisdiction} · {source.authorityCategory}</small></div>
        <span className="source-age"><Clock3 size={13} /> {ageLabel(source.assurance.ageSeconds)}</span>
        <code>{source.assurance.reason}</code>
      </article>)}</div>
      <p className="source-assurance-boundary"><AlertTriangle size={14} /> “Always on” means monitored redundancy and fail-closed admission. It does not claim external publisher or government uptime.</p>
    </section>
  );
}
