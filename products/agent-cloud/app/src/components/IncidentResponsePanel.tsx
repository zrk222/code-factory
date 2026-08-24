import { useState } from "react";
import { useMutation } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { AlertOctagon, Check, ClipboardCheck, ShieldAlert } from "lucide-react";

const runbook = ["containment-verified", "evidence-preserved", "root-cause-recorded", "rollback-verified", "owner-approved"] as const;
type Incident = Doc<"incidents"> & { checks: Doc<"incidentChecks">[] };

export function IncidentResponsePanel({ agentSpec, incidents }: { agentSpec: Doc<"agentSpecs">; incidents: Incident[] }) {
  const openIncident = useMutation(api.incidents.openIncident); const recordCheck = useMutation(api.incidents.recordRecoveryCheck); const resolve = useMutation(api.incidents.resolveIncident);
  const [busy, setBusy] = useState(false); const [notice, setNotice] = useState(""); const active = incidents.find((item) => item.status === "contained");
  async function act(work: () => Promise<{ marker: string }>) { setBusy(true); try { setNotice((await work()).marker); } catch (error) { setNotice(error instanceof Error ? error.message : "Incident action failed"); } finally { setBusy(false); } }
  return <section className="incident-section">
    <header className="incident-heading"><div><p className="eyebrow">Incident readiness · supervised recovery</p><h2>Contain first. Recover with evidence.</h2><p>One action suspends the agent, closes pending authority, rolls back canaries, and preserves the audit trail.</p></div><div className="incident-state"><ShieldAlert size={24}/><strong>{active ? `${active.severity.toUpperCase()} contained` : "Runbook ready"}</strong><span>{active ? `${active.checks.length}/5 recovery checks` : "No active incident"}</span></div></header>
    {!active ? <article className="surface incident-launch"><div><AlertOctagon size={24}/><div><strong>Start a controlled recovery drill</strong><p>Creates local evidence and pauses this AgentSpec. No external paging or production action.</p></div></div><button className="button primary" disabled={busy} onClick={() => void act(() => openIncident({ agentSpecId: agentSpec._id, severity: "sev2", summary: "Operator-initiated service-response rehearsal." }))}>Contain simulated SEV2</button></article> : <div className="incident-grid"><article className="surface incident-summary"><p className="kicker">Containment outcome</p><h3>{active.summary}</h3><dl><div><dt>Runs blocked</dt><dd>{active.closedRuns}</dd></div><div><dt>Approvals closed</dt><dd>{active.closedApprovals}</dd></div><div><dt>Canaries rolled back</dt><dd>{active.rolledBackCanaries}</dd></div></dl></article><article className="surface runbook-card"><p className="kicker">Five-check recovery contract</p><div className="runbook-list">{runbook.map((check) => { const done = active.checks.some((item) => item.check === check); return <button key={check} disabled={busy || done} className={done ? "done" : ""} onClick={() => void act(() => recordCheck({ incidentId: active._id, check }))}><span>{done ? <Check size={15}/> : <ClipboardCheck size={15}/>}</span>{check.replaceAll("-", " ")}</button>; })}</div><button className="button primary" disabled={busy || active.checks.length !== 5} onClick={() => void act(() => resolve({ incidentId: active._id, resolutionNote: "All recovery checks completed and owner approved return to service." }))}>Resolve and resume</button></article></div>}
    {incidents.length > 0 && <div className="incident-history">{incidents.map((incident) => <span key={incident._id}><b>{incident.severity.toUpperCase()}</b> {incident.status} · {incident.checks.length}/5 checks · {new Date(incident.openedAt).toLocaleString()}</span>)}</div>}
    {notice && <div className="toast success" role="status">{notice}</div>}
  </section>;
}
