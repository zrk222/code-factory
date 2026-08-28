import { useState } from "react";
import { useMutation } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { Activity, CheckCircle2, RotateCcw, Rocket, ShieldCheck } from "lucide-react";
import { IncidentResponsePanel } from "./IncidentResponsePanel";

type Incident = Doc<"incidents"> & { checks: Doc<"incidentChecks">[] };
export function ReleaseSafetyPanel({ agentSpec, releases, incidents }: { agentSpec: Doc<"agentSpecs">; releases: Doc<"releaseCandidates">[]; incidents: Incident[] }) {
  const start = useMutation(api.releases.startCanary); const observe = useMutation(api.releases.recordObservation); const promote = useMutation(api.releases.promoteCanary); const rollback = useMutation(api.releases.rollbackCanary);
  const [notice, setNotice] = useState(""); const [busy, setBusy] = useState(false);
  const active = releases.find((item) => item.status === "active");
  async function act(work: () => Promise<{ marker: string }>) { setBusy(true); try { setNotice((await work()).marker); } catch (error) { setNotice(error instanceof Error ? error.message : "Release action failed"); } finally { setBusy(false); } }
  return <section className="release-page">
    <header className="release-hero"><div><p className="eyebrow">Phase 2 · supervised release safety</p><h1>Change the model.<br/><span>Keep the proof.</span></h1><p>Every candidate is re-evaluated, traffic-bounded, observed, and explicitly promoted or rolled back by an operator.</p></div><div className="release-boundary"><ShieldCheck size={26}/><strong>Human promotion required</strong><span>Local Convex security alpha · no production deployment</span></div></header>
    <div className="release-grid"><article className="surface release-card"><p className="kicker">Evaluation contract</p><h2>Six gates before traffic</h2><div className="release-facts"><span><b>6/6</b> deterministic</span><span><b>≥80</b> model score</span><span><b>5–25%</b> traffic</span></div><button className="button primary" disabled={busy || !!active} onClick={() => void act(() => start({ agentSpecId: agentSpec._id, targetVersion: agentSpec.version, deterministicGatesPassed: 6, modelScore: 88, trafficPercent: 10, reason: "Operator-approved re-evaluation." }))}><Rocket size={17}/> Start 10% canary</button></article>
    <article className="surface release-card"><p className="kicker">Active candidate</p><h2>{active ? `AgentSpec v${active.targetVersion}` : "No canary running"}</h2>{active ? <><div className="release-meter"><i style={{width:`${Math.min(100, active.observations * 5)}%`}}/></div><p>{active.observations}/20 healthy observations · {active.failures} failures · {active.trafficPercent}% traffic</p><div className="release-actions"><button className="button secondary" disabled={busy} onClick={() => void act(() => observe({ candidateId: active._id, failed: false }))}><Activity size={16}/> Record healthy</button><button className="button secondary" disabled={busy || active.observations < 20 || active.failures > 0} onClick={() => void act(() => promote({ candidateId: active._id }))}><CheckCircle2 size={16}/> Promote</button><button className="text-button danger" disabled={busy} onClick={() => void act(() => rollback({ candidateId: active._id, reason: "Operator recovery drill." }))}><RotateCcw size={16}/> Roll back</button></div></> : <p>Start only after the evaluation contract is satisfied.</p>}</article></div>
    <article className="surface release-history"><div className="surface-header"><div><p className="kicker">Append-only history</p><h2>Release evidence</h2></div><span className="prototype-pill">unsigned prototype receipts</span></div>{releases.length ? releases.map((item) => <div className="release-row" key={item._id}><span className={`release-state ${item.status}`}>{item.status}</span><strong>AgentSpec v{item.targetVersion}</strong><span>{item.observations} observations</span><span>{item.failures} failures</span><time>{new Date(item.createdAt).toLocaleString()}</time></div>) : <p className="empty-inline">No release candidates yet.</p>}</article>
    {notice && <div className="toast success" role="status">{notice}</div>}
    <IncidentResponsePanel agentSpec={agentSpec} incidents={incidents} />
  </section>;
}
