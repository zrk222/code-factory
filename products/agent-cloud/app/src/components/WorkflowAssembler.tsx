import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { Check, CircleDollarSign, FlaskConical, GitBranch, GripVertical, Plus, Save, ShieldCheck, Trash2 } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import type { BusinessTemplate } from "../templates";
import { knowledgeConnectorCatalog } from "../knowledgeConnectorCatalog";
import { stepsForTemplate, type WorkflowStep } from "../templateWorkflow";

type Props = { agentSpec: Doc<"agentSpecs">; template: BusinessTemplate; blueprint: Doc<"agentBlueprints"> | null; versions: Doc<"agentBlueprintVersions">[] };

function estimateCredits(steps: readonly WorkflowStep[], trigger: string, memory: string, evidence: string) {
  return 20 + steps.length * 4 + (trigger === "manual" ? 0 : 8) + (memory === "governed" ? 15 : memory === "run-only" ? 5 : 0) + (evidence === "full" ? 10 : 0);
}

export function WorkflowAssembler({ agentSpec, template, blueprint, versions }: Props) {
  const saveBlueprint = useMutation(api.blueprints.save);
  const activateBlueprint = useMutation(api.blueprints.activate);
  const reserveCredits = useMutation(api.credits.reserveBlueprint);
  const settleCredits = useMutation(api.credits.settle);
  const simulation = useQuery(api.blueprints.simulate, blueprint ? { agentSpecId: agentSpec._id } : "skip");
  const [mode, setMode] = useState<"guided" | "architect">("guided");
  const [trigger, setTrigger] = useState<"manual" | "schedule" | "webhook" | "event">("manual");
  const [steps, setSteps] = useState<WorkflowStep[]>(() => stepsForTemplate(template));
  const [memory, setMemory] = useState<"none" | "run-only" | "governed">(template.memory === "architecture-history" ? "governed" : "run-only");
  const [model, setModel] = useState<"economy" | "balanced" | "highest-quality" | "auto">(template.tier === "Premium trust" ? "highest-quality" : "balanced");
  const [evidence, setEvidence] = useState<"essential" | "full">(template.tier === "Premium trust" ? "full" : "essential");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const credits = useMemo(() => estimateCredits(steps, trigger, memory, evidence), [steps, trigger, memory, evidence]);

  useEffect(() => {
    setSteps(stepsForTemplate(template));
    setMemory(template.memory === "architecture-history" ? "governed" : "run-only");
    setModel(template.tier === "Premium trust" ? "highest-quality" : "balanced");
    setEvidence(template.tier === "Premium trust" ? "full" : "essential");
  }, [template]);

  async function save() {
    setBusy(true); setNotice(null);
    try {
      const result = await saveBlueprint({ agentSpecId: agentSpec._id, templateId: template.id, name: template.title, mode, triggerKind: trigger, triggerLabel: trigger === "manual" ? "User starts a run" : `${trigger} trigger`, steps, memoryPolicy: memory, modelPolicy: model, authorityPolicy: template.authority, evidenceLevel: evidence, hardBudgetCents: Math.round(template.hardBudgetDollars * 100) });
      setNotice(`Blueprint v${result.version} saved as a draft. Estimated build: ${result.estimatedPlatformCredits} credits.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Blueprint save failed."); }
    finally { setBusy(false); }
  }

  async function purchaseAndActivate() {
    if (!blueprint) return;
    setBusy(true); setNotice(null);
    try {
      const reservation = await reserveCredits({ blueprintId: blueprint._id, idempotencyKey: `blueprint:${blueprint._id}:v${blueprint.version}` });
      await settleCredits({ reservationId: reservation.reservationId, actualCredits: reservation.quotedCredits });
      await activateBlueprint({ blueprintId: blueprint._id, creditReservationId: reservation.reservationId });
      setNotice(`Blueprint v${blueprint.version} activated for ${reservation.quotedCredits} credits with receipt evidence.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Purchase and activation failed."); }
    finally { setBusy(false); }
  }

  return (
    <section className="workflow-assembler surface" aria-labelledby="workflow-title">
      <header className="workflow-header"><div><p className="kicker">Agent Blueprint / versioned recipe</p><h2 id="workflow-title">Assemble the work line.</h2><p>Guided mode keeps the safe preset. Architect mode unlocks step types, connectors, gates, and policies without hiding their impact.</p></div><div className="mode-switch"><button className={mode === "guided" ? "active" : ""} onClick={() => setMode("guided")}>Guided</button><button className={mode === "architect" ? "active" : ""} onClick={() => setMode("architect")}>Architect</button></div></header>
      <div className="workflow-ingredients">
        <label><span>1</span>Trigger<select value={trigger} onChange={(event) => setTrigger(event.target.value as typeof trigger)}><option value="manual">Manual</option><option value="schedule">Schedule</option><option value="webhook">Webhook</option><option value="event">Business event</option></select></label>
        <label><span>2</span>Memory<select value={memory} onChange={(event) => setMemory(event.target.value as typeof memory)}><option value="none">None</option><option value="run-only">Run only</option><option value="governed">Governed history</option></select></label>
        <label><span>3</span>Model route<select value={model} onChange={(event) => setModel(event.target.value as typeof model)}><option value="economy">Economy</option><option value="balanced">Balanced</option><option value="highest-quality">Highest quality</option><option value="auto">Smart router</option></select></label>
        <label><span>4</span>Proof<select value={evidence} onChange={(event) => setEvidence(event.target.value as typeof evidence)}><option value="essential">Essential</option><option value="full">Full evidence</option></select></label>
      </div>
      <div className="workflow-line">{steps.map((step, index) => <article key={step.id}><GripVertical size={15} /><b>{index + 1}</b><input aria-label={`Step ${index + 1} label`} value={step.label} readOnly={mode === "guided"} onChange={(event) => setSteps((current) => current.map((item) => item.id === step.id ? { ...item, label: event.target.value } : item))} /><select aria-label={`Step ${index + 1} type`} value={step.kind} disabled={mode === "guided"} onChange={(event) => setSteps((current) => current.map((item) => item.id === step.id ? { ...item, kind: event.target.value as WorkflowStep["kind"] } : item))}><option value="retrieve">Retrieve</option><option value="reason">Reason</option><option value="act">Act</option><option value="validate">Validate</option><option value="notify">Notify</option></select>{mode === "architect" && <><select aria-label={`Step ${index + 1} flow`} value={step.flow ?? "sequential"} onChange={(event) => setSteps((current) => current.map((item) => item.id === step.id ? { ...item, flow: event.target.value as WorkflowStep["flow"], maxIterations: event.target.value === "loop" ? item.maxIterations ?? 3 : undefined } : item))}><option value="sequential">Sequential</option><option value="parallel">Parallel</option><option value="branch">Conditional branch</option><option value="loop">Bounded loop</option></select><select aria-label={`Step ${index + 1} connector`} value={step.connectorProvider ?? ""} onChange={(event) => setSteps((current) => current.map((item) => item.id === step.id ? { ...item, connectorProvider: event.target.value || undefined } : item))}><option value="">No connector</option>{knowledgeConnectorCatalog.map((item) => <option key={item.provider} value={item.provider}>{item.label}</option>)}</select></>}<label className="gate-check"><input type="checkbox" checked={step.humanGate} disabled={mode === "guided"} onChange={(event) => setSteps((current) => current.map((item) => item.id === step.id ? { ...item, humanGate: event.target.checked } : item))} /><ShieldCheck size={14} /> Gate</label>{mode === "architect" && steps.length > 1 && <button aria-label={`Remove step ${index + 1}`} onClick={() => setSteps((current) => current.filter((item) => item.id !== step.id))}><Trash2 size={14} /></button>}</article>)}</div>
      {mode === "architect" && <button className="text-button" onClick={() => setSteps((current) => [...current, { id: `custom-${Date.now()}`, label: "New bounded step", kind: "reason", humanGate: false, flow: "sequential", dependsOn: current.length ? [current.at(-1)!.id] : [] }])}><Plus size={14} /> Add step</button>}
      <div className="workflow-footer"><div className="credit-preview"><CircleDollarSign size={19} /><span><small>{blueprint ? "Server-owned activation price" : "Draft price estimate"}</small><strong>{blueprint?.estimatedPlatformCredits ?? credits} credits</strong></span></div><div className="workflow-actions"><button className="button secondary" disabled={busy} onClick={() => void save()}><Save size={15} /> Save draft</button>{blueprint && <button className="button primary" disabled={busy || simulation === undefined || simulation === null || !simulation.ready} onClick={() => void purchaseAndActivate()}><Check size={15} /> Buy & activate v{blueprint.version}</button>}</div></div>
      <div className="simulation-card"><FlaskConical size={18} /><div><strong>Preflight simulation</strong>{!blueprint ? <p>Save the draft to simulate its exact server-side plan.</p> : simulation === undefined ? <p>Simulating version {blueprint.version}…</p> : simulation === null ? <p>No saved blueprint found.</p> : <p>{simulation.stages.length} stages · {simulation.estimatedPlatformCredits} credits · inference hard stop ${(simulation.maxInferenceCostCents / 100).toFixed(2)} · {simulation.approvalRequired ? "human approval required" : "no global approval"}</p>}</div>{blueprint && simulation && <span className={simulation.ready ? "ready" : "blocked"}>{simulation.ready ? "READY" : `${simulation.blockers.length} BLOCKER`}</span>}</div>
      {blueprint && simulation && simulation.blockers.length > 0 && <ul className="simulation-blockers">{simulation.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>}
      {versions.length > 0 && <p className="blueprint-history"><GitBranch size={13} /> {versions.length} immutable version{versions.length === 1 ? "" : "s"} · latest digest {versions.at(-1)?.digest}</p>}
      {notice && <p className="knowledge-notice" role="status">{notice}</p>}
    </section>
  );
}
