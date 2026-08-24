import { useMemo, useState } from "react";
import { useMutation } from "convex/react";
import { Ban, Check, Clock3, CloudCog, CookingPot, Play, ShieldCheck, Sparkles } from "lucide-react";
import type { Doc, Id } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { recommendRuntimeEngines, runtimeCapabilityRegistry, type RuntimeEngine } from "../../runtime/runtimeAdapter";
import { RuntimeJobIntelligence } from "./RuntimeJobIntelligence";

type Props = {
  agentSpec: Doc<"agentSpecs">;
  blueprint: Doc<"agentBlueprints"> | null;
  jobs: Doc<"executionJobs">[];
  adapters: Doc<"runtimeAdapters">[];
};

export function HostedRuntimeLauncher({ agentSpec, blueprint, jobs, adapters }: Props) {
  const enqueue = useMutation(api.execution.enqueue);
  const cancel = useMutation(api.execution.cancel);
  const configure = useMutation(api.runtimeAdapters.configure);
  const recommended = useMemo(() => recommendRuntimeEngines({
    streaming: true,
    suspendResume: blueprint?.steps.some((step) => step.humanGate) ?? true,
    multiAgent: blueprint?.steps.some((step) => step.flow === "parallel") ?? false,
    traces: blueprint?.evidenceLevel === "full",
    preferNative: true,
  }), [blueprint]);
  const [engine, setEngine] = useState<RuntimeEngine>(() => adapters.find((item) => item.status === "ready")?.engine ?? recommended[0].engine);
  const [label, setLabel] = useState("Primary governed runtime");
  const [endpointRef, setEndpointRef] = useState("env:MASTRA_SERVER_URL");
  const [secretRef, setSecretRef] = useState("env:MASTRA_API_TOKEN");
  const [targetId, setTargetId] = useState("agent-oven-worker");
  const [environment, setEnvironment] = useState<"sandbox" | "production">("sandbox");
  const [selectedAdapterId, setSelectedAdapterId] = useState<string>(() => adapters.find((item) => item.status === "ready")?._id ?? "");
  const [inputRef, setInputRef] = useState("object://agent-inputs/example.json");
  const [inputDigest, setInputDigest] = useState("input-digest-preview");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedCapability = runtimeCapabilityRegistry.find((item) => item.engine === engine)!;
  const selectedAdapter = adapters.find((item) => item._id === selectedAdapterId);

  function selectEngine(next: RuntimeEngine) {
    setEngine(next);
    const prefix = next === "mastra" ? "MASTRA" : next.toUpperCase().replaceAll("-", "_");
    setEndpointRef(`env:${prefix}_SERVER_URL`);
    setSecretRef(`env:${prefix}_API_TOKEN`);
    setTargetId(next === "mastra" ? "agent-oven-worker" : "agent-oven-bridge");
  }

  async function saveAdapter() {
    setBusy(true); setNotice(null);
    try {
      const result = await configure({ agentSpecId: agentSpec._id, engine, label, endpointRef, secretRef: secretRef || undefined, targetId, environment });
      setNotice(`${result.marker}: configuration saved. A trusted worker must validate reachability before runs can use it.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Runtime configuration failed."); }
    finally { setBusy(false); }
  }

  async function launch() {
    if (!blueprint) return;
    setBusy(true); setNotice(null);
    try {
      const result = await enqueue({ blueprintId: blueprint._id, runtimeAdapterId: selectedAdapterId ? selectedAdapterId as Id<"runtimeAdapters"> : undefined, idempotencyKey: `ui:${blueprint._id}:${inputDigest}:${selectedAdapterId || "native"}`, inputRef, inputDigest, maxAttempts: 3 });
      setNotice(`${result.marker}: ${result.runtimeEngine ?? "Agent Oven native"} job ${result.jobId} is ${result.status ?? "queued"}.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Hosted launch failed."); }
    finally { setBusy(false); }
  }

  return <section className="runtime-launcher surface" aria-labelledby="runtime-title">
    <header><div><p className="kicker">Runtime Kitchen / execution plane</p><h2 id="runtime-title">Choose the engine. Keep Agent Oven in control.</h2><p>The recipe remains portable. Engine, hosting, credential references, durability, and proof transport can change without changing its governance contract.</p></div><span><ShieldCheck size={16} /> Platform enforced</span></header>

    <div className="runtime-kitchen">
      <div className="runtime-kitchen-heading"><span><CookingPot size={19} /></span><div><strong>Recommended for this recipe</strong><small>{recommended[0].label} · {recommended[0].reasons.join(" · ")}</small></div></div>
      <div className="runtime-engine-grid" role="radiogroup" aria-label="Runtime engine">
        {recommended.map((item) => <button key={item.engine} type="button" role="radio" aria-checked={engine === item.engine} disabled={!item.eligible} className={engine === item.engine ? "selected" : ""} onClick={() => selectEngine(item.engine)}><span>{item.nativeAdapter ? <Sparkles size={14} /> : <CloudCog size={14} />}{item.nativeAdapter ? "Native" : "Bridge"}</span><strong>{item.label}</strong><small>{item.eligible ? item.reasons.join(" · ") || "General runtime" : item.reasons.filter((reason) => reason.startsWith("missing")).join(" · ")}</small>{engine === item.engine && <Check size={15} />}</button>)}
      </div>
      <div className="runtime-capabilities"><span>{selectedCapability.transport}</span><span>{selectedCapability.streaming ? "Streaming" : "Batch"}</span><span>{selectedCapability.suspendResume ? "Durable resume" : "Restart on resume"}</span><span>{selectedCapability.multiAgent ? "Multi-agent" : "Single agent"}</span><span>{selectedCapability.traces ? "Trace export" : "Result proof"}</span></div>
      <div className="runtime-config-grid"><label>Configuration label<input value={label} onChange={(event) => setLabel(event.target.value)} /></label><label>Hosting<select value={environment} onChange={(event) => setEnvironment(event.target.value as typeof environment)}><option value="sandbox">Sandbox</option><option value="production">Production</option></select></label><label>Endpoint reference<input value={endpointRef} onChange={(event) => setEndpointRef(event.target.value)} /></label><label>Secret reference<input value={secretRef} onChange={(event) => setSecretRef(event.target.value)} /></label><label>Runtime target ID<input value={targetId} onChange={(event) => setTargetId(event.target.value)} /></label><button className="button secondary" disabled={busy} onClick={() => void saveAdapter()}>Save runtime configuration</button></div>
      <p className="runtime-boundary"><ShieldCheck size={14} /> References only. Agent Oven never stores resolved endpoints or bearer values. Configuration is not marked ready until a trusted worker validates the exact digest.</p>
    </div>

    <div className="runtime-controls"><label>Validated runtime<select value={selectedAdapterId} onChange={(event) => setSelectedAdapterId(event.target.value)}><option value="">Agent Oven native test job</option>{adapters.map((adapter) => <option key={adapter._id} value={adapter._id} disabled={adapter.status !== "ready"}>{adapter.label} · {adapter.engine} · {adapter.status}</option>)}</select></label><label>Input object reference<input value={inputRef} onChange={(event) => setInputRef(event.target.value)} /></label><label>Input digest<input value={inputDigest} onChange={(event) => setInputDigest(event.target.value)} /></label><button className="button primary" disabled={busy || !blueprint || blueprint.status !== "active" || Boolean(selectedAdapterId && selectedAdapter?.status !== "ready")} onClick={() => void launch()}><Play size={15} /> Queue governed run</button></div>
    {!blueprint || blueprint.status !== "active" ? <p className="runtime-blocked"><Ban size={14} /> Save, purchase, and activate a ready blueprint before queueing work.</p> : null}
    <div className="runtime-jobs">{jobs.length === 0 ? <div><CloudCog size={20} /><strong>No hosted jobs yet</strong><small>The first digest-bound job will appear here.</small></div> : jobs.map((job) => <article key={job._id}><span className={`runtime-state ${job.status}`}>{job.status}</span><strong>{job.inputDigest}</strong><small>{job.runtimeEngine ?? "agent-oven-native"} · {job.quotedRuntimeCredits} credits · attempt {job.attemptCount}/{job.maxAttempts}{job.runtimePresetVersion ? ` · preset v${job.runtimePresetVersion}` : ""}</small><time><Clock3 size={12} /> {new Date(job.createdAt).toLocaleString()}</time>{["queued", "running", "suspended"].includes(job.status) && <button className="text-button" onClick={() => void cancel({ jobId: job._id })}><Ban size={13} /> Cancel</button>}<RuntimeJobIntelligence job={job} /></article>)}</div>
    {notice && <p className="knowledge-notice" role="status">{notice}</p>}
  </section>;
}
