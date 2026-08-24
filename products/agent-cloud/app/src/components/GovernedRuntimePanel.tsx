import { useEffect, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { BrainCircuit, CheckCircle2, Filter, Gauge, LockKeyhole, SearchCheck } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";

const split = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
const optional = (value: string) => value || undefined;
const optionalNumber = (value: string) => value ? Number(value) : undefined;

export function GovernedRuntimePanel({ agentSpec }: { agentSpec: Doc<"agentSpecs"> }) {
  const preset = useQuery(api.agentIntelligence.getPreset, { agentSpecId: agentSpec._id });
  const savePreset = useMutation(api.agentIntelligence.savePreset);
  const publishPreset = useMutation(api.agentIntelligence.publishPreset);
  const [channel, setChannel] = useState<"frozen" | "managed">("frozen");
  const [models, setModels] = useState("openai/gpt-5, anthropic/claude-sonnet");
  const [tools, setTools] = useState("knowledge.search, artifact.write, human.approval");
  const [workflows, setWorkflows] = useState("plan-gather-check-act, creator-validator");
  const [allowDomains, setAllowDomains] = useState("");
  const [denyDomains, setDenyDomains] = useState("");
  const [country, setCountry] = useState("");
  const [region, setRegion] = useState("");
  const [city, setCity] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [latitude, setLatitude] = useState("");
  const [longitude, setLongitude] = useState("");
  const [radius, setRadius] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!preset || !Array.isArray(preset.allowedModels)) return;
    setChannel(preset.updateChannel); setModels(preset.allowedModels.join(", ")); setTools(preset.allowedTools.join(", ")); setWorkflows(preset.allowedWorkflows.join(", ")); setAllowDomains(preset.sourceAllowDomains.join(", ")); setDenyDomains(preset.sourceDenyDomains.join(", ")); setCountry(preset.country ?? ""); setRegion(preset.region ?? ""); setCity(preset.city ?? ""); setFromDate(preset.sourceFromDate ?? ""); setToDate(preset.sourceToDate ?? ""); setLatitude(preset.latitude?.toString() ?? ""); setLongitude(preset.longitude?.toString() ?? ""); setRadius(preset.radiusKm?.toString() ?? "");
  }, [preset]);

  async function save() {
    setBusy(true); setNotice(null);
    try {
      const result = await savePreset({ agentSpecId: agentSpec._id, name: "Safe business operations", updateChannel: channel, maxSteps: 24, maxInputTokens: 120000, maxOutputTokens: 12000, maxReasoningTokens: 24000, allowedModels: split(models), allowedTools: split(tools), allowedWorkflows: split(workflows), sourceAllowDomains: split(allowDomains), sourceDenyDomains: split(denyDomains), recencyDays: 30, sourceFromDate: optional(fromDate), sourceToDate: optional(toDate), country: optional(country), region: optional(region), city: optional(city), latitude: optionalNumber(latitude), longitude: optionalNumber(longitude), radiusKm: optionalNumber(radius), requireClarification: true, rubricVersion: "agent-oven.runtime-rubric.v1" });
      setNotice(`Preset v${result.version} saved as a draft. Review and publish it before hosted work.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not save runtime preset."); }
    finally { setBusy(false); }
  }

  async function publish() {
    if (!preset) return;
    setBusy(true); setNotice(null);
    try { const result = await publishPreset({ presetId: preset._id, expectedDigest: preset.digest }); setNotice(`Preset v${result.version} published and frozen to digest ${result.digest}.`); }
    catch (error) { setNotice(error instanceof Error ? error.message : "Could not publish runtime preset."); }
    finally { setBusy(false); }
  }

  return <section className="governed-runtime surface" aria-labelledby="runtime-policy-title">
    <header className="governed-runtime-header"><div><p className="kicker">Runtime recipe / explainable by design</p><h2 id="runtime-policy-title">Choose the rails before the agent runs.</h2><p>This preset pins what the agent may use, how long it may reason, what sources it may trust, and how every result will be scored.</p></div><span className={preset?.status === "published" ? "ready" : "draft"}><LockKeyhole size={14} /> {preset?.status ?? "not configured"}</span></header>
    <div className="runtime-pattern-grid">
      <article><BrainCircuit size={19} /><strong>Plan, gather, check, act</strong><small>Clarifies first, shows progress and contradictions, then acts only when evidence is sufficient.</small></article>
      <article><Gauge size={19} /><strong>Exact usage</strong><small>Cached, input, output and reasoning tokens, direct provider cost, latency and tool steps.</small></article>
      <article><SearchCheck size={19} /><strong>Component scores</strong><small>Retrieval, planning, accuracy, completeness, citations, connectors and compliance stay separate.</small></article>
      <article><CheckCircle2 size={19} /><strong>Durable resume</strong><small>Long work pauses to a digest-bound snapshot and resumes without repeating completed steps.</small></article>
    </div>
    <div className="runtime-policy-row"><label>Update channel<select value={channel} onChange={(event) => setChannel(event.target.value as typeof channel)}><option value="frozen">Frozen — explicit upgrades</option><option value="managed">Managed — stable cost/latency band</option></select></label><div className="runtime-ceilings"><span><b>24</b> tool steps</span><span><b>120k</b> input</span><span><b>12k</b> output</span><span><b>24k</b> reasoning</span></div></div>
    <details><summary><Filter size={14} /> Advanced allowlists and source policy</summary><div className="runtime-advanced"><label>Allowed models<input value={models} onChange={(event) => setModels(event.target.value)} /></label><label>Allowed tools<input value={tools} onChange={(event) => setTools(event.target.value)} /></label><label>Allowed workflows<input value={workflows} onChange={(event) => setWorkflows(event.target.value)} /></label><label>Allow web domains<input placeholder="docs.company.com, regulator.gov" value={allowDomains} onChange={(event) => setAllowDomains(event.target.value)} /></label><label>Deny web domains<input placeholder="untrusted.example" value={denyDomains} onChange={(event) => setDenyDomains(event.target.value)} /></label><div className="form-row"><label>From date<input type="date" value={fromDate} onChange={(event) => setFromDate(event.target.value)} /></label><label>To date<input type="date" value={toDate} onChange={(event) => setToDate(event.target.value)} /></label></div><div className="form-row"><label>Country<input value={country} onChange={(event) => setCountry(event.target.value)} /></label><label>Region<input value={region} onChange={(event) => setRegion(event.target.value)} /></label><label>City<input value={city} onChange={(event) => setCity(event.target.value)} /></label></div><div className="form-row"><label>Latitude<input inputMode="decimal" value={latitude} onChange={(event) => setLatitude(event.target.value)} /></label><label>Longitude<input inputMode="decimal" value={longitude} onChange={(event) => setLongitude(event.target.value)} /></label><label>Radius km<input inputMode="numeric" value={radius} onChange={(event) => setRadius(event.target.value)} /></label></div></div></details>
    <div className="workflow-footer"><p className="runtime-footnote">Required clarifications, redacted traces, editable artifacts, component evals and operations-manual compliance are always on.</p><div className="workflow-actions"><button className="button secondary" disabled={busy} onClick={() => void save()}>Save preset</button><button className="button primary" disabled={busy || !preset || preset.status !== "draft"} onClick={() => void publish()}>Publish exact v{preset?.version ?? "—"}</button></div></div>
    {preset && <p className="blueprint-history"><LockKeyhole size={13} /> v{preset.version} · {preset.updateChannel} · digest {preset.digest}</p>}{notice && <p className="knowledge-notice" role="status">{notice}</p>}
  </section>;
}
