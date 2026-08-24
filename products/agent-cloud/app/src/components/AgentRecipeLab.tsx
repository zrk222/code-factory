import { useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { Beaker, Check, Gauge, LockKeyhole, Play, ShieldCheck, Sparkles, Trophy } from "lucide-react";

type Props = { agentSpec: Doc<"agentSpecs"> };

const stages = ["Use case", "Evaluation set", "Search space", "Guardrails", "Optimize", "Review"] as const;

const splitList = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);

/** Six-stage assembly surface for bounded, evidence-driven agent recipe optimization. */
export function AgentRecipeLab({ agentSpec }: Props) {
  const response = useQuery(api.recipeLab.getStudy, { agentSpecId: agentSpec._id });
  const result = response && typeof response === "object" && "study" in response && "trials" in response ? response : null;
  const createStudy = useMutation(api.recipeLab.createStudy);
  const startStudy = useMutation(api.recipeLab.startStudy);
  const finalizeStudy = useMutation(api.recipeLab.finalizeStudy);
  const approveChampion = useMutation(api.recipeLab.approveChampion);
  const [useCase, setUseCase] = useState("Answer operational questions with grounded evidence");
  const [evaluationSetRef, setEvaluationSetRef] = useState("object://recipe-evals/operations-v1.jsonl");
  const [evaluationSetDigest, setEvaluationSetDigest] = useState("replace-with-evaluation-set-digest");
  const [models, setModels] = useState("openai/gpt-5, anthropic/claude-sonnet");
  const [retrieval, setRetrieval] = useState("4, 8, 12");
  const [trialCount, setTrialCount] = useState(6);
  const [studyCredits, setStudyCredits] = useState(300);
  const [trialCredits, setTrialCredits] = useState(60);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);

  const counts = useMemo(() => {
    const trials = result?.trials ?? [];
    return { queued: trials.filter((trial) => trial.state === "queued").length, running: trials.filter((trial) => trial.state === "running").length, completed: trials.filter((trial) => trial.state === "completed").length, pruned: trials.filter((trial) => trial.state === "pruned").length };
  }, [result]);

  async function createAndStart() {
    setBusy(true);
    setNotice(null);
    try {
      const created = await createStudy({
        agentSpecId: agentSpec._id, name: `${agentSpec.name} Recipe Lab`, useCase, evaluationSetRef, evaluationSetDigest,
        trialCount, studyCredits, trialCredits, graceCheckpointCount: 2, pruneFloor: 35, minQuality: 75, maxLatencyMs: 30000,
        qualityWeight: 50, costWeight: 30, latencyWeight: 20, modelCandidates: splitList(models),
        retrievalCandidates: splitList(retrieval).map(Number), memoryCandidates: ["run-only", "governed"], authorityCandidates: ["read-only", "approval-required"],
      });
      await startStudy({ studyId: created.studyId });
      setNotice({ tone: "success", text: "Candidate recipes are queued. No recipe is active, and no model was called by the control plane." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Recipe study could not start." });
    } finally { setBusy(false); }
  }

  async function finalize() {
    if (!result) return;
    setBusy(true);
    try {
      const proposed = await finalizeStudy({ studyId: result.study._id });
      setNotice({ tone: proposed.marker === "RECIPE_CHAMPION_PROPOSED" ? "success" : "error", text: proposed.marker === "RECIPE_CHAMPION_PROPOSED" ? "A Pareto-frontier champion is ready for an independent reviewer." : "No eligible recipe satisfied every hard guardrail." });
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "Study could not be finalized." }); }
    finally { setBusy(false); }
  }

  async function approve() {
    if (!result?.study.championDigest) return;
    setBusy(true);
    try {
      await approveChampion({ studyId: result.study._id, expectedRecipeDigest: result.study.championDigest });
      setNotice({ tone: "success", text: "Champion approved. Activation remains a separate human-controlled action." });
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "A distinct reviewer must approve this champion." }); }
    finally { setBusy(false); }
  }

  const allTerminal = result ? counts.queued === 0 && counts.running === 0 : false;

  return <section className="surface recipe-lab" data-evidence="RECIPE_LAB_SIX_STAGES" aria-labelledby="recipe-lab-title">
    <header className="recipe-lab-header">
      <div><p className="kicker">Agent Recipe Lab</p><h2 id="recipe-lab-title">Find the best safe recipe before production</h2><p>Compare models, memory, retrieval, cost, and latency against your evaluation set. Trust rules are hard constraints—not bonus points.</p></div>
      <span><Beaker size={16} /> Sandbox only</span>
    </header>

    <ol className="recipe-stages" aria-label="Recipe Lab stages">
      {stages.map((stage, index) => <li key={stage}><span>{index + 1}</span><strong>{stage}</strong></li>)}
    </ol>

    {!result ? <div className="recipe-config">
      <div className="recipe-fields">
        <label>1. What should this agent do?<textarea value={useCase} onChange={(event) => setUseCase(event.target.value)} maxLength={500} required /></label>
        <label>2. Evaluation-set reference<input value={evaluationSetRef} onChange={(event) => setEvaluationSetRef(event.target.value)} maxLength={500} required /><small>Opaque object reference only. Customer examples stay outside the control-plane record.</small></label>
        <label>Evaluation-set digest<input value={evaluationSetDigest} onChange={(event) => setEvaluationSetDigest(event.target.value)} maxLength={120} required /></label>
        <label>3. Models to compare<input value={models} onChange={(event) => setModels(event.target.value)} maxLength={700} required /><small>Comma-separated allowlist. BYOK bindings remain unchanged.</small></label>
        <label>Retrieval depths<input value={retrieval} onChange={(event) => setRetrieval(event.target.value)} inputMode="numeric" required /></label>
      </div>
      <aside className="recipe-guardrails">
        <p className="kicker">4 / Guardrails</p><h3>Bound the experiment</h3>
        <div><label>Trials<input type="number" min="2" max="24" value={trialCount} onChange={(event) => setTrialCount(Number(event.target.value))} /></label><label>Total credits<input type="number" min="1" max="100000" value={studyCredits} onChange={(event) => setStudyCredits(Number(event.target.value))} /></label><label>Credits / trial<input type="number" min="1" max="10000" value={trialCredits} onChange={(event) => setTrialCredits(Number(event.target.value))} /></label></div>
        <ul><li><ShieldCheck size={15} /> Zero policy violations</li><li><Gauge size={15} /> Quality 50% · cost 30% · latency 20%</li><li><LockKeyhole size={15} /> Independent approval before activation</li></ul>
        <button className="button primary recipe-primary" type="button" disabled={busy} onClick={() => void createAndStart()}><Play size={16} /> {busy ? "Preparing candidates…" : "Optimize within these rails"}</button>
        <small className="recipe-safety-note">The control plane only queues candidates. Trusted hosted workers perform evaluation using your provider bindings.</small>
      </aside>
    </div> : <div className="recipe-results">
      <div className="recipe-scoreboard">
        {[(["Queued", counts.queued, "queued"]), (["Running", counts.running, "running"]), (["Completed", counts.completed, "completed"]), (["Pruned safely", counts.pruned, "pruned"])].map(([label, value, tone]) => <article className={String(tone)} key={String(label)}><small>{label}</small><strong>{value}</strong></article>)}
      </div>
      <div className="recipe-ledger"><Gauge size={18} /><div><strong>{result.study.spentCredits} of {result.study.studyCredits} credits reserved</strong><span>{result.study.status} · {result.study.frontierDigests?.length ?? 0} Pareto-frontier recipes</span></div></div>
      <div className="recipe-trials">{result.trials.map((trial) => <article key={trial._id} className={trial.state}><div><small>Trial {trial.trialNumber}</small><strong>{trial.model}</strong><span>Top {trial.retrievalTopK} · {trial.memoryMode} · {trial.authorityMode}</span></div><b>{trial.state}</b>{trial.qualityScore !== undefined && <dl><div><dt>Quality</dt><dd>{trial.qualityScore}</dd></div><div><dt>Credits</dt><dd>{trial.costCredits}</dd></div><div><dt>Latency</dt><dd>{trial.latencyMs} ms</dd></div></dl>}</article>)}</div>
      {result.study.status === "running" && <button className="button secondary recipe-primary" type="button" disabled={busy || !allTerminal} onClick={() => void finalize()}><Trophy size={16} /> Review eligible recipes</button>}
      {result.study.status === "review" && result.study.championDigest && <div className="recipe-champion"><Trophy size={24} /><div><small>Proposed champion</small><strong>{result.study.championDigest}</strong><p>Pareto eligible. A reviewer other than the creator must approve the exact digest.</p></div><button className="button primary recipe-primary" type="button" disabled={busy} onClick={() => void approve()}><Check size={16} /> Approve champion</button></div>}
      {result.study.status === "approved" && <div className="recipe-approved"><Sparkles size={20} /><div><strong>Champion approved—not activated</strong><span>Deployment remains a separate human-controlled operation.</span></div></div>}
    </div>}
    {notice && <div className={`recipe-notice ${notice.tone}`} role="status">{notice.text}</div>}
  </section>;
}
