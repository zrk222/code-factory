import { useState } from "react";
import { useMutation } from "convex/react";
import { ArrowRight, Bot, BrainCircuit, CheckCircle2, CircleAlert, Code2, KeyRound, Network, ShieldCheck, Sparkles } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import type { CompiledAgentIntent, ComposerInferenceAccess, ComposerRuntimePreference } from "../../convex/agentComposerDomain";

type Compilation = CompiledAgentIntent & { draftId: Doc<"agentCompositionDrafts">["_id"]; fingerprint: string; rawDescriptionStored: false };

const runtimeChoices: { id: ComposerRuntimePreference; title: string; summary: string; Icon: typeof Bot }[] = [
  { id: "auto", title: "Best fit", summary: "Let the compiler choose from the work pattern.", Icon: Sparkles },
  { id: "agent-oven-native", title: "Agent Oven", summary: "Smallest governed hosted path.", Icon: Bot },
  { id: "langgraph", title: "LangGraph", summary: "State, checkpoints, branches, interrupts.", Icon: Network },
  { id: "mastra", title: "Mastra", summary: "TypeScript tools, workflows, workspaces, MCP.", Icon: Code2 },
];

const quickStarts = [
  { label: "Review a code change", description: "Review GitHub pull requests, read the changed requirements and tests, prepare a proof summary within 10 minutes, never merge code, stop on missing evidence, and send failed or unknown checks to a human reviewer." },
  { label: "Triage support", description: "Read new support tickets and approved product documentation, propose a clear response within 15 minutes, never issue refunds or send a reply without approval, stop on missing account facts, and escalate security or billing issues." },
  { label: "Reconcile records", description: "Compare approved database records and uploaded source files, list every mismatch with source evidence, never modify production data, finish when all records are matched or explicitly unknown, and escalate access errors or ambiguous fields." },
] as const;

export function IntentComposer({ agentSpec }: { agentSpec: Doc<"agentSpecs"> }) {
  const compileIntent = useMutation(api.agentComposer.compile);
  const saveBlueprint = useMutation(api.blueprints.save);
  const markApplied = useMutation(api.agentComposer.markApplied);
  const [description, setDescription] = useState("");
  const [runtime, setRuntime] = useState<ComposerRuntimePreference>("auto");
  const [inference, setInference] = useState<ComposerInferenceAccess>("agent-oven-api");
  const [compiled, setCompiled] = useState<Compilation | null>(null);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function compile(brief = description) {
    setBusy(true); setNotice(null);
    try {
      const result = await compileIntent({ agentSpecId: agentSpec._id, description: brief, runtimePreference: runtime, inferenceAccess: inference });
      setCompiled(result as Compilation);
      setAnswers({});
      setNotice(result.readiness === "ready-for-draft" ? "Portable draft ready. Review the graph and proof contract before saving." : "The draft is intentionally paused for missing decisions. Add the answers to your brief and compile again.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "The intent could not be compiled."); }
    finally { setBusy(false); }
  }

  function startWith(description: string) {
    setDescription(description);
    setCompiled(null);
    setAnswers({});
    setNotice("Example loaded. Change any words so the agent matches your job, then build the plan.");
  }

  async function answerAndRecompile() {
    if (!compiled || compiled.clarificationQuestions.some((question) => !answers[question]?.trim())) return;
    const additions = compiled.clarificationQuestions.map((question) => `${question} ${answers[question].trim()}`).join("\n");
    const enriched = `${description.trim()}\n\nAdditional requirements:\n${additions}`;
    setDescription(enriched);
    await compile(enriched);
  }

  async function save() {
    if (!compiled || compiled.readiness !== "ready-for-draft") return;
    setBusy(true); setNotice(null);
    try {
      const result = await saveBlueprint({
        agentSpecId: agentSpec._id,
        templateId: "custom-intent",
        name: compiled.title,
        mode: "architect",
        triggerKind: "manual",
        triggerLabel: "Authorized user or agent starts a run",
        steps: compiled.steps,
        memoryPolicy: compiled.memoryPolicy,
        modelPolicy: "auto",
        authorityPolicy: compiled.authorityPolicy,
        evidenceLevel: "full",
        hardBudgetCents: 2500,
        runtimeEngine: compiled.selectedRuntime,
        inferenceAccess: compiled.inferenceAccess,
      });
      await markApplied({ draftId: compiled.draftId, blueprintId: result.blueprintId, expectedCompilerDigest: compiled.compilerDigest });
      setNotice(`Blueprint v${result.version} saved with ${compiled.selectedRuntime}. It is still a draft; simulation, adapter validation, credits, and human activation remain required.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "The blueprint could not be saved."); }
    finally { setBusy(false); }
  }

  return <section className="intent-composer surface" aria-labelledby="intent-composer-title">
    <header className="intent-composer-header">
      <div><p className="kicker">No agent jargon required</p><h2 id="intent-composer-title">Build an agent in plain English.</h2><p>Describe the job like you would explain it to a new teammate. Agent Oven chooses the setup, asks only what is missing, and shows you the full plan before anything can run.</p></div>
      <span className="portable-badge"><BrainCircuit size={15} /> Guided Agent Builder</span>
    </header>

    <ol className="composer-progress" aria-label="Agent building progress">
      <li className="active"><b>1</b><span><strong>Describe</strong><small>What should it finish?</small></span></li>
      <li className={compiled ? "active" : ""}><b>2</b><span><strong>Review</strong><small>See the plan and safeguards</small></span></li>
      <li className={compiled?.readiness === "ready-for-draft" ? "active" : ""}><b>3</b><span><strong>Save</strong><small>Create a draft, not a live agent</small></span></li>
    </ol>

    <div className="composer-layout">
      <form className="composer-brief" onSubmit={(event) => { event.preventDefault(); void compile(); }}>
        <div className="composer-quick-start"><span>Start with an example</span><div>{quickStarts.map((item) => <button type="button" key={item.label} onClick={() => startWith(item.description)}>{item.label}</button>)}</div></div>
        <label htmlFor="agent-intent">What do you want your agent to do?</label>
        <p className="field-help">Include what “done” means, what it may read or change, and when a person should step in. Ordinary language is perfect.</p>
        <textarea id="agent-intent" value={description} onChange={(event) => setDescription(event.target.value)} minLength={40} maxLength={2400} required placeholder="Example: Review every new pull request, check the changed requirements and tests, never merge code, and send anything uncertain to a reviewer." />
        <div className="composer-counter"><span>No raw brief is stored—only its digest and compiled controls.</span><b>{description.length}/2400</b></div>

        <details className="composer-advanced"><summary>Advanced choices <small>Automatic is recommended</small></summary><div>
          <fieldset><legend>How should it run?</legend><div className="runtime-choice-grid">{runtimeChoices.map(({ id, title, summary, Icon }) => <label className={runtime === id ? "selected" : ""} key={id}><input type="radio" name="runtime" value={id} checked={runtime === id} onChange={() => setRuntime(id)} /><Icon size={18} /><span><strong>{title}</strong><small>{summary}</small></span></label>)}</div></fieldset>
          <fieldset><legend>Who supplies the AI model?</legend><div className="inference-choice-grid">
            <label className={inference === "agent-oven-api" ? "selected" : ""}><input type="radio" name="inference" checked={inference === "agent-oven-api"} onChange={() => setInference("agent-oven-api")} /><Sparkles size={18} /><span><strong>Agent Oven handles it</strong><small>The simplest choice. A verified provider route is required before a live run.</small></span></label>
            <label className={inference === "byok" ? "selected" : ""}><input type="radio" name="inference" checked={inference === "byok"} onChange={() => setInference("byok")} /><KeyRound size={18} /><span><strong>Use my own model key</strong><small>The key stays in a protected server reference, never in this page or blueprint.</small></span></label>
          </div></fieldset>
        </div></details>
        <button className="button primary composer-compile" disabled={busy || description.trim().length < 40} type="submit">{busy ? "Building your plan…" : "Build my agent plan"} <ArrowRight size={16} /></button>
      </form>

      <aside className="composer-result" aria-live="polite">
        {!compiled ? <div className="composer-empty"><Network size={28} /><h3>Your agent plan will appear here.</h3><p>You will see what it does, where a person stays in control, what proves success, and anything still missing.</p></div> : <>
          <div className="composer-result-head"><span className={compiled.readiness === "ready-for-draft" ? "ready" : "blocked"}>{compiled.readiness === "ready-for-draft" ? <CheckCircle2 size={14} /> : <CircleAlert size={14} />}{compiled.readiness.replaceAll("-", " ")}</span><small>digest {compiled.compilerDigest.slice(0, 12)}</small></div>
          <h3>{compiled.title}</h3>
          <div className="plain-agent-summary"><small>What your agent will do</small><ul><li>{compiled.memoryPolicy === "governed" ? "Use only approved project knowledge and sources." : "Use only the information available for this run."}</li><li>{compiled.authorityPolicy === "approval-required" ? "Pause for a person before any important action." : "Prepare work inside the limits you described."}</li><li>Check the finished result against visible evidence before reporting success.</li></ul></div>
          <details className="runtime-decision"><summary><Network size={19} /><span><small>Automatic setup</small><strong>{compiled.selectedRuntime}</strong></span></summary><p>{compiled.runtimeRationale}</p></details>
          <div className="compiled-graph">{compiled.steps.map((step, index) => <article key={step.id}><b>{index + 1}</b><span><strong>{step.label}</strong><small>{step.kind} · {step.flow}{step.maxIterations ? ` ≤ ${step.maxIterations}` : ""}</small></span>{step.humanGate && <em><ShieldCheck size={12} /> human gate</em>}</article>)}</div>
          {compiled.clarificationQuestions.length > 0 && <div className="composer-questions"><strong>A few details will make this agent reliable</strong><p>Answer in your own words. Agent Oven will add the safeguards for you.</p>{compiled.clarificationQuestions.map((question, index) => <label key={question} htmlFor={`composer-answer-${index}`}><span>{question}</span><textarea id={`composer-answer-${index}`} value={answers[question] ?? ""} onChange={(event) => setAnswers((current) => ({ ...current, [question]: event.target.value }))} placeholder="Type a short answer…" /></label>)}<button type="button" className="button secondary" disabled={busy || compiled.clarificationQuestions.some((question) => !answers[question]?.trim())} onClick={() => void answerAndRecompile()}>Add details and update plan</button></div>}
          <details className="proof-contract"><summary>How Agent Oven will check success ({compiled.evidenceChecks.length})</summary><ul>{compiled.evidenceChecks.map((check) => <li key={check}>{check}</li>)}</ul></details>
          <button className="button secondary composer-save" disabled={busy || compiled.readiness !== "ready-for-draft"} onClick={() => void save()}>Save agent draft</button>
          <p className="composer-boundary"><strong>You stay in control.</strong> Saving creates a draft, not a live agent. Agent Oven still checks connections, model access, budget, and your approval before a run.</p>
        </>}
      </aside>
    </div>
    {notice && <p className="knowledge-notice" role="status">{notice}</p>}
  </section>;
}
