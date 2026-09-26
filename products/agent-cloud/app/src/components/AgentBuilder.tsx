import { useEffect, useMemo, useState } from "react";
import { useMutation } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { BookOpenCheck, Braces, Check, ChevronRight, CircleDot, Cpu, Database, FlaskConical, GitBranch, Play, ShieldCheck, Sparkles, WalletCards } from "lucide-react";
import { TemplateCatalog } from "./TemplateCatalog";
import { KnowledgeWall } from "./KnowledgeWall";
import { businessTemplates, type BusinessTemplate } from "../templates";
import { WorkflowAssembler } from "./WorkflowAssembler";
import { HostedRuntimeLauncher } from "./HostedRuntimeLauncher";
import { BookedJobConcierge } from "./BookedJobConcierge";
import { GovernedRuntimePanel } from "./GovernedRuntimePanel";
import { DatabaseToolPanel } from "./DatabaseToolPanel";
import { AgentRecipeLab } from "./AgentRecipeLab";
import { IntentComposer } from "./IntentComposer";

type Props = {
  agentSpec: Doc<"agentSpecs">;
  blueprint: Doc<"agentBlueprints"> | null;
  blueprintVersions: Doc<"agentBlueprintVersions">[];
  executionJobs: Doc<"executionJobs">[];
  runtimeAdapters: Doc<"runtimeAdapters">[];
  routes: Doc<"providerRoutes">[];
  memories: Doc<"memories">[];
  connectors: Doc<"knowledgeConnectors">[];
  creditAccount: Doc<"creditAccounts"> | null;
  inferenceBinding: Doc<"inferenceBindings"> | null;
};

const ingredients = [
  ["Job", "PR assurance", GitBranch],
  ["Knowledge", "Repository + ADRs", Database],
  ["Memory", "Architecture history", Sparkles],
  ["Authority", "Approval required", ShieldCheck],
  ["Budget", "Hard stop", WalletCards],
  ["Playbook", "Knowledge Wall", BookOpenCheck],
] as const;

type AdvancedPanel = "runtime" | "database" | "recipe" | "hosted";

export function AgentBuilder({ agentSpec, blueprint, blueprintVersions, executionJobs, runtimeAdapters, routes, memories, connectors, creditAccount, inferenceBinding }: Props) {
  const saveAgentSpec = useMutation(api.control.saveAgentSpec);
  const launchRun = useMutation(api.control.launchRun);
  const [repository, setRepository] = useState(agentSpec.repository);
  const [providerProfile, setProviderProfile] = useState(agentSpec.providerProfile);
  const [memoryMode, setMemoryMode] = useState(agentSpec.memoryMode);
  const [authorityMode, setAuthorityMode] = useState(agentSpec.authorityMode);
  const [hardBudget, setHardBudget] = useState((agentSpec.hardBudgetCents / 100).toFixed(2));
  const [branch, setBranch] = useState("feature/receipt-hardening");
  const [commitSha, setCommitSha] = useState("7b5e9f4c1d3a6b8e2f0a9c4d7e1b6a3c5d8f2e4a");
  const [estimate, setEstimate] = useState("1.27");
  const [taskKind, setTaskKind] = useState<"analyze-evidence" | "draft-change" | "merge-proposal">("merge-proposal");
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [advancedPanel, setAdvancedPanel] = useState<AdvancedPanel>("runtime");
  const [selectedTemplate, setSelectedTemplate] = useState<BusinessTemplate>(() => {
    const remembered = window.localStorage.getItem("agent-oven:selected-template");
    return businessTemplates.find((template) => template.id === remembered) ?? businessTemplates[0];
  });

  useEffect(() => {
    setRepository(agentSpec.repository);
    setProviderProfile(agentSpec.providerProfile);
    setMemoryMode(agentSpec.memoryMode);
    setAuthorityMode(agentSpec.authorityMode);
    setHardBudget((agentSpec.hardBudgetCents / 100).toFixed(2));
  }, [agentSpec]);

  const activeRoute = useMemo(() => routes.find((route) => route.profile === providerProfile), [providerProfile, routes]);
  const budgetCents = Math.round(Number(hardBudget) * 100);
  const estimateCents = Math.round(Number(estimate) * 100);
  const overBudget = Number.isFinite(estimateCents) && Number.isFinite(budgetCents) && estimateCents > budgetCents;

  function applyTemplate(template: BusinessTemplate) {
    setSelectedTemplate(template);
    window.localStorage.setItem("agent-oven:selected-template", template.id);
    setRepository(template.repositoryHint);
    setProviderProfile(template.tier === "Premium trust" ? "highest-quality" : "balanced");
    setMemoryMode(template.memory);
    setAuthorityMode(template.authority);
    setHardBudget(template.hardBudgetDollars.toFixed(2));
    setNotice({ tone: "success", text: `${template.title} defaults applied. Review and save when ready; nothing has run.` });
  }

  async function save() {
    setBusy(true);
    setNotice(null);
    try {
      const result = await saveAgentSpec({
        agentSpecId: agentSpec._id,
        repository,
        providerProfile,
        memoryMode,
        authorityMode,
        hardBudgetCents: budgetCents,
        validators: agentSpec.validators,
      });
      setNotice({ tone: "success", text: `AgentSpec v${result.version} saved to Convex.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Could not save the AgentSpec." });
    } finally {
      setBusy(false);
    }
  }

  async function launch() {
    setBusy(true);
    setNotice(null);
    try {
      const result = await launchRun({
        agentSpecId: agentSpec._id,
        branch,
        commitSha,
        estimatedCostCents: estimateCents,
        taskKind,
      });
      setNotice({ tone: "success", text: `${result.marker}: six assurance gates completed; adversarial verdict is ${result.reviewVerdict}.` });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Run launch failed.";
      setNotice({ tone: "error", text: message.includes("E_BUDGET_EXCEEDED") ? "Blocked before spend: estimate exceeds the hard budget." : message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="builder-title" className="page-stack">
      <header className="page-heading">
        <div>
          <p className="eyebrow">Agent builder / PR assurance</p>
          <h1 id="builder-title">Configure the job. Lock the rails.</h1>
          <p>One canonical AgentSpec controls model route, memory scope, authority, validators, and maximum spend.</p>
        </div>
        <div className="version-stamp"><Braces size={16} /> AgentSpec v{agentSpec.version}</div>
      </header>

      <AutomationCommandCenter
        blueprint={blueprint}
        connectors={connectors}
        executionJobs={executionJobs}
        creditAccount={creditAccount}
        inferenceBinding={inferenceBinding}
        onOpenPanel={setAdvancedPanel}
      />

      <IntentComposer agentSpec={agentSpec} />
      <TemplateCatalog onApply={applyTemplate} />
      {selectedTemplate.id === "booked-job-concierge" ? <BookedJobConcierge agentSpec={agentSpec} /> : <>
      <WorkflowAssembler agentSpec={agentSpec} template={selectedTemplate} blueprint={blueprint} versions={blueprintVersions} />
      <div className="advanced-automation surface" aria-labelledby="advanced-automation-title">
        <header className="advanced-automation-header">
          <div><p className="kicker">Automation ops / expert controls</p><h2 id="advanced-automation-title">Tune one control surface at a time.</h2><p>Novice setup stays above. Enterprise operators can publish runtime presets, bind database operations, optimize recipes, and queue hosted jobs here.</p></div>
          <div className="advanced-tabs" aria-label="Advanced automation panels">
            {([
              ["runtime", "Runtime rails", ShieldCheck],
              ["database", "Database ops", Database],
              ["recipe", "Recipe Lab", FlaskConical],
              ["hosted", "Hosted runs", Play],
            ] as const).map(([id, label, Icon]) => <button key={id} className={advancedPanel === id ? "active" : ""} aria-pressed={advancedPanel === id} onClick={() => setAdvancedPanel(id)}><Icon size={15} /> {label}</button>)}
          </div>
        </header>
        <div className="advanced-panel-body">
          {advancedPanel === "runtime" && <GovernedRuntimePanel agentSpec={agentSpec} />}
          {advancedPanel === "database" && <DatabaseToolPanel agentSpec={agentSpec} />}
          {advancedPanel === "recipe" && <AgentRecipeLab agentSpec={agentSpec} />}
          {advancedPanel === "hosted" && <HostedRuntimeLauncher agentSpec={agentSpec} blueprint={blueprint} jobs={executionJobs} adapters={runtimeAdapters} />}
        </div>
      </div>

      <div className="ingredient-rail" aria-label="Agent configuration ingredients">
        {ingredients.map(([label, value, Icon], index) => (
          <div className="ingredient" key={label}>
            <span className="ingredient-icon"><Icon size={17} /></span>
            <span><small>{label}</small><strong>{value}</strong></span>
            {index < ingredients.length - 1 && <ChevronRight className="ingredient-arrow" size={16} aria-hidden="true" />}
          </div>
        ))}
      </div>

      <div className="builder-grid">
        <form className="surface form-surface" onSubmit={(event) => { event.preventDefault(); void save(); }}>
          <div className="surface-header">
            <div><p className="kicker">01 / Define</p><h2>Agent contract</h2></div>
            <span className="status-dot active">Active</span>
          </div>
          <label>Repository<input value={repository} onChange={(event) => setRepository(event.target.value)} maxLength={200} required /></label>
          <div className="form-row">
            <label>Model route<select value={providerProfile} onChange={(event) => setProviderProfile(event.target.value as typeof providerProfile)}>
              <option value="economy">Economy</option><option value="balanced">Balanced</option><option value="highest-quality">Highest quality</option>
            </select></label>
            <label>Memory<select value={memoryMode} onChange={(event) => setMemoryMode(event.target.value as typeof memoryMode)}>
              <option value="run-only">This run only</option><option value="architecture-history">Architecture history</option>
            </select></label>
          </div>
          <div className="form-row">
            <label>Authority<select value={authorityMode} onChange={(event) => setAuthorityMode(event.target.value as typeof authorityMode)}>
              <option value="read-only">Read only</option><option value="propose">Propose only</option><option value="approval-required">Approval required</option>
            </select></label>
            <label>Hard budget / run<div className="money-input"><span>$</span><input inputMode="decimal" value={hardBudget} onChange={(event) => setHardBudget(event.target.value)} required /></div></label>
          </div>
          <div className="route-card">
            <Cpu size={20} /><div><small>Active provider route</small><strong>{activeRoute ? `${activeRoute.primaryProvider} / ${activeRoute.primaryModel}` : "Not configured"}</strong><p>Fallback: {activeRoute ? `${activeRoute.fallbackProvider} / ${activeRoute.fallbackModel}` : "—"} · cache affinity on</p></div>
          </div>
          <div className="validator-list">
            {agentSpec.validators.map((validator) => <span key={validator}><Check size={14} /> {validator}</span>)}
          </div>
          <button className="button secondary" disabled={busy} type="submit">Save AgentSpec</button>
        </form>

        <form className="surface form-surface run-launcher" onSubmit={(event) => { event.preventDefault(); void launch(); }}>
          <div className="surface-header">
            <div><p className="kicker">02 / Prove</p><h2>Launch assurance run</h2></div>
            <span className="trust-chip"><ShieldCheck size={14} /> Human gated</span>
          </div>
          <label>Branch<input value={branch} onChange={(event) => setBranch(event.target.value)} maxLength={200} required /></label>
          <label>Commit SHA<input className="mono" value={commitSha} onChange={(event) => setCommitSha(event.target.value)} maxLength={64} required /></label>
          <label>Task approval mode<select value={taskKind} onChange={(event) => setTaskKind(event.target.value as typeof taskKind)}>
            <option value="analyze-evidence">Analyze evidence only · eligible for automatic approval</option>
            <option value="draft-change">Prepare a draft · reviewer checks the result</option>
            <option value="merge-proposal">Propose a merge · human approval required</option>
          </select></label>
          <label>Estimated run cost<div className="money-input"><span>$</span><input inputMode="decimal" value={estimate} onChange={(event) => setEstimate(event.target.value)} required /></div></label>
          <div className={`budget-meter ${overBudget ? "blocked" : ""}`}>
            <div><span style={{ width: `${Math.min(100, (estimateCents / Math.max(1, budgetCents)) * 100)}%` }} /></div>
            <p><strong>${(estimateCents / 100).toFixed(2)}</strong> estimated of <strong>${(budgetCents / 100).toFixed(2)}</strong> hard limit</p>
          </div>
          {overBudget && <div className="inline-alert error" role="alert">Budget rail engaged. Convex will reject this run before any records or usage are created.</div>}
          <button className="button primary" disabled={busy || overBudget} type="submit">{busy ? "Running gates…" : "Run six assurance gates"}</button>
          <p className="action-note"><ShieldCheck size={14} /> Only proved, low-cost test analysis can auto-approve. Code changes, sends, deploys, deletes, payments, credentials, and production work always require a person.</p>
        </form>
      </div>
      <KnowledgeWall agentSpec={agentSpec} memories={memories} connectors={connectors} suggestedInputs={selectedTemplate.inputs} />
      {notice && <div className={`toast ${notice.tone}`} role="status">{notice.text}</div>}
      </>}
    </section>
  );
}

function AutomationCommandCenter({ blueprint, connectors, executionJobs, creditAccount, inferenceBinding, onOpenPanel }: {
  blueprint: Doc<"agentBlueprints"> | null;
  connectors: Doc<"knowledgeConnectors">[];
  executionJobs: Doc<"executionJobs">[];
  creditAccount: Doc<"creditAccounts"> | null;
  inferenceBinding: Doc<"inferenceBindings"> | null;
  onOpenPanel: (panel: AdvancedPanel) => void;
}) {
  const readyConnectors = connectors.filter((connector) => connector.status === "ready").length;
  const activeJobs = executionJobs.filter((job) => ["queued", "running", "suspended"].includes(job.status)).length;
  const checks = [
    { label: "Recipe selected", ready: true, detail: "Template defaults are editable" },
    { label: "Blueprint active", ready: blueprint?.status === "active", detail: blueprint ? `v${blueprint.version} · ${blueprint.status}` : "Save and activate a blueprint" },
    { label: "Knowledge connected", ready: readyConnectors > 0, detail: readyConnectors > 0 ? `${readyConnectors} ready source${readyConnectors === 1 ? "" : "s"}` : "Connect docs, Drive, DB, or web" },
    { label: "Inference ready", ready: inferenceBinding?.status === "ready", detail: inferenceBinding ? `${inferenceBinding.mode} · ${inferenceBinding.status}` : "Bind workspace or agent key" },
  ];
  const next = !blueprint ? { label: "Save the guided blueprint", panel: null as AdvancedPanel | null } :
    blueprint.status !== "active" ? { label: "Buy and activate blueprint", panel: null as AdvancedPanel | null } :
    readyConnectors === 0 ? { label: "Connect the Knowledge Wall", panel: null as AdvancedPanel | null } :
    inferenceBinding?.status !== "ready" ? { label: "Finish BYOK binding", panel: "runtime" as AdvancedPanel } :
    activeJobs === 0 ? { label: "Queue a hosted run", panel: "hosted" as AdvancedPanel } :
    { label: "Monitor active automation", panel: "hosted" as AdvancedPanel };
  const creditLabel = creditAccount ? `${creditAccount.availableCredits} available · ${creditAccount.reservedCredits} reserved` : "Credit account setup required";

  return <section className="automation-command" aria-labelledby="automation-command-title">
    <div className="automation-command-copy">
      <p className="kicker">Automation readiness</p>
      <h2 id="automation-command-title">Build the agent like a recipe. Operate it like a control plane.</h2>
      <p>The builder now separates beginner choices from enterprise levers: choose the outcome, connect knowledge, activate the blueprint, then run through governed hosted execution.</p>
      <div className="automation-next"><CircleDot size={18} /><span><small>Next best action</small><strong>{next.label}</strong></span>{next.panel && <button className="text-button" onClick={() => { if (next.panel) onOpenPanel(next.panel); }}>Open {next.label.toLowerCase()} <ChevronRight size={14} /></button>}</div>
    </div>
    <div className="automation-checks">
      {checks.map((check) => <article className={check.ready ? "ready" : "blocked"} key={check.label}><span>{check.ready ? <Check size={16} /> : <CircleDot size={16} />}</span><div><strong>{check.label}</strong><small>{check.detail}</small></div></article>)}
      <article className="credit"><span><WalletCards size={16} /></span><div><strong>Credits</strong><small>{creditLabel}</small></div></article>
    </div>
  </section>;
}
