import { useEffect, useState } from "react";
import { UserButton } from "@clerk/react";
import { useMutation, useQuery } from "convex/react";
import { api } from "../convex/_generated/api";
import {
  Activity, Bell, Blocks, Bot, Boxes, BrainCircuit, CheckCircle2, ChevronRight, CircleGauge,
  FileCheck2, Fingerprint, Gauge, GitPullRequestArrow, LayoutDashboard, Menu, Rocket,
  Settings, ShieldCheck, Sparkles, Store, X,
} from "lucide-react";
import { AgentBuilder } from "./components/AgentBuilder";
import { EvidencePanel } from "./components/EvidencePanel";
import { MemoryPanel } from "./components/MemoryPanel";
import { RunPanel } from "./components/RunPanel";
import { OperationsPanel } from "./components/OperationsPanel";
import { ReleaseSafetyPanel } from "./components/ReleaseSafetyPanel";
import { AgentExchangePanel } from "./components/AgentExchangePanel";

type View = "overview" | "exchange" | "builder" | "runs" | "evidence" | "memory" | "releases" | "settings";

const navigation = [
  ["overview", "Overview", LayoutDashboard],
  ["exchange", "Outcome Exchange", Store],
  ["builder", "Agent Builder", Blocks],
  ["runs", "Runs", Activity],
  ["evidence", "Evidence", Fingerprint],
  ["memory", "Memory", BrainCircuit],
  ["releases", "Release Safety", Rocket],
  ["settings", "Settings", Settings],
] as const;

export default function App() {
  const access = useQuery(api.access.myWorkspaces);
  const ensureDemo = useMutation(api.seed.ensureDemo);
  const [creating, setCreating] = useState(false);
  const workspaceId = access?.workspaces[0]?.workspace._id;
  const data = useQuery(api.dashboard.overview, workspaceId ? { workspaceId } : "skip");
  const [view, setView] = useState<View>(() => {
    const requested = new URLSearchParams(window.location.search).get("view");
    return navigation.some(([id]) => id === requested) ? requested as View : "overview";
  });
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [view]);

  if (access === undefined) {
    return <main className="loading-screen"><div className="factory-loader"><span /><span /><span /></div><p>Connecting to the Convex control plane…</p></main>;
  }

  if (!workspaceId) {
    return <main className="setup-screen" data-testid="workspace-bootstrap"><p className="eyebrow">Authenticated · no workspace</p><h1>Create your first governed workspace.</h1><p>Your verified account becomes the owner of a new tenant-scoped workspace. Other customers cannot discover or access it.</p><button className="button primary" disabled={creating} onClick={() => { setCreating(true); void ensureDemo({}).finally(() => setCreating(false)); }}>{creating ? "Creating…" : "Create my workspace"}</button></main>;
  }

  if (data === undefined) {
    return <main className="loading-screen"><div className="factory-loader"><span /><span /><span /></div><p>Loading the authorized workspace…</p></main>;
  }

  if (data === null) {
    return <main className="loading-screen"><div className="factory-loader"><span /><span /><span /></div><p>Preparing the Factory Lab workspace…</p></main>;
  }

  const pending = data.approvals.filter((approval) => approval.status === "pending").length;
  const latestRun = data.runs[0];
  const passedGates = latestRun?.gates.filter((gate) => gate.status === "passed").length ?? 0;
  const totalSpend = data.runs.reduce((sum, run) => sum + run.actualCostCents, 0);

  function navigate(next: View) {
    setView(next);
    setMobileNavOpen(false);
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`}>
        <div className="brand-lockup"><span className="brand-mark"><Boxes size={24} /></span><div><strong>AGENT OVEN</strong><small>BY CODE FACTORY</small></div><button className="mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={20} /></button></div>
        <div className="workspace-switcher"><span>FL</span><div><strong>{data.workspace.name}</strong><small>PR Assurance · Pilot</small></div><ChevronRight size={16} /></div>
        <nav aria-label="Product navigation">
          <p className="nav-label">Control room</p>
          {navigation.map(([id, label, Icon]) => <button key={id} className={view === id ? "active" : ""} onClick={() => navigate(id)}><Icon size={18} /><span>{label}</span>{id === "runs" && pending > 0 && <em>{pending}</em>}</button>)}
        </nav>
        <div className="sidebar-proof"><ShieldCheck size={20} /><div><strong>Trust boundary active</strong><p>Memory informs. Policy authorizes.</p></div></div>
        <div className="sidebar-footer"><span className="avatar"><ShieldCheck size={16} /></span><div><strong>Verified session</strong><small>Identity by Clerk</small></div></div>
      </aside>

      <div className="app-body">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={21} /></button>
          <div className="deployment-state"><span className="pulse" /><strong>Local Convex</strong><span>Realtime control plane</span></div>
          <div className="topbar-actions"><span className="prototype-pill">Prototype · unsigned receipts</span><button className="icon-button" aria-label="Notifications"><Bell size={18} />{pending > 0 && <i />}</button><UserButton /></div>
        </header>

        <main className="main-content">
          {view === "overview" && <Overview data={data} pending={pending} passedGates={passedGates} totalSpend={totalSpend} onNavigate={navigate} />}
          {view === "exchange" && <AgentExchangePanel workspaceId={workspaceId} />}
          {view === "builder" && data.agentSpec && <AgentBuilder agentSpec={data.agentSpec} blueprint={data.blueprint} blueprintVersions={data.blueprintVersions} executionJobs={data.executionJobs} runtimeAdapters={data.runtimeAdapters} routes={data.routes} memories={data.memoryLedger} connectors={data.knowledgeConnectors} creditAccount={data.creditAccount} inferenceBinding={data.inferenceBinding} />}
          {view === "runs" && <RunPanel runs={data.runs} />}
          {view === "evidence" && <EvidencePanel receipts={data.receipts} auditEvents={data.auditEvents} />}
          {view === "memory" && data.agentSpec && <MemoryPanel agentSpec={data.agentSpec} memories={data.memories} ledger={data.memoryLedger} exported={data.memoryExport} />}
          {view === "releases" && data.agentSpec && <ReleaseSafetyPanel agentSpec={data.agentSpec} releases={data.releases} incidents={data.incidents} />}
          {view === "settings" && data.agentSpec && data.agentSpecExport && <OperationsPanel workspace={data.workspace} agentSpec={data.agentSpec} versions={data.versions} connections={data.providerConnections} creditAccount={data.creditAccount} creditTransactions={data.creditTransactions} creditPlans={data.creditPlans} inferenceBinding={data.inferenceBinding} executionJobs={data.executionJobs} backups={data.backupSnapshots} restoreDrills={data.restoreDrills} exported={data.agentSpecExport} />}
        </main>
      </div>
    </div>
  );
}

type Dashboard = NonNullable<ReturnType<typeof useQuery<typeof api.dashboard.overview>>>;

function Overview({ data, pending, passedGates, totalSpend, onNavigate }: { data: Dashboard; pending: number; passedGates: number; totalSpend: number; onNavigate: (view: View) => void }) {
  const latestRun = data.runs[0];
  const metrics = [
    ["Proof coverage", latestRun ? `${passedGates}/${latestRun.gates.length}` : "—", "Latest run gates", CircleGauge, "green"],
    ["Human decisions", String(pending), "Awaiting review", ShieldCheck, "orange"],
    ["Run spend", `$${(totalSpend / 100).toFixed(2)}`, "Across this workspace", Gauge, "blue"],
    ["Evidence", String(data.receipts.length), "Unsigned prototype receipts", Fingerprint, "cream"],
  ] as const;
  return (
    <section className="overview-page">
      <header className="overview-hero">
        <div className="hero-copy"><p className="eyebrow">Governed software agents</p><h1>Every important PR arrives with <span>proof.</span></h1><p>Configure the agent, cap the spend, inspect every gate, and keep the human decision exactly where it belongs.</p><div className="hero-actions"><button className="button primary" onClick={() => onNavigate("builder")}>Configure PR Assurance <ChevronRight size={17} /></button><button className="text-button" onClick={() => onNavigate("evidence")}><Fingerprint size={16} /> Inspect evidence chain</button></div><div className="hero-trust"><span><CheckCircle2 size={15} /> Convex realtime backend</span><span><CheckCircle2 size={15} /> Hard budget enforcement</span><span><CheckCircle2 size={15} /> Human-gated actions</span></div></div>
        <div className="factory-visual" aria-label="Code Factory assurance pipeline illustration">
          <div className="machine-top"><span /><span /><span /><strong>PROOF LINE 01</strong></div>
          <div className="machine-window">
            <div className="belt-track" />
            {["SPEC", "TEST", "TRUST", "RECEIPT"].map((label, index) => <div className={`proof-cube cube-${index + 1}`} key={label}><span><CheckCircle2 size={16} /></span><strong>{label}</strong></div>)}
          </div>
          <div className="machine-footer"><span>INPUT</span><div className="mini-gauge"><i /></div><span>HUMAN GATE</span></div>
          <div className="proof-stamp"><ShieldCheck size={27} /><span><small>STATUS</small><strong>{latestRun ? latestRun.status.toUpperCase() : "READY"}</strong></span></div>
        </div>
      </header>

      <div className="metric-grid">{metrics.map(([label, value, note, Icon, tone]) => <article className={`metric-card ${tone}`} key={label}><span><Icon size={20} /></span><div><small>{label}</small><strong>{value}</strong><p>{note}</p></div></article>)}</div>

      <div className="overview-grid">
        <article className="surface pipeline-card">
          <div className="surface-header"><div><p className="kicker">Latest assurance run</p><h2>{latestRun ? latestRun.branch : "Ready for first run"}</h2></div><button className="text-button" onClick={() => onNavigate("runs")}>Open run <ChevronRight size={15} /></button></div>
          {latestRun ? <>
            <div className="pipeline-line">{latestRun.gates.map((gate, index) => <div className={`pipeline-step ${gate.status}`} key={gate._id}><span>{index + 1}</span><strong>{gate.name}</strong><small>{gate.evidenceClass}</small></div>)}</div>
            <div className="pipeline-result"><div><span className="pulse" /><strong>{latestRun.status.replace("-", " ")}</strong><p>{latestRun.proposedAction}</p></div><span className="mono">{latestRun.actionDigest}</span></div>
          </> : <div className="empty-inline"><GitPullRequestArrow size={24} /><span>Launch the PR Assurance Agent to see its proof line here.</span></div>}
        </article>
        <article className="surface boundary-card">
          <div className="surface-header"><div><p className="kicker">Architecture invariant</p><h2>Memory ≠ authority</h2></div><BrainCircuit size={22} /></div>
          <div className="boundary-diagram"><div><Sparkles size={21} /><strong>Memory</strong><small>untrusted context</small></div><span>informs</span><div className="decision-node"><Bot size={21} /><strong>Agent</strong><small>proposes</small></div><span>requests</span><div><ShieldCheck size={21} /><strong>Trust</strong><small>authorizes</small></div></div>
          <p className="boundary-note">Four policy fields authorize actions. Zero memory fields can expand capability.</p>
          <button className="text-button" onClick={() => onNavigate("memory")}>Inspect memory provenance <ChevronRight size={15} /></button>
        </article>
      </div>
    </section>
  );
}
