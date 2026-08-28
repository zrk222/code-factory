import { useEffect, useMemo, useState } from "react";
import { useMutation } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import {
  AlertOctagon, CheckCircle2, Clipboard, CloudCog, Download, History, KeyRound,
  PauseCircle, PlayCircle, RotateCcw, ShieldAlert, ShieldCheck, Upload,
} from "lucide-react";
import { IdentityBoundaryPanel } from "./IdentityBoundaryPanel";
import { BillingInferencePanel } from "./BillingInferencePanel";
import { OperationsReadinessPanel } from "./OperationsReadinessPanel";
import { ProductionActivationPanel } from "./ProductionActivationPanel";

type ExportRecord = { marker: "AGENT_SPEC_EXPORTED"; canonical: string; digest: string; version: number };

type Props = {
  workspace: Doc<"workspaces">;
  agentSpec: Doc<"agentSpecs">;
  versions: Doc<"agentSpecVersions">[];
  connections: Doc<"providerConnections">[];
  creditAccount: Doc<"creditAccounts"> | null;
  creditTransactions: Doc<"creditTransactions">[];
  creditPlans: Array<{ plan: "starter" | "growth" | "business" | "enterprise"; name: string; monthlyCredits: number; agentLimit: number; audience: string }>;
  inferenceBinding: Doc<"inferenceBindings"> | null;
  executionJobs: Doc<"executionJobs">[];
  backups: Doc<"backupSnapshots">[];
  restoreDrills: Doc<"restoreDrills">[];
  exported: ExportRecord;
};

type Notice = { tone: "success" | "error"; text: string };

const providerDefaults = {
  openai: { label: "OpenAI production", secretRef: "env:OPENAI_API_KEY" },
  anthropic: { label: "Anthropic team vault", secretRef: "vault:anthropic/team-alpha" },
} as const;

export function OperationsPanel({ workspace, agentSpec, versions, connections, creditAccount, creditTransactions, creditPlans, inferenceBinding, executionJobs, backups, restoreDrills, exported }: Props) {
  const setLifecycle = useMutation(api.lifecycle.setLifecycle);
  const configureProvider = useMutation(api.lifecycle.configureProvider);
  const importAgentSpec = useMutation(api.lifecycle.importAgentSpec);
  const rollbackAgentSpec = useMutation(api.lifecycle.rollbackAgentSpec);
  const [reason, setReason] = useState("Operator safety review requested.");
  const [importEnvelope, setImportEnvelope] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);

  const envelope = useMemo(() => JSON.stringify({
    schema: "code-factory.AgentSpec.v1",
    digest: exported.digest,
    spec: JSON.parse(exported.canonical),
  }, null, 2), [exported]);

  useEffect(() => {
    setImportEnvelope(envelope);
  }, [envelope]);

  async function lifecycle(action: "pause" | "resume" | "revoke") {
    setBusy(true); setNotice(null);
    try {
      const result = await setLifecycle({ agentSpecId: agentSpec._id, action, reason });
      setNotice({ tone: "success", text: `${result.marker}: ${result.status}. ${result.closedRuns} run(s) and ${result.closedApprovals} approval(s) closed.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Lifecycle change failed." });
    } finally { setBusy(false); }
  }

  async function importEnvelopeValue() {
    setBusy(true); setNotice(null);
    try {
      const parsed = JSON.parse(importEnvelope) as { schema?: unknown; digest?: unknown; spec?: unknown };
      if (parsed.schema !== "code-factory.AgentSpec.v1" || typeof parsed.digest !== "string" || !parsed.spec) throw new Error("E_INVALID_IMPORT_ENVELOPE");
      const result = await importAgentSpec({ agentSpecId: agentSpec._id, canonical: JSON.stringify(parsed.spec), digest: parsed.digest });
      setNotice({ tone: "success", text: `${result.marker}: AgentSpec v${result.version} is now the active head.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Import failed." });
    } finally { setBusy(false); }
  }

  async function rollback(version: number) {
    setBusy(true); setNotice(null);
    try {
      const result = await rollbackAgentSpec({ agentSpecId: agentSpec._id, targetVersion: version });
      setNotice({ tone: "success", text: `${result.marker}: v${version} restored as new head v${result.version}.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Rollback failed." });
    } finally { setBusy(false); }
  }

  function downloadExport() {
    const blob = new Blob([envelope], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `pr-assurance-v${exported.version}.agent.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  async function copyExport() {
    await navigator.clipboard.writeText(envelope);
    setNotice({ tone: "success", text: "AGENT_SPEC_EXPORTED: canonical envelope copied." });
  }

  return (
    <section className="page-stack operations-page" aria-labelledby="operations-title">
      <header className="page-heading">
        <div><p className="eyebrow">Phase 1 / operator lifecycle</p><h1 id="operations-title">Control the agent. Keep the history.</h1><p>Pause authority, restore a known version, and connect model providers without handing secret values to the control plane.</p></div>
        <span className={`lifecycle-badge ${agentSpec.status}`}><span />{agentSpec.status}</span>
      </header>

      <div className="operations-grid">
        <article className="surface operation-card lifecycle-card">
          <div className="surface-header"><div><p className="kicker">Emergency control</p><h2>Runtime authority</h2></div><ShieldAlert size={22} /></div>
          <div className={`agent-state-panel ${agentSpec.status}`}><div><small>PR Assurance Agent</small><strong>{agentSpec.status}</strong></div><span>v{agentSpec.version}</span></div>
          <label>Operator reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} /></label>
          <div className="lifecycle-actions">
            {agentSpec.status === "active" && <button className="button warning" disabled={busy} onClick={() => void lifecycle("pause")}><PauseCircle size={18} /> Pause agent</button>}
            {agentSpec.status === "suspended" && <button className="button success" disabled={busy} onClick={() => void lifecycle("resume")}><PlayCircle size={18} /> Resume agent</button>}
            {agentSpec.status !== "revoked" && <button className="button danger" disabled={busy} onClick={() => void lifecycle("revoke")}><AlertOctagon size={18} /> Revoke permanently</button>}
          </div>
          <p className="boundary-copy"><ShieldCheck size={14} /> Pause and revoke atomically close pending runs and approvals. Revocation cannot be reversed.</p>
        </article>

        <article className="surface operation-card portable-card">
          <div className="surface-header"><div><p className="kicker">Portable contract</p><h2>Export / import</h2></div><CloudCog size={22} /></div>
          <dl className="export-facts"><div><dt>Schema</dt><dd>AgentSpec.v1</dd></div><div><dt>Version</dt><dd>{exported.version}</dd></div><div><dt>Prototype digest</dt><dd className="mono">{exported.digest}</dd></div></dl>
          <div className="button-row"><button className="button secondary" onClick={() => void copyExport()}><Clipboard size={16} /> Copy</button><button className="button secondary" onClick={downloadExport}><Download size={16} /> Download</button></div>
          <label>Import envelope<textarea className="mono import-envelope" value={importEnvelope} onChange={(event) => setImportEnvelope(event.target.value)} maxLength={5000} /></label>
          <button className="button primary" disabled={busy} onClick={() => void importEnvelopeValue()}><Upload size={16} /> Validate and import</button>
          <p className="boundary-copy">Unknown keys, malformed JSON, and mismatched digests fail before any write.</p>
        </article>
      </div>

      <article className="surface operation-card version-card">
        <div className="surface-header"><div><p className="kicker">Append-only ledger</p><h2>Version history</h2></div><History size={22} /></div>
        <div className="version-list">
          {versions.map((version) => <div className="version-row" key={version._id}>
            <span className="version-number">v{version.version}</span>
            <div><strong>{version.repository}</strong><small>{version.source}{version.restoredFromVersion ? ` · restored from v${version.restoredFromVersion}` : ""}</small></div>
            <code>{version.digest}</code>
            <time>{new Date(version.createdAt).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}</time>
            <button className="text-button" disabled={busy || version.version === agentSpec.version} onClick={() => void rollback(version.version)}><RotateCcw size={14} /> {version.version === agentSpec.version ? "Current" : "Restore"}</button>
          </div>)}
        </div>
      </article>

      <ProviderConnections workspace={workspace} connections={connections} configure={configureProvider} busy={busy} setBusy={setBusy} setNotice={setNotice} />
      <BillingInferencePanel agentSpec={agentSpec} connections={connections} account={creditAccount} transactions={creditTransactions} plans={creditPlans} binding={inferenceBinding} />
      <ProductionActivationPanel workspaceId={workspace._id} />
      <OperationsReadinessPanel workspace={workspace} jobs={executionJobs} backups={backups} restoreDrills={restoreDrills} />
      <IdentityBoundaryPanel />
      {notice && <div className={`toast ${notice.tone}`} role="status">{notice.text}</div>}
    </section>
  );
}

function ProviderConnections({ workspace, connections, configure, busy, setBusy, setNotice }: {
  workspace: Doc<"workspaces">;
  connections: Doc<"providerConnections">[];
  configure: ReturnType<typeof useMutation<typeof api.lifecycle.configureProvider>>;
  busy: boolean;
  setBusy: (value: boolean) => void;
  setNotice: (value: Notice | null) => void;
}) {
  return <article className="surface operation-card provider-section">
    <div className="surface-header"><div><p className="kicker">Secret-free BYOK</p><h2>Provider references</h2></div><KeyRound size={22} /></div>
    <div className="provider-grid">{(["openai", "anthropic"] as const).map((provider) => {
      const existing = connections.find((item) => item.provider === provider);
      return <ProviderForm key={provider} provider={provider} existing={existing} defaults={providerDefaults[provider]} busy={busy} onSave={async (values) => {
        setBusy(true); setNotice(null);
        try {
          const result = await configure({ workspaceId: workspace._id, provider, ...values, enabled: true });
          setNotice({ tone: "success", text: `${result.marker}: ${provider} uses ${result.secretRef}; 0 secret values stored.` });
        } catch (error) {
          setNotice({ tone: "error", text: error instanceof Error ? error.message : "Provider reference failed." });
        } finally { setBusy(false); }
      }} />;
    })}</div>
    <p className="provider-warning"><ShieldCheck size={16} /> References only. The runtime resolves credentials from your environment or vault; Convex stores no provider secret value.</p>
  </article>;
}

function ProviderForm({ provider, existing, defaults, busy, onSave }: {
  provider: "openai" | "anthropic";
  existing?: Doc<"providerConnections">;
  defaults: { label: string; secretRef: string };
  busy: boolean;
  onSave: (values: { label: string; secretRef: string }) => Promise<void>;
}) {
  const [label, setLabel] = useState(existing?.label ?? defaults.label);
  const [secretRef, setSecretRef] = useState(existing?.secretRef ?? defaults.secretRef);
  useEffect(() => { if (existing) { setLabel(existing.label); setSecretRef(existing.secretRef); } }, [existing]);
  return <form className="provider-form" onSubmit={(event) => { event.preventDefault(); void onSave({ label, secretRef }); }}>
    <header><span className={`provider-logo ${provider}`}>{provider === "openai" ? "OA" : "AN"}</span><div><strong>{provider === "openai" ? "OpenAI" : "Anthropic"}</strong><small>{existing?.status ?? "not configured"}</small></div>{existing && <CheckCircle2 size={18} />}</header>
    <label>Connection label<input value={label} onChange={(event) => setLabel(event.target.value)} maxLength={80} required /></label>
    <label>Secret reference<input className="mono" value={secretRef} onChange={(event) => setSecretRef(event.target.value)} maxLength={240} required /></label>
    <small className="scheme-help">env: · vault: · azure-key-vault: · aws-secrets-manager:</small>
    <button className="button secondary" disabled={busy} type="submit">Save {provider === "openai" ? "OpenAI" : "Anthropic"} reference</button>
  </form>;
}
