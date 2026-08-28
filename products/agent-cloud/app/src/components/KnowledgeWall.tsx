import { useMemo, useState } from "react";
import { useMutation } from "convex/react";
import { BookOpen, Cloud, Database, FileCheck2, Plus, Search, ShieldCheck, Upload } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { knowledgeConnectorCatalog, type KnowledgeConnectorProvider } from "../knowledgeConnectorCatalog";
import { SourceAssurancePanel } from "./SourceAssurancePanel";

type Props = { agentSpec: Doc<"agentSpecs">; memories: Doc<"memories">[]; connectors: Doc<"knowledgeConnectors">[]; suggestedInputs: readonly string[] };

export function KnowledgeWall({ agentSpec, memories, connectors, suggestedInputs }: Props) {
  const addMemory = useMutation(api.memory.add);
  const configureConnector = useMutation(api.knowledgeConnectors.configure);
  const [kind, setKind] = useState("Operating manual");
  const [source, setSource] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<KnowledgeConnectorProvider>("google-drive");
  const [connectorLabel, setConnectorLabel] = useState("Operations knowledge");
  const [connectorLocator, setConnectorLocator] = useState("");
  const [secretRef, setSecretRef] = useState("");
  const [syncMode, setSyncMode] = useState<"manual" | "daily" | "weekly">("manual");
  const wall = useMemo(() => memories.filter((item) => item.purpose === "Agent operating manual" && item.deletedAt === undefined && item.supersededAt === undefined), [memories]);
  const selectedManifest = knowledgeConnectorCatalog.find((item) => item.provider === selectedProvider)!;

  async function add() {
    setBusy(true); setNotice(null);
    try {
      await addMemory({ agentSpecId: agentSpec._id, subject: kind, content, source, purpose: "Agent operating manual", provenance: `Workspace owner supplied ${kind.toLocaleLowerCase("en-US")} from ${source}`, confidence: 90, retentionDays: 365 });
      setContent(""); setSource(""); setNotice("Added to the governed Knowledge Wall. It informs retrieval but grants no authority.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not add this knowledge source."); }
    finally { setBusy(false); }
  }

  async function saveConnector() {
    setBusy(true); setNotice(null);
    try {
      const result = await configureConnector({ workspaceId: agentSpec.workspaceId, agentSpecId: agentSpec._id, provider: selectedProvider, label: connectorLabel, sourceLocator: connectorLocator, secretRef: secretRef.trim() || undefined, syncMode });
      setNotice(`${selectedManifest.label} definition saved as ${result.status}. Complete tenant authorization before the first sync.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Connector setup failed."); }
    finally { setBusy(false); }
  }

  async function importFiles(files: FileList | null) {
    if (!files?.length) return;
    setBusy(true); setNotice(null);
    try {
      let chunksAdded = 0;
      for (const file of Array.from(files)) {
        if (file.size > 100_000) throw new Error(`${file.name} exceeds the 100 KB safe-import limit.`);
        if (!/\.(txt|md|markdown|csv|json)$/i.test(file.name)) throw new Error(`${file.name} is not a supported text, Markdown, CSV, or JSON file.`);
        const text = (await file.text()).trim();
        const chunks = text.match(/[\s\S]{1,1800}/g) ?? [];
        if (chunks.length > 56) throw new Error(`${file.name} contains too many knowledge chunks.`);
        for (const [index, chunk] of chunks.entries()) {
          await addMemory({ agentSpecId: agentSpec._id, subject: `${file.name} · part ${index + 1}/${chunks.length}`, content: chunk, source: `upload:${file.name}`, purpose: "Agent operating manual", provenance: `Workspace owner uploaded ${file.name}; client split into bounded text chunks`, confidence: 90, retentionDays: 365 });
          chunksAdded += 1;
        }
      }
      setNotice(`Imported ${chunksAdded} governed knowledge chunk${chunksAdded === 1 ? "" : "s"}. Files remain context, never authority.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "File import failed."); }
    finally { setBusy(false); }
  }

  return (
    <section className="knowledge-wall surface" aria-labelledby="knowledge-wall-title">
      <header className="knowledge-header"><div><p className="kicker">Knowledge Wall / operating context</p><h2 id="knowledge-wall-title">Give the agent the business playbook.</h2><p>Add the guidelines it should retrieve when doing the work. Every tile keeps its source and provenance; none can expand tool authority.</p></div><span><ShieldCheck size={18} /> Memory informs · policy authorizes</span></header>
      <div className="knowledge-flow"><span><Database size={17} /><b>Source</b><small>manual · DB extract · KB article</small></span><i>→</i><span><Search size={17} /><b>Retrieve</b><small>scope · purpose · confidence</small></span><i>→</i><span><FileCheck2 size={17} /><b>Apply</b><small>inside approval rails</small></span></div>
      <div className="knowledge-suggestions"><strong>Recommended for this recipe</strong>{suggestedInputs.map((item) => <button key={item} onClick={() => setKind(item)}><Plus size={12} /> {item}</button>)}</div>
      <div className="knowledge-intake">
        <label className="upload-zone"><Upload size={20} /><strong>Upload operating knowledge</strong><span>Text, Markdown, CSV, or JSON · 100 KB per file · split into bounded governed records</span><input aria-label="Upload knowledge files" type="file" accept=".txt,.md,.markdown,.csv,.json,text/plain,text/markdown,text/csv,application/json" multiple disabled={busy} onChange={(event) => void importFiles(event.target.files)} /></label>
        <div className="connector-picker"><header><Cloud size={17} /><div><strong>Connect a knowledge source</strong><span>One adapter contract · raw credentials never stored here</span></div></header><div>{knowledgeConnectorCatalog.map((connector) => <button className={selectedProvider === connector.provider ? "selected" : ""} key={connector.provider} onClick={() => { setSelectedProvider(connector.provider); setConnectorLocator(""); }}>{connector.label}<small>{connector.family}</small></button>)}</div></div>
      </div>
      <div className="connector-config">
        <header><div><small>{selectedManifest.family} connector</small><strong>{selectedManifest.label}</strong></div><span>{selectedManifest.auth}</span></header>
        <label>Connection name<input value={connectorLabel} onChange={(event) => setConnectorLabel(event.target.value)} /></label>
        <label>{selectedManifest.locatorLabel}<input value={connectorLocator} onChange={(event) => setConnectorLocator(event.target.value)} placeholder={selectedManifest.locatorPlaceholder} /></label>
        <label>Sync<select value={syncMode} onChange={(event) => setSyncMode(event.target.value as typeof syncMode)}><option value="manual">Manual import</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label>
        {selectedManifest.auth !== "OAuth 2.0" && <label>Secret reference (optional)<input value={secretRef} onChange={(event) => setSecretRef(event.target.value)} placeholder="env:KNOWLEDGE_SOURCE_KEY" /></label>}
        <div className="connector-scopes"><small>Least-privilege request</small>{selectedManifest.scopes.map((scope) => <code key={scope}>{scope}</code>)}</div>
        <button className="button secondary" disabled={busy || !connectorLabel.trim() || !connectorLocator.trim()} onClick={() => void saveConnector()}>Save connector setup</button>
      </div>
      {connectors.length > 0 && <div className="configured-connectors">{connectors.map((connector) => <span key={connector._id}><b>{connector.provider}</b><small>{connector.sourceLocator}</small><em>{connector.status}</em></span>)}</div>}
      <div className="knowledge-editor">
        <label>Knowledge type<select value={kind} onChange={(event) => setKind(event.target.value)}><option>Operating manual</option><option>Policy and guardrail</option><option>Database extract</option><option>Knowledge-base article</option><option>FAQ and script</option></select></label>
        <label>Source reference<input value={source} onChange={(event) => setSource(event.target.value)} placeholder="handbook/operations.md or kb://article/42" /></label>
        <label className="knowledge-content">Guideline or approved extract<textarea value={content} onChange={(event) => setContent(event.target.value)} placeholder="Paste the approved operating guidance the agent should retrieve…" /></label>
        <button className="button secondary" disabled={busy || !source.trim() || !content.trim()} onClick={() => void add()}><Plus size={15} /> Add to Knowledge Wall</button>
      </div>
      {notice && <p className="knowledge-notice" role="status">{notice}</p>}
      <div className="knowledge-tiles">{wall.length === 0 ? <div className="knowledge-empty"><BookOpen size={22} /><strong>No operating knowledge yet</strong><p>Add the first approved manual, policy, database extract, or KB article above.</p></div> : wall.map((item) => <article key={item._id}><span>{item.subject}</span><strong>{item.content}</strong><small>{item.source}</small><footer>{item.confidence}% confidence · {item.retentionDays}d retention · untrusted context</footer></article>)}</div>
      <p className="knowledge-connector-note"><Database size={14} /> Database and KB entries currently accept approved extracts and durable source references. Live credentialed sync remains disabled until a connector is explicitly configured and approved.</p>
      <SourceAssurancePanel agentSpec={agentSpec} />
    </section>
  );
}
