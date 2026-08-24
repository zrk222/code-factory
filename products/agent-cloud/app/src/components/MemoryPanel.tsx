import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import {
  ArchiveRestore,
  BrainCircuit,
  CheckCircle2,
  Clipboard,
  Download,
  FileClock,
  History,
  Info,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldAlert,
  Trash2,
} from "lucide-react";

type MemoryExport = {
  canonical: string;
  digest: string;
  records: Array<{
    recordNumber: number;
    state: "active" | "superseded" | "erased";
    supersedesRecordNumber: number | null;
    policyVersion: "memory-policy.v1";
  }>;
};

type Props = {
  agentSpec: Doc<"agentSpecs">;
  memories: Doc<"memories">[];
  ledger: Doc<"memories">[];
  exported: MemoryExport;
};

export function MemoryPanel({ agentSpec, memories, ledger, exported }: Props) {
  const addMemory = useMutation(api.memory.add);
  const correctMemory = useMutation(api.memory.correct);
  const removeMemory = useMutation(api.memory.remove);
  const enforceRetention = useMutation(api.memory.enforceRetention);
  const [content, setContent] = useState("Provider invocation must remain separate from route selection.");
  const [source, setSource] = useState("adr/014-provider-routing.md");
  const [selected, setSelected] = useState<Doc<"memories"> | null>(null);
  const [correction, setCorrection] = useState("");
  const [reason, setReason] = useState("Clarified after architecture review.");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [recallSubject, setRecallSubject] = useState("Architecture decision");
  const [recallPurpose, setRecallPurpose] = useState("PR architecture review");
  const [recallScope, setRecallScope] = useState({ subject: "Architecture decision", purpose: "PR architecture review" });
  const recall = useQuery(api.memory.recallScoped, { agentSpecId: agentSpec._id, ...recallScope, limit: 5 });

  const erasedCount = ledger.filter((memory) => memory.deletedAt !== undefined).length;
  const correctedCount = ledger.filter((memory) => memory.supersededAt !== undefined).length;
  const quarantinedCount = ledger.filter((memory) => memory.safetyState === "quarantined" && memory.deletedAt === undefined).length;

  async function run(operation: () => Promise<{ marker: string; safetyMarker?: string }>, suffix: string) {
    setBusy(true);
    setMessage(null);
    try {
      const result = await operation();
      setMessage(`${result.safetyMarker ?? result.marker}: ${suffix}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Memory operation failed.");
    } finally {
      setBusy(false);
    }
  }

  async function add() {
    await run(() => addMemory({
      agentSpecId: agentSpec._id,
      subject: "Architecture decision",
      content,
      source,
      purpose: "PR architecture review",
      provenance: "Repository-owned ADR selected by the workspace admin",
      confidence: 96,
      retentionDays: 365,
    }), "stored under memory-policy.v1 as untrusted context.");
  }

  function beginCorrection(memory: Doc<"memories">) {
    setSelected(memory);
    setCorrection(memory.content);
    setMessage(null);
  }

  async function correct() {
    if (!selected) return;
    await run(() => correctMemory({ memoryId: selected._id, content: correction, reason }), "successor appended; predecessor retained as superseded history.");
    setSelected(null);
  }

  async function erase(memoryId: Doc<"memories">["_id"]) {
    await run(() => removeMemory({ memoryId, reason: "Admin-requested erasure from the governance console." }), "sensitive fields erased; non-sensitive tombstone and receipt retained.");
  }

  async function retain() {
    await run(async () => {
      const result = await enforceRetention({ agentSpecId: agentSpec._id });
      return { marker: result.marker };
    }, "expired records evaluated against the server clock.");
  }

  async function copyExport() {
    await navigator.clipboard.writeText(JSON.stringify(JSON.parse(exported.canonical), null, 2));
    setMessage("MEMORY_EXPORT_READY: sanitized export copied.");
  }

  function downloadExport() {
    const blob = new Blob([JSON.stringify(JSON.parse(exported.canonical), null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "code-factory-memory-export.json";
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage("MEMORY_EXPORT_SANITIZED: portable export downloaded.");
  }

  return (
    <section className="page-stack memory-governance" aria-labelledby="memory-title">
      <header className="page-heading memory-heading">
        <div><p className="eyebrow">Phase 2 / memory governance alpha</p><h1 id="memory-title">Correct the record.<br />Prove the lifecycle.</h1><p>Append corrections, erase sensitive content, enforce retention, and export a portable provenance history without turning memory into authority.</p></div>
        <span className="alpha-boundary">Local security alpha</span>
      </header>

      <div className="trust-principle"><ShieldAlert size={22} /><div><strong>Hard separation remains active</strong><p>Memory informs proposals. Only Trust policy can authorize an action.</p></div><span>0 authority fields</span></div>

      <article className="surface memory-export-bar">
        <div><p className="kicker">Portable governance record</p><h2>Sanitized export</h2><p>Schema v1 · {ledger.length} lifecycle records · digest <code>{exported.digest}</code></p></div>
        <div className="memory-export-actions"><button className="button secondary" onClick={() => void copyExport()}><Clipboard size={16} /> Copy</button><button className="button secondary" onClick={downloadExport}><Download size={16} /> Download</button><button className="button primary" disabled={busy} onClick={() => void retain()}><RefreshCw size={16} /> Enforce retention</button></div>
      </article>

      <div className="memory-stat-grid">
        <div><span>Active</span><strong>{memories.length}</strong><small>retrievable context</small></div>
        <div><span>Corrected</span><strong>{correctedCount}</strong><small>superseded history</small></div>
        <div><span>Erased</span><strong>{erasedCount}</strong><small>content-free tombstones</small></div>
        <div><span>Quarantined</span><strong>{quarantinedCount}</strong><small>retained, never recalled</small></div>
      </div>

      <article className="surface recall-lab">
        <div className="surface-header"><div><p className="kicker">Explainable retrieval</p><h2>Scoped recall lab</h2></div><Search size={22} /></div>
        <p className="recall-intro">Recall derives workspace and agent from this AgentSpec, filters exact subject and purpose, excludes quarantine, then ranks. Memory remains untrusted context.</p>
        <div className="recall-controls">
          <label>Exact subject<input value={recallSubject} onChange={(event) => setRecallSubject(event.target.value)} maxLength={200} /></label>
          <label>Exact purpose<input value={recallPurpose} onChange={(event) => setRecallPurpose(event.target.value)} maxLength={300} /></label>
          <button className="button primary" onClick={() => setRecallScope({ subject: recallSubject, purpose: recallPurpose })}><Search size={16} /> Recall safely</button>
        </div>
        {recall?.counts && <div className="recall-proofline"><span>{recall.marker}</span><span>{recall.counts.returned} returned</span><span>{recall.counts.quarantinedExcluded} quarantined</span><span>{recall.counts.scopeExcluded} outside scope</span></div>}
        <div className="recall-results">
          {recall?.recalled?.length === 0 && <div className="empty-state compact"><ShieldCheck size={26} /><h2>No eligible exact match</h2><p>Broaden scope deliberately or add governed context. Quarantined evidence stays excluded.</p></div>}
          {recall?.recalled?.map((memory, index) => <article className="recall-card" key={`${memory.createdAt}-${index}`}>
            <div><span className="eligible-badge"><ShieldCheck size={13} /> eligible</span><strong>{memory.confidence}% confidence</strong></div>
            <h3>{memory.subject}</h3><p>{memory.content}</p>
            <dl><div><dt>Why this agent knows it</dt><dd>{memory.why}</dd></div><div><dt>Source</dt><dd>{memory.source}</dd></div><div><dt>Provenance</dt><dd>{memory.provenance}</dd></div></dl>
            <footer><code>{memory.policyVersion}</code><span>{memory.trustLabel}</span><time>{new Date(memory.createdAt).toLocaleString()}</time></footer>
          </article>)}
        </div>
        <p className="heuristic-note"><Info size={13} /> Quarantine uses a bounded five-phrase heuristic. An eligible label is not proof that content is safe and never grants authority.</p>
      </article>

      <div className="memory-layout">
        <article className="surface form-surface">
          <div className="surface-header"><div><p className="kicker">Add governed context</p><h2>New memory</h2></div><BrainCircuit size={22} /></div>
          <label>Memory content<textarea value={content} onChange={(event) => setContent(event.target.value)} maxLength={2000} /></label>
          <label>Source<input value={source} onChange={(event) => setSource(event.target.value)} maxLength={300} /></label>
          <div className="memory-metadata"><span>Purpose: PR architecture review</span><span>Confidence: 96%</span><span>Retention: 365 days</span></div>
          <button className="button primary" disabled={busy} onClick={() => void add()}><Plus size={17} /> Store with provenance</button>
          {message && <p className="inline-alert" role="status">{message}</p>}
        </article>

        <div className="memory-list">
          {memories.length === 0 ? <div className="empty-state compact"><FileClock size={26} /><h2>No active memories</h2><p>Add governed context or inspect the lifecycle ledger below.</p></div> : memories.map((memory) => (
            <article className="memory-card" key={memory._id}>
              <div className="memory-card-top"><span className={memory.safetyState === "quarantined" ? "quarantine-badge" : "untrusted-badge"}><Info size={13} /> {memory.safetyState === "quarantined" ? "quarantined" : memory.trustLabel}</span><span className="policy-badge">{memory.policyVersion ?? "memory-policy.v1"}</span></div>
              <h2>{memory.subject}</h2><p>{memory.content}</p>
              <dl><div><dt>Source</dt><dd>{memory.source}</dd></div><div><dt>Purpose</dt><dd>{memory.purpose}</dd></div><div><dt>Provenance</dt><dd>{memory.provenance}</dd></div></dl>
              <footer><span>{memory.confidence}% confidence</span><span>{memory.retentionDays}d retention</span></footer>
              <div className="memory-card-actions"><button className="text-button" onClick={() => beginCorrection(memory)}><ArchiveRestore size={15} /> Correct</button><button className="text-button danger-text" onClick={() => void erase(memory._id)}><Trash2 size={15} /> Erase</button></div>
            </article>
          ))}
        </div>
      </div>

      {selected && <article className="surface correction-editor">
        <div className="surface-header"><div><p className="kicker">Append, never overwrite</p><h2>Correct memory</h2></div><button className="text-button" onClick={() => setSelected(null)}>Cancel</button></div>
        <p>The current record becomes superseded. A new active successor carries the corrected content.</p>
        <label>Corrected content<textarea value={correction} onChange={(event) => setCorrection(event.target.value)} maxLength={2000} /></label>
        <label>Correction reason<input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} /></label>
        <button className="button primary" disabled={busy} onClick={() => void correct()}><CheckCircle2 size={16} /> Append correction</button>
      </article>}

      <article className="surface provenance-ledger">
        <div className="surface-header"><div><p className="kicker">Append-only provenance</p><h2>Memory lifecycle</h2></div><History size={22} /></div>
        {ledger.length === 0 ? <div className="empty-state compact"><FileClock size={26} /><h2>No lifecycle events</h2><p>Governed writes, corrections, and erasures will appear here.</p></div> : <div className="provenance-list">{[...ledger].sort((left, right) => right.createdAt - left.createdAt).map((memory) => {
          const state = memory.deletedAt !== undefined ? "erased" : memory.supersededAt !== undefined ? "superseded" : "active";
          return <div className={`provenance-row state-${state}`} key={memory._id}>
            <span className="provenance-node" />
            <div><strong>{state === "erased" ? "Content erased" : memory.subject}</strong><p>{state === "erased" ? "Sensitive fields removed; tombstone retained." : memory.source}</p></div>
            <span>{memory.safetyState === "quarantined" && state === "active" ? "quarantined" : state}</span>
            <code>{memory.policyVersion ?? "memory-policy.v1"}</code>
            <time>{new Date(memory.createdAt).toLocaleString()}</time>
          </div>;
        })}</div>}
      </article>
    </section>
  );
}
