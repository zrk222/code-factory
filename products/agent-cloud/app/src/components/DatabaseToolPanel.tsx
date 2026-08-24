import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { Database, KeyRound, LockKeyhole, Plus, ShieldCheck } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";

export function DatabaseToolPanel({ agentSpec }: { agentSpec: Doc<"agentSpecs"> }) {
  const state = useQuery(api.databaseTools.list, { agentSpecId: agentSpec._id });
  const configure = useMutation(api.databaseTools.configureConnection);
  const register = useMutation(api.databaseTools.registerOperation);
  const publish = useMutation(api.databaseTools.publishOperation);
  const [engine, setEngine] = useState<"postgresql" | "mysql" | "sql-server" | "mongodb" | "warehouse">("postgresql");
  const [endpointRef, setEndpointRef] = useState("env:DATABASE_ENDPOINT");
  const [secretRef, setSecretRef] = useState("vault:agent-oven/database/operations");
  const [namespace, setNamespace] = useState("operations");
  const [operationKey, setOperationKey] = useState("lookup_open_orders");
  const [target, setTarget] = useState("operations.open_orders");
  const [mode, setMode] = useState<"read" | "write">("read");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connect() {
    setBusy(true); setNotice(null);
    try { const result = await configure({ agentSpecId: agentSpec._id, engine, label: "Operations database", endpointRef, secretRef, allowedNamespaces: namespace.split(",").map((item) => item.trim()).filter(Boolean) }); setNotice(`${result.marker}. A trusted adapter must validate the reference before any query can run.`); }
    catch (error) { setNotice(error instanceof Error ? error.message : "Could not configure database."); }
    finally { setBusy(false); }
  }

  async function addOperation() {
    if (!state?.connection) return;
    setBusy(true); setNotice(null);
    try { const result = await register({ connectionId: state.connection._id, operationKey, label: operationKey.replaceAll("_", " "), mode, executionKind: mode === "write" ? "stored-procedure" : "view", target, parameterNames: ["workspace_id"] }); setNotice(`${result.marker}. Publish after reviewing the target and parameter contract.`); }
    catch (error) { setNotice(error instanceof Error ? error.message : "Could not add database operation."); }
    finally { setBusy(false); }
  }

  return <section className="database-tool surface" aria-labelledby="database-tool-title">
    <header className="governed-runtime-header"><div><p className="kicker">Remote database ingredient</p><h2 id="database-tool-title">Let agents use operations data—without giving them SQL.</h2><p>Allowlist views and named operations. Reads queue to the hosted adapter; every write needs a distinct human reviewer and an exact parameter digest.</p></div><span className={state?.connection?.status === "active" ? "ready" : "draft"}><Database size={14} /> {state?.connection?.status ?? "not connected"}</span></header>
    {!state?.connection ? <div className="database-config-grid"><label>Database type<select value={engine} onChange={(event) => setEngine(event.target.value as typeof engine)}><option value="postgresql">PostgreSQL</option><option value="mysql">MySQL</option><option value="sql-server">SQL Server</option><option value="mongodb">MongoDB</option><option value="warehouse">Data warehouse</option></select></label><label>Endpoint reference<input value={endpointRef} onChange={(event) => setEndpointRef(event.target.value)} /><small><KeyRound size={12} /> Name of a worker-side environment or vault value—not a URL with credentials.</small></label><label>Secret reference<input value={secretRef} onChange={(event) => setSecretRef(event.target.value)} /><small><LockKeyhole size={12} /> Vault, Key Vault, Secrets Manager, or environment reference only.</small></label><label>Allowed schema / namespace<input value={namespace} onChange={(event) => setNamespace(event.target.value)} /></label><button className="button primary" disabled={busy} onClick={() => void connect()}><Plus size={14} /> Add secure database</button></div> : <>
      <div className="database-connection-summary"><Database size={19} /><div><strong>{state.connection.label}</strong><small>{state.connection.engine} · {state.connection.endpointRef} · namespaces {state.connection.allowedNamespaces.join(", ")}</small></div><span>{state.connection.status}</span></div>
      <div className="database-operation-builder"><label>Operation name<input value={operationKey} onChange={(event) => setOperationKey(event.target.value)} /></label><label>Access<select value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}><option value="read">Read-only view</option><option value="write">Approved stored procedure</option></select></label><label>Allowlisted target<input value={target} onChange={(event) => setTarget(event.target.value)} /></label><button className="button secondary" disabled={busy} onClick={() => void addOperation()}><Plus size={14} /> Add operation</button></div>
      <div className="database-operations">{state.operations.length === 0 ? <p>No operations published. The agent cannot access this database yet.</p> : state.operations.map((operation) => <article key={operation._id}><ShieldCheck size={16} /><div><strong>{operation.label}</strong><small>{operation.mode} · {operation.executionKind} · {operation.target}</small></div><span>{operation.approvalRequired ? "human approval" : "read only"}</span>{operation.status === "draft" && <button className="text-button" onClick={() => void publish({ operationId: operation._id })}>Publish</button>}</article>)}</div>
    </>}
    <p className="operations-caveat"><ShieldCheck size={14} /> Arbitrary SQL, raw credentials, row payloads, and browser-side database calls are structurally excluded.</p>{notice && <p className="knowledge-notice" role="status">{notice}</p>}
  </section>;
}
