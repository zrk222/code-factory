import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { Ban, Fingerprint, KeyRound, ShieldCheck, Zap } from "lucide-react";

type ApprovedRun = Doc<"runs"> & { approval: Doc<"approvals"> | null };

export function TrustGatewayPanel({ run }: { run: ApprovedRun }) {
  const issueCapability = useMutation(api.trust.issueCapability);
  const authorizeToolCall = useMutation(api.trust.authorizeToolCall);
  const revokeCapability = useMutation(api.trust.revokeCapability);
  const trust = useQuery(api.trust.status, { runId: run._id });
  const grants = trust?.grants ?? [];
  const decisions = trust?.decisions ?? [];
  const [audience, setAudience] = useState("github-connector");
  const [resource, setResource] = useState(`branch:${run.branch}`);
  const [maxCost, setMaxCost] = useState("0.20");
  const [requestCost, setRequestCost] = useState("0.15");
  const [requestKey, setRequestKey] = useState("branch-write-01");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const exact = {
    subject: "pr-assurance-agent",
    audience,
    scope: "repository:branch-write",
    resource,
    environment: "test" as const,
    actionDigest: run.actionDigest,
  };

  async function execute(operation: () => Promise<{ marker: string }>) {
    setBusy(true);
    setMessage(null);
    try {
      const result = await operation();
      setMessage(`${result.marker}: policy evidence recorded; no connector invoked.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Trust policy operation failed.");
    } finally {
      setBusy(false);
    }
  }

  function issue() {
    return execute(() => issueCapability({
      runId: run._id,
      ...exact,
      risk: "high",
      maxCostCents: Math.round(Number(maxCost) * 100),
      ttlSeconds: 300,
    }));
  }

  function authorize(grantId: Doc<"capabilityGrants">["_id"]) {
    return execute(() => authorizeToolCall({
      grantId,
      requestKey,
      ...exact,
      requestedCostCents: Math.round(Number(requestCost) * 100),
    }));
  }

  return (
    <article className="surface trust-gateway">
      <div className="surface-header">
        <div><p className="kicker">Execution-time authorization</p><h2>Trust gateway</h2></div>
        <span className="trust-policy"><Fingerprint size={16} /> trust-policy.v1</span>
      </div>
      <p className="trust-intro">Mint a five-minute, one-use local capability for this exact approved action. Audience, scope, resource, environment, digest, and cost must all match at execution.</p>
      <div className="trust-boundary"><ShieldCheck size={17} /><span><strong>Supervised boundary</strong> This proves authorization and reserves spend atomically. It stores no raw credential and invokes no connector.</span></div>
      <div className="trust-controls">
        <label>Audience<input value={audience} onChange={(event) => setAudience(event.target.value)} maxLength={120} /></label>
        <label>Exact resource<input value={resource} onChange={(event) => setResource(event.target.value)} maxLength={300} /></label>
        <label>Maximum cost<div className="money-input"><span>$</span><input inputMode="decimal" value={maxCost} onChange={(event) => setMaxCost(event.target.value)} /></div></label>
        <button className="button primary" disabled={busy || run.approval?.status !== "approved"} onClick={() => void issue()}><KeyRound size={16} /> Issue 5-minute capability</button>
      </div>
      {run.approval?.status !== "approved" && <p className="inline-alert error">E_CAPABILITY_APPROVAL_REQUIRED: independent approval must bind the exact action digest first.</p>}
      {grants.length > 0 && <div className="capability-list">{grants.map((grant) => (
        <section className={`capability-row state-${grant.state}`} key={grant._id}>
          <div className="capability-identity"><KeyRound size={17} /><div><strong>{grant.audience}</strong><small>{grant.scope} · {grant.resource}</small></div></div>
          <div className="capability-facts"><span>{grant.state}</span><span>expires {new Date(grant.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span><span>ceiling ${(grant.maxCostCents / 100).toFixed(2)}</span></div>
          {grant.state === "active" && <div className="capability-actions">
            <label>Request key<input value={requestKey} onChange={(event) => setRequestKey(event.target.value)} maxLength={120} /></label>
            <label>Request cost<div className="money-input"><span>$</span><input inputMode="decimal" value={requestCost} onChange={(event) => setRequestCost(event.target.value)} /></div></label>
            <button className="button primary" disabled={busy} onClick={() => void authorize(grant._id)}><Zap size={15} /> Authorize exact action</button>
            <button className="text-button danger-text" disabled={busy} onClick={() => void execute(() => revokeCapability({ grantId: grant._id, reason: "Operator emergency revocation before tool execution." }))}><Ban size={15} /> Revoke</button>
          </div>}
        </section>
      ))}</div>}
      {decisions.length > 0 && <div className="trust-decisions"><strong>Allow decisions</strong>{decisions.map((decision) => <span key={decision._id}><ShieldCheck size={14} /> {decision.reasonCode} · {decision.requestKey} · {decision.requestDigest}</span>)}</div>}
      {message && <p className={`inline-alert ${message.includes("E_") ? "error" : ""}`} role="status">{message}</p>}
    </article>
  );
}
