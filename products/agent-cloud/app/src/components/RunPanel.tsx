import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { AlertTriangle, Check, CheckCircle2, Clock3, Coins, GitCommitHorizontal, LockKeyhole, RotateCcw, ShieldCheck, Sparkles, X } from "lucide-react";
import { TrustGatewayPanel } from "./TrustGatewayPanel";

type RunWithDetails = Doc<"runs"> & { gates: Doc<"gates">[]; approval: Doc<"approvals"> | null; adversarialReview: Doc<"adversarialApprovalReviews"> | null };

export function AdversarialReviewPanel({ review }: { review: Doc<"adversarialApprovalReviews"> | null }) {
  if (!review) return null;
  return <section className={`adversarial-review verdict-${review.verdict}`} aria-label="Adversarial approval review">
    <div className="adversarial-review-head"><div><p className="kicker">Adversarial approval agent</p><h3>{review.verdict.replace("-", " ")}</h3></div><span>{review.policyVersion}</span></div>
    <p>{review.reasonCodes.join(" · ")}</p>
    <div className="approval-checks">{review.checks.map((check) => <span className={check.passed ? "passed" : "failed"} key={check.id}>{check.passed ? <Check size={13} /> : <X size={13} />}{check.id}</span>)}</div>
    <div className="proof-delta"><strong>Proof Delta · {review.proofDelta.reviewScope} review</strong><span>{review.proofDelta.reusedEvidence.length} reused</span><span>{review.proofDelta.newEvidence.length} new</span><span>{review.proofDelta.missingEvidence.length} missing</span></div>
    <small>Prior evidence narrows attention only. It never carries forward approval authority.</small>
  </section>;
}

export function RunPanel({ runs }: { runs: RunWithDetails[] }) {
  const decide = useMutation(api.control.decideApproval);
  const reserveCall = useMutation(api.budget.reserveCall);
  const reconcileCall = useMutation(api.budget.reconcileCall);
  const releaseCall = useMutation(api.budget.releaseCall);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [rationale, setRationale] = useState("All deterministic gates passed; the heuristic warning is non-blocking.");
  const [message, setMessage] = useState<string | null>(null);
  const selected = runs.find((run) => run._id === selectedId) ?? runs[0];
  const budget = useQuery(api.budget.status, selected ? { runId: selected._id } : "skip");
  const budgetReservations = budget?.reservations ?? [];
  const [callKey, setCallKey] = useState("manual-check-01");
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("gpt-5-mini");
  const [estimate, setEstimate] = useState("0.25");
  const [actual, setActual] = useState("0.21");
  const [budgetMessage, setBudgetMessage] = useState<string | null>(null);
  const [budgetBusy, setBudgetBusy] = useState(false);

  async function runBudget(operation: () => Promise<{ marker: string }>) {
    setBudgetBusy(true);
    setBudgetMessage(null);
    try {
      const result = await operation();
      setBudgetMessage(`${result.marker}: authoritative ledger updated.`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Budget operation failed.";
      setBudgetMessage(detail.includes("E_BUDGET_EXCEEDED") ? "E_BUDGET_EXCEEDED: refused before provider work or ledger writes." : detail);
    } finally {
      setBudgetBusy(false);
    }
  }

  async function reserve() {
    if (!selected) return;
    await runBudget(() => reserveCall({
      runId: selected._id,
      callKey,
      provider,
      model,
      estimatedCostCents: Math.round(Number(estimate) * 100),
    }));
  }

  async function decideApproval(decision: "approved" | "rejected") {
    if (!selected?.approval) return;
    setMessage(null);
    try {
      const result = await decide({
        approvalId: selected.approval._id,
        actionDigest: selected.approval.actionDigest,
        decision,
        rationale,
      });
      setMessage(`${result.marker}: ${decision}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Decision failed.");
    }
  }

  if (!selected) {
    return <section className="empty-state"><Clock3 size={30} /><h2>No assurance runs yet</h2><p>Configure the agent and launch the six-gate proof sequence.</p></section>;
  }

  return (
    <section className="page-stack" aria-labelledby="runs-title">
      <header className="page-heading"><div><p className="eyebrow">Realtime run control</p><h1 id="runs-title">Proof before permission.</h1><p>Deterministic evidence and heuristic judgment stay visibly separate.</p></div></header>
      <div className="run-layout">
        <aside className="run-list surface" aria-label="Assurance runs">
          <div className="surface-header"><h2>Recent runs</h2><span>{runs.length}</span></div>
          {runs.map((run) => (
            <button className={`run-list-item ${run._id === selected._id ? "selected" : ""}`} key={run._id} onClick={() => setSelectedId(run._id)}>
              <span className={`run-status ${run.status}`} />
              <span><strong>{run.branch}</strong><small>{run.commitSha.slice(0, 8)} · ${(run.actualCostCents / 100).toFixed(2)}</small></span>
              <time>{new Date(run.startedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time>
            </button>
          ))}
        </aside>
        <div className="run-detail">
          <article className="surface run-summary">
            <div><p className="kicker">Run / {selected._id.slice(-6)}</p><h2>{selected.branch}</h2><p className="mono"><GitCommitHorizontal size={14} /> {selected.commitSha}</p></div>
            <div className="run-summary-meta"><span className={`state-pill ${selected.status}`}>{selected.status.replace("-", " ")}</span><strong>${(selected.actualCostCents / 100).toFixed(2)}</strong><small>actual run cost</small></div>
          </article>
          <div className="gate-list">
            {selected.gates.map((gate) => (
              <article className="gate-card" key={gate._id}>
                <span className={`gate-index ${gate.kind}`}>{gate.kind === "model" ? <Sparkles size={16} /> : <Check size={16} />}</span>
                <div><div className="gate-title"><strong>{gate.order}. {gate.name}</strong><span className={`evidence-label ${gate.evidenceClass}`}>{gate.evidenceClass}</span></div><p>{gate.summary}</p></div>
                <span className={`gate-result ${gate.status}`}>{gate.status === "warning" ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}{gate.status}</span>
              </article>
            ))}
          </div>
          <article className="surface budget-console">
            <div className="surface-header"><div><p className="kicker">Atomic cost admission</p><h2>Budget gateway</h2></div><LockKeyhole size={22} /></div>
            <p className="budget-intro">Reserve cost before provider work. Convex commits the ceiling check and reservation together, so competing calls cannot spend the same remaining cents.</p>
            {budget?.summary && <>
              <div className="budget-proofline"><span>{budget.marker}</span><span>{budget.summary.terminationReason}</span></div>
              <div className="budget-ledger">
                <div><span>Hard limit</span><strong>${(budget.summary.hardLimitCents / 100).toFixed(2)}</strong></div>
                <div><span>Settled</span><strong>${(budget.summary.settledCostCents / 100).toFixed(2)}</strong></div>
                <div><span>Reserved</span><strong>${(budget.summary.reservedCostCents / 100).toFixed(2)}</strong></div>
                <div className="remaining"><span>Remaining</span><strong>${(budget.summary.remainingCostCents / 100).toFixed(2)}</strong></div>
              </div>
              <div className="budget-utilization"><span style={{ width: `${budget.summary.utilizationPercent}%` }} /><small>{budget.summary.utilizationPercent}% committed</small></div>
            </>}
            <div className="budget-controls">
              <label>Idempotent call key<input value={callKey} onChange={(event) => setCallKey(event.target.value)} maxLength={120} /></label>
              <label>Provider<input value={provider} onChange={(event) => setProvider(event.target.value)} maxLength={120} /></label>
              <label>Model<input value={model} onChange={(event) => setModel(event.target.value)} maxLength={120} /></label>
              <label>Reserve dollars<div className="money-input"><span>$</span><input inputMode="decimal" value={estimate} onChange={(event) => setEstimate(event.target.value)} /></div></label>
              <button className="button primary" disabled={budgetBusy} onClick={() => void reserve()}><Coins size={16} /> Reserve before call</button>
            </div>
            {budgetReservations.length > 0 && <div className="reservation-list">{budgetReservations.map((reservation) => <div className={`reservation-row state-${reservation.state}`} key={reservation._id}>
              <div><strong>{reservation.callKey}</strong><small>{reservation.provider} / {reservation.model}</small></div>
              <span>{reservation.state}</span>
              <strong>${(reservation.estimatedCostCents / 100).toFixed(2)}</strong>
              {reservation.state === "reserved" ? <div className="reservation-actions"><label>Actual $<input inputMode="decimal" value={actual} onChange={(event) => setActual(event.target.value)} /></label><button className="text-button" disabled={budgetBusy} onClick={() => void runBudget(() => reconcileCall({ reservationId: reservation._id, actualCostCents: Math.round(Number(actual) * 100) }))}><Check size={15} /> Reconcile</button><button className="text-button danger-text" disabled={budgetBusy} onClick={() => void runBudget(() => releaseCall({ reservationId: reservation._id }))}><RotateCcw size={15} /> Release</button></div> : <time>{reservation.completedAt ? new Date(reservation.completedAt).toLocaleString() : "—"}</time>}
            </div>)}</div>}
            {budgetMessage && <p className={`inline-alert ${budgetMessage.includes("E_") ? "error" : ""}`} role="status">{budgetMessage}</p>}
            <p className="action-note"><ShieldCheck size={14} /> Ledger proof only: this console invokes no provider and stores no prompt, response, or credential.</p>
          </article>
          {selected.approval && (
            <article className="approval-card">
              <div className="approval-heading"><span><ShieldCheck size={24} /></span><div><p className="kicker">Independent approval</p><h2>{selected.approval.proposedAction}</h2></div></div>
              <dl className="approval-facts"><div><dt>Action digest</dt><dd className="mono">{selected.approval.actionDigest}</dd></div><div><dt>Requested by</dt><dd>{selected.approval.requestedBy}</dd></div><div><dt>Status</dt><dd>{selected.approval.status}</dd></div></dl>
              <AdversarialReviewPanel review={selected.adversarialReview} />
              {selected.approval.status === "pending" ? <>
                <label>Reviewer rationale<textarea value={rationale} onChange={(event) => setRationale(event.target.value)} maxLength={500} /></label>
                <div className="decision-actions"><button className="button danger" onClick={() => void decideApproval("rejected")}><X size={17} /> Reject proposal</button><button className="button primary" onClick={() => void decideApproval("approved")}><Check size={17} /> Approve proposal</button></div>
              </> : <div className="decision-complete"><CheckCircle2 size={20} /> Decision recorded as <strong>{selected.approval.status}</strong>. Replay is blocked.</div>}
              {message && <p className="inline-alert" role="status">{message}</p>}
            </article>
          )}
          <TrustGatewayPanel run={selected} />
        </div>
      </div>
    </section>
  );
}
