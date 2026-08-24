import { useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Id } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import {
  BadgeCheck,
  Bot,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Fingerprint,
  Handshake,
  PauseCircle,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  XCircle,
} from "lucide-react";

type Props = { workspaceId: Id<"workspaces"> };

async function digestText(value: string) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((item) => item.toString(16).padStart(2, "0")).join("");
}

export function AgentExchangePanel({ workspaceId }: Props) {
  const data = useQuery(api.agentExchange.overview, { workspaceId });
  const hire = useMutation(api.agentExchange.hire);
  const start = useMutation(api.agentExchange.start);
  const submitEvidence = useMutation(api.agentExchange.submitEvidence);
  const verify = useMutation(api.agentExchange.verify);
  const release = useMutation(api.agentExchange.release);
  const cancel = useMutation(api.agentExchange.cancel);
  const [selectedOfferId, setSelectedOfferId] = useState<string | null>(null);
  const [intentRef, setIntentRef] = useState("");
  const [artifactRefs, setArtifactRefs] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const selectedOffer = useMemo(() => data?.offers.find((offer) => offer.id === selectedOfferId) ?? null, [data, selectedOfferId]);

  if (data === undefined) return <section className="exchange-loading"><RefreshCw className="spin" size={19} /><span>Loading the result market…</span></section>;

  async function run(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setNotice(null);
    try {
      await action();
      setNotice(success);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The action was blocked.");
    } finally {
      setBusy(null);
    }
  }

  async function hireSelected() {
    if (!selectedOffer || !intentRef.trim()) return setNotice("Add the exact job or artifact reference before authorizing credits.");
    const intentDigest = await digestText(intentRef.trim());
    await run("hire", () => hire({
      workspaceId,
      offerId: selectedOffer.id,
      callerKind: "human",
      intentRef: intentRef.trim(),
      intentDigest,
      delegationDepth: 0,
      idempotencyKey: crypto.randomUUID(),
    }), `${selectedOffer.name} hired. Credits are reserved until its evidence passes.`);
  }

  async function submit(contract: NonNullable<typeof data>["contracts"][number]) {
    const refs = contract.evidenceCheckIds.map((checkId) => artifactRefs[`${contract._id}:${checkId}`]?.trim());
    if (refs.some((ref) => !ref)) return setNotice("Add one artifact reference for every required proof check.");
    const items = await Promise.all(contract.evidenceCheckIds.map(async (checkId, index) => ({
      checkId,
      artifactRef: refs[index]!,
      artifactDigest: await digestText(refs[index]!),
      status: "passed" as const,
    })));
    await run(String(contract._id), () => submitEvidence({ contractId: contract._id, items }), "Evidence submitted. A different authenticated reviewer must verify it.");
  }

  return (
    <section className="exchange-page" data-testid="outcome-exchange">
      <header className="exchange-hero">
        <div>
          <p className="eyebrow">Outcome Agent Exchange · supervised market</p>
          <h1>Hire the result.<br /><span>Release payment after proof.</span></h1>
          <p>Humans and authenticated agents can hire the same bounded workforce. Every job freezes its price, authority, evidence checklist, budget, and expiry before work begins.</p>
          <div className="exchange-hero-actions"><a className="button primary" href="#agent-catalog">Browse six result agents</a><a className="text-button" href="/.well-known/agent-card.json"><TerminalSquare size={16} /> Agent Card</a></div>
        </div>
        <div className="outcome-loop" aria-label="Outcome contract payment flow">
          <div><Bot size={20} /><strong>Hire</strong><small>exact intent</small></div><span>→</span>
          <div><Fingerprint size={20} /><strong>Prove</strong><small>artifact digests</small></div><span>→</span>
          <div><ShieldCheck size={20} /><strong>Verify</strong><small>different identity</small></div><span>→</span>
          <div><CircleDollarSign size={20} /><strong>Release</strong><small>fixed credits</small></div>
        </div>
      </header>

      <div className="exchange-stats">
        <article><Handshake size={20} /><span><strong>{data.offers.length}</strong><small>preconfigured result agents</small></span></article>
        <article><CircleDollarSign size={20} /><span><strong>{data.account?.availableCredits ?? 0}</strong><small>credits available</small></span></article>
        <article><Fingerprint size={20} /><span><strong>{data.contracts.filter((contract) => contract.state === "verified" || contract.state === "paid").length}</strong><small>results independently verified</small></span></article>
        <article><ShieldCheck size={20} /><span><strong>1 hop</strong><small>maximum agent delegation</small></span></article>
      </div>

      <section className="surface payment-rails" aria-labelledby="payment-rails-title">
        <header><div><p className="kicker">Settlement readiness</p><h2 id="payment-rails-title">One active rail. No pretend integrations.</h2></div><span className="boundary-chip"><ShieldCheck size={15} /> Real money stays off until provider-verified</span></header>
        <div>{data.paymentRails.map((rail) => <article key={rail.rail} className={rail.status}><span>{rail.status === "active" ? <CheckCircle2 size={17} /> : <PauseCircle size={17} />}</span><div><strong>{rail.rail}</strong><small>{rail.detail}</small></div><em>{rail.status}</em></article>)}</div>
      </section>

      <section id="agent-catalog" className="exchange-catalog">
        <header className="section-heading"><div><p className="kicker">Preconfigured workforce</p><h2>Six jobs with an objective finish line.</h2></div><p>Each price is fixed by the server. Each agent proposes bounded work. None can certify, pay, merge, write production data, or message a customer without the stated gate.</p></header>
        <div className="exchange-offer-grid">{data.offers.map((offer) => <article key={offer.id} className={selectedOfferId === offer.id ? "selected" : ""}>
          <header><span>{offer.category}</span><em>{offer.resultCredits} credits on verified result</em></header>
          <h3>{offer.name}</h3><p>{offer.outcome}</p>
          <dl><div><dt><Clock3 size={14} /> Window</dt><dd>{offer.deliveryHours}h</dd></div><div><dt><Fingerprint size={14} /> Proofs</dt><dd>{offer.evidenceChecks.length}</dd></div></dl>
          <div className="offer-boundary"><ShieldCheck size={15} /><span><strong>Authority boundary</strong><small>{offer.authority}</small></span></div>
          <button className="button primary" onClick={() => { setSelectedOfferId(offer.id); setNotice(null); }}>Hire for result</button>
        </article>)}</div>
      </section>

      {selectedOffer && <section className="surface hire-contract" aria-labelledby="hire-title">
        <div><p className="kicker">Authorize one bounded job</p><h2 id="hire-title">Hire {selectedOffer.name}</h2><p>{selectedOffer.deliverable}</p></div>
        <label>Exact job or artifact reference<input value={intentRef} onChange={(event) => setIntentRef(event.target.value)} placeholder="repo://org/project/pull/42" /></label>
        <div className="contract-facts"><span><Fingerprint size={15} /> {selectedOffer.evidenceChecks.length} exact checks</span><span><Clock3 size={15} /> expires after 24h</span><span><CircleDollarSign size={15} /> {selectedOffer.resultCredits} credits reserved</span></div>
        <ul>{selectedOffer.evidenceChecks.map((check) => <li key={check.id}><CheckCircle2 size={14} /> {check.label}</li>)}</ul>
        <div className="hire-actions"><button className="button primary" disabled={busy !== null} onClick={() => void hireSelected()}>{busy === "hire" ? "Sealing contract…" : `Authorize ${selectedOffer.resultCredits} credits`}</button><button className="text-button" onClick={() => setSelectedOfferId(null)}>Cancel</button></div>
      </section>}

      {notice && <div className="exchange-notice" role="status"><Sparkles size={16} /><span>{notice}</span></div>}

      <section className="exchange-contracts">
        <header className="section-heading"><div><p className="kicker">Live result contracts</p><h2>Supervise every state transition.</h2></div><p>These controls call the same authorized server functions available to machine clients.</p></header>
        {data.contracts.length === 0 ? <div className="surface exchange-empty"><Bot size={25} /><strong>No agents hired yet.</strong><p>Choose a fixed-price result above. A credit reservation is created only after authorization.</p></div> : <div className="contract-list">{data.contracts.map((contract) => {
          const offer = data.offers.find((candidate) => candidate.id === contract.offerId);
          return <article className="surface contract-card" key={contract._id}>
            <header><div><small>{contract.offerId}</small><h3>{contract.offerName}</h3></div><span className={`contract-state ${contract.state}`}>{contract.state}</span></header>
            <p>{contract.outcome}</p>
            <div className="contract-meta"><span><CircleDollarSign size={14} /> {contract.resultCredits} result credits</span><span><Clock3 size={14} /> {new Date(contract.expiresAt).toLocaleString()}</span><span><Fingerprint size={14} /> {contract.contractDigest}</span></div>
            {contract.state === "running" && <div className="evidence-entry"><strong>Bind one artifact to every proof check</strong>{contract.evidenceCheckIds.map((checkId) => <label key={checkId}>{offer?.evidenceChecks.find((check) => check.id === checkId)?.label ?? checkId}<input value={artifactRefs[`${contract._id}:${checkId}`] ?? ""} onChange={(event) => setArtifactRefs((current) => ({ ...current, [`${contract._id}:${checkId}`]: event.target.value }))} placeholder={`artifact://${checkId}`} /></label>)}<button className="button primary" disabled={busy !== null} onClick={() => void submit(contract)}>Submit proof set</button></div>}
            <div className="contract-actions">
              {contract.state === "accepted" && <button className="button primary" disabled={busy !== null} onClick={() => void run(String(contract._id), () => start({ contractId: contract._id }), "Agent work started inside the sealed contract.")}><Play size={15} /> Start work</button>}
              {contract.state === "evidence-submitted" && <button className="button primary" disabled={busy !== null} onClick={() => void run(String(contract._id), () => verify({ contractId: contract._id }), "Evidence verified independently. Result is ready for release.")}><BadgeCheck size={15} /> Verify as reviewer</button>}
              {contract.state === "verified" && <button className="button primary" disabled={busy !== null} onClick={() => void run(String(contract._id), () => release({ contractId: contract._id }), "Verified result credits released exactly once.")}><CircleDollarSign size={15} /> Release result payment</button>}
              {["accepted", "running", "evidence-submitted", "verified"].includes(contract.state) && <button className="button danger" disabled={busy !== null} onClick={() => void run(String(contract._id), () => cancel({ contractId: contract._id, disposition: contract.state === "verified" ? "disputed" : "canceled", reason: "Stopped by an accountable workspace administrator." }), "Contract stopped and reserved credits released.")}><XCircle size={15} /> {contract.state === "verified" ? "Dispute" : "Cancel"}</button>}
            </div>
          </article>;
        })}</div>}
      </section>
    </section>
  );
}
