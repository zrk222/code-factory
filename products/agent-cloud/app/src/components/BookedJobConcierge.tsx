import { useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import { ArrowRight, CalendarCheck2, Check, CircleDollarSign, KeyRound, MapPin, MessageSquareText, Play, ShieldCheck, Sparkles, UserCheck } from "lucide-react";

const adapterRecipes = [
  { kind: "calendar" as const, provider: "google-calendar", label: "Google Calendar", secretRef: "env:GOOGLE_CALENDAR_OAUTH_REF", Icon: CalendarCheck2 },
  { kind: "messaging" as const, provider: "twilio", label: "Twilio SMS", secretRef: "env:TWILIO_CONNECTION_REF", Icon: MessageSquareText },
  { kind: "billing" as const, provider: "stripe", label: "Stripe", secretRef: "env:STRIPE_CONNECTION_REF", Icon: CircleDollarSign },
  { kind: "model" as const, provider: "openai", label: "OpenAI", secretRef: "env:OPENAI_API_KEY", Icon: Sparkles },
];

export function BookedJobConcierge({ agentSpec }: { agentSpec: Doc<"agentSpecs"> }) {
  const data = useQuery(api.concierge.overview, { agentSpecId: agentSpec._id });
  const saveProfile = useMutation(api.concierge.saveProfile);
  const configureAdapter = useMutation(api.concierge.configureAdapter);
  const submitLead = useMutation(api.concierge.submitLead);
  const requestBooking = useMutation(api.concierge.requestBooking);
  const approveBooking = useMutation(api.concierge.approveBooking);
  const recordOutcome = useMutation(api.concierge.recordOutcome);
  const [serviceName, setServiceName] = useState("Emergency plumbing");
  const [serviceArea, setServiceArea] = useState("Toronto and nearby neighbourhoods");
  const [duration, setDuration] = useState("90");
  const [minimumScore, setMinimumScore] = useState("80");
  const [jobValue, setJobValue] = useState("325");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const latestLead = data?.leads[0];
  const pendingApproval = data?.approvals.find((item) => item.status === "pending");
  const latestBooking = data?.bookings[0];
  const productionReady = adapterRecipes.every((recipe) => data?.adapters.some((adapter) => adapter.kind === recipe.kind && adapter.status === "active"));
  const progress = useMemo(() => [
    { label: "Business recipe", done: Boolean(data?.profile), detail: data?.profile ? `${data.profile.serviceName} · ${data.profile.serviceArea}` : "Tell us what you book and where." },
    { label: "Sample lead", done: Boolean(latestLead), detail: latestLead ? `${latestLead.score}/100 · ${latestLead.classification}` : "Run a safe example with no customer data." },
    { label: "Human decision", done: Boolean(latestBooking), detail: pendingApproval ? "Exact slot is waiting for your approval." : latestBooking ? "Slot approved once." : "No booking happens without you." },
    { label: "Outcome", done: Boolean(data?.outcomes.some((item) => item.evidenceClass === "observed")), detail: data?.outcomes.some((item) => item.evidenceClass === "observed") ? "Observed result recorded." : "Modeled value stays clearly labeled." },
  ], [data, latestLead, latestBooking, pendingApproval]);

  async function act(work: () => Promise<unknown>, success: string) {
    setBusy(true); setNotice(null);
    try { await work(); setNotice(success); }
    catch (error) { setNotice(error instanceof Error ? error.message : "That step could not be completed."); }
    finally { setBusy(false); }
  }
  const save = () => act(() => saveProfile({ agentSpecId: agentSpec._id, serviceName, serviceArea, appointmentDurationMinutes: Number(duration), minimumLeadScore: Number(minimumScore), modeledJobValueCents: Math.round(Number(jobValue) * 100) }), "Your concierge is sandbox-ready. No credits were charged.");
  const testLead = () => act(() => submitLead({ agentSpecId: agentSpec._id, leadAlias: "Sample homeowner", serviceRequested: serviceName, areaLabel: serviceArea, serviceMatch: true, areaMatch: true, urgency: "urgent", contactReady: true, contactConsent: true }), "Sample lead qualified with server-owned reasons. Review the score, then request a slot.");
  const askForSlot = () => latestLead && act(() => requestBooking({ leadId: latestLead._id, environment: "sandbox", proposedStartAt: Date.now() + 86400000 }), "The exact sample slot is waiting for your approval.");
  const approveSlot = () => pendingApproval && act(() => approveBooking({ approvalId: pendingApproval._id, slotDigest: pendingApproval.slotDigest, approve: true }), "Sample booking confirmed. Its value remains modeled until you record a real outcome.");
  const markAttended = () => latestBooking && act(() => recordOutcome({ bookingId: latestBooking._id, type: "attended" }), "Attendance recorded as an observed outcome.");

  return <section className="concierge-studio" aria-labelledby="concierge-title">
    <header className="concierge-hero"><div><p className="eyebrow">Booked Job Concierge · guided setup</p><h2 id="concierge-title">Turn the next qualified inquiry into a booked job.</h2><p>Answer four business questions, test the full workflow without customer data, then connect production services when you are ready.</p></div><div className="concierge-price"><small>Published recipe price</small><strong>55 credits</strong><span>Sandbox setup and testing: 0 credits</span><span>Activated versions stay frozen until you approve an upgrade.</span></div></header>
    <div className="concierge-layout">
      <article className="surface concierge-wizard">
        <div className="concierge-step"><span>1</span><div><small>Your service</small><h3>What should the agent book?</h3></div></div>
        <label>Service customers ask for<input aria-label="Service customers ask for" value={serviceName} onChange={(event) => setServiceName(event.target.value)} /></label>
        <label>Where do you serve?<div className="input-with-icon"><MapPin size={16} /><input aria-label="Where do you serve?" value={serviceArea} onChange={(event) => setServiceArea(event.target.value)} /></div></label>
        <div className="concierge-step"><span>2</span><div><small>Your booking rules</small><h3>What counts as ready?</h3></div></div>
        <div className="form-row"><label>Appointment length<select value={duration} onChange={(event) => setDuration(event.target.value)}><option value="30">30 minutes</option><option value="60">60 minutes</option><option value="90">90 minutes</option><option value="120">2 hours</option></select></label><label>Minimum fit score<select value={minimumScore} onChange={(event) => setMinimumScore(event.target.value)}><option value="70">70 · flexible</option><option value="80">80 · recommended</option><option value="90">90 · strict</option></select></label></div>
        <label>Typical booked-job value<div className="money-input"><span>$</span><input aria-label="Typical booked-job value" inputMode="decimal" value={jobValue} onChange={(event) => setJobValue(event.target.value)} /></div><small className="field-help">Used for modeled pipeline only. Revenue is not measured until you confirm it.</small></label>
        <div className="concierge-step"><span>3</span><div><small>Human control</small><h3>You approve every booking.</h3></div></div>
        <div className="approval-promise"><ShieldCheck size={20} /><p><strong>Approval required is locked on.</strong><span>Knowledge can explain a recommendation. It cannot book a customer by itself.</span></p></div>
        <button className="button secondary wide" disabled={busy} onClick={() => void save()}><Check size={16} /> Save my booking setup</button>
      </article>
      <aside className="surface concierge-progress" aria-live="polite"><p className="kicker">Live work line</p><h3>See what the agent knows and what happens next.</h3><ol>{progress.map((item, index) => <li className={item.done ? "done" : ""} key={item.label}><span>{item.done ? <Check size={14} /> : index + 1}</span><div><strong>{item.label}</strong><small>{item.detail}</small></div></li>)}</ol>
        {latestLead && <div className="decision-explain"><small>Why this lead scored {latestLead.score}</small>{latestLead.decisionReasons.map((reason) => <span key={reason}><Check size={12} /> {reason.replaceAll("-", " ")}</span>)}</div>}
        {!data?.profile ? <p className="next-action"><ArrowRight size={14} /> Save the setup to unlock a safe sample.</p> : !latestLead ? <button className="button primary wide" disabled={busy} onClick={() => void testLead()}><Play size={16} /> Test with a sample lead</button> : latestLead.status === "new" && latestLead.classification === "qualified" ? <button className="button primary wide" disabled={busy} onClick={() => void askForSlot()}><CalendarCheck2 size={16} /> Request sample booking</button> : pendingApproval ? <button className="button primary wide" disabled={busy} onClick={() => void approveSlot()}><UserCheck size={16} /> Approve exact sample slot</button> : latestBooking?.status === "confirmed" ? <button className="button primary wide" disabled={busy} onClick={() => void markAttended()}><Check size={16} /> Record attended</button> : <p className="next-action success"><Check size={14} /> Sandbox journey complete.</p>}
        {notice && <p className="concierge-notice" role="status">{notice}</p>}
      </aside>
    </div>
    <section className="concierge-metrics" aria-label="Booked job outcomes"><article><small>Qualified leads</small><strong>{data?.metrics.qualified ?? 0}</strong><span>of {data?.metrics.leads ?? 0} total</span></article><article><small>Booked jobs</small><strong>{data?.metrics.bookings ?? 0}</strong><span>{data?.metrics.attended ?? 0} attended</span></article><article className="modeled"><small>Modeled pipeline</small><strong>${((data?.metrics.modeledPipelineValueCents ?? 0) / 100).toLocaleString()}</strong><span>Estimate, not revenue</span></article><article className="observed"><small>Observed revenue</small><strong>{data?.metrics.observedRevenueCents ? `$${(data.metrics.observedRevenueCents / 100).toLocaleString()}` : "Not measured"}</strong><span>Only confirmed outcomes</span></article></section>
    <section className="surface concierge-connections"><header><div><p className="kicker">4 / Go live when ready</p><h3>Connect the services you already use.</h3><p>Agent Oven stores an opaque vault or environment reference—not the key. A trusted validation worker must activate every connection.</p></div><span className={productionReady ? "ready" : "blocked"}>{productionReady ? "PRODUCTION READY" : "SANDBOX ONLY"}</span></header><div>{adapterRecipes.map(({ kind, provider, label, secretRef, Icon }) => { const adapter = data?.adapters.find((item) => item.kind === kind); return <article key={kind}><Icon size={19} /><span><strong>{label}</strong><small>{adapter?.status === "active" ? "Validated and active" : adapter?.status === "setup-required" ? "Waiting for tenant validation" : "Not connected"}</small></span><button className="text-button" disabled={busy || adapter?.status === "active"} onClick={() => void act(() => configureAdapter({ agentSpecId: agentSpec._id, kind, provider, accountLabel: label, secretRef }), `${label} reference saved. Tenant validation is still required.`)}><KeyRound size={13} /> {adapter ? "Update reference" : "Use secure reference"}</button></article>; })}</div></section>
  </section>;
}
