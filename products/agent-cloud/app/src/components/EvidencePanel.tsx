import type { Doc } from "../../convex/_generated/dataModel";
import { FileCheck2, Fingerprint, Link2, Radio, ShieldCheck } from "lucide-react";

export function EvidencePanel({ receipts, auditEvents }: { receipts: Doc<"receipts">[]; auditEvents: Doc<"auditEvents">[] }) {
  return (
    <section className="page-stack" aria-labelledby="evidence-title">
      <header className="page-heading"><div><p className="eyebrow">Evidence ledger</p><h1 id="evidence-title">A visible chain of custody.</h1><p>Prototype fingerprints prove internal lineage only. Every item is clearly labeled unsigned.</p></div><div className="prototype-warning"><Radio size={15} /> Prototype ledger · not cryptographically signed</div></header>
      <div className="evidence-grid">
        <article className="surface evidence-list">
          <div className="surface-header"><div><p className="kicker">Receipt chain</p><h2>Recent evidence</h2></div><Fingerprint size={22} /></div>
          {receipts.length === 0 ? <div className="empty-inline"><FileCheck2 size={22} /> Run an assurance flow to create evidence.</div> : receipts.map((receipt) => (
            <div className="receipt-row" key={receipt._id}>
              <span className="receipt-icon"><Link2 size={16} /></span>
              <div><strong>{receipt.event}</strong><code>{receipt.fingerprint}</code></div>
              <div className="receipt-meta"><span>{receipt.type}</span><span className="unsigned">{receipt.signatureState}</span><time>{new Date(receipt.createdAt).toLocaleString()}</time></div>
            </div>
          ))}
        </article>
        <article className="surface audit-list">
          <div className="surface-header"><div><p className="kicker">Audit stream</p><h2>Who changed what</h2></div><ShieldCheck size={22} /></div>
          {auditEvents.map((event) => (
            <div className="audit-row" key={event._id}><span className="audit-node" /><div><strong>{event.event}</strong><p>{event.detail}</p><small>{event.actor} · {new Date(event.createdAt).toLocaleString()}</small></div></div>
          ))}
        </article>
      </div>
    </section>
  );
}
