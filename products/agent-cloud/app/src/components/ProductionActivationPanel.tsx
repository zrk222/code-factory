import { useQuery } from "convex/react";
import { AlertTriangle, CheckCircle2, CircleDashed, LockKeyhole, ShieldCheck } from "lucide-react";
import type { Id } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";

type Props = { workspaceId: Id<"workspaces"> };

function PhaseCard({ label, ready, readyCopy, blockedCopy }: { label: string; ready: boolean; readyCopy: string; blockedCopy: string }) {
  return <article className={`activation-phase ${ready ? "ready" : "blocked"}`}>
    <span className="activation-phase-icon" aria-hidden="true">{ready ? <CheckCircle2 size={18} /> : <CircleDashed size={18} />}</span>
    <div><small>{label}</small><strong>{ready ? readyCopy : blockedCopy}</strong></div>
  </article>;
}

/** Renders the sanitized, administrator-only production activation explanation. */
export function ProductionActivationPanel({ workspaceId }: Props) {
  const readiness = useQuery(api.operations.productionReadiness, { workspaceId });
  if (!readiness || readiness.marker !== "PRODUCTION_READINESS_EXPLAINED") {
    return <section className="production-activation surface operation-card" aria-busy="true" aria-labelledby="activation-title">
      <header className="surface-header"><div><p className="kicker">Go-live cockpit</p><h2 id="activation-title">Checking production activation...</h2></div><CircleDashed className="spin-slow" size={22} /></header>
      <p className="activation-loading">Reading sanitized deployment status from the trusted server boundary.</p>
    </section>;
  }

  return <section className={`production-activation surface operation-card ${readiness.status}`} aria-labelledby="activation-title">
    <header className="surface-header activation-header">
      <div><p className="kicker">Go-live cockpit</p><h2 id="activation-title">Know what is live—and what still needs an operator.</h2><p>A working sign-in is the foundation. Billing, email, runtime, backups, and incident ownership complete enterprise operations.</p></div>
      <span className={`activation-status ${readiness.status}`}><ShieldCheck size={16} />{readiness.status === "ready" ? "Enterprise ready" : readiness.status === "pilot" ? "Pilot live" : "Activation blocked"}</span>
    </header>

    <div className="activation-phase-grid" aria-label="Production readiness phases">
      <PhaseCard label="Phase 1 · Control plane" ready={readiness.controlPlaneReady} readyCopy="Live" blockedCopy="Setup required" />
      <PhaseCard label="Phase 2 · Enterprise operations" ready={readiness.enterpriseReady} readyCopy="Ready" blockedCopy="Activation required" />
    </div>

    <div className="activation-progress" aria-label={`${readiness.summary.ready} of ${readiness.summary.total} production controls ready`}>
      <div><strong>{readiness.summary.ready} of {readiness.summary.total} controls ready</strong><span>{readiness.enterpriseReady ? "All declared controls are configured." : "Complete the open controls below before claiming enterprise readiness."}</span></div>
      <progress max={readiness.summary.total} value={readiness.summary.ready}>{readiness.summary.ready} of {readiness.summary.total}</progress>
    </div>

    <div className="activation-control-list" data-control-count={readiness.controls.length}>
      {readiness.controls.map((item) => <article className={`activation-control ${item.status}`} key={item.key}>
        <span className="activation-control-icon" aria-hidden="true">{item.status === "ready" ? <CheckCircle2 size={16} /> : item.status === "invalid" ? <AlertTriangle size={16} /> : <CircleDashed size={16} />}</span>
        <div><div className="activation-control-title"><strong>{item.label}</strong><small>{item.category === "foundation" ? "Control plane" : "Enterprise operations"}</small></div>{item.nextAction && <p>{item.nextAction}</p>}</div>
        <span className={`activation-control-state ${item.status}`}>{item.status}</span>
      </article>)}
    </div>

    <footer className="activation-boundary"><LockKeyhole size={14} /><span><strong>Sanitized by design.</strong> No secret values or references are returned to this page. A configured reference still requires an external activation receipt.</span></footer>
  </section>;
}
