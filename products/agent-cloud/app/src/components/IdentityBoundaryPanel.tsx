import { BadgeCheck, Building2, KeyRound, ShieldAlert, Users } from "lucide-react";

const roles = [
  ["Owner", "Membership administration and irreversible controls"],
  ["Admin", "Configuration without ownership transfer"],
  ["Operator", "Runs and bounded runtime operations"],
  ["Reviewer", "Independent approval and evidence review"],
  ["Viewer", "Read-only protected workspace data"],
] as const;

export function IdentityBoundaryPanel() {
  return (
    <article className="surface operation-card identity-boundary">
      <div className="surface-header"><div><p className="kicker">Deployment identity gate</p><h2>Workspace access boundary</h2></div><Building2 size={22} /></div>
      <div className="identity-state">
        <span><ShieldAlert size={18} /></span>
        <div><strong>OIDC session enforced</strong><p>Convex validates the identity token, then the server checks every route against an active workspace membership and minimum role.</p></div>
        <b>SERVER GUARDED</b>
      </div>
      <div className="identity-principles">
        <div><KeyRound size={17} /><span><strong>Identity is server-derived</strong>Convex combines verified issuer and subject; the client supplies no acting identity.</span></div>
        <div><BadgeCheck size={17} /><span><strong>Resource ownership is checked</strong>A valid membership in workspace A cannot read an AgentSpec belonging to workspace B.</span></div>
        <div><Users size={17} /><span><strong>Ownership cannot be orphaned</strong>Administration is owner-only and the final active owner cannot be revoked.</span></div>
      </div>
      <div className="role-matrix" aria-label="Workspace role model">
        {roles.map(([role, purpose]) => <div key={role}><strong>{role}</strong><span>{purpose}</span></div>)}
      </div>
      <p className="identity-next"><ShieldAlert size={14} /> Hosted activation remains blocked until an OIDC provider is configured and all legacy local routes are migrated in one reviewed release.</p>
    </article>
  );
}
