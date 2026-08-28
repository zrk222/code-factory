import { useState } from "react";
import { useMutation } from "convex/react";
import { Coins, KeyRound, Link2, Router, ShieldCheck } from "lucide-react";
import type { Doc, Id } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";

type Props = { agentSpec: Doc<"agentSpecs">; connections: Doc<"providerConnections">[]; account: Doc<"creditAccounts"> | null; transactions: Doc<"creditTransactions">[]; plans: Array<{ plan: string; name: string; monthlyCredits: number; agentLimit: number; audience: string }>; binding: Doc<"inferenceBindings"> | null };

export function BillingInferencePanel({ agentSpec, connections, account, transactions, plans, binding }: Props) {
  const bind = useMutation(api.inferenceBindings.bind);
  const [mode, setMode] = useState<"inherit-workspace" | "dedicated">(binding?.mode ?? "inherit-workspace");
  const [connectionId, setConnectionId] = useState<string>(binding?.providerConnectionId ?? "");
  const [profile, setProfile] = useState(agentSpec.providerProfile);
  const [notice, setNotice] = useState<string | null>(null);

  async function saveBinding() {
    try {
      const result = await bind({ agentSpecId: agentSpec._id, mode, providerConnectionId: mode === "dedicated" ? connectionId as Id<"providerConnections"> : undefined, providerProfile: profile });
      setNotice(`${result.status === "ready" ? "Ready" : "Setup required"}: inference binding saved without exposing the API key.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not save the inference binding."); }
  }

  return (
    <section className="commercial-console surface operation-card" aria-labelledby="commercial-title">
      <header className="surface-header"><div><p className="kicker">Credits + customer-owned inference</p><h2 id="commercial-title">One platform ledger. Separate model spend.</h2></div><Coins size={22} /></header>
      <div className="credit-account"><div><small>Plan</small><strong>{account?.plan ?? "not initialized"}</strong></div><div><small>Available</small><strong>{account?.availableCredits ?? 0}</strong></div><div><small>Reserved</small><strong>{account?.reservedCredits ?? 0}</strong></div><div><small>Spent</small><strong>{account?.spentCredits ?? 0}</strong></div><div><small>Monthly grant</small><strong>{account?.monthlyAllocation ?? 0}</strong></div></div>
      <div className="ledger-separation"><span><Coins size={16} /><b>Agent Oven credits</b><small>Recipes, memory, connectors, orchestration, proof</small></span><i>+</i><span><KeyRound size={16} /><b>BYOK inference</b><small>Paid directly through your selected model provider</small></span></div>
      <div className="plan-strip">{plans.map((plan) => <article className={account?.plan === plan.plan ? "current" : ""} key={plan.plan}><small>{account?.plan === plan.plan ? "Current" : plan.name}</small><strong>{plan.monthlyCredits.toLocaleString()} credits/mo</strong><span>Up to {plan.agentLimit} agents</span><p>{plan.audience}</p></article>)}</div>
      <div className="binding-config"><header><Router size={18} /><div><strong>Inference for {agentSpec.name}</strong><small>Reuse a workspace key or isolate this agent with its own reference.</small></div><em>{binding?.status ?? "not configured"}</em></header><div className="mode-cards"><button className={mode === "inherit-workspace" ? "selected" : ""} onClick={() => setMode("inherit-workspace")}><Link2 size={16} /><strong>Reuse workspace route</strong><small>Best for simple teams</small></button><button className={mode === "dedicated" ? "selected" : ""} onClick={() => setMode("dedicated")}><KeyRound size={16} /><strong>Dedicated agent key</strong><small>Best for isolation and chargeback</small></button></div><div className="binding-fields"><label>Model route<select value={profile} onChange={(event) => setProfile(event.target.value as typeof profile)}><option value="economy">Economy</option><option value="balanced">Balanced</option><option value="highest-quality">Highest quality</option></select></label>{mode === "dedicated" && <label>Saved provider reference<select value={connectionId} onChange={(event) => setConnectionId(event.target.value)}><option value="">Choose a configured reference</option>{connections.map((connection) => <option key={connection._id} value={connection._id}>{connection.label} · {connection.provider}</option>)}</select></label>}<button className="button secondary" disabled={mode === "dedicated" && !connectionId} onClick={() => void saveBinding()}><ShieldCheck size={15} /> Save inference binding</button></div></div>
      {transactions.length > 0 && <div className="credit-ledger"><strong>Recent platform credit entries</strong>{transactions.slice(0, 6).map((entry) => <span key={entry._id}><b>{entry.kind}</b><small>{entry.reference}</small><em>{entry.credits} credits · {entry.availableAfter} available</em></span>)}</div>}
      {notice && <p className="knowledge-notice" role="status">{notice}</p>}
    </section>
  );
}
