import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { AlertTriangle, BarChart3, FilePenLine, MessageCircleQuestion, PlayCircle, Route, WalletCards } from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";

export function RuntimeJobIntelligence({ job }: { job: Doc<"executionJobs"> }) {
  const state = useQuery(api.agentIntelligence.runIntelligence, { jobId: job._id });
  const answer = useMutation(api.agentIntelligence.answerClarification);
  const resume = useMutation(api.agentIntelligence.resumeJob);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState<string | null>(null);
  if (!state) return null;
  const pending = state.clarifications.filter((item) => item.required && item.answer === undefined);
  const latestSnapshot = [...state.snapshots].reverse().find((item) => item.status === "suspended");
  const resumeDigest = latestSnapshot && "resumeDigest" in latestSnapshot ? latestSnapshot.resumeDigest : undefined;
  const usage = state.usage.reduce((sum, item) => ({ tokens: sum.tokens + item.inputTokens + item.outputTokens + item.reasoningTokens, cost: sum.cost + item.providerCostMicros, steps: sum.steps + item.toolSteps }), { tokens: 0, cost: 0, steps: 0 });

  return <details className="runtime-intelligence"><summary><Route size={13} /> Inspect progress, cost and proof</summary>
    {pending.map((item) => <div className="runtime-question" key={item._id}><MessageCircleQuestion size={16} /><label><strong>Clarification required</strong><span>{item.question}</span><input aria-label={`Answer ${item.questionId}`} value={answers[item._id] ?? ""} onChange={(event) => setAnswers((current) => ({ ...current, [item._id]: event.target.value }))} /></label><button className="button secondary" disabled={!answers[item._id]?.trim()} onClick={() => void answer({ clarificationId: item._id, answer: answers[item._id] }).then(() => setNotice("Answer saved. The worker may proceed when every required question is answered."))}>Answer</button></div>)}
    <div className="runtime-intelligence-metrics"><span><WalletCards size={14} /><b>${(usage.cost / 1_000_000).toFixed(4)}</b><small>provider cost</small></span><span><BarChart3 size={14} /><b>{usage.tokens.toLocaleString()}</b><small>tokens · {usage.steps} steps</small></span><span><Route size={14} /><b>{state.progress.length}</b><small>progress events</small></span><span><FilePenLine size={14} /><b>{state.artifacts.length}</b><small>artifacts</small></span></div>
    {state.progress.length > 0 && <ol className="runtime-timeline">{state.progress.map((event) => <li key={event._id}><b>{event.phase}</b><span>{event.summary}</span><small>{event.evidenceClass}</small></li>)}</ol>}
    {state.findings.map((finding) => <p className={finding.contradiction ? "runtime-contradiction" : "runtime-finding"} key={finding._id}>{finding.contradiction && <AlertTriangle size={13} />}<strong>{finding.title}</strong> {finding.summary}</p>)}
    {state.scores.length > 0 && <div className="runtime-score-row">{state.scores.map((score) => <span key={score._id}><b>{score.score}</b>{score.component}<small>{score.method}</small></span>)}</div>}
    {job.status === "suspended" && resumeDigest && <button className="button primary" disabled={pending.length > 0} onClick={() => void resume({ jobId: job._id, resumeDigest }).then(() => setNotice("Snapshot resumed from the exact saved path."))}><PlayCircle size={14} /> Resume saved run</button>}
    {notice && <p className="knowledge-notice" role="status">{notice}</p>}
  </details>;
}
