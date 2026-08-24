import { useMemo, useState } from "react";
import { BookOpenCheck, Check, ChevronRight, CircleStop, Crown, Database, ShieldCheck, Sparkles, Workflow } from "lucide-react";
import { businessTemplates, type BusinessTemplate } from "../templates";
import { automationPackFor } from "../templateAutomationPacks";

export function TemplateCatalog({ onApply }: { onApply: (template: BusinessTemplate) => void }) {
  const [filter, setFilter] = useState<"All" | "B2B" | "B2C" | "C2C">("All");
  const [selectedId, setSelectedId] = useState(businessTemplates[0].id);
  const visible = useMemo(() => businessTemplates.filter((item) => filter === "All" || item.category === filter), [filter]);
  const selected = businessTemplates.find((item) => item.id === selectedId) ?? businessTemplates[0];
  const automationPack = automationPackFor(selected.id);

  return (
    <section className="template-studio" aria-labelledby="template-title">
      <div className="template-intro"><div><p className="eyebrow">Start with a proven business</p><h2 id="template-title">Pick the outcome. We’ll assemble the agent.</h2><p>No orchestration vocabulary required. Choose who you serve and the result you sell; every technical rail remains editable before anything runs.</p></div><span><Sparkles size={17} /> {businessTemplates.length} launch recipes</span></div>
      <div className="template-filters" aria-label="Filter templates">{(["All", "B2B", "B2C", "C2C"] as const).map((item) => <button key={item} className={filter === item ? "active" : ""} aria-pressed={filter === item} onClick={() => setFilter(item)}>{item}</button>)}</div>
      <div className="template-layout">
        <div className="template-grid">{visible.map((template) => <button className={`template-card ${selected.id === template.id ? "selected" : ""}`} key={template.id} onClick={() => setSelectedId(template.id)}><span className="template-card-top"><i>{template.category}</i>{template.tier === "Premium trust" && <b><Crown size={12} /> Premium</b>}</span><small>{template.badge}</small><strong>{template.title}</strong><p>{template.promise}</p><em>{template.revenue}</em></button>)}</div>
        <aside className="template-recipe" aria-live="polite">
          <header><span><BookOpenCheck size={20} /></span><div><small>Selected recipe</small><h3>{selected.title}</h3></div></header>
          <p>{selected.promise}</p>
          <dl><div><dt>Buyer</dt><dd>{selected.buyer}</dd></div><div><dt>Charge for</dt><dd>{selected.revenue}</dd></div></dl>
          <h4>Your agent’s work line</h4><ol>{selected.loop.map((step) => <li key={step}><span><Check size={12} /></span>{step}</li>)}</ol>
          <div className="recipe-rails"><span><Database size={14} /> {selected.inputs.length} Knowledge Wall inputs</span><span><ShieldCheck size={14} /> {selected.authority.replace("-", " ")}</span></div>
          {selected.sourcePolicy && <div className="recipe-source-policy"><strong>Evidence contract</strong><p>{selected.sourcePolicy}</p></div>}
          {selected.guardrails && <div className="recipe-guardrail-list"><strong>Hard boundaries</strong><ul>{selected.guardrails.map((guardrail) => <li key={guardrail}><ShieldCheck size={12} />{guardrail}</li>)}</ul></div>}
          {automationPack && <details className="recipe-automation-pack"><summary><Workflow size={14} /> Included automations</summary><div><h4>Answer these to launch</h4><ol>{automationPack.setupQuestions.map((question) => <li key={question}><span><Check size={12} /></span>{question}</li>)}</ol>{automationPack.automations.map((automation) => <article key={automation.name}><header><Workflow size={14} /><div><strong>{automation.name}</strong><small>When: {automation.when}</small></div></header><ol>{automation.steps.map((step) => <li key={step}>{step}</li>)}</ol><p><b>Human decision:</b> {automation.approval}</p><p><b>Delivers:</b> {automation.result}</p><footer><CircleStop size={12} /><span>Stops for {automation.stopIf.join("; ")}</span></footer></article>)}</div></details>}
          <button className="button primary" onClick={() => onApply(selected)}>Use this recipe <ChevronRight size={16} /></button>
          <small className="recipe-note">Applies editable defaults only. No run, charge, connector, or publish action occurs.</small>
        </aside>
      </div>
    </section>
  );
}
