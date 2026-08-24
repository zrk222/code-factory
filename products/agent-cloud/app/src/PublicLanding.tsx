import {
  ArrowRight,
  Blocks,
  BookOpenCheck,
  Bot,
  BrainCircuit,
  Check,
  ChevronRight,
  Code2,
  DatabaseZap,
  Fingerprint,
  Gauge,
  Layers3,
  LockKeyhole,
  Network,
  Route,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";

const recipes = [
  {
    tag: "Revenue",
    name: "Booked Job Concierge",
    detail: "Qualify inbound demand, book the right slot, and keep a human in charge of exceptions.",
    Icon: Workflow,
  },
  {
    tag: "Knowledge",
    name: "Operations Copilot",
    detail: "Turn approved manuals and connected sources into a governed, searchable wall of knowledge.",
    Icon: BookOpenCheck,
  },
  {
    tag: "Assurance",
    name: "PR Proof Agent",
    detail: "Inspect requirements, tests, policy, spend, and evidence before a change reaches a human gate.",
    Icon: Fingerprint,
  },
] as const;

const ingredients = [
  ["01", "Choose a job", "Start from a proven recipe or describe the outcome in plain language.", Bot],
  ["02", "Add knowledge", "Upload operating manuals or connect the systems your agent is allowed to read.", DatabaseZap],
  ["03", "Set the rails", "Choose models, budgets, approvals, memory, tools, and evidence requirements.", ShieldCheck],
  ["04", "Test, then activate", "Run the workflow in a bounded sandbox before the first live operation.", Sparkles],
] as const;

export function PublicLanding() {
  return (
    <div className="public-site">
      <header className="public-nav">
        <a className="public-brand" href="/" aria-label="Agent Oven home">
          <span className="public-brand-mark"><Layers3 size={22} /></span>
          <span><strong>AGENT OVEN</strong><small>BY CODE FACTORY</small></span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#how-it-works">How it works</a>
          <a href="#recipes">Recipes</a>
          <a href="#composer">Composer</a>
          <a href="#exchange">Agent Exchange</a>
          <a href="#control">Trust layer</a>
        </nav>
        <a className="public-nav-cta" href="/app">Open Agent Oven <ArrowRight size={16} /></a>
      </header>

      <main>
        <section className="public-hero" aria-labelledby="public-title">
          <div className="public-hero-copy">
            <p className="public-kicker"><span /> Governed agents, assembled for real work</p>
            <h1 id="public-title">Build the agent.<br />Keep the <em>control.</em></h1>
            <p className="public-lede">Agent Oven turns a business outcome, approved knowledge, model access, and operating rules into an agent your team can understand—and govern after launch.</p>
            <div className="public-hero-actions">
              <a className="public-primary-cta" href="/app">Build my first agent <ChevronRight size={19} /></a>
              <a className="public-secondary-cta" href="#how-it-works">See the assembly line</a>
            </div>
            <div className="public-trust-line" aria-label="Platform boundaries">
              <span><Check size={14} /> Bring your own model keys</span>
              <span><Check size={14} /> Human approval rails</span>
              <span><Check size={14} /> Workspace-scoped data</span>
            </div>
          </div>

          <div className="oven-console" aria-label="Agent Oven assembly preview">
            <div className="oven-console-top">
              <span /><span /><span />
              <strong>ASSEMBLY / 04</strong>
            </div>
            <div className="oven-console-body">
              <div className="oven-status"><span className="oven-status-dot" /><div><small>RECIPE</small><strong>Booked Job Concierge</strong></div><em>READY</em></div>
              <div className="oven-flow">
                {["INTAKE", "QUALIFY", "APPROVE", "BOOK"].map((label, index) => (
                  <div className="oven-flow-step" key={label}>
                    <span>{index + 1}</span><strong>{label}</strong><small>{index === 2 ? "human gate" : "automated"}</small>
                  </div>
                ))}
              </div>
              <div className="oven-controls">
                <div><Gauge size={17} /><span><small>MISSION BUDGET</small><strong>$25.00 hard stop</strong></span></div>
                <div><LockKeyhole size={17} /><span><small>AUTHORITY</small><strong>Propose + approve</strong></span></div>
              </div>
            </div>
            <div className="oven-console-foot"><span>MEMORY INFORMS</span><i /><span>POLICY AUTHORIZES</span></div>
            <div className="oven-proof-stamp"><ShieldCheck size={22} /><span><small>WORKFLOW</small><strong>GOVERNED</strong></span></div>
          </div>
        </section>

        <section className="public-proof-strip" aria-label="Core platform capabilities">
          <div><Blocks size={20} /><strong>Recipe-first</strong><span>Start with an outcome, not a framework.</span></div>
          <div><BrainCircuit size={20} /><strong>Memory with boundaries</strong><span>Useful context that cannot grant itself authority.</span></div>
          <div><Route size={20} /><strong>Multi-model routing</strong><span>Reuse workspace keys or bind one per agent.</span></div>
          <div><Fingerprint size={20} /><strong>Evidence by default</strong><span>Keep decisions, costs, gates, and provenance inspectable.</span></div>
        </section>

        <section className="public-process" id="how-it-works">
          <header className="public-section-heading">
            <p className="public-kicker">The novice-friendly assembly line</p>
            <h2>Complex underneath.<br />Clear at every decision.</h2>
            <p>Pick the outcome, connect only what the agent needs, and make authority explicit before anything runs.</p>
          </header>
          <div className="public-process-grid">
            {ingredients.map(([number, title, detail, Icon]) => (
              <article key={number}>
                <div className="public-process-icon"><Icon size={23} /></div>
                <span>{number}</span>
                <h3>{title}</h3>
                <p>{detail}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-composer" id="composer">
          <header className="public-section-heading compact">
            <p className="public-kicker">Plain English in. A safe agent plan out.</p>
            <h2>Describe the job.<br />Agent Oven handles the setup.</h2>
            <p>Start with one sentence or a ready-made example. Agent Oven asks only what is missing, chooses the best setup, and shows what the agent will do, when a person stays in control, and how success will be checked.</p>
          </header>
          <div className="public-runtime-grid">
            <article><Bot size={24} /><small>FASTEST PATH</small><h3>Agent Oven native</h3><p>Use the smallest hosted runtime for bounded jobs while the same budgets, approvals, memory, and receipts stay active.</p></article>
            <article><Network size={24} /><small>DURABLE GRAPH</small><h3>LangGraph</h3><p>Choose explicit state, checkpoints, branches, interrupts, replay, and long-running human-in-the-loop work.</p></article>
            <article><Code2 size={24} /><small>TYPESCRIPT ECOSYSTEM</small><h3>Mastra</h3><p>Choose TypeScript agents, tools, workflows, workspaces, and MCP—then add Agent Oven's independent proof boundary.</p></article>
          </div>
          <div className="public-composer-rail"><span><Sparkles size={17} /> Agent Oven-managed model route</span><b>or</b><span><LockKeyhole size={17} /> BYOK secret reference</span><i /><strong>Same governed blueprint</strong><a href="/app?view=builder">Compose an agent <ArrowRight size={15} /></a></div>
        </section>

        <section className="public-recipes" id="recipes">
          <div className="public-section-heading compact">
            <p className="public-kicker">Ready-to-assemble recipes</p>
            <h2>Begin with a job worth finishing.</h2>
            <p>Templates package the workflow, knowledge contract, approval points, evidence, and estimated platform credits—not just a prompt.</p>
          </div>
          <div className="public-recipe-grid">
            {recipes.map(({ tag, name, detail, Icon }) => (
              <article key={name}>
                <header><span><Icon size={21} /></span><small>{tag}</small></header>
                <h3>{name}</h3>
                <p>{detail}</p>
                <a href="/app">Use this recipe <ChevronRight size={15} /></a>
              </article>
            ))}
          </div>
        </section>

        <section className="public-control" id="control">
          <div>
            <p className="public-kicker">The control plane stays in the loop</p>
            <h2>Your agent does not graduate beyond governance.</h2>
            <p>Every activated agent continues to use Agent Oven for workspace access, credit admission, policy decisions, human approvals, source currentness, and evidence. The platform is the operating layer—not a one-time export wizard.</p>
            <ul>
              <li><Check size={16} /> One hosted control plane with tenant-scoped workspaces</li>
              <li><Check size={16} /> BYOK credentials referenced through approved secret stores</li>
              <li><Check size={16} /> Hard mission budgets and explicit kill switches</li>
              <li><Check size={16} /> Governed memory separated from execution authority</li>
            </ul>
          </div>
          <div className="public-boundary-card">
            <small>EXECUTION BOUNDARY</small>
            <div><span>01</span><strong>Knowledge</strong><em>informs</em></div>
            <div><span>02</span><strong>Agent</strong><em>proposes</em></div>
            <div><span>03</span><strong>Policy</strong><em>authorizes</em></div>
            <div><span>04</span><strong>Receipt</strong><em>records</em></div>
            <p><ShieldCheck size={16} /> High-impact actions stop for the accountable human.</p>
          </div>
        </section>

        <section className="public-exchange" id="exchange">
          <div className="public-section-heading compact">
            <p className="public-kicker">A result market for humans and agents</p>
            <h2>Hire the outcome.<br />Release credits after proof.</h2>
            <p>Choose a preconfigured worker with a fixed result price and exact evidence checklist. The same authenticated contract is callable from the Agent Oven UI or another agent—without a machine-only back door.</p>
          </div>
          <div className="public-exchange-grid">
            <article><Bot size={23} /><span>01</span><h3>Discover</h3><p>Six preconfigured agents publish bounded outcomes, authority, delivery windows, and proof checks.</p></article>
            <article><Fingerprint size={23} /><span>02</span><h3>Contract</h3><p>Intent, price, budget, delegation depth, evidence obligations, and expiry freeze before work starts.</p></article>
            <article><ShieldCheck size={23} /><span>03</span><h3>Verify</h3><p>A different authenticated identity checks an exact digest-bound proof set. The worker cannot grade itself.</p></article>
            <article><Gauge size={23} /><span>04</span><h3>Release</h3><p>Platform credits settle once after verification. External money rails stay off until provider-verified.</p></article>
          </div>
          <div className="public-exchange-cta"><div><strong>Agent-to-agent ready</strong><p>OIDC auth · idempotent hire · one-hop delegation · machine-readable contract</p></div><a className="public-primary-cta" href="/app?view=exchange">Open Outcome Exchange <ArrowRight size={17} /></a></div>
        </section>

        <section className="public-final-cta">
          <p className="public-kicker">Turn the workflow you repeat into an agent you control</p>
          <h2>What should your first agent finish?</h2>
          <a className="public-primary-cta" href="/app">Start assembling <ArrowRight size={18} /></a>
          <p>No provider key is requested on the public page. Real-money settlement is not active.</p>
        </section>
      </main>

      <footer className="public-footer">
        <a className="public-brand" href="/"><span className="public-brand-mark"><Layers3 size={20} /></span><span><strong>AGENT OVEN</strong><small>BY CODE FACTORY</small></span></a>
        <p>Governed agent assembly for useful, accountable work.</p>
        <div><a href="/legal/privacy.html">Privacy</a><a href="/legal/terms.html">Terms</a><a href="https://github.com/zrk222/code-factory">GitHub</a></div>
      </footer>
    </div>
  );
}
