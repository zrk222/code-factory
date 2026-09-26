import { useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
  Check,
  CircleDollarSign,
  FlaskConical,
  GitBranch,
  GripVertical,
  Plus,
  Save,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import type { Doc } from "../../convex/_generated/dataModel";
import { api } from "../../convex/_generated/api";
import type { BusinessTemplate } from "../templates";
import { knowledgeConnectorCatalog } from "../knowledgeConnectorCatalog";
import { stepsForTemplate, type WorkflowStep } from "../templateWorkflow";

type Props = {
  agentSpec: Doc<"agentSpecs">;
  template: BusinessTemplate;
  blueprint: Doc<"agentBlueprints"> | null;
  versions: Doc<"agentBlueprintVersions">[];
};
type WorkflowMode = "guided" | "architect";
type TriggerKind = "manual" | "schedule" | "webhook" | "event";
type MemoryPolicy = "none" | "run-only" | "governed";
type ModelPolicy = "economy" | "balanced" | "highest-quality" | "auto";
type EvidenceLevel = "essential" | "full";
type StateSetter<T> = Dispatch<SetStateAction<T>>;
type Blueprint = Doc<"agentBlueprints"> | null;
type Simulation = FunctionReturnType<typeof api.blueprints.simulate> | undefined;

function estimateCredits(
  steps: readonly WorkflowStep[],
  trigger: TriggerKind,
  memory: MemoryPolicy,
  evidence: EvidenceLevel,
) {
  return (
    20 +
    steps.length * 4 +
    (trigger === "manual" ? 0 : 8) +
    (memory === "governed" ? 15 : memory === "run-only" ? 5 : 0) +
    (evidence === "full" ? 10 : 0)
  );
}

function updateWorkflowStep(
  setSteps: StateSetter<WorkflowStep[]>,
  stepId: string,
  changes: Partial<WorkflowStep>,
) {
  setSteps((current) =>
    current.map((step) => (step.id === stepId ? { ...step, ...changes } : step)),
  );
}

function addWorkflowStep(setSteps: StateSetter<WorkflowStep[]>) {
  setSteps((current) => [
    ...current,
    {
      id: `custom-${Date.now()}`,
      label: "New bounded step",
      kind: "reason",
      humanGate: false,
      flow: "sequential",
      dependsOn: current.length ? [current.at(-1)!.id] : [],
    },
  ]);
}

function WorkflowHeader({
  mode,
  setMode,
}: {
  mode: WorkflowMode;
  setMode: StateSetter<WorkflowMode>;
}) {
  return (
    <header className="workflow-header">
      <div>
        <p className="kicker">Agent Blueprint / versioned recipe</p>
        <h2 id="workflow-title">Assemble the work line.</h2>
        <p>
          Guided mode keeps the safe preset. Architect mode unlocks step types,
          connectors, gates, and policies without hiding their impact.
        </p>
      </div>
      <div className="mode-switch">
        <button
          className={mode === "guided" ? "active" : ""}
          onClick={() => setMode("guided")}
        >
          Guided
        </button>
        <button
          className={mode === "architect" ? "active" : ""}
          onClick={() => setMode("architect")}
        >
          Architect
        </button>
      </div>
    </header>
  );
}

function WorkflowIngredients({
  trigger,
  setTrigger,
  memory,
  setMemory,
  model,
  setModel,
  evidence,
  setEvidence,
}: {
  trigger: TriggerKind;
  setTrigger: StateSetter<TriggerKind>;
  memory: MemoryPolicy;
  setMemory: StateSetter<MemoryPolicy>;
  model: ModelPolicy;
  setModel: StateSetter<ModelPolicy>;
  evidence: EvidenceLevel;
  setEvidence: StateSetter<EvidenceLevel>;
}) {
  return (
    <div className="workflow-ingredients">
      <label>
        <span>1</span>Trigger
        <select
          value={trigger}
          onChange={(event) => setTrigger(event.target.value as TriggerKind)}
        >
          <option value="manual">Manual</option>
          <option value="schedule">Schedule</option>
          <option value="webhook">Webhook</option>
          <option value="event">Business event</option>
        </select>
      </label>
      <label>
        <span>2</span>Memory
        <select
          value={memory}
          onChange={(event) => setMemory(event.target.value as MemoryPolicy)}
        >
          <option value="none">None</option>
          <option value="run-only">Run only</option>
          <option value="governed">Governed history</option>
        </select>
      </label>
      <label>
        <span>3</span>Model route
        <select
          value={model}
          onChange={(event) => setModel(event.target.value as ModelPolicy)}
        >
          <option value="economy">Economy</option>
          <option value="balanced">Balanced</option>
          <option value="highest-quality">Highest quality</option>
          <option value="auto">Smart router</option>
        </select>
      </label>
      <label>
        <span>4</span>Proof
        <select
          value={evidence}
          onChange={(event) => setEvidence(event.target.value as EvidenceLevel)}
        >
          <option value="essential">Essential</option>
          <option value="full">Full evidence</option>
        </select>
      </label>
    </div>
  );
}

function ArchitectStepFields({
  step,
  index,
  setSteps,
}: {
  step: WorkflowStep;
  index: number;
  setSteps: StateSetter<WorkflowStep[]>;
}) {
  return (
    <>
      <select
        aria-label={`Step ${index + 1} flow`}
        value={step.flow ?? "sequential"}
        onChange={(event) => {
          const flow = event.target.value as WorkflowStep["flow"];
          updateWorkflowStep(setSteps, step.id, {
            flow,
            maxIterations:
              flow === "loop" ? step.maxIterations ?? 3 : undefined,
          });
        }}
      >
        <option value="sequential">Sequential</option>
        <option value="parallel">Parallel</option>
        <option value="branch">Conditional branch</option>
        <option value="loop">Bounded loop</option>
      </select>
      <select
        aria-label={`Step ${index + 1} connector`}
        value={step.connectorProvider ?? ""}
        onChange={(event) =>
          updateWorkflowStep(setSteps, step.id, {
            connectorProvider: event.target.value || undefined,
          })
        }
      >
        <option value="">No connector</option>
        {knowledgeConnectorCatalog.map((item) => (
          <option key={item.provider} value={item.provider}>
            {item.label}
          </option>
        ))}
      </select>
    </>
  );
}

function StepGateControl({
  step,
  mode,
  setSteps,
}: {
  step: WorkflowStep;
  mode: WorkflowMode;
  setSteps: StateSetter<WorkflowStep[]>;
}) {
  return (
    <label className="gate-check">
      <input
        type="checkbox"
        checked={step.humanGate}
        disabled={mode === "guided"}
        onChange={(event) =>
          updateWorkflowStep(setSteps, step.id, {
            humanGate: event.target.checked,
          })
        }
      />
      <ShieldCheck size={14} /> Gate
    </label>
  );
}

function WorkflowStepRow({
  step,
  index,
  stepCount,
  mode,
  setSteps,
}: {
  step: WorkflowStep;
  index: number;
  stepCount: number;
  mode: WorkflowMode;
  setSteps: StateSetter<WorkflowStep[]>;
}) {
  return (
    <article>
      <GripVertical size={15} />
      <b>{index + 1}</b>
      <input
        aria-label={`Step ${index + 1} label`}
        value={step.label}
        readOnly={mode === "guided"}
        onChange={(event) =>
          updateWorkflowStep(setSteps, step.id, { label: event.target.value })
        }
      />
      <select
        aria-label={`Step ${index + 1} type`}
        value={step.kind}
        disabled={mode === "guided"}
        onChange={(event) =>
          updateWorkflowStep(setSteps, step.id, {
            kind: event.target.value as WorkflowStep["kind"],
          })
        }
      >
        <option value="retrieve">Retrieve</option>
        <option value="reason">Reason</option>
        <option value="act">Act</option>
        <option value="validate">Validate</option>
        <option value="notify">Notify</option>
      </select>
      {mode === "architect" && (
        <ArchitectStepFields step={step} index={index} setSteps={setSteps} />
      )}
      <StepGateControl
        step={step}
        mode={mode}
        setSteps={setSteps}
      />
      {mode === "architect" && stepCount > 1 && (
        <button
          aria-label={`Remove step ${index + 1}`}
          onClick={() => setSteps((current) => current.filter((item) => item.id !== step.id))}
        >
          <Trash2 size={14} />
        </button>
      )}
    </article>
  );
}

function WorkflowStepList({
  steps,
  mode,
  setSteps,
}: {
  steps: WorkflowStep[];
  mode: WorkflowMode;
  setSteps: StateSetter<WorkflowStep[]>;
}) {
  return (
    <div className="workflow-line">
      {steps.map((step, index) => (
        <WorkflowStepRow
          key={step.id}
          step={step}
          index={index}
          stepCount={steps.length}
          mode={mode}
          setSteps={setSteps}
        />
      ))}
    </div>
  );
}

function AddWorkflowStep({
  mode,
  setSteps,
}: {
  mode: WorkflowMode;
  setSteps: StateSetter<WorkflowStep[]>;
}) {
  if (mode !== "architect") return null;
  return (
    <button className="text-button" onClick={() => addWorkflowStep(setSteps)}>
      <Plus size={14} /> Add step
    </button>
  );
}

function ActivateBlueprintButton({
  blueprint,
  simulation,
  busy,
  onActivate,
}: {
  blueprint: Blueprint;
  simulation: Simulation;
  busy: boolean;
  onActivate: () => void;
}) {
  if (!blueprint) return null;
  const disabled =
    busy || simulation === undefined || simulation === null || !simulation.ready;
  return (
    <button
      className="button primary"
      disabled={disabled}
      onClick={() => void onActivate()}
    >
      <Check size={15} /> Buy &amp; activate v{blueprint.version}
    </button>
  );
}

function WorkflowFooter({
  blueprint,
  simulation,
  credits,
  busy,
  onSave,
  onActivate,
}: {
  blueprint: Blueprint;
  simulation: Simulation;
  credits: number;
  busy: boolean;
  onSave: () => void;
  onActivate: () => void;
}) {
  return (
    <div className="workflow-footer">
      <div className="credit-preview">
        <CircleDollarSign size={19} />
        <span>
          <small>
            {blueprint ? "Server-owned activation price" : "Draft price estimate"}
          </small>
          <strong>{blueprint?.estimatedPlatformCredits ?? credits} credits</strong>
        </span>
      </div>
      <div className="workflow-actions">
        <button
          className="button secondary"
          disabled={busy}
          onClick={() => void onSave()}
        >
          <Save size={15} /> Save draft
        </button>
        <ActivateBlueprintButton
          blueprint={blueprint}
          simulation={simulation}
          busy={busy}
          onActivate={onActivate}
        />
      </div>
    </div>
  );
}

function simulationMessage(blueprint: Blueprint, simulation: Simulation) {
  if (!blueprint) return "Save the draft to simulate its exact server-side plan.";
  if (simulation === undefined) return `Simulating version ${blueprint.version}…`;
  if (simulation === null) return "No saved blueprint found.";
  return `${simulation.stages.length} stages · ${simulation.estimatedPlatformCredits} credits · inference hard stop $${(simulation.maxInferenceCostCents / 100).toFixed(2)} · ${simulation.approvalRequired ? "human approval required" : "no global approval"}`;
}

function SimulationStatus({
  blueprint,
  simulation,
}: {
  blueprint: Blueprint;
  simulation: Simulation;
}) {
  if (!blueprint || !simulation) return null;
  return (
    <span className={simulation.ready ? "ready" : "blocked"}>
      {simulation.ready ? "READY" : `${simulation.blockers.length} BLOCKER`}
    </span>
  );
}

function SimulationCard({
  blueprint,
  simulation,
}: {
  blueprint: Blueprint;
  simulation: Simulation;
}) {
  return (
    <div className="simulation-card">
      <FlaskConical size={18} />
      <div>
        <strong>Preflight simulation</strong>
        <p>{simulationMessage(blueprint, simulation)}</p>
      </div>
      <SimulationStatus blueprint={blueprint} simulation={simulation} />
    </div>
  );
}

function SimulationBlockers({
  blueprint,
  simulation,
}: {
  blueprint: Blueprint;
  simulation: Simulation;
}) {
  if (!blueprint || !simulation || simulation.blockers.length === 0) return null;
  return (
    <ul className="simulation-blockers">
      {simulation.blockers.map((blocker) => (
        <li key={blocker}>{blocker}</li>
      ))}
    </ul>
  );
}

function BlueprintHistory({ versions }: { versions: Doc<"agentBlueprintVersions">[] }) {
  if (versions.length === 0) return null;
  return (
    <p className="blueprint-history">
      <GitBranch size={13} /> {versions.length} immutable version
      {versions.length === 1 ? "" : "s"} · latest digest {versions.at(-1)?.digest}
    </p>
  );
}

export function WorkflowAssembler({
  agentSpec,
  template,
  blueprint,
  versions,
}: Props) {
  const saveBlueprint = useMutation(api.blueprints.save);
  const activateBlueprint = useMutation(api.blueprints.activate);
  const reserveCredits = useMutation(api.credits.reserveBlueprint);
  const settleCredits = useMutation(api.credits.settle);
  const simulation = useQuery(
    api.blueprints.simulate,
    blueprint ? { agentSpecId: agentSpec._id } : "skip",
  );
  const [mode, setMode] = useState<WorkflowMode>("guided");
  const [trigger, setTrigger] = useState<TriggerKind>("manual");
  const [steps, setSteps] = useState<WorkflowStep[]>(() => stepsForTemplate(template));
  const [memory, setMemory] = useState<MemoryPolicy>(
    template.memory === "architecture-history" ? "governed" : "run-only",
  );
  const [model, setModel] = useState<ModelPolicy>(
    template.tier === "Premium trust" ? "highest-quality" : "balanced",
  );
  const [evidence, setEvidence] = useState<EvidenceLevel>(
    template.tier === "Premium trust" ? "full" : "essential",
  );
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const credits = useMemo(
    () => estimateCredits(steps, trigger, memory, evidence),
    [steps, trigger, memory, evidence],
  );

  useEffect(() => {
    setSteps(stepsForTemplate(template));
    setMemory(template.memory === "architecture-history" ? "governed" : "run-only");
    setModel(template.tier === "Premium trust" ? "highest-quality" : "balanced");
    setEvidence(template.tier === "Premium trust" ? "full" : "essential");
  }, [template]);

  async function save() {
    setBusy(true);
    setNotice(null);
    try {
      const result = await saveBlueprint({
        agentSpecId: agentSpec._id,
        templateId: template.id,
        name: template.title,
        mode,
        triggerKind: trigger,
        triggerLabel:
          trigger === "manual" ? "User starts a run" : `${trigger} trigger`,
        steps,
        memoryPolicy: memory,
        modelPolicy: model,
        authorityPolicy: template.authority,
        evidenceLevel: evidence,
        hardBudgetCents: Math.round(template.hardBudgetDollars * 100),
      });
      setNotice(
        `Blueprint v${result.version} saved as a draft. Estimated build: ${result.estimatedPlatformCredits} credits.`,
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Blueprint save failed.");
    } finally {
      setBusy(false);
    }
  }

  async function purchaseAndActivate() {
    if (!blueprint) return;
    setBusy(true);
    setNotice(null);
    try {
      const reservation = await reserveCredits({
        blueprintId: blueprint._id,
        idempotencyKey: `blueprint:${blueprint._id}:v${blueprint.version}`,
      });
      await settleCredits({
        reservationId: reservation.reservationId,
        actualCredits: reservation.quotedCredits,
      });
      await activateBlueprint({
        blueprintId: blueprint._id,
        creditReservationId: reservation.reservationId,
      });
      setNotice(
        `Blueprint v${blueprint.version} activated for ${reservation.quotedCredits} credits with receipt evidence.`,
      );
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "Purchase and activation failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workflow-assembler surface" aria-labelledby="workflow-title">
      <WorkflowHeader mode={mode} setMode={setMode} />
      <WorkflowIngredients
        trigger={trigger}
        setTrigger={setTrigger}
        memory={memory}
        setMemory={setMemory}
        model={model}
        setModel={setModel}
        evidence={evidence}
        setEvidence={setEvidence}
      />
      <WorkflowStepList steps={steps} mode={mode} setSteps={setSteps} />
      <AddWorkflowStep mode={mode} setSteps={setSteps} />
      <WorkflowFooter
        blueprint={blueprint}
        simulation={simulation}
        credits={credits}
        busy={busy}
        onSave={save}
        onActivate={purchaseAndActivate}
      />
      <SimulationCard blueprint={blueprint} simulation={simulation} />
      <SimulationBlockers blueprint={blueprint} simulation={simulation} />
      <BlueprintHistory versions={versions} />
      {notice && <p className="knowledge-notice" role="status">{notice}</p>}
    </section>
  );
}
