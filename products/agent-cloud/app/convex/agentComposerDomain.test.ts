import { describe, expect, test } from "vitest";
import { compileAgentIntent, runtimeCompatibility } from "./agentComposerDomain";

const detailed = "Monitor GitHub pull requests and verify requirements and tests within 10 minutes. Read the repository only, never merge code, stop on missing evidence, retry one transient API timeout, and escalate every failed or unknown check to a human reviewer.";

describe("portable agent intent compiler", () => {
  test("selects LangGraph for durable state and seals a ready graph", () => {
    const result = compileAgentIntent({ description: `${detailed} Use checkpoints and resume after human approval.`, runtimePreference: "auto", inferenceAccess: "agent-oven-api" });
    expect(result).toMatchObject({ marker: "AGENT_INTENT_COMPILED", selectedRuntime: "langgraph", readiness: "ready-for-draft", authorityPolicy: "approval-required" });
    expect(result.steps.some((step) => step.humanGate)).toBe(true);
    expect(result.evidenceChecks).toHaveLength(4);
  });

  test("selects Mastra for TypeScript MCP tooling and preserves BYOK", () => {
    const result = compileAgentIntent({ description: `${detailed} Implement the tools in TypeScript and expose the bounded agent through MCP.`, runtimePreference: "auto", inferenceAccess: "byok" });
    expect(result.selectedRuntime).toBe("mastra");
    expect(result.inferenceAccess).toBe("byok");
    expect(runtimeCompatibility.map((item) => item.runtime)).toEqual(["agent-oven-native", "langgraph", "mastra"]);
  });

  test("fails closed on vague intent instead of inventing production controls", () => {
    const result = compileAgentIntent({ description: "Build a helpful assistant that handles our daily business operations and makes the team more efficient.", runtimePreference: "agent-oven-native", inferenceAccess: "agent-oven-api" });
    expect(result.readiness).toBe("needs-clarification");
    expect(result.clarificationQuestions.length).toBeGreaterThanOrEqual(3);
    expect(() => compileAgentIntent({ description: "Build an agent", runtimePreference: "auto", inferenceAccess: "byok" })).toThrow("E_AGENT_INTENT_TOO_SHORT");
  });

  test("recompiles identical intent to the same digest", () => {
    const input = { description: `${detailed} Use checkpoints and resume after human approval.`, runtimePreference: "auto" as const, inferenceAccess: "agent-oven-api" as const };
    expect(compileAgentIntent(input).compilerDigest).toBe(compileAgentIntent(input).compilerDigest);
  });
});
