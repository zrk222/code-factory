import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { AdversarialReviewPanel } from "./RunPanel";

describe("AdversarialReviewPanel", () => {
  test("shows the verdict, exact checks, and Proof Delta boundary", () => {
    render(<AdversarialReviewPanel review={{
      verdict: "human-required",
      policyVersion: "adversarial-approval.v1",
      reasonCodes: ["HUMAN_ACCOUNTABILITY_REQUIRED"],
      checks: [{ id: "action-digest-bound", passed: true, evidence: "abcd" }],
      proofDelta: { reviewScope: "focused", reusedEvidence: ["a"], newEvidence: ["b"], missingEvidence: [] },
    } as never} />);
    expect(screen.getByText("human required")).toBeInTheDocument();
    expect(screen.getByText("action-digest-bound")).toBeInTheDocument();
    expect(screen.getByText(/Proof Delta · focused review/i)).toBeInTheDocument();
    expect(screen.getByText(/never carries forward approval authority/i)).toBeInTheDocument();
  });
});
