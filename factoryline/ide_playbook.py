"""Vendor-neutral, low-vocabulary onboarding map for IDEs and coding agents."""
from __future__ import annotations
from typing import Any

SUPPORTED_JOURNEYS = ("solo", "team", "enterprise")


class AdoptionGuideError(ValueError):
    """A stable refusal for an unsupported adoption journey."""

    code = "E_GUIDE_JOURNEY"


ADOPTION_JOURNEYS = (
    {
        "id": "solo",
        "label": "Individual developer",
        "question": "Can this test actually fail?",
        "problem": "AI-generated tests can stay green even when the behavior they claim to protect is missing.",
        "first_command": "factory first-proof --root .",
        "primary": True,
        "maturity": "locally_verified_core",
        "verification": ["tests/test_adoption.py", "tests/test_e2e_proof.py", "tests/test_adoption_guide.py"],
        "expected_local_evidence": "A local hollow-test result, receipt, and privacy-safe Proof Card from a disposable demonstration.",
        "next_safe_action": "Run the same positive-and-negative proof pattern against one human-approved behavior in your repository.",
        "authority_boundary": "The demonstration does not assess or change your project and uploads nothing.",
    },
    {
        "id": "team",
        "label": "Engineering team",
        "question": "Did the agent build what we asked for?",
        "problem": "An agent summary does not prove the exact file delta matched the original intent or that its tests could detect failure.",
        "first_command": "factory oracle status --root .",
        "primary": False,
        "maturity": "controlled_pilot",
        "verification": ["tests/test_oracle_firewall.py", "tests/test_evidence_supply_line.py", "tests/test_control_plane.py"],
        "expected_local_evidence": "A source-bound intent chain, observed file delta, independent validation, and explicit review state.",
        "next_safe_action": "Seal the original intent before the next coding run, then observe that admitted run with factory wrap.",
        "authority_boundary": "Agents cannot approve intent, weaken a blocking gate, change scope, or grant release authority.",
    },
    {
        "id": "enterprise",
        "label": "Enterprise evaluator",
        "question": "Can we govern agent work without trusting the agent's story?",
        "problem": "Teams need reviewable evidence, policy boundaries, and expiring authority without turning governance into hidden automation.",
        "first_command": "factory graph ops --root . --json",
        "primary": False,
        "maturity": "reference_pilot",
        "verification": ["tests/test_enterprise_enforcement.py", "tests/test_graph_ops.py"],
        "expected_local_evidence": "A read-only source-to-decision graph with blockers, unknowns, receipts, and retained human authority.",
        "next_safe_action": "Run a controlled pilot on one repository and one reviewed workflow before considering broader enforcement.",
        "authority_boundary": "The guide and Graph Ops do not execute, approve, publish, deploy, sign, message, or access credentials.",
    },
)


def adoption_guide(journey: str | None = None) -> dict[str, Any]:
    """Return the three read-only adoption journeys or one selected journey."""
    if journey is not None and journey not in SUPPORTED_JOURNEYS:
        supported = ", ".join(SUPPORTED_JOURNEYS)
        raise AdoptionGuideError(f"unsupported journey {journey!r}; choose one of: {supported}")
    selected = [dict(item) for item in ADOPTION_JOURNEYS if journey is None or item["id"] == journey]
    return {
        "schema": "factory.adoption-guide.v1",
        "marker": "TEAM_GUIDE_RENDERED" if journey == "team" else "ADOPTION_GUIDE_RENDERED",
        "action_summary": "Choose one question, see the smallest safe workflow, and keep advanced controls hidden until needed.",
        "recommended": "solo",
        "selected_journey": journey,
        "journeys": selected,
        "triggered_capabilities": [
            {
                "id": "mobile_delivery",
                "label": "AppForge",
                "when": "The work explicitly includes mobile release preparation.",
                "maturity": "candidate_bound_preflight",
                "boundary": "Surfaces candidate-bound evidence and avoidable gaps; it does not guarantee store approval.",
            }
        ],
        "actions_executed": False,
        "action_count": 0,
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "credential_access": False,
        },
        "claim_boundary": "Read-only guidance. It does not run tests or agents, control an IDE, or change local or provider state.",
        "battle_testing": "No independent production-scale or adoption claim is made by this guide; inspect the linked tests and run a bounded pilot.",
    }

PLAYBOOK = (
 {"id":"deep_audit","when":"Independent analyzer reports exist for nested defects, leaks or risky code paths.","use":"Deep audit evidence review","outcome":"signed-rule evaluation, canary checks and prioritized repair guidance; not release approval","next":"factory.deep_audit_status"},
 {"id":"start","when":"Before changing code or when intent is unclear.","use":"Intake Grill + SpecLine","outcome":"reviewable intent, forbidden outcomes, and approved gates","next":"factory.intake_status"},
 {"id":"prove","when":"After an agent changes implementation or tests.","use":"First Proof + Oracle Firewall","outcome":"tests challenged and oracle weakening surfaced","next":"factory.verifier_status"},
 {"id":"challenge","when":"A change is risky, autonomous, or release-bound.","use":"Gauntlet + independent challenge lane","outcome":"counterfactual cases without changing production code","next":"factory.gauntlet_status"},
 {"id":"runtime_assurance","when":"A service, workflow, API, database, tenant boundary, or performance-sensitive change is release-bound.","use":"Six-lane Runtime Assurance","outcome":"stateful, tenant, recovery, compatibility, migration, performance, and memory-retention evidence with exact repair actions","next":"factory.runtime_audit_status"},
 {"id":"trace","when":"A reviewer asks why a change is allowed.","use":"Proof Continuity + Graph Ops","outcome":"source to obligation to gate to evidence","next":"factory.proof_continuity_status"},
 {"id":"handoff","when":"An IDE agent hands work to another agent or human.","use":"Agent Proof Bridge + ForgeLine","outcome":"bounded handoff with scope, evidence, and next action","next":"factory.agent_handoff_brief"},
 {"id":"deliver_mobile","when":"The work explicitly includes iOS/App Store delivery.","use":"AppForge capability pack","outcome":"candidate-bound delivery gates","next":"factory.appforge_submission_integrity_status"},
)
def ide_playbook() -> dict[str, Any]:
 """Return the read-only, progressive-disclosure operating map for IDE and A2A clients."""
 return {"schema":"factory.ide-agent-playbook.v1","marker":"FACTORY_IDE_AGENT_PLAYBOOK_READ_ONLY","action_summary":"Give IDEs and coding agents a short plain-language map of when to use each Code Factory capability before action.","default_path":["start","prove","challenge","runtime_assurance","trace","handoff"],"capability_packs":list(PLAYBOOK),"ui_contract":{"panels":["Mission: current intent, scope, owner, and autonomy mode","Work: active module, inputs read, and expected artifact","Proof: gates, challenge result, and source-to-evidence trace","Review: blockers, unknowns, and explicit human decisions","History: sealed receipts and reopened incidents"],"action_card_required":["what_will_happen","why_now","inputs","risk_or_unknown","authority","evidence_after","next_safe_action"],"progressive_disclosure":"Show the default path first; reveal advanced modules only when their trigger is true. Never hide a blocking gate or consequential action."},"proof_moment":{"trigger":"A user-visible verified result exists: a hollow test caught, an oracle weakening blocked, a high-risk change challenged, or a human confirms the receipt was useful.","show":["plain-language outcome","linked local receipt","what remains unknown","shareable redacted summary"],"invitation":"If this helped, would you be willing to leave an honest review describing what happened?","limits":["Never ask for a rating or positive review.","Never interrupt a blocked, failed, or first-run experience.","Never offer a reward, discount, or feature in exchange for feedback.","Show at most once per user after a confirmed useful outcome; allow dismissal."],"claim_boundary":"A product-level prompt policy only; it does not post, collect, fabricate, or influence reviews."},"agent_human_briefing":{"before":"I will run [module] because [trigger]. I will read [inputs], write [local artifact], and will not [locked authority].","after":"Result: [pass|blocked|unknown]. Evidence: [receipt]. Impact: [plain language]. Next: [one safe action].","on_block":"Blocked by [exact condition]. It matters because [consequence]. To continue, [smallest safe repair]. Human decision needed: [yes/no]."},"external_agent_ingress":{"protocols":["A2A","MCP"],"required_envelope_fields":["agent_identity","issuer","intent_digest","scope","allowed_capabilities","issued_at","expires_at","nonce"],"admission_rules":["Verify the signed, time-limited envelope before exposing a capability.","Reject an unknown, expired, replayed, or scope-expanded request.","Treat agent-proposed gates as advisory until a human-confirmed or trusted-source rule approves them.","Return the same playbook and next-safe-action receipt to every admitted agent."],"default_mode":"supervised","elevation":"human-approved, task-scoped, and expiring"},"rules":["Use plain problem language first; module names are optional labels.","Never let an agent select or weaken its own blocking gate.","Runtime assurance requires all six signed lanes; missing native tooling is incomplete, never pass.","AppForge activates only for explicit mobile delivery scope.","Each step returns evidence and one next safe action; none grants execution or release authority."],"authority":{"execution":False,"agent_control":False,"release":False,"credential_access":False},"claim_boundary":"Read-only guide, not automatic routing, A2A admission, agent execution, IDE control, or approval."}
