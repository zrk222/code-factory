"""Compatibility checks for shared Factoryline protocol enumerations."""
from __future__ import annotations

from factoryline.agent_license import AUTONOMY_RANK
from factoryline.agent_proof_bridge import _AUTONOMY, _CAPABILITIES, _ISOLATION, _NODE_KINDS, _PROVIDERS, _STATUS
from factoryline.atomic_proof_adapter import _AUTONOMY as ATOMIC_AUTONOMY
from factoryline.atomic_proof_adapter import _CAPABILITIES as ATOMIC_CAPABILITIES
from factoryline.atomic_proof_adapter import _ISOLATION as ATOMIC_ISOLATION
from factoryline.atomic_proof_adapter import _STAGE_KINDS, _STAGE_STATUS
from factoryline.lifecycle_ledger import _EVENTS, _TRACE_STAGES
from factoryline.operations_control import _TIERS, _WORK_KINDS
from factoryline.oracle_firewall import AUTHORITY_ORIGINS, EFFECTS, ORIGINS
from factoryline.protocol_enums import (
    AgentCapability,
    AgentProvider,
    AgentRunStatus,
    AuthorityOrigin,
    AutonomyLevel,
    IsolationBoundary,
    LifecycleEvent,
    OperationsEvidenceTier,
    OperationsWorkKind,
    RepairConsequence,
    RepairSeverity,
    RuleEffect,
    SessionTraceStage,
    WorkflowNodeKind,
)
from factoryline.repair_loop import _CONSEQUENCES, _SEVERITIES


def test_shared_protocol_enums_preserve_existing_wire_values() -> None:
    """Keep persisted manifest strings stable while centralizing validators."""
    assert ORIGINS == AuthorityOrigin.values()
    assert EFFECTS == RuleEffect.values()
    assert AUTHORITY_ORIGINS == {"human_confirmed", "trusted_source"}
    assert AUTONOMY_RANK == {"human_controlled": 0, "supervised": 1, "autonomous": 2}
    assert _PROVIDERS == AgentProvider.values()
    assert _STATUS == AgentRunStatus.values() == _STAGE_STATUS
    assert _AUTONOMY == AutonomyLevel.values() == ATOMIC_AUTONOMY
    assert _ISOLATION == IsolationBoundary.values() == ATOMIC_ISOLATION
    assert _NODE_KINDS == WorkflowNodeKind.values() == _STAGE_KINDS
    assert _CAPABILITIES == AgentCapability.values() == ATOMIC_CAPABILITIES
    assert tuple(item.value for item in LifecycleEvent) == _EVENTS
    assert tuple(item.value for item in SessionTraceStage) == _TRACE_STAGES
    assert _TIERS == OperationsEvidenceTier.values()
    assert _WORK_KINDS == OperationsWorkKind.values()
    assert _SEVERITIES == RepairSeverity.values()
    assert _CONSEQUENCES == RepairConsequence.values()


def test_protocol_enum_members_are_json_strings() -> None:
    """Require string-compatible members for backwards-compatible JSON artifacts."""
    assert isinstance(AgentProvider.CODERABBIT, str)
    assert AgentProvider.CODERABBIT == "coderabbit"
    assert AutonomyLevel.SUPERVISED == "supervised"
    assert RepairConsequence.DATA_INTEGRITY == "data_integrity"
