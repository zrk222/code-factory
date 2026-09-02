"""Shared, wire-compatible enumerations for Factoryline control protocols.

Every member inherits :class:`str`, so manifests and receipts continue to use
their existing JSON string values.  This module centralizes only values shared
between control-plane boundaries; feature-local vocabulary remains local to
avoid turning ordinary configuration into a global compatibility contract.
"""
from __future__ import annotations

from enum import Enum


class ProtocolEnum(str, Enum):
    """String enum whose values are safe to persist in JSON protocol artifacts."""

    @classmethod
    def values(cls) -> frozenset[str]:
        """Return the stable wire values accepted by this protocol type."""
        return frozenset(member.value for member in cls)


class AuthorityOrigin(ProtocolEnum):
    """Provenance classification for a contract rule or source."""

    HUMAN_CONFIRMED = "human_confirmed"
    TRUSTED_SOURCE = "trusted_source"
    OBSERVED_PRODUCTION = "observed_production"
    AGENT_PROPOSED = "agent_proposed"


class RuleEffect(ProtocolEnum):
    """The allowable decision effect of an Oracle rule."""

    ADVISORY = "advisory"
    BLOCKING = "blocking"
    RELEASE = "release"


class AutonomyLevel(ProtocolEnum):
    """Human-to-agent authority gradient used by governed handoffs."""

    HUMAN_CONTROLLED = "human_controlled"
    SUPERVISED = "supervised"
    AUTONOMOUS = "autonomous"


class AgentProvider(ProtocolEnum):
    """Declared coding-agent handoff source; this is not identity proof."""

    EVE = "eve"
    JUNIE = "junie"
    GROK_BUILD = "grok_build"
    CODERABBIT = "coderabbit"
    DEVIN = "devin"
    GENERIC = "generic"


class AgentRunStatus(ProtocolEnum):
    """Terminal or paused status reported by an evidence-only agent envelope."""

    COMPLETED = "completed"
    PAUSED = "paused"
    BLOCKED = "blocked"
    FAILED = "failed"


class IsolationBoundary(ProtocolEnum):
    """Declared isolation boundary; declarations are not sandbox verification."""

    WORKTREE = "declared_worktree"
    CONTAINER = "declared_container"
    VM = "declared_vm"
    REMOTE = "declared_remote"
    UNVERIFIED = "unverified"


class WorkflowNodeKind(ProtocolEnum):
    """Typed role in a supplied handoff DAG."""

    PLANNER = "planner"
    WORKER = "worker"
    REVIEWER = "reviewer"
    VALIDATOR = "validator"
    APPROVAL = "approval"


class AgentCapability(ProtocolEnum):
    """Declared local capability in a handoff topology."""

    READ_WORKSPACE = "read_workspace"
    WRITE_WORKSPACE = "write_workspace"
    VERIFY = "verify"
    REVIEW = "review"
    APPROVE = "approve"
    HANDOFF = "handoff"


class EvidenceKind(ProtocolEnum):
    """Evidence type accepted by the portable agent bridge."""

    LOGIC = "logic"
    VISUAL = "visual"


class OperationsEvidenceTier(ProtocolEnum):
    """Minimum proof tier selected for a bounded operations change."""

    LOGS_METRICS = "logs_metrics"
    VISUAL_PAIR = "visual_pair"
    INTERACTION_VIDEO = "interaction_video"


class OperationsWorkKind(ProtocolEnum):
    """Work kind used to select controlled reproduction requirements."""

    BUG_FIX = "bug_fix"
    FEATURE = "feature"


class LifecycleEvent(ProtocolEnum):
    """Hash-linked lifecycle event emitted by the local ledger."""

    CREATED = "created"
    ISOLATED = "isolated"
    CONTEXT_READY = "context_ready"
    PROOF_READY = "proof_ready"
    REVIEW_REQUIRED = "review_required"
    ESCALATED = "escalated"
    COMPLETED = "completed"
    STOPPED = "stopped"


class SessionTraceStage(ProtocolEnum):
    """Explicit stage recorded for an agent or harness session trace."""

    INTAKE = "intake"
    PLANNING = "planning"
    IMPLEMENTATION = "implementation"
    VERIFICATION = "verification"
    HANDOFF = "handoff"
    REVIEW = "review"


class RepairSeverity(ProtocolEnum):
    """Human-readable consequence severity in a repair-loop packet."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RepairConsequence(ProtocolEnum):
    """Consequence classification requiring named human review."""

    AVAILABILITY = "availability"
    COMPLIANCE = "compliance"
    DATA_INTEGRITY = "data_integrity"
    SECURITY = "security"
    USER_EXPERIENCE = "user_experience"
    UNKNOWN = "unknown"


class MissionControlState(ProtocolEnum):
    """Read-only Mission Control state derived from evidence projections."""

    BLOCKED = "blocked"
    REVIEW_REQUIRED = "review_required"
    EVIDENCE_MISSING = "evidence_missing"
    SUPERVISED_ONLY = "supervised_only"
