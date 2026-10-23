"""Versioned cross-brick protocol and compatibility checks."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from enum import Enum
from importlib import metadata

RECEIPT_SCHEMA = "factory.receipt.v2"
CHALLENGE_SCHEMA = "factory.challenge.v1"
PASSPORT_SCHEMA = "factory.passport.v1"

MINIMUM_VERSIONS = {
    "specline": "0.5.4",
    "forgeline": "0.10.8",
    "hsf": "0.5.5",
    "prestige": "0.7.4",
}

REQUIRED_COMMANDS = {
    "specline": {"strict", "verify-validators", "challenge"},
    "forgeline": {"gate", "fill", "verify-tests", "challenge"},
    "hsf": {"compile", "goldens", "challenge"},
    "prestige": {
        "audit",
        "render-audit",
        "challenge",
        "tokens",
        "verify-tokens",
        "init",
        "report",
        "pr",
        "ci",
        "benchmark",
    },
}


def version_tuple(value: str) -> tuple[int, ...]:
    """Parse the numeric release components from a version for compatibility checks."""
    numbers = re.findall(r"\d+", value)
    return tuple(int(part) for part in numbers[:3]) or (0,)


@dataclass(frozen=True)
class Compatibility:
    module: str
    cli: str
    package: str
    installed: bool
    version: str | None
    minimum: str
    version_ok: bool
    commands_ok: bool | None = None
    missing_commands: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Return whether the installed producer satisfies the required protocol range."""
        return self.installed and self.version_ok and self.commands_ok is not False


def package_version(package: str) -> str | None:
    """Return an installed package version, or None when the package is unavailable."""
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def compatibility(
    module: str,
    meta: dict,
    help_text: str | None = None,
    *,
    reported_version: str | None = None,
) -> Compatibility:
    """Evaluate producer compatibility against explicit minimum and maximum versions."""
    installed = shutil.which(meta["cli"]) is not None
    version = package_version(meta["pip"]) or reported_version
    minimum = MINIMUM_VERSIONS[module]
    required = REQUIRED_COMMANDS[module]
    missing = tuple(
        sorted(
            command
            for command in required
            if help_text is not None and command not in help_text
        )
    )
    return Compatibility(
        module=module,
        cli=meta["cli"],
        package=meta["pip"],
        installed=installed,
        version=version,
        minimum=minimum,
        version_ok=version is not None
        and version_tuple(version) >= version_tuple(minimum),
        commands_ok=None if help_text is None else not missing,
        missing_commands=missing,
    )


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
