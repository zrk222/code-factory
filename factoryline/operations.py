"""Operations-plane evidence: telemetry, promotion, rollback, and response."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterable

from .control_plane import ControlPlaneError, canonical_json, sha256


OPERATIONS_SCHEMA = "factory.operations.v1"
TELEMETRY_SCHEMA = "factory.telemetry.span.v1"
DEPLOYMENT_SCHEMA = "factory.deployment.receipt.v1"
VULNERABILITY_SCHEMA = "factory.vulnerability.response.v1"
CONNECTOR_SCHEMA = "factory.connector.event.v1"


class OperationsError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationsError("E_REQUIRED", f"{name} is required")
    return value.strip()


@dataclass
class TelemetryRecorder:
    tenant_id: str
    service: str = "factoryline"
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    spans: list[dict[str, Any]] = field(default_factory=list)

    def span(self, name: str, *, attributes: dict[str, Any] | None = None, status: str = "OK", duration_ms: int = 0) -> dict[str, Any]:
        """Record a bounded telemetry span after validating its status and duration."""
        span = {
            "schema": TELEMETRY_SCHEMA,
            "trace_id": self.trace_id,
            "span_id": uuid.uuid4().hex[:16],
            "tenant_id": _required(self.tenant_id, "tenant_id"),
            "service": _required(self.service, "service"),
            "name": _required(name, "name"),
            "status": status,
            "duration_ms": max(0, int(duration_ms)),
            "attributes": attributes or {},
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        span["span_sha256"] = sha256(canonical_json(span))
        self.spans.append(span)
        return span


@contextmanager
def measured_span(recorder: TelemetryRecorder, name: str, *, attributes: dict[str, Any] | None = None):
    """Context manager-like generator for a measured local span."""
    started = time.perf_counter()
    try:
        yield
    except Exception:
        recorder.span(name, attributes=attributes, status="ERROR", duration_ms=round((time.perf_counter() - started) * 1000))
        raise
    else:
        recorder.span(name, attributes=attributes, duration_ms=round((time.perf_counter() - started) * 1000))


@dataclass(frozen=True)
class CanaryPolicy:
    max_error_rate: float = 0.01
    max_latency_p95_ms: int = 1000
    min_requests: int = 100


def evaluate_canary(
    *,
    artifact_digest: str,
    environment: str,
    metrics: dict[str, Any],
    policy: CanaryPolicy = CanaryPolicy(),
    previous_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate canary metrics against explicit thresholds and emit a promotion verdict."""
    requests = int(metrics.get("requests", 0))
    error_rate = float(metrics.get("error_rate", 1.0))
    latency = int(metrics.get("latency_p95_ms", 2**31 - 1))
    reasons: list[str] = []
    if requests < policy.min_requests:
        reasons.append("insufficient_requests")
    if error_rate > policy.max_error_rate:
        reasons.append("error_rate_exceeded")
    if latency > policy.max_latency_p95_ms:
        reasons.append("latency_exceeded")
    promoted = not reasons
    return {
        "schema": DEPLOYMENT_SCHEMA,
        "deployment_id": uuid.uuid4().hex,
        "environment": _required(environment, "environment"),
        "artifact_digest": _required(artifact_digest, "artifact_digest"),
        "previous_digest": previous_digest,
        "strategy": "canary",
        "metrics": {"requests": requests, "error_rate": error_rate, "latency_p95_ms": latency},
        "policy": {"max_error_rate": policy.max_error_rate, "max_latency_p95_ms": policy.max_latency_p95_ms, "min_requests": policy.min_requests},
        "decision": "PROMOTE" if promoted else "ROLLBACK",
        "reasons": reasons,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def rollback_receipt(deployment: dict[str, Any], *, actor: str, reason: str) -> dict[str, Any]:
    """Build an auditable rollback receipt bound to the original deployment digest."""
    if deployment.get("decision") != "ROLLBACK":
        raise OperationsError("E_ROLLBACK_NOT_REQUIRED", "rollback receipt requires a failed deployment decision")
    previous = _required(deployment.get("previous_digest"), "previous_digest")
    receipt = {
        "schema": DEPLOYMENT_SCHEMA,
        "kind": "rollback",
        "deployment_id": deployment.get("deployment_id"),
        "environment": deployment.get("environment"),
        "from_digest": deployment.get("artifact_digest"),
        "to_digest": previous,
        "actor": _required(actor, "actor"),
        "reason": _required(reason, "reason"),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    receipt["receipt_sha256"] = sha256(canonical_json(receipt))
    return receipt


def vulnerability_response(
    *,
    vulnerability: str,
    severity: str,
    components: Iterable[str],
    actions: Iterable[str],
    status: str = "OPEN",
) -> dict[str, Any]:
    """Create a severity-aware vulnerability response with deterministic next actions."""
    severity = _required(severity, "severity").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise OperationsError("E_VULNERABILITY_SEVERITY", "severity must be LOW, MEDIUM, HIGH, or CRITICAL")
    response = {
        "schema": VULNERABILITY_SCHEMA,
        "vulnerability": _required(vulnerability, "vulnerability"),
        "severity": severity,
        "components": sorted({_required(item, "component") for item in components}),
        "actions": sorted({_required(item, "action") for item in actions}),
        "status": _required(status, "status").upper(),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    response["response_sha256"] = sha256(canonical_json(response))
    return response


def connector_event(*, target: str, event_type: str, tenant_id: str, subject_digest: str, attributes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalize a tenant connector event while rejecting missing authority fields."""
    target = _required(target, "target").lower()
    if target not in {"siem", "ticketing"}:
        raise OperationsError("E_CONNECTOR_TARGET", "target must be siem or ticketing")
    event = {
        "schema": CONNECTOR_SCHEMA,
        "target": target,
        "event_type": _required(event_type, "event_type"),
        "tenant_id": _required(tenant_id, "tenant_id"),
        "subject_digest": _required(subject_digest, "subject_digest"),
        "attributes": attributes or {},
        "disclosure": "metadata-only",
    }
    event["event_sha256"] = sha256(canonical_json(event))
    return event
