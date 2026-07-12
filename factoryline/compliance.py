"""Versioned, non-certifying compliance evidence packs."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Iterable

from .control_plane import ControlPlaneError, canonical_json, sha256


COMPLIANCE_SCHEMA = "factory.compliance.v1"
OSCAL_SCHEMA = "https://docs.oasis-open.org/oscal/assessment-common/v1.1/oscal-assessment-common.json"


class ComplianceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# These are deliberately factory-owned mappings, not claims of complete
# coverage of any external standard. Each pack must be versioned and reviewed.
CONTROL_PACKS: dict[str, dict[str, Any]] = {
    "nist-ssdf": {
        "version": "factory-baseline-1",
        "source": "NIST SSDF",
        "controls": [
            {"id": "PW.1", "title": "Prepare and maintain well-secured software", "evidence": ["spec", "policy"]},
            {"id": "PW.7", "title": "Review and/or analyze human-readable code", "evidence": ["tests", "review"]},
            {"id": "RV.1", "title": "Identify and confirm vulnerabilities", "evidence": ["sbom", "vex"]},
        ],
    },
    "owasp-asvs": {
        "version": "factory-baseline-1",
        "source": "OWASP ASVS",
        "controls": [
            {"id": "V1", "title": "Architecture, design and threat modeling", "evidence": ["spec", "graph"]},
            {"id": "V2", "title": "Authentication", "evidence": ["identity", "approval"]},
            {"id": "V14", "title": "Configuration", "evidence": ["policy", "receipt"]},
        ],
    },
    "soc2": {
        "version": "factory-baseline-1",
        "source": "SOC 2 Trust Services Criteria",
        "controls": [
            {"id": "CC6", "title": "Logical and physical access controls", "evidence": ["identity", "audit"]},
            {"id": "CC7", "title": "System operations monitoring", "evidence": ["telemetry", "vulnerability"]},
            {"id": "CC8", "title": "Change management", "evidence": ["approval", "trace"]},
        ],
    },
    "iso27001": {
        "version": "factory-baseline-1",
        "source": "ISO/IEC 27001",
        "controls": [
            {"id": "A.5", "title": "Organizational controls", "evidence": ["policy", "approval"]},
            {"id": "A.8", "title": "Technological controls", "evidence": ["sbom", "vex", "telemetry"]},
            {"id": "A.8.25", "title": "Secure development life cycle", "evidence": ["spec", "tests", "trace"]},
        ],
    },
    "customer": {
        "version": "factory-baseline-1",
        "source": "Customer policy mapping",
        "controls": [],
    },
}


def _control_pack(name: str, controls: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    name = name.strip().lower()
    if name not in CONTROL_PACKS:
        raise ComplianceError("E_CONTROL_PACK", f"unknown control pack: {name}")
    pack = CONTROL_PACKS[name]
    selected = list(controls) if controls is not None else list(pack["controls"])
    for control in selected:
        if not isinstance(control, dict) or not control.get("id") or not control.get("title"):
            raise ComplianceError("E_CONTROL", "controls need id and title")
    return {"name": name, "version": pack["version"], "source": pack["source"], "controls": selected}


def build_oscal_assessment(
    pack_name: str,
    *,
    tenant_id: str,
    evidence: Iterable[dict[str, Any]],
    custom_controls: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    pack = _control_pack(pack_name, custom_controls)
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise ComplianceError("E_TENANT_REQUIRED", "tenant_id is required")
    evidence_list = [item for item in evidence if isinstance(item, dict)]
    evidence_controls = {
        control_id
        for item in evidence_list
        for control_id in item.get("control_ids", item.get("controls", []))
        if isinstance(control_id, str)
    }
    observations = []
    findings = []
    for control in sorted(pack["controls"], key=lambda item: item["id"]):
        satisfied = control["id"] in evidence_controls
        observation = {
            "uuid": hashlib.sha256(f"{tenant_id}:{pack['name']}:{control['id']}".encode()).hexdigest()[:32],
            "title": control["title"],
            "props": [
                {"name": "factory_status", "value": "satisfied" if satisfied else "not_assessed"},
                {"name": "factory_evidence_types", "value": ",".join(control.get("evidence", []))},
            ],
        }
        observations.append(observation)
        if not satisfied:
            findings.append({"target": {"type": "control-id", "id": control["id"]}, "status": {"state": "not-satisfied"}})
    result = {
        "schema": COMPLIANCE_SCHEMA,
        "oscal_schema": OSCAL_SCHEMA,
        "assessment-results": {
            "uuid": hashlib.sha256(canonical_json({"tenant_id": tenant_id, "pack": pack})).hexdigest()[:32],
            "metadata": {
                "title": f"FactoryLine assessment: {pack['source']}",
                "version": pack["version"],
                "last-modified": datetime.now(timezone.utc).isoformat(),
                "props": [
                    {"name": "tenant_id", "value": tenant_id},
                    {"name": "certification", "value": "not-a-certification"},
                ],
            },
            "results": [{"title": "FactoryLine evidence result", "observations": observations, "findings": findings}],
        },
    }
    result["assessment_sha256"] = sha256(canonical_json(result))
    return result

