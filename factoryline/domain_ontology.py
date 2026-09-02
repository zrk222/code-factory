"""Small, human-approved domain ontologies for intent and repair review."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


SCHEMA = "factory.domain-ontology.v1"
REPORT_SCHEMA = "factory.domain-ontology-report.v1"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_RELATIONS = {"depends_on", "forbids", "maps_to", "produces", "requires"}
AUTHORITY = {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}


class DomainOntologyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message); self.code = code


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _load(root: Path, source: Path) -> dict[str, Any]:
    relative = str(source).replace("\\", "/")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", "ontology must be readable UTF-8 JSON below the workspace") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "id", "concepts", "relationships"} or value.get("schema") != SCHEMA:
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", f"ontology must use exact {SCHEMA} fields")
    if not isinstance(value["id"], str) or not _ID.fullmatch(value["id"]):
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", "ontology id must be safe")
    concepts = value["concepts"]
    if not isinstance(concepts, list) or not 1 <= len(concepts) <= 128:
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", "concepts must contain 1-128 entries")
    normalized = []
    identifiers = set()
    for index, item in enumerate(concepts):
        if not isinstance(item, dict) or set(item) != {"id", "definition", "owner", "invariants"} or not isinstance(item["id"], str) or not _ID.fullmatch(item["id"]) or item["id"] in identifiers or not isinstance(item["definition"], str) or not item["definition"].strip() or len(item["definition"]) > 400 or not isinstance(item["owner"], str) or not _ID.fullmatch(item["owner"]) or not isinstance(item["invariants"], list) or len(item["invariants"]) > 16 or any(not isinstance(rule, str) or not rule.strip() or len(rule) > 240 for rule in item["invariants"]):
            raise DomainOntologyError("E_ONTOLOGY_SCHEMA", f"concepts[{index}] is invalid")
        identifiers.add(item["id"]); normalized.append({"id": item["id"], "definition": item["definition"].strip(), "owner": item["owner"], "invariants": sorted(item["invariants"])})
    relations = value["relationships"]
    if not isinstance(relations, list) or len(relations) > 256:
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", "relationships must contain at most 256 entries")
    normalized_relations = []
    for index, item in enumerate(relations):
        if not isinstance(item, dict) or set(item) != {"subject", "predicate", "object"} or item["subject"] not in identifiers or item["object"] not in identifiers or item["predicate"] not in _RELATIONS:
            raise DomainOntologyError("E_ONTOLOGY_SCHEMA", f"relationships[{index}] is invalid")
        normalized_relations.append({"subject": item["subject"], "predicate": item["predicate"], "object": item["object"]})
    return {"id": value["id"], "concepts": sorted(normalized, key=lambda item: item["id"]), "relationships": sorted(normalized_relations, key=lambda item: (item["subject"], item["predicate"], item["object"]))}


def validate_domain_ontology(root: Path, source: Path, referenced_concepts: list[str]) -> dict[str, Any]:
    """Validate only explicitly human-approved concepts referenced by a workflow."""
    ontology = _load(Path(root).resolve(), source)
    if not referenced_concepts or len(referenced_concepts) > 64 or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in referenced_concepts):
        raise DomainOntologyError("E_ONTOLOGY_SCHEMA", "referenced concepts must contain 1-64 safe ids")
    known = {item["id"] for item in ontology["concepts"]}
    unknown = sorted(set(referenced_concepts) - known)
    core = {"schema": REPORT_SCHEMA, "marker": "ONTOLOGY_READY" if not unknown else "ONTOLOGY_UNKNOWN_CONCEPT_BLOCKED", "ontology": {"id": ontology["id"], "sha256": _sha(ontology)}, "referenced_concepts": sorted(set(referenced_concepts)), "unknown_concepts": unknown, "authority": dict(AUTHORITY), "claim_boundary": "A reviewed vocabulary check only. It does not infer a domain model, change an intent contract, or authorize work."}
    return {**core, "report_sha256": _sha(core)}


def domain_ontology_template() -> dict[str, Any]:
    """Return a secret-free template for a small human-owned domain vocabulary."""
    return {"schema": "factory.domain-ontology-template.v1", "ontology_schema": SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. A human must define and approve every concept and invariant before it constrains review.", "ontology": {"schema": SCHEMA, "id": "replace-with-domain", "concepts": [{"id": "entitlement", "definition": "The currently permitted product capability for one subject and tenant.", "owner": "billing", "invariants": ["A revoked entitlement must not allow paid capability access."]}, {"id": "refund", "definition": "A financial reversal that may require entitlement revocation.", "owner": "billing", "invariants": ["A refund is not itself proof that access was revoked."]}], "relationships": [{"subject": "refund", "predicate": "requires", "object": "entitlement"}]}}
