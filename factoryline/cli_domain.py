"""Bounded, lazily loaded domain and mission-control CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "domain"
OWNER = "domain-control-maintainers"


def add_parser(sub: Any) -> None:
    """Register ontology and mission-control readers without loading engines."""
    ontology = sub.add_parser("ontology", help="validate an explicitly human-approved domain vocabulary without inferring or mutating intent")
    ontology_sub = ontology.add_subparsers(required=True, dest="ontology_cmd")
    template = ontology_sub.add_parser("template", help="render a domain-ontology template")
    template.add_argument("--json", action="store_true")
    validate = ontology_sub.add_parser("validate", help="fail closed when referenced concepts are not in the approved ontology")
    validate.add_argument("--root", default=".")
    validate.add_argument("--ontology", required=True, help="workspace-relative factory.domain-ontology.v1 JSON")
    validate.add_argument("--concept", required=True, action="append", help="referenced domain concept id; repeat as needed")
    validate.add_argument("--json", action="store_true")

    mission = sub.add_parser("mission-control", help="read one unified, zero-authority human and agent evidence status")
    mission_sub = mission.add_subparsers(required=True, dest="mission_control_cmd")
    status = mission_sub.add_parser("status", help="read local mission-control facts without granting authority")
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")
    profile = mission_sub.add_parser("profile", help="measure local evidence readers with body-free fingerprints")
    profile.add_argument("--root", default=".")
    profile.add_argument("--json", action="store_true")


def _run_ontology(args: Any) -> int:
    from .domain_ontology import DomainOntologyError, domain_ontology_template, validate_domain_ontology

    root = Path(getattr(args, "root", ".")).resolve()
    try:
        result = domain_ontology_template() if args.ontology_cmd == "template" else validate_domain_ontology(root, Path(args.ontology), args.concept)
        code = 0 if args.ontology_cmd == "template" or result.get("marker") == "ONTOLOGY_READY" else 1
    except (DomainOntologyError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        result = {"schema": "factory.domain-ontology.error.v1", "marker": "ONTOLOGY_INPUT_REJECTED", "code": getattr(exc, "code", "E_ONTOLOGY_SCHEMA"), "message": str(exc)}
        code = 2
    print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr if code else sys.stdout)
    return code


def _run_mission(args: Any) -> int:
    from .mission_control_status import mission_control_profile, mission_control_status

    reader = mission_control_profile if args.mission_control_cmd == "profile" else mission_control_status
    result = reader(Path(args.root).resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def run(args: Any) -> int:
    """Dispatch domain commands with lazy imports."""
    return _run_ontology(args) if args.cmd == "ontology" else _run_mission(args)
