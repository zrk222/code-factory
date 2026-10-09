"""Local, privacy-bounded activation evidence and shareable Proof Cards.

The adoption surface deliberately avoids hosted analytics.  The first proof
keeps its disposable sandbox demonstration, but also records a bounded local
inventory of the selected workspace so a new user can see what was assessed.
The inventory is not a certification and never includes source bodies,
commands, prompts, logs, or user identifiers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable
from .e2e_proof import (
    E2EProofError,
    validate_e2e_proof_receipt,
    verify_e2e_proof,
    write_e2e_proof_artifacts,
)
from .review_audits import MAX_SECURITY_SOURCE_FILES


FIRST_PROOF_SCHEMA = "factory.first-proof.v1"
PROOF_CARD_SCHEMA = "factory.proof-card.v1"
ADOPTION_EVENT_SCHEMA = "factory.adoption-event.v1"
ADOPTION_STATUS_SCHEMA = "factory.adoption-status.v1"
MILESTONES = frozenset(
    {
        "first_proof_completed",
        "proof_receipt_saved",
        "proof_card_saved",
        "seven_day_return",
    }
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class AdoptionError(ValueError):
    """Malformed or tampered adoption evidence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _utc(value: datetime | None = None) -> datetime:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


_INVENTORY_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".factory",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
    }
)


def _workspace_inventory(workspace: Path, *, limit: int = 10_000) -> dict[str, Any]:
    """Collect only relative file metadata for an immediate, safe assessment."""
    rows: list[dict[str, Any]] = []
    truncated = False
    for directory, dirnames, filenames in os.walk(workspace, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames if name not in _INVENTORY_IGNORED_DIRS
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            try:
                relative = path.relative_to(workspace).as_posix()
                size = path.stat().st_size
            except (OSError, ValueError):
                continue
            rows.append({"path": relative, "bytes": size})
            if len(rows) >= limit:
                truncated = True
                break
        if truncated:
            break
    suffixes = {
        "python": (".py",),
        "javascript": (".js", ".jsx", ".mjs", ".cjs"),
        "typescript": (".ts", ".tsx"),
        "docs": (".md", ".rst"),
        "go": (".go",),
        "rust": (".rs",),
        "java": (".java",),
        "kotlin": (".kt", ".kts"),
        "c_cpp": (".c", ".h", ".cpp", ".hpp", ".cc"),
        "csharp": (".cs",),
        "ruby": (".rb",),
        "php": (".php",),
        "swift": (".swift",),
        "shell": (".sh", ".ps1", ".bash"),
    }
    counts = {
        key: sum(row["path"].lower().endswith(extensions) for row in rows)
        for key, extensions in suffixes.items()
    }
    return {
        "state": "ASSESSED" if rows else "INCOMPLETE",
        "files_discovered": len(rows),
        "files_truncated": truncated,
        "file_types": counts,
        "inventory_sha256": _sha(rows),
        "scope": "relative file names and byte sizes only; source contents were not read",
    }


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)
    return path


def _workspace_path(root: Path, path: Path) -> Path:
    workspace = Path(root).resolve()
    candidate = Path(path)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workspace / candidate).resolve()
    )
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise AdoptionError(
            "E_ADOPTION_PATH_ESCAPE",
            "adoption artifacts must stay inside the workspace",
        ) from exc
    return resolved


def _card_facts(receipt: dict[str, Any]) -> dict[str, Any]:
    validated = validate_e2e_proof_receipt(receipt)
    marker = validated["marker"]
    if marker == "E2E_PROOF_PASS":
        outcome = "FAILURE_CASE_REJECTED"
        headline = "The declared failure case was rejected"
    elif marker == "HOLLOW_E2E_TEST":
        outcome = "HOLLOW_TEST_DETECTED"
        headline = "A test that could not say no was caught"
    else:
        outcome = "PROOF_BLOCKED"
        headline = "The declared proof did not complete"
    core = {
        "schema": PROOF_CARD_SCHEMA,
        "evidence_schema": validated["schema"],
        "source_receipt_sha256": validated["receipt_sha256"],
        "marker": marker,
        "outcome": outcome,
        "headline": headline,
        "positive_check_passed": validated["commands"]["positive"]["exit_code"] == 0,
        "negative_case_rejected": validated["commands"]["negative"]["exit_code"]
        not in (None, 0),
        "hollow_test_detected": marker == "HOLLOW_E2E_TEST",
        "privacy": {
            "contains_commands": False,
            "contains_paths": False,
            "contains_repository_name": False,
            "contains_prompts_or_logs": False,
            "contains_user_identity": False,
        },
        "authority": {
            "share": True,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
        },
        "scope_limit": "This card summarizes one verified local receipt. It is not a production-readiness, security, coverage, or identity certificate.",
    }
    return {**core, "card_sha256": _sha(core)}


def _card_markdown(card: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Code Factory Proof Card",
            "",
            f"## {card['headline']}",
            "",
            f"- Outcome: `{card['outcome']}`",
            f"- Marker: `{card['marker']}`",
            f"- Positive check passed: `{str(card['positive_check_passed']).lower()}`",
            f"- Negative case rejected: `{str(card['negative_case_rejected']).lower()}`",
            f"- Hollow test detected: `{str(card['hollow_test_detected']).lower()}`",
            f"- Source receipt: `{card['source_receipt_sha256']}`",
            f"- Card SHA-256: `{card['card_sha256']}`",
            "",
            "No commands, paths, repository name, prompts, logs, or user identity are included.",
            "",
            card["scope_limit"],
            "",
            "https://github.com/zrk222/code-factory",
            "",
        ]
    )


def _card_svg(card: dict[str, Any]) -> str:
    positive = "PASS" if card["positive_check_passed"] else "BLOCKED"
    negative = "REJECTED" if card["negative_case_rejected"] else "SURVIVED"
    accent = "#0f766e" if card["outcome"] == "FAILURE_CASE_REJECTED" else "#b45309"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img" aria-labelledby="title desc">
  <title id="title">Code Factory Proof Card</title>
  <desc id="desc">{escape(card["headline"])}. Privacy-safe summary of one verified local receipt.</desc>
  <rect width="1280" height="720" rx="36" fill="#f8fafc"/>
  <rect x="44" y="44" width="1192" height="632" rx="28" fill="#ffffff" stroke="#cbd5e1" stroke-width="3"/>
  <text x="92" y="118" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#475569">CODE FACTORY · PROOF CARD</text>
  <text x="92" y="205" font-family="Arial, sans-serif" font-size="50" font-weight="800" fill="#0f172a">{escape(card["headline"])}</text>
  <rect x="92" y="260" width="500" height="126" rx="20" fill="#ecfeff" stroke="#a5f3fc"/>
  <text x="124" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">POSITIVE CHECK</text>
  <text x="124" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="#0f766e">{positive}</text>
  <rect x="620" y="260" width="500" height="126" rx="20" fill="#fff7ed" stroke="#fed7aa"/>
  <text x="652" y="308" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#475569">DECLARED FAILURE CASE</text>
  <text x="652" y="358" font-family="Arial, sans-serif" font-size="34" font-weight="800" fill="{accent}">{negative}</text>
  <text x="92" y="468" font-family="Arial, sans-serif" font-size="23" fill="#334155">Outcome · {escape(card["outcome"])}</text>
  <text x="92" y="510" font-family="Arial, sans-serif" font-size="20" fill="#64748b">Receipt · {card["source_receipt_sha256"][:20]}…</text>
  <text x="92" y="550" font-family="Arial, sans-serif" font-size="20" fill="#64748b">No code, paths, prompts, logs, or identity included.</text>
  <line x1="92" y1="590" x2="1120" y2="590" stroke="#e2e8f0" stroke-width="2"/>
  <text x="92" y="632" font-family="Arial, sans-serif" font-size="18" fill="#64748b">One verified receipt · not a production-readiness certificate</text>
  <text x="1120" y="632" text-anchor="end" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#2563eb">github.com/zrk222/code-factory</text>
</svg>
'''


def verify_proof_card(value: object) -> dict[str, Any]:
    """Validate the exact Proof Card schema, privacy flags, and canonical digest."""
    if not isinstance(value, dict) or value.get("schema") != PROOF_CARD_SCHEMA:
        raise AdoptionError(
            "E_PROOF_CARD_INVALID", f"a {PROOF_CARD_SCHEMA} object is required"
        )
    required = {
        "schema",
        "evidence_schema",
        "source_receipt_sha256",
        "marker",
        "outcome",
        "headline",
        "positive_check_passed",
        "negative_case_rejected",
        "hollow_test_detected",
        "privacy",
        "authority",
        "scope_limit",
        "card_sha256",
    }
    if set(value) != required:
        raise AdoptionError("E_PROOF_CARD_INVALID", "Proof Card fields changed")
    if not _SHA256.fullmatch(str(value.get("source_receipt_sha256", ""))):
        raise AdoptionError("E_PROOF_CARD_INVALID", "source receipt digest is invalid")
    core = {key: value[key] for key in value if key != "card_sha256"}
    if value.get("card_sha256") != _sha(core):
        raise AdoptionError("E_PROOF_CARD_INVALID", "Proof Card hash does not match")
    if value["privacy"] != {
        "contains_commands": False,
        "contains_paths": False,
        "contains_repository_name": False,
        "contains_prompts_or_logs": False,
        "contains_user_identity": False,
    }:
        raise AdoptionError(
            "E_PROOF_CARD_INVALID", "Proof Card privacy boundary changed"
        )
    return value


def write_proof_card(receipt: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write JSON, Markdown, and SVG cards from one verified E2E proof receipt."""
    card = verify_proof_card(_card_facts(receipt))
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"proof-card-{card['card_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
        "svg": destination / f"{stem}.svg",
    }
    _atomic_json(paths["json"], card)
    paths["markdown"].write_text(_card_markdown(card), encoding="utf-8")
    paths["svg"].write_text(_card_svg(card), encoding="utf-8")
    return {"card": card, "paths": {key: str(path) for key, path in paths.items()}}


def proof_card_from_receipt(
    root: Path, receipt_path: Path, out_dir: Path
) -> dict[str, Any]:
    """Create a Proof Card from a workspace-contained E2E receipt file."""
    workspace = Path(root).resolve()
    source = _workspace_path(workspace, receipt_path)
    if not source.is_file():
        raise AdoptionError(
            "E_PROOF_CARD_SOURCE", "receipt must name a workspace-contained JSON file"
        )
    try:
        receipt = json.loads(source.read_text(encoding="utf-8"))
        validate_e2e_proof_receipt(receipt)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, E2EProofError) as exc:
        raise AdoptionError(
            "E_PROOF_CARD_SOURCE", f"receipt is not a valid E2E proof: {exc}"
        ) from exc
    return write_proof_card(receipt, _workspace_path(workspace, out_dir))


def record_adoption_event(
    root: Path,
    milestone: str,
    *,
    evidence_sha256: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Append one allowlisted, identity-free local activation milestone."""
    if milestone not in MILESTONES:
        raise AdoptionError(
            "E_ADOPTION_MILESTONE",
            f"milestone must be one of {', '.join(sorted(MILESTONES))}",
        )
    if evidence_sha256 is not None and not _SHA256.fullmatch(evidence_sha256):
        raise AdoptionError(
            "E_ADOPTION_EVIDENCE", "evidence_sha256 must be a lowercase SHA-256 digest"
        )
    core = {
        "schema": ADOPTION_EVENT_SCHEMA,
        "milestone": milestone,
        "observed_at": _iso(observed_at),
        "evidence_sha256": evidence_sha256,
        "privacy": "local aggregate milestone only; no project, path, prompt, log, command, user, or provider identity",
    }
    event = {**core, "event_sha256": _sha(core)}
    stamp = core["observed_at"].replace(":", "").replace("-", "")
    path = (
        Path(root).resolve()
        / ".factory"
        / "adoption"
        / "events"
        / f"{stamp}-{milestone}-{event['event_sha256'][:12]}.json"
    )
    _atomic_json(path, event)
    return {"event": event, "path": str(path)}


def _load_events(root: Path) -> list[dict[str, Any]]:
    directory = Path(root).resolve() / ".factory" / "adoption" / "events"
    events: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", f"cannot read adoption event: {exc}"
            ) from exc
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "milestone",
            "observed_at",
            "evidence_sha256",
            "privacy",
            "event_sha256",
        }:
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", "adoption event shape changed"
            )
        core = {key: value[key] for key in value if key != "event_sha256"}
        if (
            value["schema"] != ADOPTION_EVENT_SCHEMA
            or value["milestone"] not in MILESTONES
            or value["event_sha256"] != _sha(core)
        ):
            raise AdoptionError(
                "E_ADOPTION_EVENT_INVALID", "adoption event is malformed or tampered"
            )
        events.append(value)
    return events


def adoption_status(root: Path) -> dict[str, Any]:
    """Aggregate verified local milestones while preserving unknown provider facts."""
    events = _load_events(root)
    counts = {
        milestone: sum(event["milestone"] == milestone for event in events)
        for milestone in sorted(MILESTONES)
    }
    first = min((event["observed_at"] for event in events), default=None)
    last = max((event["observed_at"] for event in events), default=None)
    return {
        "schema": ADOPTION_STATUS_SCHEMA,
        "measurement": "local_opt_in_events_only",
        "events": len(events),
        "first_observed_at": first,
        "last_observed_at": last,
        "milestones": counts,
        "funnel": {
            "page_visit": None,
            "install": None,
            "first_proof": counts["first_proof_completed"],
            "proof_receipt_saved": counts["proof_receipt_saved"],
            "proof_card_saved": counts["proof_card_saved"],
            "seven_day_return": counts["seven_day_return"],
        },
        "unknown_reason": "Page visits and installs are provider metrics. Local events are not users, conversions, or causal attribution.",
        "privacy": "No central transmission; no project, path, prompt, log, command, user, or provider identity.",
    }


def export_adoption_status(root: Path, out: Path) -> dict[str, Any]:
    """Write the privacy-bounded local activation aggregate inside the workspace."""
    workspace = Path(root).resolve()
    path = _workspace_path(workspace, out)
    payload = adoption_status(workspace)
    _atomic_json(path, payload)
    # The export is intentionally safe to paste into an issue or dashboard.
    # Return the workspace-relative artifact reference rather than disclosing
    # the caller's absolute checkout path on POSIX or Windows.
    return {"status": payload, "path": path.relative_to(workspace).as_posix()}


SCHEMA = "factory.deep-repository-audit.v1"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _lane(
    measurement_id: str,
    *,
    state: str,
    applicable: bool,
    result: Any = None,
    basis: str,
    next_action: str,
    denominator_state: str = "DECLARED",
) -> dict[str, Any]:
    measurement_state = {
        "PASS": "MEASURED",
        "HEALTHY": "MEASURED",
        "CLEAN": "MEASURED",
        "OBSERVED": "MEASURED",
        "NOT_APPLICABLE": "NOT_APPLICABLE",
        "NOT_RUN": "NOT_MEASURED",
        "INCOMPLETE": "NOT_MEASURED",
        "BLOCKED": "BLOCKED",
        "INVALID": "BLOCKED",
        "REVIEW_REQUIRED": "REVIEW_REQUIRED",
    }.get(state, "NOT_MEASURED")
    return {
        "measurement_id": measurement_id,
        "state": state,
        "measurement_state": measurement_state,
        "applicability_state": "APPLICABLE" if applicable else "NOT_APPLICABLE",
        "denominator_state": denominator_state,
        "basis": basis,
        "result": result,
        "next_action": next_action,
    }


def _safe(call: Callable[[], Any], *, error_action: str) -> tuple[Any, str | None]:
    try:
        return call(), None
    except Exception as exc:  # analyzers must not hide a failed lane
        return {
            "state": "INVALID",
            "message": "Analyzer failed: " + type(exc).__name__,
        }, error_action


def _manifest_paths(root: Path) -> list[str]:
    names = (
        "pyproject.toml",
        "requirements.txt",
        "requirements.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile.lock",
    )
    ignored = {".git", ".factory", ".venv", "venv", "node_modules", "dist", "build"}
    found: list[str] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in ignored and not (Path(directory) / name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if name in names and not path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def _receipt_inventory(
    root: Path, *, patterns: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Inventory bounded worker receipts without treating presence as proof."""
    evidence_root = root / ".factory"
    if not evidence_root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    from .deep_audit_io import local_file

    for path in evidence_root.rglob("*"):
        if not any(path.match(pattern) for pattern in patterns) or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            verified_path = local_file(root, relative)
            with verified_path.open("rb") as stream:
                payload = stream.read(16 * 1024 * 1024 + 1)
        except (OSError, UnicodeError, ValueError):
            continue
        if len(payload) > 16 * 1024 * 1024:
            continue
        parsed_schema = None
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(payload.decode("utf-8"))
                if isinstance(parsed, dict):
                    parsed_schema = parsed.get("schema")
            except (UnicodeError, json.JSONDecodeError):
                parsed_schema = None
        rows.append(
            {
                "path": relative,
                "sha256": sha256(payload).hexdigest(),
                "schema": parsed_schema,
                "verification": "PRESENT_UNVERIFIED",
            }
        )
        if len(rows) >= 256:
            break
    return sorted(rows, key=lambda row: row["path"])


def _state_for_findings(result: dict[str, Any], *, clean: str = "PASS") -> str:
    if result.get("state") in {"BLOCKED", "INVALID"}:
        return "BLOCKED"
    if result.get("findings") or result.get("regressions"):
        return "BLOCKED"
    if str(result.get("state", "")).upper() in {
        "INCOMPLETE",
        "NOT_RUN",
        "INSUFFICIENT_EVIDENCE",
    }:
        return "INCOMPLETE"
    if result.get("decision") == "REVIEW_REQUIRED":
        return "REVIEW_REQUIRED"
    return clean


def _python_audit_lanes(
    workspace: Path, python_count: int, tenant_contract: str
) -> list[dict[str, Any]]:
    lanes: list[dict[str, Any]] = []
    if python_count:
        from .review_audits import (
            load_tenant_read_contract,
            security_evals,
            security_scan,
        )

        try:
            calls, bindings, contract = load_tenant_read_contract(
                workspace, tenant_contract
            )
            security = security_scan(
                workspace,
                tenant_read_calls=tuple(calls),
                tenant_read_bindings=tuple(bindings),
                tenant_read_scopes=contract.get("scoped_reads"),
            )
            security_state = _state_for_findings(
                security, clean=security.get("state", "INVALID")
            )
        except Exception as exc:
            security = {
                "state": "INVALID",
                "message": "Analyzer failed: " + type(exc).__name__,
            }
            security_state = "BLOCKED"
        lanes.append(
            _lane(
                "python_ast_security",
                state=security_state,
                applicable=True,
                result=security,
                basis="Python AST security, hollow-test, tenant-contract and alias-aware checks over the 460-file scanner boundary.",
                next_action=security.get(
                    "action_summary", "Resolve Python security or test-oracle findings."
                ),
                denominator_state="MEASURED"
                if security_state != "BLOCKED"
                else "DECLARED",
            )
        )
        evals, error = _safe(
            security_evals,
            error_action="Repair the scanner self-evaluation fixtures and rerun.",
        )
        if error:
            evals["next_action"] = error
        lanes.append(
            _lane(
                "scanner_self_evaluation",
                state="PASS" if evals.get("state") == "PASS" else "BLOCKED",
                applicable=True,
                result=evals,
                basis="Adversarial and safe-control fixtures for scanner rule behavior; separate from repository findings.",
                next_action=evals.get(
                    "action_summary", "Repair failed scanner self-evaluations."
                ),
            )
        )
    else:
        lanes.extend(
            [
                _lane(
                    "python_ast_security",
                    state="NOT_APPLICABLE",
                    applicable=False,
                    basis="No Python source was discovered.",
                    next_action="Run a language-specific security lane for each detected non-Python language.",
                    denominator_state="MEASURED",
                ),
                _lane(
                    "scanner_self_evaluation",
                    state="NOT_APPLICABLE",
                    applicable=False,
                    basis="Python scanner self-evaluation is not applicable without Python source.",
                    next_action="Use the applicable language-specific verifier suite.",
                    denominator_state="MEASURED",
                ),
            ]
        )

    return lanes


def _native_worker_lane(
    workspace: Path, config: str | None, applicable: bool
) -> dict[str, Any]:
    """Execute existing signed worker plans only on explicit operator request."""
    action = "Supply --deep --worker-config with a signed execution manifest, authorization and pinned trust root."
    if config is None:
        return _lane(
            "native_worker_execution",
            state="NOT_RUN" if applicable else "NOT_APPLICABLE",
            applicable=applicable,
            basis="Isolated native scanners require explicit signed authorization.",
            next_action=action,
        )
    from .deep_audit import scan_deep_audit
    from .deep_audit_io import LIMIT, local_file, strict_json
    from .runtime_audit_common import require_digest

    def execute() -> dict:
        path = local_file(workspace, config)
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("Worker configuration exceeds byte budget")
        settings = strict_json(raw)
        required = {
            "manifest",
            "manifest_sha256",
            "authorization",
            "trust_root",
            "trust_root_sha256",
        }
        if set(settings) != required:
            raise ValueError(
                "Worker configuration fields do not match the execution contract"
            )
        return scan_deep_audit(
            workspace,
            local_file(workspace, settings["manifest"]),
            require_digest(settings["manifest_sha256"], "manifest_sha256"),
            authorization=local_file(workspace, settings["authorization"]),
            trust_root=local_file(workspace, settings["trust_root"]),
            trust_root_sha256=require_digest(
                settings["trust_root_sha256"], "trust_root_sha256"
            ),
        )

    result, error = _safe(execute, error_action=action)
    state = "BLOCKED" if error else "INCOMPLETE"
    if not error and result.get("analysis_complete") is True:
        state = "REVIEW_REQUIRED"
    return _lane(
        "native_worker_execution",
        state=state,
        applicable=True,
        result=result,
        basis="Signed manifest and authorization checked by the existing isolated Docker worker engine.",
        next_action=action
        if error
        else "Inspect native gaps and repairs; obtain independent agent review for this run before release.",
    )


def _candidate_inventory_lane(
    inventory: dict[str, Any], source_count: int
) -> dict[str, Any]:
    truncated = inventory.get("files_truncated")
    return _lane(
        "candidate_inventory",
        state="PASS" if source_count and not truncated else "INCOMPLETE",
        applicable=True,
        result=inventory,
        basis="Bounded relative-path inventory with byte sizes and stable digest.",
        next_action=(
            "Resolve an empty or truncated candidate inventory before trusting any lane."
            if not source_count or truncated
            else "Inventory is bound; continue through every applicable lane."
        ),
        denominator_state="MEASURED",
    )


def _architecture_health_lane(workspace: Path) -> dict[str, Any]:
    policy_path = workspace / "architecture-policy.json"
    if not policy_path.is_file():
        return _lane(
            "architecture_health",
            state="NOT_APPLICABLE",
            applicable=False,
            basis="No architecture-policy.json was supplied by this repository.",
            next_action="Add a reviewed architecture policy if architecture budgets are required.",
            denominator_state="UNDECLARED",
        )
    from .architecture_health import evaluate_architecture_health

    result, error = _safe(
        lambda: evaluate_architecture_health(workspace, policy_path, strict=True),
        error_action="Repair the architecture policy or runner error, then rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "architecture_health",
        state=_state_for_findings(result, clean=result.get("decision", "INVALID")),
        applicable=True,
        result=result,
        basis="Strict architecture budgets, file-size guards, boundaries, changelog and cadence policy.",
        next_action=result.get("next_action", "Resolve architecture findings."),
    )


def _pattern_guard_path_lane(workspace: Path, source_count: int) -> dict[str, Any]:
    review_policy = workspace / ".factory" / "review-audits.json"
    if not review_policy.is_file():
        return _lane(
            "pattern_and_guard_path_audit",
            state="NOT_MEASURED",
            applicable=bool(source_count),
            basis="No .factory/review-audits.json manifest was supplied.",
            next_action="Create a project review-audits manifest before treating pattern coverage as measured.",
            denominator_state="UNDECLARED",
        )
    from .review_audits import audit_code

    result, error = _safe(
        lambda: audit_code(workspace, ".factory/review-audits.json", tool="all"),
        error_action="Repair or bind the project review-audits manifest, then rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "pattern_and_guard_path_audit",
        state=_state_for_findings(result),
        applicable=True,
        result=result,
        basis="Manifest-bound patterns and guard paths; unlisted paths are not silently counted as clean.",
        next_action=result.get(
            "next_action", "Resolve each pattern or guard-path finding."
        ),
    )


def _non_python_security_lane(workspace: Path, languages: list[str]) -> dict[str, Any]:
    non_python = [name for name in languages if name not in {"python", "docs"}]
    receipts = _receipt_inventory(
        workspace,
        patterns=(
            "*.sarif",
            "*codeql*.json",
            "*semgrep*.json",
            "*gitleaks*.json",
            "*trivy*.json",
        ),
    )
    return _lane(
        "non_python_security",
        state="NOT_MEASURED" if non_python else "NOT_APPLICABLE",
        applicable=bool(non_python),
        result={"receipts": receipts, "verification": "UNVERIFIED"},
        basis="The bundled AST lane does not cover non-Python source languages.",
        next_action=(
            "Run and verify language-specific CodeQL/Semgrep or equivalent worker receipts for: "
            + ", ".join(non_python)
            if non_python
            else "No non-Python source was discovered."
        ),
        denominator_state="UNMEASURED" if non_python else "MEASURED",
    )


def _documentation_integrity_lane(
    documentation_count: int,
) -> dict[str, Any]:
    applicable = bool(documentation_count)
    return _lane(
        "documentation_integrity",
        state="NOT_MEASURED" if applicable else "NOT_APPLICABLE",
        applicable=applicable,
        result={"files_discovered": documentation_count},
        basis="Documentation was inventoried separately from executable source; links, examples and product claims need explicit documentation checks.",
        next_action=(
            "Run canonical-document, link, example and claim-boundary checks for the documentation set."
            if applicable
            else "No supported documentation files were discovered."
        ),
        denominator_state="UNMEASURED" if applicable else "MEASURED",
    )


def _workflow_integrity_lane(workspace: Path) -> dict[str, Any]:
    workflow_dir = workspace / ".github" / "workflows"
    if not workflow_dir.is_dir() or not list(workflow_dir.glob("*.y*ml")):
        return _lane(
            "workflow_integrity",
            state="NOT_APPLICABLE",
            applicable=False,
            basis="No GitHub workflow files were discovered.",
            next_action="Declare a CI profile if external workflow integrity is in scope.",
            denominator_state="MEASURED",
        )
    from .workflow_audit import audit_action_pins

    result, error = _safe(
        lambda: audit_action_pins(workspace),
        error_action="Repair workflow evidence and rerun.",
    )
    if error:
        result["next_action"] = error
    return _lane(
        "workflow_integrity",
        state=_state_for_findings(result),
        applicable=True,
        result=result,
        basis="GitHub workflow syntax and immutable action/container reference pinning.",
        next_action=result.get(
            "next_action", "Pin every workflow action to an immutable revision."
        ),
    )


def _requirement_runtime_lanes(
    workspace: Path, code_count: int
) -> list[dict[str, Any]]:
    from .coverage import requirement_coverage
    from .runtime_coverage import read_runtime_coverage_report

    requirement = requirement_coverage(workspace)
    applies = bool(requirement.get("applicable"))
    requirement_lane = _lane(
        "requirement_to_test_coverage",
        state=(
            "PASS"
            if requirement.get("status") == "complete"
            else "NOT_APPLICABLE"
            if not applies
            else "INCOMPLETE"
        ),
        applicable=applies,
        result=requirement,
        basis="Requirement manifest to non-hollow smoke-test mapping when an app blueprint declares it.",
        next_action=(
            "Resolve uncovered requirements."
            if applies
            else "No app requirement manifest declared."
        ),
        denominator_state="MEASURED" if applies else "UNDECLARED",
    )

    runtime = read_runtime_coverage_report(workspace, include_files=True)
    runtime_state = (
        "PASS"
        if runtime.get("state") == "OBSERVED"
        and runtime.get("receipt_status") == "VERIFIED"
        else "NOT_MEASURED"
        if runtime.get("state") == "NOT_RUN"
        else "INCOMPLETE"
    )
    runtime_lane = _lane(
        "runtime_coverage",
        state=runtime_state,
        applicable=bool(code_count),
        result=runtime,
        basis="Hash-bound Coverage.py statement and branch evidence; runtime counts do not prove correctness.",
        next_action="Run the project tests with the documented coverage profile and bind a clean receipt.",
        denominator_state=(
            "MEASURED" if runtime.get("state") == "OBSERVED" else "UNMEASURED"
        ),
    )
    return [requirement_lane, runtime_lane]


def _supply_chain_lane(workspace: Path) -> dict[str, Any]:
    manifests = _manifest_paths(workspace)
    receipts = _receipt_inventory(
        workspace,
        patterns=(
            "*.sbom.json",
            "*osv*.json",
            "*supply-chain*.json",
            "*provenance*.json",
        ),
    )
    has_manifests = bool(manifests)
    return _lane(
        "dependencies_and_supply_chain",
        state="NOT_MEASURED" if has_manifests else "NOT_APPLICABLE",
        applicable=has_manifests,
        result={
            "manifests": manifests,
            "worker_receipts": receipts,
            "verification": "UNVERIFIED",
        },
        basis="Dependency manifests were inventoried; advisory, SBOM and provenance workers require explicit receipts.",
        next_action=(
            "Generate a pinned SBOM and run OSV/advisory/provenance workers."
            if has_manifests
            else "No supported dependency manifest was discovered."
        ),
        denominator_state="UNMEASURED" if has_manifests else "MEASURED",
    )


def _deep_audit_report(
    lanes: list[dict[str, Any]], python_count: int, languages: list[str]
) -> dict[str, Any]:
    applicable = [lane for lane in lanes if lane["applicability_state"] == "APPLICABLE"]
    blocked = [lane for lane in applicable if lane["measurement_state"] == "BLOCKED"]
    unmeasured = [
        lane for lane in applicable if lane["measurement_state"] == "NOT_MEASURED"
    ]
    review_required = [
        lane for lane in applicable if lane["measurement_state"] == "REVIEW_REQUIRED"
    ]
    measured = [lane for lane in applicable if lane["measurement_state"] == "MEASURED"]
    state = (
        "BLOCKED"
        if blocked
        else "INCOMPLETE"
        if unmeasured or review_required
        else "PASS"
    )
    report = {
        "schema": SCHEMA,
        "state": state,
        "scope": {
            "root": ".",
            "python_source_limit": MAX_SECURITY_SOURCE_FILES,
            "python_source_discovered": python_count,
            "languages": languages,
        },
        "lanes": lanes,
        "coverage": {
            "applicable": len(applicable),
            "measured": len(measured),
            "blocked": len(blocked),
            "unmeasured": len(unmeasured),
            "review_required": len(review_required),
            "not_applicable": len(lanes) - len(applicable),
            "audit_rate": round(len(measured) / len(applicable), 4)
            if applicable
            else None,
        },
        "claim_boundary": "Full local orchestration of available evidence lanes; not a penetration test, runtime certification, or release approval.",
        "next_actions": [
            lane["next_action"] for lane in [*blocked, *unmeasured, *review_required]
        ],
    }
    report["audit_sha256"] = _digest(
        {key: value for key, value in report.items() if key != "audit_sha256"}
    )
    return report


def run_deep_repository_audit(
    root: Path,
    inventory: dict[str, Any],
    *,
    tenant_contract: str = ".factory/tenant-read-contract.json",
    worker_config: str | None = None,
) -> dict[str, Any]:
    """Run all applicable local audit lanes and return an evidence map."""
    workspace = Path(root).resolve()
    file_types = inventory.get("file_types", {})
    python_count = int(file_types.get("python", 0))
    source_count = inventory.get("files_discovered", 0)
    code_count = sum(
        int(count) for name, count in file_types.items() if name not in {"docs"}
    )
    languages = [name for name, count in file_types.items() if count]
    lanes = [
        _candidate_inventory_lane(inventory, source_count),
        _architecture_health_lane(workspace),
        _pattern_guard_path_lane(workspace, source_count),
        *_python_audit_lanes(workspace, python_count, tenant_contract),
        _non_python_security_lane(workspace, languages),
        _documentation_integrity_lane(int(file_types.get("docs", 0))),
        _workflow_integrity_lane(workspace),
        *_requirement_runtime_lanes(workspace, code_count),
        _supply_chain_lane(workspace),
        _native_worker_lane(workspace, worker_config, bool(code_count)),
    ]
    return _deep_audit_report(lanes, python_count, languages)


def _scan_security_and_deep_audit(
    workspace: Path,
    inventory: dict[str, Any],
    deep: bool,
    worker_config: str | None,
) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    if not deep:
        return (
            {
                "state": "NOT_RUN",
                "findings": [],
                "audit_coverage": {"measurement_state": "not_run"},
                "action_summary": "Use factory scan --deep to orchestrate local audit lanes and identify missing evidence.",
            },
            None,
            None,
        )
    try:
        deep_audit = run_deep_repository_audit(
            workspace, inventory, worker_config=worker_config
        )
        static_security = next(
            (
                lane.get("result") or {}
                for lane in deep_audit["lanes"]
                if lane["measurement_id"] == "python_ast_security"
            ),
            {
                "state": "NOT_RUN",
                "findings": [],
                "audit_coverage": {"measurement_state": "not_run"},
            },
        )
        return static_security, deep_audit, None
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        return (
            {
                "state": "INVALID",
                "findings": [],
                "audit_coverage": {"measurement_state": "invalid"},
            },
            None,
            "Analyzer failed: " + type(exc).__name__,
        )


def _repo_scan_state(
    deep_audit: dict[str, Any] | None,
    static_security: dict[str, Any],
    deep: bool,
    inventory: dict[str, Any],
) -> tuple[str, str]:
    if deep_audit is not None:
        state = deep_audit["state"]
        return state, state
    findings = static_security.get("findings", [])
    if static_security.get("state") in {"BLOCKED", "INVALID"} or findings:
        return "BLOCKED", "BLOCKED"
    if not deep or inventory["files_discovered"] == 0:
        return "INCOMPLETE", "INCOMPLETE"
    return "ASSESSED_STATIC_ONLY", "INCOMPLETE"


def run_repo_scan(
    root: Path, *, deep: bool = False, worker_config: str | None = None
) -> dict[str, Any]:
    """Run a zero-config inventory and, when requested, every local audit lane.

    This is intentionally an honest first verdict: static evidence can block a
    workspace, but a clean result remains incomplete until the project supplies
    its tenant contract and runtime/test evidence.
    """
    if worker_config is not None and not deep:
        raise ValueError("--worker-config requires --deep")
    workspace = Path(root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    inventory = _workspace_inventory(workspace)
    static_security, deep_audit, security_error = _scan_security_and_deep_audit(
        workspace, inventory, deep, worker_config
    )
    state, verdict = _repo_scan_state(deep_audit, static_security, deep, inventory)
    result = {
        "schema": "factory.repo-scan.v1",
        "state": state,
        "verdict": verdict,
        "assessment": inventory,
        "static_security": static_security,
        "deep_audit": deep_audit,
        "evidence_limits": [
            "Inventory and Python AST findings are local observations, not runtime coverage or certification.",
            "The default scan is intentionally fast; --deep runs all applicable local audit lanes and reports every unmeasured lane.",
            "A missing tenant-read contract keeps the Python security lane incomplete even when no static finding is raised.",
            "Tests, dependency analysis, runtime behavior, and deployment behavior require explicit project evidence and are not inferred.",
            "Deep orchestration is not a penetration test, runtime certification, or release approval.",
        ],
        "next_actions": (
            deep_audit["next_actions"]
            if deep_audit is not None
            else [
                "Add .factory/tenant-read-contract.json for every tenant-scoped read, or explicitly declare an empty set.",
                "Run every applicable worker lane and bind clean, commit-scoped receipts before treating the result as complete.",
                "Review every finding and every unmeasured lane before treating the result as a merge or release decision.",
            ]
        ),
    }
    if security_error:
        result["static_security_error"] = security_error
    result["scan_sha256"] = _sha(result)
    return result


def run_first_proof(
    root: Path, *, out_dir: Path | None = None, observed_at: datetime | None = None
) -> dict[str, Any]:
    """Run an explicit sandbox proof that demonstrates a hollow negative check."""
    workspace = Path(root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    instant = _utc(observed_at)
    run_id = instant.strftime("first-proof-%Y%m%dT%H%M%SZ")
    destination = _workspace_path(
        workspace, out_dir or Path(".factory/adoption/first-proof") / run_id
    )
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "factory.e2e_proof_manifest.v1",
        "id": run_id,
        "approval": {"state": "approved", "approved_by": "local-first-proof-user"},
        "working_directory": ".",
        "timeout_seconds": 30,
        "network_egress": "not_granted",
        "positive": {"argv": [sys.executable, "-c", "raise SystemExit(0)"]},
        "negative": {"argv": [sys.executable, "-c", "raise SystemExit(0)"]},
        "artifact_paths": [],
    }
    manifest_path = destination / "first-proof.manifest.json"
    _atomic_json(manifest_path, manifest)
    proof = verify_e2e_proof(workspace, manifest_path)
    if proof["marker"] != "HOLLOW_E2E_TEST":
        raise AdoptionError(
            "E_FIRST_PROOF_UNEXPECTED",
            "sandbox first proof did not detect the deliberately hollow check",
        )
    proof_artifacts = write_e2e_proof_artifacts(proof, destination / "evidence")
    card_artifacts = write_proof_card(proof, destination / "share")
    for milestone in (
        "first_proof_completed",
        "proof_receipt_saved",
        "proof_card_saved",
    ):
        evidence = (
            proof["receipt_sha256"]
            if milestone != "proof_card_saved"
            else card_artifacts["card"]["card_sha256"]
        )
        record_adoption_event(
            workspace, milestone, evidence_sha256=evidence, observed_at=instant
        )
    assessment = _workspace_inventory(workspace)
    core = {
        "schema": FIRST_PROOF_SCHEMA,
        "observed_at": _iso(instant),
        "demo": True,
        "marker": "HOLLOW_TEST_DETECTED",
        "assessment": assessment,
        "proof_receipt_sha256": proof["receipt_sha256"],
        "proof_card_sha256": card_artifacts["card"]["card_sha256"],
        "scope_limits": [
            "The sandbox demonstration is separate from the bounded workspace inventory; it does not execute or certify the caller's project.",
            "The inventory records only relative file names and byte sizes. It is not a source, runtime, dependency, or security assessment.",
            "The generated Proof Card omits commands, paths, repository name, prompts, logs, and user identity.",
            "No network, approval, merge, release, publication, deployment, signing, credential, connector, or message authority is granted.",
        ],
    }
    activation = {**core, "receipt_sha256": _sha(core)}
    activation_path = _atomic_json(destination / "activation.json", activation)
    return {
        "activation": activation,
        "activation_path": str(activation_path),
        "proof": {key: value for key, value in proof.items() if key != "_captures"},
        "proof_artifacts": proof_artifacts,
        "proof_card": card_artifacts,
        "adoption_status": adoption_status(workspace),
    }
