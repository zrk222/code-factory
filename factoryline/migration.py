"""Deterministic migration readiness and repository context receipts."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import tempfile

from .failure_guidance import explain_failure
from .repository_history import RepositoryHistoryError, git_lines


READINESS_INPUT_SCHEMA = "factory.migration.readiness-input.v1"
READINESS_SCHEMA = "factory.migration.readiness.v1"
CONTEXT_SCHEMA = "factory.repository-context.v1"
READINESS_CATEGORIES = (
    "unit", "integration", "e2e", "lint_type", "architecture",
    "coverage_fuzz", "environment", "telemetry_security",
)


class MigrationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _load(path: Path, schema: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError("MIGRATION_ARTIFACT_INVALID", f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise MigrationError("MIGRATION_SCHEMA_INVALID", f"expected schema {schema}: {path}")
    return value


def _contained(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise MigrationError("MIGRATION_EVIDENCE_OUTSIDE_ROOT", f"evidence must be beneath {root.resolve()}: {resolved}") from exc
    return resolved


def _atomic_json(path: Path, value: dict[str, Any], *, force: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == payload:
        return path
    if path.exists() and not force:
        raise MigrationError("MIGRATION_ARTIFACT_EXISTS", f"refusing to replace {path}; pass --force after review")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with open(fd, "w", encoding="utf-8", closefd=True) as stream:
            stream.write(payload)
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


def _argv_valid(command: object) -> bool:
    return isinstance(command, list) and bool(command) and all(
        isinstance(item, str) and item.strip() for item in command
    )


def _bound_check_evidence(root: Path, category: str, values: object) -> tuple[bool, list[dict[str, Any]]]:
    if not isinstance(values, list) or not values:
        return False, []
    bound = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            return False, []
        path = _contained(root, value)
        if not path.is_file():
            return False, []
        bound.append({"path": str(path), "sha256": _sha_path(path), "bytes": path.stat().st_size, "category": category})
    return True, bound


def _assess_check(root: Path, check: object) -> tuple[str, bool, list[dict[str, Any]]]:
    if not isinstance(check, dict) or check.get("category") not in READINESS_CATEGORIES:
        raise MigrationError("MIGRATION_READINESS_INPUT", f"every check category must be one of {', '.join(READINESS_CATEGORIES)}")
    category = check["category"]
    if not _argv_valid(check.get("command")):
        raise MigrationError("MIGRATION_READINESS_INPUT", f"{category} must declare an argv command")
    proof_ok, evidence = _bound_check_evidence(root, category, check.get("evidence"))
    proof_ok = proof_ok and check.get("passed") is True
    if category == "environment":
        runs = check.get("reproducibility_runs")
        proof_ok = proof_ok and isinstance(runs, dict) and runs.get("total", 0) >= 2 and runs.get("passed") == runs.get("total")
    return category, proof_ok, evidence if proof_ok else []


def assess_migration_readiness(manifest_path: Path, root: Path, *, force: bool = False) -> dict[str, Any]:
    """Separate registered checks from executable, hash-bound proof."""
    root = Path(root).resolve()
    manifest = _load(manifest_path, READINESS_INPUT_SCHEMA)
    checks = manifest.get("checks")
    if not isinstance(checks, list) or not checks:
        raise MigrationError("MIGRATION_READINESS_INPUT", "checks must be a non-empty list")
    registered: set[str] = set()
    verified: set[str] = set()
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    for check in checks:
        category, proof_ok, bound = _assess_check(root, check)
        registered.add(category)
        if proof_ok:
            verified.add(category)
            evidence.extend(bound)
        else:
            findings.append({"category": category, "status": "unverified", "next_action": "Run the declared command and attach its local receipt; environment proof requires at least two clean runs."})
    missing = [item for item in READINESS_CATEGORIES if item not in registered]
    unverified = [item for item in READINESS_CATEGORIES if item not in verified]
    core = {
        "schema": READINESS_SCHEMA,
        "project": str(manifest.get("project") or root.name),
        "source": {"path": str(Path(manifest_path).resolve()), "sha256": _sha_path(Path(manifest_path))},
        "categories": list(READINESS_CATEGORIES),
        "registered_categories": sorted(registered),
        "verified_categories": sorted(verified),
        "missing_categories": missing,
        "unverified_categories": unverified,
        "lane_registration_pct": round(len(registered) / len(READINESS_CATEGORIES) * 100, 2),
        "executable_proof_pct": round(len(verified) / len(READINESS_CATEGORIES) * 100, 2),
        "ready": not unverified,
        "evidence": evidence,
        "findings": findings,
        "markers": ["MIGRATION_REGISTRATION_SEPARATE", "MIGRATION_EXECUTABLE_PROOF_SEPARATE"] + (["MIGRATION_AGENT_READY"] if not unverified else ["MIGRATION_AGENT_NOT_READY"]),
        "authority": "readiness evidence only; no migration execution or promotion authority",
    }
    receipt = {**core, "receipt_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    out = root / ".factory" / "migration" / "readiness.json"
    _atomic_json(out, receipt, force=force)
    return {**receipt, "path": str(out)}


def verify_migration_readiness(receipt_path: Path) -> dict[str, Any]:
    receipt = _load(receipt_path, READINESS_SCHEMA)
    core = {key: value for key, value in receipt.items() if key not in {"receipt_sha256", "generated_at", "path"}}
    errors: list[str] = []
    if _sha_bytes(_canonical(core)) != receipt.get("receipt_sha256"):
        errors.append("readiness receipt hash mismatch")
    for item in receipt.get("evidence", []):
        path = Path(item["path"])
        if not path.is_file() or _sha_path(path) != item["sha256"]:
            errors.append(f"readiness evidence drift: {path}")
    valid = not errors
    return {
        "schema": "factory.migration.readiness-verification.v1",
        "valid": valid,
        "ready": valid and receipt.get("ready") is True,
        "marker": "MIGRATION_READINESS_VERIFIED" if valid else "MIGRATION_READINESS_DRIFT",
        "errors": errors,
    }


def _git(root: Path, *args: str) -> list[str]:
    try:
        return git_lines(root, *args)
    except RepositoryHistoryError as exc:
        raise MigrationError("REPOSITORY_CONTEXT_GIT_REQUIRED", str(exc)) from exc


def _adr_rows(root: Path, tracked: list[str]) -> list[tuple[str, str]]:
    rows = []
    for name in tracked:
        if name.lower().startswith("adr/") and name.lower().endswith(".md"):
            path = root / name
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            title = next((line.lstrip("# ").strip() for line in lines if line.startswith("#")), path.stem)
            rows.append((name, title))
    return rows


def _component_origins(root: Path, top: Counter) -> list[dict[str, str]]:
    origins = []
    for component, _count in top.most_common(12):
        rows = _git(root, "log", "--reverse", "--date=short", "--pretty=format:%h|%ad|%an|%s", "--", component)
        if rows:
            commit, date, author, subject = rows[0].split("|", 3)
            origins.append({"component": component, "commit": commit, "date": date, "author": author, "subject": subject})
    return origins


def _repository_facts(root: Path) -> dict[str, Any]:
    tracked = _git(root, "ls-files")
    manifests = [item for item in tracked if Path(item).name in {"pyproject.toml", "package.json", "Cargo.toml", "go.mod", "build.gradle.kts", "pom.xml"} or Path(item).suffix.lower() == ".sln"]
    top = Counter(Path(item).parts[0] for item in tracked if Path(item).parts)
    return {
        "tracked": tracked,
        "extensions": Counter((Path(item).suffix.lower() or "[none]") for item in tracked),
        "top": top,
        "adrs": _adr_rows(root, tracked),
        "history": _git(root, "log", "-n", "25", "--date=short", "--pretty=format:%h|%ad|%s"),
        "contributors": _git(root, "shortlog", "-sne", "HEAD"),
        "manifests": manifests,
        "architecture_shape": "monorepo" if len({Path(item).parent.as_posix() for item in manifests}) > 1 else "single-package repository",
        "origins": _component_origins(root, top),
    }


def _autowiki_text(facts: dict[str, Any]) -> str:
    return (
        "# AutoWiki\n\nGenerated from Git-tracked files only. It is a human onboarding map, not behavioral proof.\n\n"
        f"## Canonical architecture\n\n- Shape: **{facts['architecture_shape']}**\n- Tracked files: **{len(facts['tracked'])}**\n- Package manifests: **{len(facts['manifests'])}**\n\n"
        "## Start here\n\n1. Read the root README and contributor instructions.\n2. Review the architecture decisions below.\n3. Enter the component that owns your change.\n4. Run its declared tests before editing.\n5. Read Lore for the human history behind the current structure.\n\n"
        "## Components\n\n" + "\n".join(f"- `{name}`: {count} tracked files" for name, count in facts["top"].most_common(20))
        + "\n\n## File types\n\n" + "\n".join(f"- `{name}`: {count}" for name, count in facts["extensions"].most_common(30))
        + "\n\n## Architecture decisions\n\n" + ("\n".join(f"- [{title}](../../{path})" for path, title in facts["adrs"]) or "- None tracked") + "\n"
    )


def _lore_text(facts: dict[str, Any]) -> str:
    return (
        "# Repository Lore\n\nA factual celebration of the people and decisions in Git history. It does not infer private reasoning.\n\n"
        "## People\n\n" + ("\n".join(f"- {row.strip()}" for row in facts["contributors"]) or "- No contributor records")
        + "\n\n## Component origins\n\n" + ("\n".join(
            f"- `{item['component']}` began at `{item['commit']}` on {item['date']} with {item['author']}: {item['subject']}"
            for item in facts["origins"]
        ) or "- No component origin records")
        + "\n\n## Decisions\n\n" + ("\n".join(f"- `{path}`: {title}" for path, title in facts["adrs"]) or "- None tracked")
        + "\n\n## Recent history\n\n" + ("\n".join(f"- `{row.split('|', 2)[0]}` {row.split('|', 2)[1]}: {row.split('|', 2)[2]}" for row in facts["history"]) or "- No commits") + "\n"
    )


def _video_payload() -> dict[str, Any]:
    return {
        "schema": "factory.repository-video-plan.v1",
        "status": "planned",
        "duration_seconds": 300,
        "allowed_duration_seconds": {"minimum": 240, "maximum": 360},
        "renderer": "remotion",
        "narration": {"provider": "external_authorized_tts", "synchronized": True, "generated": False},
        "scenes": [
            {"id": "shape", "seconds": 45, "source": "AUTOWIKI.md#canonical-architecture"},
            {"id": "components", "seconds": 60, "source": "AUTOWIKI.md#components"},
            {"id": "decisions", "seconds": 55, "source": "AUTOWIKI.md#architecture-decisions"},
            {"id": "people", "seconds": 50, "source": "LORE.md#people"},
            {"id": "history", "seconds": 55, "source": "LORE.md#recent-history"},
            {"id": "first-change", "seconds": 35, "source": "AUTOWIKI.md#start-here"},
        ],
        "claim_boundary": "A plan is not rendered video; media remains ungenerated until an authorized renderer and TTS provider succeed.",
    }


def _write_context_text(autowiki: Path, lore: Path, facts: dict[str, Any], force: bool) -> None:
    autowiki.parent.mkdir(parents=True, exist_ok=True)
    values = ((autowiki, _autowiki_text(facts)), (lore, _lore_text(facts)))
    for path, payload in values:
        if path.exists() and not force and path.read_text(encoding="utf-8") != payload:
            raise MigrationError("MIGRATION_ARTIFACT_EXISTS", f"refusing to replace {path}; pass --force after review")
        path.write_text(payload, encoding="utf-8")


def build_repository_context(root: Path, *, force: bool = False) -> dict[str, Any]:
    """Build compact AutoWiki and Lore files from tracked facts only."""
    root = Path(root).resolve()
    facts = _repository_facts(root)
    context_dir = root / ".factory" / "context"
    autowiki = context_dir / "AUTOWIKI.md"
    lore = context_dir / "LORE.md"
    video_plan = context_dir / "video-overview.json"
    _write_context_text(autowiki, lore, facts, force)
    _atomic_json(video_plan, _video_payload(), force=force)
    core = {
        "schema": CONTEXT_SCHEMA,
        "tracked_files": len(facts["tracked"]),
        "artifacts": [
            {"path": str(autowiki), "sha256": _sha_path(autowiki)},
            {"path": str(lore), "sha256": _sha_path(lore)},
            {"path": str(video_plan), "sha256": _sha_path(video_plan)},
        ],
        "architecture_shape": facts["architecture_shape"],
        "contributors": len(facts["contributors"]),
        "component_origins": len(facts["origins"]),
        "video_overview": {"status": "planned", "duration_seconds": 300, "path": str(video_plan)},
        "source": {"git_head": _git(root, "rev-parse", "HEAD")[0]},
        "markers": ["AUTOWIKI_TRACKED_FACTS_ONLY", "LORE_ADR_GIT_BOUND", "REPOSITORY_CONTEXT_NO_HIDDEN_REASONING"],
        "authority": "context generation only; no source modification or promotion authority",
    }
    receipt = {**core, "receipt_sha256": _sha_bytes(_canonical(core)), "generated_at": _now()}
    path = context_dir / "context-receipt.json"
    _atomic_json(path, receipt, force=force)
    return {**receipt, "path": str(path)}


def verify_repository_context(receipt_path: Path) -> dict[str, Any]:
    receipt = _load(receipt_path, CONTEXT_SCHEMA)
    core = {key: value for key, value in receipt.items() if key not in {"receipt_sha256", "generated_at", "path"}}
    errors = []
    if _sha_bytes(_canonical(core)) != receipt.get("receipt_sha256"):
        errors.append("context receipt hash mismatch")
    for item in receipt.get("artifacts", []):
        path = Path(item["path"])
        if not path.is_file() or _sha_path(path) != item["sha256"]:
            errors.append(f"context artifact drift: {path}")
    return {
        "schema": "factory.repository-context.verification.v1",
        "valid": not errors,
        "marker": "REPOSITORY_CONTEXT_VERIFIED" if not errors else "REPOSITORY_CONTEXT_DRIFT",
        "errors": errors,
    }
