"""Shared machine-readable provenance envelope for FactoryLine itself."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from ._build_provenance import SOURCE_COMMIT


class NativeOraclePayload(str):
    """Native in-memory cache checksum; not signing or invocation authority."""

    __slots__ = ("_seal",)

    def __new__(cls, text, key):
        value = super().__new__(cls, text)
        object.__setattr__(
            value, "_seal", (key, hashlib.sha256(text.encode("utf-8")).digest())
        )
        return value

    def __setattr__(self, *args):
        raise AttributeError("native cache metadata is immutable")

    __delattr__ = __setattr__

    def valid(self, key):
        return type(self) is NativeOraclePayload and getattr(self, "_seal", None) == (
            key,
            hashlib.sha256(self.encode("utf-8")).digest(),
        )


def _source_commit(module_dir: Path) -> str | None:
    source_root = module_dir.parent
    manifest = source_root / "pyproject.toml"
    if not (source_root / ".git").exists() or not manifest.exists():
        return None
    if 'name = "factoryline-code-factory"' not in manifest.read_text(encoding="utf-8"):
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or dirty.returncode != 0 or dirty.stdout.strip():
        return None
    return result.stdout.strip()


def _build_hash(module_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(module_dir.rglob("*.py")):
        digest.update(path.relative_to(module_dir).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def provenance() -> dict:
    """Return package, source-commit, and build-hash provenance for this installation."""
    module_dir = Path(__file__).resolve().parent
    direct_url = None
    origin = "unknown"
    try:
        distribution = importlib.metadata.distribution("factoryline-code-factory")
        text = distribution.read_text("direct_url.json")
        if text:
            direct_url = json.loads(text).get("url")
            origin = "direct-url"
        else:
            origin = "site-packages"
    except importlib.metadata.PackageNotFoundError:
        origin = "source-tree"
    commit = _source_commit(module_dir) or SOURCE_COMMIT
    build_hash = _build_hash(module_dir)
    return {
        "schema": "factoryline.provenance.v1",
        "package": "factoryline-code-factory",
        "version": __version__,
        "source_commit": commit,
        "build_hash": build_hash,
        "install_origin": origin,
        "direct_url": direct_url,
        "python": sys.version.split()[0],
        "runtime": {
            "python": sys.version.split()[0],
            "implementation": sys.implementation.name,
        },
        "receipt_schema": "factory.receipt.v2",
        "identity_complete": bool(commit and build_hash),
    }


def _emit_version(as_json: bool) -> int:
    """Print the same provenance envelope as the full CLI."""
    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


_QUICK_HELP = """Code Factory - review your code with less setup.

Start here:
  Scan my code       factory scan --root .
  Open dashboard     factory studio --root .
  Get guidance       factory guide

Next steps:
  More scan options  factory scan --help
  Check setup        factory doctor --strict --json
  All commands       factory --help-all

Scan reads eligible Python source without running your project.
Review findings, verify repairs with your tests, then rerun affected checks.
Keep pytest, mutation testing, CodeQL and Semgrep in your existing CI.
Missing evidence means INCOMPLETE; a scan is not release approval.
No adoption, signing keys or tenant configuration needed for a basic scan.
"""


def main(argv=None) -> int:
    """Show quick help and version probes without loading the command registry."""
    values = list(sys.argv[1:] if argv is None else argv)
    if values in (["--help"], ["-h"]):
        print(_QUICK_HELP, end="")
        return 0
    if values == ["--help-all"]:
        values = ["--help"]
    if values and values[0] == "--version":
        return _emit_version("--json" in values)
    started = time.monotonic()
    from .ops_telemetry import _measure_phase, _phase_telemetry

    with _phase_telemetry(started):
        with _measure_phase("entrypoint_startup"):
            from .cli import main as cli_main
        return cli_main(values)


def public_symbolic_findings(relative, node, findings, integrity):
    """Attach native source proofs; preserve the original primitive observation."""
    import hashlib
    import json

    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    profile = getattr(module, "_fixed_program_workspace", {})
    if (
        not isinstance(context, tuple)
        or len(context) != 2
        or not isinstance(profile, dict)
    ):
        return findings
    root, sources = context
    raw = sources.get(root / relative) if isinstance(sources, dict) else None
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return findings
    for finding in findings:
        facts = finding.get("facts", {})
        if (
            finding.get("code") != "SECURITY_HARDCODED_SECRET"
            or facts.get("role_candidate") != "symbolic_enum_identifier"
        ):
            continue
        evidence = profile.get("credential_consumers", {}).get(
            f"{node.lineno}:{facts.get('name')}"
        )
        if not isinstance(evidence, dict) or not evidence.get("consumers"):
            continue
        finding["facts"] = {
            **facts,
            **evidence,
            "schema": "factory.public-symbolic-identifier.v1",
            "disposition": "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER",
            "source_path": relative,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "workspace_sources_sha256": profile.get("sources_sha256"),
            "declaration_span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "runtime_assurance": "INCOMPLETE",
            "target_execution": "not_performed",
            "evidence_scope": "source-snapshot-publication-boundary",
            "downstream_consumer_security": "UNASSESSED",
        }
        finding["facts"]["proof_facts_sha256"] = hashlib.sha256(
            json.dumps(finding["facts"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    return findings


def public_symbolic_binding(finding, sources, bindings):
    """Verify retained evidence integrity, without granting execution authority."""
    import hashlib
    import json
    from .review_integrity import _valid_source_span

    facts = finding.get("facts", {})
    consumers, profiles = facts.get("consumers"), facts.get("source_profiles")
    span = facts.get("declaration_span")
    if not (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and facts.get("schema") == "factory.public-symbolic-identifier.v1"
        and facts.get("disposition") == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
        and facts.get("role_candidate") == "symbolic_enum_identifier"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("target_execution") == "not_performed"
        and facts.get("source_path") == finding.get("path")
        and facts.get("source_sha256") == bindings.get(finding.get("path"))
        and _valid_source_span(span)
        and span[:2] == [finding.get("line"), finding.get("column")]
        and isinstance(consumers, list)
        and 0 < len(consumers) <= 200_000
        and isinstance(profiles, list)
        and len(profiles) <= 2000
    ):
        return False
    if any(
        not isinstance(row, dict)
        or row.get("source_sha256") != bindings.get(row.get("path"))
        or type(row.get("line")) is not int
        or row["line"] < 1
        for row in consumers
    ):
        return False
    if any(
        not isinstance(row, dict)
        or row.get("entrypoint_sha256") != bindings.get(row.get("entrypoint"))
        or row.get("module_sha256") != bindings.get(row.get("source_path"))
        or row.get("runtime_assurance") != "INCOMPLETE"
        for row in profiles
    ):
        return False
    digest = hashlib.sha256(
        json.dumps(
            {"consumers": consumers, "source_profiles": profiles},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    workspace = hashlib.sha256(
        json.dumps(
            sorted((row["path"], row["sha256"]) for row in sources),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    proof = hashlib.sha256(
        json.dumps(
            {key: value for key, value in facts.items() if key != "proof_facts_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return (
        facts.get("consumer_evidence_sha256") == digest
        and facts.get("workspace_sources_sha256") == workspace
        and facts.get("proof_facts_sha256") == proof
    )


def bind_public_symbolic_consumers(
    root, snapshots, imports, contexts, source_bytes, inventory, integrity
):
    from . import review_audits as audit
    from .runtime_audit_integrity import _LiteralConsumers
    import hashlib
    import json

    for context in contexts.values():
        context["credential_consumers"] = {}
        context["finite_template_inputs"] = {}
    try:
        if not isinstance(inventory, dict) or set(contexts) != set(inventory):
            return
        graph = _LiteralConsumers(
            root,
            snapshots,
            {path: dict(view) for path, view in imports.items()},
            audit,
            integrity,
            source_bytes=source_bytes,
            inventory=inventory,
        )
        witnesses = graph.witnesses()
        templates = graph.finite_template_inputs()
        if graph.snapshot_complete is not True:
            return
        if not graph.complete:
            witnesses = {}
        workspace = hashlib.sha256(
            json.dumps(
                sorted(
                    (path.relative_to(root).as_posix(), digest)
                    for path, digest in inventory.items()
                ),
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        for (path, line, column), facts in templates.items():
            evidence = {**facts, "workspace_sources_sha256": workspace}
            evidence["proof_facts_sha256"] = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            contexts[path]["finite_template_inputs"][f"{line}:{column}"] = evidence
        profiles = [
            {"source_path": path.relative_to(root).as_posix(), **profile}
            for path, profile in sorted(getattr(graph, "source_profiles", {}).items())
        ]
        for (path, line, member), consumers in witnesses.items():
            evidence = {"consumers": consumers, "source_profiles": profiles}
            digest = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            contexts[path]["credential_consumers"][f"{line}:{member}"] = {
                **evidence,
                "consumer_evidence_sha256": digest,
            }
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
        MemoryError,
    ):
        for context in contexts.values():
            context["credential_consumers"] = {}
            context["finite_template_inputs"] = {}


def finite_template_witness(relative, node, call_name, root, sources, profile):
    """Read native finite-input evidence; never evaluate generated target code."""
    import ast

    if call_name not in {"exec", "builtins.exec"} or not isinstance(node, ast.Call):
        return {}
    ledger = profile.get("finite_template_inputs", {})
    if not isinstance(ledger, dict):
        return {}
    facts = ledger.get(f"{node.lineno}:{node.col_offset}")
    if not isinstance(facts, dict) or facts.get("source_path") != relative:
        return {}
    if facts.get("call_span") != [
        node.lineno,
        node.col_offset,
        node.end_lineno,
        node.end_col_offset,
    ]:
        return {}
    for path_key, hash_key in (
        ("source_path", "source_sha256"),
        ("capture_path", "capture_sha256"),
        ("domain_path", "domain_sha256"),
    ):
        name = facts.get(path_key)
        raw = sources.get(root / name) if isinstance(name, str) else None
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != facts.get(
            hash_key
        ):
            return {}
    return dict(facts)


def finite_template_binding(finding, sources, bindings):
    """Check the stated input-closure envelope, not runtime harmlessness."""
    import re
    from .review_integrity import _valid_source_span

    facts = finding.get("facts", {})
    if not isinstance(facts, dict):
        return False
    span, template = facts.get("call_span"), facts.get("template_span")
    programs, size = facts.get("program_hashes"), facts.get("domain_size")
    if not (
        finding.get("code") == "SECURITY_DYNAMIC_EXECUTION"
        and facts.get("schema") == "factory.finite-template-input.v1"
        and facts.get("disposition") == "PROVEN_FINITE_TEMPLATE_INPUT"
        and facts.get("scope_profile") == "pytest-collection-finite-parameter"
        and facts.get("hypothesis") == "ARGUMENT_CODE_INJECTION"
        and facts.get("input_effect") == "FINITE_SOURCE_TEMPLATE_INPUT"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("execution_effects") == "UNASSESSED"
        and facts.get("target_execution") == "not_performed"
        and facts.get("source_path") == finding.get("path")
        and facts.get("capture_path") == finding.get("path")
        and _valid_source_span(span)
        and _valid_source_span(template)
        and span[:2] == [finding.get("line"), finding.get("column")]
        and tuple(span[:2])
        <= tuple(template[:2])
        <= tuple(template[2:])
        <= tuple(span[2:])
        and _valid_source_span(facts.get("capture_span"))
        and tuple(facts["capture_span"][2:]) <= tuple(span[:2])
        and _valid_source_span(facts.get("domain_span"))
        and type(size) is int
        and 1 <= size <= 64
        and isinstance(programs, list)
        and len(programs) == size
        and all(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in programs
        )
        and isinstance(facts.get("template_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", facts["template_sha256"])
    ):
        return False
    for path_key, hash_key in (
        ("source_path", "source_sha256"),
        ("capture_path", "capture_sha256"),
        ("domain_path", "domain_sha256"),
    ):
        name = facts.get(path_key)
        if (
            not isinstance(name, str)
            or sum(row["path"] == name for row in sources) != 1
        ):
            return False
        if not isinstance(facts.get(hash_key), str) or facts[hash_key] != bindings.get(
            name
        ):
            return False
    workspace = hashlib.sha256(
        json.dumps(
            sorted((row["path"], row["sha256"]) for row in sources),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    proof = hashlib.sha256(
        json.dumps(
            {key: value for key, value in facts.items() if key != "proof_facts_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return (
        facts.get("workspace_sources_sha256") == workspace
        and facts.get("proof_facts_sha256") == proof
    )
