"""Deterministic deep-audit decisions over externally bound analyzer evidence.

The execute entry point verifies signatures and re-normalizes reports itself.
The pure evaluator does not authenticate caller-supplied dictionaries. Neither
legacy entry point executes an analyzer or grants approval or release rights.
The explicit scan entry point runs authorized, isolated adapter containers.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import islice
from pathlib import Path
import stat
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone

from .deep_audit_contract import verify_deep_audit_plan
from .deep_audit_io import LIMIT, digest, local_file, strict_json
from .deep_audit_sarif import normalize_sarif
from .runtime_audit_common import RuntimeAuditError, canonical_bytes


def _execution_gap(code: str, action: str, path: str = ".") -> dict:
    return {"code": code, "path": path, "action": action}


def _obligation_gaps(obligations: list[dict], files: dict[str, dict]) -> list[dict]:
    gaps = []
    for obligation in obligations:
        if not set(obligation["paths"] + obligation["requirements"]) <= files.keys():
            gaps.append(
                _execution_gap(
                    "UNBOUND_OBLIGATION",
                    "Bind every obligation and requirement to inventoried source.",
                    obligation["id"],
                )
            )
        for challenge in obligation["challenges"]:
            if (
                files.get(challenge["fixture_path"], {}).get("sha256")
                != challenge["fixture_sha256"]
            ):
                gaps.append(
                    _execution_gap(
                        "UNBOUND_CHALLENGE",
                        "Bind the challenge fixture bytes to the inventoried candidate.",
                        challenge["fixture_path"],
                    )
                )
    return gaps


def _language_lanes(plan: dict) -> dict[str, set[str]]:
    by_family = {}
    for lane in plan["lanes"]:
        by_family.setdefault(lane["family"], set()).update(lane["languages"])
    return by_family


def _source_families(language: str) -> set[str]:
    families = {"secrets"}
    if language == "dependency":
        families.add("dependencies")
    elif language == "configuration":
        families.add("configuration")
    elif language != "data":
        families.update({"static", "runtime", "fuzz"})
    return families


def _source_gaps(
    files: dict[str, dict],
    language_lanes: dict[str, set[str]],
    obligations: list[dict],
) -> list[dict]:
    gaps = []
    for path, item in files.items():
        language = item["language"]
        for family in sorted(_source_families(language)):
            if language not in language_lanes.get(family, set()) or not any(
                obligation["family"] == family and path in obligation["paths"]
                for obligation in obligations
            ):
                gaps.append(
                    _execution_gap(
                        "UNCOVERED_SOURCE",
                        f"Add a {family} analyzer and source-bound obligation for {language}.",
                        path,
                    )
                )
    return gaps


def _dependency_scope_gap(plan: dict) -> list[dict]:
    engines = {lane["engine"] for lane in plan["lanes"]}
    if {"syft", "osv"} <= engines:
        return []
    return [
        _execution_gap(
            "DEPENDENCY_DEPTH",
            "Declare both SBOM inventory (Syft) and vulnerability analysis (OSV).",
        )
    ]


def _scope_gaps(plan: dict, inventory: dict) -> list:
    """Source-derived obligations cannot be removed by a narrow PRD or lane."""
    files = {item["path"]: item for item in inventory["files"]}
    obligations = plan["obligations"]
    gaps = _obligation_gaps(obligations, files)
    gaps.extend(_source_gaps(files, _language_lanes(plan), obligations))
    gaps.extend(_dependency_scope_gap(plan))
    return gaps


def _event(directory: Path, state: dict, kind: str, details: dict, emit=None) -> None:
    from .deep_audit_io import write_run_json

    sequence = state.get("sequence", 0) + 1
    event = {
        "sequence": sequence,
        "run_id": state["run_id"],
        "kind": kind,
        "at": datetime.now(timezone.utc).isoformat(),
        "previous_sha256": state.get("event_sha256"),
        "details": details,
    }
    write_run_json(directory, f"event-{sequence:05d}.json", event)
    state.update(sequence=sequence, event_sha256=digest(event), updated_at=event["at"])
    write_run_json(directory, "state.json", state)
    if emit is not None:
        emit(event)


def _docker_base() -> list[str]:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeAuditError(
            "E_DOCKER_UNAVAILABLE",
            "Install and start a local Linux Docker engine; host execution is disabled",
        )
    endpoint = (
        "npipe:////./pipe/dockerDesktopLinuxEngine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    return [executable, "--host", endpoint]


def _docker_control(base: list, args: list, *, timeout: int = 15) -> tuple[dict, bytes]:
    from .runtime_audit_process import run_bounded_command

    with tempfile.TemporaryDirectory(prefix="factory-docker-") as temporary:
        directory = Path(temporary)
        output = directory / "stdout"
        facts = run_bounded_command(
            base + args, directory, timeout, directory, stdout_path=output
        )
        raw = output.read_bytes() if output.exists() else b""
        if (
            facts["timed_out"]
            or facts["output_limit_exceeded"]
            or not facts["cleanup_confirmed"]
        ):
            raise RuntimeAuditError(
                "E_DOCKER_CONTROL",
                "Docker control request did not complete within bounds",
            )
        return facts, raw


def _docker_preflight(base: list, lane: dict) -> None:
    facts, raw = _docker_control(base, ["info", "--format", "{{json .OSType}}"])
    if facts["exit_code"] != 0 or raw.strip() != b'"linux"':
        raise RuntimeAuditError(
            "E_DOCKER_UNAVAILABLE", "A running local Linux Docker engine is required"
        )
    facts, raw = _docker_control(
        base, ["image", "inspect", lane["image"], "--format", "{{json .RepoDigests}}"]
    )
    if facts["exit_code"] != 0:
        raise RuntimeAuditError(
            "E_IMAGE_UNAVAILABLE",
            "Provision the pinned adapter image before running; automatic pulls are disabled",
        )
    try:
        pins = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeAuditError(
            "E_IMAGE_PIN", "cannot verify the locally installed image"
        ) from exc
    if not isinstance(pins, list) or lane["image"] not in pins:
        raise RuntimeAuditError(
            "E_IMAGE_PIN",
            "installed image does not match the declared repository digest",
        )


def _container_argv(
    base: list,
    lane: dict,
    snapshot: Path,
    name: str,
    run_id: str,
    candidate: str,
    contract: Path | None = None,
) -> list:
    if "," in str(snapshot):
        raise RuntimeAuditError(
            "E_MOUNT_PATH", "Docker bind paths cannot contain commas"
        )
    mounts = []
    if contract is not None:
        if "," in str(contract):
            raise RuntimeAuditError(
                "E_MOUNT_PATH", "Docker contract paths cannot contain commas"
            )
        mounts = [
            "--mount",
            f"type=bind,source={contract},target=/factory-contract.json,readonly",
            "--env",
            "FACTORY_CONTRACT=/factory-contract.json",
        ]
    return base + [
        "run",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=128",
        f"--memory={lane['memory_mib']}m",
        f"--memory-swap={lane['memory_mib']}m",
        "--cpus=2",
        "--ulimit",
        "nofile=256:256",
        "--log-driver=none",
        "--mount",
        f"type=bind,source={snapshot},target=/src,readonly,bind-recursive=readonly",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
        "--tmpfs",
        "/out:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--workdir=/src",
        "--env",
        f"FACTORY_RUN_ID={run_id}",
        "--env",
        f"FACTORY_CANDIDATE_SHA256={candidate}",
        *mounts,
        "--entrypoint",
        lane["argv"][0],
        lane["image"],
        *lane["argv"][1:],
    ]


def _container_cleanup(base: list, name: str) -> bool:
    try:
        _docker_control(base, ["rm", "--force", name])
        facts, raw = _docker_control(
            base,
            [
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.Names}}",
            ],
        )
        return facts["exit_code"] == 0 and not raw.strip()
    except (OSError, RuntimeAuditError):
        return False


def _monitor_lane(
    directory: Path,
    state: dict,
    stop: threading.Event,
    cancelled: threading.Event,
    emit,
) -> None:
    last = time.monotonic()
    while not stop.wait(0.25):
        if (directory / "cancel.json").exists():
            cancelled.set()
        if time.monotonic() - last >= 15:
            _event(
                directory,
                state,
                "lane_running",
                {"lane_id": state["active_lane"]},
                emit,
            )
            last = time.monotonic()


def _execute_lane(
    root: Path,
    directory: Path,
    state: dict,
    snapshot: Path,
    lane: dict,
    inventory: dict,
    plan: dict,
    emit,
) -> dict:
    from .deep_audit_sarif import normalize_execution_bundle
    from .deep_audit_io import write_run_json
    from .runtime_audit_process import run_bounded_command

    base = _docker_base()
    _docker_preflight(base, lane)
    name = f"factory-deep-{state['run_id']}-{lane['id']}"
    cancelled, stop = threading.Event(), threading.Event()
    monitor = threading.Thread(
        target=_monitor_lane,
        args=(directory, state, stop, cancelled, emit),
        daemon=True,
    )
    monitor.start()
    cleanup = False
    try:
        with tempfile.TemporaryDirectory(prefix="factory-lane-") as temporary:
            scratch = Path(temporary)
            output = scratch / "worker.json"
            contract = scratch / "contract.json"
            contract.write_bytes(
                canonical_bytes(
                    {
                        "schema": "factory.deep-adapter-input.v1",
                        "run_id": state["run_id"],
                        "manifest_sha256": state["manifest_sha256"],
                        "inventory": inventory,
                        "lane": lane,
                        "obligations": plan["obligations"],
                    }
                )
            )
            argv = _container_argv(
                base,
                lane,
                snapshot,
                name,
                state["run_id"],
                inventory["candidate_sha256"],
                contract,
            )
            facts = run_bounded_command(
                argv,
                scratch,
                lane["timeout_seconds"],
                scratch,
                stdout_path=output,
                cancelled=cancelled,
            )
            raw = output.read_bytes() if output.exists() else b""
    finally:
        stop.set()
        monitor.join(timeout=2)
        cleanup = _container_cleanup(base, name)
    if not cleanup:
        raise RuntimeAuditError(
            "E_CONTAINER_CLEANUP", f"Container cleanup could not be verified: {name}"
        )
    if (
        facts["exit_code"] != 0
        or facts.get("cancelled")
        or facts["timed_out"]
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
    ):
        return {
            "lane_id": lane["id"],
            "state": "INCOMPLETE",
            "findings": [],
            "gaps": ["WORKER_FAILED"],
            "execution": facts,
        }
    bundle = strict_json(raw)
    result = normalize_execution_bundle(
        bundle, lane, inventory, state["run_id"], plan["obligations"]
    )
    # Retain native evidence for independent review, never emit raw logs/secrets.
    write_run_json(directory, f"bundle-{lane['id']}.json", bundle)
    result.update(bundle_sha256=digest(bundle), execution=facts)
    return result


def _run_lanes(
    root: Path,
    directory: Path,
    state: dict,
    snapshot: Path,
    inventory: dict,
    plan: dict,
    emit,
    authorize,
) -> None:
    for lane in plan["lanes"]:
        if (directory / "cancel.json").exists():
            state["gaps"].append(
                _execution_gap(
                    "CANCELLED", "Start a fresh retry of this exact candidate."
                )
            )
            break
        state["active_lane"] = lane["id"]
        _event(
            directory,
            state,
            "lane_started",
            {"lane_id": lane["id"], "engine": lane["engine"]},
            emit,
        )
        try:
            authorize()
            result = _execute_lane(
                root, directory, state, snapshot, lane, inventory, plan, emit
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            code = getattr(exc, "code", "E_WORKER_EVIDENCE")
            result = {
                "lane_id": lane["id"],
                "state": "INCOMPLETE",
                "findings": [],
                "gaps": [code],
            }
        state["lanes"].append(result)
        for finding in result["findings"]:
            finding["rerun"] = [
                "factory",
                "deep-audit",
                "scan",
                "--root",
                str(root),
                "--manifest",
                "<operator-manifest>",
                "--manifest-sha256",
                state["manifest_sha256"],
                "--authorization",
                "<fresh-coordinator-authorization>",
                "--trust-root",
                "<operator-trust-root>",
                "--trust-root-sha256",
                plan["trust_root_sha256"],
            ]
            _event(directory, state, "finding_observed", finding, emit)
        _event(
            directory,
            state,
            "lane_completed",
            {"lane_id": lane["id"], "state": result["state"], "gaps": result["gaps"]},
            emit,
        )
        if "E_CONTAINER_CLEANUP" in result["gaps"]:
            state["gaps"].append(
                _execution_gap(
                    "E_CONTAINER_CLEANUP",
                    "Remove the named run container and verify its absence before retrying.",
                )
            )
            break


def _check_resume(
    root: Path,
    resume: str | None,
    manifest_sha256: str,
    plan: dict,
    read_run_json,
    run_directory,
) -> None:
    if not resume:
        return
    previous = read_run_json(run_directory(root, resume), "state.json")
    if (
        previous["manifest_sha256"] != manifest_sha256
        or previous["candidate_sha256"] != plan["candidate_sha256"]
    ):
        raise RuntimeAuditError(
            "E_RESUME_DRIFT", "retry must bind the identical manifest and candidate"
        )


def _initial_run_state(
    run_id: str,
    resume: str | None,
    manifest_sha256: str,
    plan: dict,
    authorized: dict,
) -> dict:
    return {
        "schema": "factory.deep-run.v1",
        "run_id": run_id,
        "state": "RUNNING",
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_sha256": manifest_sha256,
        "manifest_content_sha256": digest(plan),
        "parent_run": resume,
        "authorization_sha256": digest(authorized),
        "lanes": [],
        "gaps": [],
        "authority": "none",
        "release_approval": False,
    }


def _capture_and_execute(
    root: Path,
    directory: Path,
    state: dict,
    plan: dict,
    manifest_sha256: str,
    authorization: Path,
    trust_root: Path,
    trust_root_sha256: str,
    emit,
    verify_authorization,
    inventory_candidate,
    write_run_json,
) -> None:
    with tempfile.TemporaryDirectory(prefix="factory-source-") as temporary:
        # Canonicalize the trusted system temp parent (macOS /var is linked).
        # inventory_candidate still rejects caller-supplied linked snapshots.
        snapshot = Path(temporary).resolve(strict=True) / "src"
        snapshot.mkdir()
        inventory = inventory_candidate(root, snapshot)
        write_run_json(directory, "inventory.json", inventory)
        state["gaps"].extend(inventory["gaps"] + _scope_gaps(plan, inventory))
        if inventory["candidate_sha256"] != plan["candidate_sha256"]:
            state["gaps"].append(
                _execution_gap(
                    "CANDIDATE_DRIFT",
                    "Regenerate the plan against the current complete inventory.",
                )
            )
        # Rehash live inputs before execution so file changes during capture fail closed.
        recheck = inventory_candidate(root)
        if (
            recheck["candidate_sha256"] != inventory["candidate_sha256"]
            or recheck["gaps"] != inventory["gaps"]
        ):
            state["gaps"].append(
                _execution_gap(
                    "SNAPSHOT_DRIFT", "Stop source edits and retry snapshot capture."
                )
            )
        _event(
            directory,
            state,
            "inventory_completed",
            {
                "accounted_paths": inventory["accounted_paths"],
                "gap_count": len(state["gaps"]),
            },
            emit,
        )
        if not state["gaps"]:
            verify_authorization(
                plan, manifest_sha256, authorization, trust_root, trust_root_sha256
            )
            _run_lanes(
                root,
                directory,
                state,
                snapshot,
                inventory,
                plan,
                emit,
                lambda: verify_authorization(
                    plan,
                    manifest_sha256,
                    authorization,
                    trust_root,
                    trust_root_sha256,
                ),
            )
        final = inventory_candidate(root)
        if final["candidate_sha256"] != plan["candidate_sha256"] or final["gaps"]:
            state["gaps"].append(
                _execution_gap(
                    "SOURCE_CHANGED_DURING_RUN",
                    "Review the new candidate and rerun all affected analysis.",
                )
            )


def _finish_scan(
    directory: Path,
    state: dict,
    plan: dict,
    emit,
    write_run_json,
) -> dict:
    state.pop("active_lane", None)
    state["state"] = "INCOMPLETE"
    state["analysis_complete"] = (
        not state["gaps"]
        and len(state["lanes"]) == len(plan["lanes"])
        and all(lane["state"] == "OBSERVED" for lane in state["lanes"])
    )
    state["review"] = "REQUIRED"
    _event(
        directory,
        state,
        "run_completed",
        {"analysis_complete": state["analysis_complete"], "review": "REQUIRED"},
        emit,
    )
    write_run_json(directory, "evidence.json", state)
    return state


def scan_deep_audit(
    root: Path,
    manifest: Path,
    manifest_sha256: str,
    *,
    authorization: Path,
    trust_root: Path,
    trust_root_sha256: str,
    resume: str | None = None,
    emit=None,
) -> dict:
    """Explicit isolated execution; unsigned observations never establish readiness."""
    from .deep_audit_contract import load_execution_manifest
    from .deep_audit_io import (
        inventory_candidate,
        read_run_json,
        run_directory,
        write_run_json,
    )
    from .deep_audit_attestation import verify_execution_authorization, _execution_bytes

    root = Path(root).resolve()
    plan = load_execution_manifest(manifest, manifest_sha256)
    authorized = verify_execution_authorization(
        plan, manifest_sha256, authorization, trust_root, trust_root_sha256
    )
    _check_resume(root, resume, manifest_sha256, plan, read_run_json, run_directory)
    run_id = uuid.uuid4().hex
    directory = run_directory(root, run_id, create=True)
    state = _initial_run_state(run_id, resume, manifest_sha256, plan, authorized)
    write_run_json(directory, "manifest.json", plan)
    write_run_json(
        directory, "authorization.json", strict_json(_execution_bytes(authorization))
    )
    _event(
        directory,
        state,
        "run_started",
        {"candidate_sha256": plan["candidate_sha256"]},
        emit,
    )
    try:
        _capture_and_execute(
            root,
            directory,
            state,
            plan,
            manifest_sha256,
            authorization,
            trust_root,
            trust_root_sha256,
            emit,
            verify_execution_authorization,
            inventory_candidate,
            write_run_json,
        )
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as exc:
        state["gaps"].append(
            _execution_gap(
                getattr(exc, "code", "RUN_INTERRUPTED"),
                "Inspect run events, restore prerequisites, and start an exact-bound retry.",
            )
        )
    return _finish_scan(directory, state, plan, emit, write_run_json)


def deep_run_status(root: Path, run_id: str) -> dict:
    """Read and verify state hashes only; never execute Git, Docker, or analyzers."""
    from .deep_audit_io import read_run_json, run_directory

    directory = run_directory(root, run_id)
    state = read_run_json(directory, "state.json")
    if state.get("run_id") != run_id or state.get("schema") != "factory.deep-run.v1":
        raise RuntimeAuditError("E_RUN_INTEGRITY", "run identity mismatch")
    sequence = state.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= 100_000:
        raise RuntimeAuditError("E_EVENT_INTEGRITY", "event sequence outside bounds")
    previous = None
    for index in range(1, sequence + 1):
        event = read_run_json(directory, f"event-{index:05d}.json")
        if (
            event.get("sequence") != index
            or event.get("run_id") != run_id
            or event.get("previous_sha256") != previous
        ):
            raise RuntimeAuditError("E_EVENT_INTEGRITY", "event chain mismatch")
        previous = digest(event)
    if previous != state["event_sha256"]:
        raise RuntimeAuditError("E_EVENT_INTEGRITY", "event head mismatch")
    # Self hashes are not authentication. Read-only status never promotes a run.
    return {
        **state,
        "state": "INCOMPLETE",
        "observed_state": state["state"],
        "authority": "none",
        "release_approval": False,
        "status_limit": "Unreviewed local observations; use review with explicitly pinned trust to verify readiness.",
    }


def cancel_deep_run(root: Path, run_id: str) -> dict:
    """Request cooperative cancellation of one verified local execution run."""
    from .deep_audit_io import run_directory, write_run_json

    directory = run_directory(root, run_id)
    state = deep_run_status(root, run_id)
    if state["observed_state"] != "RUNNING":
        return {"run_id": run_id, "state": "ALREADY_STOPPED", "authority": "none"}
    write_run_json(
        directory,
        "cancel.json",
        {"run_id": run_id, "requested_at": datetime.now(timezone.utc).isoformat()},
    )
    return {"run_id": run_id, "state": "CANCELLATION_REQUESTED", "authority": "none"}


def execution_repairs(
    root: Path, run_id: str, *, before_run: str | None = None
) -> dict:
    """Expose durable resolution tasks; disappearance alone never verifies repair."""
    current = deep_run_status(root, run_id)
    findings = [dict(item) for lane in current["lanes"] for item in lane["findings"]]
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (ranks.get(item["severity"], 0), item["finding_id"]))
    gaps = list(current["gaps"])
    for lane in current["lanes"]:
        for code in lane["gaps"]:
            gaps.append(
                _execution_gap(
                    code,
                    "Resolve this analyzer prerequisite, inspect its bound report, and rerun the signed scan.",
                    lane["lane_id"],
                )
            )
    comparison = None
    if before_run:
        previous = deep_run_status(root, before_run)
        before_ids = {
            item["finding_id"]
            for lane in previous["lanes"]
            for item in lane["findings"]
        }
        after_ids = {item["finding_id"] for item in findings}
        comparison = {
            "before_run": before_run,
            "disappeared_pending_verification": sorted(before_ids - after_ids),
            "introduced": sorted(after_ids - before_ids),
            "remaining": sorted(before_ids & after_ids),
            "resolved": [],
            "reason": "Independent signed review and regression evidence are required to close a repair.",
        }
    return {
        "schema": "factory.deep-resolution-queue.v1",
        "run_id": run_id,
        "candidate_sha256": current["candidate_sha256"],
        "state": "INCOMPLETE",
        "findings": findings,
        "coverage_tasks": gaps,
        "comparison": comparison,
        "review": "REQUIRED",
        "authority": "none",
        "release_approval": False,
    }


SCHEMA = "factory.deep-audit-receipt.v1"
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _reports(plan: dict, supplied: list, field: str) -> dict:
    expected = {item["id"]: item for item in plan["analyzers"]}
    found = {}
    for report in supplied:
        body = {
            key: value for key, value in report.items() if key != "normalized_sha256"
        }
        identity = report["analyzer"]
        key = identity["id"]
        if (
            report.get("schema") != "factory.deep-sarif.v1"
            or report.get("authority") != "none"
        ):
            raise RuntimeAuditError("E_DEEP_REPORT", "unexpected normalized report")
        if (
            key not in expected
            or key in found
            or digest(body) != report.get("normalized_sha256")
        ):
            raise RuntimeAuditError(
                "E_DEEP_REPORT", "duplicate, unknown or modified report"
            )
        declared = expected[key]
        if (
            identity != {name: declared[name] for name in ("id", "driver", "version")}
            or report["report_sha256"] != declared[field]["sha256"]
        ):
            raise RuntimeAuditError(
                "E_DEEP_REPORT", "report differs from signed binding"
            )
        found[key] = report
    if set(found) != set(expected):
        raise RuntimeAuditError(
            "E_ANALYZER_INCOMPLETE", "required analyzer evidence missing"
        )
    return found


def _action(code: str, rule: dict | None = None, finding: dict | None = None) -> dict:
    rule, finding = rule or {}, finding or {}
    locations = finding.get("locations", [])
    return {
        "code": code,
        "severity": rule.get("severity", "high"),
        "rule_id": rule.get("id", finding.get("rule_id", "")),
        "obligation_id": rule.get("obligation_id", ""),
        "finding_id": finding.get("finding_id", ""),
        "path": locations[0]["path"] if locations else "",
        "remediation": rule.get(
            "remediation",
            "Restore independently produced evidence and request policy-owner review.",
        ),
        "consequence": rule.get(
            "consequence", "The supplied evidence cannot justify readiness."
        ),
    }


def _canary_actions(plan: dict, reports: dict) -> list:
    actions = []
    for canary in plan["canaries"]:
        findings = reports[canary["analyzer_id"]]["findings"]
        detected = any(
            item["rule_id"] == canary["rule_id"]
            and item["native_fingerprint_sha256"] == canary["fingerprint_sha256"]
            and item["kind"] == "fail"
            and item["baseline"] != "absent"
            and not item["suppressed"]
            for item in findings
        )
        if not detected:
            action = _action("HOLLOW_DEEP_AUDIT")
            action["canary_id"] = canary["id"]
            action["analyzer_id"] = canary["analyzer_id"]
            actions.append(action)
    return actions


def _ordered_source_sink(flows: list) -> bool:
    for flow in flows:
        source_seen = False
        for step in flow:
            if source_seen and "sink" in step["kinds"]:
                return True
            source_seen = source_seen or "source" in step["kinds"]
    return False


def _finding_actions(rule: dict | None, finding: dict) -> list:
    actions = []
    approved = (
        rule is not None
        and finding["native_fingerprint_sha256"] in rule["allowed_suppressions"]
    )
    if finding["suppressed"] and not approved:
        actions.append(_action("DEEP_SUPPRESSION_UNAPPROVED", rule, finding))
    if rule is None:
        if finding["level"] == "error" and finding["baseline"] in {
            "new",
            "updated",
            "unbaselined",
        }:
            actions.append(_action("DEEP_UNKNOWN_ERROR", None, finding))
        return actions
    if finding["trace_depth"] < rule["min_trace_steps"] or (
        rule["require_source_sink"] and not _ordered_source_sink(finding["flows"])
    ):
        actions.append(_action("DEEP_TRACE_INCOMPLETE", rule, finding))
    return actions


def _clusters(findings: list) -> list:
    grouped = defaultdict(list)
    for finding in findings:
        if finding.get("obligation_id"):
            for path in {item["path"] for item in finding["locations"]}:
                grouped[path].append(finding)
    clusters = []
    for path, members in sorted(grouped.items()):
        obligations = defaultdict(list)
        for finding in members:
            obligations[finding["obligation_id"]].append(finding)
        for obligation, same in sorted(obligations.items()):
            if len({item["analyzer_id"] for item in same}) > 1:
                clusters.append(
                    {
                        "kind": "corroboration",
                        "path": path,
                        "obligation_id": obligation,
                        "findings": sorted(item["finding_id"] for item in same),
                        "claim": "routing_signal_not_causation",
                    }
                )
        if len({item["category"] for item in members}) > 1:
            clusters.append(
                {
                    "kind": "compound_risk",
                    "path": path,
                    "findings": sorted(item["finding_id"] for item in members),
                    "claim": "routing_signal_not_causation",
                }
            )
    return clusters


def _collect_findings(plan: dict, target: dict, actions: list) -> tuple:
    aliases = {
        (alias["analyzer_id"], alias["rule_id"]): rule
        for rule in plan["rules"]
        for alias in rule["aliases"]
    }
    findings, counts = [], defaultdict(list)
    for analyzer_id in sorted(target):
        for original in target[analyzer_id]["findings"]:
            finding = dict(original)
            rule = aliases.get((analyzer_id, finding["rule_id"]))
            actions.extend(_finding_actions(rule, finding))
            if rule:
                finding.update(
                    obligation_id=rule["obligation_id"],
                    category=rule["category"],
                    severity=rule["severity"],
                )
                counts[rule["id"]].append(finding)
            findings.append(finding)
            if len(findings) > 20_000 or len(actions) > 20_000:
                raise RuntimeAuditError(
                    "E_DEEP_LIMIT", "aggregate finding or action limit exceeded"
                )
    return findings, counts


def _threshold_actions(plan: dict, counts: dict) -> list:
    actions = []
    for rule in plan["rules"]:
        items = counts[rule["id"]]
        introduced = sum(
            item["baseline"] in {"new", "updated", "unbaselined"} for item in items
        )
        if len(items) > rule["max_total"] or introduced > rule["max_new"]:
            action = _action("DEEP_RULE_THRESHOLD", rule)
            action.update(
                total=len(items),
                introduced=introduced,
                max_total=rule["max_total"],
                max_new=rule["max_new"],
            )
            actions.append(action)
    return actions


def evaluate_deep_audit(plan: dict, reports: list, canary_reports: list) -> dict:
    """Evaluate supplied normalized facts without authenticating dictionaries or granting any execution or release authority."""
    target = _reports(plan, reports, "report")
    canaries = _reports(plan, canary_reports, "canary_report")
    actions = _canary_actions(plan, canaries)
    findings, counts = _collect_findings(plan, target, actions)
    actions.extend(_threshold_actions(plan, counts))
    clusters = _clusters(findings)
    if len(actions) > 20_000 or len(clusters) > 20_000:
        raise RuntimeAuditError(
            "E_DEEP_LIMIT", "aggregate action or cluster limit exceeded"
        )
    actions.sort(
        key=lambda item: (
            SEVERITY[item["severity"]],
            item["path"],
            item["rule_id"],
            item["code"],
            item["finding_id"],
            item.get("canary_id", ""),
        )
    )
    receipt = {
        "schema": SCHEMA,
        "candidate_sha256": plan["candidate_sha256"],
        "plan_payload_sha256": digest(plan),
        "findings": sorted(findings, key=lambda item: item["finding_id"]),
        "clusters": clusters,
        "repair_queue": actions,
        "decision": "BLOCKED" if actions else "READY_FOR_HUMAN_REVIEW",
        "report_hashes": {
            key: value["normalized_sha256"] for key, value in sorted(target.items())
        },
        "canary_hashes": {
            key: value["normalized_sha256"] for key, value in sorted(canaries.items())
        },
        "authority": "none",
        "claim_boundary": "Supplied analyzer evidence is not proof of defect absence or release approval.",
    }
    return {**receipt, "receipt_sha256": digest(receipt)}


def _write_receipt(root: Path, receipt: dict) -> Path:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        directory.mkdir(exist_ok=True)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError(
                "E_PATH_ESCAPE", "receipt directory must not be linked"
            )
    path = directory / (receipt["receipt_sha256"] + ".json")
    raw = canonical_bytes(receipt)
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_DEEP_LIMIT", "receipt exceeds byte budget")
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError:
        checked = local_file(root, path.relative_to(root).as_posix())
        with checked.open("rb") as stream:
            if stream.read(LIMIT + 1) != raw:
                raise RuntimeAuditError(
                    "E_RECEIPT_COLLISION", "existing receipt differs"
                )
    return path


def execute_deep_audit(
    plan_path: Path, trust_root_path: Path, trust_root_sha256: str, workspace_root: Path
) -> dict:
    """Verify signed inputs, normalize exact reports, evaluate policies and persist one non-authorizing audit receipt."""
    checked = verify_deep_audit_plan(
        plan_path, trust_root_path, trust_root_sha256, workspace_root
    )
    plan, sources = checked["plan"], checked["source_hashes"]
    targets, canaries = [], []
    for analyzer in plan["analyzers"]:
        targets.append(
            normalize_sarif(workspace_root, analyzer["report"], analyzer, sources)
        )
        canaries.append(
            normalize_sarif(
                workspace_root, analyzer["canary_report"], analyzer, sources
            )
        )
    receipt = evaluate_deep_audit(plan, targets, canaries)
    if (
        verify_deep_audit_plan(
            plan_path, trust_root_path, trust_root_sha256, workspace_root
        )
        != checked
    ):
        raise RuntimeAuditError("E_INPUT_CHANGED", "inputs changed across evaluation")
    receipt.pop("receipt_sha256")
    for name in ("plan_sha256", "ruleset_sha256", "canary_set_sha256"):
        receipt[name] = checked[name]
    receipt["receipt_sha256"] = digest(receipt)
    path = _write_receipt(Path(workspace_root).resolve(), receipt)
    return {"receipt": receipt, "receipt_path": str(path), "authority": "none"}


def _history(root: Path) -> list:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        if not directory.exists() and not directory.is_symlink():
            return []
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("receipt history must be an unlinked directory")
    paths = list(islice(directory.glob("*.json"), 1025))
    if len(paths) > 1024:
        raise ValueError("receipt history exceeds inspection bound")
    return paths


def _read_receipt(root: Path, path: Path) -> tuple:
    path = local_file(root, path.relative_to(root).as_posix())
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("receipt exceeds inspection budget")
    receipt = strict_json(raw)
    claimed = receipt.pop("receipt_sha256")
    if (
        digest(receipt) != claimed
        or path.stem != claimed
        or receipt["schema"] != SCHEMA
        or receipt["authority"] != "none"
    ):
        raise ValueError("receipt integrity mismatch")
    expected = "BLOCKED" if receipt["repair_queue"] else "READY_FOR_HUMAN_REVIEW"
    if receipt["decision"] != expected:
        raise ValueError("decision inconsistent with blockers")
    return receipt, claimed, expected


def deep_audit_status(root: Path) -> dict:
    """Read bounded receipt history with tamper checks, never treating a self-hash as signer authentication."""
    root = Path(root).resolve()
    result = {
        "schema": "factory.deep-audit-status.v1",
        "state": "NOT_RUN",
        "authority": "none",
    }
    try:
        paths = _history(root)
        if not paths:
            return result
        path = max(paths, key=lambda item: (item.stat().st_mtime_ns, item.name))
        receipt, claimed, expected = _read_receipt(root, path)
        return {
            **result,
            "state": expected,
            "receipt_path": str(path),
            "receipt_sha256": claimed,
            "finding_count": len(receipt["findings"]),
            "repair_queue": receipt["repair_queue"],
            "verification": "self_hash_only_not_signature_or_freshness",
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "state": "INCOMPLETE"}
