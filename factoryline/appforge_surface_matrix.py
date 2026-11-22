"""Generate a sealed real-device configuration matrix from Native Surface Truth."""

from __future__ import annotations

from .contract import write_atomic_json

from pathlib import Path
from typing import Any
import hashlib
import json

from .appforge_evidence_kit import _read_candidate
from .appforge_native_surface import RECEIPT_SCHEMA as NATIVE_RECEIPT_SCHEMA
from .revenueforge import _artifact_local, _artifact_json
from .revenueforge import AUTHORITY, RevenueForgeError
from . import canonical_json_compat_bytes as _canonical  # noqa: F401 - module encoder contract
from . import compat_sha as _sha


RECEIPT_SCHEMA = "factory.appforge.surface-matrix-receipt.v1"
MAX_BYTES = 1_048_576


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    return _artifact_local(Path(root), path, "APPFORGE_SURFACE_MATRIX", exists)


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    value = _artifact_json(
        source,
        "APPFORGE_SURFACE_MATRIX",
        MAX_BYTES,
        object_message="input must be an object",
        large_message="input exceeds 1 MiB",
    )
    return value, source


def _sealed_native(value: dict[str, Any]) -> bool:
    return (
        value.get("schema") == NATIVE_RECEIPT_SCHEMA
        and value.get("marker") == "APPFORGE_NATIVE_SURFACE_READY"
        and isinstance(value.get("receipt_sha256"), str)
        and _sha({key: item for key, item in value.items() if key != "receipt_sha256"})
        == value["receipt_sha256"]
    )


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    write_atomic_json(path, payload, ensure_ascii=True)


def create_surface_matrix(
    root: Path, candidate_path: Path, native_surface_path: Path, out_path: Path
) -> dict[str, Any]:
    """Create a device-configuration test plan; it never operates a device."""
    workspace = Path(root).resolve()
    candidate, _candidate_source = _read_candidate(workspace, candidate_path)
    native, native_source = _read(workspace, native_surface_path)
    if not _sealed_native(native) or native.get("candidate") != candidate:
        raise RevenueForgeError(
            "APPFORGE_SURFACE_MATRIX_NATIVE_SURFACE_INVALID",
            "native-surface receipt must be hash-valid, ready, and bound to the exact candidate",
        )
    platforms = native.get("platforms")
    if (
        not isinstance(platforms, list)
        or set(platforms) - {"iphone", "ipad"}
        or not platforms
    ):
        raise RevenueForgeError(
            "APPFORGE_SURFACE_MATRIX_NATIVE_SURFACE_INVALID",
            "native-surface receipt has unsupported platforms",
        )
    shared = [
        "default appearance",
        "Dynamic Type accessibility size",
        "Reduce Motion",
        "Reduce Transparency",
        "Increase Contrast",
        "VoiceOver",
    ]
    scenarios: list[dict[str, str]] = []
    if "iphone" in platforms:
        scenarios.extend(
            {
                "platform": "iphone",
                "configuration": item,
                "required_evidence": "supervised physical-device capture",
            }
            for item in shared
        )
    if "ipad" in platforms:
        scenarios.extend(
            {
                "platform": "ipad",
                "configuration": item,
                "required_evidence": "supervised physical-device capture",
            }
            for item in [
                "regular-width workspace",
                "Split View / compact width",
                *shared,
            ]
        )
    result: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_SURFACE_MATRIX_WRITTEN",
        "action_summary": "Generate the exact cross-device and accessibility configurations that must be proven later through supervised Device Reality; do not launch a simulator, control hardware, collect captures, access Apple, or claim any configuration passed.",
        "candidate": candidate,
        "native_surface_receipt_sha256": native["receipt_sha256"],
        "native_surface_path_sha256": hashlib.sha256(
            native_source.read_bytes()
        ).hexdigest(),
        "scenarios": scenarios,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "device_access": False,
            "apple_access": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "A sealed test plan only. Every listed configuration remains unproven until a matching supervised Device Reality evidence receipt is reviewed.",
    }
    result["receipt_sha256"] = _sha(result)
    destination = _local(workspace, out_path, exists=False)
    _atomic(destination, result)
    return {**result, "path": destination.relative_to(workspace).as_posix()}


def surface_matrix_projection(root: Path) -> dict[str, Any]:
    """Project valid local surface-matrix plans without asserting device or Store execution."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted(
        (workspace / ".factory" / "appforge").rglob("*surface-matrix*.json")
    )[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            invalid.append(path.relative_to(workspace).as_posix())
            continue
        supplied = value.get("receipt_sha256") if isinstance(value, dict) else None
        if (
            isinstance(value, dict)
            and value.get("schema") == RECEIPT_SCHEMA
            and isinstance(supplied, str)
            and _sha(
                {key: item for key, item in value.items() if key != "receipt_sha256"}
            )
            == supplied
        ):
            current.append(
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "marker": value.get("marker"),
                    "receipt_sha256": supplied,
                    "candidate": value.get("candidate"),
                    "scenario_count": len(value.get("scenarios", [])),
                }
            )
        else:
            invalid.append(path.relative_to(workspace).as_posix())
    return {
        "schema": "factory.appforge.surface-matrix-projection.v1",
        "marker": "APPFORGE_SURFACE_MATRIX_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "latest": current[-1] if current else None,
        "invalid": invalid,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "device_access": False,
            "apple_access": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "Read-only local device-test plan status; not a simulator, physical device, screenshot, TestFlight, App Review, or approval result.",
    }
