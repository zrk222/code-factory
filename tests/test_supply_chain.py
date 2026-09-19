from __future__ import annotations

from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from factoryline.assurance import build_cyclonedx_sbom, build_vex
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.supply_chain import (
    ATTESTATION_SCHEMA,
    PAYLOAD_TYPE,
    evaluate_supply_chain,
    supply_chain_status,
    verify_signed_supply_chain_attestation,
    write_supply_chain_receipt,
)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def _descriptor(root: Path, relative: str) -> dict:
    path = root / relative
    data = path.read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _write_zip(root: Path, relative: str, content: bytes = b"artifact") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dist/payload.txt", content)


def _manifest(root: Path) -> tuple[dict, datetime]:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("print('candidate')\n", encoding="utf-8")
    (root / "requirements.lock").write_text("factoryline==0.46.4\n", encoding="utf-8")
    _write_zip(root, "dist/factoryline-0.46.4.whl")
    sbom = build_cyclonedx_sbom([{"name": "factoryline", "version": "0.46.7"}])
    (root / "sbom.json").write_text(json.dumps(sbom, sort_keys=True), encoding="utf-8")
    vex = build_vex(
        [
            {
                "vulnerability": "CVE-0000-0000",
                "component": "factoryline",
                "status": "not_affected",
            }
        ]
    )
    (root / "vex.json").write_text(json.dumps(vex, sort_keys=True), encoding="utf-8")
    source_files = [_descriptor(root, "src/app.py")]
    source_sha = _digest(source_files)
    artifact = _descriptor(root, "dist/factoryline-0.46.4.whl")
    rebuild = {"id": "builder-a", "artifacts": [artifact]}
    now = NOW
    manifest = {
        "schema": ATTESTATION_SCHEMA,
        "attestation_id": "sca-001",
        "candidate_sha256": source_sha,
        "source_manifest": {"sha256": source_sha, "files": source_files},
        "lockfiles": [_descriptor(root, "requirements.lock")],
        "sbom": _descriptor(root, "sbom.json"),
        "vex": _descriptor(root, "vex.json"),
        "vex_policy": {
            "max_unresolved": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "exceptions": [],
        },
        "licenses": {
            "policy_sha256": hashlib.sha256(b"license-policy").hexdigest(),
            "entries": [
                {
                    "component": "factoryline",
                    "license": "Apache-2.0",
                    "status": "allowed",
                }
            ],
            "exceptions": [],
        },
        "build": {
            "builder_id": "builder",
            "builder_version": "1",
            "toolchain_sha256": hashlib.sha256(b"python-3.11").hexdigest(),
            "command_sha256": hashlib.sha256(b"build").hexdigest(),
            "clean_environment": True,
            "reproducible": True,
            "rebuilds": [rebuild, {"id": "builder-b", "artifacts": [artifact]}],
        },
        "collector": {"id": "local", "role": "local_evaluator", "backend": "local"},
        "issued_at": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "authority": "none",
        "release_approval": False,
    }
    return manifest, now


def test_supply_chain_passes_and_writes_hash_bound_receipt(tmp_path: Path) -> None:
    manifest, now = _manifest(tmp_path)
    result = evaluate_supply_chain(tmp_path, manifest, now=now)
    assert result["decision"] == "PASS"
    assert {check["id"] for check in result["checks"]} == {
        "SOURCE_MANIFEST_BOUND",
        "LOCKFILES_BOUND",
        "SBOM_BOUND",
        "VEX_POLICY_BOUND",
        "LICENSE_POLICY_BOUND",
        "REPRODUCIBLE_BUILDS",
        "ARTIFACT_SECRET_SCAN",
    }
    out = tmp_path / ".factory" / "supply-chain" / "supply-chain-receipt.json"
    written = write_supply_chain_receipt(tmp_path, manifest, out, now=now)
    assert written["receipt_sha256"] == _digest(
        {key: value for key, value in written.items() if key != "receipt_sha256"}
    )
    assert supply_chain_status(tmp_path)["state"] == "PASS"


def test_rebuild_drift_and_license_policy_fail_closed(tmp_path: Path) -> None:
    manifest, now = _manifest(tmp_path)
    _write_zip(tmp_path, "dist/second-0.46.4.whl", b"different")
    drift = copy.deepcopy(manifest)
    drift["build"]["rebuilds"][1]["artifacts"] = [
        _descriptor(tmp_path, "dist/second-0.46.4.whl")
    ]
    blocked = evaluate_supply_chain(tmp_path, drift, now=now)
    assert blocked["decision"] == "BLOCKED"
    assert blocked["blockers"][0]["code"] == "E_REPRO_BUILD_DRIFT"
    denied = copy.deepcopy(manifest)
    denied["licenses"]["entries"][0]["status"] = "unknown"
    blocked = evaluate_supply_chain(tmp_path, denied, now=now)
    assert blocked["blockers"][0]["code"] == "E_LICENSE_POLICY"


def test_vulnerability_threshold_and_archive_secret_fail_closed(tmp_path: Path) -> None:
    manifest, now = _manifest(tmp_path)
    (tmp_path / "vex.json").write_text(
        json.dumps(
            build_vex(
                [{"vulnerability": "CVE-1", "component": "x", "status": "affected"}]
            )
            | {}
        ),
        encoding="utf-8",
    )
    # Rebuild the VEX descriptor after changing the file and add the required severity.
    vex = build_vex(
        [{"vulnerability": "CVE-1", "component": "x", "status": "affected"}]
    )
    vex["entries"][0]["severity"] = "high"
    vex["vex_sha256"] = _digest(
        {key: value for key, value in vex.items() if key != "vex_sha256"}
    )
    (tmp_path / "vex.json").write_text(
        json.dumps(vex, sort_keys=True), encoding="utf-8"
    )
    manifest["vex"] = _descriptor(tmp_path, "vex.json")
    blocked = evaluate_supply_chain(tmp_path, manifest, now=now)
    assert blocked["blockers"][0]["code"] == "E_VULNERABILITY_THRESHOLD"
    manifest, now = _manifest(tmp_path)
    _write_zip(
        tmp_path, "dist/factoryline-0.46.4.whl", b"ghp_abcdefghijklmnopqrstuvwxyz"
    )
    artifact = _descriptor(tmp_path, "dist/factoryline-0.46.4.whl")
    manifest["build"]["rebuilds"] = [
        {"id": "a", "artifacts": [artifact]},
        {"id": "b", "artifacts": [artifact]},
    ]
    blocked = evaluate_supply_chain(tmp_path, manifest, now=now)
    assert blocked["blockers"][0]["code"] == "E_SECRET_IN_ARTIFACT"


def test_vex_exception_is_bound_to_finding_before_threshold(tmp_path: Path) -> None:
    manifest, now = _manifest(tmp_path)
    vex = build_vex(
        [{"vulnerability": "CVE-1", "component": "x", "status": "affected"}]
    )
    vex["entries"][0]["severity"] = "high"
    vex["vex_sha256"] = _digest(
        {key: value for key, value in vex.items() if key != "vex_sha256"}
    )
    (tmp_path / "vex.json").write_text(
        json.dumps(vex, sort_keys=True), encoding="utf-8"
    )
    manifest["vex"] = _descriptor(tmp_path, "vex.json")
    manifest["vex_policy"]["exceptions"] = [
        {
            "id": "approved-cve-1",
            "vulnerability": "CVE-1",
            "component": "x",
            "severity": "high",
            "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "reason": "A reviewed mitigation is active for this release.",
        }
    ]
    passed = evaluate_supply_chain(tmp_path, manifest, now=now)
    assert passed["decision"] == "PASS"
    assert passed["facts"]["unresolved"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }
    assert passed["facts"]["unresolved_after_exceptions"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    unmatched = copy.deepcopy(manifest)
    unmatched["vex_policy"]["exceptions"][0]["vulnerability"] = "CVE-NOT-PRESENT"
    blocked = evaluate_supply_chain(tmp_path, unmatched, now=now)
    assert blocked["blockers"][0]["code"] == "E_EXCEPTION_UNMATCHED"


def test_external_signed_attestation_is_verified_but_local_is_rejected(
    tmp_path: Path,
) -> None:
    manifest, now = _manifest(tmp_path)
    manifest["collector"] = {
        "id": "independent",
        "role": "independent_builder",
        "backend": "remote-builder",
    }
    keys = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="sca",
        identity="builder@example.test",
        issuer="factory.test",
    )
    envelope = sign_payload(
        manifest,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid="sca",
        identity="builder@example.test",
        issuer="factory.test",
    )
    attestation = tmp_path / "attestation.json"
    attestation.write_text(json.dumps(envelope), encoding="utf-8")
    verified = verify_signed_supply_chain_attestation(
        attestation, Path(keys["trust_root"]), tmp_path, now=now
    )
    assert verified["state"] == "VERIFIED"
    local = copy.deepcopy(manifest)
    local["collector"] = {"id": "local", "role": "local_evaluator", "backend": "local"}
    local_envelope = sign_payload(
        local,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid="sca",
        identity="builder@example.test",
        issuer="factory.test",
    )
    attestation.write_text(json.dumps(local_envelope), encoding="utf-8")
    with pytest.raises(Exception) as error:
        verify_signed_supply_chain_attestation(
            attestation, Path(keys["trust_root"]), tmp_path, now=now
        )
    assert getattr(error.value, "code", None) == "E_COLLECTOR_INDEPENDENCE"
