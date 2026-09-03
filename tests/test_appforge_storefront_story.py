from __future__ import annotations

import hashlib
import json
from pathlib import Path

from factoryline.appforge_storefront_story import CONTRACT_SCHEMA, EVIDENCE_SCHEMA, RECEIPT_SCHEMA, storefront_story_projection, verify_storefront_story
from factoryline.cli import main


CANDIDATE = {"bundle_identifier": "app.example.calm", "version": "1.0", "build_number": "42", "source_commit": "abc123"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _candidate(root: Path) -> Path:
    return _write(root / "candidate.json", {"schema": "factory.appforge.release-candidate.v1", "candidate": CANDIDATE})


def _media(root: Path) -> Path:
    core = {
        "schema": "factory.appforge.store-media-receipt.v1",
        "marker": "APPFORGE_STORE_MEDIA_READY",
        "candidate": CANDIDATE,
        "media_sets": {
            "iphone": {"captures": [{"id": "phone-first", "journey": "first value"}]},
            "ipad": {"captures": [{"id": "ipad-workspace", "journey": "core workspace"}]},
        },
    }
    core["receipt_sha256"] = _sha(core)
    return _write(root / "store-media.json", core)


def _contract(root: Path, media: Path, *, headline: str = "Your calm workspace") -> Path:
    media_value = json.loads(media.read_text(encoding="utf-8"))
    return _write(root / "story.json", {
        "schema": CONTRACT_SCHEMA,
        "candidate": CANDIDATE,
        "store_media_receipt_sha256": media_value["receipt_sha256"],
        "scenes": [
            {"set_id": "iphone", "capture_id": "phone-first", "story_beat": "mission", "headline": headline, "supporting_copy": "See the first useful next step.", "claim_kind": "experience", "evidence_refs": []},
            {"set_id": "ipad", "capture_id": "ipad-workspace", "story_beat": "agency", "headline": "Work with context", "supporting_copy": "Open the work that matters without losing your place.", "claim_kind": "feature", "evidence_refs": ["evidence-reference.md"]},
        ],
    })


def _evidence(root: Path, contract: Path) -> Path:
    (root / "evidence-reference.md").write_text("Local feature walkthrough reference.", encoding="utf-8")
    return _write(root / "evidence.json", {
        "schema": EVIDENCE_SCHEMA,
        "candidate": CANDIDATE,
        "contract_sha256": hashlib.sha256(contract.read_bytes()).hexdigest(),
        "review": {"reviewed_by": "Product Owner", "confirmed_at": "2026-09-02T12:00:00Z", "storyboard_truth": True, "claims_checked": True},
    })


def test_storefront_story_binds_every_capture_to_one_reviewed_scene(tmp_path: Path, capsys) -> None:
    candidate = _candidate(tmp_path)
    media = _media(tmp_path)
    contract = _contract(tmp_path, media)
    evidence = _evidence(tmp_path, contract)

    receipt = verify_storefront_story(tmp_path, candidate, media, contract, evidence, Path(".factory/appforge/storefront-story.json"))

    assert receipt["schema"] == RECEIPT_SCHEMA
    assert receipt["marker"] == "APPFORGE_STOREFRONT_STORY_READY"
    assert len(receipt["scenes"]) == 2
    assert receipt["authority"]["app_store_connect_write"] is False
    assert storefront_story_projection(tmp_path)["current_count"] == 1
    assert main(["revenue", "appforge-storefront-story", "--root", str(tmp_path), "--candidate", "candidate.json", "--store-media", "store-media.json", "--contract", "story.json", "--evidence", "evidence.json", "--out", ".factory/appforge/cli-storefront-story.json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "APPFORGE_STOREFRONT_STORY_READY"


def test_storefront_story_blocks_unsourced_marketing_claim(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    media = _media(tmp_path)
    contract = _contract(tmp_path, media, headline="Guaranteed to save 3 days")
    evidence = _evidence(tmp_path, contract)

    receipt = verify_storefront_story(tmp_path, candidate, media, contract, evidence, Path(".factory/appforge/storefront-story.json"))

    assert receipt["marker"] == "APPFORGE_STOREFRONT_STORY_BLOCKED"
    assert receipt["findings"][0]["code"] == "APPFORGE_STOREFRONT_STORY_UNSOURCED_CLAIM"
