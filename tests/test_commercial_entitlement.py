"""Tests for offline signed commercial entitlements."""

from datetime import datetime, timezone
import json

import pytest

from factoryline.commercial_entitlement import (
    CommercialEntitlementError,
    covering_entitlement,
    import_entitlement,
    load_entitlements,
    sign_entitlement,
    verify_entitlement_envelope,
    version_in_range,
)
from factoryline.enterprise_receipts import generate_key_material

NOW = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _payload(**overrides):
    payload = {
        "schema": "factory.commercial.entitlement.v1",
        "entitlement_id": "ent-test-1",
        "subject": "rick",
        "product": "code-factory",
        "covered_versions": {"min": "0.49.0", "max": "0.50.9"},
        "seats": 1,
        "not_before": "2027-01-01T00:00:00+00:00",
        "not_after": "2027-12-31T23:59:59+00:00",
        "issued_at": "2026-11-21T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def keys(tmp_path):
    material = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="commercial-test",
        identity="commercial-issuer",
        issuer="factoryline",
    )
    return material


def _sign(keys, payload):
    return sign_entitlement(
        payload,
        private_key_path=keys["private_key"],
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )


def _trust_root(keys):
    return json.loads(open(keys["trust_root"], encoding="utf-8").read())


def test_sign_and_verify_roundtrip(keys):
    envelope = _sign(keys, _payload())
    entitlement = verify_entitlement_envelope(envelope, trust_root=_trust_root(keys))
    assert entitlement.subject == "rick"
    assert entitlement.covers(
        subject="rick", product="code-factory", version="0.50.0", now=NOW
    )


def test_tampered_payload_fails_verification(keys, tmp_path):
    envelope = _sign(keys, _payload())
    other = _sign(keys, _payload(subject="mallory"))
    envelope["payload"] = other["payload"]  # swapped, signature no longer matches
    with pytest.raises(CommercialEntitlementError):
        verify_entitlement_envelope(envelope, trust_root=_trust_root(keys))


def test_wrong_trust_root_fails(keys, tmp_path):
    other = generate_key_material(
        out_dir=tmp_path / "other", keyid="k2", identity="i2", issuer="x"
    )
    envelope = _sign(keys, _payload())
    with pytest.raises(CommercialEntitlementError):
        verify_entitlement_envelope(envelope, trust_root=_trust_root(other))


def test_open_ended_future_versions_are_not_issuable(keys):
    payload = _payload()
    payload["covered_versions"] = {"min": "0.49.0", "max": None}
    with pytest.raises(CommercialEntitlementError) as exc:
        _sign(keys, payload)
    assert exc.value.code == "E_ENTITLEMENT_VERSIONS"


def test_coverage_window_and_subject_and_version(keys):
    entitlement = verify_entitlement_envelope(
        _sign(keys, _payload()), trust_root=_trust_root(keys)
    )
    assert not entitlement.covers(
        subject="rick",
        product="code-factory",
        version="0.50.0",
        now=datetime(2028, 1, 1, tzinfo=timezone.utc),
    )
    assert not entitlement.covers(
        subject="someone-else", product="code-factory", version="0.50.0", now=NOW
    )
    assert not entitlement.covers(
        subject="rick", product="code-factory", version="0.51.0", now=NOW
    )
    assert not entitlement.covers(
        subject="rick", product="specline", version="0.50.0", now=NOW
    )


def test_version_in_range():
    assert version_in_range("0.50.0", "0.49.0", "0.50.9")
    assert not version_in_range("0.51.0", "0.49.0", "0.50.9")
    assert not version_in_range("0.48.9", "0.49.0", "0.50.9")


def test_import_stores_and_reverifies(keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(json.dumps(_sign(keys, _payload())), encoding="utf-8")
    home = tmp_path / "home"
    imported = import_entitlement(
        envelope_path, trust_root_path=keys["trust_root"], home=home
    )
    assert imported.entitlement_id == "ent-test-1"
    loaded = load_entitlements(home)
    assert len(loaded) == 1
    covering = covering_entitlement(
        loaded, subject="rick", product="code-factory", version="0.50.0", now=NOW
    )
    assert covering is not None


def test_tampered_stored_copy_is_dropped(keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(json.dumps(_sign(keys, _payload())), encoding="utf-8")
    home = tmp_path / "home"
    import_entitlement(envelope_path, trust_root_path=keys["trust_root"], home=home)
    stored = next((home / "entitlements").glob("*.json"))
    tampered = json.loads(stored.read_text(encoding="utf-8"))
    tampered["payload_sha256"] = "0" * 64
    stored.write_text(json.dumps(tampered), encoding="utf-8")
    assert load_entitlements(home) == []


def test_conflicting_trust_root_is_refused(keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(json.dumps(_sign(keys, _payload())), encoding="utf-8")
    home = tmp_path / "home"
    import_entitlement(envelope_path, trust_root_path=keys["trust_root"], home=home)
    other = generate_key_material(
        out_dir=tmp_path / "other", keyid="k2", identity="i2", issuer="x"
    )
    other_envelope = sign_entitlement(
        _payload(entitlement_id="ent-test-2"),
        private_key_path=other["private_key"],
        keyid=other["keyid"],
        identity=other["identity"],
        issuer=other["issuer"],
    )
    other_path = tmp_path / "ent2.json"
    other_path.write_text(json.dumps(other_envelope), encoding="utf-8")
    with pytest.raises(CommercialEntitlementError) as exc:
        import_entitlement(other_path, trust_root_path=other["trust_root"], home=home)
    assert exc.value.code == "E_TRUST_ROOT_CONFLICT"


def test_invalid_envelope_is_never_stored(keys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "factory.dsse.envelope.v1"}), encoding="utf-8")
    home = tmp_path / "home"
    with pytest.raises(CommercialEntitlementError):
        import_entitlement(bad, trust_root_path=keys["trust_root"], home=home)
    assert load_entitlements(home) == []
