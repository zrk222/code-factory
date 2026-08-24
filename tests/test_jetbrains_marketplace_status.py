from __future__ import annotations

import json

from scripts import jetbrains_marketplace_status as status


def _plugin(**overrides):
    value = {
        "id": 33009,
        "name": "FactoryLine AI Proof",
        "downloads": 46,
        "pricingModel": "FREE",
        "approve": True,
        "hasUnapprovedUpdate": False,
    }
    value.update(overrides)
    return value


def _updates():
    return [{"id": 1, "version": "0.7.2", "approve": True, "listed": True}]


def test_pending_metadata_is_not_hidden_by_an_approved_version():
    result = status.classify_status(_plugin(approve=False, hasUnapprovedUpdate=True), _updates())

    assert result["clear"] is False
    assert result["marker"] == "MARKETPLACE_UPDATE_PENDING"
    assert result["latest_approved"] is True
    assert result["upload_slot_clear"] is False


def test_metadata_review_does_not_impersonate_a_queued_binary_update():
    result = status.classify_status(_plugin(approve=False, hasUnapprovedUpdate=False), _updates())

    assert result["clear"] is False
    assert result["marker"] == "MARKETPLACE_UPDATE_PENDING"
    assert result["upload_slot_clear"] is True


def test_expected_version_must_be_present_approved_and_listed():
    missing = status.classify_status(_plugin(), _updates(), expected_version="2027.1.0")
    pending = status.classify_status(
        _plugin(), [{"version": "2027.1.0", "approve": False, "listed": False}], expected_version="2027.1.0"
    )
    clear = status.classify_status(_plugin(), _updates(), expected_version="0.7.2")

    assert missing["marker"] == "MARKETPLACE_VERSION_MISSING"
    assert pending["marker"] == "MARKETPLACE_VERSION_PENDING"
    assert clear["marker"] == "MARKETPLACE_UPDATE_CLEAR"
    assert clear["clear"] is True


def test_cli_require_clear_uses_distinct_pending_exit_code(monkeypatch, capsys):
    responses = iter([_plugin(approve=False, hasUnapprovedUpdate=True), _updates()])
    monkeypatch.setattr(status, "fetch_json", lambda _url: next(responses))

    assert status.main(["--require-clear", "--json"]) == 3
    assert json.loads(capsys.readouterr().out)["marker"] == "MARKETPLACE_UPDATE_PENDING"


def test_cli_can_require_only_an_open_binary_submission_slot(monkeypatch, capsys):
    responses = iter([_plugin(approve=False, hasUnapprovedUpdate=False), _updates()])
    monkeypatch.setattr(status, "fetch_json", lambda _url: next(responses))

    assert status.main(["--require-upload-slot", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["upload_slot_clear"] is True


def test_cli_rejects_a_queued_binary_update(monkeypatch, capsys):
    responses = iter([_plugin(approve=True, hasUnapprovedUpdate=True), _updates()])
    monkeypatch.setattr(status, "fetch_json", lambda _url: next(responses))

    assert status.main(["--require-upload-slot", "--json"]) == 4
    assert json.loads(capsys.readouterr().out)["upload_slot_clear"] is False


def test_cli_reports_unavailable_without_claiming_clear(monkeypatch, capsys):
    monkeypatch.setattr(status, "fetch_json", lambda _url: (_ for _ in ()).throw(OSError("offline")))

    assert status.main(["--require-clear", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["marker"] == "MARKETPLACE_STATUS_UNAVAILABLE"
