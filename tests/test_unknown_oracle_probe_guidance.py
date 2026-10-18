"""Unknown-oracle guidance remains advisory and does not change detection."""

from factoryline import review_audits as audit


def test_unknown_callback_includes_existing_native_probe_guidance(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior():\n"
        "    def check():\n"
        "        assert compute() == 42\n"
        "    pass\n",
        encoding="utf-8",
    )
    report = audit.security_scan(tmp_path, cache_enabled=False)
    finding = next(f for f in report["findings"]
                   if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE")
    assert finding["severity"] == "INFO"
    assert finding["facts"]["state"] == "INCOMPLETE"
    probe = finding["facts"]["native_assertion_probe"]
    assert probe["assertion_lines"] == [3]
    assert probe["nodeid_hint"] == "test_case.py::test_behavior"
    assert probe["exact_collection_id_required"] is True
    assert probe["call_available"] is False
    assert "never started by a static scan" in probe["execution"]


def test_unknown_call_probe_does_not_execute_target_and_cache_preserves_guidance(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "from pathlib import Path\n"
        "Path('scanner-ran-source').write_text('unexpected')\n"
        "def test_behavior():\n"
        "    callback()\n"
        "    pass\n"
        "def callback():\n"
        "    pass\n",
        encoding="utf-8",
    )
    cold = audit.security_scan(tmp_path)
    warm = audit.security_scan(tmp_path)
    assert cold["findings"] == warm["findings"]
    finding = next(f for f in cold["findings"]
                   if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE")
    probe = finding["facts"]["native_assertion_probe"]
    assert probe["call_lines"] == [4]
    assert probe["call_available"] is True
    assert "<exact collected pytest node ID>" in probe["call_command"]
    assert not (tmp_path / "scanner-ran-source").exists()
