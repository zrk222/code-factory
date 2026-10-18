"""Native semantic sensing preserves existing defects and separates source claims."""

import pytest
from factoryline import review_audits as audit
from factoryline import semantic_credential_sensor as sensors


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://identity.example.test/oauth/token",
        "https://api.telegram.org/bot123456789:AAEabcdefghijklmnopqrstuvwxyz0123456789/getMe",
        "https://user:fixed-value@id.example.test/token",
        "https://id.example.test/token?key=fixed-value",
    ],
)
def test_target_role_alone_never_suppresses_credential_warning(tmp_path, endpoint):
    (tmp_path / "config.py").write_text(f"ACCESS_TOKEN_URL = {endpoint!r}\n")
    (tmp_path / "client.py").write_text(
        "import requests\nfrom config import ACCESS_TOKEN_URL\nrequests.get(ACCESS_TOKEN_URL)\n"
    )
    report = audit.security_scan(tmp_path, cache_enabled=False)
    [secret] = [
        f for f in report["findings"] if f["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert secret["severity"] == "CRITICAL"
    assert not report.get("primitive_observations")


def test_native_unnamed_auth_literal_and_original_secret_survive_cold_warm(tmp_path):
    (tmp_path / "app.py").write_text(
        "import requests\nPASSWORD='hunter2'\n"
        "def send(url):\n"
        "    return requests.post(url, auth=('someone', 'literal-for-auth'))\n"
    )
    audit._oracle_context_cache_clear()
    cold = audit.security_scan(tmp_path)
    warm = audit.security_scan(tmp_path)
    assert cold["findings"] == warm["findings"]
    assert audit._oracle_context_cache_info()["hits"] >= 1
    by_code = {f["code"]: f for f in cold["findings"]}
    assert by_code["SECURITY_HARDCODED_SECRET"]["severity"] == "CRITICAL"
    sensor = by_code["SECURITY_LITERAL_HTTP_CREDENTIAL"]
    assert sensor["facts"]["consumer_role"] == "http_auth"
    assert sensor["facts"]["credential_validity"] == "not_established"
    assert sensor["facts"]["claim_boundary"] == "static_not_runtime"
    assert "literal-for-auth" not in repr(cold)
    assert "hunter2" not in repr(cold)


def test_native_public_url_target_and_unknown_runtime_auth_add_no_sensor_alert(
    tmp_path,
):
    (tmp_path / "app.py").write_text(
        "import httpx\n"
        "httpx.get('https://id.example.test/token')\n"
        "def send(url, supplied):\n"
        "    return httpx.get(url, auth=supplied)\n"
    )
    assert audit.security_scan(tmp_path, cache_enabled=False)["findings"] == []


@pytest.mark.parametrize("name", ["credential_findings", "_auth_literal_nodes"])
def test_semantic_validator_replacement_invalidates_native_cache(
    tmp_path, monkeypatch, name
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = getattr(sensors, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(sensors, name, replacement)
    assert before != audit._oracle_context_cache_key(tmp_path, [], {})
