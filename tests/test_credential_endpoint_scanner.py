"""Exercise actual source derivation and scanner output, with no mocked proofs."""

import pytest

from factoryline.review_audits import security_scan

ENDPOINT = "https://appleid.apple.com/auth/token"


def _write(root, extra=""):
    (root / "client.py").write_text(
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {ENDPOINT!r}\n"
        "    def send(self):\n"
        "        return requests.get(self.ACCESS_TOKEN_URL)\n" + extra,
        encoding="utf-8",
    )


def _secrets(result, primitive=False):
    key = "primitive_observations" if primitive else "findings"
    return [f for f in result.get(key, []) if f["code"] == "SECURITY_HARDCODED_SECRET"]


@pytest.mark.parametrize("cache", [False, True])
def test_actual_complete_role_partitions_only_heuristic_and_preserves_priority(
    tmp_path, cache
):
    _write(tmp_path)
    for _ in range(2):
        result = security_scan(tmp_path, cache_enabled=cache)
        assert not _secrets(result)
        observations = _secrets(result, primitive=True)
        assert len(observations) == 1
        assert observations[0]["severity"] == "CRITICAL"
        facts = observations[0]["facts"]
        assert facts["disposition"] == "ENDPOINT_DECLARATION_ROLE_PROVEN"
        assert facts["value_use_audit"]["state"] == "COMPLETE"
        assert facts["runtime_assurance"] == "INCOMPLETE"
        assert facts["credential_safety"] == "UNASSESSED"


@pytest.mark.parametrize(
    "extra",
    [
        "    def auth(self):\n"
        "        requests.get('https://example.test', auth=('u', self.ACCESS_TOKEN_URL))\n",
        "    def auth(self):\n"
        "        requests.get(self.ACCESS_TOKEN_URL, auth=opaque(self.ACCESS_TOKEN_URL))\n",
        "    def escape(self):\n        consume(self.ACCESS_TOKEN_URL)\n",
        "class Child(Client):\n    pass\n"
        "requests.get('https://example.test', auth=('u', Child.ACCESS_TOKEN_URL))\n",
        "consume(getattr(Client, 'ACCESS_TOKEN_URL'))\n",
        "Alias = Client\n"
        "requests.get('https://example.test', auth=('u', Alias.ACCESS_TOKEN_URL))\n",
        "instance = Client()\nconsume(instance.ACCESS_TOKEN_URL)\n",
        "import builtins\nconsume(builtins.getattr(Client, 'ACCESS_TOKEN_URL'))\n",
        "from builtins import getattr as read\nconsume(read(Client, 'ACCESS_TOKEN_URL'))\n",
    ],
)
def test_actual_mixed_or_unresolved_use_keeps_original_critical(tmp_path, extra):
    _write(tmp_path, extra)
    result = security_scan(tmp_path, cache_enabled=False)
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["line"] == 3
    assert not _secrets(result, primitive=True)


def test_source_change_invalidates_both_context_and_role_projection(tmp_path):
    _write(tmp_path)
    first = security_scan(tmp_path, cache_enabled=True)
    assert len(_secrets(first, primitive=True)) == 1
    _write(tmp_path, "    def escape(self):\n        consume(self.ACCESS_TOKEN_URL)\n")
    second = security_scan(tmp_path, cache_enabled=True)
    assert len(_secrets(second)) == 1
    assert not _secrets(second, primitive=True)


def test_real_credential_positive_is_retained_at_original_priority(tmp_path):
    _write(tmp_path, "PASSWORD = 'synthetic-fixed-credential-control'\n")
    result = security_scan(tmp_path, cache_enabled=False)
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["facts"]["name"] == "PASSWORD"
    assert alerts[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "mutation",
    [
        "requests.get = supplied",
        "setattr(requests, 'get', supplied)",
    ],
)
def test_mutated_http_provider_cannot_supply_endpoint_proof(tmp_path, mutation):
    _write(tmp_path, mutation + "\n")
    result = security_scan(tmp_path, cache_enabled=False)
    assert len(_secrets(result)) == 1
    assert not _secrets(result, primitive=True)


def test_omitted_oversized_auth_consumer_keeps_original_credential_alert(
    tmp_path, monkeypatch
):
    from factoryline import review_audits as scanner

    _write(tmp_path)
    monkeypatch.setattr(scanner, "MAX_BYTES", 500)
    hidden = "from client import Client\n" + "#" * 501 + "\n"
    hidden += (
        "import requests\nrequests.get('https://other.example', "
        "auth=('u', Client.ACCESS_TOKEN_URL))\n"
    )
    (tmp_path / "hidden.py").write_text(hidden, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=False)
    assert result["audit_coverage"]["complete"] is False
    alerts = _secrets(result)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert not _secrets(result, primitive=True)
