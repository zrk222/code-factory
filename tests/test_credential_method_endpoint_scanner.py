"""Exercise method-value admission through the actual scanner and native partition."""

import pytest

from factoryline.review_audits import security_scan

URL = "https://appleid.apple.com/auth/token"


def _scan(tmp_path, getter, extra="", cache=False):
    source = (
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {URL!r}\n"
        "    def endpoint(self):\n" + getter + "    def send(self, url):\n"
        "        return requests.request('POST', url)\n"
        "    def run(self):\n"
        "        return self.send(self.endpoint())\n" + extra
    )
    path = tmp_path / "client.py"
    path.write_text(source, encoding="utf-8")
    result = security_scan(tmp_path, cache_enabled=cache)
    alerts = [
        f
        for f in result["findings"]
        if f["code"] == "SECURITY_HARDCODED_SECRET" and f["line"] == 3
    ]
    observations = [
        f
        for f in result.get("primitive_observations", [])
        if f["code"] == "SECURITY_HARDCODED_SECRET" and f["line"] == 3
    ]
    return alerts, observations


@pytest.mark.parametrize("cache", [False, True])
@pytest.mark.parametrize(
    "getter",
    [
        "        return self.ACCESS_TOKEN_URL\n",
        "        return None or self.ACCESS_TOKEN_URL\n",
    ],
)
def test_public_endpoint_method_return_has_exact_scanner_partition(
    tmp_path, cache, getter
):
    alerts, observations = _scan(tmp_path, getter, cache=cache)
    assert not alerts
    assert len(observations) == 1
    assert observations[0]["severity"] == "CRITICAL"
    assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"
    assert observations[0]["facts"]["credential_safety"] == "UNASSESSED"


@pytest.mark.parametrize(
    "getter,extra",
    [
        (
            "        url = self.ACCESS_TOKEN_URL\n        opaque(url)\n        return url\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def leak(self):\n        return opaque(self.endpoint())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "class Child(Client):\n    def leak(self):\n        return opaque(self.endpoint())\n",
        ),
        (
            "        url = self.ACCESS_TOKEN_URL\n        return url.format(**opaque(url))\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def leak(self):\n        getter = self.endpoint\n        return opaque(getter())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "opaque(Client().endpoint())\n",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "def leak(client):\n    return opaque(client.endpoint())\nleak(Client())\n",
        ),
        (
            "        return opaque(self.ACCESS_TOKEN_URL) or self.ACCESS_TOKEN_URL\n",
            "",
        ),
        (
            "        return self.ACCESS_TOKEN_URL\n",
            "    def invoke_leak(self):\n        return leak(self)\n"
            "def leak(client):\n    return opaque(client.endpoint())\n",
        ),
    ],
)
def test_opaque_candidate_value_uses_retain_original_priority(tmp_path, getter, extra):
    alerts, observations = _scan(tmp_path, getter, extra)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert not observations
