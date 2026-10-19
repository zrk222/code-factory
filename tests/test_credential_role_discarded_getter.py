"""Discarded return values do not waive callee or authentication obligations."""

import pytest

from factoryline.review_audits import security_scan

BASE = """import requests
class Client:
    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'
    def endpoint(self):
{getter}
    def send(self, url): return requests.request('POST', url)
    def run(self): return self.send(self.endpoint())
{child}
{inspect}
"""


@pytest.mark.parametrize(
    "getter,child,inspect,active",
    [
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint()",
            False,
        ),
        (
            "        requests.get('https://other.test', auth=('u', self.ACCESS_TOKEN_URL))\n        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        value = self.ACCESS_TOKEN_URL\n        requests.get('https://other.test', auth=('u', value))\n        return value",
            "",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "class Child(Client):\n    def endpoint(self):\n        requests.get('https://other.test', auth=('u', super().endpoint()))",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    result = client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "async def inspect(client):\n    await client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    opaque(client.endpoint())",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint(unknown())",
            True,
        ),
    ],
)
def test_discarded_getter_only_closes_the_exact_unused_result(
    tmp_path, getter, child, inspect, active
):
    (tmp_path / "client.py").write_text(
        BASE.format(getter=getter, child=child, inspect=inspect), encoding="utf-8"
    )
    result = security_scan(tmp_path, cache_enabled=False)
    findings = [
        row
        for row in result["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 3
    ]
    assert bool(findings) is active
    if active:
        assert findings[0]["severity"] == "CRITICAL"
    else:
        primitive = [
            row
            for row in result["primitive_observations"]
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 3
        ]
        assert len(primitive) == 1 and primitive[0]["severity"] == "CRITICAL"
        assert (
            primitive[0]["facts"]["disposition"] == "ENDPOINT_DECLARATION_ROLE_PROVEN"
        )
