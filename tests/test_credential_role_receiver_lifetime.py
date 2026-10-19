"""Native scanner controls for class identity after local construction."""

import pytest

from factoryline.review_audits import security_scan

BASE = """import requests
class Candidate:
    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'
    def endpoint(self): return self.ACCESS_TOKEN_URL
    def send(self, url): return requests.request('POST', url)
    def run(self): return self.send(self.endpoint())
class Other(Candidate):
    ACCESS_TOKEN_URL = None
{methods}
def inspect():
    backend = Other()
{effects}
    return opaque(backend.endpoint())
"""


@pytest.mark.parametrize(
    "methods,effects,active",
    [
        ("", "", False),
        ("    def harmless(self): self.data = {}", "    backend.harmless()", False),
        (
            "    def morph(self): self.__class__ = Candidate",
            "    backend.morph()",
            True,
        ),
        ("    def __init__(self): self.__class__ = Candidate", "", True),
        ("    def __init__(self): super().__init__()", "", True),
        (
            "    def morph(self): locals()['self'].__class__ = Candidate",
            "    backend.morph()",
            True,
        ),
        (
            "    def morph(self): eval(\"setattr(self, '__class__', Candidate)\")",
            "    backend.morph()",
            True,
        ),
        ("    def morph(self): hidden_frame_mutation()", "    backend.morph()", True),
        ("", "    mutate(backend)", True),
        ("", "    alias = backend\n    alias.__class__ = Candidate", True),
        ("", "    saved = [backend]\n    saved[0].__class__ = Candidate", True),
        ("", "    backend.__class__ = Candidate", True),
        ("    def __getattribute__(self, name): return evil(name)", "", True),
        (
            "    @property\n    def data(self): return None\n"
            "    @data.setter\n    def data(self, value): self.__class__ = Candidate\n"
            "    def harmless(self): self.data = None",
            "    backend.harmless()",
            True,
        ),
    ],
)
def test_native_receiver_identity_changes_preserve_critical(
    tmp_path, methods, effects, active
):
    source = BASE.format(methods=methods, effects=effects)
    if "super().__init__()" in methods:
        source = source.replace(
            "class Candidate:\n",
            "class Candidate:\n    def __init__(self): self.__class__ = Candidate\n",
        )
    (tmp_path / "client.py").write_text(
        source,
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET" and item["path"] == "client.py"
    ]
    assert bool(findings) is active
    if active:
        assert findings[0]["severity"] == "CRITICAL"
    else:
        observations = [
            item
            for item in result.get("primitive_observations", [])
            if item["code"] == "SECURITY_HARDCODED_SECRET"
            and item["path"] == "client.py"
        ]
        assert len(observations) == 1 and observations[0]["severity"] == "CRITICAL"
