"""Candidate-linked unsupported shapes must retain the credential heuristic."""

import pytest

from factoryline.review_audits import security_scan


@pytest.mark.parametrize(
    "extra",
    [
        "aliases = [Client]\n"
        "requests.get('https://example.test', auth=('u', aliases[0].ACCESS_TOKEN_URL))\n",
        "registry = {'client': Client}\nconsume(registry['client'].ACCESS_TOKEN_URL)\n",
    ],
)
def test_candidate_escape_is_unresolved(tmp_path, extra):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "class Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n"
        "        requests.get(self.ACCESS_TOKEN_URL)\n" + extra,
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in result["findings"])


def test_local_provider_mutation_cannot_supply_url_role(tmp_path):
    (tmp_path / "app.py").write_text(
        "class Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n"
        "        import requests as local\n"
        "        local.get = supplied\n"
        "        local.get(self.ACCESS_TOKEN_URL)\n",
        encoding="utf-8",
    )
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(f["code"] == "SECURITY_HARDCODED_SECRET" for f in result["findings"])
