import ast
import pytest

from factoryline.review_audits import _security_aliases
from factoryline.semantic_credential_sensor import (
    configuration_and_credential_findings,
    credential_findings,
)


def _scan(source):
    tree = ast.parse(source)
    return credential_findings(
        tree, _security_aliases(list(ast.walk(tree))), "sample.py"
    )


def test_reports_literal_http_auth_and_authorization_without_exposing_values():
    findings = _scan(
        "import requests as r\n"
        "import httpx\n"
        "r.get('https://api.example.test', auth=('name', 'p@ss-value'))\n"
        "httpx.Client().post('https://api.example.test', headers={'Authorization': 'Bearer abc-token'})\n"
        "r.get('https://api.example.test', headers={'authorization': 'Basic QWxwaGE='})\n"
    )
    assert len(findings) == 3
    assert {item["facts"]["consumer_role"] for item in findings} == {
        "http_auth",
        "http_header",
    }
    assert all(item["severity"] == "MEDIUM" for item in findings)
    assert all(
        item["facts"]["source_role"] == "credential_literal" for item in findings
    )
    assert all(
        item["facts"]["proof_scope"] == "local_static_wiring" for item in findings
    )
    assert all(
        "p@ss-value" not in repr(item) and "abc-token" not in repr(item)
        for item in findings
    )


def test_reports_direct_basic_auth_password_and_ignores_username_only():
    findings = _scan(
        "from requests.auth import HTTPBasicAuth as Basic\n"
        "Basic('user', 'direct-password')\n"
        "import requests\n"
        "requests.get('https://host.test', auth=('only-user', ''))\n"
        "requests.get('https://host.test', auth=('user', 'your-'))\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["credential_slot"] == "password"


def test_ignores_urls_schemes_placeholders_and_noncanonical_calls():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer '})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer ${TOKEN}'})\n"
        "fake.get('https://host.test', headers={'Authorization': 'Bearer abc-token'})\n"
        "def send(requests):\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    assert findings == []


def test_detects_http_url_userinfo_without_retaining_the_url_or_password():
    findings = _scan(
        "import requests\n"
        "requests.get('https://name:secret-value@host.test/path')\n"
        "requests.get('https://host.test/path')\n"
        "requests.get('https://name@host.test/path')\n"
        "requests.get('https://:secret-value@host.test/path')\n"
        "requests.get(dynamic_url)\n"
        "requests.post(ACCESS_TOKEN_URL)\n"
        "requests.get('http://[malformed')\n"
        "fake.get('https://name:secret-value@host.test/path')\n"
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["facts"]["consumer_role"] == "http_url_userinfo"
    assert finding["facts"]["credential_slot"] == "userinfo_password"
    assert "host.test" not in repr(finding)
    assert "secret-value" not in repr(finding)


def test_basic_auth_keyword_binding_requires_exact_valid_call_shape():
    findings = _scan(
        "from requests.auth import HTTPBasicAuth\n"
        "HTTPBasicAuth(username='name', password='keyword-password')\n"
        "HTTPBasicAuth('name', 'positional-password', password='invalid-duplicate')\n"
        "HTTPBasicAuth(username='name', password='placeholder')\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["credential_slot"] == "password"


def test_authorization_header_duplicates_use_python_last_value_and_unknown_expansions():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer old-token', 'authorization': 'Bearer live-token'})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-token', 'authorization': dynamic_value})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-token', **extra})\n"
    )
    assert len(findings) == 1
    assert findings[0]["facts"]["consumer_role"] == "http_header"
    assert "old-token" not in repr(findings[0])
    assert "live-token" not in repr(findings[0])


def test_authorization_headers_resolve_exact_dict_keys_before_casefold_merge():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer upper-old', 'authorization': 'Bearer lower-final'})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-exact', 'Authorization': dynamic_value})\n"
        "requests.get('https://host.test', headers={'Authorization': 'Bearer hidden-upper', 'authorization': dynamic_value, 'Authorization': 'Bearer hidden-final'})\n"
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert "upper-old" not in repr(findings[0])
    assert "lower-final" not in repr(findings[0])


def test_shadowed_import_and_parameter_are_not_canonical_http_sinks():
    findings = _scan(
        "import requests as client\n"
        "client = fake\n"
        "client.get('https://host.test', headers={'Authorization': 'Bearer literal-token'})\n"
        "def send(requests):\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    assert findings == []


@pytest.mark.parametrize(
    "mutation",
    [
        "requests.get = fake_get",
        "setattr(requests.auth, 'HTTPBasicAuth', fake_auth)",
        "saved_provider = requests",
        "requests.auth.HTTPBasicAuth = fake_auth",
        "httpx.Client = FakeClient",
    ],
)
def test_each_provider_mutation_vetoes_http_credential_proof(mutation):
    findings = _scan(
        "import requests\n"
        "import httpx\n"
        f"{mutation}\n"
        "def later():\n"
        "    requests.get('https://host.test', auth=('user', 'literal-password'))\n"
        "    requests.auth.HTTPBasicAuth('user', 'literal-password')\n"
        "    httpx.Client().post('https://host.test', headers={'Authorization': 'Bearer token-value'})\n"
    )
    assert findings == []


def test_your_prefixed_literal_is_not_a_new_placeholder_waiver():
    findings = _scan(
        "import requests\n"
        "requests.get('https://host.test', auth=('user', 'your-password'))\n"
    )
    assert len(findings) == 1


def test_combined_sensor_returns_configuration_and_credential_findings():
    tree = ast.parse(
        "from jinja2 import Environment\n"
        "env = Environment(autoescape=False)\n"
        "env.get_template('page.html')\n"
        "import httpx\n"
        "httpx.get('https://host.test', auth=('user', 'literal-password'))\n"
    )
    findings = configuration_and_credential_findings(
        tree, _security_aliases(list(ast.walk(tree))), "sample.py"
    )
    assert {item["code"] for item in findings} == {
        "SECURITY_JINJA_AUTOESCAPE_DISABLED",
        "SECURITY_LITERAL_HTTP_CREDENTIAL",
    }
