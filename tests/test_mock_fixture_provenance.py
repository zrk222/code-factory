from __future__ import annotations

from factoryline.review_audits import security_scan


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
