from pathlib import Path
from textwrap import dedent

import pytest

from factoryline.cli import _build_parser
from factoryline.cli_audit import prepare_bounded_security_report


_FILES = {
    "manage.py": """
        import os
        import sys
        from django.core.management import execute_from_command_line

        def main():
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
            execute_from_command_line(sys.argv)

        if __name__ == '__main__':
            main()
    """,
    "config/__init__.py": "",
    "config/settings.py": """
        import os
        INSTALLED_APPS = ['django.contrib.auth', 'rest_framework']
        MIDDLEWARE = []
        ROOT_URLCONF = 'config.urls'
        DATABASES = {'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'HOST': os.getenv('POSTGRES_HOST'),
            'PORT': os.getenv('POSTGRES_PORT', '5432'),
        }}
    """,
    "config/urls.py": """
        from django.urls import path
        from rest_framework_simplejwt.views import TokenObtainPairView
        urlpatterns = [path('auth/token/', TokenObtainPairView.as_view())]
    """,
    "tests/__init__.py": "",
    "tests/base.py": """
        from django.contrib.auth import get_user_model
        from rest_framework.test import APITestCase

        class AccountFixture(APITestCase):
            password = 'synthetic-test-account-value'

            @classmethod
            def setUpTestData(cls):
                cls.user = get_user_model().objects.create_user(
                    username='example', email='user@example.invalid', password=cls.password,
                )

            def setUp(self):
                self.client.force_authenticate(self.user)
    """,
    "tests/test_authentication.py": """
        from .base import AccountFixture

        class AccountTests(AccountFixture):
            def test_login(self):
                self.client.force_authenticate(user=None)
                response = self.client.post(
                    '/auth/token/', {'username': self.user.username, 'password': self.password},
                    format='json',
                )
                self.assertEqual(response.status_code, 200)
    """,
    ".github/workflows/ci.yml": """
        name: CI
        on: pull_request
        env:
          DJANGO_SETTINGS_MODULE: config.settings
          POSTGRES_HOST: 127.0.0.1
          POSTGRES_PORT: "5432"
          POSTGRES_DB: example_test
          POSTGRES_USER: example_test
          POSTGRES_PASSWORD: synthetic-ci-only
        jobs:
          test:
            runs-on: ubuntu-24.04
            services:
              postgres:
                image: postgres:17-alpine
                ports:
                  - 5432:5432
                env:
                  POSTGRES_DB: example_test
                  POSTGRES_USER: example_test
                  POSTGRES_PASSWORD: synthetic-ci-only
            steps:
              - run: python manage.py test
    """,
}


@pytest.mark.parametrize(
    "mutation",
    [
        "closed",
        "runtime-import",
        "external-request",
        "database-route",
        "custom-signer",
        "serializer-override",
        "parser-override",
        "database-options",
        "aliased-receiver",
        "route-list-mutation",
        "alternate-runner",
        "alternate-runner-same-job",
        "alternate-pytest",
        "alternate-py-test",
        "unproven-runner-script",
        "quoted-runner-script",
        "uncaptured-reusable-job",
        "root-include",
        "definition-time-read",
        "definition-time-namespace",
        "middleware-mutation",
        "middleware-dispatch-hook",
        "assigned-setup",
    ],
)
def test_drf_fixture_requires_replayed_account_and_consumer_closure(tmp_path, mutation):
    files = {name: dedent(source).lstrip() for name, source in _FILES.items()}
    if mutation == "runtime-import":
        files["runtime.py"] = "from tests.base import AccountFixture\n"
    elif mutation == "external-request":
        files["tests/test_authentication.py"] = files[
            "tests/test_authentication.py"
        ].replace("'/auth/token/'", "'https://example.invalid/auth/token/'")
    elif mutation == "database-route":
        files["config/settings.py"] = files["config/settings.py"].replace(
            "os.getenv('POSTGRES_HOST')", "'external-db.invalid'"
        )
    elif mutation == "custom-signer":
        files["config/settings.py"] += "TEST_RUNNER = 'config.custom.DiscoverRunner'\n"
    elif mutation == "serializer-override":
        files["config/settings.py"] += (
            "SIMPLE_JWT = {}\nSIMPLE_JWT['TOKEN_OBTAIN_SERIALIZER'] = 'config.custom.Serializer'\n"
        )
    elif mutation == "parser-override":
        files["config/settings.py"] += (
            "REST_FRAMEWORK = {'DEFAULT_PARSER_CLASSES': ['config.custom.Parser']}\n"
        )
    elif mutation == "database-options":
        files["config/settings.py"] = files["config/settings.py"].replace(
            "'HOST':", "'OPTIONS': {'hostaddr': 'external-db.invalid'},\n    'HOST':"
        )
    elif mutation == "aliased-receiver":
        files["tests/test_authentication.py"] += (
            "\n    def test_other(account):\n        receive(account)\n"
        )
    elif mutation == "route-list-mutation":
        files["config/urls.py"] += "\nreplace_routes(urlpatterns)\n"
    elif mutation == "alternate-runner":
        files[".github/workflows/other.yml"] = (
            "jobs:\n  other:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python manage.py test --keepdb\n"
        )
    elif mutation == "alternate-runner-same-job":
        files[".github/workflows/ci.yml"] += (
            "      - run: python manage.py test --keepdb\n"
        )
    elif mutation == "alternate-pytest":
        files[".github/workflows/other.yml"] = (
            "jobs:\n  verification:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python -m pytest\n"
        )
    elif mutation == "alternate-py-test":
        files[".github/workflows/ci.yml"] += "      - run: py.test\n"
    elif mutation == "unproven-runner-script":
        files[".github/workflows/ci.yml"] += "      - run: bash ./ci/verify.sh\n"
    elif mutation == "quoted-runner-script":
        files[".github/workflows/ci.yml"] += '      - run: bash "./ci/verify.sh"\n'
    elif mutation == "uncaptured-reusable-job":
        files[".github/workflows/other.yml"] = (
            "jobs:\n  verification:\n    uses: ./.github/workflows/missing.yml\n"
        )
    elif mutation == "root-include":
        files["config/urls.py"] = (
            files["config/urls.py"]
            .replace("import path", "import include, path")
            .replace(
                "urlpatterns = [", "urlpatterns = [path('', include('config.other')), "
            )
        )
    elif mutation == "definition-time-read":
        files["tests/base.py"] = files["tests/base.py"].replace(
            "    @classmethod", "    observed = observe(password)\n\n    @classmethod"
        )
    elif mutation == "definition-time-namespace":
        files["tests/base.py"] = files["tests/base.py"].replace(
            "    @classmethod", "    observe(locals())\n\n    @classmethod"
        )
    elif mutation == "middleware-mutation":
        files["config/settings.py"] += (
            "\nactive = MIDDLEWARE\nactive.append('config.other.Custom')\n"
        )
    elif mutation == "middleware-dispatch-hook":
        files["config/settings.py"] = files["config/settings.py"].replace(
            "MIDDLEWARE = []", "MIDDLEWARE = ['config.middleware.Logger']"
        )
        files["config/middleware.py"] = (
            "class Logger:\n"
            "    def __init__(self, get_response):\n"
            "        self.get_response = get_response\n"
            "    def __call__(self, request):\n"
            "        return self.get_response(request)\n"
            "    def process_view(self, request, view, args, kwargs):\n"
            "        record(request.body)\n"
        )
    elif mutation == "assigned-setup":
        files["tests/test_authentication.py"] += "\n    setUp = replacement\n"

    for relative, source in files.items():
        path = tmp_path / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    args = _build_parser().parse_args(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            "source-role-v3",
            "--json",
        ]
    )
    report = prepare_bounded_security_report(args)
    assert report["audit_coverage"]["complete"] is True
    assert report["finding_conservation"]["state"] == "PASS"
    ledger = [row["raw_finding"] for row in report["finding_tier_report"]["ledger"]]
    raw = [
        row
        for row in ledger
        if row["path"] == "tests/base.py" and row["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    if mutation == "closed":
        assert not raw
        [refuted] = [
            row
            for row in report["refuted_security_observations"]
            if row["path"] == "tests/base.py"
        ]
        proof = refuted["facts"]["fixture_evidence"]
        assert proof["fixture_contract"] == "DRF_CLASS_ACCOUNT_LIFECYCLE"
        assert [row["role"] for row in proof["consumer_use_closure"]["uses"]] == [
            "fresh_account_password",
            "test_client_password",
        ]
    else:
        assert len(raw) == 1
