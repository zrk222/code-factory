from __future__ import annotations

import os

import pytest

from factoryline.hosted_storage import PostgresAssuranceStore
from factoryline.pr_assurance import PRAssuranceError


DSN = os.getenv("FACTORY_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="FACTORY_TEST_POSTGRES_DSN is required")


def test_postgres_installation_binding_is_immutable_and_ready():
    store = PostgresAssuranceStore(DSN)
    store.initialize()
    assert store.ping() is True
    store.register_installation("integration-a", 99001)
    assert store.tenant_for_installation(99001) == "integration-a"
    with pytest.raises(PRAssuranceError) as error:
        store.register_installation("integration-b", 99001)
    assert error.value.code == "E_INSTALLATION_TENANT"
