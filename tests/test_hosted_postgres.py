from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest

from factoryline.hosted_storage import PostgresAssuranceStore
from factoryline.hosted_control import PostgresControlStore
from factoryline.control_plane import Principal
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


def test_postgres_control_plane_binds_tenant_identity_state_audit_and_redacted_overview():
    assurance = PostgresAssuranceStore(DSN)
    assurance.initialize()
    control = PostgresControlStore(assurance)
    control.initialize()
    platform = Principal("platform-owner", "*", ("platform_admin",))
    tenant = control.create_tenant(platform, "integration-control", "Integration Control")
    assert tenant.get("tenant_id") == "integration-control"
    control.configure_identity(
        platform, "integration-control", issuer="https://id.integration.test",
        audience="factory", jwks_url="https://id.integration.test/jwks",
    )
    with assurance._transaction("different-tenant") as (_db, cursor):
        cursor.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='factory_rls_test') "
            "THEN CREATE ROLE factory_rls_test NOLOGIN; END IF; END $$"
        )
        cursor.execute("GRANT SELECT ON factory_tenant_identity TO factory_rls_test")
        cursor.execute("SET LOCAL ROLE factory_rls_test")
        cursor.execute(
            "SELECT tenant_id FROM factory_tenant_identity WHERE tenant_id=%s",
            ("integration-control",),
        )
        assert cursor.fetchone() is None
    control.replace_roles(platform, "integration-control", {"release": "approver", "owners": "admin"})
    control.set_secret_reference(
        platform, "integration-control", "github_webhook", "env://FACTORY_INTEGRATION_WEBHOOK"
    )
    issued = control.issue_state(platform, "integration-control")
    bound = control.bind_installation(issued["state"], 99002)
    assert bound["tenant_id"] == "integration-control"
    with pytest.raises(PRAssuranceError) as replay:
        control.bind_installation(issued["state"], 99002)
    assert replay.value.code == "E_INSTALLATION_STATE"
    expiring = control.issue_state(platform, "integration-control")
    control.clock = lambda: datetime.now(timezone.utc) + timedelta(seconds=601)
    with pytest.raises(PRAssuranceError) as expired:
        control.bind_installation(expiring["state"], 99003)
    assert expired.value.code == "E_INSTALLATION_STATE"
    overview = control.overview(platform, "integration-control")
    assert overview["audit"]["valid"] is True
    assert 99002 in overview["installation_ids"]
    assert overview["secret_purposes"] == ["github_webhook"]
    assert "env://" not in str(overview)
    tenant_admin = Principal("tenant-admin", "integration-control", ("admin",))
    with pytest.raises(PRAssuranceError) as boundary:
        control.configure_identity(
            tenant_admin, "integration-other", issuer="https://id.other.test",
            audience="factory", jwks_url="https://id.other.test/jwks",
        )
    assert boundary.value.code == "E_TENANT_BOUNDARY"
