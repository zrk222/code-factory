from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import uuid

import pytest

from factoryline.hosted_storage import PostgresAssuranceStore
from factoryline.hosted_control import PostgresControlStore
from factoryline.control_plane import ControlPlaneError, Principal
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
    tenant = control.create_tenant(
        platform, "integration-control", "Integration Control"
    )
    assert tenant.get("tenant_id") == "integration-control"
    control.configure_identity(
        platform,
        "integration-control",
        issuer="https://id.integration.test",
        audience="factory",
        jwks_url="https://id.integration.test/jwks",
    )
    workflow_operator = Principal(
        "workflow-operator", "integration-control", ("operator",)
    )
    workflow_approver = Principal(
        "workflow-approver", "integration-control", ("approver",)
    )
    workflow_binding = {"run_id": "rls-seeded"}
    workflow_evidence = control.put(
        workflow_operator,
        {
            "schema": "factory.workflow-approval.v1",
            "tenant_id": "integration-control",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
            "phase_evidence": workflow_binding,
        },
        evidence_id="rls-workflow-evidence",
    )
    workflow_approval = control.request_approval(
        workflow_operator,
        "integration-control",
        workflow_evidence["evidence_id"],
        "seed workflow rows for RLS verification",
    )
    control.decide_approval(
        workflow_approver,
        "integration-control",
        workflow_approval["approval_id"],
        "approved",
        "independent test approval",
    )
    control.workflow_approval_verifier(
        workflow_operator,
        "integration-control",
        workflow_approval["approval_id"],
        resolve_principal=lambda subject, tenant: workflow_approver
        if subject == workflow_approver.subject
        else workflow_operator,
    )(workflow_binding)
    with assurance._transaction("different-tenant") as (_db, cursor):
        cursor.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='factory_rls_test') "
            "THEN CREATE ROLE factory_rls_test NOLOGIN; END IF; END $$"
        )
        for table in (
            "factory_tenant_identity",
            "factory_workflow_evidence",
            "factory_workflow_approvals",
            "factory_workflow_approval_uses",
            "factory_hosted_repairs",
        ):
            cursor.execute(f"GRANT SELECT ON {table} TO factory_rls_test")
        cursor.execute("SET LOCAL ROLE factory_rls_test")
        for table in (
            "factory_tenant_identity",
            "factory_workflow_evidence",
            "factory_workflow_approvals",
            "factory_workflow_approval_uses",
            "factory_hosted_repairs",
        ):
            cursor.execute(
                f"SELECT tenant_id FROM {table} WHERE tenant_id=%s",
                ("integration-control",),
            )
            assert cursor.fetchone() is None
    control.replace_roles(
        platform, "integration-control", {"release": "approver", "owners": "admin"}
    )
    control.set_secret_reference(
        platform,
        "integration-control",
        "github_webhook",
        "env://FACTORY_INTEGRATION_WEBHOOK",
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
            tenant_admin,
            "integration-other",
            issuer="https://id.other.test",
            audience="factory",
            jwks_url="https://id.other.test/jwks",
        )
    assert boundary.value.code == "E_TENANT_BOUNDARY"


def test_postgres_workflow_approval_keeps_evidence_independent_and_exactly_replayable():
    assurance = PostgresAssuranceStore(DSN)
    assurance.initialize()
    control = PostgresControlStore(assurance)
    control.initialize()
    platform = Principal("workflow-platform", "*", ("platform_admin",))
    tenant_id = "workflow-" + uuid.uuid4().hex[:12]
    control.create_tenant(platform, tenant_id, "Workflow approval integration")
    requester = Principal("repair-requester", tenant_id, ("operator",))
    approver = Principal("independent-approver", tenant_id, ("approver",))
    expected = {"candidate_sha256": "a" * 64, "phase": "repair.dispatch"}
    payload = {
        "schema": "factory.workflow-approval.v1",
        "tenant_id": tenant_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "phase_evidence": expected,
        "verdict": "APPROVED_FOR_REVIEW",
    }
    evidence = control.put(requester, payload, evidence_id="repair-evidence")
    assert evidence["payload_sha256"]
    with pytest.raises(ControlPlaneError) as immutable:
        control.put(
            requester,
            {**payload, "phase_evidence": {"phase": "changed"}},
            evidence_id="repair-evidence",
        )
    assert immutable.value.code == "E_EVIDENCE_IMMUTABLE"

    approval = control.request_approval(
        requester, tenant_id, evidence["evidence_id"], "dispatch exact repair"
    )
    control.decide_approval(
        approver, tenant_id, approval["approval_id"], "approved", "independent review"
    )

    def resolve(subject, resolved_tenant):
        assert resolved_tenant == tenant_id
        return approver if subject == approver.subject else requester

    verifier = control.workflow_approval_verifier(
        requester,
        tenant_id,
        approval["approval_id"],
        resolve_principal=resolve,
        require_requester=True,
    )
    with ThreadPoolExecutor(max_workers=8) as workers:
        outcomes = list(workers.map(lambda _index: verifier(expected), range(8)))
    assert outcomes == [expected] * 8
    with assurance._transaction(tenant_id) as (_db, cursor):
        cursor.execute(
            "SELECT count(*) FROM factory_admin_audit "
            "WHERE tenant_id=%s AND action='approval.workflow.consume' AND resource_id=%s",
            (tenant_id, approval["approval_id"]),
        )
        assert cursor.fetchone()[0] == 1
    with pytest.raises(ControlPlaneError) as changed_binding:
        verifier({**expected, "phase": "different"})
    assert changed_binding.value.code == "E_APPROVAL_EVIDENCE"
    with assurance._transaction(tenant_id) as (_db, cursor):
        cursor.execute(
            "UPDATE factory_workflow_approval_uses SET fingerprint=%s "
            "WHERE tenant_id=%s AND approval_id=%s",
            ("0" * 64, tenant_id, approval["approval_id"]),
        )
    with pytest.raises(ControlPlaneError) as changed_replay:
        verifier(expected)
    assert changed_replay.value.code == "E_APPROVAL_REPLAY"

    expired_payload = {
        **payload,
        "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        "phase_evidence": {"candidate_sha256": "b" * 64},
    }
    expired_evidence = control.put(
        requester, expired_payload, evidence_id="expired-repair-evidence"
    )
    expired_approval = control.request_approval(
        requester,
        tenant_id,
        expired_evidence["evidence_id"],
        "expired dispatch test",
    )
    control.decide_approval(
        approver,
        tenant_id,
        expired_approval["approval_id"],
        "approved",
        "test approval",
    )
    expired_verifier = control.workflow_approval_verifier(
        requester,
        tenant_id,
        expired_approval["approval_id"],
        resolve_principal=resolve,
        require_requester=True,
    )
    with pytest.raises(ControlPlaneError) as expired_binding:
        expired_verifier(expired_payload["phase_evidence"])
    assert expired_binding.value.code == "E_APPROVAL_EVIDENCE"
    assert control.overview(platform, tenant_id)["audit"]["valid"] is True


def test_postgres_hosted_repair_registry_is_tenant_scoped_immutable_and_single_use():
    assurance = PostgresAssuranceStore(DSN)
    assurance.initialize()
    control = PostgresControlStore(assurance)
    control.initialize()
    platform = Principal("repair-registry-platform", "*", ("platform_admin",))
    tenant = "repair-registry-" + uuid.uuid4().hex[:12]
    control.create_tenant(platform, tenant, "Repair Registry Test")
    binding = {"schema": "factory.repair.dispatch.v1", "candidate_sha256": "a" * 64}
    repair_id = "repair_" + uuid.uuid4().hex
    registration = {
        "tenant_id": tenant,
        "repair_id": repair_id,
        "workspace_path": "workspace",
        "approval_path": "approval.json",
        "workflow_approval_id": "workflow_" + uuid.uuid4().hex[:16],
        "requester": "repair-requester",
        "binding": binding,
        "registered_by": "tenant-admin",
    }
    registered = control.register_hosted_repair(**registration)
    target = control.get_hosted_repair(tenant, repair_id)
    assert target["binding"] == binding
    assert target["binding_sha256"] == registered["binding_sha256"]
    with pytest.raises(PRAssuranceError) as duplicate:
        control.register_hosted_repair(**{**registration, "workspace_path": "other"})
    assert duplicate.value.code == "E_REPAIR_EXISTS"
    with pytest.raises(PRAssuranceError) as cross_tenant:
        control.get_hosted_repair("different-tenant", repair_id)
    assert cross_tenant.value.code == "E_REPAIR_NOT_FOUND"
    control.claim_hosted_repair(tenant, repair_id, "repair-requester")
    with pytest.raises(PRAssuranceError) as replay:
        control.claim_hosted_repair(tenant, repair_id, "repair-requester")
    assert replay.value.code == "E_REPAIR_REPLAY"
    control.finish_hosted_repair(
        tenant, repair_id, succeeded=True, actor="repair-requester"
    )
