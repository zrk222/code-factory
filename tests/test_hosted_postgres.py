from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
import os
import uuid

import pytest

from factoryline.hosted_storage import PostgresAssuranceStore
from factoryline.hosted_control import PostgresControlStore
from factoryline.control_plane import ControlPlaneError, Principal, canonical_json
from factoryline.pr_assurance import PRAssuranceError, PullRequestEvent


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


def _postgres_delivery_fixture(prefix="delivery-retry"):
    store = PostgresAssuranceStore(DSN)
    store.initialize()
    tenant_id = f"{prefix}-{uuid.uuid4().hex[:12]}"
    installation_id = 2_000_000_000 + int(uuid.uuid4().int % 1_000_000_000)
    store.register_installation(tenant_id, installation_id)
    event = PullRequestEvent(
        delivery_id="delivery-" + uuid.uuid4().hex,
        repository="acme/assurance",
        pull_request=17,
        installation_id=installation_id,
        head_sha="a" * 40,
        actor="integration-actor",
        action="synchronize",
        payload_sha256=hashlib.sha256(b"authenticated webhook body").hexdigest(),
    )
    return store, tenant_id, event


def test_postgres_queue_retries_are_idempotent_across_connections_and_default_is_strict():
    store, tenant_id, event = _postgres_delivery_fixture()

    def retry(_index):
        # Each call creates an independent PostgreSQL connection via the store.
        return PostgresAssuranceStore(DSN).ingest(
            tenant_id, event, allow_duplicate=True
        )

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(retry, range(8)))

    assert len({result["approval_id"] for result in results}) == 1
    assert len({result["evidence_sha256"] for result in results}) == 1
    assert sum(result["duplicate"] is False for result in results) == 1
    assert sum(result["duplicate"] is True for result in results) == 7
    assert all(result["event"] == event.to_dict() for result in results)

    with pytest.raises(PRAssuranceError) as strict_replay:
        store.ingest(tenant_id, event)
    assert strict_replay.value.code == "E_WEBHOOK_REPLAY"
    with store._transaction(tenant_id) as (_db, cursor):
        cursor.execute(
            "SELECT count(*), min(approval_status) FROM factory_pr_deliveries "
            "WHERE tenant_id=%s AND delivery_id=%s",
            (tenant_id, event.delivery_id),
        )
        assert cursor.fetchone() == (1, "pending")
        cursor.execute(
            "SELECT count(*) FROM factory_check_outbox WHERE tenant_id=%s",
            (tenant_id,),
        )
        assert cursor.fetchone()[0] == 0


def test_postgres_queue_retry_rejects_changed_bindings_without_disclosure():
    store, tenant_id, event = _postgres_delivery_fixture("delivery-conflict")
    original = store.ingest(tenant_id, event)
    changed_events = (
        replace(event, payload_sha256="b" * 64),
        replace(event, installation_id=event.installation_id + 1),
        replace(event, repository="acme/other"),
        replace(event, pull_request=event.pull_request + 1),
        replace(event, head_sha="c" * 40),
        replace(event, actor="different-actor"),
        replace(event, action="opened"),
    )
    for changed in changed_events:
        with pytest.raises(PRAssuranceError) as conflict:
            store.ingest(tenant_id, changed, allow_duplicate=True)
        expected_code = (
            "E_INSTALLATION_TENANT"
            if changed.installation_id != event.installation_id
            else "E_WEBHOOK_REPLAY"
        )
        assert conflict.value.code == expected_code
        assert original["approval_id"] not in conflict.value.message
        assert original["evidence_sha256"] not in conflict.value.message
        assert event.payload_sha256 not in conflict.value.message

    other_tenant = "delivery-other-" + uuid.uuid4().hex[:12]
    with pytest.raises(PRAssuranceError) as hidden:
        store.ingest(other_tenant, event, allow_duplicate=True)
    assert hidden.value.code == "E_INSTALLATION_TENANT"
    assert original["approval_id"] not in hidden.value.message
    with store._transaction(other_tenant) as (_db, cursor):
        cursor.execute(
            "SELECT approval_id FROM factory_pr_deliveries "
            "WHERE tenant_id=%s AND delivery_id=%s",
            (other_tenant, event.delivery_id),
        )
        assert cursor.fetchone() is None
    with store._transaction(tenant_id) as (_db, cursor):
        cursor.execute(
            "SELECT count(*), min(approval_status) FROM factory_pr_deliveries "
            "WHERE tenant_id=%s AND delivery_id=%s",
            (tenant_id, event.delivery_id),
        )
        assert cursor.fetchone() == (1, "pending")


def test_postgres_queue_retry_after_decision_preserves_approval_and_outbox_state():
    store, tenant_id, event = _postgres_delivery_fixture("delivery-decided")
    original = store.ingest(tenant_id, event)
    approver = Principal("queue-retry-approver", tenant_id, ("approver",))
    decision = store.decide(
        approver,
        original["approval_id"],
        issuer="https://id.integration.test",
        jti=uuid.uuid4().hex,
        decision="approved",
        reason="independent integration approval",
    )

    replay = store.ingest(tenant_id, event, allow_duplicate=True)

    assert replay["duplicate"] is True
    assert replay["approval_id"] == original["approval_id"]
    assert replay["evidence_sha256"] == original["evidence_sha256"]
    with store._transaction(tenant_id) as (_db, cursor):
        cursor.execute(
            "SELECT approval_status, approver, decision_reason "
            "FROM factory_pr_deliveries WHERE tenant_id=%s AND delivery_id=%s",
            (tenant_id, event.delivery_id),
        )
        assert cursor.fetchone() == (
            "approved",
            approver.subject,
            "independent integration approval",
        )
        cursor.execute(
            "SELECT approval_id, state, check_run_id FROM factory_check_outbox "
            "WHERE tenant_id=%s",
            (tenant_id,),
        )
        outbox = cursor.fetchall()
        assert len(outbox) == 1
        assert str(outbox[0][0]) == original["approval_id"]
        assert outbox[0][1:] == ("pending", None)
    assert decision["status"] == "approved"


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


def test_postgres_admin_audit_hashes_are_utc_stable_and_legacy_exact_only():
    assurance = PostgresAssuranceStore(DSN)
    assurance.initialize()
    control = PostgresControlStore(assurance)
    control.initialize()
    platform = Principal("audit-timezone-platform", "*", ("platform_admin",))
    tenant_id = "audit-timezone-" + uuid.uuid4().hex[:12]
    original_clock = control.clock
    control.clock = lambda: datetime(
        2026, 11, 21, 12, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    control.create_tenant(platform, tenant_id, "UTC audit normalization")
    control.clock = original_clock
    original_connect = assurance.connect

    def set_session_timezone(zone):
        def connect(dsn):
            db = original_connect(dsn)
            with db.cursor() as cursor:
                cursor.execute("SELECT set_config('TimeZone', %s, false)", (zone,))
            return db

        assurance.connect = connect

    def overview_in_timezone(zone):
        set_session_timezone(zone)
        return control.overview(platform, tenant_id)

    def audit_row():
        with assurance._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                "SELECT sequence,action,actor,resource_id,payload_json,previous_hash,event_hash,created_at "
                "FROM factory_admin_audit WHERE tenant_id=%s ORDER BY sequence",
                (tenant_id,),
            )
            return cursor.fetchone()

    try:
        original = audit_row()
        assert original is not None
        original_hash, original_payload = str(original[6]), original[4]
        for zone in ("UTC", "America/New_York", "Asia/Kolkata"):
            assert overview_in_timezone(zone)["audit"]["valid"] is True
            assert str(audit_row()[6]) == original_hash

        set_session_timezone("America/New_York")
        legacy = audit_row()
        legacy_event = {
            "schema": "factory.hosted.admin-audit.v1",
            "sequence": int(legacy[0]),
            "tenant_id": tenant_id,
            "action": str(legacy[1]),
            "actor": str(legacy[2]),
            "resource_id": str(legacy[3]),
            "payload": legacy[4],
            "previous_hash": str(legacy[5]),
            "created_at": legacy[7].astimezone(timezone.utc).isoformat(),
        }
        legacy_event["created_at"] = legacy[7].isoformat()
        legacy_hash = hashlib.sha256(canonical_json(legacy_event)).hexdigest()
        with assurance._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                "UPDATE factory_admin_audit SET event_hash=%s WHERE tenant_id=%s AND sequence=%s",
                (legacy_hash, tenant_id, legacy[0]),
            )
        assert overview_in_timezone("America/New_York")["audit"]["valid"] is True
        assert overview_in_timezone("UTC")["audit"]["valid"] is False

        with assurance._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                "UPDATE factory_admin_audit SET event_hash=%s WHERE tenant_id=%s AND sequence=%s",
                (original_hash, tenant_id, legacy[0]),
            )
            cursor.execute(
                "UPDATE factory_admin_audit SET payload_json=%s::jsonb WHERE tenant_id=%s AND sequence=%s",
                (
                    canonical_json({"display_name": "tampered"}).decode(),
                    tenant_id,
                    legacy[0],
                ),
            )
        assert overview_in_timezone("Asia/Kolkata")["audit"]["valid"] is False
    finally:
        with assurance._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                "UPDATE factory_admin_audit SET event_hash=%s,payload_json=%s::jsonb "
                "WHERE tenant_id=%s AND sequence=%s",
                (
                    original_hash,
                    canonical_json(original_payload).decode(),
                    tenant_id,
                    original[0],
                ),
            )
        assurance.connect = original_connect

    assert overview_in_timezone("UTC")["audit"]["valid"] is True
    assurance.connect = original_connect


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


def test_postgres_hosted_repair_session_lock_blocks_active_reconcile_and_releases():
    assurance = PostgresAssuranceStore(DSN)
    control = PostgresControlStore(assurance)
    control.initialize()
    tenant = "repair-lock-" + uuid.uuid4().hex[:12]
    repair_id = "repair_" + uuid.uuid4().hex
    with control.hosted_repair_session_lock(tenant, repair_id):
        with pytest.raises(PRAssuranceError) as busy:
            with control.hosted_repair_session_lock(tenant, repair_id):
                pytest.fail("second session unexpectedly acquired repair guard")
        assert busy.value.code == "E_REPAIR_BUSY"
    with control.hosted_repair_session_lock(tenant, repair_id):
        pass


def _executing_postgres_repair_for_recovery():
    from factoryline.hosted_api import _recovery_result

    assurance = PostgresAssuranceStore(DSN)
    assurance.initialize()
    control = PostgresControlStore(assurance)
    control.initialize()
    platform = Principal("recovery-platform", "*", ("platform_admin",))
    tenant = "repair-recovery-" + uuid.uuid4().hex[:12]
    control.create_tenant(platform, tenant, "Repair Recovery Test")
    repair_id = "repair_" + uuid.uuid4().hex
    binding = {"schema": "factory.repair.dispatch.v1", "candidate_sha256": "a" * 64}
    control.register_hosted_repair(
        tenant_id=tenant,
        repair_id=repair_id,
        workspace_path="workspace",
        approval_path="approval.json",
        workflow_approval_id="workflow_" + uuid.uuid4().hex[:16],
        requester="repair-requester",
        binding=binding,
        registered_by="tenant-admin",
    )
    control.claim_hosted_repair(tenant, repair_id, "repair-requester")
    outcome = _recovery_result(
        repair_id,
        "failed",
        "interrupted",
        "REPAIR_ATTEMPT_MISSING",
        None,
        {"binding_sha256": hashlib.sha256(b"binding").hexdigest()},
    )
    return control, tenant, repair_id, outcome


def test_postgres_hosted_repair_recovery_rejects_identity_mismatch():
    control, tenant, repair_id, outcome = _executing_postgres_repair_for_recovery()
    wrong_id = dict(outcome, repair_id="repair_other_12345678")
    with pytest.raises(PRAssuranceError) as mismatched:
        control.reconcile_hosted_repair(
            tenant, repair_id, actor="tenant-admin", recovery=wrong_id
        )
    assert mismatched.value.code == "E_REPAIR_RECOVERY"
    malformed = dict(outcome, status=[])
    with pytest.raises(PRAssuranceError) as invalid:
        control.reconcile_hosted_repair(
            tenant, repair_id, actor="tenant-admin", recovery=malformed
        )
    assert invalid.value.code == "E_REPAIR_RECOVERY"


def _assert_postgres_recovery_audit_and_scope(control, tenant, repair_id):
    assert control.get_hosted_repair(tenant, repair_id)["status"] == "failed"
    with control._workflow_transaction(tenant) as (_db, cursor):
        cursor.execute(
            """SELECT count(*) FROM factory_admin_audit
               WHERE tenant_id=%s AND action='repair.dispatch.reconcile'
                 AND resource_id=%s""",
            (tenant, repair_id),
        )
        assert cursor.fetchone()[0] == 1
    with pytest.raises(PRAssuranceError) as hidden:
        control.get_hosted_repair(tenant + "-other", repair_id)
    assert hidden.value.code == "E_REPAIR_NOT_FOUND"


def _assert_postgres_recovery_conflict(control, tenant, repair_id):
    from factoryline.hosted_api import _recovery_result

    changed = _recovery_result(
        repair_id,
        "failed",
        "interrupted",
        "REPAIR_JOURNAL_INVALID",
        None,
        {"binding_sha256": hashlib.sha256(b"different").hexdigest()},
    )
    with pytest.raises(PRAssuranceError) as conflict:
        control.reconcile_hosted_repair(
            tenant, repair_id, actor="tenant-admin", recovery=changed
        )
    assert conflict.value.code == "E_REPAIR_RECOVERY_CONFLICT"


def test_postgres_hosted_repair_recovery_is_atomic_idempotent_and_tenant_scoped():
    control, tenant, repair_id, outcome = _executing_postgres_repair_for_recovery()

    def reconcile():
        return control.reconcile_hosted_repair(
            tenant, repair_id, actor="tenant-admin", recovery=outcome
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: reconcile(), range(2)))
    assert results == [outcome, outcome]
    _assert_postgres_recovery_audit_and_scope(control, tenant, repair_id)
    _assert_postgres_recovery_conflict(control, tenant, repair_id)
