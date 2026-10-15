"""Provider-neutral identity and SCM claim adapters.

These adapters normalize already-verified claims into the control-plane
contract. They intentionally do not verify JWTs or webhook signatures; doing
that requires provider-specific key discovery and deployment configuration.
Failing closed when the caller omits a verification marker prevents a raw
webhook or unsigned header from becoming an authority decision.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
import base64
from pathlib import Path
from typing import Any, Iterable

from .control_plane import ControlPlaneError, Principal, canonical_json


SUPPORTED_SCM_PROVIDERS = frozenset({"github", "gitlab", "azure_devops"})


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ControlPlaneError(
            "E_IDENTITY_CLAIM", f"verified claim {name} is required"
        )
    return value.strip()


def roles_from_groups(
    groups: Iterable[str], role_map: dict[str, str]
) -> tuple[str, ...]:
    """Map verified directory groups to a sorted, deduplicated role tuple."""
    roles = {
        role_map[group]
        for group in groups
        if group in role_map and role_map[group].strip()
    }
    if not roles:
        raise ControlPlaneError(
            "E_NO_ROLE", "verified identity has no mapped factory role"
        )
    return tuple(sorted(roles))


def principal_from_verified_oidc(
    claims: dict[str, Any],
    *,
    expected_issuer: str,
    role_map: dict[str, str],
) -> Principal:
    """Build a tenant principal from already verified OIDC claims, failing closed."""
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError(
            "E_UNVERIFIED_IDENTITY", "OIDC claims must be verified before authorization"
        )
    issuer = _required(claims.get("iss"), "iss")
    if issuer != expected_issuer:
        raise ControlPlaneError("E_IDENTITY_ISSUER", "OIDC issuer is not trusted")
    tenant_id = _required(claims.get("tenant_id"), "tenant_id")
    subject = _required(claims.get("sub"), "sub")
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(
        isinstance(group, str) for group in groups
    ):
        raise ControlPlaneError("E_IDENTITY_CLAIM", "groups must be a list of strings")
    return Principal(
        subject=subject, tenant_id=tenant_id, roles=roles_from_groups(groups, role_map)
    )


@dataclass(frozen=True)
class SCMEvent:
    schema: str
    provider: str
    tenant_id: str
    delivery_id: str
    event_type: str
    repository: str
    change_id: str
    actor: str
    payload_sha256: str

    def to_dict(self) -> dict[str, str]:
        """Return the normalized SCM event as a stable serializable dictionary."""
        return self.__dict__.copy()


def normalize_scm_event(
    provider: str,
    claims: dict[str, Any],
    *,
    tenant_id: str,
    actor_roles: Iterable[str],
) -> tuple[SCMEvent, Principal]:
    """Normalize a supported SCM webhook and its actor or reject unsafe claims."""
    provider = provider.strip().lower()
    _validate_scm_provider(provider)
    payload = _verified_scm_payload(claims)
    delivery_id, event_type = _event_header(claims)
    repository, actor, change = _provider_identity(provider, payload)
    change_id = _required(str(change) if change is not None else "", "change_id")
    tenant_id = _required(tenant_id, "tenant_id")
    roles = _mapped_roles(actor_roles)
    event = _scm_event(
        provider,
        tenant_id,
        delivery_id,
        event_type,
        repository,
        change_id,
        actor,
        payload,
    )
    principal = Principal(
        subject=f"scm:{provider}:{actor}", tenant_id=tenant_id, roles=roles
    )
    return event, principal


def _validate_scm_provider(provider: str) -> None:
    if provider not in SUPPORTED_SCM_PROVIDERS:
        raise ControlPlaneError(
            "E_SCM_PROVIDER", f"unsupported SCM provider: {provider}"
        )


def _verified_scm_payload(claims: dict[str, Any]) -> dict[str, Any]:
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError(
            "E_UNVERIFIED_WEBHOOK",
            "SCM claims must be signature-verified before normalization",
        )
    payload = claims.get("payload")
    if not isinstance(payload, dict):
        raise ControlPlaneError(
            "E_SCM_PAYLOAD", "verified SCM payload must be an object"
        )
    return payload


def _event_header(claims: dict[str, Any]) -> tuple[str, str]:
    delivery_id = _required(claims.get("delivery_id"), "delivery_id")
    event_type = _required(claims.get("event_type"), "event_type")
    return delivery_id, event_type


def _github_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    repository = _required(
        (payload.get("repository") or {}).get("full_name"), "repository.full_name"
    )
    actor = _required((payload.get("sender") or {}).get("login"), "sender.login")
    change = (
        (payload.get("pull_request") or {}).get("number")
        or payload.get("after")
        or payload.get("ref")
    )
    return repository, actor, change


def _gitlab_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    repository = _required(
        (payload.get("project") or {}).get("path_with_namespace"),
        "project.path_with_namespace",
    )
    actor = _required(payload.get("user_username"), "user_username")
    change = (payload.get("object_attributes") or {}).get("iid") or payload.get(
        "checkout_sha"
    )
    return repository, actor, change


def _azure_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    resource = payload.get("resource") or {}
    repository = _required(
        (resource.get("repository") or {}).get("name"), "resource.repository.name"
    )
    actor = _required(
        (resource.get("createdBy") or {}).get("id"), "resource.createdBy.id"
    )
    change = (
        resource.get("pullRequestId")
        or resource.get("sourceRefName")
        or payload.get("id")
    )
    return repository, actor, change


def _provider_identity(provider: str, payload: dict[str, Any]) -> tuple[str, str, Any]:
    if provider == "github":
        return _github_identity(payload)
    if provider == "gitlab":
        return _gitlab_identity(payload)
    return _azure_identity(payload)


def _mapped_roles(actor_roles: Iterable[str]) -> tuple[str, ...]:
    roles = tuple(sorted({role.strip() for role in actor_roles if role.strip()}))
    if not roles:
        raise ControlPlaneError("E_NO_ROLE", "SCM actor has no mapped factory role")
    return roles


def _scm_event(
    provider: str,
    tenant_id: str,
    delivery_id: str,
    event_type: str,
    repository: str,
    change_id: str,
    actor: str,
    payload: dict[str, Any],
) -> SCMEvent:
    return SCMEvent(
        schema="factory.scm.event.v1",
        provider=provider,
        tenant_id=tenant_id,
        delivery_id=delivery_id,
        event_type=event_type,
        repository=repository,
        change_id=change_id,
        actor=actor,
        payload_sha256=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )


def event_json(event: SCMEvent) -> bytes:
    """Serialize an SCM event into deterministic canonical JSON bytes."""
    return canonical_json(event.to_dict())


# Explicit ticket operations share the existing workflow audit, not another runner.
_ISSUE_LIMIT = 1_048_576


class IssueIntegrationError(ValueError):
    """Safe refusal which never includes provider response bodies or credentials."""


def _issue_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _issue_text(value: object, maximum: int = 32768) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise IssueIntegrationError("ISSUE_INPUT_INVALID: missing or oversized text")
    return value


def _issue_target(provider: str, issue: str, site: str) -> str:
    if provider not in {"linear", "jira"}:
        raise IssueIntegrationError("ISSUE_PROVIDER_UNSUPPORTED")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,30}-[1-9][0-9]{0,12}", issue):
        raise IssueIntegrationError("ISSUE_IDENTIFIER_INVALID: use a project issue key")
    if provider == "linear":
        if site:
            raise IssueIntegrationError("ISSUE_SITE_INVALID: Linear uses its fixed API")
        return "https://api.linear.app/graphql"
    if not re.fullmatch(r"https://[a-z0-9][a-z0-9-]{0,61}\.atlassian\.net", site):
        raise IssueIntegrationError("ISSUE_SITE_INVALID: use an HTTPS Jira Cloud site")
    return site


class _IssueNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IssueIntegrationError("ISSUE_REDIRECT_REJECTED")


def _issue_credentials(provider: str) -> str:
    if provider == "linear":
        token = os.environ.get("FACTORY_LINEAR_TOKEN", "")
        mode = os.environ.get("FACTORY_LINEAR_AUTH", "api-key")
        if mode not in {"api-key", "oauth"}:
            raise IssueIntegrationError("ISSUE_AUTH_MODE_INVALID")
        result = ("Bearer " if mode == "oauth" else "") + token
    else:
        token = os.environ.get("FACTORY_JIRA_TOKEN", "")
        email = os.environ.get("FACTORY_JIRA_EMAIL", "")
        if not email or any(c in email for c in "\r\n:"):
            raise IssueIntegrationError(
                "ISSUE_CREDENTIALS_MISSING: set Jira email privately"
            )
        result = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()
    if not token or len(token) > 4096 or any(c.isspace() for c in token):
        raise IssueIntegrationError(
            "ISSUE_CREDENTIALS_MISSING: configure token privately"
        )
    return result


def _issue_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise IssueIntegrationError("ISSUE_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _issue_request(provider, issue, site, method, suffix="", payload=None):
    base = _issue_target(provider, issue, site)
    url = base if provider == "linear" else f"{base}/rest/api/3/issue/{issue}{suffix}"
    data = canonical_json(payload) if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": _issue_credentials(provider),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.build_opener(_IssueNoRedirect()).open(
            request, timeout=20
        ) as response:
            raw = response.read(_ISSUE_LIMIT + 1)
        if len(raw) > _ISSUE_LIMIT:
            raise IssueIntegrationError("ISSUE_RESPONSE_TOO_LARGE")
        value = json.loads(raw, object_pairs_hook=_issue_pairs)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if isinstance(exc, IssueIntegrationError):
            raise
        raise IssueIntegrationError(
            "ISSUE_PROVIDER_FAILED: response unavailable or invalid"
        ) from None
    if not isinstance(value, dict) or value.get("errors"):
        raise IssueIntegrationError(
            "ISSUE_PROVIDER_FAILED: incomplete provider response"
        )
    return value


def _issue_graphql(issue, query, variables):
    value = _issue_request(
        "linear",
        issue,
        "",
        "POST",
        payload={
            "query": query,
            "variables": variables,
        },
    ).get("data", {})
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_PROVIDER_FAILED: missing GraphQL data")
    return value


def _issue_object(value):
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_PROVIDER_FAILED: expected an object")
    return value


def _issue_description(value):
    """Flatten Jira ADF text without interpreting links, commands or rich objects."""
    if value is None:
        return ""
    if isinstance(value, str):
        return _issue_text(value)
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_DESCRIPTION_INVALID")
    stack, texts, count = [(value, 0)], [], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 4096 or depth > 32 or not isinstance(node, dict):
            raise IssueIntegrationError("ISSUE_DESCRIPTION_TOO_COMPLEX")
        if "text" in node:
            texts.append(_issue_text(node["text"]))
        content = node.get("content", [])
        if not isinstance(content, list):
            raise IssueIntegrationError("ISSUE_DESCRIPTION_INVALID")
        stack.extend((child, depth + 1) for child in reversed(content))
    return _issue_text("\n".join(texts)) if texts else ""


def _issue_fetch(provider, issue, site):
    _issue_target(provider, issue, site)
    if provider == "linear":
        value = _issue_graphql(
            issue,
            "query CFImport($id: String!) { issue(id: $id) { id identifier title description updatedAt } }",
            {"id": issue},
        ).get("issue")
        if not isinstance(value, dict) or value.get("identifier") != issue:
            raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
        return {
            "key": issue,
            "id": _issue_text(value.get("id"), 128),
            "title": _issue_text(value.get("title"), 512),
            "description": _issue_description(value.get("description")),
            "updated": _issue_text(value.get("updatedAt"), 128),
        }
    value = _issue_request(
        provider, issue, site, "GET", "?fields=summary,description,updated"
    )
    if value.get("key") != issue or not isinstance(value.get("fields"), dict):
        raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
    fields = value["fields"]
    return {
        "key": issue,
        "id": _issue_text(value.get("id"), 128),
        "title": _issue_text(fields.get("summary"), 512),
        "description": _issue_description(fields.get("description")),
        "updated": _issue_text(fields.get("updated"), 128),
    }


def _issue_local(root, path):
    root, value = Path(root).resolve(), Path(path)
    if value.is_absolute() or ".." in value.parts:
        raise IssueIntegrationError("ISSUE_PATH_REJECTED")
    target = root / value
    for parent in [target, *target.parents]:
        if parent == root:
            break
        if parent.is_symlink() or (
            parent.exists() and getattr(parent.lstat(), "st_file_attributes", 0) & 1024
        ):
            raise IssueIntegrationError("ISSUE_PATH_REJECTED")
    try:
        target.resolve().relative_to(root)
    except ValueError:
        raise IssueIntegrationError("ISSUE_PATH_REJECTED") from None
    return target


def _issue_load(root, path, with_hash=False):
    with _issue_local(root, path).open("rb") as handle:
        raw = handle.read(_ISSUE_LIMIT + 1)
    if len(raw) > _ISSUE_LIMIT:
        raise IssueIntegrationError("ISSUE_INPUT_TOO_LARGE")
    value = json.loads(raw, object_pairs_hook=_issue_pairs)
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_INPUT_INVALID")
    return (value, hashlib.sha256(raw).hexdigest()) if with_hash else value


def _issue_save(root, body, label):
    digest = _issue_digest(body)
    result = {**body, "sha256": digest}
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if len(encoded.encode("utf-8")) > _ISSUE_LIMIT:
        raise IssueIntegrationError("ISSUE_OUTPUT_TOO_LARGE")
    relative = f".factory/issues/{label}-{digest}.json"
    target = _issue_local(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        if _issue_load(root, relative) != result:
            raise IssueIntegrationError("ISSUE_LOCAL_CONFLICT") from None
    return {**result, "path": relative}


def _issue_sealed(root, path, schema):
    value = _issue_load(root, path)
    core = {k: v for k, v in value.items() if k != "sha256"}
    if value.get("schema") != schema or value.get("sha256") != _issue_digest(core):
        raise IssueIntegrationError("ISSUE_BINDING_INVALID")
    return value


def import_issue(
    root: Path, provider: str, issue: str, *, site="", criteria=()
) -> dict:
    """Fetch one explicit issue; preserve untrusted text and operator requirements locally."""
    requirements = [_issue_text(item, 2048) for item in criteria]
    if len(requirements) > 64 or len(set(requirements)) != len(requirements):
        raise IssueIntegrationError("ISSUE_REQUIREMENTS_INVALID")
    return _issue_save(
        root,
        {
            "schema": "factory.issue-import.v1",
            "provider": provider,
            "site": site,
            "issue": _issue_fetch(provider, issue, site),
            "criteria": requirements,
            "content_trust": "UNTRUSTED_DATA",
            "execution": "NOT_RUN",
            "review_required": True,
        },
        "import",
    )


def _issue_draft(root, imported, contract, observations):
    from .workflow_audit import audit_workflows

    packet = _issue_sealed(root, imported, "factory.issue-import.v1")
    catalog, contract_hash = _issue_load(root, contract, with_hash=True)
    observations_value, observations_hash = _issue_load(
        root, observations, with_hash=True
    )
    receipt = audit_workflows(Path(root), contract, observations)
    if (contract_hash, observations_hash) != (
        receipt["contract_sha256"],
        receipt["observations_sha256"],
    ):
        raise IssueIntegrationError("ISSUE_EVIDENCE_CHANGED_DURING_REVIEW")
    requirements = [row["requirement"] for row in catalog.get("checks", [])]
    if not packet.get("criteria") or set(packet["criteria"]) != set(requirements):
        raise IssueIntegrationError(
            "ISSUE_REQUIREMENTS_UNMAPPED: review all ticket criteria"
        )
    observed = observations_value["observations"]
    bindings = [
        {
            "criterion": criterion,
            "checks": [
                {
                    "id": check["id"],
                    "profiles": check["profiles"],
                    "observations": [
                        {key: row[key] for key in ("profile", "status", "artifacts")}
                        for row in observed
                        if row["id"] == check["id"]
                    ],
                }
                for check in catalog["checks"]
                if check["requirement"] == criterion
            ],
        }
        for criterion in packet["criteria"]
    ]
    core = {
        "schema": "factory.issue-draft.v1",
        "import_path": imported,
        "import_sha256": packet["sha256"],
        "contract_path": contract,
        "observations_path": observations,
        "provider": packet["provider"],
        "site": packet["site"],
        "issue": packet["issue"]["key"],
        "issue_id": packet["issue"]["id"],
        "issue_updated": packet["issue"]["updated"],
        "workflow_receipt_sha256": receipt["receipt_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "declared_criteria_bindings": bindings,
        "criteria_assessment": "DECLARED_COVERAGE_NOT_SEMANTIC_VERIFICATION",
        "state": receipt["state"],
        "checks": receipt["checks"],
    }
    marker = _issue_digest(core)
    core["body"] = (
        f"Code Factory evidence update [cf-evidence:{marker}]\n"
        f"Workflow evidence: {receipt['state']}; declared checks: {receipt['checks']}.\n"
        f"Candidate: {receipt['candidate_sha256']}\n"
        f"Receipt: {receipt['receipt_sha256']}\n"
        "Criteria mapping is declared coverage, not semantic verification. "
        "This verifies recorded evidence completeness and hashes only. "
        "It does not certify software, approve release, or close this issue."
    )
    core["review_required"] = True
    return core


def draft_issue_update(
    root: Path, imported: str, contract: str, observations: str
) -> dict:
    """Prepare a source-current metadata-only comment from the existing workflow audit."""
    return _issue_save(
        root, _issue_draft(root, imported, contract, observations), "draft"
    )


def _issue_comments(provider, issue, site):
    if provider == "linear":
        issue_value = _issue_object(
            _issue_graphql(
                issue,
                "query CFDedup($id: String!) { issue(id: $id) { comments(first: 100) { nodes { id body } pageInfo { hasNextPage } } } }",
                {"id": issue},
            ).get("issue")
        )
        value = _issue_object(issue_value.get("comments"))
        if _issue_object(value.get("pageInfo")).get("hasNextPage") is not False:
            raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
        rows = value.get("nodes")
    else:
        value = _issue_request(provider, issue, site, "GET", "/comment?maxResults=100")
        rows = value.get("comments")
        if (
            not isinstance(rows, list)
            or type(value.get("total")) is not int
            or value["total"] != len(rows)
        ):
            raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
    if not isinstance(rows, list) or len(rows) > 100:
        raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
    return [
        {
            "id": _issue_text(_issue_object(row).get("id"), 128),
            "body": _issue_description(row.get("body")),
        }
        for row in rows
    ]


def _issue_post(provider, issue, site, body, remote_id):
    if provider == "linear":
        value = _issue_object(
            _issue_graphql(
                issue,
                "mutation CFComment($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id body } } }",
                {"input": {"issueId": remote_id, "body": body}},
            ).get("commentCreate")
        )
        if value.get("success") is not True:
            raise IssueIntegrationError("ISSUE_DELIVERY_UNKNOWN")
        return _issue_object(value.get("comment")).get("id")
    adf = {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": body}]}],
    }
    return _issue_request(provider, issue, site, "POST", "/comment", {"body": adf}).get(
        "id"
    )


def _issue_existing(rows, body):
    marker = body.splitlines()[0]
    matches = [row for row in rows if marker in row["body"]]
    if len(matches) > 1 or any(row["body"] != body for row in matches):
        raise IssueIntegrationError("ISSUE_REMOTE_CONFLICT")
    return matches[0]["id"] if matches else None


def publish_issue_update(root: Path, draft: str, confirmation: str) -> dict:
    """Send one exact confirmed comment; uncertain prior deliveries are never resent."""
    value = _issue_sealed(root, draft, "factory.issue-draft.v1")
    if confirmation != f"publish:{value['sha256']}":
        raise IssueIntegrationError(
            "ISSUE_CONFIRMATION_REQUIRED: approve exact draft digest"
        )
    current = _issue_draft(
        root, value["import_path"], value["contract_path"], value["observations_path"]
    )
    if _issue_digest(current) != value["sha256"]:
        raise IssueIntegrationError("ISSUE_DRAFT_STALE")
    provider, issue, site = value["provider"], value["issue"], value["site"]
    remote = _issue_fetch(provider, issue, site)
    if remote["id"] != value["issue_id"]:
        raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
    comment = _issue_existing(_issue_comments(provider, issue, site), value["body"])
    confirmation_record = _issue_save(
        root,
        {
            "schema": "factory.issue-confirmation.v1",
            "draft_sha256": value["sha256"],
            "candidate_sha256": value["candidate_sha256"],
            "provider": provider,
            "site": site,
            "issue": issue,
            "body_sha256": _issue_digest(value["body"]),
            "basis": "EXPLICIT_OPERATOR_CONFIRMATION_UNAUTHENTICATED",
            "scope": "COMMENT_ONLY",
        },
        "confirmation",
    )
    if comment is None:
        if remote["updated"] != value["issue_updated"]:
            raise IssueIntegrationError(
                "ISSUE_REMOTE_STALE: import changed requirements again"
            )
        attempt = _issue_local(root, f".factory/issues/attempt-{value['sha256']}.json")
        try:
            with attempt.open("x", encoding="utf-8") as output:
                output.write(
                    json.dumps({"draft_sha256": value["sha256"], "state": "RESERVED"})
                )
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise IssueIntegrationError(
                "ISSUE_DELIVERY_UNKNOWN: reconcile prior attempt before retry"
            ) from None
        comment = _issue_text(
            _issue_post(provider, issue, site, value["body"], remote["id"]), 128
        )
        if (
            _issue_existing(_issue_comments(provider, issue, site), value["body"])
            != comment
        ):
            raise IssueIntegrationError(
                "ISSUE_DELIVERY_UNKNOWN: comment readback not confirmed"
            )
    return _issue_save(
        root,
        {
            "schema": "factory.issue-delivery.v1",
            "draft_sha256": value["sha256"],
            "provider": provider,
            "issue": issue,
            "comment_id": comment,
            "confirmation_sha256": confirmation_record["sha256"],
            "state": "COMMENT_VERIFIED",
            "issue_closed": False,
            "release_approved": False,
        },
        "delivery",
    )
