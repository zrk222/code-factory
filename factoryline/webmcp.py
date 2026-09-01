"""Canonical read-only WebMCP contract for the local Graph Ops page."""
from __future__ import annotations

from typing import Any


WEBMCP_SPEC_STATUS = "draft-community-group-report"
WEBMCP_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "factory.graph_summary",
        "title": "Read proof graph summary",
        "description": "Read a bounded summary of the Graph Ops snapshot already visible on this page. No work is executed.",
    },
    {
        "name": "factory.next_action",
        "title": "Read next proof action",
        "description": "Read the current fact-derived recommendation already visible on this page. It is not authorization to execute it.",
    },
    {
        "name": "factory.revenue_status",
        "title": "Read purchase evidence status",
        "description": "Read bounded RevenueForge status already visible on this page. It never contacts Apple or changes provider state.",
    },
    {
        "name": "factory.appforge_status",
        "title": "Read design evidence status",
        "description": "Read bounded AppForge design-receipt status already visible on this page. It never creates, approves, renders, or releases a design.",
    },
    {
        "name": "factory.oracle_firewall_status",
        "title": "Read sealed intent and gate authority",
        "description": "Read bounded Oracle Firewall facts already visible on this page. It never changes a contract, candidate, agent, or release.",
    },
    {
        "name": "factory.appforge_oracle_status",
        "title": "Read AppForge policy authority",
        "description": "Read candidate-bound AppForge authority state already visible on this page. It never contacts Apple or changes a submission.",
    },
    {
        "name": "factory.saas_status",
        "title": "Read SaaS promise-to-permission status",
        "description": "Read bounded provider-neutral OAuth/OIDC-to-entitlement status already visible on this page. It never contacts or mutates a provider.",
    },
    {
        "name": "factory.jetbrains_handshake_status",
        "title": "Read agent and analyzer proof handshake",
        "description": "Read the latest bounded coding-agent and Qodana-or-SonarQube handshake already visible on this page. It never runs or approves an agent, analyzer, or test.",
    },
)


def webmcp_manifest() -> dict[str, Any]:
    """Return the deterministic progressive-enhancement contract."""
    return {
        "schema": "factory.webmcp.manifest.v1",
        "marker": "FACTORY_WEBMCP_PROGRESSIVE_READ_ONLY",
        "spec_status": WEBMCP_SPEC_STATUS,
        "transport": "document.modelContext",
        "tools": [
            {
                **tool,
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "annotations": {"readOnlyHint": True, "untrustedContentHint": True},
            }
            for tool in WEBMCP_TOOLS
        ],
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
        "claim_boundary": "progressive browser tool discovery over the currently loaded local Graph Ops snapshot; unsupported browsers retain the normal UI",
    }
