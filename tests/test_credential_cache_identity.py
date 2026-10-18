"""Every external native credential validator participates in cache identity."""

import pytest

from factoryline import credential_httpx_origins as httpx
from factoryline import credential_json_assertions as assertions
from factoryline import credential_role_flows as roles
from factoryline import credential_router_publication as routers
from factoryline import review_audits as audit


@pytest.mark.parametrize(
    "module,name",
    [
        (httpx, "request_client_origin"),
        (assertions, "public_json_assertion"),
        (roles, "binding_dominates"),
        (routers, "router_factory_call_published"),
    ],
)
def test_validator_replacement_invalidates_native_context(
    tmp_path, monkeypatch, module, name
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = getattr(module, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, replacement)
    after = audit._oracle_context_cache_key(tmp_path, [], {})
    assert before != after
