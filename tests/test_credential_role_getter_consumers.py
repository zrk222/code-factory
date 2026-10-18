import ast
import hashlib

import pytest

from factoryline import review_audits as audit
from factoryline import review_integrity as integrity
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.credential_role_getter_consumers import getter_consumer_role


def _proof(tmp_path, source):
    path = tmp_path / "sample.py"
    raw = source.encode()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    integrity.bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(
        tmp_path, {path: tree}, {path: raw}, {path: tree._oracle_source_sha256}
    )
    node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "endpoint"
    )
    return getter_consumer_role(node, index, path, audit)


@pytest.mark.parametrize(
    "source",
    [
        "import responses\nresponses.add('POST', client.endpoint())",
        "import responses as r\nr.replace('POST', url=client.endpoint())",
        "from responses import add\nadd('POST', url=client.endpoint())",
        "import responses\nresponses.get(client.endpoint())",
        "import responses\nresponses.add(responses.POST, client.endpoint())",
        "import requests\nrequests.request('GET', url=client.endpoint())",
        "import requests\nrequests.post(client.endpoint(), data={'value': 'x'})",
        "assert client.endpoint() == 'https://appleid.apple.com/auth/token'",
        "import responses\nx = responses.calls[0].request.url == client.endpoint()",
        "import responses\nx = next(c for c in responses.calls if c.request.url == client.endpoint())",
        "import responses\nx = next(c for c in responses.calls if c.request.url.startswith(client.endpoint()))",
        "import responses\nfrom typing import cast\nx = next(c for c in responses.calls if cast('str', c.request.url).startswith(client.endpoint()))",
    ],
)
def test_exact_getter_result_url_use_is_not_an_origin_witness(tmp_path, source):
    proof = _proof(tmp_path, source)
    assert proof and proof["role"].startswith("verified_url_")
    assert proof["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert "origin" not in proof and "credential_safety" not in proof


@pytest.mark.parametrize(
    "source",
    [
        "import responses\nresponses.add('GET', 'https://other.test', body=client.endpoint())",
        "import requests\nrequests.get('https://other.test', auth=client.endpoint())",
        "import requests\nrequests.get('https://other.test', headers={'Authorization': client.endpoint()})",
        "import responses\nresponses.add('GET', client.endpoint(), url='https://other.test')",
        "import responses\nresponses.add('GET', client.endpoint(), **options)",
        "import responses\nresponses.add(*methods, url=client.endpoint())",
        "import responses\nresponses.add = opaque\nresponses.add('GET', client.endpoint())",
        "import responses\ndef test(responses):\n    responses.add('GET', client.endpoint())",
        "def test():\n    import responses as r\n    r.add = opaque\n    r.add('GET', client.endpoint())",
        "import responses\nresponses.add('GET', opaque(client.endpoint()))",
        "import responses\nresponses.add('GET', client.endpoint(secret()))",
        "import responses\nx = foreign.request.url == client.endpoint()",
        "import responses\nx = next(c for c in other_calls if c.request.url == client.endpoint())",
        "import responses\nx = next(c for c in responses.calls for c in foreign if c.request.url == client.endpoint())",
        "import responses\nx = next(c for c in responses.calls if (lambda c: c.request.url == client.endpoint())(foreign))",
        "import responses\nfrom typing import cast\ncast = opaque\nx = next(c for c in responses.calls if cast('str', c.request.url).startswith(client.endpoint()))",
        "assert client.endpoint() == supplied_password",
        "assert client.endpoint() == 'https://private.test/credential'",
        "opaque(client.endpoint())",
        "responses.add('GET', client.endpoint())\nimport responses",
        "def test():\n    r.add('GET', client.endpoint())\n    import responses as r",
        "x = responses.calls[0].request.url == client.endpoint()\nimport responses",
        "def test():\n    x = r.calls[0].request.url == client.endpoint()\n    import responses as r",
        "import responses\nresponses.calls[0].request.url = secret\nx = responses.calls[0].request.url == client.endpoint()",
        "import responses\nresponses.calls.append(foreign)\nx = responses.calls[0].request.url == client.endpoint()",
        "import responses\nsaved = responses.calls\nmutate(saved)\nx = responses.calls[0].request.url == client.endpoint()",
        "import responses\nx = next(c for c in responses.calls if mutate(c) or c.request.url == client.endpoint())",
        "import responses\nx = next(c for c in responses.calls if setattr(c.request, 'url', secret) or c.request.url == client.endpoint())",
        "import responses\nsaved=next(c for c in responses.calls)\nsaved.request.url=secret\nx=next(c for c in responses.calls if c.request.url==client.endpoint())",
        "import responses\nsaved=[c for c in responses.calls]\nsaved[0].request.url=secret\nx=next(c for c in responses.calls if c.request.url==client.endpoint())",
        "import responses\nsaved=next(c for c in responses.calls)\nsaved.request.__dict__['url']=secret\nx=next(c for c in responses.calls if c.request.url==client.endpoint())",
        "import responses\nsaved=next(c for c in responses.calls)\nsaved.request.__setattr__('url',secret)\nx=next(c for c in responses.calls if c.request.url==client.endpoint())",
        "import responses\nd={c: 1 for c in responses.calls}\nx=responses.calls[0].request.url==client.endpoint()",
    ],
)
def test_auth_opaque_ambiguous_or_mutated_consumer_stays_unknown(tmp_path, source):
    assert _proof(tmp_path, source) is None


def test_provider_check_cache_is_local_profile_bound_and_freshly_validated(
    tmp_path, monkeypatch
):
    from factoryline import credential_role_getter_consumers as consumer
    from factoryline.credential_role_chain_memo import ClassChainMemo

    path = tmp_path / "sample.py"
    raw = b"import responses\nresponses.add('GET', 'https://example.test')\n"
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    index.class_chain_memo = ClassChainMemo(index, {path: {}}, {}, audit)
    checked, original = [], consumer._provider_mutated

    def observe(*args):
        checked.append(args[-1])
        return original(*args)

    monkeypatch.setattr(consumer, "_provider_mutated", observe)
    aliases = {"responses": "responses"}
    for _ in range(3):
        assert consumer._provider_result(index, path, aliases, False) is False
        assert consumer._provider_result(index, path, aliases, True) is False
    assert checked == [False, True]
    assert index.class_chain_memo.valid()
    index.source_bytes[path] += b"# changed\n"
    assert index.class_chain_memo.valid() is False
