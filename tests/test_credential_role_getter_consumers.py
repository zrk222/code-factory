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


@pytest.mark.parametrize('source', [
    "import responses\ndef test():\n    request = next(c.request for c in responses.calls)\n    assert request.url == client.endpoint()",
    "import responses\ndef test():\n    call = responses.calls[0]\n    request = call.request\n    assert request.url.startswith(client.endpoint())",
    "import responses\ndef test():\n    request = next(c.request for c in responses.calls)\n    parse(request.body)\n    assert request.url == client.endpoint()",
])
def test_transfer155_source_record_scalar_projection(tmp_path, source):
    proof = _proof(tmp_path, source)
    assert proof and proof['role'].startswith('verified_url_')


@pytest.mark.parametrize('extra', [
    "opaque(request)", "return request", "saved = [request]",
    "request.url = secret", "del request.body", "request.__dict__['url'] = secret",
    "request.__setattr__('url', secret)", "request = foreign",
    "def captured(): return request", "opaque(responses.calls)",
])
def test_transfer155_record_capability_escape_is_not_a_scalar_proof(tmp_path, extra):
    source = ('import responses\ndef test():\n'
              '    request = next(c.request for c in responses.calls)\n'
              f'    {extra}\n'
              '    assert request.url == client.endpoint()')
    assert _proof(tmp_path, source) is None


@pytest.mark.parametrize('source', [
    "import responses\ndef test(responses):\n    request = next(c.request for c in responses.calls)\n    assert request.url == client.endpoint()",
    "import responses\ndef test(next):\n    request = next(c.request for c in responses.calls)\n    assert request.url == client.endpoint()",
    "import responses\ndef test():\n    next = opaque\n    request = next(c.request for c in responses.calls)\n    assert request.url == client.endpoint()",
    "import responses\ndef test():\n    request = next(c.request for c in responses.calls if opaque(c))\n    assert request.url == client.endpoint()",
    "import responses\ndef test():\n    request = next(c.request for c in responses.calls for c in other)\n    assert request.url == client.endpoint()",
    "import responses\ndef test():\n    request = next(c.request for c in responses.calls if (c := foreign))\n    assert request.url == client.endpoint()",
])
def test_transfer155_unproven_or_invalid_projection_stays_unknown(tmp_path, source):
    # The final row is parseable AST but invalid executable Python, not a bypass.
    assert _proof(tmp_path, source) is None


@pytest.mark.parametrize('body', [
    'operation()', 'with context():\n            operation()',
])
def test_transfer155_finite_callable_tuple_discards_exact_result(tmp_path, body):
    source = ('def test():\n'
              '    for operation, stage in ((client.endpoint, "url"),):\n'
              f'        {body}')
    proof = _proof(tmp_path, source)
    assert proof and proof['role'] == 'verified_discarded_callable_result'


@pytest.mark.parametrize('row,body,tail', [
    ('(client.endpoint, "url", "extra")', 'operation()', ''),
    ('(client.endpoint,)', 'operation()', ''),
    ('(client.endpoint, "url")', 'if False:\n            operation()', ''),
    ('(client.endpoint, "url")', 'operation(secret)', ''),
    ('(client.endpoint, "url")', 'opaque(operation)', ''),
    ('(client.endpoint, "url")', 'saved = operation', ''),
    ('(client.endpoint, "url")', 'operation = other\n        operation()', ''),
    ('(client.endpoint, "url")', 'operation()', '\n    return operation'),
])
def test_transfer155_callable_shape_or_escape_stays_unknown(tmp_path, row, body, tail):
    source = ('def test():\n'
              f'    for operation, stage in ({row},):\n'
              f'        {body}{tail}')
    assert _proof(tmp_path, source) is None


@pytest.mark.parametrize('mutation', ['binding', 'code'])
def test_transfer155_record_methods_invalidate_context_cache(tmp_path, monkeypatch, mutation):
    from factoryline import credential_role_getter_records as records
    from factoryline.credential_endpoint_admission import endpoint_admission_helpers
    method = records.RecordProjectionIndex.closed
    assert method in endpoint_admission_helpers()
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    def reject(self):
        return False
    if mutation == 'binding':
        monkeypatch.setattr(records.RecordProjectionIndex, 'closed', reject)
    else:
        monkeypatch.setattr(method, '__code__', reject.__code__)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != before


def test_transfer155_record_budget_exhaustion_cannot_accept_partial_graph():
    from factoryline.credential_role_getter_records import RecordProjectionIndex
    tree = ast.parse('import responses\nx = responses.calls[0].request.url')
    model = RecordProjectionIndex(tree, {'responses': 'responses'})
    model.remaining = 0
    assert model.closed() is False


@pytest.mark.parametrize('extra', [
    'count = len(responses.calls)',
    'body = responses.calls[-1].request.body',
    'count = sum(1 for c in responses.calls if c.request.url == "x")',
    'requests = [c.request for c in responses.calls]\n    body = requests[-1].body\n    count = len(requests)',
])
def test_transfer155_readonly_record_collection_operations(tmp_path, extra):
    source = ('import responses\ndef test():\n'
              f'    {extra}\n'
              '    assert responses.calls[0].request.url == client.endpoint()')
    assert _proof(tmp_path, source)


@pytest.mark.parametrize('signature,extra', [
    ('len', 'count = len(responses.calls)'),
    ('*next', 'request = next(c.request for c in responses.calls)'),
    ('**next', 'request = next(c.request for c in responses.calls)'),
    ('sum', 'count = sum(1 for c in responses.calls)'),
])
def test_transfer155_shadowed_builtin_collection_operation_is_unknown(tmp_path, signature, extra):
    source = (f'import responses\ndef test({signature}):\n'
              f'    {extra}\n'
              '    assert responses.calls[0].request.url == client.endpoint()')
    assert _proof(tmp_path, source) is None


def test_transfer155_nested_finite_callable_dispatch(tmp_path):
    source = ('def test():\n    values = (1, 2)\n'
              '    for operation, stage in ((client.endpoint, "url"),):\n'
              '        for value in values:\n'
              '            with context():\n'
              '                operation()')
    assert _proof(tmp_path, source)


@pytest.mark.parametrize('mutation', [
    "responses.__dict__['calls'] = foreign",
    "namespace = responses.__dict__\nnamespace['calls'] = foreign",
    "globals()['responses'] = foreign",
    "namespace = globals()\nnamespace['responses'] = foreign",
    "locals()['responses'] = foreign",
    "namespace = vars()\nnamespace['responses'] = foreign",
    "opaque(responses.__dict__)",
    "namespace = function.__globals__\nnamespace['responses'] = foreign",
    "import builtins\nbuiltins.__dict__['next'] = foreign",
    "exec(source)",
    "import builtins\nbuiltins.next = foreign",
    "import builtins\nsetattr(builtins, 'next', foreign)",
    "import builtins\nbuiltins.len = foreign",
    "namespace_fn = globals\nnamespace_fn()['responses'] = foreign",
    "namespace = getattr(function, '__globals__')\nnamespace['responses'] = foreign",
    "namespace = function.__getattribute__('__globals__')\nnamespace['responses'] = foreign",
])
def test_transfer155_namespace_mutation_or_escape_restores_unknown(tmp_path, mutation):
    source = ('import responses\n' + mutation + '\n'
              'def test():\n'
              '    request = next(c.request for c in responses.calls)\n'
              '    assert request.url == client.endpoint()')
    assert _proof(tmp_path, source) is None


@pytest.mark.parametrize('expression', [
    'any(next(c.request for c in responses.calls).url == client.endpoint() for next in foreign)',
    '(lambda next: next(c.request for c in responses.calls).url == client.endpoint())(foreign)',
    '(lambda *next: next(c.request for c in responses.calls).url == client.endpoint())(foreign)',
    'any(len(responses.calls) and responses.calls[0].request.url == client.endpoint() for len in foreign)',
    '(lambda sum: sum(1 for c in responses.calls) and responses.calls[0].request.url == client.endpoint())(foreign)',
    '(lambda responses: responses.calls[0].request.url == client.endpoint())(foreign)',
    'any(responses.calls[0].request.url == client.endpoint() for responses in foreign)',
    '(lambda cast: cast("str", responses.calls[0].request.url) == client.endpoint())(foreign)',
])
def test_transfer155_comprehension_or_lambda_builtin_shadow_is_unknown(tmp_path, expression):
    assert _proof(tmp_path, 'import responses\nfrom typing import cast\n' + expression) is None


@pytest.mark.parametrize('binding,expression', [
    ('next = foreign', 'next(c.request for c in responses.calls).url'),
    ('len = foreign', 'len(responses.calls) and responses.calls[0].request.url'),
    ('responses = foreign', 'responses.calls[0].request.url'),
])
def test_transfer155_class_body_shadow_is_not_a_provider(tmp_path, binding, expression):
    source = ('import responses\nclass Case:\n'
              f'    {binding}\n    assert {expression} == client.endpoint()')
    assert _proof(tmp_path, source) is None


@pytest.mark.parametrize('declaration', ['class Case(metaclass=foreign):', 'class Case(foreign):'])
def test_transfer155_unproven_class_namespace_is_unknown(tmp_path, declaration):
    source = ('import responses\n' + declaration + '\n'
              '    assert next(c.request for c in responses.calls).url == client.endpoint()')
    assert _proof(tmp_path, source) is None
