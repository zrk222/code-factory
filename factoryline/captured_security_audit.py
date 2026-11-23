"""Source-bound captured security evidence shared by verification consumers."""

import ast
from functools import partial
import hashlib
from hashlib import sha256
import json
import re
from copy import deepcopy
from pathlib import Path, PurePosixPath

from .captured_operand_audit import (
    _CapturedRecordText,
    _CapturedTextDefinitions,
    _captured_argument_definition,
    _captured_closed_text_callers,
    _captured_literal_argument_origin,
    _captured_record_read,
    captured_log_field_text_closed,
)
from .captured_operand_audit import (
    _COOKIE_NAME_PROVIDERS,
    _COOKIE_NAME_ROLE,
    _registry_cookie_name_use,
)


def captured_django_startup_body(node):
    """Project only guards equivalent to the existing default-binding operation."""
    from .intent_quality import _canary_main_guard_test
    from .review_audits import _name

    if not isinstance(node, ast.If):
        return (node,)
    if _canary_main_guard_test(node.test):
        return node.body
    key = "DJANGO_SETTINGS_MODULE"
    match node:
        case ast.If(
            test=ast.UnaryOp(
                op=ast.Not(),
                operand=ast.Call(
                    func=get, args=[ast.Constant(value=read)], keywords=[]
                ),
            ),
            body=[
                ast.Expr(
                    value=ast.Call(
                        func=put,
                        args=[ast.Constant(value=write), ast.Constant(value=str())],
                        keywords=[],
                    )
                ) as default
            ],
            orelse=[],
        ) if read == write == key and (_name(get), _name(put)) == (
            "os.environ.get",
            "os.environ.setdefault",
        ):
            # For a present key setdefault is inert, even when its value is empty.
            # The existing loader verifier still binds os and checks provider mutation.
            return (default,)
        case _:
            return (node,)


def _captured_hmac_operands(call):
    """Bind a one-shot HMAC constructor with explicit message and digest operands."""
    from . import _bind_source_call

    signature = ast.parse("def new(key, msg, digestmod): pass").body[0]
    try:
        bound = _bind_source_call(call, signature, apply_defaults=False)
    except ValueError:
        return None
    return bound["key"], bound["msg"], bound["digestmod"]


def yaml_loading_finding(provider, relative, call, aliases):
    """Apply the selected parser's loader contract before emitting a diagnostic."""
    from .review_audits import _security_finding
    from .security_configuration import yaml_safe_loader

    if provider in {"ruamel.yaml.YAML.load", "ruamel.yaml.YAML.load_all"}:
        if _ruamel_loader_closed(call, aliases):
            return None
        message = "YAML instance loader mode or constructor authority is unverified."
    elif provider in {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}:
        if provider == "yaml.load" and yaml_safe_loader(call, aliases):
            return None
        message = "YAML is loaded without an explicit reviewed Loader."
    else:
        return None
    return _security_finding(
        "SECURITY_UNSAFE_YAML", relative, call, message, "HIGH", call=provider
    )


def configured_call_finding(provider, relative, call, aliases):
    """Apply the configuration rule for a resolved provider call."""
    if provider in {"hashlib.md5", "hashlib.new"}:
        return _weak_hash_finding(provider, relative, call, aliases)

    from .security_configuration import tls_finding

    return tls_finding(provider, relative, call, aliases)


def _weak_hash_finding(call, relative, node, aliases):
    """Observe confirmed hashlib MD5 calls with no explicit compatibility flag."""
    from .review_audits import _security_finding
    from .security_configuration import _canonical, _keyword
    from .weak_hash_compatibility import definite_compatibility_checksum

    if _canonical(node, aliases) != call:
        return None
    if call == "hashlib.new":
        algorithm = _keyword(node, "name", 0)
        if not (
            isinstance(algorithm, ast.Constant)
            and isinstance(algorithm.value, str)
            and algorithm.value.lower() == "md5"
        ):
            return None
    if definite_compatibility_checksum(node):
        return None
    return _security_finding(
        "SECURITY_WEAK_HASH",
        relative,
        node,
        "MD5 has known collision weaknesses. Use a suitable hash for security "
        "operations, or mark a compatibility checksum with usedforsecurity=False.",
        "MEDIUM",
        call=call,
        algorithm="md5",
    )


def _ruamel_loader_closed(call, aliases):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .review_integrity import _security_module_scope
    from .runtime_audit_integrity import _conditional_module_name
    from .semantic_credential_sensor import _security_source_path

    module = _security_module_scope(getattr(call, "_security_lexical_scope", None))
    index = getattr(module, "_security_source_model", None)
    owner = _security_source_path(index, module)
    if owner is None or not isinstance(call.func, ast.Attribute):
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Name):
        return False
    origin = _yaml_instance_origin(module, receiver.id, aliases)
    paths = index.module_paths()
    if (
        origin is None
        or paths is None
        or any(p.name == "ruamel.py" or "ruamel" in p.parts for p in index.snapshots)
    ):
        return False
    bindings = tuple(
        (_conditional_module_name(name) + "." + receiver.id, (owner, receiver.id))
        for name, path in paths.items()
        if path == owner
    )
    return not _captured_terminal_provider_mutation(
        index,
        audit,
        "ruamel.yaml.YAML",
        additional_bindings=bindings,
        readonly_nodes=(origin,),
    )


def _yaml_instance_origin(module, name, aliases):
    """Use a single constructor with no raw receiver escapes or local mutation."""
    from .security_configuration import _canonical

    references = [
        ref for ref in ast.walk(module) if isinstance(ref, ast.Name) and ref.id == name
    ]
    stores = [ref for ref in references if isinstance(ref.ctx, ast.Store)]
    match stores:
        case [origin]:
            pass
        case _:
            return None
    assignment = getattr(origin, "_security_parent", None)
    if not isinstance(assignment, ast.Assign) or assignment.targets != [origin]:
        return None
    if isinstance(getattr(assignment, "_security_lexical_scope", None), ast.ClassDef):
        return None
    constructor = assignment.value
    if not (
        isinstance(constructor, ast.Call)
        and _canonical(constructor, aliases) == "ruamel.yaml.YAML"
        and _yaml_safe_constructor_mode(constructor)
        and all(ref is origin or _yaml_instance_read_call(ref) for ref in references)
    ):
        return None
    return origin


def _yaml_safe_constructor_mode(constructor):
    if constructor.args:
        return False
    match constructor.keywords:
        case []:
            return True
        case [ast.keyword(arg="typ", value=ast.Constant(value=str() as mode))]:
            return mode in {"rt", "safe", "base"}
        case _:
            return False


def _yaml_instance_read_call(reference):
    access = getattr(reference, "_security_parent", None)
    call = getattr(access, "_security_parent", None)
    return (
        isinstance(reference.ctx, ast.Load)
        and isinstance(access, ast.Attribute)
        and access.attr in {"load", "load_all"}
        and isinstance(call, ast.Call)
        and call.func is access
    )


_CLI_METADATA_FACTORIES = {
    "argparse.ArgumentParser": (
        "argparse.ArgumentParser",
        {"prog", "description", "epilog"},
        0,
    ),
    "argparse.ArgumentParser.add_subparsers": (
        "argparse._SubParsersAction",
        {"dest", "required", "help"},
        0,
    ),
    "argparse._SubParsersAction.add_parser": (
        "argparse.ArgumentParser",
        {"help", "description"},
        1,
    ),
}


def _cli_metadata_factory(factory, call):
    """Resolve metadata-only standard argparse allocations with literal arguments."""
    profile = _CLI_METADATA_FACTORIES.get(factory)
    if profile is None:
        return None
    result, keys, arity = profile
    return (
        result
        if len(call.args) == arity
        and all(isinstance(value, ast.Constant) for value in call.args)
        and all(
            kw.arg in keys and isinstance(kw.value, ast.Constant)
            for kw in call.keywords
        )
        else None
    )


def _captured_immutable_module_text(site, name):
    """Locate one unconditional module binding and gather every source-visible use."""
    from .credential_role_constructor_provider import binding_occurrences
    from .review_integrity import _security_module_scope
    from .semantic_credential_sensor import _security_source_path

    module = _security_module_scope(getattr(site, "_security_lexical_scope", None))
    index = getattr(module, "_security_source_model", None)
    owner = _security_source_path(index, module)
    if owner is None or not index.validate(owner):
        return None
    match binding_occurrences(module.body, name):
        case [ast.Name() as target]:
            pass
        case _:
            return None
    declaration = getattr(target, "_security_parent", None)
    if declaration not in module.body or not isinstance(declaration, ast.Assign):
        return None
    if declaration.targets != [target] or not isinstance(
        declaration.value, ast.Constant
    ):
        return None
    value = declaration.value.value
    if type(value) is not str or len(value) > 4096:
        return None
    uses = [
        ref
        for ref in ast.walk(module)
        if isinstance(ref, ast.Name) and ref.id == name and ref is not target
    ]
    if any(
        not isinstance(ref.ctx, ast.Load) or not _uses_module_binding(ref, module)
        for ref in uses
    ):
        return None
    return index, owner, target, value, uses


def _uses_module_binding(reference, module):
    scope = getattr(reference, "_security_lexical_scope", None)
    while scope is not module:
        if scope is None or any(
            reference.id in getattr(scope, field, ())
            for field in (
                "_security_local_names",
                "_security_parameter_names",
                "_security_nonlocal_names",
            )
        ):
            return False
        scope = getattr(scope, "_security_parent_scope", None)
    return True


def _captured_module_text_unchanged(
    index, owner, target, references, providers=(), *, scalar_reads=()
):
    return _captured_named_provider_unchanged(
        index,
        owner,
        target.id,
        providers,
        readonly_argument=lambda node, _aliases, _parents: node in references,
        readonly_nodes=(target, *scalar_reads),
    )


def _captured_named_provider_unchanged(
    index, owner, name, providers=(), *, readonly_argument=None, readonly_nodes=()
):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .runtime_audit_integrity import _conditional_module_name

    paths = index.module_paths()
    if paths is None:
        return False
    bindings = [
        (_conditional_module_name(module) + "." + name, (owner, name))
        for module, path in paths.items()
        if path == owner
    ]
    if not bindings:
        return False
    canonical, local = bindings[0]
    return not _captured_terminal_provider_mutation(
        index,
        audit,
        canonical,
        local_binding=local,
        additional_bindings=(
            *bindings[1:],
            *((provider, None) for provider in providers),
        ),
        readonly_argument=readonly_argument,
        readonly_nodes=readonly_nodes,
    )


def captured_module_text(site, reference):
    """Read a bound source constant without assuming that a mutable alias is current."""
    source = _captured_immutable_module_text(site, reference.id)
    if source is None:
        return None
    index, owner, origin, value, references = source
    return (
        value
        if reference in references
        and origin.lineno < site.lineno
        and value.casefold().startswith("https://")
        and _captured_module_text_unchanged(index, owner, origin, frozenset(references))
        else None
    )


def _cli_metadata_receiver(call, aliases, source, path, depth=0):
    """Resolve a local, non-escaping argparse receiver before this call."""
    from .credential_role_constructor_provider import (
        _scope_scope_bindings,
        binding_occurrences,
    )

    func = call.func
    if (
        depth >= 3
        or not isinstance(func, ast.Attribute)
        or not isinstance(func.value, ast.Name)
    ):
        return None
    parents = source.parents[path]
    scope = _scope_scope_bindings(call, parents, None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    name = func.value.id
    match binding_occurrences(scope.body, name):
        case [ast.Name() as target]:
            pass
        case _:
            return None
    declaration = parents.get(id(target))
    if not (
        isinstance(declaration, ast.Assign)
        and declaration in scope.body
        and declaration.lineno < call.lineno
        and declaration.targets == [target]
        and isinstance(declaration.value, ast.Call)
    ):
        return None
    if not _cli_receiver_uses_closed(scope, name, call.lineno, parents):
        return None
    constructor = declaration.value
    factory = _captured_call_provider(constructor, aliases, source, path)
    if factory == "argparse.ArgumentParser":
        return _cli_metadata_factory(factory, constructor)
    parent = _cli_metadata_receiver(constructor, aliases, source, path, depth + 1)
    return (
        _cli_metadata_factory(f"{parent}.{constructor.func.attr}", constructor)
        if parent and isinstance(constructor.func, ast.Attribute)
        else None
    )


def _cli_receiver_uses_closed(scope, name, before, parents):
    methods = {"add_argument", "add_subparsers", "add_parser", "set_defaults"}
    for ref in ast.walk(scope):
        if not (
            isinstance(ref, ast.Name)
            and ref.id == name
            and isinstance(ref.ctx, ast.Load)
            and ref.lineno <= before
        ):
            continue
        member = parents.get(id(ref))
        call = parents.get(id(member))
        if not (
            isinstance(member, ast.Attribute)
            and member.attr in methods
            and isinstance(call, ast.Call)
            and call.func is member
        ):
            return False
    return True


def _environment_label_diagnostic(source, path, node):
    """An exact raised message uses a label as text; a lookup must separately prove it."""
    parents = source.parents[path]
    item = parents.get(id(node))
    if not isinstance(item, ast.FormattedValue) or item.value is not node:
        return None
    message = parents.get(id(item))
    call = parents.get(id(message))
    match parents.get(id(call)):
        case ast.Raise(
            exc=ast.Call(func=ast.Name(), args=[argument], keywords=[]) as raised
        ) if (
            raised is call
            and argument is message
            and _registry_formatted_label(item, message)
        ):
            pass
        case _:
            return None
    from .credential_identity_audit import _app_builtin_annotation_inert
    from .credential_role_identity_effects import (
        source_symbol_index,
        _enclosing_function,
    )
    from .mock_fixture_provenance import _app_source_symbol

    index = source_symbol_index(source)
    if index is None:
        return None
    scope = _enclosing_function(call, parents)
    found = _app_source_symbol(index, path, call.func, scope)
    builtins = {"Exception", "RuntimeError", "ValueError"}
    if found is None:
        stable = call.func.id in builtins and _app_builtin_annotation_inert(
            index, path, call.func
        )
    else:
        owner_path, owner = found
        stable = (
            isinstance(owner, ast.ClassDef)
            and not owner.decorator_list
            and not owner.keywords
            and len(owner.bases) == 1
            and isinstance(owner.bases[0], ast.Name)
            and owner.bases[0].id in builtins
            and _app_builtin_annotation_inert(index, owner_path, owner.bases[0])
            and all(
                isinstance(part, ast.Pass)
                or isinstance(part, ast.Expr)
                and isinstance(part.value, ast.Constant)
                and isinstance(part.value.value, str)
                for part in owner.body
            )
            and _captured_exception_type_unchanged(index, owner_path, owner)
        )
    return "diagnostic" if stable else None


def _captured_exception_type_unchanged(index, owner, cls):
    """Close class identity without treating a verified pytest type operand as mutation."""
    from .credential_role_identity_effects import (
        _enclosing_function,
        _source_call_head_shadowed,
    )
    from .mock_fixture_provenance import _app_expression_name
    from .semantic_credential_sensor import _security_source_path

    source = index["source"]
    providers = ()
    if not any(
        name == "pytest.py" or name.startswith("pytest/")
        for name in index["module_paths"]
    ):
        providers = ("pytest.raises",)

    def readonly(ref, aliases, parents):
        from . import review_audits as audit

        if not providers:
            return False
        call = parents.get(id(ref))
        context = parents.get(id(call))
        if not (
            isinstance(call, ast.Call)
            and call.args == [ref]
            and not call.keywords
            and isinstance(context, ast.withitem)
            and context.context_expr is call
            and audit._resolved_ast_name(call.func, aliases) == "pytest.raises"
        ):
            return False
        module = call
        while id(module) in parents:
            module = parents[id(module)]
        path = _security_source_path(source, module)
        return (
            path is not None
            and _app_expression_name(
                index, path, call.func, _enclosing_function(call, parents)
            )
            == "pytest.raises"
            and not _source_call_head_shadowed(call, source, path, audit)
        )

    return _captured_named_provider_unchanged(
        source, owner, cls.name, providers, readonly_argument=readonly
    )


def _registry_stderr_message(call, message, aliases, source, path):
    from . import review_audits as audit
    from .credential_identity_audit import _app_builtin_annotation_inert
    from .credential_role_constructor_provider import _presentation_provider_shadow
    from .credential_role_identity_effects import source_symbol_index

    match call:
        case ast.Call(
            func=ast.Name(id="print") as printer,
            args=[arg],
            keywords=[
                ast.keyword(
                    arg="file", value=ast.Attribute(value=ast.Name() as root) as sink
                )
            ],
        ) if arg is message:
            index = source_symbol_index(source)
            return (
                index is not None
                and audit._resolved_ast_name(sink, aliases) == "sys.stderr"
                and not _presentation_provider_shadow(
                    sink, root.id, source, path, audit
                )
                and _app_builtin_annotation_inert(index, path, printer)
            )
    return False


def _registry_stderr_operands(source):
    """Return only captured stderr references consumed by the stable print builtin."""
    from . import review_audits as audit

    result = set()
    for path, tree in source.snapshots.items():
        aliases = audit._module_security_aliases(tree)
        parents = source.parents[path]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or len(node.args) != 1:
                continue
            if _registry_stderr_message(node, node.args[0], aliases, source, path):
                value = node.keywords[0].value
                if parents.get(id(value)) is node.keywords[0]:
                    result.add(value)
    return result


def _registry_help_message(argument, aliases, source, path):
    parents = source.parents[path]
    keyword = parents.get(id(argument))
    call = parents.get(id(keyword))
    return (
        isinstance(keyword, ast.keyword)
        and keyword.arg == "help"
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "add_argument"
        and all(
            kw.arg in {"help", "default", "required", "dest", "metavar"}
            for kw in call.keywords
        )
        and _cli_metadata_receiver(call, aliases, source, path)
        == "argparse.ArgumentParser"
    )


_CREDENTIAL_LOCATOR_PROVIDERS = frozenset(
    f"{module}.{name}"
    for module in ("fastapi.security", "fastapi.security.api_key")
    for name in ("APIKeyHeader", "APIKeyQuery", "APIKeyCookie")
)


def _captured_call_provider(call, aliases, source, path):
    """Resolve one imported callable only when its lexical root stays unshadowed."""
    from . import review_audits as audit
    from .credential_role_constructor_provider import _presentation_provider_shadow
    from .mock_fixture_provenance import _root_name
    from .security_configuration import _canonical

    root = _root_name(call.func)
    if not root or _presentation_provider_shadow(call.func, root, source, path, audit):
        return None
    return _canonical(call, aliases)


def _registry_locator_use(keyword, call, aliases, source, path):
    """Check a documented lookup-name slot on a stable captured provider."""
    if not (
        keyword.arg == "name"
        and isinstance(call, ast.Call)
        and not call.args
        and all(
            item.arg in {"name", "scheme_name", "description", "auto_error"}
            for item in call.keywords
        )
        and len({item.arg for item in call.keywords}) == len(call.keywords)
    ):
        return None
    canonical = _captured_call_provider(call, aliases, source, path)
    return canonical if canonical in _CREDENTIAL_LOCATOR_PROVIDERS else None


def _public_registry_use(reference, aliases, source, path):
    parents = source.parents[path]
    parent = parents.get(id(reference))
    if _registry_cookie_name_use(reference, parent, aliases, source, path):
        return _COOKIE_NAME_ROLE
    match parent:
        case ast.Call(args=[operand, *defaults], keywords=[]) if (
            operand is reference
            and len(defaults) <= 1
            and all(isinstance(default, ast.Constant) for default in defaults)
        ):
            canonical = _captured_call_provider(parent, aliases, source, path)
            if canonical == "sys.exit":
                return (
                    "exit_message"
                    if not defaults and _exit_chain_closed(source, path, parent)
                    else False
                )
            return canonical in {"os.environ.get", "os.getenv"}
    if isinstance(parent, ast.keyword):
        return _registry_locator_use(
            parent, parents.get(id(parent)), aliases, source, path
        )
    if isinstance(parent, ast.FormattedValue):
        return _registry_formatted_use(reference, parent, aliases, source, path)
    match parent:
        case ast.BinOp(left=ast.Constant(value=str()), op=ast.Mod(), right=right) if (
            right is reference
        ):
            if _registry_help_message(parent, aliases, source, path):
                return "help"
    return False


def _registry_formatted_use(reference, item, aliases, source, path):
    parents = source.parents[path]
    message = parents.get(id(item))
    if not _registry_formatted_label(item, message):
        return False
    if _registry_help_message(message, aliases, source, path):
        return "help"
    if _registry_stderr_message(
        parents.get(id(message)), message, aliases, source, path
    ):
        return "stderr"
    return _environment_label_diagnostic(source, path, reference)


def _registry_formatted_label(item, message):
    return (
        item.format_spec is None
        and item.conversion == -1
        and isinstance(message, ast.JoinedStr)
        and all(
            part is item or isinstance(part, ast.Constant) for part in message.values
        )
    )


def _registry_external_references(source, owner, origin):
    """Use the same exact symbol inventory for copied strings and imported roles."""
    from . import review_audits as audit
    from .credential_role_identity_effects import source_symbol_index

    symbols = source_symbol_index(source)
    if symbols is None:
        return None
    identity = owner, source.parents[owner].get(id(origin))
    reads = _text_binding_reads(source, symbols, identity, None)
    if reads is None:
        return None
    return [
        (ref, path, audit._module_security_aliases(source.snapshots[path]))
        for ref, path in reads
        if path != owner
    ]


def _registry_locator_namespace_closed(source, name, value):
    """Reject shadow providers and namespace reads that lack a tracked use edge."""
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", value) is None:
        return False
    paths = source.module_paths()
    if paths is None or any(
        {"fastapi", "fastapi.py"}.intersection(path.casefold().split("/"))
        for path in paths
    ):
        return False
    return _registry_binding_namespace_closed(source, name)


def _registry_binding_namespace_closed(source, name, *, reject_reflection=False):
    attributes = {name}
    dynamic = frozenset()
    if reject_reflection:
        paths = source.module_paths()
        if paths is None or any(
            {"os", "os.py"}.intersection(path.casefold().split("/")) for path in paths
        ):
            return False
        dynamic = frozenset(
            {"eval", "exec", "globals", "locals", "vars", "__import__", "import_module"}
        )
        attributes.update(dynamic | {"__dict__", "__globals__", "__getattribute__"})
    return not any(
        isinstance(item, ast.Attribute)
        and item.attr in attributes
        or isinstance(item, ast.ImportFrom)
        and any(alias.name in {name, "*"} for alias in item.names)
        or isinstance(item, (ast.Name, ast.alias))
        and (item.id if isinstance(item, ast.Name) else item.name) in dynamic
        for tree in source.snapshots.values()
        for item in ast.walk(tree)
    )


def _environment_scalar_reads(source):
    """A direct read returns a string, never the verified stdlib mapping."""
    from . import review_audits as audit
    from .credential_role_constructor_provider import _presentation_provider_shadow

    for path, tree in source.snapshots.items():
        aliases = audit._module_security_aliases(tree)
        for flow in ast.walk(tree):
            if not isinstance(flow, (ast.Return, ast.Yield)):
                continue
            match flow.value:
                case (
                    ast.Subscript(value=ast.Name(id=root) as mapping, ctx=ast.Load())
                    | ast.Subscript(
                        value=ast.Attribute(value=ast.Name(id=root)) as mapping,
                        ctx=ast.Load(),
                    )
                ):
                    if audit._resolved_ast_name(
                        mapping, aliases
                    ) == "os.environ" and not _presentation_provider_shadow(
                        mapping, root, source, path, audit
                    ):
                        yield flow


def _captured_text_may_be_secret(value):
    """Keep an undecodable candidate active without repeating the pattern scan."""
    from .context_efficiency import _SECRET_BYTES

    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return any(pattern.search(raw) for pattern in _SECRET_BYTES)


def _registry_label_kind(value, aliases):
    if not isinstance(value, str) or not value.isascii() or not value:
        return None
    registry_label = value.isupper() and value.isidentifier()
    if not registry_label and (
        len(value) > 128
        or not any(
            candidate == binding or candidate.startswith(binding + ".")
            for candidate in _CREDENTIAL_LOCATOR_PROVIDERS
            for binding in aliases.values()
            if isinstance(binding, str)
        )
    ):
        return None
    return None if _captured_text_may_be_secret(value) else registry_label


def captured_public_registry_label(node, target, aliases):
    """Recognize closed registry labels used only for lookup and public messages."""
    node._security_cookie_role_facts = {}
    value = getattr(node.value, "value", None)
    registry_label = _registry_label_kind(value, aliases)
    if registry_label is None and {"sys", "sys.exit"}.isdisjoint(
        binding for binding in aliases.values() if isinstance(binding, str)
    ):
        return False
    source = _captured_immutable_module_text(node, target.id)
    if source is None or source[2] is not target:
        return False
    index, owner, origin, _, references = source
    foreign = _registry_external_references(index, owner, origin)
    if foreign is None:
        return False
    uses = [(ref, owner, aliases) for ref in references] + list(foreign)
    roles = [
        _public_registry_use(ref, occurrence, index, path)
        for ref, path, occurrence in uses
    ]
    readonly = set(references) | {ref for ref, _, _ in foreign}
    binding = index, owner, origin, readonly
    if set(roles) == {"exit_message"}:
        _stage_registry_exit_message(binding, value, node)
        return False
    proven = _registry_roles_closed(binding, value, registry_label, roles)
    if proven and _COOKIE_NAME_ROLE in roles:
        _stage_public_registry_exclusion(
            index, owner, node, cookie_uses=zip(uses, roles)
        )
        return False
    return proven


def _stage_registry_exit_message(binding, value, node):
    """Stage the exit-message witness only for an unchanged public provider."""
    if not _captured_text_may_be_secret(value) and _captured_module_text_unchanged(
        *binding, providers=("sys.exit",)
    ):
        index, owner, _, _ = binding
        _stage_public_registry_exclusion(index, owner, node)


def _stage_public_registry_exclusion(index, owner, node, *, cookie_uses=None):
    from .captured_operand_audit import cookie_name_trace
    from .pytest_collection_audit import _captured_pytest_inputs

    stage = getattr(
        _captured_pytest_inputs(index.snapshots[owner])[1],
        "provisional_exclusions",
        None,
    )
    if type(stage) is set:
        point = (
            "SECURITY_HARDCODED_SECRET",
            index.relative(owner),
            *_native_span(node),
            "CRITICAL",
        )
        if cookie_uses is not None:
            trace = cookie_name_trace(index, cookie_uses)
            if trace is None:
                return
            digest = sha256(
                json.dumps(trace, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            node._security_cookie_role_facts = {"cookie_name_use_trace": trace}
            point = (*point, digest)
        stage.add(point)


def _exit_chain_closed(source, path, site, active=()):
    """Follow exact source callers; catching or inspecting SystemExit keeps the origin live."""
    tree, parents = source.snapshots[path], source.parents[path]
    child = site
    while (parent := parents.get(id(child))) is not None:
        if isinstance(parent, (ast.Try, getattr(ast, "TryStar", ast.Try))) and (
            parent.finalbody or child in parent.body
        ):
            return False
        if (
            isinstance(parent, (ast.With, ast.AsyncWith))
            and child is not parent.items[0]
        ):
            return False
        if isinstance(
            parent, (ast.ClassDef, ast.Lambda, ast.AsyncFunctionDef, ast.GeneratorExp)
        ):
            return False
        if isinstance(parent, ast.FunctionDef):
            if (
                parent in active
                or len(active) >= 8
                or any(
                    isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(parent)
                )
            ):
                return False
            callers = _sql_batch_callers(source, path, tree, parent)
            return bool(callers) and all(
                _exit_chain_closed(source, path, ref, (*active, parent))
                for ref, _ in callers
            )
        child = parent
    return child is tree


def _registry_roles_closed(binding, value, registry_label, roles):
    if registry_label is None:
        return False
    index, _, origin, readonly = binding
    if "stderr" in roles:
        readonly.update(_registry_stderr_operands(index))
    cookie_name = _COOKIE_NAME_ROLE in roles
    if any(role in _CREDENTIAL_LOCATOR_PROVIDERS for role in roles) and all(
        role in _CREDENTIAL_LOCATOR_PROVIDERS or role == _COOKIE_NAME_ROLE
        for role in roles
    ):
        providers = ("fastapi.security", "sys.modules")
        if cookie_name:
            if not _registry_binding_namespace_closed(
                index, origin.id, reject_reflection=True
            ) or any(
                {"starlette", "starlette.py"}.intersection(path.casefold().split("/"))
                for path in index.module_paths() or ()
            ):
                return False
            providers = (*providers, *sorted(_COOKIE_NAME_PROVIDERS))
        return _registry_locator_namespace_closed(
            index, origin.id, value
        ) and _captured_module_text_unchanged(*binding, providers)
    if cookie_name or not (registry_label and True in roles and all(roles)):
        return False
    lookup_only = all(role is True for role in roles)
    public = {"help", "stderr", "diagnostic"}.intersection(roles)
    namespace = partial(_registry_binding_namespace_closed, index, origin.id)
    if not (public or lookup_only and namespace(reject_reflection=True)):
        return False
    providers = {
        "help": (*_CLI_METADATA_FACTORIES, "argparse.ArgumentParser.add_argument"),
        "stderr": ("builtins.print", "sys.stderr"),
    }
    selected = {provider for role in roles for provider in providers.get(role, ())}
    selected.update(("os.environ", "os.getenv"))
    if lookup_only:
        selected.add("os._Environ")
    return _captured_module_text_unchanged(
        *binding,
        providers=tuple(sorted(selected)),
        scalar_reads=_environment_scalar_reads(index) if lookup_only else (),
    )


def tls_transport_relation(url, site):
    """Classify the selected source URL without performing network I/O."""
    from urllib.parse import urlsplit

    match url:
        case ast.Constant(value=str() as value):
            pass
        case ast.Name():
            value = captured_module_text(site, url)
        case (
            ast.BinOp(op=ast.Add(), left=ast.Constant(value=str() as prefix))
            | ast.JoinedStr(values=[ast.Constant(value=str() as prefix), *_])
        ):
            return "https_capable" if prefix.casefold().startswith("https://") else None
        case _:
            return None
    try:
        parsed = urlsplit(value) if value else None
        return (
            "static_https"
            if parsed and parsed.scheme == "https" and parsed.hostname
            else None
        )
    except (ValueError, UnicodeError):
        return None


def _local_transport_value(node, reference):
    """Resolve a direct local allocation and its complete set of lexical uses."""
    from .credential_role_constructor_provider import binding_occurrences

    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if reference.id not in getattr(scope, "_security_local_names", ()):
        return None
    match binding_occurrences(scope.body, reference.id):
        case [ast.Name() as definition]:
            pass
        case _:
            return None
    assignment = getattr(definition, "_security_parent", None)
    if not (
        isinstance(assignment, ast.Assign)
        and assignment in scope.body
        and assignment.targets == [definition]
    ):
        return None
    uses = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Name)
        and item.id == reference.id
        and item is not definition
    ]
    if any(
        not isinstance(item.ctx, ast.Load)
        or getattr(item, "_security_lexical_scope", None) is not scope
        or item.lineno <= assignment.end_lineno
        for item in uses
    ):
        return None
    return assignment.value, uses


def _urllib_context_uses(source):
    """Follow an inline context or a definite local with no unrelated uses."""
    parent = getattr(source, "_security_parent", None)
    if isinstance(parent, ast.keyword):
        return (source,)
    if not (
        isinstance(parent, ast.Assign)
        and len(parent.targets) == 1
        and isinstance(parent.targets[0], ast.Name)
        and parent.value is source
    ):
        return ()
    proof = _local_transport_value(source, parent.targets[0])
    return proof[1] if proof is not None and proof[0] is source else ()


def _stdlib_http_url(call, positional, keyword_only=()):
    from .security_configuration import _expanded, _keyword

    keywords = {item.arg for item in call.keywords}
    if (
        _expanded(call)
        or len(call.args) > len(positional)
        or len(keywords) != len(call.keywords)
        or not keywords <= set(positional[len(call.args) :] + keyword_only)
    ):
        return None
    return _keyword(call, "url", 0)


def _urllib_request_transport(call, aliases):
    from .security_configuration import _canonical

    target = _stdlib_http_url(call, ("url", "data", "timeout"), ("context",))
    if isinstance(target, ast.Name):
        proof = _local_transport_value(call, target)
        if proof is not None and proof[1] == [target]:
            target = proof[0]
    if (
        isinstance(target, ast.Call)
        and _canonical(target, aliases) == "urllib.request.Request"
    ):
        target = _stdlib_http_url(
            target,
            ("url", "data", "headers", "origin_req_host", "unverifiable", "method"),
        )
    return tls_transport_relation(target, call)


def _urllib_context_consumer(reference, aliases):
    from .security_configuration import _canonical, _expanded
    from .semantic_credential_sensor import security_precondition_path_possible

    keyword = getattr(reference, "_security_parent", None)
    call = getattr(keyword, "_security_parent", None)
    if not (
        isinstance(keyword, ast.keyword)
        and keyword.arg == "context"
        and isinstance(call, ast.Call)
        and not _expanded(call)
        and sum(item.arg == "context" for item in call.keywords) == 1
        and _canonical(call, aliases) == "urllib.request.urlopen"
        and security_precondition_path_possible(call)
    ):
        return None
    return call, _urllib_request_transport(call, aliases)


def _stdlib_tls_providers_closed(source):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .review_integrity import _security_module_scope

    module = _security_module_scope(getattr(source, "_security_lexical_scope", None))
    index = getattr(module, "_security_source_model", None)
    return (
        index is not None
        and not any(
            p.name in {"ssl.py", "urllib.py"} or "urllib" in p.parts
            for p in index.snapshots
        )
        and not _captured_terminal_provider_mutation(
            index,
            audit,
            "ssl._create_unverified_context",
            additional_bindings=(
                ("urllib.request.urlopen", None),
                ("urllib.request.Request", None),
            ),
        )
    )


def bind_urllib_tls_context(finding, source, aliases):
    """Bind a verified stdlib HTTPS consumer to its exact TLS context allocation."""
    from .security_configuration import _canonical
    from .semantic_credential_sensor import (
        _SECURITY_EFFECT_CONTRACTS_BASELINE,
        security_precondition_path_possible,
        supported_security_precondition,
    )

    if (
        source.args
        or source.keywords
        or _canonical(source, aliases) != "ssl._create_unverified_context"
        or not security_precondition_path_possible(source)
    ):
        return finding
    consumers = [
        _urllib_context_consumer(ref, aliases) for ref in _urllib_context_uses(source)
    ]
    if not consumers or None in consumers:
        return finding
    selected = next(
        ((call, relation) for call, relation in consumers if relation), None
    )
    if selected is None or not _stdlib_tls_providers_closed(source):
        return finding
    contract = _SECURITY_EFFECT_CONTRACTS_BASELINE[finding["code"]]
    call, relation = selected
    witness = {
        "effect_kind": contract["effect_kind"],
        "source_span": [
            source.lineno,
            source.col_offset,
            source.end_lineno,
            source.end_col_offset,
        ],
        "effect_facts": {
            "provider_id": "urllib.request.urlopen",
            "verification_setting": "unverified_context",
            "transport_relation": relation,
            "https_operation_span": [
                call.lineno,
                call.col_offset,
                call.end_lineno,
                call.end_col_offset,
            ],
        },
    }
    finding["facts"]["security_precondition"] = supported_security_precondition(
        source,
        contract["source_role"],
        contract["consumer_role"],
        witness,
    )
    return finding


_COMPOSE_PROFILE_FILES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)
_LAUNCH_BLOCKERS = (
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
)


def is_launch_configuration(name):
    """Identify only bounded Compose selectors and declared Docker build inputs."""
    return isinstance(name, str) and (
        name.casefold() in (*_COMPOSE_PROFILE_FILES, *_LAUNCH_BLOCKERS)
        or bool(
            re.fullmatch(
                r"(?:[\w.-]+/)*(?:Dockerfile(?:\.[\w.-]+)?|\.dockerignore)",
                name,
                re.ASCII | re.IGNORECASE,
            )
        )
        and all(part not in {".", ".."} for part in name.split("/"))
    )


def _compose_services(raw):
    import yaml

    if not isinstance(raw, bytes) or len(raw) > 65_536:
        return None
    try:
        if any(
            getattr(event, "anchor", None) or getattr(event, "tag", None)
            for event in yaml.parse(raw, Loader=yaml.SafeLoader)
        ):
            return None
        node = yaml.compose(raw, Loader=yaml.SafeLoader)
        pending = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, yaml.MappingNode):
                keys = [
                    key.value
                    for key, _ in current.value
                    if isinstance(key, yaml.ScalarNode)
                ]
                if len(keys) != len(current.value) or len(set(keys)) != len(keys):
                    return None
                pending.extend(value for _, value in current.value)
            elif isinstance(current, yaml.SequenceNode):
                pending.extend(current.value)
        document = yaml.safe_load(raw)
    except (yaml.YAMLError, UnicodeError, ValueError, RecursionError, TypeError):
        return None
    if not isinstance(document, dict) or "include" in document:
        return None
    services = document.get("services")
    return services if isinstance(services, dict) else None


def _compose_build(service):
    build = service.get("build") if isinstance(service, dict) else None
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict) or not set(build) <= {"context", "dockerfile"}:
        return None
    context, file = build.get("context", "."), build.get("dockerfile", "Dockerfile")
    if not all(isinstance(part, str) for part in (context, file)):
        return None
    root, docker = PurePosixPath(context), PurePosixPath(file)
    if (
        root.is_absolute()
        or docker.is_absolute()
        or ".." in (*root.parts, *docker.parts)
    ):
        return None
    path = (root / docker).as_posix()
    return (root, path) if is_launch_configuration(path) else None


def _observed_launcher_path(root, declared):
    """Bind a selector to its actual spelling on case-insensitive filesystems."""
    try:
        (root / declared).resolve(strict=True).relative_to(root)
        path = root
        for part in PurePosixPath(declared.casefold()).parts:
            (path,) = [p for p in path.iterdir() if p.name.casefold() == part]
        return path.relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):
        return declared


def capture_launch_configuration(root, read_source, limit, paths):
    """Discover only local build inputs referenced by the captured Compose files."""
    cached = {}
    selected = set(paths)
    observe = partial(_observed_launcher_path, Path(root).resolve())
    for declared in (*_COMPOSE_PROFILE_FILES, *_LAUNCH_BLOCKERS):
        name = observe(declared)
        try:
            raw = read_source(root, name)
        except (OSError, ValueError, RuntimeError) as exc:
            if not (
                isinstance(exc, FileNotFoundError)
                or getattr(exc, "code", None) == "E_SOURCE_MISSING"
            ):
                selected.add(name)
            continue
        cached[name] = raw
        selected.add(name)
        services = (
            _compose_services(raw) if name == declared and len(raw) <= limit else None
        )
        builds = map(_compose_build, (services or {}).values())
        for directory, docker in filter(None, builds):
            ignore = (directory / ".dockerignore").as_posix()
            selected.update(map(observe, (docker, ignore, docker + ".dockerignore")))

    def read(workspace, name):
        return cached[name] if name in cached else read_source(workspace, name)

    read.order = lambda name: (name not in cached, name)
    return selected, read


def _launch_text_sources(module):
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return {}
    root, documents = context
    explicit = getattr(module, "_security_oracle_context", {}).get(
        "_security_launch_configs"
    )
    if explicit is not None:
        return {
            name: raw for name, raw in explicit.items() if is_launch_configuration(name)
        }
    return {
        relative: raw
        for path, raw in documents.items()
        if Path(path).is_relative_to(root)
        and is_launch_configuration(relative := Path(path).relative_to(root).as_posix())
    }


def _launch_import_roots(source, configs, focal_path):
    """Map fixed launches and reject unresolved builds that may own the focal source."""
    folded = {name.casefold() for name in configs}
    if folded.intersection(_LAUNCH_BLOCKERS):
        return frozenset()
    focal = PurePosixPath(focal_path.relative_to(source.root).as_posix().casefold())
    roots = set()
    for path in sorted(folded.intersection(_COMPOSE_PROFILE_FILES)):
        services = _compose_services(configs.get(path))
        if services is None or not all(
            isinstance(item, dict) for item in services.values()
        ):
            return frozenset()
        for service in (item for item in services.values() if "build" in item):
            if (selected := _compose_build(service)) is None:
                return frozenset()
            directory, docker_path = selected
            if not _launch_service_closed(service, directory, docker_path, configs):
                return frozenset()
            launched = _fixed_python_launch(configs.get(docker_path), directory)
            if launched is None:
                overlap = focal.is_relative_to(PurePosixPath(str(directory).casefold()))
                if (
                    overlap
                    or service.get("volumes")
                    or (docker_path.casefold() in folded and docker_path not in configs)
                ):
                    return frozenset()
                continue
            work, copies, entry = launched
            mapped = _mapped_launch_sources(source, copies, work, entry)
            if len(mapped) != 1 or not _launch_mounts_closed(
                service, work, entry, mapped
            ):
                return frozenset()
            roots.add(next(iter(mapped))[0])
    return frozenset(roots) if len(roots) == 1 else frozenset()


def _fixed_python_launch(raw, context):
    if not isinstance(raw, bytes) or len(raw) > 65_536:
        return None
    try:
        parsed = _docker_launch_steps(
            raw.decode("utf-8").replace("\\\n", " ").splitlines(), context
        )
    except (UnicodeError, ValueError, TypeError, IndexError):
        return None
    if parsed is None:
        return None
    work, copies, argv = parsed
    entry = _asgi_launch_entry(argv)
    return (work, copies, entry) if entry else None


def _docker_launch_steps(lines, context):
    work, copies, argv = PurePosixPath("/"), [], []
    first = False
    for line in lines:
        directive, _, value = line.strip().partition(" ")
        if not directive or directive.startswith("#"):
            continue
        match directive.upper():
            case "FROM" if not first:
                first = True
            case "WORKDIR" if re.fullmatch(r"/(?:[A-Za-z0-9_-]+/?)+", value):
                work = PurePosixPath(value)
            case "COPY":
                copy = _docker_fixed_copy(value, context, work)
                if copy is None:
                    return None
                copies.append(copy)
            case "CMD" if not argv:
                argv = _docker_json_argv(value)
            case instruction if _launch_build_metadata(instruction, value, copies):
                pass
            case "USER" | "EXPOSE" | "HEALTHCHECK" | "LABEL":
                pass
            case _:
                return None
    return (work, copies, argv) if first else None


def _docker_json_argv(value):
    argv = json.loads(value)
    if not isinstance(argv, list) or any(type(arg) is not str for arg in argv):
        raise ValueError("expected literal Docker CMD")
    return argv


def _docker_fixed_copy(value, context, work):
    import shlex

    rows = shlex.split(value)
    if rows and re.fullmatch(r"--chown=[\w-]+:[\w-]+", rows[0], re.ASCII):
        rows = rows[1:]
    if len(rows) != 2 or not all(
        re.fullmatch(r"[A-Za-z0-9_./-]+", item) for item in rows
    ):
        return None
    src, dst = map(PurePosixPath, rows)
    if src.is_absolute() or ".." in (*src.parts, *dst.parts):
        return None
    return context / src, work / dst


def _asgi_launch_entry(argv):
    match argv:
        case ["uvicorn", target, *flags] | ["python", "-m", "uvicorn", target, *flags]:
            module, sep, variable = target.partition(":")
            if (
                sep
                and variable.isidentifier()
                and all(part.isidentifier() for part in module.split("."))
                and len(flags) % 2 == 0
                and set(flags[::2]) <= {"--host", "--port", "--workers", "--log-level"}
            ):
                return tuple(module.split("."))
    return ()


def _launch_build_metadata(instruction, value, copies):
    if instruction == "ENV":
        return _launch_environment_closed(value.split())
    return instruction == "RUN" and _launch_build_step_closed(value, copies)


def _launch_build_step_closed(value, copied):
    """Decline late opaque build effects; admit only allocation/ownership metadata."""
    if not any(src.suffix != ".txt" for src, _ in copied):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_:/ .&-]+", value):
        return False
    return all(
        command.split()[0] in {"mkdir", "chown", "useradd"}
        for command in value.split("&&")
        if command.strip()
    )


def _launch_environment_closed(entries):
    return all(
        isinstance(entry, str)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key := entry.split("=")[0])
        and (
            not key.startswith(("PYTHON", "UVICORN", "LD_", "DYLD_"))
            or key in {"PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
        )
        and key not in {"PATH", "BASH_ENV", "ENV", "GUNICORN_CMD_ARGS"}
        for entry in entries
    )


def _launch_service_closed(service, context, docker, configs):
    env = service.get("environment", {})
    return (
        not set(service).intersection(
            {
                "command",
                "entrypoint",
                "working_dir",
                "env_file",
                "extends",
                "volumes_from",
                "configs",
                "secrets",
                "develop",
                "post_start",
                "pre_stop",
            }
        )
        and isinstance(env, (dict, list))
        and _launch_environment_closed(env)
        and not set(name.casefold() for name in configs).intersection(
            {
                (context / ".dockerignore").as_posix().casefold(),
                (docker + ".dockerignore").casefold(),
            }
        )
    )


def _mapped_launch_sources(index, copies, work, entry):
    mapped = set()
    module_path = work.joinpath(*entry).with_suffix(".py")
    protected = work / entry[0]
    for origin, destination in copies:
        if destination.is_relative_to(protected) and not module_path.is_relative_to(
            destination
        ):
            return set()
        if not module_path.is_relative_to(destination):
            continue
        relative = origin / module_path.relative_to(destination)
        path = index.root / relative.as_posix()
        if path in index.snapshots and index.validate(path):
            mapped.add((path.parents[len(entry) - 1], relative))
        elif origin.suffix != ".txt" or destination != work:
            return set()
    return mapped


def _launch_mounts_closed(service, work, entry, mapped):
    protected = work / entry[0]
    _, launch = next(iter(mapped))
    source_dir = launch.parents[len(entry) - 2] if len(entry) >= 2 else launch
    mounts = service.get("volumes", [])
    if not isinstance(mounts, list):
        return False
    for mount in mounts:
        if not isinstance(mount, str):
            return False
        origin, sep, target = mount.partition(":")
        target, _, mode = target.partition(":")
        path = PurePosixPath(target)
        if not sep or not path.is_absolute() or ".." in path.parts:
            return False
        if (path.is_relative_to(protected) or protected.is_relative_to(path)) and not (
            path == protected
            and origin.startswith("./")
            and PurePosixPath(origin) == source_dir
            and mode == "ro"
        ):
            return False
    return True


def captured_noncredential_assignment(node, target, aliases):
    """Route source-bound non-credential roles at the common raw boundary."""
    return (
        captured_public_registry_label(node, target, aliases)
        or captured_unread_settings_field(node, target)
        or captured_test_derived_input(node, target)
        or captured_config_rejection_point(node, target)
    )


def captured_config_rejection_point(node, target):
    """Stage a source-only rejection proof without suppressing a raw finding."""
    from .pytest_collection_audit import (
        _captured_pytest_inputs,
        captured_pytest_documents,
    )
    from .semantic_credential_sensor import _security_helper_source_context

    scope = _rejected_config_scope(node, target)
    if scope is None:
        return False
    module, source, path = _security_helper_source_context(node, None)
    stage = getattr(_captured_pytest_inputs(module)[1], "provisional_exclusions", None)
    if type(stage) is not set or not (
        location := _rejected_config_location(source, path, node, scope)
    ):
        return False
    if _captured_text_may_be_secret(node.value.value):
        return False
    if _CapturedConfigRejection(source, path).proven(
        module, *scope, captured_pytest_documents(module)
    ):
        stage.add(("SECURITY_HARDCODED_SECRET", *location, "CRITICAL"))
    return False


def _rejected_config_scope(node, target):
    match node:
        case ast.Assign(
            targets=[ast.Name() as name], value=ast.Constant(value=value)
        ) if (
            name is target
            and name.id.isupper()
            and type(value) is str
            and len(value) <= 4096
        ):
            cls = getattr(node, "_security_parent", None)
            owner = getattr(cls, "_security_parent", None)
            if isinstance(cls, ast.ClassDef) and isinstance(owner, ast.FunctionDef):
                return cls, owner
    return None


def _rejected_config_location(source, path, node, scope):
    if (
        path is None
        or not source.validate(path)
        or not (span := _native_span(node))
        or not (relative := source.relative(path))
    ):
        return None
    parents = source.parents[path]
    if (parents.get(id(node)), parents.get(id(scope[0]))) == scope:
        return relative, *span
    return None


class _CapturedConfigRejection:
    """Close the selected class, loader, and all paths before the policy raise."""

    def __init__(self, source, path):
        from .credential_role_identity_effects import source_symbol_index

        self.source, self.path = source, path
        self.symbols = source_symbol_index(source)
        self.external = {"flask.Flask", "flask.config.Config", "pytest.raises"}
        self.readonly = set()

    def proven(self, module, cls, owner, documents):
        from .credential_role_constructor_provider import binding_occurrences
        from .credential_role_identity_effects import resolve_source_identity_call
        from .mock_fixture_provenance import _app_test_function_external_uses_clear
        from .pytest_collection_audit import (
            ConfigurationRejectionProjection,
            _rejection_single_argument,
            captured_pytest_function_selected,
        )

        if (
            self.symbols is None
            or owner not in module.body
            or owner.decorator_list
            or any(ast.iter_child_nodes(owner.args))
        ):
            return False
        match owner.body:
            case [
                selected,
                ast.With(
                    items=[
                        ast.withitem(
                            context_expr=ast.Call() as expect, optional_vars=None
                        )
                    ],
                    body=[ast.Expr(value=ast.Call() as invocation)],
                ),
            ] if selected is cls:
                pass
            case _:
                return False
        references = tuple(_settings_names(owner, cls.name))
        if len(references) != 1 or binding_occurrences(owner.body, cls.name) != [cls]:
            return False
        if not (
            len(expect.args) == 1
            and not expect.keywords
            and self.provider(self.path, owner, expect.func) == "pytest.raises"
            and self.provider(self.path, owner, expect.args[0]) == "RuntimeError"
            and captured_pytest_function_selected(
                self.source, self.path, owner, documents, invocation_index=self.symbols
            )
            and _app_test_function_external_uses_clear(self.symbols, self.path, owner)
        ):
            return False
        bound = resolve_source_identity_call(
            invocation, self.path, self.source, lexical_scope=owner
        )
        if not bound or not bound.negative_binding_closed or len(bound.arguments) != 1:
            return False
        formal, actual = next(iter(bound.arguments.items()))
        if actual is not references[0] or binding_occurrences(
            bound.function.body, formal
        ):
            return False
        config = self.configuration(cls, owner)
        policy = self.policy(bound.path, bound.function, formal)
        if config is None or policy is None:
            return False
        receiver = _rejection_single_argument(policy)
        if receiver is None:
            return False
        projection = ConfigurationRejectionProjection(
            partial(self.provider, bound.path),
            policy,
            config,
            receiver,
            resolve_guard=partial(self.local_function, bound.path),
        )
        return projection.terminal(policy.body) is not None and self.providers_closed(
            bound
        )

    def provider(self, path, owner, node, names=()):
        from .credential_role_constructor_provider import binding_occurrences
        from .mock_fixture_provenance import (
            _app_expression_name,
            _django_builtins_unshadowed,
        )
        from .pytest_collection_audit import _rejection_single_argument

        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in names:
            return None
        if (
            isinstance(node, ast.Name)
            and node.id in {"int", "float", "str", "RuntimeError"}
            and _django_builtins_unshadowed(self.symbols, path, {node.id})
            and (
                owner is None
                or not binding_occurrences(owner.body, node.id)
                and _rejection_single_argument(owner) != node.id
            )
        ):
            self.external.add("builtins." + node.id)
            return node.id
        provider = _app_expression_name(self.symbols, path, node, owner)
        if provider in {"os.environ.get", "pathlib.Path"}:
            self.external.add(provider)
        return provider

    def configuration(self, cls, owner):
        from .credential_role_constructor_provider import binding_occurrences
        from .mock_fixture_provenance import _app_source_symbol
        from .pytest_collection_audit import (
            ConfigurationRejectionProjection,
            _projection_unknown,
        )

        chain = [(self.path, cls)]
        while chain[-1][1].bases:
            p, current = chain[-1]
            if len(chain) >= 8 or len(current.bases) != 1:
                return None
            base = _app_source_symbol(
                self.symbols, p, current.bases[0], owner if current is cls else None
            )
            if not base or not isinstance(base[1], ast.ClassDef) or base in chain:
                return None
            chain.append(base)
        self.bases = chain[1:]
        props = {}
        for p, current in reversed(chain):
            tree = self.source.snapshots[p]
            if (
                current.keywords
                or current.decorator_list
                or current is not cls
                and current not in tree.body
            ):
                return None
            domain = ConfigurationRejectionProjection(
                partial(self.provider, p), owner if current is cls else None, {}
            )
            global_names = {}
            if current is not cls:
                if binding_occurrences(tree.body, "__file__"):
                    return None
                prefix = [
                    n
                    for n in tree.body
                    if isinstance(n, ast.Assign) and n.lineno < current.lineno
                ]
                global_names = domain.namespace(
                    prefix, {"__file__": _projection_unknown("str")}
                )
                if global_names is None or any(
                    len(binding_occurrences(tree.body, name)) != 1
                    for name in global_names
                    if name != "__file__"
                ):
                    return None
            fields = domain.namespace(current.body, global_names, fields=True)
            if fields is None:
                return None
            props.update(fields)
        return props

    def local_function(self, path, node, owner):
        from .mock_fixture_provenance import _app_source_symbol

        ref = _app_source_symbol(self.symbols, path, node, owner)
        if (
            ref
            and ref[0] == path
            and isinstance((fn := ref[1]), ast.FunctionDef)
            and not fn.decorator_list
            and _captured_named_provider_unchanged(self.source, path, fn.name)
        ):
            return fn
        return None

    def allocated_receiver(self, path, function, allocation):
        from .credential_role_constructor_provider import binding_occurrences
        from .pytest_collection_audit import _rejection_assignment
        from .semantic_credential_sensor import _flask_bind_created_app

        receiver = _rejection_assignment(allocation)
        if receiver is None or not isinstance(allocation.value, ast.Call):
            return None
        invocation = allocation.value
        ctor = invocation.func
        if (
            not isinstance(ctor, ast.Name)
            or self.provider(path, function, ctor) != "flask.Flask"
        ):
            return None
        if not (
            len(invocation.args) == 1
            and isinstance(invocation.args[0], ast.Name)
            and invocation.args[0].id == "__name__"
            and not any(
                binding_occurrences(body, "__name__")
                for body in (function.body, self.source.snapshots[path].body)
            )
            and all(
                k.arg == "instance_relative_config"
                and isinstance(k.value, ast.Constant)
                and type(k.value.value) is bool
                for k in invocation.keywords
            )
        ):
            return None
        allocated = {}
        _flask_bind_created_app(allocation, allocated, {ctor.id: "flask.Flask"})
        return receiver if allocated.get(receiver) is invocation else None

    def policy(self, path, function, formal):
        if function.decorator_list or len(function.body) < 3:
            return None
        allocation, loader, *prefix = function.body
        receiver = self.allocated_receiver(path, function, allocation)
        load = _rejection_call_statement(loader)
        if not (
            receiver
            and load
            and not load.keywords
            and len(load.args) == 1
            and ast.unparse(load.func) == receiver + ".config.from_object"
            and tuple(_settings_names(function, formal)) == tuple(load.args)
        ):
            return None
        for stmt in prefix:
            call = _rejection_call_statement(stmt)
            if not call or call.keywords or not isinstance(call.func, ast.Name):
                return None
            callee = self.local_function(path, call.func, function)
            if callee is None:
                return None
            if (
                len(call.args) == 1
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == receiver
            ):
                return callee
            if (
                call.args
                or any(ast.iter_child_nodes(callee.args))
                or not 0 < len(callee.body) <= 8
                or not all(self.registry(path, callee, n) for n in callee.body)
            ):
                return None
        return None

    def registry(self, path, owner, statement):
        from .pytest_collection_audit import _rejection_single_argument

        call = _rejection_call_statement(statement)
        if not (
            call
            and not call.keywords
            and len(call.args) == 2
            and self.provider(path, owner, call.func) == "sqlite3.register_adapter"
        ):
            return False
        key, callback = call.args
        native = self.provider(path, owner, key)
        if (
            native not in {"datetime.date", "datetime.datetime"}
            or not isinstance(callback, ast.Lambda)
            or (arg := _rejection_single_argument(callback)) is None
        ):
            return False
        body = callback.body
        if not (
            isinstance(body, ast.Call)
            and not body.args
            and len(body.keywords) <= 1
            and isinstance(body.func, ast.Attribute)
            and body.func.attr == "isoformat"
            and isinstance(body.func.value, ast.Name)
            and body.func.value.id == arg
            and all(
                k.arg == "sep"
                and isinstance(k.value, ast.Constant)
                and type(k.value.value) is str
                for k in body.keywords
            )
        ):
            return False
        self.external.update((native, "sqlite3.register_adapter"))
        self.readonly.add(key)
        return True

    def providers_closed(self, bound):
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )
        from .credential_role_identity_effects import _enclosing_function
        from .mock_fixture_provenance import _app_source_symbol

        base_reads, env_writes = set(), []
        for p, tree in self.source.snapshots.items():
            if not self.source.validate(p):
                return False
            parents = self.source.parents[p]
            for n in ast.walk(tree):
                if (
                    self.bases
                    and isinstance(n, ast.Call)
                    and len(n.args) == 1
                    and not n.keywords
                    and _app_source_symbol(
                        self.symbols, p, n.func, _enclosing_function(n, parents)
                    )
                    == (bound.path, bound.function)
                ):
                    base_reads.add(n.args[0])
                if (
                    isinstance(n, ast.Assign)
                    and len(n.targets) == 1
                    and isinstance((lhs := n.targets[0]), ast.Subscript)
                    and isinstance(lhs.slice, ast.Constant)
                    and type(lhs.slice.value) is str
                    and self.provider(p, _enclosing_function(n, parents), lhs.value)
                    == "os.environ"
                ):
                    env_writes.append(lhs)
        if not all(
            _captured_named_provider_unchanged(
                self.source,
                p,
                c.name,
                readonly_argument=lambda n, _a, _p: n in base_reads,
            )
            for p, c in self.bases
        ):
            return False
        roots = {name.split(".", 1)[0] for name in self.external}
        if any(
            name.split("/", 1)[0].removesuffix(".py") in roots
            for name in self.symbols["module_paths"]
        ):
            return False
        return not any(
            _captured_terminal_provider_mutation(
                self.source,
                audit,
                provider,
                readonly_argument=(lambda n, _a, _p: n in self.readonly)
                if provider.startswith("datetime.")
                else None,
                readonly_nodes=env_writes if provider == "os.environ.get" else (),
            )
            for provider in sorted(self.external)
        )


def _rejection_call_statement(stmt):
    return (
        stmt.value
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
        else None
    )


def captured_test_derived_input(node, target):
    """Prove a test value feeds a derived payload and a locally replaced effect."""
    from .credential_role_identity_effects import _enclosing_function
    from .semantic_credential_sensor import _security_helper_source_context

    match node:
        case ast.Assign(
            targets=[ast.Name() as name], value=ast.Constant(value=value)
        ) if name is target and type(value) is str and len(value) <= 4096:
            pass
        case _:
            return False
    module, source, path = _security_helper_source_context(node, None)
    if path is None or not source.validate(path):
        return False
    owner = _enclosing_function(node, source.parents[path])
    match owner:
        case ast.FunctionDef(body=body, decorator_list=[]) if (
            owner in module.body
            and node in body
            and any(isinstance(stmt, ast.With) for stmt in body)
        ):
            if not _captured_text_may_be_secret(value):
                return _CapturedDerivedTestInput(
                    module, source, path, owner, node
                ).proven()
    return False


class _CapturedDerivedTestInput:
    """Close the literal, the derived operands, and the patch interval separately."""

    def __init__(self, module, source, path, function, assignment):
        from .credential_role_identity_effects import source_symbol_index

        self.module, self.source, self.path = module, source, path
        self.function, self.assignment = function, assignment
        self.parents = source.parents[path]
        self.symbols = source_symbol_index(source)
        self.patch = None
        self.effects = []
        self.digest_assertions = set()

    def proven(self):
        from .credential_role_identity_effects import _enclosing_function
        from .finite_capture import captured_value_use_closure
        from .mock_fixture_provenance import _app_test_function_external_uses_clear

        if self.symbols is None or not self._selected():
            return False
        self.patch = self._patch_statement()
        if self.patch is None:
            return False
        proof = captured_value_use_closure(
            self.function,
            self.assignment.value,
            self.parents,
            lambda node: _enclosing_function(node, self.parents),
            lambda _scope: None,
            self._use,
        )
        return (
            proof is not None
            and len(self.effects) == 1
            and _app_test_function_external_uses_clear(
                self.symbols, self.path, self.function
            )
            and self._provider_closure()
        )

    def _selected(self):
        from .pytest_collection_audit import (
            _pytest_collection_hook_names,
            _pytest_plugin_declaration_active,
            captured_pytest_documents,
            captured_pytest_function_selected,
        )

        if not captured_pytest_function_selected(
            self.source,
            self.path,
            self.function,
            captured_pytest_documents(self.module),
        ):
            return False
        return all(
            self.source.validate(path)
            and not _pytest_collection_hook_names(
                tree, path.name == "conftest.py", False
            )
            and not any(_pytest_plugin_declaration_active(node) for node in tree.body)
            and not any(
                isinstance(node, ast.Name) and node.id == "__test__"
                for node in ast.walk(tree)
            )
            for path, tree in self.source.snapshots.items()
        )

    def _canonical(self, path, node, function=None):
        from .mock_fixture_provenance import _app_expression_name

        return _app_expression_name(self.symbols, path, node, function)

    def _patch_statement(self):
        patches = []
        for node in self.function.body:
            match node:
                case ast.With(
                    items=[
                        ast.withitem(
                            context_expr=ast.Call(
                                args=[
                                    ast.Attribute() as receiver,
                                    ast.Constant(value=str() as member),
                                ],
                                keywords=[ast.keyword(arg="return_value")],
                            ) as factory,
                            optional_vars=ast.Name() as mock,
                        )
                    ],
                    body=[ast.Expr(value=ast.Call() as exercise)],
                ) if (
                    self._canonical(self.path, factory.func, self.function)
                    == "unittest.mock.patch.object"
                ):
                    patches.append((receiver, member, mock, exercise))
        return patches[0] if len(patches) == 1 else None

    def _use(self, scope, ref):
        if scope is not self.function or not isinstance(ref, ast.Name):
            return None
        parent = self.parents.get(id(ref))
        if (
            isinstance(parent, ast.Call)
            and parent.args == [ref]
            and not parent.keywords
        ):
            if parent is self.patch[3]:
                effect = self._mocked_digest_effect(parent)
                if effect is None:
                    return None
                self.effects.append(effect)
                return parent
            return self._digest_assertion(parent)
        return self._absence_assertion(ref, parent)

    def _digest_assertion(self, call):
        bracket = self.parents.get(id(call))
        compare = self.parents.get(id(bracket))
        statement = self.parents.get(id(compare))
        if not (
            isinstance(bracket, ast.Subscript)
            and bracket.value is call
            and _digest_slice_bound(bracket, upper=True) is not None
            and isinstance(compare, ast.Compare)
            and len(compare.ops) == 1
            and isinstance(compare.ops[0], ast.Eq)
            and isinstance(statement, ast.Assert)
            and statement.test is compare
            and statement.msg is None
        ):
            return None
        provider = self._digest_callable(self.path, call)
        if provider is None:
            return None
        self.digest_assertions.add(provider)
        return statement

    def _absence_assertion(self, ref, compare):
        match compare:
            case ast.Compare(
                left=left, ops=[ast.NotIn()], comparators=[ast.Name(id=name)]
            ) if left is ref:
                statement = self.parents.get(id(compare))
                if (
                    isinstance(statement, ast.Assert)
                    and statement.test is compare
                    and statement.msg is None
                ):
                    return (
                        statement
                        if self._mock_argument_local(name, statement)
                        else None
                    )
        return None

    def _mock_argument_local(self, name, statement):
        from .credential_role_constructor_provider import (
            binding_dominates,
            binding_occurrences,
        )

        bindings = binding_occurrences(self.function.body, name)
        if len(bindings) != 1:
            return False
        assignment = self.parents.get(id(bindings[0]))
        if not isinstance(assignment, ast.Assign) or not binding_dominates(
            assignment, statement, self.parents, self.function
        ):
            return False
        match assignment.value:
            case ast.Subscript(
                value=ast.Attribute(
                    value=ast.Attribute(
                        value=ast.Name(id=mock) as receiver, attr="call_args"
                    ),
                    attr="args",
                ),
                slice=ast.Constant(value=0),
            ):
                return (
                    mock == self.patch[2].id
                    and binding_occurrences(self.function.body, mock) == [self.patch[2]]
                    and list(_settings_names(self.function, mock)) == [receiver]
                )
        return False

    def _digest_callable(self, path, call):
        from .credential_role_identity_effects import resolve_source_identity_call

        result = resolve_source_identity_call(call, path, self.source)
        if not result or not result.negative_binding_closed:
            return None
        fn = result.function
        if not (
            isinstance(fn, ast.FunctionDef)
            and len(fn.args.args) == 1
            and not fn.args.defaults
            and len(result.arguments) == 1
        ):
            return None
        body = _fixture_effect_body(fn)
        if len(body) != 1 or not isinstance(body[0], ast.Return):
            return None
        digest = _digest_return_shape(body[0].value, fn.args.args[0].arg)
        if digest is None:
            return None
        provider = self._canonical(result.path, digest.func, fn)
        return (
            provider
            if provider in {"hashlib.sha1", "hashlib.sha256", "hashlib.sha512"}
            else None
        )

    def _mocked_digest_effect(self, call):
        from .credential_role_identity_effects import resolve_source_identity_call

        bound = resolve_source_identity_call(call, self.path, self.source)
        if not bound or not bound.negative_binding_closed:
            return None
        formal = next(
            (name for name, arg in bound.arguments.items() if arg is call.args[0]), None
        )
        if formal is None:
            return None
        return self._derived_receiver_effect(bound.path, bound.function, formal)

    def _derived_receiver_effect(self, path, function, formal):
        body = _fixture_effect_body(function)
        if len(body) < 3:
            return None
        match body[:3]:
            case [
                ast.Assign(
                    targets=[ast.Name(id=digest)],
                    value=ast.Call(
                        args=[ast.Name(id=arg) as raw], keywords=[]
                    ) as derive,
                ),
                ast.Assign(
                    targets=[
                        ast.Tuple(elts=[ast.Name(id=prefix), ast.Name(id=suffix)])
                    ],
                    value=ast.Tuple(
                        elts=[ast.Subscript() as first, ast.Subscript() as rest]
                    ),
                ),
                ast.Assign(
                    targets=[ast.Name()],
                    value=ast.Call(
                        args=[
                            ast.BinOp(
                                op=ast.Add(),
                                left=base,
                                right=ast.Name(id=prefix_use) as excerpt,
                            )
                        ]
                    ) as request,
                ),
            ] if formal == arg and prefix_use == prefix:
                pass
            case _:
                return None
        split = _digest_partition(function, digest, first, rest)
        if not (
            split is not None
            and list(_settings_names(function, formal)) == [raw]
            and list(_settings_names(function, prefix)) == [excerpt]
            and _digest_comparison_only(function, suffix, self.source.parents[path])
        ):
            return None
        provider = self._digest_callable(path, derive)
        selected = self._patch_matches_request(path, function, request, base)
        if provider is None or selected is None:
            return None
        return (provider, selected)

    def _patch_matches_request(self, path, function, request, base):
        from .import_context import captured_import_module

        receiver, member, _, _ = self.patch
        if not isinstance(request.func, ast.Attribute) or request.func.attr != member:
            return None
        if member != "get" or not isinstance(request.func.value, ast.Name):
            return None
        bound = self._canonical(self.path, receiver, self.function)
        provider = self._canonical(path, request.func.value, function)
        if not bound or provider != "requests":
            return None
        module, _, attribute = bound.rpartition(".")
        if attribute != request.func.value.id or captured_import_module(
            self.source, self.path, module
        ) != (True, path):
            return None
        if not _fixed_digest_request_base(
            _captured_text_operand(self.source, self.symbols, path, function, base)
        ):
            return None
        return path, request.func.value.id, provider + "." + member

    def _provider_closure(self):
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )

        digest, (owner, slot, transport) = self.effects[0]
        if any(
            name == root + ".py" or name.startswith(root + "/")
            for name in self.symbols["module_paths"]
            for root in ("unittest", "requests", "hashlib")
        ):
            return False
        if not _captured_named_provider_unchanged(
            self.source, owner, slot, readonly_argument=_fixed_mock_patch_operand
        ):
            return False
        return (
            not _captured_terminal_provider_mutation(
                self.source,
                audit,
                digest,
                additional_bindings=(
                    ("unittest.mock.patch.object", None),
                    *(
                        (name, None)
                        for name in sorted(self.digest_assertions - {digest})
                    ),
                ),
            )
            and transport == "requests.get"
        )


def _fixed_mock_patch_operand(node, aliases, parents):
    """A scoped standard-library patch reads the module binding it will patch."""
    from . import review_audits as audit

    call = parents.get(id(node))
    owner = parents.get(id(call))
    return (
        isinstance(call, ast.Call)
        and len(call.args) == 2
        and call.args[0] is node
        and isinstance(call.args[1], ast.Constant)
        and call.args[1].value == "get"
        and [kw.arg for kw in call.keywords] == ["return_value"]
        and isinstance(owner, ast.withitem)
        and owner.context_expr is call
        and audit._resolved_ast_name(call.func, aliases) == "unittest.mock.patch.object"
    )


def _fixture_effect_body(function):
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is str
    ):
        return body[1:]
    return body


def _digest_return_shape(value, formal):
    match value:
        case ast.Call(
            func=ast.Attribute(value=inner, attr=("upper" | "lower")),
            args=[],
            keywords=[],
        ):
            value = inner
    match value:
        case ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    args=[
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id=selected), attr="encode"
                            ),
                            args=[ast.Constant(value=("utf-8" | "ascii"))],
                            keywords=[],
                        )
                    ],
                    keywords=[],
                ) as digest,
                attr="hexdigest",
            ),
            args=[],
            keywords=[],
        ) if selected == formal:
            return digest
    return None


def _digest_partition(function, name, first, rest):
    if not all(
        isinstance(part.value, ast.Name) and part.value.id == name
        for part in (first, rest)
    ):
        return None
    if set(_settings_names(function, name)) != {first.value, rest.value}:
        return None
    start, end = (
        _digest_slice_bound(rest, upper=False),
        _digest_slice_bound(first, upper=True),
    )
    return start if start == end else None


def _digest_slice_bound(bracket, *, upper):
    slc = bracket.slice
    if not isinstance(slc, ast.Slice) or slc.step is not None:
        return None
    index, empty = (slc.upper, slc.lower) if upper else (slc.lower, slc.upper)
    if (
        empty is not None
        or not isinstance(index, ast.Constant)
        or type(index.value) is not int
    ):
        return None
    return index.value if 0 < index.value < 40 else None


def _digest_comparison_only(function, suffix, parents):
    uses = tuple(_settings_names(function, suffix))
    if len(uses) != 1:
        return False
    compare = parents.get(id(uses[0]))
    return (
        isinstance(compare, ast.Compare)
        and compare.comparators == [uses[0]]
        and len(compare.ops) == 1
        and isinstance(compare.ops[0], ast.Eq)
        and isinstance(parents.get(id(compare)), ast.If)
    )


def _captured_text_operand(source, symbols, path, function, expression):
    """Resolve a copied immutable module string while checking live slot writes."""
    from .mock_fixture_provenance import _app_source_symbol

    if isinstance(expression, ast.Constant):
        return expression.value
    if not isinstance(expression, ast.Name):
        return None
    selected = _app_source_symbol(symbols, path, expression, function)
    if selected is None:
        return None
    owner, binding = selected
    match binding:
        case ast.Assign(
            targets=[ast.Name() as target], value=ast.Constant(value=str() as text)
        ):
            if binding not in source.snapshots[owner].body:
                return None
        case _:
            return None
    immutable = _text_binding_reads(source, symbols, selected, target.id)
    return (
        text
        if immutable
        and expression in immutable
        and _captured_module_text_unchanged(source, owner, target, immutable)
        else None
    )


def _text_binding_reads(source, symbols, selected, name):
    from .credential_role_identity_effects import _enclosing_function
    from .mock_fixture_provenance import _app_source_symbol

    reads = set()
    for path, tree in source.snapshots.items():
        if not source.validate(path):
            return None
        parents = source.parents[path]
        for ref in ast.walk(tree):
            candidate = (
                ref.id if isinstance(ref, ast.Name) else getattr(ref, "attr", "")
            )
            if (name is not None and candidate != name) or not isinstance(
                getattr(ref, "ctx", None), ast.Load
            ):
                continue
            if (
                _app_source_symbol(
                    symbols, path, ref, _enclosing_function(ref, parents)
                )
                == selected
            ):
                reads.add(ref if name is not None else (ref, path))
    return reads


def _captured_builtin_copy_kind(scope, path, callee):
    if not isinstance(callee, ast.Name):
        return None
    name, audit = scope.canonical(path, callee), scope.audit
    kinds = {
        "builtins.list": "list",
        "builtins.tuple": "tuple",
        "builtins.dict": "dict",
    }
    if (
        name is None
        and (builtin := "builtins." + callee.id) in kinds
        and audit._app_builtin_annotation_inert(scope.index, path, callee)
    ):
        name = builtin
    return (
        kinds[name]
        if name in kinds and audit._app_signing_terminal_stable(scope.index, name)
        else None
    )


def captured_builtin_copy(scope, flow, path, call, arguments, keywords):
    """Transfer an exact builtin container without invoking arbitrary iteration."""
    from dataclasses import replace
    from .credential_role_identity_effects import _validated_exact_scalar

    if (
        keywords
        or len(arguments) > 1
        or not (kind := _captured_builtin_copy_kind(scope, path, call.func))
    ):
        return None
    (original,) = arguments or (None,)
    allowed = {"dict": {"dict"}}.get(kind, {"list", "tuple"})
    if original is not None and (
        not _validated_exact_scalar(original, as_truth=True)
        or original.inert_kind not in allowed
    ):
        return None
    scope.witness(path, call, "modeled_test_scope_container_copy")
    if original is None:
        return flow.allocate_container(path, call, kind, ())
    if (kind, original.inert_kind) == ("tuple", "tuple"):
        return original
    result = flow.allocate_container(path, call, kind, original.items)
    return replace(result, roots=original.roots, trace=original.trace)


def _fixed_digest_request_base(value):
    from urllib.parse import urlsplit

    if type(value) is not str:
        return False
    try:
        bits = urlsplit(value)
        return (
            bits.scheme == "https"
            and bool(bits.hostname)
            and bits.path.endswith("/")
            and bits.username is None
            and bits.password is None
            and not bits.query
            and not bits.fragment
        )
    except ValueError:
        return False


def captured_unread_settings_field(node, target):
    """Reject a literal credential classification only for a closed settings field."""
    if not isinstance(node, ast.AnnAssign) or not isinstance(target, ast.Name):
        return False
    owner = getattr(node, "_security_parent", None)
    if not isinstance(owner, ast.ClassDef) or len(owner.bases) != 1:
        return False
    value = getattr(node.value, "value", None)
    if type(value) is not str:
        return False
    from .semantic_credential_sensor import _security_helper_source_context

    if _captured_text_may_be_secret(value):
        return False
    module, index, path = _security_helper_source_context(node, None)
    if path is None or not index.validate(path) or owner not in module.body:
        return False
    return _launch_unread_field(index, path, module, owner, target.id)


def _launch_unread_field(index, path, module, owner, name):
    from .credential_role_identity_effects import source_symbol_index
    from .mock_fixture_provenance import _app_expression_name

    config = _launch_text_sources(module)
    if not config:
        return False
    symbols = source_symbol_index(index)
    if (
        symbols is None
        or _app_expression_name(symbols, path, owner.bases[0])
        != "pydantic_settings.BaseSettings"
    ):
        return False
    roots = _launch_import_roots(index, config, path)
    if len(roots) != 1 or not path.is_relative_to(scope := next(iter(roots))):
        return False
    fields = _launch_settings_fields(symbols, path, owner)
    if fields is None or name not in fields:
        return False
    carrier = _launch_settings_carrier(symbols, path, module, owner)
    return carrier is not None and _settings_read_set(
        index, symbols, path, scope, module, carrier, owner, fields, name
    )


_SETTINGS_CONFIG_KEYS = {"env_file", "env_file_encoding", "case_sensitive", "extra"}
_SETTINGS_OPAQUE_MODULES = {"importlib", "runpy", "__main__"}


def _launch_settings_fields(symbols, path, owner):
    """Allow plain data fields; dynamic class features have no negative authority."""
    if owner.decorator_list or owner.keywords:
        return None
    fields = {}
    configurations = []
    for statement in owner.body:
        match statement:
            case ast.Expr(value=ast.Constant(value=str())):
                continue
            case ast.AnnAssign(
                target=ast.Name(id=name), annotation=annotation, value=value
            ):
                if not _plain_settings_field(
                    symbols, path, fields, name, annotation, value
                ):
                    return None
                fields[name] = annotation
            case ast.Assign(
                targets=[ast.Name(id="model_config")], value=ast.Call() as call
            ):
                configurations.append(_launch_safe_settings_config(symbols, path, call))
            case ast.ClassDef(name="Config") as config:
                configurations.append(_legacy_literal_settings_config(config))
            case _:
                return None
    return fields if len(configurations) <= 1 and all(configurations) else None


def _plain_settings_field(symbols, path, fields, name, annotation, value):
    if name in fields or name.startswith("_") or value is None:
        return False
    if not all(
        _settings_annotation_node(symbols, path, item) for item in ast.walk(annotation)
    ):
        return False
    if isinstance(value, ast.Call):
        value = _literal_settings_default(symbols, path, value)
        if value is None:
            return False
    try:
        ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return False
    return True


def _literal_settings_default(symbols, path, call):
    from .mock_fixture_provenance import _app_expression_name

    match call:
        case ast.Call(
            func=provider,
            args=[],
            keywords=[
                ast.keyword(arg="default_factory", value=ast.Lambda() as factory)
            ],
        ) if _app_expression_name(symbols, path, provider) == "pydantic.Field":
            if not any(ast.iter_child_nodes(factory.args)) and not any(
                isinstance(node, (ast.Call, ast.Name))
                for node in ast.walk(factory.body)
            ):
                return factory.body
    return None


def _settings_annotation_node(symbols, path, item):
    from .credential_role_constructor_provider import binding_occurrences
    from .mock_fixture_provenance import _app_expression_name

    if isinstance(item, ast.Name):
        if item.id in {"str", "int", "float", "bool", "list", "dict", "tuple", "set"}:
            return not binding_occurrences(symbols["modules"][path].body, item.id)
        return _app_expression_name(symbols, path, item) in {
            "typing.Optional",
            "typing.List",
            "typing.Dict",
            "typing.Tuple",
            "typing.Set",
            "typing.Union",
        }
    return isinstance(item, (ast.Load, ast.Subscript, ast.Tuple)) or (
        isinstance(item, ast.Constant) and item.value is None
    )


def _launch_safe_settings_config(symbols, path, call):
    from .mock_fixture_provenance import _app_expression_name

    return (
        not call.args
        and len(call.keywords) == len({key.arg for key in call.keywords})
        and _app_expression_name(symbols, path, call.func)
        == "pydantic_settings.SettingsConfigDict"
        and all(
            key.arg in _SETTINGS_CONFIG_KEYS and isinstance(key.value, ast.Constant)
            for key in call.keywords
        )
    )


def _legacy_literal_settings_config(config):
    if config.bases or config.keywords or config.decorator_list:
        return False
    keys = set()
    for statement in config.body:
        match statement:
            case ast.Expr(value=ast.Constant(value=str())):
                continue
            case ast.Assign(
                targets=[ast.Name(id=name)], value=ast.Constant(value=value)
            ) if name in _SETTINGS_CONFIG_KEYS and name not in keys:
                if name == "case_sensitive" and type(value) is not bool:
                    return False
                if name != "case_sensitive" and type(value) not in {str, type(None)}:
                    return False
                keys.add(name)
            case _:
                return False
    return True


def _launch_settings_carrier(symbols, path, tree, owner):
    from .credential_role_constructor_provider import binding_occurrences
    from .mock_fixture_provenance import _app_expression_name

    wrappers = []
    allowed = set()
    for statement in tree.body:
        match statement:
            case ast.FunctionDef(
                args=args,
                body=[
                    ast.Return(
                        value=ast.Call(func=ast.Name() as ctor, args=[], keywords=[])
                    )
                ],
            ) if ctor.id == owner.name and not any(ast.iter_child_nodes(args)):
                decorators = [
                    _app_expression_name(symbols, path, item)
                    for item in statement.decorator_list
                ]
                if decorators not in ([], ["functools.lru_cache"]):
                    return None
                wrappers.append((statement.name, statement))
                if (
                    isinstance(statement.returns, ast.Name)
                    and statement.returns.id == owner.name
                ):
                    allowed.add(statement.returns)
                allowed.add(ctor)
            case ast.Assign(
                targets=[ast.Name() as binding],
                value=ast.Call(func=ast.Name() as ctor, args=[], keywords=[]),
            ) if ctor.id == owner.name and binding.lineno > owner.end_lineno:
                wrappers.append((binding.id, binding))
                allowed.add(ctor)
    if len(wrappers) != 1 or binding_occurrences(tree.body, owner.name) != [owner]:
        return None
    return wrappers[0] if set(_settings_names(tree, owner.name)) == allowed else None


def _settings_names(tree, name):
    return (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == name
    )


def _settings_read_set(
    index, symbols, path, root, owner_tree, carrier, owner, fields, name
):
    from .credential_role_constructor_provider import binding_occurrences
    from .runtime_audit_integrity import _conditional_module_name

    carrier_name, definition = carrier
    if binding_occurrences(owner_tree.body, carrier_name) != [definition]:
        return False
    canonical = {
        name
        for base in (root, index.root)
        for name in (
            ".".join(path.relative_to(base).with_suffix("").parts),
            _conditional_module_name(path.relative_to(base).as_posix()),
        )
        if name
    }
    singleton = definition if isinstance(definition, ast.Name) else None
    if singleton is not None:
        fields = {
            key: annotation
            for key, annotation in fields.items()
            if isinstance(annotation, ast.Name)
            and annotation.id in {"str", "int", "float", "bool"}
        }
    read, reexports = set(), {}
    for file, tree in index.snapshots.items():
        if (
            not index.validate(file)
            or (
                aliases := _settings_consumer_aliases(
                    symbols, file, tree, canonical, carrier_name, owner
                )
            )
            is None
        ):
            return False
        if file == path:
            aliases.add(carrier_name)
        elif aliases:
            reexports[file] = aliases
        if not _settings_file_reads(
            index, file, tree, aliases, fields, name, read, singleton
        ):
            return False
    if not read or not _settings_qualified_aliases_closed(
        index, symbols, root, reexports
    ):
        return False
    return _settings_source_providers_stable(index)


def _settings_source_providers_stable(index):
    """Reject writes to provider namespaces, including lazy exports and base classes."""
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )

    providers = ("pydantic_settings", "pydantic", "pydantic_core")
    if any(
        provider in path.parts or path.name == provider + ".py"
        for path in index.snapshots
        for provider in providers
    ):
        return False
    return not _captured_terminal_provider_mutation(
        index,
        audit,
        providers[0],
        additional_bindings=tuple(
            (name, None) for name in (*providers[1:], "functools.lru_cache")
        ),
    )


def _settings_qualified_aliases_closed(index, symbols, root, reexports):
    """Check the second namespace edge before declaring a first-edge read closed."""
    from .mock_fixture_provenance import _django_import_rows, _django_package
    from .runtime_audit_integrity import _conditional_module_name

    modules = {
        _conditional_module_name(name): reexports[path]
        for name, path in symbols["module_paths"].items()
        if path in reexports
    }
    modules.update(
        {
            _conditional_module_name(path.relative_to(root).as_posix()): names
            for path, names in reexports.items()
            if path.is_relative_to(root)
        }
    )
    if not modules:
        return True
    for path, tree in index.snapshots.items():
        package = _django_package(symbols, path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for _, selected in _django_import_rows(node, package) or ():
                module, _, member = selected.rpartition(".")
                if selected in modules or member in modules.get(module, ()):
                    return False
    return True


def _settings_consumer_aliases(symbols, path, tree, modules, carrier_name, owner):
    from .credential_role_constructor_provider import binding_occurrences
    from .mock_fixture_provenance import _django_import_rows, _django_package

    package = _django_package(symbols, path)
    aliases = set()
    for statement in ast.walk(tree):
        if not isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        rows = _django_import_rows(statement, package)
        if rows is None:
            return None
        for local, canonical in rows:
            if any(
                value == canonical or value.startswith(canonical + ".")
                for value in modules
            ):
                return None
            module, _, member = canonical.rpartition(".")
            if module not in modules:
                continue
            if member == owner.name or (
                member == carrier_name
                and (
                    statement not in tree.body
                    or binding_occurrences(tree.body, local) != [statement]
                )
            ):
                return None
            if member == carrier_name:
                aliases.add(local)
    return aliases


_SETTINGS_OPAQUE_NAMES = {
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "eval",
    "exec",
    "__import__",
    "import_module",
    "run_module",
    "run_path",
    "modules",
    "__dict__",
    "__globals__",
    "__code__",
    "__builtins__",
    "__getattribute__",
}


def _settings_file_reads(index, path, tree, aliases, fields, field, reads, singleton):
    from . import review_audits as audit
    from .credential_role_constructor_provider import _presentation_provider_shadow

    nodes = tuple(ast.walk(tree))
    if any(_settings_opaque_access(n) for n in nodes):
        return False
    for node in nodes:
        if isinstance(node, ast.Attribute) and node.attr.casefold() == field.casefold():
            return False
        if (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and aliases.intersection(node.names)
            or singleton is not None
            and isinstance(node, ast.Name)
            and node.id in aliases
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node is not singleton
        ):
            return False
    parents = index.parents[path]
    for alias in aliases:
        for ref in _settings_names(tree, alias):
            if singleton is not None and _presentation_provider_shadow(
                ref, alias, index, path, audit
            ):
                return False
            values = _settings_allocation_uses(ref, tree, parents, singleton)
            if not values or not all(
                _settings_member_read(n, fields, parents, reads) for n in values
            ):
                return False
    return True


def _settings_opaque_access(node):
    if isinstance(node, ast.Name):
        # A bare local name does not address the module registry.
        return node.id != "modules" and node.id in _SETTINGS_OPAQUE_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in _SETTINGS_OPAQUE_NAMES
    if isinstance(node, ast.ImportFrom):
        return node.module in _SETTINGS_OPAQUE_MODULES or any(
            alias.name == "*"
            or alias.name in _SETTINGS_OPAQUE_NAMES
            or node.module == "sys"
            and alias.name in {"path", "meta_path", "path_hooks"}
            for alias in node.names
        )
    if isinstance(node, ast.Import):
        return any(
            alias.name.partition(".")[0] in _SETTINGS_OPAQUE_MODULES
            for alias in node.names
        )
    return (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "__getattr__"
    )


def _settings_allocation_uses(reference, tree, parents, singleton):
    from .credential_role_constructor_provider import (
        _scope_scope_bindings,
        binding_occurrences,
    )

    if singleton is not None:
        return (reference,)
    call = parents.get(id(reference))
    if not (
        isinstance(call, ast.Call)
        and call.func is reference
        and not call.args
        and not call.keywords
    ):
        return ()
    parent = parents.get(id(call))
    if not isinstance(parent, ast.Assign):
        return (call,)
    match parent.targets:
        case [ast.Name(id=name) as target]:
            pass
        case _:
            return ()
    scope = _scope_scope_bindings(parent, parents, tree)
    if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        return ()
    if binding_occurrences(scope.body, name) != [target]:
        return ()
    reads = tuple(_settings_names(scope, name))
    if parent in scope.body:
        return reads
    return _settings_guarded_alias_reads(scope, parent, parents, reads, name)


def _settings_guarded_alias_reads(scope, allocation, parents, reads, name):
    from .credential_role_constructor_provider import (
        _scope_scope_bindings,
        binding_occurrences,
    )
    from .intent_quality import _canary_main_guard_test

    guard = parents.get(id(allocation))
    if not (
        isinstance(scope, ast.Module)
        and isinstance(guard, ast.If)
        and guard in scope.body
        and not guard.orelse
        and allocation in guard.body
        and _canary_main_guard_test(guard.test)
        and not binding_occurrences(scope.body, "__name__")
    ):
        return ()
    guarded_nodes = set(ast.walk(guard))
    local_reads = []
    for ref in reads:
        lexical_scope = _scope_scope_bindings(ref, parents, scope)
        if lexical_scope is scope:
            if ref not in guarded_nodes or ref.lineno <= allocation.end_lineno:
                return ()
            local_reads.append(ref)
        elif not _settings_separate_local_read(lexical_scope, ref, name, parents):
            return ()
    return tuple(local_reads)


def _settings_separate_local_read(scope, ref, name, parents):
    from .credential_role_constructor_provider import (
        binding_dominates,
        binding_occurrences,
    )

    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) or any(
        isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
        for node in ast.walk(scope)
    ):
        return False
    match binding_occurrences(scope.body, name):
        case [ast.Name(ctx=ast.Store()) as binding]:
            assignment = parents.get(id(binding))
            return assignment in scope.body and binding_dominates(
                assignment, ref, parents, scope
            )
    return False


def _settings_member_read(node, fields, parents, reads):
    parent = parents.get(id(node))
    if not (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and isinstance(parent.ctx, ast.Load)
        and parent.attr in fields
    ):
        return False
    reads.add(parent.attr)
    return True


def captured_sql_statement_text_closed(call, query, driver):
    """Keep bound data separate from source-closed statement text."""
    if driver not in {"sqlite3", "mysql.connector"}:
        return False
    match call:
        case ast.Call(
            func=ast.Attribute(attr="execute"),
            args=[ast.Name(), ast.Name() as values],
            keywords=[],
        ) if query is call.args[0] and query.id != values.id:
            return (
                driver == "sqlite3"
                and _captured_sql_batch_from_loop(call, query.id, values.id)
            ) or _captured_statement_text_closed(call, query, driver)
    return False


def _captured_statement_text_closed(call, query, driver):
    """Prove captured statement text from closed scalar inputs and field reads."""
    from .semantic_credential_sensor import _security_helper_source_context
    from .credential_role_constructor_provider import (
        binding_occurrences,
        _scope_scope_bindings,
    )
    from .credential_role_identity_effects import _Value, resolve_source_identity_call
    from .credential_role_method_use_getter_audit import CapturedOriginProjection
    from .mock_fixture_provenance import _app_source_symbol, _django_name
    from .type_intent_provider_provenance import _module_has_dynamic_capability_access

    if not (
        isinstance(query, ast.Name)
        and len(call.args) == 2
        and call.args[0] is query
        and not call.keywords
        and isinstance(call.args[1], ast.Name)
    ):
        return False
    tree, index, path = _security_helper_source_context(call, None)
    if path is None or not index.validate(path):
        return False
    parents = index.parents[path]
    owner = _sql_batch_function(call, tree, parents)
    if (
        owner is None
        or owner.decorator_list
        or binding_occurrences(tree.body, owner.name) != [owner]
    ):
        return False
    nodes = tuple(ast.walk(owner))
    if not (
        any(
            arg.arg == query.id
            for arg in (
                *owner.args.posonlyargs,
                *owner.args.args,
                *owner.args.kwonlyargs,
            )
        )
        or any(
            isinstance(n, ast.AugAssign)
            and isinstance(n.target, ast.Name)
            and n.target.id == query.id
            for n in nodes
        )
    ):
        return False
    if any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in nodes):
        return False
    projection = CapturedOriginProjection(index, lambda *_args: (False, None))
    callers = _captured_closed_text_callers(
        index,
        projection,
        path,
        owner,
        _app_source_symbol,
        _scope_scope_bindings,
        resolve_source_identity_call,
        _module_has_dynamic_capability_access,
    )
    if not callers:
        return False
    name = _django_name(projection.symbols, path)
    if not projection._symbol_closed(
        [(name + "." + owner.name, path, owner.name)],
        _Value(),
        readonly_call=lambda expr: id(expr) in callers,
    ):
        return False
    if not _captured_sql_receiver_allocation(
        call, owner, index, path, binding_occurrences, driver
    ):
        return False
    return _CapturedTextDefinitions(
        nodes, parents, tuple(callers.values()), owner, binding_occurrences
    ).prove(query)


def _captured_sql_binding(expr, use, lexical, parents, bind_names):
    """Return a unique assignment that dominates the observed receiver use."""
    from .credential_role_constructor_provider import binding_dominates

    if not isinstance(expr, ast.Name):
        return expr
    found = bind_names(lexical.body, expr.id)
    if len(found) != 1:
        return None
    binding = parents.get(id(found[0]))
    targets = getattr(binding, "targets", None) or [getattr(binding, "target", None)]
    if (
        isinstance(binding, (ast.Assign, ast.AnnAssign))
        and targets == found
        and binding_dominates(binding, use, parents, lexical)
    ):
        return binding.value
    return None


def _captured_sql_receiver_allocation(call, owner, index, path, bind_names, driver):
    """Bind the actual cursor and native allocation before applying statement proof."""
    from .credential_role_identity_effects import resolve_source_identity_call
    from . import review_audits as audit, review_integrity as flow
    from .credential_role_method_use_getter_audit import CapturedOriginProjection

    cursor = _captured_sql_binding(
        call.func.value, call, owner, index.parents[path], bind_names
    )
    match cursor:
        case ast.Call(
            func=ast.Attribute(value=db, attr="cursor"), args=[], keywords=options
        ) if _sql_cursor_options_closed(options, driver):
            connection = _captured_sql_binding(
                db, cursor, owner, index.parents[path], bind_names
            )
        case _:
            return False
    projection = CapturedOriginProjection(index, lambda *_args: (False, None))
    for _ in range(8):
        if not isinstance(connection, ast.Call):
            return False
        aliases = audit._module_security_aliases(index.snapshots[path])
        canonical = flow.security_call_name(connection, aliases)
        if canonical == driver + ".connect":
            return _closed_sql_connector(
                connection, driver, projection.symbols, aliases
            )
        bound = resolve_source_identity_call(connection, path, index)
        if (
            bound is None
            or not bound.negative_binding_closed
            or not isinstance(bound.function, ast.FunctionDef)
            or bound.function.decorator_list
        ):
            return False
        helper, path = bound.function, bound.path
        returns = [n for n in flow._lexical_nodes(helper) if isinstance(n, ast.Return)]
        if (
            len(returns) != 1
            or helper.body[-1] is not returns[0]
            or any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in ast.walk(helper))
        ):
            return False
        connection = _captured_sql_binding(
            returns[0].value, returns[0], helper, index.parents[path], bind_names
        )
    return False


def _sql_cursor_options_closed(options, driver):
    return not options or (
        driver == "mysql.connector"
        and len(options) == 1
        and options[0].arg == "dictionary"
        and isinstance(options[0].value, ast.Constant)
        and type(options[0].value.value) is bool
    )


def _closed_sql_connector(connection, driver, symbols, aliases):
    from . import review_audits as audit, review_integrity as flow
    from .credential_identity_audit import _app_signing_terminal_stable

    root = driver.partition(".")[0]
    if any(
        {root, root + ".py"}.intersection(path.casefold().split("/"))
        for path in symbols["module_paths"]
    ):
        return False
    if driver == "sqlite3":
        return (
            len(connection.args) == 1
            and not isinstance(connection.args[0], ast.Starred)
            and not connection.keywords
            and all(
                _app_signing_terminal_stable(symbols, provider)
                for provider in (
                    "sqlite3.connect",
                    "sqlite3.Connection.cursor",
                    "sqlite3.Cursor.execute",
                )
            )
        )
    head = audit._call_name(connection).partition(".")[0]
    visible, _constants = flow._security_flow_bindings(connection, aliases)
    return (
        head in visible
        and not connection.args
        and all(
            kw.arg in {"host", "port", "user", "password", "database", "unix_socket"}
            for kw in connection.keywords
        )
        and _app_signing_terminal_stable(symbols, root)
    )


def _captured_sql_batch_from_loop(call, statement_name, values_name):
    from .credential_role_constructor_provider import binding_occurrences
    from .semantic_credential_sensor import _security_helper_source_context

    tree, index, path = _security_helper_source_context(call, None)
    if path is None or not index.validate(path):
        return False
    parents = index.parents[path]
    expression = parents.get(id(call))
    loop = parents.get(id(expression))
    match loop:
        case ast.For(
            target=ast.Tuple(elts=[ast.Name(id=left), ast.Name(id=right)]),
            iter=ast.Name(id=formal),
            body=[ast.Expr() as body],
            orelse=[],
        ) if (left, right, body.value) == (statement_name, values_name, call):
            sink = _sql_batch_function(loop, tree, parents)
        case _:
            return False
    if sink is None or binding_occurrences(sink.body, formal):
        return False
    if _sql_batch_name_refs(sink, formal) != [loop.iter]:
        return False
    callers = _sql_batch_callers(index, path, tree, sink)
    default_nodes = (*sink.args.defaults, *sink.args.kw_defaults)
    return bool(callers) and all(
        proof.arguments.get(formal) not in default_nodes
        and _sql_bound_rows(proof.arguments.get(formal), site, tree, index, path)
        for site, proof in callers
    )


def _sql_batch_function(node, tree, parents):
    from .credential_role_constructor_provider import _scope_scope_bindings

    function = _scope_scope_bindings(node, parents, tree)
    return (
        function
        if function in tree.body and isinstance(function, ast.FunctionDef)
        else None
    )


def _sql_batch_callers(index, path, tree, function):
    from . import review_audits as audit
    from .credential_role_constructor_provider import binding_occurrences
    from .credential_role_identity_effects import resolve_source_identity_call
    from .type_intent_provider_provenance import _module_has_dynamic_capability_access

    if binding_occurrences(tree.body, function.name) != [function]:
        return []
    nodes = tuple(ast.walk(tree))
    if _module_has_dynamic_capability_access(nodes):
        return []
    if not _sql_batch_imports_closed(index, path, audit):
        return []
    parents, callers = index.parents[path], []
    for ref in nodes:
        if not isinstance(ref, ast.Name) or ref.id != function.name:
            continue
        site = parents.get(id(ref))
        if not isinstance(site, ast.Call) or site.func is not ref:
            return []
        proof = resolve_source_identity_call(site, path, index)
        if (
            proof is None
            or proof.function is not function
            or not proof.negative_binding_closed
        ):
            return []
        callers.append((site, proof))
    return callers


def _sql_batch_imports_closed(index, path, audit):
    from .import_context import _shell_import_aliases
    from .runtime_audit_integrity import _conditional_module_name

    module = _conditional_module_name(index.relative(path))
    for other, snapshot in index.snapshots.items():
        if other == path:
            continue
        package = _conditional_module_name(index.relative(other))
        if other.name != "__init__.py":
            package = package.rpartition(".")[0]
        aliases = _shell_import_aliases(
            tuple(ast.walk(snapshot)), audit, module, package=package
        )
        if aliases is None or any(
            part in {module, path.stem}
            or module.startswith(part + ".")
            or part.startswith(module + ".")
            for part in aliases.values()
        ):
            return False
    return True


def _sql_bound_rows(value, site, tree, index, path):
    from .credential_role_constructor_provider import (
        binding_dominates,
        binding_occurrences,
    )
    from .credential_role_identity_effects import resolve_source_identity_call

    if isinstance(value, (ast.List, ast.Tuple)):
        return all(_sql_bound_row(row) for row in value.elts)
    if not isinstance(value, ast.Name):
        return False
    parents = index.parents[path]
    scope = _sql_batch_function(site, tree, parents)
    if scope is None:
        return False
    match _sql_batch_assignment(binding_occurrences(scope.body, value.id), parents):
        case (
            ast.Assign(
                targets=[ast.Tuple(elts=targets)], value=ast.Call() as build
            ) as assignment
        ):
            if not binding_dominates(assignment, site, parents, scope):
                return False
        case _:
            return False
    names = [target.id for target in targets if isinstance(target, ast.Name)]
    if len(set(names)) != len(targets):
        return False
    slot = names.index(value.id)
    if set(_sql_batch_name_refs(scope, value.id)) != {value, targets[slot]}:
        return False
    provider = resolve_source_identity_call(build, path, index)
    if (
        provider is None
        or provider.path != path
        or not provider.negative_binding_closed
    ):
        return False
    return _sql_batch_return_slot(provider.function, slot, len(names), parents)


def _sql_batch_return_slot(producer, slot, arity, parents):
    from .credential_role_constructor_provider import binding_occurrences
    from .review_integrity import _implementation_scope_nodes

    returns = [
        node
        for node in _implementation_scope_nodes(producer)
        if isinstance(node, ast.Return)
    ]
    if len(returns) != 1 or returns[0] is not producer.body[-1]:
        return False
    result = returns[0].value
    if not isinstance(result, ast.Tuple) or len(result.elts) != arity:
        return False
    carrier = result.elts[slot]
    if isinstance(carrier, (ast.List, ast.Tuple)):
        return all(_sql_bound_row(row) for row in carrier.elts)
    if not isinstance(carrier, ast.Name):
        return False
    match _sql_batch_assignment(
        binding_occurrences(producer.body, carrier.id), parents
    ):
        case (
            ast.Assign(
                targets=[ast.Name() as target], value=ast.List(elts=rows)
            ) as init
        ):
            if init not in producer.body or not all(
                _sql_bound_row(row) for row in rows
            ):
                return False
        case _:
            return False
    return all(
        ref in (target, carrier) or _sql_batch_append(ref, parents, init, producer)
        for ref in ast.walk(producer)
        if isinstance(ref, ast.Name) and ref.id == carrier.id
    )


def _sql_batch_assignment(bindings, parents):
    match bindings:
        case [ast.Name(ctx=ast.Store()) as name]:
            parent = parents.get(id(name))
            return parents.get(id(parent)) if isinstance(parent, ast.Tuple) else parent
    return None


def _sql_batch_name_refs(scope, name):
    return [
        ref for ref in ast.walk(scope) if isinstance(ref, ast.Name) and ref.id == name
    ]


def _sql_batch_append(ref, parents, init, producer):
    from .credential_role_constructor_provider import binding_dominates

    attribute = parents.get(id(ref))
    invocation = parents.get(id(attribute))
    return (
        isinstance(attribute, ast.Attribute)
        and attribute.attr == "append"
        and isinstance(invocation, ast.Call)
        and invocation.func is attribute
        and not invocation.keywords
        and len(invocation.args) == 1
        and _sql_bound_row(invocation.args[0])
        and binding_dominates(init, invocation, parents, producer)
    )


def _sql_bound_row(row):
    return (
        isinstance(row, (ast.Tuple, ast.List))
        and len(row.elts) == 2
        and isinstance(row.elts[0], ast.Constant)
        and type(row.elts[0].value) is str
        and isinstance(row.elts[1], (ast.Tuple, ast.List))
    )


def _captured_credential_handler_authority(context, finding, handler, declaration):
    from .credential_endpoint_admission import _OperativeCredentialOrigin
    from .review_audits import _resolved_ast_name

    framework = handler["application"]["framework"]
    if framework == "fastapi":
        return _OperativeCredentialOrigin(
            context, finding, handler, declaration
        ).handler_authority()
    function, path = handler["function"], handler["path"]
    if framework != "flask" or not any(
        isinstance(node, ast.Call)
        and _resolved_ast_name(node.func, context["aliases"][path])
        == "hmac.compare_digest"
        for node in ast.walk(function)
    ):
        return None
    origin = _OperativeCredentialOrigin(context, finding, handler, declaration)
    return _CapturedHTTPSignatureFlow(origin).authority()


class _CapturedHTTPSignatureFlow:
    """Join a typed signature calculation to an HTTP rejection boundary."""

    def __init__(self, origin):
        self.origin = origin
        handler = origin.handler
        self.path, self.function = handler["path"], handler["function"]
        self.providers, self.transfers, self.readonly = set(), [], set()
        self.request_reads = set()

    def canonical(self, node):
        """Resolve a captured expression against the handler provider bindings."""
        return self.origin.canonical(self.path, node, self.function)

    def expression(self, node, values):
        """Project supported expressions into signature-flow kinds and header origins."""
        match node:
            case ast.Name(id=name) if name in values:
                return values[name]
            case ast.Attribute() if self.canonical(node) == "flask.request.data":
                self.request_reads.add(node)
                return "payload", frozenset()
            case ast.Name() | ast.Attribute() if self.key_origin(node):
                return "key_text", frozenset()
            case ast.Constant(value=bytes()):
                return "bytes", frozenset()
            case ast.Subscript(value=receiver, slice=ast.Constant(value=str() as name)):
                if self.canonical(receiver) == "flask.request.headers":
                    self.request_reads.add(node)
                    return "header", frozenset({name.casefold()})
            case ast.BinOp(left=left, op=ast.Add(), right=right):
                operands = [self.expression(item, values) for item in (left, right)]
                kinds = {kind for kind, _ in operands}
                if kinds <= {"bytes", "payload"}:
                    return (
                        "payload" if "payload" in kinds else "bytes",
                        frozenset().union(*(headers for _, headers in operands)),
                    )
            case ast.Call():
                return self.call(node, values)
        return "", frozenset()

    def key_origin(self, node):
        """Require a source-bound key reference without competing assignments."""
        from .credential_role_constructor_provider import binding_occurrences

        origin = self.origin
        if origin.literal_reference(self.path, node, self.function, origin.projection):
            return True
        name = origin.finding["facts"]["name"]
        tree = origin.index.snapshots[self.path]
        return (
            self.path == origin.path
            and isinstance(node, ast.Name)
            and node.id == name
            and origin.declaration in tree.body
            and origin.declaration.lineno < self.function.lineno
            and len(bindings := binding_occurrences(tree.body, name)) == 1
            and origin.index.parents[self.path].get(id(bindings[0]))
            is origin.declaration
            and not binding_occurrences(self.function.body, name)
        )

    def call(self, node, values):
        """Track supported HMAC construction, comparison and value conversions."""
        canonical = self.canonical(node.func)
        if canonical == "hmac.new":
            return self.constructor(node, values)
        if (
            canonical == "hmac.compare_digest"
            and len(node.args) == 2
            and not node.keywords
        ):
            operands = dict(self.expression(arg, values) for arg in node.args)
            if (
                operands.keys() == {"digest", "header"}
                and not operands["digest"] & operands["header"]
            ):
                self.providers.add(canonical)
                self.transfers.append(node)
                return "verified", frozenset()
        if (encoded := self.encoded_header(node, values)) is not None:
            return encoded
        return self.member_call(node, values)

    def constructor(self, node, values):
        """Bind the published key and request payload to SHA-256 HMAC."""
        operands = _captured_hmac_operands(node)
        if operands is None:
            return "", frozenset()
        key, message, digest = operands
        payload_kind, headers = self.expression(message, values)
        if (
            self.expression(key, values)[0] != "key_bytes"
            or payload_kind != "payload"
            or self.canonical(digest) != "hashlib.sha256"
        ):
            return "", frozenset()
        self.providers.update({"hmac.new", "hmac.HMAC", "hashlib.sha256"})
        self.readonly.add(id(digest))
        self.transfers.extend((key, message, digest, node))
        return "hmac", headers

    def encoded_header(self, node, values):
        """Recognize UTF-8 header encoding only when bytes is unshadowed."""
        from .credential_role_constructor_provider import binding_occurrences

        match node:
            case ast.Call(
                func=ast.Name(id="bytes"),
                args=[value, ast.Constant(value="utf8" | "utf-8")],
                keywords=[],
            ):
                source = self.origin.index.snapshots[self.path]
                if not any(
                    binding_occurrences(scope.body, "bytes")
                    for scope in (source, self.function)
                ):
                    kind, headers = self.expression(value, values)
                    if kind == "header":
                        self.providers.add("builtins.bytes")
                        return "bytes", headers
        return None

    def member_call(self, node, values):
        """Project supported header reads, splits, encodings and digest extraction."""
        if node.keywords:
            return "", frozenset()
        match node.func, node.args:
            case ast.Attribute(value=receiver, attr="get"), [
                ast.Constant(value=str() as name),
                ast.Constant(value=str()),
            ]:
                if self.canonical(receiver) == "flask.request.headers":
                    self.request_reads.add(node)
                    return "header", frozenset({name.casefold()})
            case ast.Attribute(value=receiver, attr="split"), [
                ast.Constant(value=str() as sep)
            ] if sep:
                kind, headers = self.expression(receiver, values)
                if kind == "header":
                    return "headers", headers
            case ast.Attribute(value=receiver, attr=method), []:
                kind, headers = self.expression(receiver, values)
                projected = {
                    ("key_text", "encode"): "key_bytes",
                    ("header", "encode"): "bytes",
                    ("hmac", "hexdigest"): "digest",
                }.get((kind, method), "")
                return projected, headers
        return "", frozenset()

    def response(self, statement, success):
        """Recognize a typed Flask response in the required HTTP status class."""
        match statement:
            case ast.Return(
                value=ast.Call(
                    func=func,
                    args=[ast.Constant(value=str())],
                    keywords=[
                        ast.keyword(
                            arg="status", value=ast.Constant(value=int() as status)
                        )
                    ],
                )
            ):
                if self.canonical(func) == "flask.Response" and status // 100 == (
                    2 if success else 4
                ):
                    self.providers.add("flask.Response")
                    return True
        return False

    def logging(self, statement):
        """Allow bounded handler logging while recording provider dependencies."""
        receiver = self.origin.handler["application"]["name"]
        match statement:
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Attribute(value=ast.Name(id=owner), attr="logger"),
                        attr="warning" | "info",
                    ),
                    args=[value],
                    keywords=[],
                )
            ) if owner == receiver:
                if isinstance(value, ast.Constant):
                    self.providers.add("logging.Logger")
                    return True
                if self.canonical(value) == "flask.request.json":
                    self.request_reads.add(value)
                    self.providers.add("logging.Logger")
                    return True
        return False

    def rejects(self, statement, values):
        """Require a failed signature comparison to return an HTTP rejection."""
        match statement:
            case ast.If(
                test=ast.UnaryOp(op=ast.Not(), operand=condition),
                body=[*prefix, response],
                orelse=[],
            ):
                if (
                    self.expression(condition, values)[0] == "verified"
                    and all(self.logging(item) for item in prefix)
                    and self.response(response, False)
                ):
                    self.transfers.extend((statement, response))
                    return True
        return False

    def assignments(self, statements, values):
        """Propagate supported signature values through simple local assignments."""
        for statement in statements:
            match statement:
                case ast.Assign(targets=[ast.Name(id=name)], value=node):
                    kind = self.expression(node, values)
                    if not kind[0]:
                        return False
                    values[name] = kind
                case _:
                    return False
        return True

    def guarded(self, statements, values):
        """Prove direct or nonempty-loop signature rejection before success."""
        if not statements:
            return False
        *prefix, guard = statements
        if not self.assignments(prefix, values):
            return False
        match guard:
            case ast.For(
                target=ast.Name(id=name),
                iter=sequence,
                body=[*inner, rejection],
                orelse=[],
            ):
                # A fixed nonempty separator leaves at least one input-derived item.
                kind, headers = self.expression(sequence, values)
                if kind != "headers":
                    return False
                values[name] = "header", headers
                return self.assignments(inner, values) and self.rejects(
                    rejection, values
                )
        return self.rejects(guard, values)

    def authority(self):
        """Build source-bound authority after route, dataflow and provider checks."""
        from .semantic_credential_sensor import _flask_constructor_arguments

        handler, function = self.origin.handler, self.function
        tree = self.origin.index.snapshots[self.path]
        creation = handler["application"]["creation"]
        allocation = handler["application"]["statement"]
        if not (
            function in tree.body
            and allocation in tree.body
            and tree.body.index(allocation) < tree.body.index(function)
            and function.decorator_list == [handler["decorator"]]
            and handler["application"]["path"] == self.path
            and handler["receiver"] is handler["application"]
            and len(creation.args) + len(creation.keywords) == 1
            and _flask_constructor_arguments(creation)
            and self.route_path(handler["decorator"])
            and not any(
                getattr(function.args, field) for field in function.args._fields
            )
            and len(function.body) >= 2
        ):
            return None
        *prefix, accepted = function.body
        while prefix and self.logging(prefix[-1]):
            prefix.pop()
        if not self.response(accepted, True) or not self.guarded(prefix, {}):
            return None
        if not self.providers_closed(tree):
            return None
        self.origin.consumer = ("hmac", "verified_http_signature_rejection")
        from .semantic_credential_sensor import _signing_source_span

        self.origin.consumer_transfers = [
            _signing_source_span(self.origin.index, self.path, node)
            for node in sorted(
                {*self.transfers, *self.request_reads},
                key=lambda item: (
                    item.lineno,
                    item.col_offset,
                    item.end_lineno,
                    item.end_col_offset,
                ),
            )
        ]
        return self.origin.witness(accepted, self.origin.key)

    @staticmethod
    def route_path(decorator):
        """Require a literal route; validate explicit methods when supplied."""
        match decorator:
            case ast.Call(
                func=ast.Attribute(attr=method),
                args=[ast.Constant(value=str() as path)],
                keywords=keywords,
            ) if path.startswith("/") and "<" not in path:
                if not keywords:
                    return True
                match keywords:
                    case [
                        ast.keyword(
                            arg="methods",
                            value=ast.List(elts=methods) | ast.Tuple(elts=methods),
                        )
                    ] if method == "route":
                        return bool(methods) and all(
                            isinstance(item, ast.Constant)
                            and item.value
                            in (
                                "GET",
                                "POST",
                                "PUT",
                                "PATCH",
                                "DELETE",
                                "OPTIONS",
                                "HEAD",
                            )
                            for item in methods
                        )
        return False

    def providers_closed(self, tree):
        """Reject mutated or reflective providers across captured source modules."""
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )
        from .credential_identity_audit import _app_digest_algorithm_argument
        from .runtime_audit_integrity import _conditional_module_name
        from .semantic_credential_sensor import _signing_framework_external
        from .type_intent_provider_provenance import (
            _module_has_dynamic_capability_access,
        )

        origin, handler = self.origin, self.origin.handler
        index, app = origin.index, handler["application"]["name"]
        allowed_calls = {
            handler["decorator"].func,
            *(
                node.func
                for node in ast.walk(self.function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "logger"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == app
            ),
        }
        parents = index.parents[self.path]
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Name)
                or node.id != app
                or not isinstance(node.ctx, ast.Load)
            ):
                continue
            owner = parents.get(id(node))
            if (
                owner not in allowed_calls
                and parents.get(id(owner)) not in allowed_calls
            ):
                return False
        providers = sorted(
            self.providers
            | {
                "flask.Flask",
                "flask.request",
                "flask.Request",
                "flask.wrappers.Request",
                "flask.wrappers.Response",
                "werkzeug.wrappers.Request",
                "werkzeug.wrappers.Response",
            }
        )
        if not all(
            _signing_framework_external(
                origin.context, name.split(".")[0], origin.execution_root
            )
            for name in providers
        ):
            return False
        for path, snapshot in index.snapshots.items():
            nodes = tuple(ast.walk(snapshot))
            direct_calls = {node.func for node in nodes if isinstance(node, ast.Call)}
            if _module_has_dynamic_capability_access(
                tuple(
                    node
                    for node in nodes
                    if path == self.path or node not in direct_calls
                )
            ):
                return False
            if not all(
                origin.provider_reflection_closed(
                    nodes, origin.context["aliases"][path], root
                )
                for root in {name.split(".")[0] for name in providers}
            ):
                return False
        module = _conditional_module_name(index.relative(self.path))
        bindings = [(name, None) for name in providers]
        bindings.extend(
            (qualified + "." + name, (self.path, name))
            for qualified in sorted({module, self.path.stem})
            for name in (app, self.function.name, origin.finding["facts"]["name"])
        )
        return not _captured_terminal_provider_mutation(
            index,
            audit,
            providers[0],
            additional_bindings=tuple(bindings[1:]),
            readonly_nodes=self.request_reads
            | {
                node
                for node in ast.walk(self.function)
                if isinstance(node, ast.Assign) and node.value in self.request_reads
            },
            readonly_argument=lambda node, aliases, parents: id(node) in self.readonly
            or _app_digest_algorithm_argument(node, aliases, parents),
        )


def _native_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _captured_sink_failure(schema, code, reason, base=None):
    return {
        **(base or {"schema": schema, "status": "INCOMPLETE"}),
        "code": code,
        "truncation": [reason],
    }


def _captured_sink_source(
    path_arg, expected, index, raw, tree, max_sources, max_states, max_output, schema
):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_INVALID", "invalid_limit"
            )
        }
    limits = tuple(
        min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000))
    )
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "invalid_source_path"
            )
        }
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_hash_mismatch"
            )
        }
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_encoding_invalid"
            )
        }
    base = {
        "schema": schema,
        "status": "INCOMPLETE",
        "source": {"path": path[:1024], "sha256": digest, "bytes": len(raw)},
        "source_count": 1,
    }
    return {
        "tree": tree,
        "parents": parents,
        "text": text,
        "base": base,
        "digest": digest,
        "limits": limits,
        "indexed": indexed,
        "tree_supplied": tree_supplied,
    }


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_not_indexed"
            )
        }
    if (
        sum(len(value) for value in inventory.values() if isinstance(value, bytes))
        > 32_000_000
    ):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes"
            )
        }
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_bytes_changed"
            )
        }
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable"
            )
        }
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_snapshot_invalid"
            )
        }
    return {
        "raw": captured,
        "tree": index.snapshots[path_arg],
        "parents": index.parents[path_arg],
    }


def _captured_sink_raw_tree(path, raw, tree, schema):
    try:
        parsed = ast.parse(raw, filename=path)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(
            tree, include_attributes=True
        ):
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_SOURCE_STALE", "ast_source_mismatch"
                )
            }
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_parse_failed"
            )
        }
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _native_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base
            )
        }
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base
            )
        }
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base
                )
            }
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if (
            isinstance(item, ast.Call)
            and _native_span(item) == span
            and ast.dump(item, include_attributes=True)
            == ast.dump(node, include_attributes=True)
        ):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base
            )
        }
    if len(matches) == 1:
        return {
            "node": matches[0],
            "parents": parents,
            "source_ast_nodes_examined": count,
        }
    return {
        "error": _captured_sink_failure(
            schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base
        )
    }


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _native_span(item)
    return (
        {"status": status, "source": {"path": path, "sha256": digest, "span": span}}
        if span is not None
        else {"status": "UNKNOWN", "reason": "span_unavailable"}
    )


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = (
        {"status": "UNKNOWN", "reason": "no_enclosing_callable"},
        None,
        None,
    )
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if (
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement in scope.body
        ):
            body = scope.body
            row = {
                "status": "OBSERVED",
                "name": scope.name,
                "kind": type(scope).__name__,
                **fact(scope),
            }
        else:
            row = {
                "status": "UNKNOWN",
                "reason": "sink_outside_callable_body",
                **fact(scope),
            }
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {
                "error": _captured_sink_failure(
                    base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
                )
            }
        if item is not scope and isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {
        "scope": scope,
        "body": body,
        "statement": statement,
        "nodes": nodes,
        "row": row,
    }


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append(
            {
                "position": index,
                "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    for keyword in node.keywords:
        value = keyword.value
        arguments.append(
            {
                "keyword": keyword.arg,
                "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                "expression": excerpt(value),
                "span": _native_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    callees = [
        item
        for item in ast.walk(node.func)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    ]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [
        item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    if len(nodes) + len(modules) > budget:
        return {
            "error": _captured_sink_failure(
                base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
            )
        }
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [
        row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))
    ]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (
                alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name
            )
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = (
                not wildcard
                and binding_occurrences(container, name) == [item]
                and name not in params
            )
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append(
                {
                    "name": name,
                    "module": (
                        item.module if isinstance(item, ast.ImportFrom) else alias.name
                    ),
                    "kind": type(item).__name__,
                    "status": status,
                    "reason": None if stable else "binding_replaced_or_ambiguous",
                    "span": _native_span(item),
                    **fact(item, status),
                }
            )
    return {
        "rows": rows,
        "module_imports": modules,
        "states_used": sum(len(item.names) for item in modules),
        "binding_occurrences": binding_occurrences,
    }


def _captured_sink_values(
    node, names, scope, body, statement, nodes, parents, tree, fact, excerpt
):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [
            {
                "name": name,
                "status": "UNKNOWN",
                "reason": "no_supported_callable_scope",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": [],
            }
            for name in sorted(names)
        ]
    params = _captured_sink_parameter_names(scope)
    reflective = _captured_sink_reflective_barrier(node, scope, nodes, parents)
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(
            name,
            scope,
            body,
            statement,
            parents,
            tree,
            params,
            fact,
            excerpt,
            binding_occurrences,
        )
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(
                row.id
                for row in ast.walk(assignment.value)
                if isinstance(row, ast.Name)
                and isinstance(row.ctx, ast.Load)
                and row.id not in visited
                and row.id not in pending
            )
        if reflective:
            value.update(
                status="UNKNOWN",
                reason="reflective_binding_possible",
                origin="UNRESOLVED",
            )
            value["replacements"].append(
                {"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")}
            )
        result.append(value)
    return result


def _captured_sink_reflective_barrier(node, scope, nodes, parents):
    """Return whether a reflective call can precede or feed this selected sink."""
    reflective_names = {
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
    }
    selected_span = _native_span(node)
    selected_start = tuple(selected_span[:2]) if selected_span else None
    selected_subtree = {id(item) for item in ast.walk(node)}
    for item in nodes:
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Name)
            or item.func.id not in reflective_names
            or item is node
        ):
            continue
        if id(item) in selected_subtree:
            return True
        if _captured_sink_enclosing_callable(item, parents) is not scope:
            continue
        span = _native_span(item)
        if selected_start is None or span is None:
            return True
        if tuple(span[:2]) <= selected_start:
            return True
    return False


def _captured_sink_value(
    name,
    scope,
    body,
    statement,
    parents,
    tree,
    params,
    fact,
    excerpt,
    binding_occurrences,
):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = (
            parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        )
        if statement_node is None:
            statement_node = binding
        rows.append(
            {
                "kind": type(binding).__name__,
                "binding_span": _native_span(binding),
                "expression": excerpt(statement_node),
                **fact(statement_node, "UNKNOWN"),
            }
        )
    assignment = None
    if (
        len(bindings) == 1
        and isinstance(bindings[0], ast.Name)
        and isinstance(bindings[0].ctx, ast.Store)
    ):
        candidate = parents.get(id(bindings[0]))
        targets = (
            candidate.targets
            if isinstance(candidate, ast.Assign)
            else [candidate.target]
            if isinstance(candidate, ast.AnnAssign)
            else []
        )
        if (
            candidate in body
            and body.index(candidate) < body.index(statement)
            and getattr(candidate, "value", None) is not None
            and len(targets) == 1
            and targets[0] is bindings[0]
        ):
            assignment = candidate
    if assignment is not None:
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "LOCAL_DEFINITION",
            "definitions": [
                {
                    "expression": excerpt(assignment.value),
                    "span": _native_span(assignment),
                    **fact(assignment),
                }
            ],
            "replacements": [],
        }
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        )
    elif not bindings and name in params:
        args = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            *([scope.args.vararg] if scope.args.vararg else []),
            *([scope.args.kwarg] if scope.args.kwarg else []),
        )
        arg = next(row for row in args if row.arg == name)
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "CALLABLE_PARAMETER",
            "definitions": [
                {"kind": "PARAMETER", "span": _native_span(arg), **fact(arg)}
            ],
            "replacements": [],
        }
    elif not bindings and any(
        row in tree.body for row in binding_occurrences(tree.body, name)
    ):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(
            module_bindings[0], (ast.Import, ast.ImportFrom)
        ):
            value = {
                "name": name,
                "status": "INFERRED",
                "reason": None,
                "origin": "LEXICAL_IMPORT",
                "definitions": [
                    {
                        "kind": type(module_bindings[0]).__name__,
                        "span": _native_span(module_bindings[0]),
                        **fact(module_bindings[0]),
                    }
                ],
                "replacements": [],
            }
        else:
            value = {
                "name": name,
                "status": "UNKNOWN",
                "reason": "module_binding_ambiguous",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": rows,
            }
    else:
        value = {
            "name": name,
            "status": "UNKNOWN",
            "reason": (
                "binding_replaced_or_not_straight_line"
                if bindings
                else "no_source_definition_or_parameter"
            ),
            "origin": "UNRESOLVED",
            "definitions": [],
            "replacements": rows,
        }
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        getattr(ast, "TryStar", ast.Try),
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
    )
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append(
                {
                    "kind": type(current).__name__,
                    "expression": excerpt(test) if test is not None else "",
                    "semantics": "UNKNOWN",
                    "span": _native_span(current),
                    **fact(current),
                }
            )
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in module_imports
    ):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(
        body, name
    ) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if (
            len(bindings) == 1
            and bindings[0] in tree.body
            and isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        ):
            row = {
                "status": "INFERRED",
                "reason": None,
                "name": name,
                "declaration": fact(bindings[0]),
            }
    return row


def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _security_request_binary_decode_kind(
    value, requests, aliases, scope, statement, *, audit
):
    """Carry request text through an exact, source-stable base64-to-bytes transform."""
    if not isinstance(value, ast.Call) or len(value.args) != 1 or value.keywords:
        return None
    if any((isinstance(argument, ast.Starred) for argument in value.args)):
        return None
    if audit.security_call_name(value, aliases) not in {
        "base64.b64decode",
        "base64.urlsafe_b64decode",
    }:
        return None
    from .semantic_credential_sensor import (
        _provider_identity_uncertain,
        request_payload_value_kind,
    )

    module = audit._security_module_scope(scope)
    if module is None or _provider_identity_uncertain(
        module, aliases, roots=(audit.security_call_name(value, aliases),)
    ):
        return None
    source = value.args[0]
    if request_payload_value_kind(
        source,
        requests,
        aliases,
        audit._security_scope_request_aliases,
        scope,
        statement,
    ) == "text" and audit._security_expr_tainted(source, requests, set(), aliases):
        return "bytes"
    return None


def _security_bind_local_native_input_precondition(
    call, canonical, primitive, scope, requests, aliases, *, audit
):
    """Bind one sink against its own provider identities when unrelated module code is ambiguous."""
    from .semantic_credential_sensor import (
        _native_input_request_is_supported,
        security_precondition_call_shape,
        security_precondition_path_possible,
        supported_security_precondition,
    )
    from .finite_capture import security_input_value_flow

    eligible = {
        "SECURITY_DYNAMIC_EXECUTION",
        "SECURITY_OS_COMMAND",
        "SECURITY_SHELL_COMMAND",
        "SECURITY_UNSAFE_DESERIALIZATION",
        "SECURITY_UNSAFE_YAML",
    }
    if primitive.get("code") not in eligible or not call.args:
        return
    module = audit._security_module_scope(scope)
    if module is None or not (
        security_precondition_call_shape(call, canonical)
        or audit._security_shell_call_shape_for_flow(call, canonical)
    ):
        return
    if not security_precondition_path_possible(call):
        return
    supported = getattr(requests, "supported_view", lambda: requests)()
    if supported is None or not _native_input_request_is_supported(
        call, canonical, supported, aliases, scope, audit
    ):
        return
    if audit._security_local_request_provider_identity_uncertain(module, aliases):
        return
    provider_roots = (
        ("subprocess",)
        if canonical.startswith("subprocess.")
        else ("os.system",)
        if canonical == "os.system"
        else ("_pickle",)
        if canonical.startswith("_pickle.")
        else ("pickle",)
        if canonical.startswith("pickle.")
        else ("dill",)
        if canonical.startswith("dill.")
        else ("yaml",)
        if canonical.startswith("yaml.")
        else ("builtins",)
    )
    if audit._security_local_provider_identity_uncertain(
        module, aliases, provider_roots, audit=audit
    ):
        return
    premise = supported_security_precondition(call, "untrusted_request", canonical)
    if trace := security_input_value_flow(call.args[0], supported, aliases):
        premise["input_value_flow"] = trace
    call._security_supported_precondition = premise


def _security_local_request_provider_identity_uncertain(module, aliases):
    """Keep request-provider mutations in every captured module as source blockers."""
    from .review_audits import _security_aliases
    from .semantic_credential_sensor import (
        _native_input_inventory_epoch,
        _native_input_provider_inventory,
        _provider_identity_uncertain,
    )

    selected_providers = (
        "flask.request",
        *(
            path
            for path in aliases.values()
            if path.split(".")[0] in {"flask", "django"}
        ),
    )
    source_model = getattr(module, "_security_source_model", None)
    trees = (
        tuple(source_model.snapshots.values())
        if source_model is not None
        else (module,)
    )
    for tree in trees:
        nodes = list(ast.walk(tree))
        source_aliases = aliases if tree is module else _security_aliases(nodes)
        inventory = _native_input_provider_inventory(tree, source_aliases, nodes)
        parents = {
            id(child): parent
            for parent in nodes
            for child in ast.iter_child_nodes(parent)
        }
        if _provider_identity_uncertain(
            tree,
            source_aliases,
            roots=selected_providers,
            selected_paths=True,
            nodes=inventory,
            parents=parents,
            inventory_projector=_native_input_provider_inventory,
            inventory_dependencies=_native_input_inventory_epoch(),
        ):
            return True
    return False


def _security_shell_call_shape_for_flow(call, canonical):
    """Allow inert process options around an explicitly enabled shell sink."""
    if (
        canonical
        not in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
        or len(call.args) != 1
        or isinstance(call.args[0], ast.Starred)
    ):
        return False
    keywords = {item.arg: item.value for item in call.keywords}
    if (
        None in keywords
        or len(keywords) != len(call.keywords)
        or "shell" not in keywords
        or (not isinstance(keywords["shell"], ast.Constant))
        or (keywords["shell"].value is not True)
    ):
        return False
    inert_options = {
        "shell",
        "stdin",
        "stdout",
        "stderr",
        "timeout",
        "check",
        "cwd",
        "env",
        "text",
        "encoding",
        "errors",
        "universal_newlines",
        "bufsize",
        "close_fds",
        "start_new_session",
        "creationflags",
    }
    return set(keywords).issubset(inert_options)


def _security_local_provider_identity_uncertain(module, aliases, roots, *, audit):
    """Ignore only read-only subprocess stream constants in otherwise exact provider checks."""
    from types import SimpleNamespace
    from .finite_capture import finite_provider_mutation_index
    from .review_audits import _resolved_ast_name

    nodes = list(ast.walk(module))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    mutations = finite_provider_mutation_index(
        nodes, aliases, SimpleNamespace(_resolved_ast_name=_resolved_ast_name), parents
    )
    if "subprocess" in roots:
        inert = set()
        for node in nodes:
            if not (
                isinstance(node, ast.Attribute)
                and node.attr in {"STDOUT", "PIPE", "DEVNULL"}
                and isinstance(node.ctx, ast.Load)
                and (audit._resolve(node, aliases) == f"subprocess.{node.attr}")
            ):
                continue
            keyword = parents.get(id(node))
            call = (
                parents.get(id(keyword)) if isinstance(keyword, ast.keyword) else None
            )
            if (
                isinstance(keyword, ast.keyword)
                and keyword.value is node
                and (keyword.arg in {"stdin", "stdout", "stderr"})
                and isinstance(call, ast.Call)
                and audit.security_call_name(call, aliases).startswith("subprocess.")
            ):
                inert.add((f"subprocess.{node.attr}", "*"))
        mutations = [item for item in mutations if item not in inert]
    return any(
        (
            path == root or path.startswith(root + ".")
            for path, _attribute in mutations
            for root in roots
        )
    )


_NATIVE_INPUT_EPOCH_BINDINGS = tuple(
    (module, names.split())
    for module, names in {
        "factoryline.semantic_credential_sensor": """
        _signing_provider_clear _signing_provider_reads _signing_bound_providers_clear
        _security_builtin_identity_closed _provider_identity_uncertain _provider_path_conflicts
        _native_input_provider_inventory http_request_payload
        _http_request_subscript_payload _http_request_call_payload
        _http_request_attribute_payload _flask_request_body_kind
        _credential_get_source_key _http_request_mapping
        _request_mapping_value_unchanged _request_mapping_aliases
        _request_mapping_mutation _django_http_body_payload
        _native_request_data_member _new_security_request_alias_memo
        _security_scope_request_aliases _security_scope_request_aliases_uncached
        _security_request_alias_module_bindings
        _security_store_request_alias_bindings
        supported_security_precondition tls_finding log_security_precondition
        bind_request_sink_precondition _security_request_sink_slot
        security_precondition_providers_stable _native_input_precondition_eligible
        """,
        "factoryline.captured_security_audit": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain _native_input_inventory_epoch
        """,
        "factoryline.import_context": """
        finite_key_reflection_reads _finite_loop_reflection_reads _finite_dictionary_key_domain _finite_dictionary_key_use_closed _finite_key_reflection_call _finite_table_peers_closed import_resolution_helpers close_selected_import_sources eager_import_closure _eager_import_model_roots _eager_import_edges _eager_import_target
        """,
        "factoryline.credential_endpoint_admission": """
        _django_setting_import_closure _django_setting_import_aliases _django_setting_import_sites _django_setting_import_operand _django_import_namespace_unknown _django_importer_external
        """,
        "factoryline.credential_role_constructor_provider": """
        binding_occurrences _binds
        """,
        "factoryline.credential_role_identity_effects": """
        source_symbol_index
        """,
        "factoryline.mock_fixture_provenance": """
        _django_import_rows _django_name _django_assignment
        """,
        "factoryline.review_integrity": """
        _security_request_binary_decode_kind _security_bind_local_native_input_precondition _security_local_request_provider_identity_uncertain _security_shell_call_shape_for_flow _security_local_provider_identity_uncertain
        bind_security_call_scopes _bind_security_scope_node _bind_security_function
        _bind_security_class _function_annotations _security_scope_local_names
        _security_scope_nonlocal_names _security_scope_declared_names
        _security_module_scope _security_apply_import_bindings
        security_precondition_providers_confirmed _security_source_sink_findings_bound
        _security_scope_request_aliases
        _security_unsafe_flask_file_save _security_upload_path_expression
        tls_verification_disabled
        """,
        "factoryline.audit_log_flow": """
        audit_log_source_findings
        """,
        "factoryline.finite_capture": """
        finite_provider_mutation_index _provider_mutation_for_node
        _provider_mutation_facts _record_provider_paths _record_provider_capture
        _provider_alias_bindings _provider_paths _provider_call_argument
        _reflective_provider_write _foreign_provider_inputs
        _foreign_provider_source_mutations _project_provider_inventory
        """,
        "factoryline.credential_role_paths": """
        matches_regenerated_security_precondition valid_security_precondition
        security_effect_fact_matches logging_consumer_configuration
        logging_security_effect_witness logging_security_precondition source_span
        upload_path_expression bind_request_sink_precondition tls_security_finding
        upload_name_origin upload_join_effect upload_concat_effect source_domain_guarded
        _literal_domain _domain_choices _domain_corridor _upload_domain
        _logging_plain_source logging_domain_guarded module_binding
        _upload_control_path _upload_definition_reaches _upload_receiver_names
        _upload_prior_field_write _upload_filename_mutated
        bind_upload_sink_precondition
        regenerate_security_source_model
        _logging_configuration _logging_direct_configuration
        _logging_declared_configuration _logging_active_settings
        _logging_node_possible _logging_reference _logging_dict_fields
        _logging_literal _logging_assignment _logging_receiver
        _logging_receiver_name _logging_receiver_assignments _logging_call_level
        _logging_logger_route _logging_logger_entry _logging_root_route
        _logging_plain_handler_routes _logging_plain_handler_route
        _logging_plain_formatter _logging_route_facts _logging_config_sections
        _logging_mutation_present _logging_local_mutation_present
        _logging_filter_provider_uncertain
        logging_input_value_trace logging_merge_log_flow
        """,
        "factoryline.review_audits": """
        _name _resolved_ast_name _security_aliases _bound_names _binding_name
        _iter_ast_nodes
        """,
        "factoryline.intent_quality": """
        _security_scope_request_aliases
        """,
        "factoryline": """
        _source_binding_helpers _bind_source_call _source_call_signature
        """,
    }.items()
)


def _native_input_inventory_epoch(_cache_owner):
    from importlib import import_module
    from . import review_audits, intent_quality, semantic_credential_sensor
    from . import credential_role_paths
    from . import audit_log_flow

    functions = [
        getattr(import_module(module), name)
        for module, names in import_module(
            _cache_owner.__module__
        )._NATIVE_INPUT_EPOCH_BINDINGS
        for name in names
    ]
    helpers = import_module("factoryline.import_context").import_resolution_helpers()
    functions.extend(helpers if isinstance(helpers, tuple) else ())
    identity = (
        tuple(
            (
                (
                    fn,
                    getattr(fn, "__code__", None),
                    id(getattr(fn, "__defaults__", None)),
                )
                for fn in functions
            )
        ),
        semantic_credential_sensor.SECURITY_EFFECT_WITNESS_SCHEMA,
        import_module("factoryline.import_context")._eager_import_model_roots(),
        semantic_credential_sensor.SECURITY_EFFECT_CONTRACTS,
        semantic_credential_sensor._SECURITY_EFFECT_WITNESS_SCHEMA_BASELINE,
        semantic_credential_sensor._SECURITY_EFFECT_CONTRACTS_BASELINE,
        tuple(sorted(credential_role_paths._LOG_LEVEL_VALUES.items())),
        tuple(sorted(credential_role_paths._LOG_STANDARD_HANDLERS)),
        tuple(
            (
                (name, fn, getattr(fn, "__code__", None))
                for name, fn in vars(audit_log_flow._LogReader).items()
                if callable(fn)
            )
        ),
        audit_log_flow._LOGGING_LEVELS,
        audit_log_flow.log_evidence,
        ast.dump(semantic_credential_sensor._FLASK_BODY_SIGNATURE),
        review_audits._FUNCTION_NODES,
        intent_quality._SECURITY_REQUEST_ALIAS_MEMO,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_ENTRIES,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_PAIRS,
        intent_quality._SECURITY_REQUEST_ALIAS_MAX_BYTES,
    )
    cached = getattr(_cache_owner, "_cached_epoch", None)
    if cached is None or cached[0] != identity:
        cached = (identity, object())
        _cache_owner._cached_epoch = cached
    return cached[1]


_SOURCE_ROLE_COMPONENTS = frozenset(
    {
        "test",
        "tests",
        "example",
        "examples",
        "example_projects",
        "demo",
        "demo_project",
        "demos",
        "archive",
    }
)


def _source_role_path(relative):
    if not isinstance(relative, str):
        return None
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None
    path = PurePosixPath(normalized)
    parts = path.parts
    if path.is_absolute() or ".." in parts or path.suffix.lower() != ".py":
        return None
    role = next(
        (
            part.lower()
            for part in parts[:-1]
            if part.lower() in _SOURCE_ROLE_COMPONENTS
        ),
        None,
    )
    return (path, role) if role is not None else None


def source_role_distribution_domain(
    captured, relative, *, line=None, credential_name=None
):
    """Resolve source-role authority from bound package or archive evidence."""
    resolved = _source_role_path(relative)
    if not isinstance(captured, dict) or resolved is None:
        return None
    path, role = resolved
    if role == "archive":
        redaction = _archive_redaction_domain(
            captured, path, line=line, credential_name=credential_name
        )
        if redaction is not None:
            return redaction
    from .pytest_collection_audit import _distribution_selection_excludes_source

    proof = _distribution_selection_excludes_source(captured, path)
    if proof is None:
        return None
    return _distribution_domain(path, role, proof)


def _distribution_domain(path, role, proof):
    return {
        "schema": "factory.security.source-role-package-scope.v1",
        "role": role,
        "application_authority": "UNKNOWN",
        "proof_scope": "source_bound_distribution_package_selection",
        "package_scope": "EXCLUDED_FROM_CAPTURED_STATIC_PACKAGE_SELECTION",
        "selection_basis": proof["basis"],
        "claim_boundary": "Package selection only; repository source may still be runnable.",
        "candidate_path": path.as_posix(),
        "manifest_path": proof["path"],
        "manifest_sha256": proof["sha256"],
        "supporting_sources": {proof["path"]: proof["sha256"]},
    }


def selected_django_credential_domain(
    context, path, observation, selected, finding, index
):
    """Prefer captured Django test evidence before checking distribution scope."""
    from .credential_identity_audit import django_test_domain_evidence

    domain = django_test_domain_evidence(context, path, observation, selected)
    if domain is not None:
        return domain
    relative = index.relative(path)
    distribution = _hatch_consumer_domain(
        context, relative
    ) or source_role_distribution_domain(
        context.get("captured", {}),
        relative,
        line=finding.get("line"),
        credential_name=(finding.get("facts") or {}).get("name"),
    )
    if _mapped_distribution_scope(distribution) and not _mapped_scope_contains_loaders(
        context, path, index, distribution
    ):
        return None
    return distribution


def _mapped_distribution_scope(domain):
    return isinstance(domain, dict) and domain.get("selection_basis") in {
        "setuptools_mapped_source_root",
        "hatch_explicit_consumer_root",
    }


def _hatch_consumer_path(relative, roots):
    if not isinstance(relative, str) or re.search(r"[:\\]", relative):
        return None
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        return None
    component = path.parts[0]
    if any(root.parts[0].casefold() == component.casefold() for root in roots):
        return None
    return path


def _hatch_consumer_domain(context, relative):
    from .pytest_collection_audit import (
        captured_hatch_wheel_roots,
        captured_unpacked_consumer,
    )

    if context.get("hatch_alternate_absent") is not True:
        return None
    captured = context["captured"]
    raw = captured.get("pyproject.toml")
    roots = captured_hatch_wheel_roots(raw)
    path = _hatch_consumer_path(relative, roots)
    if not roots or path is None or "hatch.toml" in captured:
        return None
    if not all(
        isinstance(captured.get((root / "__init__.py").as_posix()), bytes)
        for root in roots
    ):
        return None
    child = f"{path.parts[0]}/pyproject.toml"
    nested = captured.get(child)
    if not captured_unpacked_consumer(raw, nested):
        return None
    domain = _distribution_domain(
        path,
        "unpacked_distribution_consumer",
        {
            "path": "pyproject.toml",
            "sha256": sha256(raw).hexdigest(),
            "basis": "hatch_explicit_consumer_root",
        },
    )
    domain["supporting_sources"][child] = sha256(nested).hexdigest()
    domain["scope_root"] = path.parts[0]
    return domain


def _mapped_scope_contains_loaders(context, path, index, domain):
    from .semantic_credential_sensor import _django_signing_consumer

    parts = PurePosixPath(index.relative(path)).parts
    depth = (
        1
        if "scope_root" in domain
        else next(
            i + 1 for i, part in enumerate(parts) if part.lower() == domain["role"]
        )
    )
    scope = tuple(part.casefold() for part in parts[:depth])
    contained = False
    prefix = ".".join(scope)
    for other, tree in index.snapshots.items():
        relative = PurePosixPath(index.relative(other))
        inside = tuple(part.casefold() for part in relative.parts[:depth]) == scope
        loader = _django_signing_consumer(path, other, tree, context) is not None
        if not inside and (loader or _mapped_scope_referenced(tree, relative, prefix)):
            return False
        contained |= inside and loader
    return contained


def _mapped_scope_referenced(tree, relative, prefix):
    from importlib.util import resolve_name

    package = ".".join(relative.parts[:-1])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                try:
                    module = resolve_name("." * node.level + module, package)
                except ImportError:
                    continue
            names = [module, *(f"{module}.{a.name}" for a in node.names)]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Includes literal module arguments and module:object entrypoints.
            names = [node.value.partition(":")[0]]
        else:
            continue
        if any(
            name.casefold().startswith(prefix + ".") or name.casefold() == prefix
            for name in names
        ):
            return True
    return False


def _source_role_candidate(finding, bound, credential_evidence, generated):
    unresolved = (generated is None and credential_evidence is None) or (
        isinstance(generated, dict) and generated.get("authority_domain") is None
    )
    facts = finding.get("facts")
    return (
        unresolved
        and bound
        and finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(facts, dict)
        and isinstance(facts.get("name"), str)
    )


def source_role_context_fallback(
    finding, bound, credential_evidence, generated, context, source_bindings
):
    """Attach independently bound role evidence to an unresolved secret finding."""
    if not _source_role_candidate(finding, bound, credential_evidence, generated):
        return None
    if not isinstance(context, dict) or not isinstance(source_bindings, dict):
        return None
    index = context.get("index")
    path = Path(finding.get("path", ""))
    if index is None or not index.validate(path):
        return None
    domain = source_role_distribution_domain(
        context.get("captured", {}),
        index.relative(path),
        line=finding.get("line"),
        credential_name=finding["facts"]["name"],
    )
    if _mapped_distribution_scope(domain):
        # A package root is not an independent witness of runtime ownership.
        return None
    supporting = _bound_role_support(domain, source_bindings)
    if not supporting:
        return None
    observation = {
        "schema": "factory.security.source-role-context-observation.v1",
        "proof_scope": domain["proof_scope"],
        "credential_key": finding["facts"]["name"],
        "source_role": domain["role"],
        "authority_domain": domain,
        "supporting_sources": [
            {"path": source, "sha256": digest}
            for source, digest in sorted(supporting.items())
        ],
    }
    if generated is not None:
        observation["selected_framework_observation"] = generated
    return (
        "NEEDS_CONTEXT",
        domain["proof_scope"],
        {"credential_authority_observation": observation},
    )


def _bound_role_support(domain, bindings):
    supporting = domain.get("supporting_sources") if isinstance(domain, dict) else None
    if isinstance(supporting, dict) and all(
        bindings.get(source) == digest for source, digest in supporting.items()
    ):
        return supporting
    return None


def source_role_tier_override(
    finding, bound, credential_evidence, context, source_bindings
):
    """Resolve operative signing and role context from the same captured inputs."""
    from .credential_endpoint_admission import operative_signing_default_evidence

    generated = (
        operative_signing_default_evidence(finding, context)
        if bound and credential_evidence is None and context is not None
        else None
    )
    fallback = source_role_context_fallback(
        finding, bound, credential_evidence, generated, context, source_bindings
    )
    return generated, fallback


def _source_role_support_hashes(support, bindings):
    """Return hashes only when every auxiliary source is valid and bound."""
    if not (
        isinstance(support, dict)
        and all(
            isinstance(path, str) and isinstance(raw, bytes) and len(raw) <= 1_000_000
            for path, raw in support.items()
        )
    ):
        return {}
    hashes = {}
    for path, raw in support.items():
        digest = hashlib.sha256(raw).hexdigest()
        if path in bindings and digest != bindings[path]:
            return {}
        hashes[path] = digest
    return hashes


def source_role_capture_context(source_bytes, bindings, context):
    """Bind auxiliary role bytes without modifying the Python inventory."""
    support = getattr(source_bytes, "source_role_sources", {})
    support_hashes = _source_role_support_hashes(support, bindings)
    if not support_hashes:
        support = {}
    role_bindings = dict(bindings)
    role_bindings.update(support_hashes)
    role_context = context
    if (
        support
        and isinstance(context, dict)
        and isinstance(context.get("captured"), dict)
    ):
        capture = getattr(source_bytes, "source_role_capture", None)
        role_context = {
            **context,
            "captured": {**context["captured"], **support},
            "hatch_alternate_absent": isinstance(capture, dict)
            and capture.get("hatch_alternate_absent") is True,
        }
    return role_context, role_bindings


def _archive_redaction_domain(captured, path, *, line, credential_name):
    if (
        not isinstance(line, int)
        or not isinstance(credential_name, str)
        or not re.search(
            r"secret|password|token|credential|api[_-]?key|private[_-]?key",
            credential_name,
            re.IGNORECASE,
        )
    ):
        return None
    candidate_path = path.as_posix()
    source = captured.get(candidate_path)
    manifest = captured.get("archive/manifest.json")
    readme = captured.get("archive/README.md")
    if not all(isinstance(raw, bytes) for raw in (source, manifest, readme)):
        return None
    try:
        source_hash = hashlib.sha256(source).hexdigest()
        manifest_rows = json.loads(manifest)
        document = ast.parse(source.decode("utf-8"))
        readme_text = readme.decode("utf-8").lower()
    except (UnicodeDecodeError, SyntaxError, ValueError, TypeError):
        return None
    if not isinstance(manifest_rows, list) or not all(
        phrase in readme_text
        for phrase in ("historical source archive", "sanitized", "secret")
    ):
        return None
    manifest_row = next(
        (
            row
            for row in manifest_rows
            if isinstance(row, dict)
            and row.get("published") == candidate_path
            and row.get("published_sha256") == source_hash
            and isinstance(row.get("transformations"), list)
            and any(
                isinstance(item, str)
                and "secret" in item.lower()
                and re.search(r"(?:removed|redacted|sanitized)", item, re.I)
                for item in row["transformations"]
            )
        ),
        None,
    )
    if manifest_row is None:
        return None
    for node in ast.walk(document):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno != line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {
            target.id if isinstance(target, ast.Name) else target.attr
            for root in targets
            for target in ast.walk(root)
            if isinstance(target, ast.Name | ast.Attribute)
        }
        value = node.value
        if (
            credential_name in names
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and re.fullmatch(
                r"[\[({<]\s*(?:removed|redacted|sanitized)"
                r"(?:[-_\s]+[A-Za-z][A-Za-z0-9]{0,23}){1,4}\s*[\])}>]",
                value.value,
                re.I,
            )
        ):
            return {
                "schema": "factory.security.source-role-archive-redaction.v1",
                "role": "archive",
                "application_authority": "UNKNOWN",
                "proof_scope": "source_bound_archive_redaction_manifest",
                "redaction": "DECLARED_SECRET_REMOVAL",
                "candidate_path": candidate_path,
                "candidate_sha256": source_hash,
                "credential_name": credential_name,
                "assignment_line": line,
                "manifest_path": "archive/manifest.json",
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "documentation_path": "archive/README.md",
                "documentation_sha256": hashlib.sha256(readme).hexdigest(),
                "claim_boundary": (
                    "The captured archive manifest identifies this exact credential "
                    "assignment as sanitized; the raw finding remains and runtime "
                    "or deployment safety is unassessed."
                ),
                "supporting_sources": {
                    candidate_path: source_hash,
                    "archive/manifest.json": hashlib.sha256(manifest).hexdigest(),
                    "archive/README.md": hashlib.sha256(readme).hexdigest(),
                },
            }
    return None


def _application_configuration_hashes(class_profiles):
    """Select only bounded configuration digests from explicit class profiles."""
    from .import_context import application_configuration_names

    config_hashes = {}
    for evidence in class_profiles:
        configured = evidence.get("configuration_sha256", {})
        if not isinstance(configured, dict):
            continue
        for name, digest in configured.items():
            if (
                name in application_configuration_names((name,))
                and isinstance(digest, str)
                and len(digest) == 64
            ):
                config_hashes[name] = digest
    return config_hashes


def _captured_application_source_bytes(
    workspace, findings, bindings, source_bytes, *, capture_all_sources=False
):
    from .primitive_observation_binding import fixed_program_proof_dispositions

    program_proofs = fixed_program_proof_dispositions()
    # Byte binding is evidence substrate for every finding, never defect credit.
    paths = {finding.get("path") for finding in findings}
    for finding in findings:
        evidence = finding.get("facts", {}).get("fixture_evidence", {})
        closure = evidence.get("consumer_use_closure", {})
        if evidence.get("classification") == "APPLICATION_TEST_CREDENTIAL_ROLE":
            paths.update(
                row.get("path")
                for row in closure.get("operations", [])
                if isinstance(row, dict)
            )
    hashes = {row["path"]: row["sha256"] for row in bindings}
    whole_inventory = capture_all_sources or any(
        finding.get("facts", {}).get("disposition") in program_proofs
        or isinstance(finding.get("facts", {}).get("security_precondition"), dict)
        for finding in findings
    )
    paths.update(hashes if whole_inventory else ())
    needs_signing_sources = any(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("facts", {}).get("name") == "SECRET_KEY"
        for finding in findings
    )
    paths.update(name for name in hashes if needs_signing_sources)
    class_profiles = [
        finding.get("facts", {}).get("fixture_evidence", {})
        for finding in findings
        if finding.get("facts", {}).get("fixture_evidence", {}).get("classification")
        in {
            "APPLICATION_TEST_CREDENTIAL_ROLE",
            "PRESENTATION_METADATA_ROLE",
        }
    ]
    config_hashes = _application_configuration_hashes(class_profiles)
    if class_profiles:
        # These profiles independently recompute over the whole inventory.
        paths.update(name for name in hashes if name.endswith(".py"))
    paths.update(config_hashes)
    hashes.update(config_hashes)
    jwt_findings = [
        finding
        for finding in findings
        if finding.get("facts", {}).get("disposition")
        in {
            "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
            "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
            "PROVEN_CLOSED_LITERAL_PICKLE_BYTES",
            "ENDPOINT_DECLARATION_ROLE_PROVEN",
        }
    ]
    if jwt_findings:
        # Revalidation uses the complete current source inventory, including
        # imported initializers and shadows; selective capture would omit risks.
        paths.update(hashes)
    captured = {}
    for relative in paths:
        if (
            not isinstance(relative, str)
            or relative.startswith(("/", "\\"))
            or ":" in relative
            or ".." in relative.replace("\\", "/").split("/")
        ):
            continue
        data = source_bytes.get(workspace / relative)
        if relative in config_hashes and not isinstance(data, bytes):
            try:
                data = (workspace / relative).read_bytes()
            except OSError:
                continue
        if (
            isinstance(data, bytes)
            and len(data) <= 1_000_000
            and sha256(data).hexdigest() == hashes.get(relative)
        ):
            captured[relative] = data
    from .audit_action_refs import _CapturedSecuritySources

    sources, bindings = _capture_archive_support(workspace, findings, captured)
    hatch = _capture_hatch_consumer_support(workspace, findings, captured)
    sources.update(hatch)
    bindings = [
        *bindings,
        *(
            {"path": name, "sha256": sha256(raw).hexdigest(), "bytes": len(raw)}
            for name, raw in hatch.items()
        ),
    ]
    return _CapturedSecuritySources(
        captured,
        source_role_capture={
            "sources": sources,
            "bindings": bindings,
            "workspace": workspace if sources else None,
            "hatch_alternate_absent": bool(hatch),
        },
    )


def _hatch_alternate_absent(workspace):
    try:
        (workspace / "hatch.toml").lstat()
    except FileNotFoundError:
        return True
    except OSError:
        pass
    return False


def _read_role_manifest(workspace, name):
    from . import review_audits as audit

    try:
        raw = audit._security_source_bytes(workspace, name)
    except (OSError, audit.ReviewAuditError, audit.RuntimeAuditError):
        return None
    return raw if len(raw) <= 1_000_000 else None


def _capture_hatch_consumer_support(workspace, findings, captured):
    from .pytest_collection_audit import (
        captured_hatch_wheel_roots,
        captured_unpacked_consumer,
    )

    paths = {
        finding["path"]
        for finding in findings
        if finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and finding.get("facts", {}).get("name") == "SECRET_KEY"
        and finding.get("path") in captured
    }
    if not paths:
        return {}
    raw = _read_role_manifest(workspace, "pyproject.toml")
    roots = captured_hatch_wheel_roots(raw)
    if not roots or not _hatch_alternate_absent(workspace):
        return {}
    names = {
        f"{path.parts[0]}/pyproject.toml"
        for relative in paths
        if (path := _hatch_consumer_path(relative, roots)) is not None
    }
    nested = {
        name: local
        for name in sorted(names)[:16]
        if (local := _read_role_manifest(workspace, name)) is not None
        and captured_unpacked_consumer(raw, local)
    }
    return {"pyproject.toml": raw, **nested} if nested else {}


def _capture_archive_support(workspace, findings, captured):
    bindings = []
    role_sources = {}
    if any(
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and isinstance(finding.get("path"), str)
        and finding["path"].replace("\\", "/").startswith("archive/")
        and finding.get("path") in captured
        for finding in findings
    ):
        from . import review_audits as audit

        for relative in ("archive/README.md", "archive/manifest.json"):
            try:
                data = audit._security_source_bytes(workspace, relative)
            except (OSError, audit.ReviewAuditError):
                role_sources = {}
                break
            if len(data) > 1_000_000:
                role_sources = {}
                break
            role_sources[relative] = data
        if role_sources:
            bindings = [
                {
                    "path": relative,
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                }
                for relative, data in role_sources.items()
            ]
            try:
                audit._verify_security_bindings(workspace, bindings)
            except audit.ReviewAuditError:
                role_sources = {}
    return role_sources, bindings if role_sources else ()


def _tier_report_auxiliary_role_paths(tier_report):
    expected = {"archive/README.md", "archive/manifest.json"}
    paths = set()
    for row in (tier_report or {}).get("ledger", []):
        if not isinstance(row, dict):
            continue
        observation = row.get("credential_authority_observation")
        domain = (
            observation.get("authority_domain")
            if isinstance(observation, dict)
            else None
        )
        if (
            isinstance(domain, dict)
            and domain.get("selection_basis") == "hatch_explicit_consumer_root"
        ):
            paths.update(
                ("pyproject.toml", f"{domain.get('scope_root')}/pyproject.toml")
            )
        supporting = (
            observation.get("supporting_sources", [])
            if isinstance(observation, dict)
            else []
        )
        if any(
            isinstance(source, dict) and source.get("path") in expected
            for source in supporting
        ):
            paths.update(expected)
    return paths


def _auxiliary_role_support_current(audit, capture):
    support = capture.get("sources")
    bindings = capture.get("bindings")
    workspace = capture.get("workspace")
    if not (
        isinstance(support, dict)
        and isinstance(bindings, list)
        and len(bindings) == len(support)
        and isinstance(workspace, Path)
    ):
        return False
    by_path = {
        row["path"]: row
        for row in bindings
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    if set(by_path) != set(support) or not _archive_support_matches(support, by_path):
        return False
    if capture.get("hatch_alternate_absent") is True and not _hatch_alternate_absent(
        workspace
    ):
        return False
    try:
        audit._verify_security_bindings(workspace, bindings)
    except (OSError, audit.ReviewAuditError, audit.RuntimeAuditError):
        return False
    return True


def _archive_support_matches(support, bindings):
    return all(
        isinstance(raw, bytes)
        and len(raw) == bindings[path].get("bytes")
        and sha256(raw).hexdigest() == bindings[path].get("sha256")
        for path, raw in support.items()
    )


def source_role_verifier_sources(audit, verified, captured):
    """Keep the sidecar only after verifying it against the current workspace."""
    from .audit_action_refs import _CapturedSecuritySources

    capture = getattr(captured, "source_role_capture", None)
    if (
        isinstance(capture, dict)
        and capture.get("hatch_alternate_absent") is True
        and _auxiliary_role_support_current(audit, capture)
        and capture["sources"].get("pyproject.toml") == verified.get("pyproject.toml")
    ):
        return _CapturedSecuritySources(verified, source_role_capture=capture)
    return verified


def _revalidate_scan_role_support(audit, core, captured, primitive, native_rows):
    role_capture = getattr(captured, "source_role_capture", None)
    required = _tier_report_auxiliary_role_paths(core.get("finding_tier_report"))
    if (
        isinstance(role_capture, dict)
        and isinstance(role_capture.get("sources"), dict)
        and role_capture["sources"]
    ):
        invalidate_role_support = (
            not required.issubset(role_capture["sources"])
            or (
                "pyproject.toml" in required
                and role_capture.get("hatch_alternate_absent") is not True
            )
            or not _auxiliary_role_support_current(audit, role_capture)
        )
    else:
        invalidate_role_support = bool(required)
    if invalidate_role_support:
        if isinstance(role_capture, dict):
            role_capture.update(
                sources={}, bindings=[], workspace=None, hatch_alternate_absent=False
            )
        ledger = core.get("finding_tier_report", {}).get("ledger", [])
        raw_findings = [
            deepcopy(row["raw_finding"])
            for row in ledger
            if isinstance(row, dict) and isinstance(row.get("raw_finding"), dict)
        ]
        coverage_complete = core.get("audit_coverage", {}).get("complete") is True
        core["finding_tier_report"] = primitive.build_finding_tier_report(
            raw_findings,
            core.get("primitive_observations", []),
            core.get("sources", []),
            captured,
            coverage_state=coverage_complete,
            partition_state="VALIDATED" if coverage_complete else "INCOMPLETE",
            _verifier_native_rows=native_rows,
        )


def argument_role_proof_helpers():
    """Bind the exact argument and HTTP name proofs to scanner cache generations."""
    from . import (
        audit_action_refs,
        audit_log_flow,
        captured_operand_audit,
        review_audits,
        review_integrity,
    )
    from .fixture_scope_value_audit import (
        hash_fixture_proof_helpers,
        password_validation_proof_helpers,
    )
    from .intent_quality import bound_sink_argument
    from .pickle_model_audit import captured_local_serialization_proof
    from .provenance import (
        credential_role_witness,
        oauth_placeholder_proof_helpers,
        oauth_service_locator_proof_helpers,
    )
    from .pytest_collection_audit import (
        http_fixture_token_proof_helpers,
        validation_marker_proof_helpers,
    )
    from .xonsh_program_audit import xonsh_program_role_helpers

    return (
        bound_sink_argument,
        _captured_argument_definition,
        captured_operand_audit._argument_binding_is_parameter_or_external,
        _captured_literal_argument_origin,
        _captured_closed_text_callers,
        captured_log_field_text_closed,
        _captured_record_read,
        captured_operand_audit._captured_record_receiver_escapes,
        _CapturedRecordText.__init__,
        _CapturedRecordText.field,
        _CapturedRecordText.scalar,
        audit_log_flow._LogReader._flow,
        audit_log_flow._LogReader._unsafe,
        audit_log_flow.bound_sink_argument,
        audit_log_flow.captured_log_field_text_closed,
        captured_public_registry_label,
        credential_role_witness,
        _stage_public_registry_exclusion,
        _stage_registry_exit_message,
        _registry_cookie_name_use,
        _registry_formatted_use,
        captured_operand_audit.cookie_name_trace,
        audit_action_refs._captured_operand_prover,
        audit_action_refs._captured_credential_operand_proof,
        audit_action_refs._with_captured_operand_proof,
        audit_action_refs._attach_installer_prerequisite,
        audit_action_refs._attach_validation_marker_context,
        audit_action_refs._bound_operand_refutation,
        review_integrity.security_assignment_findings,
        review_audits.with_decl_proof,
        *password_validation_proof_helpers(),
        *hash_fixture_proof_helpers(),
        *oauth_placeholder_proof_helpers(),
        *oauth_service_locator_proof_helpers(),
        *validation_marker_proof_helpers(),
        *http_fixture_token_proof_helpers(),
        *captured_operand_audit.command_operand_proof_helpers(),
        *captured_operand_audit.installer_prerequisite_helpers(),
        captured_local_serialization_proof,
        *captured_operand_audit.captured_local_representation_helpers(),
        *xonsh_program_role_helpers(),
        _registry_roles_closed,
        _COOKIE_NAME_PROVIDERS,
        *(
            value
            for name, value in vars(captured_operand_audit).items()
            if name.startswith("_registry_") and callable(value)
        ),
    )
