"""Static source and workflow evidence for DRF class-owned account fixtures."""

import ast
from copy import copy
from functools import lru_cache
import hashlib
import re

from . import credential_role_identity_effects as roles
from .credential_role_constructor_provider import binding_occurrences


FIXTURE_CONTRACT = "DRF_CLASS_ACCOUNT_LIFECYCLE"
_MANAGEMENT_PROVIDER = "from django.core.management import execute_from_command_line"
_BOOTSTRAP = ast.parse(
    "import os\nimport sys\n" + _MANAGEMENT_PROVIDER + "\ndef main(): pass"
)
_PROTECTED = frozenset(
    "client client_class user setUpTestData setUpClass _pre_setup _fixture_setup "
    "databases serialized_rollback fixtures run __call__ __new__ __init__ "
    "__getattribute__ __getattr__ __setattr__ __delattr__".split()
)


def application_class_account_evidence(index, path, assignment, secret):
    source = index["source"]
    owner = source.parents[path].get(id(assignment))
    if (
        not isinstance(owner, ast.ClassDef)
        or source.parents[path].get(id(owner)) is not index["modules"][path]
    ):
        return None
    target = roles._fixture_declaration_target_node(assignment)
    if target is None or binding_occurrences(owner.body, secret) != [target]:
        return None
    runner = _ci_runner(index)
    if runner is None:
        return None
    settings = _runner_settings(index, runner)
    lifecycle = _owner_lifecycle(index, path, owner, secret)
    if settings is None or lifecycle is None:
        return None
    settings_path, settings_tree = settings
    setup_data, enrollment, password_use, setup, activate = lifecycle
    peers = _fixture_classes(index, path, owner, secret)
    if not peers:
        return None
    uses = [_location(source, path, password_use, "fresh_account_password")]
    operations = [
        _location(source, path, enrollment, "fresh_account_enrollment"),
        _location(source, path, activate, "in_process_client_authentication"),
    ]
    for peer, test_path in peers:
        result = _class_uses(index, test_path, peer, owner, secret, lifecycle, settings)
        if result is None:
            return None
        for value, request, route_path, registration in result:
            uses.append(_location(source, test_path, value, "test_client_password"))
            operations.extend(
                (
                    _location(
                        source, test_path, request, "in_process_client_token_request"
                    ),
                    _location(
                        source,
                        route_path,
                        registration,
                        "standard_token_password_verifier",
                    ),
                )
            )
    if len(uses) < 2 or not _providers_closed(
        index, peers, ((path, setup_data), (path, setup))
    ):
        return None
    declaration = _location(source, path, assignment, "credential_declaration")
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": declaration["path"],
        "source_sha256": declaration["sha256"],
        "declaration_span": declaration["span"],
        "profile": "DJANGO_CLASS_LOCAL_ACCOUNT_ENROLLMENT",
        "fixture_contract": FIXTURE_CONTRACT,
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "external_api_assumptions": [
            "django.DiscoverRunner.fresh_test_database.v1",
            "django.UserManager.default-password-enrollment.v1",
            "rest_framework.APITestCase.test-client-lifecycle.v1",
            "rest_framework_simplejwt.TokenObtainPairView.default-serializer.v1",
        ],
        "runner": runner,
        "settings": _location(
            source,
            settings_path,
            settings_tree.body[0],
            "selected_configuration_module",
        ),
        "consumer_use_closure": {
            "schema": "factory.application-consumer-use-closure.v2",
            "complete": True,
            "assignments": [declaration],
            "uses": uses,
            "operations": operations,
        },
    }


def _location(source, path, node, role):
    return {
        "path": source.relative(path),
        "sha256": source.inventory[path],
        "span": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
        "role": role,
    }


def _ci_runner(index):
    """Bind literal workflow invocations and their job-owned database services."""
    import yaml

    from .full_stack_ux_spec import _UniqueKeyLoader

    runners = []
    for name, raw in sorted(index["configuration_bytes"].items()):
        if not name.startswith(".github/workflows/"):
            continue
        try:
            if any(
                isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
                for token in yaml.scan(raw)
            ):
                return None
            document = yaml.load(raw, Loader=_UniqueKeyLoader)
            if not isinstance(document, dict) or not isinstance(
                document.get("jobs"), dict
            ):
                return None
        except (TypeError, ValueError, UnicodeError, RecursionError, yaml.YAMLError):
            return None
        if not all(isinstance(name, str) for name in document["jobs"]):
            return None
        for job_name, job in sorted(document["jobs"].items()):
            if not isinstance(job, dict):
                return None
            if "uses" in job:
                if not _captured_reusable_job(index, name, job):
                    return None
                continue
            evidence = _ci_test_job(document, job)
            if evidence is None and _declares_test_command(job_name, job):
                return None
            if evidence is not None:
                runners.append(
                    {
                        "path": name,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "job": job_name,
                        **evidence,
                    }
                )
    settings = {runner["settings_module"] for runner in runners}
    return (
        {"settings_module": settings.pop(), "workflows": runners}
        if len(settings) == 1
        else None
    )


def _captured_reusable_job(index, path, job):
    reference = job["uses"]
    return (
        isinstance(reference, str)
        and re.fullmatch(r"\./\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", reference)
        and reference[2:] != path
        and reference[2:] in index["configuration_bytes"]
        and job.keys() <= {"uses", "name", "if", "needs", "permissions"}
    )


def _is_test_command(command):
    if not isinstance(command, str):
        return False
    return bool(
        re.search(
            r"\b(?:py\.test|pytest|unittest|tox|nox|django-admin(?:\.py)?)\b"
            r"""|\b(?:manage\.py|django|make|just)["']?\s+test\b""",
            command,
        )
        or re.search(
            r"\b(?:python[23]?|bash|sh|pwsh|coverage\s+run)\s+"
            r"""["']?(?:\./)?(?!manage\.py\b)[\w./-]+\.(?:py|sh|ps1)\b"""
            r"""|(?:^|\s)["']?\./[\w./-]+\.(?:py|sh|ps1)\b""",
            command,
        )
    )


def _declares_test_command(job_name, job):
    labels = (job_name, job.get("name"))
    if any(
        isinstance(word, str) and re.search(r"(?:^|[-_ ])tests?(?:$|[-_ ])", word, re.I)
        for word in labels
    ):
        return True
    return isinstance(job.get("steps"), list) and any(
        isinstance(step, dict) and _is_test_command(step.get("run"))
        for step in job["steps"]
    )


def _ci_test_job(document, job):
    steps = job.get("steps", ())
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        return None
    commands = [step.get("run", "") for step in steps]
    if not all(
        isinstance(command, str)
        and "GITHUB_ENV" not in command
        and "GITHUB_PATH" not in command
        for command in commands
    ):
        return None
    match = [
        i
        for i, command in enumerate(commands)
        if re.fullmatch(
            r"(?:poetry run )?(?:python(?:3)?|coverage run) manage\.py test",
            command.strip(),
        )
    ]
    if (
        len(match) != 1
        or not isinstance(job.get("runs-on"), str)
        or not job["runs-on"].startswith("ubuntu-")
    ):
        return None
    if any(
        i != match[0] and _is_test_command(command)
        for i, command in enumerate(commands)
    ):
        return None
    step = steps[match[0]]
    if "if" in job or "if" in step:
        return None
    if any(
        key in group
        for group in (document, job, step)
        for key in ("defaults", "working-directory", "container", "shell", "strategy")
    ):
        return None
    envs = [group.get("env", {}) for group in (document, job, step)]
    if not all(isinstance(env, dict) for env in envs):
        return None
    env = {key: value for group in envs for key, value in group.items()}
    if (
        any(
            key in env
            for key in (
                "DATABASE_URL",
                "DJANGO_USE_SQLITE",
                "DJANGO_ENV",
                "PYTHONPATH",
                "PYTHONHOME",
            )
        )
        or env.get("POSTGRES_HOST") not in {"localhost", "127.0.0.1"}
        or env.get("POSTGRES_PORT") not in {5432, "5432"}
        or not isinstance(env.get("DJANGO_SETTINGS_MODULE"), str)
    ):
        return None
    services = job.get("services", {})
    if not isinstance(services, dict) or len(services) != 1:
        return None
    service = next(iter(services.values()))
    if (
        not isinstance(service, dict)
        or not isinstance(service.get("image"), str)
        or not re.fullmatch(
            r"postgres:[0-9]+(?:\.[0-9]+)?(?:-alpine)?", service["image"]
        )
        or service.get("ports") != ["5432:5432"]
        or not isinstance(service.get("env"), dict)
        or any(
            not isinstance(env.get(key), str)
            or not env[key]
            or "${{" in env[key]
            or env[key] != service["env"].get(key)
            for key in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
        )
    ):
        return None
    return {
        "settings_module": env["DJANGO_SETTINGS_MODULE"],
        "command_step": match[0] + 1,
        "database_service": service["image"],
    }


def _runner_settings(index, runner):
    """Bind Django's default runner and default user with stock database backends."""
    from .import_context import _management_script_contract

    source = index["source"]
    manage_path = source.root / "manage.py"
    if manage_path not in index["modules"] or not source.validate(manage_path):
        return None
    manage = copy(index["modules"][manage_path])
    manage.body = [copy(node) for node in manage.body]
    for node in manage.body:
        if (
            isinstance(node, ast.FunctionDef)
            and isinstance(node.returns, ast.Constant)
            and node.returns.value is None
        ):
            node.returns = None
    contract = _management_script_contract(
        manage,
        [ast.dump(node) for node in _BOOTSTRAP.body[:2]],
        ast.dump(_BOOTSTRAP.body[2]),
        ast.dump(_BOOTSTRAP.body[3].args),
        _MANAGEMENT_PROVIDER,
    )
    if contract is None or contract[0] != runner["settings_module"]:
        return None
    path, tree = fixture._django_mod(index, runner["settings_module"])
    if (
        tree is None
        or not source.validate(path)
        or fixture._app_expression_name(index, path, ast.Name(id="os")) != "os"
    ):
        return None
    denied = "TEST_RUNNER DATABASE_ROUTERS MIGRATION_MODULES AUTH_USER_MODEL AUTHENTICATION_BACKENDS PASSWORD_HASHERS".split()
    if any(binding_occurrences(tree.body, name) for name in denied):
        return None
    apps = roles._fixture_literal_setting(tree, "INSTALLED_APPS")
    if not isinstance(apps, list) or not {
        "django.contrib.auth",
        "rest_framework",
    } <= set(apps):
        return None
    bindings = binding_occurrences(tree.body, "DATABASES")
    parents = source.parents[path]
    if (
        not bindings
        or not all(
            isinstance(statement := parents.get(id(target)), ast.Assign)
            and statement.targets == [target]
            and _database_config(statement, tree, parents)
            for target in bindings
        )
        or any(
            isinstance(node, ast.Name)
            and node.id == "DATABASES"
            and isinstance(node.ctx, ast.Load)
            for node in ast.walk(tree)
        )
    ):
        return None
    runner["bootstrap"] = _location(
        source,
        manage_path,
        index["modules"][manage_path].body[-1],
        "management_test_dispatch",
    )
    return path, tree


def _literal_fields(value):
    if not isinstance(value, ast.Dict) or any(
        not isinstance(key, ast.Constant) or type(key.value) is not str
        for key in value.keys
    ):
        return None
    result = dict(zip((key.value for key in value.keys), value.values))
    return result if len(result) == len(value.keys) else None


def _database_config(statement, tree, parents):
    fields = _literal_fields(statement.value)
    if fields is None or set(fields) != {"default"}:
        return False
    default = _literal_fields(fields["default"])
    if default is None or not isinstance(default.get("ENGINE"), ast.Constant):
        return False
    if default["ENGINE"].value not in {
        "django.db.backends.sqlite3",
        "django.db.backends.postgresql",
    } or set(default) - {
        "ENGINE",
        "NAME",
        "USER",
        "PASSWORD",
        "HOST",
        "PORT",
        "CONN_MAX_AGE",
        "CONN_HEALTH_CHECKS",
        "OPTIONS",
    }:
        return False
    if default["ENGINE"].value == "django.db.backends.sqlite3":
        return "OPTIONS" not in default
    return _ci_excludes_database_url(statement, tree, parents) or (
        (
            isinstance(host := default.get("HOST"), ast.Constant)
            and host.value in {"127.0.0.1", "localhost"}
            or _ci_uses_env(host, "POSTGRES_HOST", tree)
        )
        and (
            isinstance(port := default.get("PORT"), ast.Constant)
            and port.value in {5432, "5432"}
            or _ci_uses_env(port, "POSTGRES_PORT", tree)
        )
        and _database_options_closed(default.get("OPTIONS"), tree, parents)
    )


def _database_options_closed(options, tree, parents):
    if options is None:
        return True
    allowed = {"connect_timeout", "sslmode"}
    if isinstance(options, ast.Dict):
        fields = _literal_fields(options)
        return fields is not None and set(fields) <= allowed
    if not isinstance(options, ast.Name):
        return False
    bindings = binding_occurrences(tree.body, options.id)
    if len(bindings) != 1:
        return False
    allocation = parents.get(id(bindings[0]))
    if (
        not isinstance(allocation, (ast.Assign, ast.AnnAssign))
        or allocation.lineno >= options.lineno
    ):
        return False
    fields = _literal_fields(allocation.value)
    if fields is None or set(fields) - allowed:
        return False
    for use in ast.walk(tree):
        if (
            not isinstance(use, ast.Name)
            or use.id != options.id
            or use in (options, bindings[0])
        ):
            continue
        match parents.get(id(use)):
            case ast.Subscript(
                value=receiver, slice=ast.Constant(value=key), ctx=ast.Store()
            ) if receiver is use and isinstance(key, str) and key in allowed:
                continue
        return False
    return True


_FIRST_ENV = ast.parse("""def helper(*names, default=''):
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return default
""").body[0]


def _ci_uses_env(node, env, tree):
    match node:
        case ast.Call(
            func=ast.Attribute(value=ast.Name(id="os"), attr="getenv"),
            args=[ast.Constant(value=key), *defaults],
            keywords=[],
        ):
            return (
                key == env
                and len(defaults) <= 1
                and all(isinstance(value, ast.Constant) for value in defaults)
            )
        case ast.Call(
            func=ast.Name(id=name),
            args=[ast.Constant(value=key), *other],
            keywords=keywords,
        ) if key == env:
            return _literal_env_helper(tree, name, other, keywords)
    return False


def _literal_env_helper(tree, name, other, keywords):
    if (
        not all(isinstance(value, ast.Constant) for value in other)
        or len(keywords) > 1
        or any(
            keyword.arg != "default" or not isinstance(keyword.value, ast.Constant)
            for keyword in keywords
        )
    ):
        return False
    rows = binding_occurrences(tree.body, name)
    if (
        len(rows) != 1
        or not isinstance(actual := rows[0], ast.FunctionDef)
        or actual.decorator_list
    ):
        return False
    args = copy(actual.args)
    args.vararg = copy(args.vararg)
    args.kwonlyargs = [copy(arg) for arg in args.kwonlyargs]
    for arg in [args.vararg, *args.kwonlyargs]:
        if (
            arg is not None
            and isinstance(arg.annotation, ast.Name)
            and arg.annotation.id == "str"
        ):
            arg.annotation = None
    return ast.dump(args) == ast.dump(_FIRST_ENV.args) and [
        ast.dump(node) for node in actual.body
    ] == [ast.dump(node) for node in _FIRST_ENV.body]


def _ci_excludes_database_url(statement, tree, parents):
    expected = ast.parse("os.getenv('DATABASE_URL', '').strip()", mode="eval").body
    current = statement
    while (owner := parents.get(id(current))) is not None:
        if isinstance(owner, ast.If) and current in owner.body:
            tests = (
                owner.test.values
                if isinstance(owner.test, ast.BoolOp)
                and isinstance(owner.test.op, ast.And)
                else [owner.test]
            )
            for condition in tests:
                if isinstance(condition, ast.Name):
                    rows = fixture._django_assignment(tree, condition.id)
                    if (
                        len(rows) == 1
                        and rows[0][0].lineno < owner.lineno
                        and ast.dump(rows[0][1]) == ast.dump(expected)
                    ):
                        return True
        current = owner
    return False


def _owner_lifecycle(index, path, owner, secret):
    if (
        owner.decorator_list
        or owner.keywords
        or len(owner.bases) != 1
        or fixture._app_expression_name(index, path, owner.bases[0])
        != "rest_framework.test.APITestCase"
    ):
        return None
    if any(
        binding_occurrences(owner.body, name) for name in _PROTECTED - {"setUpTestData"}
    ):
        return None
    data = _only_method(owner, "setUpTestData")
    setup = _only_method(owner, "setUp")
    if not _method_receiver(data, "cls", classmethod=True) or not _method_receiver(
        setup, "self"
    ):
        return None
    match data.body, setup.body:
        case (
            [
                ast.Assign(
                    targets=[ast.Attribute(value=ast.Name(id="cls"), attr="user")],
                    value=ast.Call() as enrollment,
                )
            ],
            [ast.Expr(value=ast.Call() as activate)],
        ):
            pass
        case _:
            return None
    provider = roles._fixture_create_user_provider(enrollment)
    if not roles._fixture_resolve_user_model_provider(
        index, path, data, provider, fixture
    ):
        return None
    arguments = roles._fixture_keywords(enrollment)
    if (
        arguments is None
        or enrollment.args
        or set(arguments) != {"username", "email", "password"}
    ):
        return None
    if any(
        not isinstance(arguments[name], ast.Constant)
        or type(arguments[name].value) is not str
        for name in ("username", "email")
    ):
        return None
    password = arguments["password"]
    if fixture._app_member_chain(password) != ["cls", secret]:
        return None
    if (
        fixture._app_member_chain(activate.func)
        != ["self", "client", "force_authenticate"]
        or activate.keywords
        or len(activate.args) != 1
        or fixture._app_member_chain(activate.args[0]) != ["self", "user"]
    ):
        return None
    return data, enrollment, password, setup, activate


def _only_method(owner, name):
    rows = binding_occurrences(owner.body, name)
    return rows[0] if len(rows) == 1 and isinstance(rows[0], ast.FunctionDef) else None


def _method_receiver(method, name, *, classmethod=False):
    if not isinstance(method, ast.FunctionDef):
        return False
    signature = method.args
    if (
        signature.posonlyargs
        or signature.kwonlyargs
        or signature.defaults
        or signature.vararg
        or signature.kwarg
    ):
        return False
    if (
        signature.args != []
        and len(signature.args) == 1
        and signature.args[0].arg == name
        and signature.args[0].annotation is None
    ):
        return [ast.dump(marker) for marker in method.decorator_list] == (
            [ast.dump(ast.Name(id="classmethod", ctx=ast.Load()))]
            if classmethod
            else []
        )
    return False


def _fixture_classes(index, path, owner, secret):
    source = index["source"]
    origin = fixture._django_name(index, path)
    if not origin:
        return None
    qualified = f"{origin}.{owner.name}"
    peers = [(owner, path)]
    for other, tree in sorted(index["modules"].items()):
        if not source.validate(other):
            return None
        aliases = {owner.name} if other == path else set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                rows = fixture._django_import_rows(
                    node, fixture._django_package(index, other)
                )
                if rows is None:
                    return None
                for name, canonical in rows:
                    if canonical == qualified:
                        if node not in tree.body or binding_occurrences(
                            tree.body, name
                        ) != [node]:
                            return None
                        aliases.add(name)
                    elif (
                        canonical == origin
                        or canonical.startswith(origin + ".")
                        or canonical == origin.rpartition(".")[0]
                        or canonical.endswith(".*")
                    ):
                        return None
            elif isinstance(node, ast.Name) and node.id in {
                "__builtins__",
                "__globals__",
                "__import__",
                "globals",
                "eval",
                "exec",
            }:
                return None
        children = _fixture_subclasses(index, other, tree, aliases, secret)
        if children is None or (aliases and other != path and not children):
            return None
        peers.extend((child, other) for child in children)
    return peers if len(peers) > 1 else None


def _fixture_subclasses(index, path, tree, aliases, secret):
    if not aliases:
        return []
    parents = index["source"].parents[path]
    descendants = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or node.id not in aliases:
            continue
        owner = parents.get(id(node))
        if not (
            isinstance(node.ctx, ast.Load)
            and isinstance(owner, ast.ClassDef)
            and owner in tree.body
            and owner.bases == [node]
            and not (owner.decorator_list or owner.keywords)
            and path.name.startswith("test")
            and path.parent / "__init__.py" in index["modules"]
            and any(
                isinstance(method, ast.FunctionDef)
                and method.name.startswith("test")
                and not method.decorator_list
                for method in owner.body
            )
            and not any(
                binding_occurrences(owner.body, name) for name in _PROTECTED | {secret}
            )
            and roles._fixture_testcase_owner_closed(index, path, owner)
        ):
            return None
        setup = binding_occurrences(owner.body, "setUp")
        if setup and not (
            len(setup) == 1
            and _method_receiver(setup[0], "self")
            and _parent_setup(setup[0].body[0])
        ):
            return None
        descendants.append(owner)
    return descendants


def _parent_setup(statement):
    match statement:
        case ast.Expr(
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Call(func=ast.Name(id="super"), args=[], keywords=[]),
                    attr="setUp",
                ),
                args=[],
                keywords=[],
            )
        ):
            return True
    return False


def _class_uses(index, path, owner, declaration, secret, lifecycle, settings):
    source = index["source"]
    parents = source.parents[path]
    if not _class_definition_closed(index["modules"][path], owner):
        return None
    setup_data, _, initial_password, _, activate = lifecycle
    known_user_refs = {activate.args[0]}
    requests = []
    for node in ast.walk(owner):
        if isinstance(node, (ast.ClassDef, ast.Lambda)) and node is not owner:
            return None
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id == secret
        ):
            return None
        if (
            not isinstance(node, ast.Attribute)
            or node.attr != secret
            or node is initial_password
        ):
            continue
        method = roles._enclosing_function(node, parents)
        if not (
            method in owner.body
            and owner is not declaration
            and _method_receiver(method, "self")
            and method.name.startswith("test")
            and fixture._app_member_chain(node) == ["self", secret]
        ):
            return None
        sink = _credential_request(index, path, method, node, settings)
        if sink is None:
            return None
        request, username, route_path, registration = sink
        known_user_refs.add(username.value)
        requests.append((node, request, route_path, registration))
    return (
        requests
        if _receiver_uses_closed(index, path, owner, setup_data, known_user_refs)
        else None
    )


def _class_definition_closed(module, owner):
    """Allow class declarations without execution that observes the fixture namespace."""
    postponed = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(item.name == "annotations" for item in node.names)
        for node in module.body
    )
    for position, statement in enumerate(owner.body):
        match statement:
            case ast.Expr(value=ast.Constant(value=str())) if position == 0:
                continue
            case ast.Assign(targets=[ast.Name(id=name)], value=ast.Constant()) if (
                not name.startswith("__")
            ):
                continue
            case ast.FunctionDef(args=signature, returns=returns):
                defaults = [
                    arg
                    for arg in (*signature.defaults, *signature.kw_defaults)
                    if arg is not None
                ]
                annotations = [
                    arg.annotation
                    for arg in (
                        *signature.posonlyargs,
                        *signature.args,
                        *signature.kwonlyargs,
                    )
                ]
                annotations.extend(
                    arg.annotation
                    for arg in (signature.vararg, signature.kwarg)
                    if arg is not None
                )
                if all(isinstance(default, ast.Constant) for default in defaults) and (
                    postponed
                    or all(
                        ann is None or isinstance(ann, ast.Constant)
                        for ann in (*annotations, returns)
                    )
                ):
                    continue
        return False
    return True


def _receiver_uses_closed(index, path, owner, setup_data, known_user_refs):
    if not all(
        _canonical_method_receiver(method)
        for method in owner.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return False
    parents = index["source"].parents[path]
    for node in ast.walk(owner):
        if isinstance(node, (ast.Nonlocal, ast.Global)):
            return False
        if not isinstance(node, ast.Name) or node.id not in {"self", "cls"}:
            continue
        member = parents.get(id(node))
        if (
            not isinstance(node.ctx, ast.Load)
            or not isinstance(member, ast.Attribute)
            or member.attr.startswith("_")
        ):
            return False
        function = roles._enclosing_function(node, parents)
        if (
            function is None
            or function not in owner.body
            or not function.args.args
            or function.args.args[0].arg != node.id
        ):
            return False
        if (
            member.attr == "user"
            and member not in known_user_refs
            and not (function is setup_data and isinstance(member.ctx, ast.Store))
        ):
            return False
        if member.attr == "client" and not _client_member_call(member, parents):
            return False
    return True


def _canonical_method_receiver(method):
    markers = method.decorator_list
    if (
        len(markers) == 1
        and isinstance(markers[0], ast.Name)
        and markers[0].id == "staticmethod"
    ):
        return True
    args = [*method.args.posonlyargs, *method.args.args]
    if not markers:
        return bool(args and args[0].arg == "self")
    return bool(
        len(markers) == 1
        and isinstance(markers[0], ast.Name)
        and markers[0].id == "classmethod"
        and args
        and args[0].arg == "cls"
    )


def _client_member_call(member, parents):
    method = parents.get(id(member))
    call = parents.get(id(method))
    return (
        isinstance(member.ctx, ast.Load)
        and isinstance(method, ast.Attribute)
        and method.attr
        in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "head",
            "force_authenticate",
            "credentials",
        }
        and isinstance(call, ast.Call)
        and call.func is method
    )


def _credential_request(index, path, method, password, settings):
    parents = index["source"].parents[path]
    payload = parents.get(id(password))
    request = parents.get(id(payload))
    fields = _literal_fields(payload)
    if not (
        fields is not None
        and set(fields) == {"username", "password"}
        and fields["password"] is password
        and fixture._app_member_chain(fields["username"])
        == ["self", "user", "username"]
        and isinstance(request, ast.Call)
        and len(request.args) == 2
        and request.args[1] is payload
        and fixture._app_member_chain(request.func) == ["self", "client", "post"]
        and isinstance(request.args[0], ast.Constant)
        and isinstance(request.args[0].value, str)
    ):
        return None
    statement = parents.get(id(request))
    if not (
        statement in method.body
        and all(
            _clear_test_client_authentication(node)
            for node in method.body[: method.body.index(statement)]
        )
    ):
        return None
    assert isinstance(fields["username"], ast.Attribute)
    keywords = roles._fixture_keywords(request)
    if (
        keywords is None
        or len(keywords) > 1
        or (
            keywords
            and not (
                isinstance(keywords.get("format"), ast.Constant)
                and keywords["format"].value == "json"
            )
        )
    ):
        return None
    route = _token_route(index, settings, request.args[0].value)
    return (request, fields["username"], *route) if route is not None else None


def _clear_test_client_authentication(node):
    match node:
        case ast.Expr(
            value=ast.Call(
                func=callee,
                args=[],
                keywords=[ast.keyword(arg="user", value=ast.Constant(value=None))],
            )
        ):
            return fixture._app_member_chain(callee) == [
                "self",
                "client",
                "force_authenticate",
            ]
    return False


def _token_route(index, settings, request_path):
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)+", request_path):
        return None
    _, settings_tree = settings
    if not (
        _token_settings(settings_tree)
        and _rest_request_hooks_closed(index, settings_tree)
        and _middlewares_closed(index, settings_tree)
    ):
        return None
    selected = roles._fixture_literal_setting(settings_tree, "ROOT_URLCONF")
    if not isinstance(selected, str):
        return None
    path, tree = fixture._django_mod(index, selected)
    if tree is None or not index["source"].validate(path):
        return None
    rows = fixture._django_assignment(tree, "urlpatterns")
    if (
        len(rows) != 1
        or not isinstance(rows[0][1], ast.List)
        or _binding_read(tree, "urlpatterns")
    ):
        return None
    for item in rows[0][1].elts:
        if not (
            isinstance(item, ast.Call)
            and len(item.args) == 2
            and isinstance(item.args[0], ast.Constant)
            and isinstance(item.args[0].value, str)
            and fixture._app_expression_name(index, path, item.func)
            == "django.urls.path"
        ):
            return None
        prefix = item.args[0].value
        if prefix == request_path[1:]:
            return (
                (path, item)
                if _standard_token_view(index, path, item.args[1])
                else None
            )
        if "<" in prefix or (prefix and request_path[1:].startswith(prefix)):
            return None
        if not prefix and not _source_root_view(index, path, item.args[1]):
            return None
    return None


def _source_root_view(index, path, expression):
    """A source-bound function at the empty path consumes exactly that path."""
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )

    if not isinstance(expression, (ast.Name, ast.Attribute)):
        return False
    resolved = fixture._app_source_symbol(index, path, expression)
    canonical = fixture._app_expression_name(index, path, expression)
    if resolved is None or not canonical:
        return False
    _, view = resolved
    return (
        isinstance(view, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not view.decorator_list
        and not _captured_terminal_provider_mutation(
            index["source"], audit, canonical, readonly_nodes=(expression,)
        )
    )


_DRF_REQUEST_PROVIDERS = {
    "DEFAULT_PARSER_CLASSES": {
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    },
    "DEFAULT_AUTHENTICATION_CLASSES": {
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    },
    "DEFAULT_PERMISSION_CLASSES": {
        "rest_framework.permissions.AllowAny",
        "rest_framework.permissions.IsAuthenticated",
    },
    "DEFAULT_RENDERER_CLASSES": {
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    },
    "DEFAULT_THROTTLE_CLASSES": {
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    },
    "DEFAULT_SCHEMA_CLASS": {
        "drf_spectacular.openapi.AutoSchema",
        "rest_framework.schemas.openapi.AutoSchema",
    },
    "DEFAULT_PAGINATION_CLASS": {"rest_framework.pagination.PageNumberPagination"},
    "DEFAULT_CONTENT_NEGOTIATION_CLASS": {
        "rest_framework.negotiation.DefaultContentNegotiation"
    },
}


def _rest_request_hooks_closed(index, tree):
    rows = fixture._django_assignment(tree, "REST_FRAMEWORK")
    if not rows:
        return not binding_occurrences(tree.body, "REST_FRAMEWORK")
    fields = _literal_fields(rows[0][1])
    if len(rows) != 1 or fields is None or _binding_read(tree, "REST_FRAMEWORK"):
        return False
    for key, node in fields.items():
        if key in {"PAGE_SIZE", "DEFAULT_THROTTLE_RATES"}:
            continue
        if key == "EXCEPTION_HANDLER":
            if (
                not isinstance(node, ast.Constant)
                or not isinstance(node.value, str)
                or not _metadata_exception_handler(index, node.value)
            ):
                return False
            continue
        providers = _DRF_REQUEST_PROVIDERS.get(key)
        values = node.elts if isinstance(node, (ast.List, ast.Tuple)) else [node]
        if providers is None or not all(
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value in providers
            for value in values
        ):
            return False
    return True


def _metadata_exception_handler(index, name):
    if name == "rest_framework.views.exception_handler":
        return True
    module, _, function = name.rpartition(".")
    path, tree = fixture._django_mod(index, module)
    if (
        tree is None
        or not index["source"].validate(path)
        or not fixture._django_builtins_unshadowed(index, path, {"getattr"})
    ):
        return False
    handler = _only_method(tree, function)
    if (
        handler is None
        or handler.decorator_list
        or [arg.arg for arg in handler.args.args] != ["exc", "context"]
        or len(handler.body) < 3
    ):
        return False
    first, bind_request, read_metadata, *tail = handler.body
    match first:
        case ast.Assign(
            targets=[ast.Name()],
            value=ast.Call(
                func=callee,
                args=[ast.Name(id="exc"), ast.Name(id="context")],
                keywords=[],
            ),
        ):
            if (
                fixture._app_expression_name(index, path, callee, handler)
                != "rest_framework.views.exception_handler"
            ):
                return False
        case _:
            return False
    expected = ast.parse(
        'request = context.get("request")\nrequest_id = getattr(request, "request_id", None)'
    ).body
    return [ast.dump(node) for node in (bind_request, read_metadata)] == [
        ast.dump(node) for node in expected
    ] and not any(
        isinstance(node, ast.Name) and node.id in {"request", "context"}
        for statement in tail
        for node in ast.walk(statement)
    )


def _token_settings(tree):
    rows = fixture._django_assignment(tree, "SIMPLE_JWT")
    if len(rows) == 0:
        return not binding_occurrences(tree.body, "SIMPLE_JWT")
    values = _literal_fields(rows[0][1])
    return (
        len(rows) == 1
        and values is not None
        and not _binding_read(tree, "SIMPLE_JWT")
        and not {
            "TOKEN_OBTAIN_SERIALIZER",
            "USER_AUTHENTICATION_RULE",
            "ON_LOGIN_SUCCESS",
            "ON_LOGIN_FAILED",
        }.intersection(values)
    )


def _binding_read(tree, name):
    return any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
        for node in ast.walk(tree)
    )


def _standard_token_view(index, path, view):
    if not isinstance(view, ast.Call) or view.args:
        return False
    if (
        fixture._app_expression_name(index, path, view.func)
        != "rest_framework_simplejwt.views.TokenObtainPairView.as_view"
    ):
        return False
    return not view.keywords or (
        len(view.keywords) == 1
        and view.keywords[0].arg == "permission_classes"
        and isinstance(view.keywords[0].value, ast.List)
        and len(view.keywords[0].value.elts) == 1
        and fixture._app_expression_name(index, path, view.keywords[0].value.elts[0])
        == "rest_framework.permissions.AllowAny"
    )


def _middlewares_closed(index, settings):
    names = roles._fixture_literal_setting(settings, "MIDDLEWARE")
    if (
        _binding_read(settings, "MIDDLEWARE")
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
    ):
        return False
    known = {
        "corsheaders.middleware.CorsMiddleware",
        "whitenoise.middleware.WhiteNoiseMiddleware",
    }
    return all(
        name in known
        or name.startswith("django.middleware.")
        or name.startswith(
            (
                "django.contrib.sessions.middleware.",
                "django.contrib.messages.middleware.",
                "django.contrib.auth.middleware.",
            )
        )
        or _metadata_middleware(index, name)
        for name in names
    )


def _metadata_middleware(index, name):
    module, _, cls = name.rpartition(".")
    path, tree = fixture._django_mod(index, module)
    if tree is None or not index["source"].validate(path):
        return False
    owners = binding_occurrences(tree.body, cls)
    if len(owners) != 1 or not isinstance(owners[0], ast.ClassDef):
        return False
    owner = owners[0]
    if owner.decorator_list or owner.bases or owner.keywords:
        return False
    parents = index["source"].parents[path]
    initialize, invoke = (
        _only_method(owner, "__init__"),
        _only_method(owner, "__call__"),
    )
    if not all(
        method is not None and not method.decorator_list
        for method in (initialize, invoke)
    ):
        return False
    body = owner.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if set(body) != {initialize, invoke} or not fixture._django_builtins_unshadowed(
        index, path, {"getattr"}
    ):
        return False
    expected = ast.parse("self.get_response = get_response").body[0]
    if len(initialize.body) != 1 or ast.dump(initialize.body[0]) != ast.dump(expected):
        return False
    if binding_occurrences(owner.body, "get_response") or [
        arg.arg for arg in invoke.args.args
    ] != ["self", "request"]:
        return False
    for node in ast.walk(invoke):
        if (
            isinstance(node, ast.Attribute)
            and not isinstance(node.ctx, ast.Load)
            and node.attr == "get_response"
        ):
            return False
        if not isinstance(node, ast.Name) or node.id != "request":
            continue
        parent = parents.get(id(node))
        if isinstance(node.ctx, ast.Load) and _middleware_metadata_read(parent, node):
            continue
        return False
    return True


def _middleware_metadata_read(parent, operand):
    if isinstance(parent, ast.Attribute):
        return parent.attr in {"method", "path", "headers", "request_id"}
    if (
        isinstance(parent, ast.Call)
        and parent.args == [operand]
        and not parent.keywords
    ):
        return fixture._app_member_chain(parent.func) == ["self", "get_response"]
    return (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Name)
        and parent.func.id == "getattr"
        and len(parent.args) == 3
        and parent.args[0] is operand
        and not parent.keywords
        and isinstance(parent.args[1], ast.Constant)
        and parent.args[1].value == "resolver_match"
        and isinstance(parent.args[2], ast.Constant)
        and parent.args[2].value is None
    )


def _providers_closed(index, peers, lifecycle):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation as mutated,
    )

    source = index["source"]
    providers = (
        "django.contrib.auth.get_user_model",
        "django.contrib.auth.models.User",
        "django.core.management.execute_from_command_line",
        "django.test.runner.DiscoverRunner",
        "rest_framework.test.APITestCase",
        "rest_framework.test.APIClient",
        "rest_framework_simplejwt.views.TokenObtainPairView",
        "django.conf.settings.AUTH_USER_MODEL",
        "django.conf.settings.AUTHENTICATION_BACKENDS",
        "django.conf.settings.DATABASES",
        "django.conf.settings.TEST_RUNNER",
        "django.conf.settings.ROOT_URLCONF",
        "django.conf.settings.SIMPLE_JWT",
        "django.conf.settings.REST_FRAMEWORK",
        "django.conf.settings.MIDDLEWARE",
        "django.urls.path",
        "rest_framework.views.exception_handler",
        "os.getenv",
    )
    if fixture._django_provider_root_shadowed(
        index["module_paths"], "rest_framework_simplejwt"
    ) or any(mutated(source, audit, provider) for provider in providers):
        return False
    if any(
        not fixture._django_builtins_unshadowed(
            index, path, {"classmethod", "staticmethod", "super"}
        )
        for _, path in peers
    ):
        return False
    for path, tree in index["modules"].items():
        if not fixture._django_model_signal_registration_clear(index, path):
            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and (
                node.name == "load_tests"
                or node.name == "ready"
                and isinstance(source.parents[path].get(id(node)), ast.ClassDef)
            ):
                return False
    return all(
        fixture._app_provider_unchanged(index, path, function, providers[0])
        for path, function in lifecycle
    )


def class_fixture_helpers():
    """Bind producer and independent verifier cache epochs to the complete proof."""
    helpers = tuple(
        value
        for value in globals().values()
        if callable(value) and getattr(value, "__module__", None) == __name__
    )
    policy = _fixture_policy_epoch(
        (
            tuple(
                sorted(
                    (name, tuple(sorted(providers)))
                    for name, providers in _DRF_REQUEST_PROVIDERS.items()
                )
            ),
            tuple(sorted(_PROTECTED)),
            ast.dump(_FIRST_ENV),
            ast.dump(_BOOTSTRAP),
        )
    )
    return (*helpers, policy)


@lru_cache(maxsize=16)
def _fixture_policy_epoch(_contents):
    return object()


# Fixture provenance imports the verifier epoch during its own initialization.
from . import mock_fixture_provenance as fixture  # noqa: E402
