"""Python lexical bindings must not create or conceal database export escapes."""

import ast

import pytest

from factoryline.import_context import _db_python_context_export_stable


def stable(source):
    return _db_python_context_export_stable(
        [("consumer", ast.parse(source))],
        "database",
        "connection",
        lambda _module, node: node.module or "",
    )


@pytest.mark.parametrize(
    "body",
    [
        "def run():\n    connection = object()\n    return connection",
        "def run(connection):\n    return connection",
        "async def run(*, connection):\n    return connection",
        "def run():\n    with object() as connection:\n        return connection",
        "def run():\n    connection = object()\n    def inner():\n        return connection\n    return inner",
        "def run():\n    connection = object()\n    def inner():\n        nonlocal connection\n        return connection\n    return inner",
        "def run():\n    try:\n        pass\n    except Exception as connection:\n        return connection",
        "def run():\n    def connection():\n        pass\n    return connection",
    ],
)
def test_local_bindings_are_not_imported_function_escapes(body):
    assert stable("from database import connection\n" + body)


@pytest.mark.parametrize(
    "body",
    [
        "saved = connection",
        "def run():\n    return connection",
        "def run(connection=connection):\n    return connection",
        "@connection\ndef run(connection):\n    return connection",
        "def run(connection: connection):\n    return connection",
        "def outer():\n    connection = object()\n    def inner():\n        global connection\n        return connection\n    return inner",
        "def run():\n    from database import connection\n    return connection",
        "def outer(connection):\n    def inner():\n        from database import connection\n        return connection\n    return inner",
        "def outer():\n    connection = object()\n    class Worker:\n        global connection\n        saved = connection\n    return Worker",
        "def run():\n    connection = object()\n    eval('anything')",
        "def run():\n    connection = object()\n    database.connect = object()",
    ],
)
def test_real_escapes_and_mutation_remain_rejected(body):
    assert not stable("from database import connection\n" + body)


def test_module_alias_parameter_shadow_does_not_hide_global_escape():
    assert stable("import database as db\ndef run(db):\n    return db")
    assert not stable("import database as db\ndef run(db=db):\n    return db")


def test_class_attribute_does_not_shadow_module_export_in_method():
    assert not stable(
        "from database import connection\n"
        "class Worker:\n    connection = 1\n"
        "    def run(self):\n        return connection\n"
    )


@pytest.mark.parametrize(
    "statement",
    [
        "exec('anything')",
        "eval('anything')",
        "globals()",
        "locals()",
        "vars()",
        "__import__('database')",
        "setattr(target, 'connection', attacker)",
        "delattr(target, 'connection')",
        "target.__dict__['connection'] = attacker",
        "sys.modules['database'] = attacker",
        "database.connect = attacker",
    ],
)
@pytest.mark.parametrize("imported", [False, True])
def test_resolved_or_absent_aliases_do_not_hide_unsafe_nodes(statement, imported):
    prefix = "from database import connection\n" if imported else ""
    assert not stable(
        prefix + "def outer():\n    def inner(connection):\n        " + statement + "\n"
    )
