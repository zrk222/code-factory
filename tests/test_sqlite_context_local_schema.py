"""SQLite execute facts stay scoped to a proven connection and control-flow path."""

import ast
import sqlite3

import pytest

from factoryline.intent_quality import _database_structure


def project(source):
    return _database_structure(
        {"main.py": source.encode()}, "sqlite", None, {"main.py": ast.parse(source)}
    )


def test_sqlite_connect_callable_is_captured_before_path_conversion(monkeypatch):
    class PathValue:
        def __str__(self):
            monkeypatch.setattr(sqlite3, "connect", lambda *_: "rebound")
            return ":memory:"

    db = sqlite3.connect(str(PathValue()))
    try:
        assert type(db) is sqlite3.Connection
        assert db.execute("SELECT 1").fetchone() == (1,)
    finally:
        db.close()


DIRECT = """import sqlite3
def run():
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE app_events(app_id TEXT)')
        db.execute('INSERT INTO app_events(app_id) VALUES (?)', ('synthetic',))
        return db.execute('SELECT app_id FROM app_events WHERE app_id=?', ('synthetic',)).fetchall()
"""
WRAPPER = """import sqlite3
from contextlib import contextmanager
@contextmanager
def connection(path):
    db=sqlite3.connect(path)
    try:
        yield db
    finally:
        db.close()
"""
YIELDED = (
    WRAPPER
    + """def run():
    with connection(':memory:') as db:
        db.execute('CREATE TABLE app_events(app_id TEXT)')
        db.execute('INSERT INTO app_events(app_id) VALUES (?)', ('synthetic',))
        return db.execute('SELECT app_id FROM app_events WHERE app_id=?', ('synthetic',)).fetchall()
"""
)


@pytest.mark.parametrize("source", [DIRECT, YIELDED])
def test_executable_sqlite_repro_is_complete_only_in_its_local_scope(source):
    namespace = {}
    exec(source, namespace)
    assert namespace["run"]() == [("synthetic",)]
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert result["tables"] == []
    assert [q["operation"] for q in result["queries"]] == ["insert", "select"]
    assert all("app_events" in q["scoped_tables"] for q in result["queries"])


def test_sqlite_pragma_and_first_comprehension_iterable_keep_receiver_scope():
    source = """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('BEGIN IMMEDIATE')
    columns = {row[1] for row in db.execute('PRAGMA table_info(things)')}
    db.execute('SELECT value FROM things')
"""
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert result["queries"][-1]["tables"] == ["things"]


def test_unrecognized_pragma_remains_incomplete():
    result = project("""import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('PRAGMA writable_schema=ON')
""")
    assert "python_executed_non_query_unsupported:main.py" in result["gaps"]


def test_nested_function_can_prove_its_own_connection():
    source = """import sqlite3
def outer():
    def inner():
        with sqlite3.connect(':memory:') as local:
            local.execute('CREATE TABLE things(value TEXT)')
            return local.execute('SELECT value FROM things').fetchall()
    return inner
"""
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert result["queries"][-1]["tables"] == ["things"]


def test_class_method_with_local_connection_has_its_queries_projected():
    source = """import sqlite3
class Reader:
    def read(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE things(value TEXT)')
            return db.execute('SELECT value FROM things').fetchall()
"""
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert result["queries"][-1]["tables"] == ["things"]


def test_witnessed_plain_field_context_keeps_unbound_context_explicit():
    store = """from pathlib import Path
from .provider import connection
class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.seed()
    def seed(self):
        with connection(self.path) as db:
            db.execute('SELECT 1')
"""
    sources = {
        "pkg/provider.py": WRAPPER.encode(),
        "pkg/store.py": store.encode(),
        "pkg/app.py": b"from .store import Store\ndef run():\n    Store(':memory:')\n",
    }
    result = _database_structure(sources, "sqlite", None)
    assert "python_execute_receiver_unproven:pkg/store.py" in result["gaps"]
    assert len(result["queries"]) == 1
    context = result["queries"][0]["source_context"]
    assert context["class_path"] == "pkg/store.py"
    assert context["callsite_path"] == "pkg/app.py"
    assert len(context["class_sha256"]) == len(context["callsite_sha256"]) == 64


def test_witnessed_context_rejects_descriptor_or_effectful_constructor_argument():
    store = """from pathlib import Path
from .provider import connection
class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.seed()
    def seed(self):
        with connection(self.path) as db:
            db.execute('SELECT 1')
"""
    for changed, call in [
        (
            store.replace(
                "    def seed(self):",
                "    @property\n    def path(self):\n        return ':memory:'\n    def seed(self):",
            ),
            "Store(':memory:')",
        ),
        (store, "Store(attacker.path)"),
    ]:
        sources = {
            "pkg/provider.py": WRAPPER.encode(),
            "pkg/store.py": changed.encode(),
            "pkg/app.py": (
                "from .store import Store\ndef run():\n    " + call + "\n"
            ).encode(),
        }
        result = _database_structure(sources, "sqlite", None)
        assert result["queries"] == []
        assert "python_execute_receiver_unproven:pkg/store.py" in result["gaps"]


@pytest.mark.parametrize(
    "tamper", ["args.database = attacker", "effect(args)", "Path = attacker"]
)
def test_argparse_witness_rejects_namespace_escape_and_path_rebinding(tamper):
    store = """from pathlib import Path
from .provider import connection
class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.seed()
    def seed(self):
        with connection(self.path) as db:
            db.execute('SELECT 1')
"""
    app = f"""import argparse
from pathlib import Path
from .store import Store
def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', type=Path)
    args = parser.parse_args()
    {tamper}
    Store(args.database)
"""
    result = _database_structure(
        {
            "pkg/provider.py": WRAPPER.encode(),
            "pkg/store.py": store.encode(),
            "pkg/app.py": app.encode(),
        },
        "sqlite",
        None,
    )
    assert result["queries"] == []
    assert "python_execute_receiver_unproven:pkg/store.py" in result["gaps"]


@pytest.mark.parametrize("call", ["fetch(db)", "fetch(db=db)"])
def test_source_bound_call_preserves_local_schema_and_unknown_public_context(call):
    source = f"""import sqlite3
def fetch(db):
    return db.execute('SELECT value FROM things').fetchone()
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    {call}
    db.execute('SELECT value FROM things')
"""
    result = project(source)
    assert "python_execute_receiver_unproven:main.py" in result["gaps"]
    contextual = [q for q in result["queries"] if "source_context" in q]
    assert len(contextual) == 1
    assert "things" in contextual[0]["scoped_tables"]
    assert "query_table_unresolved:things" not in result["gaps"]


def test_source_bound_calls_keep_two_private_schemas_separate():
    source = """import sqlite3
def fetch(db):
    return db.execute('SELECT value FROM things').fetchone()
with sqlite3.connect(':memory:') as first:
    first.execute('CREATE TABLE things(value TEXT)')
    with sqlite3.connect(':memory:') as second:
        fetch(first)
        fetch(second)
"""
    result = project(source)
    contextual = [q for q in result["queries"] if "source_context" in q]
    assert len(contextual) == 2
    assert sum("things" in q.get("scoped_tables", {}) for q in contextual) == 1
    assert "query_table_unresolved:things" in result["gaps"]


def test_rebound_formal_never_propagates_new_schema_to_caller():
    source = """import sqlite3
def change(db):
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE things(value TEXT)')
    db.execute('SELECT value FROM things')
with sqlite3.connect(':memory:') as original:
    change(original)
    original.execute('SELECT value FROM things')
"""
    result = project(source)
    assert "query_table_unresolved:things" in result["gaps"]
    caller_query = [q for q in result["queries"] if q["source"]["line"] == 8][0]
    assert "things" not in caller_query.get("scoped_tables", {})


def test_duplicate_actual_receiver_is_not_split_into_independent_resources():
    source = """import sqlite3
def pair(first, second):
    first.execute('SELECT 1')
    second.execute('SELECT 1')
with sqlite3.connect(':memory:') as db:
    pair(db, db)
"""
    result = project(source)
    assert "python_resource_alias_unresolved:main.py" in result["gaps"]
    assert result["status"] == "INCOMPLETE"


@pytest.mark.parametrize("effect", ["db.close()", "db.execute('DROP TABLE things')"])
def test_effectful_sibling_argument_never_transfers_stale_schema(effect):
    source = f"""import sqlite3
def fetch(db, ignored):
    return db.execute('SELECT value FROM things').fetchone()
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    fetch(db, {effect})
"""
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert not any("source_context" in query for query in result["queries"])
    assert "python_connection_escape_schema_unknown:main.py" in result["gaps"]


def test_captured_function_import_transfers_receiver_and_rejects_rebinding():
    sources = {
        "pkg/provider.py": b"def fetch(db):\n    return db.execute('SELECT value FROM things').fetchone()\n",
        "pkg/caller.py": b"""import sqlite3
def run():
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE things(value TEXT)')
        from .provider import fetch
        fetch(db)
""",
    }
    result = _database_structure(sources, "sqlite", None)
    context = [q for q in result["queries"] if "source_context" in q]
    assert len(context) == 1
    assert context[0]["source_context"]["source_path"] == "pkg/provider.py"
    assert "things" in context[0]["scoped_tables"]
    sources["pkg/caller.py"] += b"\nfetch = replacement\n"
    result = _database_structure(sources, "sqlite", None)
    assert not any("source_context" in q for q in result["queries"])


def server_field_project(
    *,
    work_extra="",
    work_before="",
    witness="Store(':memory:')",
    startup="",
    handler_prefix="",
):
    store = """from pathlib import Path
from .provider import connection
class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.seed()
    def seed(self):
        with connection(self.path) as db:
            db.execute('SELECT 1')
"""
    work = (
        f"""from .provider import connection
class Work:
    def __init__(self, store):
        self.store = store
    def start(self):
        {work_before or "pass"}
        with connection(self.store.path) as db:
            db.execute('SELECT 1')
"""
        + work_extra
    )
    server = f"""from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .store import Store
from .service import Service
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.work()
    def work(self):
        from .work import Work
        store = self.server.service.store
        {handler_prefix or "pass"}
        Work(store).start()
class Server(ThreadingHTTPServer):
    def __init__(self, address, store):
        super().__init__(address, Handler)
        self.service = Service(store)
        {startup or "pass"}
def run():
    Server(('127.0.0.1', 0), {witness})
"""
    sources = {
        "pkg/provider.py": WRAPPER.encode(),
        "pkg/store.py": store.encode(),
        "pkg/work.py": work.encode(),
        "pkg/service.py": b"class Service:\n    def __init__(self, store):\n        self.store = store\n",
        "pkg/server.py": server.encode(),
    }
    return _database_structure(sources, "sqlite", None)


def test_witnessed_http_plain_field_chain_projects_contextual_query():
    result = server_field_project()
    work = [
        q
        for q in result["queries"]
        if q.get("source_context", {}).get("class") == "Work"
    ]
    assert len(work) == 1
    assert work[0]["source_context"]["callsite_path"] == "pkg/server.py"
    assert "python_execute_receiver_unproven:pkg/work.py" in result["gaps"]


@pytest.mark.parametrize(
    "options",
    [
        {
            "work_extra": "    @property\n    def store(self):\n        return attacker\n"
        },
        {"witness": "Store(attacker.path)"},
        {"startup": "unknown(store)"},
        {"handler_prefix": "unknown(store)"},
        {"work_before": "self.store = attacker"},
        {"work_before": "self.__dict__['store'] = attacker"},
        {"work_before": "leak(self.store)"},
    ],
)
def test_http_field_chain_rejects_descriptor_effectful_witness_or_unknown_startup(
    options,
):
    result = server_field_project(**options)
    assert not any(
        q.get("source_context", {}).get("class") == "Work" for q in result["queries"]
    )
    assert "python_execute_receiver_unproven:pkg/work.py" in result["gaps"]


def test_forwarded_connection_cannot_reuse_external_schema_without_effect_proof():
    source = b"""import sqlite3
with sqlite3.connect('database.db') as db:
    guard(db)
    db.execute('SELECT value FROM things')
"""
    result = _database_structure(
        {"schema.sql": b"CREATE TABLE things(value TEXT)", "main.py": source},
        "sqlite",
        None,
        {"main.py": ast.parse(source)},
    )
    assert result["status"] == "INCOMPLETE"
    assert "query_table_unresolved:things" in result["gaps"]
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]


@pytest.mark.parametrize(
    "middle",
    [
        "[mutate(db) for _ in (0,)]",
        "class Local:\n        mutate(db)",
        "def helper():\n        db.executescript('DROP TABLE things')\n    helper()",
        "[db.executescript('DROP TABLE things') for _ in (0,)]",
        "leaked = [db for _ in (0,)]",
    ],
)
def test_nested_or_comprehension_escape_invalidates_prior_schema(middle):
    source = (
        "import sqlite3\nwith sqlite3.connect(':memory:') as db:\n"
        "    db.execute('CREATE TABLE things(value TEXT)')\n    "
        + middle
        + "\n    db.execute('SELECT value FROM things')\n"
    )
    result = project(source)
    assert result["status"] == "INCOMPLETE", result
    assert "query_table_unresolved:things" in result["gaps"]


def test_guarded_context_chain_proves_receiver_but_not_schema_effects():
    source = (
        WRAPPER.replace("def connection(path):", "def session(path):")
        + """
@contextmanager
def transaction(path, db):
    with db:
        guard(path, db)
        yield db
        guard(path, db)
@contextmanager
def connection(path):
    with session(path) as db:
        with transaction(path, db):
            yield db
def run():
    with connection('file.db') as db:
        db.execute('SELECT value FROM things')
"""
    )
    result = _database_structure(
        {"schema.sql": b"CREATE TABLE things(value TEXT)", "main.py": source.encode()},
        "sqlite",
        None,
        {"main.py": ast.parse(source)},
    )
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
    assert "python_guarded_schema_effect_unknown:main.py" in result["gaps"]
    assert "query_table_unresolved:things" in result["gaps"]


def test_cross_module_context_uses_captured_source_export_and_rejects_mutation():
    provider = WRAPPER.encode()
    consumer = b"""from .provider import connection
def run():
    with connection(':memory:') as db:
        db.execute('CREATE TABLE things(value TEXT)')
        db.execute('SELECT value FROM things')
"""
    sources = {"pkg/provider.py": provider, "pkg/consumer.py": consumer}
    result = _database_structure(sources, "sqlite", None)
    assert result["status"] == "COMPLETE", result["gaps"]
    sources["pkg/consumer.py"] += b"\nconnection.__code__ = replacement\n"
    result = _database_structure(sources, "sqlite", None)
    assert "python_execute_receiver_unproven:pkg/consumer.py" in result["gaps"]


def test_guarded_context_unknown_path_retains_receiver_without_claiming_schema():
    source = (
        WRAPPER.replace("def connection(path):", "def session(path):")
        + """
@contextmanager
def transaction(path, db):
    with db:
        guard(path, db)
        yield db
@contextmanager
def connection(path):
    with session(path) as db:
        with transaction(path, db):
            yield db
def run(path):
    with connection(path) as db:
        db.execute('SELECT 1')
"""
    )
    result = project(source)
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
    assert "python_guarded_schema_effect_unknown:main.py" in result["gaps"]
    assert result["queries"][0]["schema_unknown"] is True


def test_guarded_context_does_not_trust_effectful_outer_property():
    source = (
        WRAPPER.replace("def connection(path):", "def session(path):")
        + """
@contextmanager
def transaction(path, db):
    with db:
        guard(path, db)
        yield db
@contextmanager
def connection(path):
    with session(path) as db:
        with transaction(path, db):
            yield db
def run(store):
    with connection(store.path) as db:
        db.execute('SELECT 1')
"""
    )
    result = project(source)
    assert "python_execute_receiver_unproven:main.py" in result["gaps"]


@pytest.mark.parametrize("invocation", ["connection(path=':memory:')", "connection()"])
def test_guarded_context_keyword_and_default_keep_private_database(invocation):
    source = (
        WRAPPER.replace("def connection(path):", "def session(path):")
        + f"""
@contextmanager
def transaction(path, db):
    with db:
        guard(path, db)
        yield db
@contextmanager
def connection(path=':memory:'):
    with session(path) as db:
        with transaction(path, db):
            yield db
def run():
    with {invocation} as db:
        db.execute('SELECT value FROM things')
"""
    )
    result = _database_structure(
        {"schema.sql": b"CREATE TABLE things(value TEXT)", "main.py": source.encode()},
        "sqlite",
        None,
        {"main.py": ast.parse(source)},
    )
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
    assert "query_table_unresolved:things" in result["gaps"]
    assert result["queries"][0]["private_schema_only"] is True


@pytest.mark.parametrize("invocation", ["connection(path=':memory:')", "connection()"])
def test_context_private_memory_keyword_and_default_do_not_borrow_external_schema(
    invocation,
):
    source = (
        WRAPPER.replace("def connection(path):", "def connection(path=':memory:'):")
        + f"""
def run():
    with {invocation} as db:
        db.execute('SELECT value FROM things')
"""
    )
    result = _database_structure(
        {"schema.sql": b"CREATE TABLE things(value TEXT)", "main.py": source.encode()},
        "sqlite",
        None,
        {"main.py": ast.parse(source)},
    )
    assert "query_table_unresolved:things" in result["gaps"]
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]


def test_context_unknown_database_path_does_not_borrow_external_schema():
    source = (
        WRAPPER
        + """
def run(path):
    with connection(path) as db:
        db.execute('SELECT value FROM things')
"""
    )
    result = _database_structure(
        {"schema.sql": b"CREATE TABLE things(value TEXT)", "main.py": source.encode()},
        "sqlite",
        None,
        {"main.py": ast.parse(source)},
    )
    assert "query_table_unresolved:things" in result["gaps"]
    assert result["queries"][0]["schema_unknown"] is True


def test_contextmanager_can_initialize_known_sqlite_row_factory_and_pragma():
    source = (
        WRAPPER.replace(
            "    try:\n",
            "    db.row_factory=sqlite3.Row\n    db.execute('PRAGMA foreign_keys=ON')\n    try:\n",
        )
        + """def run():
    with connection(':memory:') as db:
        db.execute('CREATE TABLE things(value TEXT)')
        return db.execute('SELECT value FROM things').fetchall()
"""
    )
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]


def test_contextmanager_with_unknown_setup_cannot_prove_receiver():
    source = (
        WRAPPER.replace("    try:\n", "    configure(db)\n    try:\n")
        + """def run():
    with connection(':memory:') as db:
        db.execute('SELECT 1')
"""
    )
    result = project(source)
    assert "python_execute_receiver_unproven:main.py" in result["gaps"]


@pytest.mark.parametrize(
    "source",
    [
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('SELECT value FROM things')
    db.execute('CREATE TABLE things(value TEXT)')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    if flag:
        db.execute('CREATE TABLE things(value TEXT)')
    db.execute('SELECT value FROM things')
""",
        """import sqlite3
def create():
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE things(value TEXT)')
def read():
    with sqlite3.connect(':memory:') as db:
        db.execute('SELECT value FROM things')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as first:
    first.execute('CREATE TABLE things(value TEXT)')
    with sqlite3.connect(':memory:') as second:
        second.execute('SELECT value FROM things')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    db=sqlite3.connect(':memory:')
    db.execute('SELECT value FROM things')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE IF NOT EXISTS things(value TEXT)')
    db.execute('SELECT value FROM things')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    db.rollback()
    db.execute('SELECT value FROM things')
""",
        """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    db.execute(dynamic_sql)
    db.execute('SELECT value FROM things')
""",
    ],
)
def test_unrelated_or_conditional_schema_never_proves_query(source):
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert "query_table_unresolved:things" in result["gaps"]


@pytest.mark.parametrize(
    "source",
    [
        WRAPPER
        + "connection = other\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER.replace("@contextmanager", "@untrusted")
        + "with connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER.replace("        yield db", "        yield other")
        + "with connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER.replace("        yield db", "        leak(db)\n        yield db")
        + "with connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER.replace("        yield db", "        db = other\n        yield db")
        + "with connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER.replace(
            "db=sqlite3.connect(path)", "db=sqlite3.connect(path, factory=custom)"
        )
        + "with connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER
        + "sqlite3.connect = other\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER
        + "connection.__code__ = other\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER
        + "sqlite3.__dict__['connect'] = other\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER
        + "module_alias = sqlite3\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        "import sqlite3\nexec('sqlite3.connect = other')\nwith sqlite3.connect(':memory:') as db:\n    db.execute('SELECT 1')\n",
        WRAPPER
        + "vars()['connection'] = other\nwith connection(':memory:') as db:\n    db.execute('SELECT 1')\n",
        "import sqlite3, sys\nsys.modules['sqlite3'].connect = other\nwith sqlite3.connect(':memory:') as db:\n    db.execute('SELECT 1')\n",
        "import sqlite3\nwith sqlite3.connect(':memory:', factory=custom) as db:\n    db.execute('SELECT 1')\n",
        "import sqlite3 as s\ns.connect=other\nfrom sqlite3 import connect\nwith connect(':memory:') as db:\n    db.execute('SELECT 1')\n",
    ],
)
def test_unknown_or_shadowed_factories_remain_unproven(source):
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert "python_execute_receiver_unproven:main.py" in result["gaps"]


def test_closed_connection_table_free_query_remains_unproven():
    result = project("""import sqlite3
with sqlite3.connect(':memory:') as db:
    db.close()
    db.execute('SELECT 1')
""")
    assert result["status"] == "INCOMPLETE"
    assert "python_execute_receiver_unproven:main.py" in result["gaps"]


@pytest.mark.parametrize(
    "middle",
    [
        "leak(db)",
        "alias=db",
        "leak([db])",
        "alias={'x': db}",
        "leak(db.execute)",
        "leak(db.cursor())",
    ],
)
def test_forwarded_connection_keeps_identity_but_loses_schema(middle):
    source = (
        "import sqlite3\nwith sqlite3.connect(':memory:') as db:\n    db.execute('CREATE TABLE things(value TEXT)')\n    "
        + middle
        + "\n    db.execute('SELECT value FROM things')\n"
    )
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
    assert "query_table_unresolved:things" in result["gaps"]


@pytest.mark.parametrize(
    "middle", ["db.close()", "db.executescript('DROP TABLE things')"]
)
def test_closed_or_unsupported_connection_never_inherits_stale_schema(middle):
    source = (
        "import sqlite3\nwith sqlite3.connect(':memory:') as db:\n    db.execute('CREATE TABLE things(value TEXT)')\n    "
        + middle
        + "\n    db.execute('SELECT value FROM things')\n"
    )
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    if middle == "db.close()":
        assert "python_execute_receiver_unproven:main.py" in result["gaps"]
    else:
        assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
        assert "python_connection_method_unsupported:main.py" in result["gaps"]
        assert "query_table_unresolved:things" in result["gaps"]


@pytest.mark.parametrize(
    "prefix",
    [
        "import sqlite3\nwith sqlite3.connect(':memory:') as db:\n",
        WRAPPER + "with connection(':memory:') as db:\n",
    ],
)
def test_external_schema_never_proves_fresh_private_memory_connection(prefix):
    source = (
        prefix
        + "    db.execute('SELECT value FROM things')\n    db.execute('CREATE TABLE things(value TEXT)')\n"
    )
    sources = {
        "main.py": source.encode(),
        "schema.sql": b"CREATE TABLE things(value TEXT)",
    }
    result = _database_structure(
        sources, "sqlite", None, {"main.py": ast.parse(source)}
    )
    assert result["status"] == "INCOMPLETE"
    assert "query_table_unresolved:things" in result["gaps"]


def test_conditional_schema_mutation_does_not_survive_join():
    source = """import sqlite3
with sqlite3.connect(':memory:') as db:
    db.execute('CREATE TABLE things(value TEXT)')
    if flag:
        db.execute('DROP TABLE things')
    db.execute('SELECT value FROM things')
"""
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert "query_table_unresolved:things" in result["gaps"]


def test_escaped_receiver_cannot_reacquire_schema_without_fresh_connection():
    source = """import sqlite3
with sqlite3.connect(':memory:') as db:
    guard(db)
    db.execute('CREATE TABLE things(value TEXT)')
    db.execute('SELECT value FROM things')
"""
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert "python_execute_receiver_unproven:main.py" not in result["gaps"]
    assert "python_connection_escaped_schema_unproven:main.py" in result["gaps"]
    assert "query_table_unresolved:things" in result["gaps"]
