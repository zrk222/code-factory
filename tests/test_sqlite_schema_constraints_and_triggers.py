import hashlib
import inspect
import sqlite3

import pytest

from factoryline.intent_quality import database_structure


def graph(sql):
    return database_structure({"schema.sql": sql.encode()}, "sqlite")


def test_bare_constraints_checks_and_autoincrement_are_retained():
    sql = (
        "CREATE TABLE parent(id INTEGER PRIMARY KEY AUTOINCREMENT); "
        "CREATE TABLE child(id INTEGER, parent_id INTEGER CHECK(parent_id > 0), "
        "PRIMARY KEY(id), FOREIGN KEY(parent_id) REFERENCES parent(id), UNIQUE(parent_id));"
    )
    result = graph(sql)
    assert result["status"] == "COMPLETE", result["gaps"]
    tables = {t["name"]: t for t in result["tables"]}
    assert tables["parent"]["columns"][0]["autoincrement"] is True
    child = tables["child"]
    assert child["primary_key"] == ["id"]
    assert child["unique"] == [["parent_id"]]
    assert child["foreign_keys"] == [
        {"columns": ["parent_id"], "target_table": "parent", "target_columns": ["id"]}
    ]
    check = next(c for c in child["columns"] if c["name"] == "parent_id")["checks"][0]
    assert check["columns"] == ["parent_id"] and check["expression_sha256"]


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE t(id INTEGER, PRIMARY KEY(missing));",
        "CREATE TABLE t(id INTEGER PRIMARY KEY, PRIMARY KEY(id));",
        "CREATE TABLE t(id INTEGER, UNIQUE(missing));",
        "CREATE TABLE p(id INTEGER); CREATE TABLE t(id INTEGER, FOREIGN KEY(missing) REFERENCES p(id));",
        "CREATE TABLE p(id INTEGER); CREATE TABLE t(id INTEGER REFERENCES p(id) ON DELETE CASCADE);",
        "CREATE TABLE p(id INTEGER); CREATE TABLE t(id INTEGER, FOREIGN KEY(id) REFERENCES p(id) ON UPDATE CASCADE);",
        "CREATE TABLE t(id INTEGER CHECK(missing > 0));",
        "CREATE TABLE t(id INT PRIMARY KEY AUTOINCREMENT);",
        "CREATE TABLE t(id INTEGER UNSIGNED PRIMARY KEY AUTOINCREMENT);",
        "CREATE TABLE t(id INTEGER(8) PRIMARY KEY AUTOINCREMENT);",
        "CREATE TABLE t(id INTEGER AUTOINCREMENT);",
        "CREATE TABLE t(id INTEGER PRIMARY KEY DESC AUTOINCREMENT);",
        "CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT) WITHOUT ROWID;",
    ],
)
def test_invalid_constraints_are_incomplete(sql):
    assert graph(sql)["status"] != "COMPLETE"


@pytest.mark.parametrize(
    "type_name", ["INTEGER", "integer", '"INTEGER"', "[INTEGER]", "`INTEGER`"]
)
def test_exact_sqlite_integer_type_accepts_sqlite_identifier_quoting(type_name):
    result = graph(f"CREATE TABLE t(id {type_name} PRIMARY KEY AUTOINCREMENT);")
    assert result["status"] == "COMPLETE", result["gaps"]


def test_trigger_preserves_predicate_and_quoted_statement_boundaries():
    sql = (
        "CREATE TABLE t(id INTEGER, label TEXT); "
        "CREATE TRIGGER prevent BEFORE INSERT ON t WHEN EXISTS "
        "(SELECT 1 FROM t WHERE rowid = NEW.rowid OR id = NEW.id) "
        "BEGIN SELECT RAISE(ABORT, 'private; END'); END; "
        "CREATE TABLE after_it(id INTEGER);"
    )
    result = graph(sql)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert {t["name"] for t in result["tables"]} == {"t", "after_it"}
    trigger = next(o for o in result["operations"] if o["op"] == "create_trigger")
    assert (trigger["name"], trigger["table"], trigger["timing"], trigger["event"]) == (
        "prevent",
        "t",
        "BEFORE",
        "INSERT",
    )
    assert trigger["predicate"]["kind"] == "EXISTS"
    assert trigger["predicate"]["expression"]["op"] == "OR"
    assert trigger["source"]["sha256"] == hashlib.sha256(sql.encode()).hexdigest()
    assert "private; END" not in repr(result)


@pytest.mark.parametrize(
    "trigger",
    [
        "CREATE TRIGGER x BEFORE INSERT ON missing BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t WHEN EXISTS(SELECT 1 FROM t WHERE id = OLD.id) BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE DELETE ON t WHEN EXISTS(SELECT 1 FROM t WHERE id = NEW.id) BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t WHEN EXISTS(SELECT 1 FROM t WHERE id = NEW.missing) BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t BEGIN DELETE FROM t; SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TRIGGER x 'BEFORE' INSERT ON t BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t BEGIN SELECT RAISE('ABORT', 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t WHEN EXISTS(SELECT 1 FROM t WHERE id = x.NEW.id) BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x AFTER INSERT ON t BEGIN SELECT RAISE(ABORT, 'x'); END;",
        "CREATE TRIGGER x BEFORE INSERT ON t BEGIN SELECT RAISE(ABORT, 'x'); END",
    ],
)
def test_unsupported_triggers_are_incomplete(trigger):
    assert graph("CREATE TABLE t(id INTEGER); " + trigger)["status"] != "COMPLETE"


def test_trigger_comments_and_duplicate_names():
    trigger = (
        "CREATE TRIGGER x BEFORE INSERT ON t BEGIN SELECT RAISE(ABORT, 'x; END'); END;"
    )
    assert (
        graph("CREATE TABLE t(id INTEGER); -- END;\n" + trigger)["status"] == "COMPLETE"
    )
    assert (
        graph("CREATE TABLE t(id INTEGER); " + trigger + trigger)["status"]
        != "COMPLETE"
    )


def test_index_columns_must_exist_and_be_simple():
    valid = 'CREATE TABLE t("id" INTEGER); CREATE INDEX ix ON t("id" DESC);'
    invalid = "CREATE TABLE t(id INTEGER); CREATE INDEX ix ON t(missing);"
    with sqlite3.connect(":memory:") as conn:
        conn.executescript(valid)
    with (
        sqlite3.connect(":memory:") as conn,
        pytest.raises(sqlite3.OperationalError, match="no such column"),
    ):
        conn.executescript(invalid)
    assert graph(valid)["status"] == "COMPLETE"
    assert graph(invalid)["status"] != "COMPLETE"
    assert (
        graph("CREATE TABLE t(id INTEGER); CREATE INDEX ix ON t(lower(id));")["status"]
        != "COMPLETE"
    )


def test_partial_index_distinguishes_keys_from_predicate_using_native_sqlite():
    sql = (
        "CREATE TABLE sequence_jobs(job_id TEXT, owned INTEGER); "
        "CREATE UNIQUE INDEX sequence_job_owner ON sequence_jobs(job_id) WHERE owned = 1;"
    )
    with sqlite3.connect(":memory:") as conn:
        conn.executescript(sql)
        native_keys = [
            row[2] for row in conn.execute("PRAGMA index_info(sequence_job_owner)")
        ]
    result = graph(sql)
    assert result["status"] == "COMPLETE", result["gaps"]
    index = result["tables"][0]["indexes"][0]
    assert native_keys == index["columns"] == ["job_id"]
    assert index["partial"] is True and len(index["predicate_sha256"]) == 64
    assert "owned" not in index["columns"]


def test_partial_index_with_unresolved_predicate_is_incomplete():
    sql = "CREATE TABLE t(id INTEGER); CREATE INDEX idx ON t(id) WHERE missing = 1;"
    with (
        sqlite3.connect(":memory:") as conn,
        pytest.raises(sqlite3.OperationalError, match="no such column"),
    ):
        conn.executescript(sql)
    assert graph(sql)["status"] != "COMPLETE"


@pytest.mark.parametrize("name", ["_bind_source_call", "_source_call_signature"])
def test_database_cache_identity_tracks_transitive_source_binder(monkeypatch, name):
    import factoryline
    from factoryline.intent_quality import _db_code_identity

    before = _db_code_identity(inspect, hashlib.sha256)
    monkeypatch.setattr(factoryline, name, test_index_columns_must_exist_and_be_simple)
    assert _db_code_identity(inspect, hashlib.sha256) != before
