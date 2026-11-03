"""SQLite call evidence follows Python's callee/argument/call evaluation order."""

import ast
import sqlite3

import pytest

from factoryline.intent_quality import _database_structure


def project(source):
    return _database_structure(
        {"main.py": source.encode()}, "sqlite", None, {"main.py": ast.parse(source)}
    )


def source_with(argument):
    return (
        "import sqlite3\n"
        "with sqlite3.connect(':memory:') as db:\n"
        "    db.execute('CREATE TABLE things(value TEXT)')\n"
        f"    db.execute('SELECT value FROM things WHERE 1 = ?', ({argument},))\n"
    )


def test_pure_parameters_keep_valid_query_and_scoped_schema():
    source = source_with("1")
    exec(source, {})
    result = project(source)
    assert result["status"] == "COMPLETE", result["gaps"]
    assert len(result["queries"]) == 1
    assert "things" in result["queries"][0]["scoped_tables"]


@pytest.mark.parametrize(
    "argument,error",
    [
        ("db.close()", sqlite3.ProgrammingError),
        ("db.execute('DROP TABLE things')", sqlite3.OperationalError),
        ("db.executescript('DROP TABLE things;')", sqlite3.OperationalError),
    ],
)
def test_effectful_argument_cannot_leave_stale_outer_query(argument, error):
    source = source_with(argument)
    with pytest.raises(error):
        exec(source, {})
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert not [query for query in result["queries"] if query["source"]["line"] == 4]


def test_nested_calls_are_observed_once_in_execution_order():
    result = project(source_with("db.execute('SELECT 2')"))
    assert result["status"] == "INCOMPLETE"
    assert len(result["queries"]) == 1
    assert result["queries"][0]["tables"] == []
    assert "python_execute_argument_effect_unproven:main.py" in result["gaps"]


def test_unknown_argument_callback_does_not_preserve_prior_schema():
    source = (
        "import sqlite3\n"
        "def mutate():\n    db.execute('DROP TABLE things')\n    return 1\n"
        "with sqlite3.connect(':memory:') as db:\n"
        "    db.execute('CREATE TABLE things(value TEXT)')\n"
        "    db.execute('SELECT value FROM things WHERE 1 = ?', (mutate(),))\n"
    )
    with pytest.raises(sqlite3.OperationalError):
        exec(source, {})
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert not any(query["operation"] == "select" for query in result["queries"])


def test_rebound_receiver_is_not_replaced_with_post_argument_connection():
    source = (
        "import sqlite3\n"
        "with sqlite3.connect(':memory:') as first, sqlite3.connect(':memory:') as second:\n"
        "    first.execute('CREATE TABLE things(value TEXT)')\n"
        "    second.execute('CREATE TABLE different(value TEXT)')\n"
        "    first.execute('SELECT value FROM things WHERE 1 = ?', ((first := second, 1)[1],))\n"
    )
    # Python captured first.execute before the argument rebound first to second.
    exec(source, {})
    result = project(source)
    assert result["status"] == "INCOMPLETE"
    assert not any(query["operation"] == "select" for query in result["queries"])
    assert "python_execute_target_changed_during_arguments:main.py" in result["gaps"]
