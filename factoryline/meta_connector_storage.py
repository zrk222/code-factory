"""Small transaction adapter for the Meta connector's SQLite and PostgreSQL stores.

PostgreSQL is used on stateless hosts. The adapter keeps the existing bounded
SQL resource independent of a larger ORM and never logs connection strings.
"""

from __future__ import annotations

import sqlite3
from typing import Any


class StorageUnavailable(Exception):
    """A database connection or query failed without exposing provider details."""


class PostgresConnection:
    """Expose the subset of sqlite3.Connection used by the connector."""

    def __init__(self, dsn: str):
        try:
            import psycopg

            self._driver = psycopg
            self._connection = psycopg.connect(dsn, connect_timeout=5)
        except Exception:
            raise StorageUnavailable("audit storage is unavailable") from None

    def __enter__(self) -> PostgresConnection:
        return self

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        try:
            if kind is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        except self._driver.Error:
            raise StorageUnavailable("audit storage is unavailable") from None
        finally:
            self._connection.close()

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        if statement == "BEGIN IMMEDIATE":
            # Psycopg starts a transaction on the first statement. Caller-owned
            # account rows are locked with SELECT ... FOR UPDATE below.
            return None
        try:
            return self._connection.execute(statement.replace("?", "%s"), parameters)
        except self._driver.Error:
            raise StorageUnavailable("audit storage is unavailable") from None


def connect(database: str) -> sqlite3.Connection | PostgresConnection:
    """Select durable PostgreSQL by DSN; retain SQLite for local workflows."""
    if database.startswith(("postgresql://", "postgres://")):
        return PostgresConnection(database)
    return sqlite3.connect(database, timeout=5)


def is_postgres(database: str) -> bool:
    return database.startswith(("postgresql://", "postgres://"))
