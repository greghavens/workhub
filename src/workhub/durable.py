"""SQLAlchemy over Cloudflare Durable Object SQLite storage.

A Durable Object's SQL API is synchronous and every request to the object is serialized, which
matches the hub's short write transactions. SQL `BEGIN` and `SAVEPOINT` are forbidden there, so
rollback is provided by an undo log that triggers maintain (https://www.sqlite.org/undoredo.html):
`Database.write()` clears the log on entry, discards it on commit, and replays it newest-first on
rollback. Durability comes from the Durable Object itself: writes made without an intervening
`await` commit atomically, and write blocks perform no network I/O.
"""

import sys
import threading

from sqlalchemy import create_engine
from sqlalchemy.dialects import registry
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy.pool import StaticPool

# DB-API 2.0 module attributes used by SQLAlchemy.
apilevel = "2.0"
threadsafety = 1
paramstyle = "qmark"
sqlite_version_info = (3, 45, 0)
sqlite_version = "3.45.0"
UNDO = "_workhub_undo"
SAFE_INTEGER = 2**53 - 1  # Durable Object bindings pass JavaScript numbers.


class Warning(Exception):  # noqa: A001 - DB-API name
    pass


class Error(Exception):
    pass


class InterfaceError(Error):
    pass


class DatabaseError(Error):
    pass


class DataError(DatabaseError):
    pass


class OperationalError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class InternalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    pass


def prepare(value):
    """Normalize a bound parameter to what Durable Object SQL stores faithfully."""
    if isinstance(value, bool):
        return int(value)  # A JavaScript boolean would be stored as the text "true".
    if isinstance(value, int) and abs(value) > SAFE_INTEGER:
        raise DataError("Integer exceeds the 53-bit range of Durable Object SQL bindings")
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return value


def translate(exc):
    message = str(exc)
    if "constraint failed" in message or "SQLITE_CONSTRAINT" in message:
        return IntegrityError(message)
    return OperationalError(message)


class WorkersStorage:
    """Adapts `ctx.storage.sql` inside a Python Worker to (columns, rows) results."""

    def __init__(self, sql):
        from pyodide.ffi import JsProxy, jsnull, to_js

        self.sql, self.JsProxy, self.jsnull, self.to_js = sql, JsProxy, jsnull, to_js

    def encode(self, value):
        if value is None:
            return self.jsnull
        if isinstance(value, bytes):
            return self.to_js(value)
        return value

    def decode(self, value):
        if value is None or value is self.jsnull:
            return None
        if isinstance(value, self.JsProxy):
            if value.typeof == "undefined":
                return None
            return bytes(value.to_bytes())
        return value

    def exec(self, query, params):
        cursor = self.sql.exec(query, *[self.encode(value) for value in params])
        columns = [str(name) for name in cursor.columnNames]
        rows = [tuple(self.decode(value) for value in row) for row in cursor.raw()]
        return columns, rows


class Cursor:
    arraysize = 1

    def __init__(self, connection):
        self.connection = connection
        self.description = None
        self.rowcount = -1
        self.lastrowid = None
        self.rows = []

    def execute(self, operation, parameters=()):
        columns, rows = self.connection.run(operation, parameters or ())
        self.description = tuple((c, None, None, None, None, None, None) for c in columns) or None
        self.rows = list(rows)
        verb = operation.lstrip().split(None, 1)[0].upper() if operation.strip() else ""
        if verb in {"INSERT", "UPDATE", "DELETE", "REPLACE"}:
            _, [(changes, rowid)] = self.connection.run("SELECT changes(), last_insert_rowid()", ())
            self.rowcount, self.lastrowid = changes, rowid
        else:
            self.rowcount = -1
        return self

    def executemany(self, operation, sequence):
        total = 0
        for parameters in sequence:
            self.execute(operation, parameters)
            total += max(self.rowcount, 0)
        self.rowcount = total
        return self

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchmany(self, size=None):
        size = size or self.arraysize
        result, self.rows = self.rows[:size], self.rows[size:]
        return result

    def fetchall(self):
        result, self.rows = self.rows, []
        return result

    def __iter__(self):
        while self.rows:
            yield self.rows.pop(0)

    def setinputsizes(self, *_):
        pass

    def setoutputsize(self, *_):
        pass

    def close(self):
        self.rows = []


class Connection:
    def __init__(self, storage):
        self.storage = storage
        # A Durable Object serializes requests on one thread; the lock gives the same
        # guarantee when the adapter is exercised from a threaded test server.
        self.lock, self.owner = threading.Lock(), None

    def run(self, query, params):
        try:
            return self.storage.exec(query, tuple(prepare(value) for value in params))
        except Error:
            raise
        except Exception as exc:
            raise translate(exc) from exc

    def cursor(self):
        return Cursor(self)

    # Statement-level autocommit: transactions are scoped by begin_write/end_write.
    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

    def tables(self):
        _, rows = self.run(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
            "AND name NOT LIKE '_cf_%' AND name != ?",
            (UNDO,),
        )
        return [row[0] for row in rows]

    def install_undo(self):
        """(Re)create undo triggers for every hub table, covering its current columns."""
        self.run(f'CREATE TABLE IF NOT EXISTS "{UNDO}" (seq INTEGER PRIMARY KEY, stmt TEXT)', ())
        for table in self.tables():
            _, info = self.run(f'PRAGMA table_info("{table}")', ())
            columns = [row[1] for row in info]
            names = ",".join(f'"{c}"' for c in columns)
            restore = "||','||".join(f'quote(old."{c}")' for c in columns)
            assign = "||','||".join(f'\'"{c}"=\'||quote(old."{c}")' for c in columns)
            triggers = {
                "i": (
                    "AFTER INSERT",
                    f"'DELETE FROM \"{table}\" WHERE rowid='||new.rowid",
                ),
                "u": (
                    "AFTER UPDATE",
                    f"'UPDATE \"{table}\" SET rowid='||old.rowid||','||{assign}"
                    "||' WHERE rowid='||new.rowid",
                ),
                "d": (
                    "BEFORE DELETE",
                    f"'INSERT INTO \"{table}\"(rowid,{names}) VALUES('||old.rowid||','||{restore}||')'",
                ),
            }
            for suffix, (timing, statement) in triggers.items():
                name = f"{UNDO}_{table}_{suffix}"
                self.run(f'DROP TRIGGER IF EXISTS "{name}"', ())
                self.run(
                    f'CREATE TRIGGER "{name}" {timing} ON "{table}" BEGIN '
                    f'INSERT INTO "{UNDO}"(stmt) VALUES({statement}); END',
                    (),
                )

    def begin_write(self):
        if self.owner == threading.get_ident():
            # A nested write, or one interleaved by I/O inside a write block, would corrupt
            # the undo log. Durable Object requests otherwise cannot interleave here.
            raise OperationalError("Write transactions cannot nest or interleave")
        self.lock.acquire()
        self.owner = threading.get_ident()
        try:
            self.run(f'DELETE FROM "{UNDO}"', ())
        except BaseException:
            self.owner = None
            self.lock.release()
            raise

    def end_write(self, commit):
        try:
            if not commit:
                _, entries = self.run(f'SELECT stmt FROM "{UNDO}" ORDER BY seq DESC', ())
                for (statement,) in entries:
                    self.run(statement, ())
            self.run(f'DELETE FROM "{UNDO}"', ())
        finally:
            self.owner = None
            self.lock.release()


class DurableDialect(SQLiteDialect_pysqlite):
    driver = "durable"
    supports_statement_cache = True

    @classmethod
    def import_dbapi(cls):
        return sys.modules[__name__]

    def create_connect_args(self, url):
        return [], {}

    def on_connect(self):
        return None

    def get_isolation_level(self, dbapi_connection):
        return "SERIALIZABLE"

    def set_isolation_level(self, dbapi_connection, level):
        pass

    def _get_server_version_info(self, connection):
        return sqlite_version_info

    def has_table(self, connection, table_name, schema=None, **kw):
        # The SQLite dialect also probes the temp schema, which Durable Objects forbid.
        return (
            connection.exec_driver_sql(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)
            ).first()
            is not None
        )


registry.register("sqlite.durable", __name__, "DurableDialect")


def durable_engine(storage):
    connection = Connection(storage)
    engine = create_engine(
        "sqlite+durable://",
        creator=lambda: connection,
        poolclass=StaticPool,
        pool_reset_on_return=None,
    )
    return engine, connection
