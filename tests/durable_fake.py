"""A sqlite3-backed stand-in for Durable Object SQL storage, with its observed restrictions."""

import re
import sqlite3
import threading

TRANSACTION = re.compile(r"^\s*(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b", re.IGNORECASE)
UNAUTHORIZED_PRAGMAS = {"journal_mode", "read_uncommitted", "synchronous"}


class FakeDurableStorage:
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        # Durable Objects do not flush every autocommitted statement; neither does the stand-in.
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA journal_mode=MEMORY")
        self.db.set_authorizer(self.authorize)
        self.lock = threading.Lock()
        self.statements = []

    def authorize(self, action, arg1, arg2, database, _source):
        if action == sqlite3.SQLITE_FUNCTION and arg2 == "sqlite_version":
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and (arg1 in UNAUTHORIZED_PRAGMAS or database == "temp"):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def exec(self, query, params):
        if TRANSACTION.match(query):
            raise RuntimeError(
                "Error: To execute a transaction, please use the state.storage.transaction() "
                "or state.storage.transactionSync() APIs: SQLITE_ERROR"
            )
        bound = []
        for value in params:
            if isinstance(value, bool):
                value = "true" if value else "false"  # What Durable Objects store for booleans.
            if isinstance(value, int) and abs(value) > 2**53 - 1:
                raise TypeError("Cannot convert a BigInt value to a number")
            bound.append(value)
        with self.lock:
            self.statements.append(query)
            try:
                cursor = self.db.execute(query, bound)
            except sqlite3.Error as exc:
                raise RuntimeError(f"Error: {exc}: SQLITE_ERROR") from exc
            columns = [d[0] for d in cursor.description or []]
            return columns, cursor.fetchall()
