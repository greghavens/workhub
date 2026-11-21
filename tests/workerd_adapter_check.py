"""Adapter scenarios executed inside a real Durable Object by tests/test_workerd.py.

Copied into the test Worker only; it is never part of a deployed bundle.
"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError

from workhub.db import Database
from workhub.durable import UNDO, OperationalError, WorkersStorage
from workhub.models import Audit, Contributor, Repository, Source, SourceRepository


def snapshot(db):
    with db.read() as session:
        return {
            "contributors": sorted(
                (c.id, c.name, c.active, c.github_id, c.github_login)
                for c in session.scalars(select(Contributor))
            ),
            "sources": sorted(
                (s.id, s.exclude, s.approver_ids) for s in session.scalars(select(Source))
            ),
            "links": sorted(
                (link.source_id, link.repository_id)
                for link in session.scalars(select(SourceRepository))
            ),
            "audit": sorted((a.id, a.action, a.detail) for a in session.scalars(select(Audit))),
        }


def seed(db):
    with db.write() as session:
        session.add(Contributor(id="c1", name="bob", token_hash="h1", active=True, github_id=2))
        session.add(
            Source(
                id="s1",
                name="alice",
                github_id=1,
                github_login="alice",
                github_token="t",
                approver_ids=[1],
                exclude=[],
            )
        )
        session.flush()
        session.add(
            Repository(id=100, full_name="alice/widget", authority_source_id="s1", private=False)
        )
        session.flush()
        session.add(SourceRepository(source_id="s1", repository_id=100))
        session.add(Audit(timestamp=1, actor="admin", action="seeded", detail={"k": "it's"}))


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def scenarios(db):
    yield "seed"
    seed(db)
    before = snapshot(db)

    yield "rollback restores inserts, updates, deletes, NULLs, and quoting"
    try:
        with db.write() as session:
            user = session.get(Contributor, "c1")
            user.active, user.name, user.github_login = False, "o'brien", None
            session.get(Source, "s1").exclude = ["secret/*"]
            session.delete(session.get(SourceRepository, ("s1", 100)))
            session.add(Contributor(id="c2", name="carol", token_hash="h2", active=True))
            session.add(Audit(timestamp=2, actor="admin", action="discarded", detail={}))
            session.flush()
            raise RuntimeError("abort")
    except RuntimeError:
        pass
    expect(snapshot(db) == before, "state changed after rollback")

    yield "constraint violation maps to IntegrityError and rolls back"
    try:
        with db.write() as session:
            session.get(Contributor, "c1").name = "changed first"
            session.flush()
            session.add(Contributor(id="c3", name="dup", token_hash="h1", active=True))
        raise AssertionError("duplicate token_hash was accepted")
    except IntegrityError:
        pass
    expect(snapshot(db) == before, "state changed after constraint rollback")

    yield "commit persists and clears the undo log"
    with db.write() as session:
        session.get(Contributor, "c1").active = False
    with db.read() as session:
        expect(session.get(Contributor, "c1").active is False, "boolean did not persist")
        count = session.connection().exec_driver_sql(f'SELECT count(*) FROM "{UNDO}"').scalar()
        expect(count == 0, "undo log not cleared")

    yield "values round-trip and oversized integers are rejected"
    with db.read() as session:
        expect(session.get(Source, "s1").approver_ids == [1], "JSON did not round-trip")
        expect(session.get(Contributor, "c1").github_id == 2, "integer did not round-trip")
    try:
        with db.write() as session:
            session.get(Contributor, "c1").github_id = 2**60
        raise AssertionError("oversized integer accepted")
    except StatementError:
        pass

    yield "writes cannot nest"
    try:
        with db.write(), db.write():
            pass
        raise AssertionError("nested write accepted")
    except OperationalError:
        pass


def run(sql):
    results, current = {}, None
    db = Database(storage=WorkersStorage(sql))
    try:
        for name in scenarios(db):
            if current:
                results[current] = "ok"
            current = name
        results[current] = "ok"
    except Exception as exc:  # noqa: BLE001 - reported to the test
        results[current] = f"FAIL: {type(exc).__name__}: {exc}"
    return results
