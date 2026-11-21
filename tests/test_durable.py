"""The Durable Object SQLite adapter: rollback without SQL transactions, and value fidelity."""

import pytest
from durable_fake import FakeDurableStorage
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError

from workhub.db import Database
from workhub.durable import UNDO, OperationalError
from workhub.models import Audit, Contributor, Repository, Source, SourceRepository


@pytest.fixture
def db(tmp_path):
    database = Database(storage=FakeDurableStorage(str(tmp_path / "durable.sqlite")))
    yield database
    database.engine.dispose()


def snapshot(db):
    with db.read() as session:
        return {
            "contributors": sorted(
                (c.id, c.name, c.active, c.github_id) for c in session.scalars(select(Contributor))
            ),
            "sources": sorted((s.id, s.name, s.exclude) for s in session.scalars(select(Source))),
            "links": sorted(
                (link.source_id, link.repository_id)
                for link in session.scalars(select(SourceRepository))
            ),
            "audit": sorted((a.id, a.action) for a in session.scalars(select(Audit))),
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
        session.add(Audit(timestamp=1, actor="admin", action="seeded", detail={}))


def test_failed_write_restores_inserts_updates_and_deletes(db):
    seed(db)
    before = snapshot(db)
    with pytest.raises(RuntimeError, match="abort"), db.write() as session:
        user = session.get(Contributor, "c1")
        user.active, user.name = False, "renamed"
        session.get(Source, "s1").exclude = ["secret/*"]
        session.delete(session.get(SourceRepository, ("s1", 100)))
        session.add(Contributor(id="c2", name="carol", token_hash="h2", active=True))
        session.add(Audit(timestamp=2, actor="admin", action="discarded", detail={}))
        session.flush()  # The statements reach storage before the failure.
        raise RuntimeError("abort")
    assert snapshot(db) == before
    with db.read() as session:
        assert session.get(Contributor, "c1").active is True


def test_constraint_violation_rolls_back_earlier_statements(db):
    seed(db)
    before = snapshot(db)
    with pytest.raises(IntegrityError), db.write() as session:
        session.get(Contributor, "c1").name = "changed first"
        session.flush()
        session.add(Contributor(id="c3", name="dup", token_hash="h1", active=True))  # unique
    assert snapshot(db) == before


def test_committed_write_persists_and_clears_undo_log(db):
    seed(db)
    with db.write() as session:
        session.get(Contributor, "c1").active = False
    with db.read() as session:
        assert session.get(Contributor, "c1").active is False
        assert session.connection().exec_driver_sql(f'SELECT count(*) FROM "{UNDO}"').scalar() == 0
    # A later failure must not replay the earlier committed change.
    with pytest.raises(RuntimeError), db.write() as session:
        session.get(Contributor, "c1").name = "temporary"
        session.flush()
        raise RuntimeError
    with db.read() as session:
        user = session.get(Contributor, "c1")
        assert (user.active, user.name) == (False, "bob")


def test_values_round_trip_faithfully(db):
    seed(db)
    with db.read() as session:
        user = session.get(Contributor, "c1")
        assert user.active is True and user.github_id == 2
        assert session.get(Source, "s1").approver_ids == [1]
    with pytest.raises(StatementError, match="53-bit"), db.write() as session:
        session.get(Contributor, "c1").github_id = 2**60


def test_writes_cannot_nest(db):
    with pytest.raises(OperationalError, match="cannot nest"):
        with db.write(), db.write():
            pass
    with db.write() as session:  # The lock and log recover after the failure.
        session.add(Audit(timestamp=3, actor="admin", action="after", detail={}))


def test_transactions_never_reach_storage_and_triggers_cover_schema(tmp_path):
    storage = FakeDurableStorage(str(tmp_path / "durable.sqlite"))
    db = Database(storage=storage)
    seed(db)
    assert not [s for s in storage.statements if s.lstrip().upper().startswith(("BEGIN", "SAVE"))]
    _, rows = storage.exec(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE ?", (UNDO + "%",)
    )
    triggers = {row[0] for row in rows}
    for table in ("contributors", "tasks", "attempts", "remote_admin_grants"):
        assert {f"{UNDO}_{table}_{kind}" for kind in "iud"} <= triggers
    # Restarting the object reinstalls triggers idempotently.
    Database(storage=storage).engine.dispose()
    db.engine.dispose()
