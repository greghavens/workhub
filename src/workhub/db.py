from contextlib import contextmanager

from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from workhub.migrations import upgrade
from workhub.models import Mutex


class Database:
    def __init__(self, url: str | None = None, storage=None):
        """Use a database URL, or `storage` for Cloudflare Durable Object SQLite."""
        self.durable = None
        if storage is not None:
            from workhub.durable import durable_engine

            self.engine, self.durable = durable_engine(storage)
            sqlite = False
        else:
            sqlite = url.startswith("sqlite")
            self.engine = create_engine(
                url,
                connect_args={"check_same_thread": False, "timeout": 30} if sqlite else {},
                pool_pre_ping=True,
            )
        if sqlite:

            @event.listens_for(self.engine, "connect")
            def configure(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA journal_mode=WAL")

        upgrade(self.engine)
        if self.durable:
            self.durable.install_undo()
        with Session(self.engine) as session:
            if not session.get(Mutex, 1):
                session.add(Mutex(id=1))
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()

    @contextmanager
    def read(self):
        with Session(self.engine, expire_on_commit=False) as session:
            yield session

    @contextmanager
    def write(self):
        # A short database lock serializes decisions across threads/processes.
        # GitHub requests must be made before entering this transaction.
        if self.durable:
            yield from self.durable_write()
            return
        with Session(self.engine, expire_on_commit=False) as session:
            if self.engine.dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            else:
                session.execute(select(Mutex).where(Mutex.id == 1).with_for_update())
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def durable_write(self):
        # Durable Object requests are serialized; the undo log provides rollback.
        with Session(self.engine, expire_on_commit=False) as session:
            self.durable.begin_write()
            committed = False
            try:
                yield session
                session.commit()
                committed = True
            except BaseException:
                session.rollback()
                raise
            finally:
                self.durable.end_write(committed)
