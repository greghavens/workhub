"""Versioned, additive upgrade from the original v1 database without data loss."""

import time

from sqlalchemy import delete, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from workhub.models import Base, Contributor, GitHubCredential, SchemaVersion, Source

CURRENT_VERSION = 4


def upgrade(engine):
    tables = set(inspect(engine).get_table_names())
    if "schema_version" in tables:
        with Session(engine) as session:
            version = (
                session.scalar(
                    select(SchemaVersion.version).order_by(SchemaVersion.version.desc()).limit(1)
                )
                or 0
            )
        if version > CURRENT_VERSION:
            raise RuntimeError("Database schema is newer than this Work Hub binary")
    # v2 adds integrations; v3 adds independent owner MCP grants. Existing columns stay intact.
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        if not session.get(SchemaVersion, 4):
            remove_github_write_access(session)
        for version in range(1, CURRENT_VERSION + 1):
            if not session.get(SchemaVersion, version):
                session.add(SchemaVersion(version=version, applied_at=int(time.time())))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()  # Another startup applied the same additive version records.
    return CURRENT_VERSION


def remove_github_write_access(session):
    """v4: the hub keeps no GitHub credential that could write.

    Earlier versions stored repo-scoped sign-in tokens, pasted contributor tokens, and
    pasted or OAuth source tokens. All are deleted; sources must be reinstalled through
    the read-only GitHub App.
    """
    session.execute(delete(GitHubCredential))
    for user in session.scalars(select(Contributor).where(Contributor.github_token.is_not(None))):
        user.github_token = None
    for source in session.scalars(select(Source)):
        if not source.github_token.startswith("installation:"):
            source.github_token = "removed:"
