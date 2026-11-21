import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from workhub.db import Database
from workhub.models import Base, Contributor, GitHubCredential, SchemaVersion, Source


def test_v1_upgrade_preserves_identity_and_is_idempotent(tmp_path):
    url = f"sqlite:///{tmp_path}/old.db"
    engine = create_engine(url)
    old = {
        "mutex",
        "contributors",
        "sources",
        "repositories",
        "source_repositories",
        "tasks",
        "attempts",
        "audit",
        "approvals",
    }
    Base.metadata.create_all(
        engine, tables=[t for t in Base.metadata.sorted_tables if t.name in old]
    )
    with Session(engine) as session:
        session.add(
            Contributor(
                id="existing",
                name="Existing",
                token_hash="hash",
                github_id=55,
                github_login="friend",
                github_token="encrypted",
            )
        )
        session.commit()
    engine.dispose()
    for _ in range(2):
        database = Database(url)
        with database.read() as session:
            user = session.get(Contributor, "existing")
            # v4 discards stored GitHub tokens but keeps the identity.
            assert user.github_token is None
            assert user.github_id == 55
            assert session.get(SchemaVersion, 2)
            assert session.get(SchemaVersion, 3)
            assert session.get(SchemaVersion, 4)
        assert "github_credentials" in inspect(database.engine).get_table_names()
        assert "remote_admin_grants" in inspect(database.engine).get_table_names()
        database.engine.dispose()


def test_newer_database_is_never_downgraded(tmp_path):
    url = f"sqlite:///{tmp_path}/new.db"
    database = Database(url)
    with database.write() as session:
        session.add(SchemaVersion(version=999, applied_at=1))
    database.engine.dispose()
    with pytest.raises(RuntimeError, match="newer"):
        Database(url)


def test_v4_removes_every_stored_github_credential(tmp_path):
    url = f"sqlite:///{tmp_path}/v3.db"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        for version in (1, 2, 3):
            session.add(SchemaVersion(version=version, applied_at=1))
        session.add_all(
            [
                GitHubCredential(
                    id="cred_owner", provider="oauth", github_id=1, encrypted_tokens="repo-scope"
                ),
                Contributor(
                    id="friend",
                    name="Friend",
                    token_hash="hash",
                    github_id=2,
                    github_login="friend",
                    github_token="credential:cred_friend",
                ),
                Source(
                    id="pasted",
                    name="pasted",
                    github_id=1,
                    github_login="alice",
                    github_token="encrypted-pat",
                    approver_ids=[1],
                    exclude=[],
                ),
                Source(
                    id="app",
                    name="app",
                    github_id=1,
                    github_login="alice",
                    github_token="installation:7",
                    approver_ids=[1],
                    exclude=[],
                ),
            ]
        )
        session.commit()
    engine.dispose()
    database = Database(url)
    with database.read() as session:
        assert list(session.scalars(select(GitHubCredential))) == []
        assert session.get(Contributor, "friend").github_token is None
        assert session.get(Contributor, "friend").github_id == 2
        assert session.get(Source, "pasted").github_token == "removed:"
        assert session.get(Source, "app").github_token == "installation:7"
    database.engine.dispose()
