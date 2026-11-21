from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Mutex(Base):
    __tablename__ = "mutex"
    id: Mapped[int] = mapped_column(primary_key=True)


class Contributor(Base):
    __tablename__ = "contributors"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    github_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    github_login: Mapped[str | None] = mapped_column(String)
    github_token: Mapped[str | None] = mapped_column(String)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    github_id: Mapped[int] = mapped_column(BigInteger)
    github_login: Mapped[str] = mapped_column(String)
    github_token: Mapped[str] = mapped_column(String)
    approver_ids: Mapped[list] = mapped_column(JSON)
    exclude: Mapped[list] = mapped_column(JSON)


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    full_name: Mapped[str] = mapped_column(String)
    authority_source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    private: Mapped[bool] = mapped_column(Boolean)


class SourceRepository(Base):
    __tablename__ = "source_repositories"
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), primary_key=True)


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("repository_id", "issue_number"),
        Index(
            "one_leased_task_per_repository",
            "repository_id",
            unique=True,
            sqlite_where=text("state = 'leased'"),
            postgresql_where=text("state = 'leased'"),
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"))
    issue_number: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String, default="needs_approval")
    revision: Mapped[int] = mapped_column(Integer, default=0)
    generation: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[int] = mapped_column(Integer)
    approval: Mapped[dict] = mapped_column(JSON, default=dict)
    spec: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_hash: Mapped[str] = mapped_column(String, default="")
    policy_commit: Mapped[str] = mapped_column(String, default="")
    reason: Mapped[str | None] = mapped_column(String)


class Attempt(Base):
    __tablename__ = "attempts"
    __table_args__ = (
        UniqueConstraint("contributor_id", "claim_key"),
        Index(
            "one_lease_per_contributor",
            "contributor_id",
            unique=True,
            sqlite_where=text("state = 'leased'"),
            postgresql_where=text("state = 'leased'"),
        ),
        Index(
            "one_lease_per_task",
            "task_id",
            unique=True,
            sqlite_where=text("state = 'leased'"),
            postgresql_where=text("state = 'leased'"),
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"))
    contributor_id: Mapped[str] = mapped_column(ForeignKey("contributors.id"))
    claim_key: Mapped[str] = mapped_column(String)
    request_hash: Mapped[str] = mapped_column(String)
    generation: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String)
    expires_at: Mapped[int] = mapped_column(Integer)
    deadline: Mapped[int] = mapped_column(Integer)
    contract: Mapped[dict] = mapped_column(JSON)
    note: Mapped[str | None] = mapped_column(String)
    submission: Mapped[dict | None] = mapped_column(JSON)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    task_id: Mapped[str | None] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Approval(Base):
    __tablename__ = "approvals"
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    specification: Mapped[dict] = mapped_column(JSON)
    policy: Mapped[dict] = mapped_column(JSON)
    policy_commit: Mapped[str] = mapped_column(String)
    record: Mapped[dict] = mapped_column(JSON)


class IntegrationConfig(Base):
    __tablename__ = "integration_config"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    encrypted_value: Mapped[str] = mapped_column(String)


class GitHubCredential(Base):
    __tablename__ = "github_credentials"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String)
    github_id: Mapped[int] = mapped_column(BigInteger)
    encrypted_tokens: Mapped[str] = mapped_column(String)
    expires_at: Mapped[int | None] = mapped_column(BigInteger)
    refresh_expires_at: Mapped[int | None] = mapped_column(BigInteger)
    refresh_owner: Mapped[str | None] = mapped_column(String)
    refresh_until: Mapped[int] = mapped_column(BigInteger, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class HubSession(Base):
    __tablename__ = "hub_sessions"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    contributor_id: Mapped[str | None] = mapped_column(ForeignKey("contributors.id"))
    role: Mapped[str] = mapped_column(String)
    github_id: Mapped[int | None] = mapped_column(BigInteger)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[int] = mapped_column(BigInteger)
    csrf: Mapped[str] = mapped_column(String)


class AuthFlow(Base):
    __tablename__ = "auth_flows"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    state_hash: Mapped[str | None] = mapped_column(String, unique=True)
    browser_hash: Mapped[str | None] = mapped_column(String)
    poll_hash: Mapped[str | None] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    provider: Mapped[str] = mapped_column(String)
    actor_id: Mapped[str | None] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    verifier: Mapped[str | None] = mapped_column(String)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String)
    result: Mapped[str | None] = mapped_column(String)
    error: Mapped[str | None] = mapped_column(String)


class GitHubInstallation(Base):
    __tablename__ = "github_installations"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    account_id: Mapped[int] = mapped_column(BigInteger)
    account_login: Mapped[str] = mapped_column(String)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), unique=True)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_token: Mapped[str | None] = mapped_column(String)
    expires_at: Mapped[int] = mapped_column(BigInteger, default=0)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    event: Mapped[str] = mapped_column(String)
    encrypted_payload: Mapped[str] = mapped_column(String)
    payload_hash: Mapped[str] = mapped_column(String)
    received_at: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[int] = mapped_column(BigInteger)
    locked_until: Mapped[int] = mapped_column(BigInteger, default=0)
    lock_owner: Mapped[str | None] = mapped_column(String)
    error: Mapped[str | None] = mapped_column(String)


class TaskDependency(Base):
    __tablename__ = "task_dependencies"
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)
    dependency_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[int] = mapped_column(BigInteger)


class RemoteClient(Base):
    __tablename__ = "remote_clients"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    encrypted_metadata: Mapped[str] = mapped_column(String)


class RemoteAuthorization(Base):
    __tablename__ = "remote_authorizations"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("remote_clients.id"))
    params: Mapped[dict] = mapped_column(JSON)
    contributor_id: Mapped[str | None] = mapped_column(ForeignKey("contributors.id"))
    code_hash: Mapped[str | None] = mapped_column(String, unique=True)
    state: Mapped[str] = mapped_column(String)
    expires_at: Mapped[int] = mapped_column(BigInteger)


class RemoteGrant(Base):
    __tablename__ = "remote_grants"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("remote_clients.id"))
    contributor_id: Mapped[str] = mapped_column(ForeignKey("contributors.id"))
    scopes: Mapped[list] = mapped_column(JSON)
    resource: Mapped[str] = mapped_column(String)
    access_hash: Mapped[str] = mapped_column(String, unique=True)
    refresh_hash: Mapped[str] = mapped_column(String, unique=True)
    access_expires_at: Mapped[int] = mapped_column(BigInteger)
    refresh_expires_at: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class RemoteAdminGrant(Base):
    __tablename__ = "remote_admin_grants"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("remote_clients.id"))
    github_id: Mapped[int] = mapped_column(BigInteger)
    scopes: Mapped[list] = mapped_column(JSON)
    resource: Mapped[str] = mapped_column(String)
    access_hash: Mapped[str] = mapped_column(String, unique=True)
    refresh_hash: Mapped[str] = mapped_column(String, unique=True)
    access_expires_at: Mapped[int] = mapped_column(BigInteger)
    refresh_expires_at: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
