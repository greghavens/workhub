from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContributorInput(StrictModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class ConnectInput(StrictModel):
    github_token: SecretStr


class Policy(StrictModel):
    schema_version: Literal[1] = 1
    enabled: bool = True
    allowed_paths: list[str] = Field(default_factory=lambda: ["**"])
    forbidden_paths: list[str] = Field(default_factory=lambda: [".github/workflows/**"])
    setup: list[list[str]] = Field(default_factory=list)
    validation: list[list[str]] = Field(default_factory=list)
    required_checks: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    dependency_changes: bool = False
    delivery: Literal["fork", "branch", "either"] = "either"
    max_work_minutes: int = Field(default=60, ge=1, le=240)


class ClaimInput(StrictModel):
    source: str | None = None
    repository: str | None = None
    capabilities: list[str] = Field(default_factory=list, max_length=100)
    work_minutes: int = Field(default=60, ge=1, le=240)
    idempotency_key: str = Field(min_length=8, max_length=128)
    task_id: str | None = None
    fork_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,100}$")


class LeaseInput(StrictModel):
    attempt_id: str
    generation: int = Field(ge=1)


class NoteInput(LeaseInput):
    note: str = Field(min_length=1, max_length=10000)


class SubmitInput(LeaseInput):
    pr_url: str = Field(max_length=500)
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    evidence: str = Field(min_length=1, max_length=30000)


class ApproveInput(StrictModel):
    source: str
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    issue_number: int = Field(gt=0)


class RetryInput(StrictModel):
    reason: str = Field(min_length=1, max_length=10000)


class OAuthStart(StrictModel):
    kind: Literal["login", "contributor", "source", "admin_link"] = "login"
    provider: Literal["oauth", "app"] = "oauth"
    invitation: SecretStr | None = None
    name: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    approvers: list[str] = Field(default_factory=list, max_length=100)
    exclude: list[str] = Field(default_factory=list, max_length=100)


class SessionInput(StrictModel):
    token: SecretStr


class OAuthConfigInput(StrictModel):
    client_id: str = Field(min_length=1, max_length=200)
    client_secret: SecretStr


class AppStart(StrictModel):
    name: str = Field(default="Work Hub", min_length=1, max_length=80)
    organization: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]+$")
    approvers: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class DependenciesInput(StrictModel):
    dependencies: list[str] = Field(default_factory=list, max_length=100)
