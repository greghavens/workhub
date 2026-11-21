import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.fernet import Fernet


@dataclass(frozen=True)
class Settings:
    database_url: str
    encryption_key: str
    admin_token: str
    lease_seconds: int = 900
    max_work_minutes: int = 240
    sync_seconds: int = 120
    public_url: str = "http://127.0.0.1:8000"
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    github_app_id: str = ""
    github_app_slug: str = ""
    github_app_client_id: str = ""
    github_app_client_secret: str = ""
    github_app_private_key: str = ""
    github_webhook_secret: str = ""
    admin_github_ids: tuple[int, ...] = ()
    session_seconds: int = 86400

    def __post_init__(self):
        Fernet(self.encryption_key.encode())
        if len(self.admin_token) < 32:
            raise ValueError("WORKHUB_ADMIN_TOKEN must contain at least 32 characters")
        if self.lease_seconds < 30 or self.max_work_minutes < 1 or self.sync_seconds < 1:
            raise ValueError("Invalid timing configuration")
        parsed = urlsplit(self.public_url)
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not parsed.hostname
            or (
                parsed.scheme != "https"
                and not (
                    parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
        ):
            raise ValueError(
                "WORKHUB_PUBLIC_URL must be an HTTPS origin (HTTP allowed on loopback)"
            )

    @classmethod
    def from_env(cls):
        try:
            return cls(
                database_url=os.getenv("WORKHUB_DATABASE_URL", "sqlite:///workhub.db"),
                encryption_key=os.environ["WORKHUB_ENCRYPTION_KEY"],
                admin_token=os.environ["WORKHUB_ADMIN_TOKEN"],
                lease_seconds=int(os.getenv("WORKHUB_LEASE_SECONDS", "900")),
                max_work_minutes=int(os.getenv("WORKHUB_MAX_WORK_MINUTES", "240")),
                sync_seconds=int(os.getenv("WORKHUB_SYNC_SECONDS", "120")),
                public_url=os.getenv("WORKHUB_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"),
                github_oauth_client_id=os.getenv("GITHUB_OAUTH_CLIENT_ID", ""),
                github_oauth_client_secret=os.getenv("GITHUB_OAUTH_CLIENT_SECRET", ""),
                github_app_id=os.getenv("GITHUB_APP_ID", ""),
                github_app_slug=os.getenv("GITHUB_APP_SLUG", ""),
                github_app_client_id=os.getenv("GITHUB_APP_CLIENT_ID", ""),
                github_app_client_secret=os.getenv("GITHUB_APP_CLIENT_SECRET", ""),
                github_app_private_key=os.getenv("GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n"),
                github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
                admin_github_ids=tuple(
                    int(i)
                    for i in os.getenv("WORKHUB_ADMIN_GITHUB_IDS", "").split(",")
                    if i.strip()
                ),
                session_seconds=int(os.getenv("WORKHUB_SESSION_SECONDS", "86400")),
            )
        except KeyError as exc:
            raise ValueError(f"Missing {exc.args[0]}; run `workhub init` first") from exc
