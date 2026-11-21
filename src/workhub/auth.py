"""Browser OAuth, CLI browser handoff, and server-side sessions."""

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

from sqlalchemy import select

from workhub.domain import HubError, token_hash
from workhub.models import AuthFlow, Contributor, GitHubInstallation, HubSession, Source


@dataclass
class Principal:
    role: str
    contributor_id: str | None = None
    github_id: int | None = None
    session_hash: str | None = None
    csrf: str | None = None


class Auth:
    def __init__(self, hub):
        self.hub = hub

    def principal(self, token):
        if secrets.compare_digest(token, self.hub.settings.admin_token):
            return Principal("admin")
        with self.hub.db.read() as session:
            record = session.get(HubSession, token_hash(token))
            if record and record.expires_at > self.hub.now():
                if (
                    record.role == "admin"
                    and record.github_id is not None
                    and record.github_id
                    not in self.hub.integrations.config("admins").get("ids", [])
                ):
                    # Owner sessions follow the current owner list, like remote owner grants.
                    raise HubError(401, "Owner authorization was removed")
                if record.contributor_id:
                    user = session.get(Contributor, record.contributor_id)
                    if not user or not user.active:
                        raise HubError(401, "Contributor is revoked")
                return Principal(
                    record.role,
                    record.contributor_id,
                    record.github_id,
                    record.token_hash,
                    record.csrf,
                )
        user = self.hub.authenticate(token)
        return Principal("contributor", user.id, user.github_id)

    def session(self, role, contributor_id=None, github_id=None):
        token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
        with self.hub.db.write() as session:
            session.add(
                HubSession(
                    token_hash=token_hash(token),
                    role=role,
                    contributor_id=contributor_id,
                    github_id=github_id,
                    expires_at=self.hub.now() + self.hub.settings.session_seconds,
                    created_at=self.hub.now(),
                    csrf=csrf,
                )
            )
        return token

    def logout(self, token):
        with self.hub.db.write() as session:
            record = session.get(HubSession, token_hash(token))
            if record:
                session.delete(record)

    def begin(self, kind, provider, principal=None, invitation=None, data=None, cli=False):
        self.hub.integrations.oauth_config(provider)
        actor = None
        if invitation:
            actor = self.hub.authenticate(invitation).id
        if kind == "login":
            if principal and principal.contributor_id:
                actor = principal.contributor_id
        elif kind == "contributor":
            if not principal or not principal.contributor_id:
                raise HubError(401, "Sign in or use an invitation first")
            actor = principal.contributor_id
        elif kind == "source":
            # Sign-in grants no repository access; sources use the read-only GitHub App.
            raise HubError(
                422, "Connect repositories by installing the read-only GitHub App on them"
            )
        elif kind == "admin_link":
            if not principal or principal.role != "admin":
                raise HubError(403, "Administrator access required")
            actor = "admin"
        else:
            raise HubError(422, "Unknown authorization purpose")
        flow_id, poll = secrets.token_urlsafe(24), secrets.token_urlsafe(40)
        with self.hub.db.write() as session:
            session.add(
                AuthFlow(
                    id=flow_id,
                    kind=kind,
                    provider=provider,
                    actor_id=actor,
                    data=data or {},
                    poll_hash=token_hash(poll) if cli else None,
                    expires_at=self.hub.now() + 600,
                    status="waiting",
                )
            )
        if cli:
            return {
                "id": flow_id,
                "poll_token": poll,
                "expires_in": 600,
                "interval": 2,
                "authorization_url": self.hub.settings.public_url + f"/auth/cli/{flow_id}",
            }
        return self.authorize(flow_id)

    def authorize(self, flow_id):
        state, browser, verifier = (secrets.token_urlsafe(40) for _ in range(3))
        with self.hub.db.write() as session:
            flow = session.get(AuthFlow, flow_id)
            if not flow or flow.expires_at <= self.hub.now() or flow.status != "waiting":
                raise HubError(410, "Sign-in request expired or was already used")
            flow.state_hash, flow.browser_hash = token_hash(state), token_hash(browser)
            flow.verifier = self.hub.encrypt(verifier)
            provider = flow.provider
        config = self.hub.integrations.oauth_config(provider)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return {
            "id": flow_id,
            "browser": browser,
            "authorization_url": "https://github.com/login/oauth/authorize?"
            + urlencode(
                {
                    "client_id": config["client_id"],
                    "redirect_uri": self.callback_url,
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    # Identity only: OAuth App sign-in grants no repository access. App user
                    # tokens are capped by the read-only App permissions.
                    "scope": "" if provider == "oauth" else "offline_access",
                }
            ),
        }

    @property
    def callback_url(self):
        return self.hub.settings.public_url + "/auth/github/callback"

    def take_flow(self, state, browser, kinds):
        if not state or not browser:
            raise HubError(400, "Missing OAuth state or browser binding; restart sign-in")
        with self.hub.db.write() as session:
            flow = session.scalar(select(AuthFlow).where(AuthFlow.state_hash == token_hash(state)))
            if (
                not flow
                or flow.kind not in kinds
                or flow.status != "waiting"
                or flow.expires_at <= self.hub.now()
                or not secrets.compare_digest(flow.browser_hash or "", token_hash(browser))
            ):
                raise HubError(400, "Invalid, expired, or already-used OAuth state")
            flow.status = "processing"
            return flow

    def complete(self, state, browser, code, error=None):
        flow = self.take_flow(state, browser, {"login", "contributor", "admin_link"})
        try:
            if error or not code:
                raise HubError(401, "GitHub sign-in was not authorized")
            config = self.hub.integrations.oauth_config(flow.provider)
            tokens = self.hub.integrations.provider.exchange(
                config,
                code,
                self.hub.cipher.decrypt(flow.verifier.encode()).decode(),
                self.callback_url,
            )
            if not tokens.get("access_token"):
                raise HubError(401, "GitHub did not grant an access token")
            with self.hub.github_factory(tokens["access_token"]) as github:
                identity = github.me()
            # The GitHub token proved identity; it is discarded, never stored.
            token = self.bind(flow, identity)
            if token and flow.data.get("control_actor"):
                # MCP-initiated connections are monitored by their initiator; nobody can
                # retrieve a session for them, so none is left behind.
                self.logout(token)
                token = None
            with self.hub.db.write() as session:
                current = session.get(AuthFlow, flow.id)
                current.status = "complete"
                current.verifier = None
                current.result = (
                    self.hub.encrypt(
                        json.dumps(
                            {
                                "token": token,
                                "github_login": identity["login"],
                                "purpose": flow.kind,
                                "role": self.principal(token).role if token else None,
                            }
                        )
                    )
                    if flow.poll_hash and not flow.data.get("control_actor")
                    else None
                )
            return {"token": token, "cli": bool(flow.poll_hash), "purpose": flow.kind}
        except Exception:
            self.fail(flow.id, "GitHub sign-in failed; restart authorization")
            raise

    def fail(self, flow_id, message):
        with self.hub.db.write() as session:
            current = session.get(AuthFlow, flow_id)
            current.status, current.error, current.verifier = "failed", message, None

    def failure(self, exc, fallback):
        # Hub errors carry hub-authored text; provider and unexpected errors stay generic.
        return exc.message if isinstance(exc, HubError) else fallback

    def bind(self, flow, identity):
        if flow.kind == "admin_link":
            config = self.hub.integrations.config("admins")
            config["ids"] = sorted(set(config.get("ids", []) + [identity["id"]]))
            self.hub.integrations.save_config("admins", config)
            return self.session("admin", github_id=identity["id"])
        admin_ids = self.hub.integrations.config("admins").get("ids", [])
        with self.hub.db.write() as session:
            user = (
                session.get(Contributor, flow.actor_id)
                if flow.actor_id
                else session.scalar(
                    select(Contributor).where(Contributor.github_id == identity["id"])
                )
            )
            if user:
                if not user.active or (user.github_id and user.github_id != identity["id"]):
                    raise HubError(403, "GitHub identity does not match this active contributor")
                duplicate = session.scalar(
                    select(Contributor).where(Contributor.github_id == identity["id"])
                )
                if duplicate and duplicate.id != user.id:
                    raise HubError(409, "GitHub account already belongs to another contributor")
                if user.github_id is None:
                    # First OAuth binding consumes the invitation. Existing token-based users
                    # retain their established credential when upgrading to browser sign-in.
                    user.token_hash = token_hash(secrets.token_urlsafe(40))
                user.github_id, user.github_login, user.github_token = (
                    identity["id"],
                    identity["login"],
                    None,
                )
                user_id = user.id
                self.hub.audit(session, user.id, "github.oauth_connected", github_id=identity["id"])
            else:
                user_id = None
                if identity["id"] not in admin_ids:
                    raise HubError(403, "Ask the hub owner for a contributor invitation")
        return self.session(
            "admin" if identity["id"] in admin_ids else "contributor", user_id, identity["id"]
        )

    def poll(self, flow_id, token):
        with self.hub.db.write() as session:
            flow = session.get(AuthFlow, flow_id)
            if (
                not flow
                or not flow.poll_hash
                or not secrets.compare_digest(flow.poll_hash, token_hash(token))
            ):
                raise HubError(401, "Invalid sign-in poll credential")
            if flow.expires_at <= self.hub.now() or flow.status == "consumed":
                raise HubError(410, "Sign-in request expired or was already retrieved")
            if flow.status == "failed":
                raise HubError(401, flow.error)
            if flow.status != "complete":
                return {"status": "pending"}
            result = json.loads(self.hub.cipher.decrypt(flow.result.encode()))
            flow.result, flow.status = None, "consumed"
            return {"status": "complete", **result}

    def special_flow(self, kind, data):
        state, browser = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
        flow_id = secrets.token_urlsafe(24)
        with self.hub.db.write() as session:
            session.add(
                AuthFlow(
                    id=flow_id,
                    kind=kind,
                    provider="app",
                    actor_id="admin",
                    data=data,
                    state_hash=token_hash(state),
                    browser_hash=token_hash(browser),
                    expires_at=self.hub.now() + 600,
                    status="waiting",
                )
            )
        return {"id": flow_id, "state": state, "browser": browser}

    def manifest(self, name):
        url = self.hub.settings.public_url
        return {
            "name": name,
            "url": url,
            "redirect_url": url + "/auth/github/app/manifest/callback",
            "callback_urls": [self.callback_url],
            "setup_url": url + "/auth/github/app/installed",
            "hook_attributes": {"url": url + "/webhooks/github", "active": True},
            "public": False,
            "request_oauth_on_install": False,
            "setup_on_update": True,
            "default_permissions": {
                "metadata": "read",
                "contents": "read",
                "issues": "read",
                "pull_requests": "read",
                "checks": "read",
                "statuses": "read",
            },
            "default_events": [
                "issues",
                "pull_request",
                "pull_request_review",
                "push",
                "check_run",
                "check_suite",
            ],
        }

    def complete_manifest(self, state, browser, code):
        flow = self.take_flow(state, browser, {"manifest"})
        try:
            self.register_manifest(flow, code)
        except Exception as exc:
            self.fail(
                flow.id,
                self.failure(exc, "GitHub App registration failed; restart registration"),
            )
            raise

    def register_manifest(self, flow, code):
        if not code:
            raise HubError(400, "Missing GitHub App manifest code")
        data = self.hub.integrations.provider.convert_manifest(code)
        self.hub.integrations.save_config(
            "app",
            {
                "app_id": str(data["id"]),
                "slug": data.get("slug") or data["html_url"].rstrip("/").split("/")[-1],
                "client_id": data["client_id"],
                "client_secret": data["client_secret"],
                "private_key": data["pem"],
                "webhook_secret": data["webhook_secret"],
            },
        )
        with self.hub.db.write() as session:
            session.get(AuthFlow, flow.id).status = "complete"

    def complete_installation(self, state, browser, installation_id):
        flow = self.take_flow(state, browser, {"installation"})
        try:
            self.install(flow, installation_id)
        except Exception as exc:
            self.fail(
                flow.id,
                self.failure(exc, "GitHub App installation failed; restart installation"),
            )
            raise

    def install(self, flow, installation_id):
        app = self.hub.integrations.config("app")
        installation = self.hub.integrations.provider.installation(app, installation_id)
        if int(installation["app_id"]) != int(app["app_id"]) or installation.get("suspended_at"):
            raise HubError(403, "Installation does not belong to this active GitHub App")
        account = installation["account"]
        token = self.hub.integrations.provider.installation_token(app, installation_id)["token"]
        with self.hub.github_factory(token) as github:
            approvers = [github.user(login)["id"] for login in flow.data.get("approvers", [])]
        if not approvers:
            if account["type"] == "User":
                approvers = [account["id"]]
            else:
                raise HubError(422, "Organization installations require explicit human approvers")
        with self.hub.db.write() as session:
            existing = session.get(GitHubInstallation, installation_id)
            if not existing:
                name = flow.data.get("name") or f"app-{account['login']}-{installation_id}"
                if session.scalar(select(Source).where(Source.name == name)):
                    raise HubError(409, "Source name is already in use")
                source = Source(
                    id="source_" + secrets.token_hex(12),
                    name=name,
                    github_id=account["id"],
                    github_login=account["login"],
                    github_token=f"installation:{installation_id}",
                    approver_ids=approvers,
                    exclude=flow.data.get("exclude", []),
                )
                session.add(source)
                session.flush()
                session.add(
                    GitHubInstallation(
                        id=installation_id,
                        account_id=account["id"],
                        account_login=account["login"],
                        source_id=source.id,
                    )
                )
            else:
                existing.suspended = False
            session.get(AuthFlow, flow.id).status = "complete"
            self.hub.audit(
                session, "admin", "installation.connected", installation_id=installation_id
            )
