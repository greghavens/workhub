"""GitHub OAuth and installation credentials. All provider requests are fixed-origin."""

import json
from urllib.parse import quote

import httpx
import jwt

from workhub.domain import HubError, timestamp
from workhub.github import USER_AGENT, http_client
from workhub.models import GitHubInstallation, IntegrationConfig


class GitHubIdentityProvider:
    def request(self, method, url, **kwargs):
        try:
            with http_client(timeout=20, headers={"User-Agent": USER_AGENT}) as client:
                response = client.request(method, url, **kwargs)
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise HubError(503, "GitHub authentication is unavailable; restart sign-in") from exc
        if response.is_error or data.get("error"):
            raise HubError(
                401 if response.status_code < 500 else 503,
                "GitHub authorization was denied or expired; sign in again",
            )
        return data

    def exchange(self, config, code, verifier, redirect_uri):
        return self.request(
            "POST",
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
        )

    def convert_manifest(self, code):
        return self.request(
            "POST",
            f"https://api.github.com/app-manifests/{quote(code, safe='')}/conversions",
            headers={"Accept": "application/vnd.github+json"},
        )

    def app_request(self, config, method, path, **kwargs):
        import time

        now = int(time.time())
        token = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": str(config["app_id"])},
            config["private_key"],
            algorithm="RS256",
        )
        return self.request(
            method,
            f"https://api.github.com{path}",
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"},
            **kwargs,
        )

    def installation(self, config, installation_id):
        return self.app_request(config, "GET", f"/app/installations/{installation_id}")

    def installation_token(self, config, installation_id):
        return self.app_request(
            config,
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            json={
                "permissions": {
                    "contents": "read",
                    "issues": "read",
                    "pull_requests": "read",
                    "checks": "read",
                    "statuses": "read",
                    "metadata": "read",
                }
            },
        )


class Integrations:
    def __init__(self, hub, provider=None):
        self.hub = hub
        self.provider = provider or GitHubIdentityProvider()

    def config(self, key):
        settings = self.hub.settings
        defaults = {
            "oauth": {
                "client_id": settings.github_oauth_client_id,
                "client_secret": settings.github_oauth_client_secret,
            },
            "app": {
                "app_id": settings.github_app_id,
                "slug": settings.github_app_slug,
                "client_id": settings.github_app_client_id,
                "client_secret": settings.github_app_client_secret,
                "private_key": settings.github_app_private_key,
                "webhook_secret": settings.github_webhook_secret,
            },
            "admins": {"ids": list(settings.admin_github_ids)},
        }.get(key, {})
        with self.hub.db.read() as session:
            stored = session.get(IntegrationConfig, key)
        if stored:
            defaults.update(json.loads(self.hub.cipher.decrypt(stored.encrypted_value.encode())))
        return defaults

    def save_config(self, key, data):
        with self.hub.db.write() as session:
            record = session.get(IntegrationConfig, key)
            encrypted = self.hub.encrypt(json.dumps(data))
            if record:
                record.encrypted_value = encrypted
            else:
                session.add(IntegrationConfig(key=key, encrypted_value=encrypted))
            self.hub.audit(session, "admin", "integration.configured", provider=key)

    def oauth_config(self, provider):
        if provider not in {"oauth", "app"}:
            raise HubError(422, "Unknown GitHub provider")
        config = self.config(provider)
        if not config.get("client_id") or not config.get("client_secret"):
            raise HubError(
                409, "Configure GitHub OAuth or register the GitHub App in Settings first"
            )
        return config

    def resolve(self, reference):
        """The GitHub token for a source. Only read-only App installations hold access."""
        if reference.startswith("installation:"):
            return self.installation_token(int(reference.split(":", 1)[1]))
        raise HubError(
            403,
            "This source no longer has GitHub access; "
            "install the read-only GitHub App on its repositories",
        )

    def installation_token(self, installation_id):
        with self.hub.db.read() as session:
            installation = session.get(GitHubInstallation, installation_id)
        if not installation or installation.suspended:
            raise HubError(403, "GitHub App installation is suspended or removed")
        if installation.encrypted_token and installation.expires_at > self.hub.now() + 60:
            return self.hub.cipher.decrypt(installation.encrypted_token.encode()).decode()
        data = self.provider.installation_token(self.config("app"), installation_id)
        with self.hub.db.write() as session:
            current = session.get(GitHubInstallation, installation_id)
            if not current or current.suspended:
                raise HubError(403, "GitHub App installation is unavailable")
            current.encrypted_token = self.hub.encrypt(data["token"])
            current.expires_at = timestamp(data["expires_at"])
        return data["token"]
