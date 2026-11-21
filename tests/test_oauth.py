import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from workhub.domain import HubError
from workhub.models import (
    AuthFlow,
    Contributor,
    GitHubCredential,
    GitHubInstallation,
    HubSession,
    Source,
)


class IdentityProvider:
    def __init__(self, env):
        self.env, self.exchanges = env, []

    def exchange(self, config, code, verifier, redirect_uri):
        self.exchanges.append((code, verifier, redirect_uri))
        if code == "denied":
            raise HubError(401, "Authorization denied")
        return {
            "access_token": f"{code}-token",
            "refresh_token": f"refresh-{code}",
            "expires_in": 3600,
            "refresh_token_expires_in": 86400,
        }

    def convert_manifest(self, code):
        return {
            "id": 123,
            "slug": "workhub-test",
            "client_id": "app-client",
            "client_secret": "app-secret",
            "pem": "test-key",
            "webhook_secret": "webhook-secret",
        }

    def installation(self, config, installation_id):
        return {
            "id": installation_id,
            "app_id": 123,
            "account": {"id": 1, "login": "alice", "type": "User"},
        }

    def installation_token(self, config, installation_id):
        return {"token": "alice-token", "expires_at": self.env.github.iso(3600)}


@pytest.fixture
def oauth(env):
    provider = IdentityProvider(env)
    env.hub.integrations.provider = provider
    env.hub.integrations.save_config(
        "oauth", {"client_id": "test-client", "client_secret": "secret"}
    )
    env.hub.integrations.save_config(
        "app",
        {
            "app_id": "123",
            "slug": "workhub-test",
            "private_key": "test-key",
            "client_id": "app-client",
            "client_secret": "app-secret",
            "webhook_secret": "webhook-secret",
        },
    )
    return env, provider


def begin(env, **data):
    response = env.client.post("/auth/start", json={"kind": "login", "provider": "oauth", **data})
    assert response.status_code == 200, response.text
    return parse_qs(urlsplit(response.json()["authorization_url"]).query)


def callback(env, params, code="bob"):
    return env.client.get(
        "/auth/github/callback",
        params={"state": params["state"][0], "code": code},
        follow_redirects=False,
    )


def test_oauth_pkce_login_cookie_csrf_and_logout(oauth):
    env, provider = oauth
    params = begin(env)
    assert params["code_challenge_method"] == ["S256"]
    assert not params.get("scope")  # Identity only: sign-in grants no repository access.
    response = callback(env, params)
    assert response.status_code == 303, response.text
    verifier = provider.exchanges[0][1]
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert params["code_challenge"] == [expected]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert env.client.get("/v1/me").json()["github_login"] == "bob"
    assert env.client.post("/auth/logout").status_code == 403
    status = env.client.get("/auth/status").json()
    assert (
        env.client.post("/auth/logout", headers={"X-CSRF-Token": status["csrf"]}).status_code == 200
    )
    assert env.client.get("/v1/me").status_code == 401


def test_oauth_wrong_state_cookie_expiry_replay_and_denial(oauth):
    env, provider = oauth
    params = begin(env)
    assert (
        env.client.get(
            "/auth/github/callback", params={"state": "wrong", "code": "bob"}
        ).status_code
        == 400
    )
    cookie = env.client.cookies.get("workhub_oauth")
    env.client.cookies.clear()
    assert callback(env, params).status_code == 400
    env.client.cookies.set("workhub_oauth", cookie, path="/auth")
    assert callback(env, params).status_code == 303
    assert callback(env, params).status_code == 400
    assert len(provider.exchanges) == 1
    env.client.cookies.clear()
    params = begin(env)
    env.github.now += 601
    assert callback(env, params).status_code == 400
    params = begin(env)
    assert callback(env, params, "denied").status_code == 401


def test_cli_handoff_keeps_token_out_of_browser(oauth):
    env, _ = oauth
    result = env.client.post("/auth/cli/start", json={"kind": "login"}).json()
    authorized = env.client.get(urlsplit(result["authorization_url"]).path, follow_redirects=False)
    params = parse_qs(urlsplit(authorized.headers["location"]).query)
    assert (
        env.client.get(
            f"/auth/cli/{result['id']}/result", headers={"Authorization": "Bearer bad"}
        ).status_code
        == 401
    )
    headers = {"Authorization": f"Bearer {result['poll_token']}"}
    assert (
        env.client.get(f"/auth/cli/{result['id']}/result", headers=headers).json()["status"]
        == "pending"
    )
    completed = callback(env, params)
    assert completed.status_code == 200
    assert "workhub_session" not in completed.cookies
    response = env.client.get(f"/auth/cli/{result['id']}/result", headers=headers)
    token = response.json()["token"]
    assert token not in completed.text
    assert env.client.get("/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert env.client.get(f"/auth/cli/{result['id']}/result", headers=headers).status_code == 410


def test_oauth_cannot_take_over_invitation_or_escalate(oauth):
    env, _ = oauth
    params = begin(env, invitation=env.users["bob"]["Authorization"][7:])
    assert callback(env, params, "carol").status_code == 403
    assert env.client.post("/auth/start", json={"kind": "admin_link"}).status_code == 403
    # Sources come only from the read-only GitHub App; OAuth source connection is refused.
    assert (
        env.client.post(
            "/auth/start", headers=env.users["bob"], json={"kind": "source", "name": "evil"}
        ).status_code
        == 422
    )


def test_admin_can_link_github_then_sign_in_without_bootstrap(oauth):
    env, _ = oauth
    response = env.client.post("/auth/start", headers=env.admin, json={"kind": "admin_link"})
    params = parse_qs(urlsplit(response.json()["authorization_url"]).query)
    assert callback(env, params, "alice").status_code == 303
    assert env.client.get("/v1/admin/tasks").status_code == 200
    env.client.cookies.clear()
    assert callback(env, begin(env), "alice").status_code == 303
    assert env.client.get("/auth/status").json()["role"] == "admin"


def test_oauth_cannot_connect_a_source(oauth):
    env, _ = oauth
    response = env.client.post(
        "/auth/start", headers=env.admin, json={"kind": "source", "name": "alice-oauth"}
    )
    assert response.status_code == 422
    assert "read-only GitHub App" in response.json()["detail"]
    with pytest.raises(HubError):
        env.hub.source("alice-oauth")


def test_sign_in_stores_no_github_token(oauth):
    env, _ = oauth
    # A contributor, then the owner (link and later sign-in): each token proves identity only.
    assert callback(env, begin(env)).status_code == 303
    env.client.cookies.clear()
    start = env.client.post("/auth/start", headers=env.admin, json={"kind": "admin_link"})
    params = parse_qs(urlsplit(start.json()["authorization_url"]).query)
    assert callback(env, params, "alice").status_code == 303
    env.client.cookies.clear()
    assert callback(env, begin(env), "alice").status_code == 303
    with env.hub.db.read() as session:
        assert list(session.scalars(select(GitHubCredential))) == []
        bob = session.scalar(select(Contributor).where(Contributor.name == "bob"))
        assert bob.github_id == 2 and bob.github_token is None


def test_github_app_manifest_and_installation_callbacks(oauth):
    env, _ = oauth
    registered = env.client.post(
        "/v1/admin/integrations/app/register", headers=env.admin, json={"name": "Test Work Hub"}
    ).json()
    url = urlsplit(registered["url"])
    page = env.client.get(url.path + "?" + url.query, headers=env.admin)
    assert page.status_code == 200
    assert "https://github.com/settings/apps/new" in page.text
    assert "client_secret" not in page.text
    state = parse_qs(url.query)["state"][0]
    response = env.client.get(
        "/auth/github/app/manifest/callback",
        params={"code": "manifest-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    result = env.client.post(
        "/v1/admin/integrations/app/install", headers=env.admin, json={"name": "app-alice"}
    ).json()
    state = parse_qs(urlsplit(result["url"]).query)["state"][0]
    response = env.client.get(
        "/auth/github/app/installed",
        params={"installation_id": 99, "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    with env.hub.db.read() as session:
        installation = session.get(GitHubInstallation, 99)
        source = session.get(Source, installation.source_id)
    assert source.github_token == "installation:99"
    assert env.hub.sync(source.name)["errors"] == []
    assert env.hub.integrations.resolve(source.github_token) == "alice-token"


def test_cross_origin_and_missing_csrf_are_rejected(oauth):
    env, _ = oauth
    assert (
        env.client.post(
            "/auth/session", headers={"Origin": "https://evil.example"}, json={"token": "A" * 40}
        ).status_code
        == 403
    )
    assert env.client.post("/auth/session", json={"token": "A" * 40}).status_code == 200
    assert env.client.get("/v1/admin/tasks").status_code == 200
    assert env.client.post("/v1/admin/sync").status_code == 403
    csrf = env.client.get("/auth/status").json()["csrf"]
    assert (
        env.client.post(
            "/v1/admin/sync", headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert env.client.post("/v1/admin/sync", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_failed_oauth_flow_never_issues_session(oauth):
    env, _ = oauth
    params = begin(env)
    assert callback(env, params, "denied").status_code == 401
    with env.hub.db.read() as session:
        assert not list(session.scalars(select(HubSession)))
        flow = session.scalar(select(AuthFlow).where(AuthFlow.kind == "login"))
        assert flow.status == "failed"
        assert flow.result is None
    audit = env.client.get("/v1/admin/audit", headers=env.admin).text
    assert "app-secret" not in audit
    assert "refresh-bob" not in audit


def test_new_invitation_is_consumed_and_uninvited_login_rejected(oauth):
    env, _ = oauth
    env.github.identities["dave-token"] = {"id": 44, "login": "dave"}
    assert callback(env, begin(env), "dave").status_code == 403
    invite = env.client.post(
        "/v1/admin/contributors", headers=env.admin, json={"name": "dave"}
    ).json()
    params = begin(env, invitation=invite["token"])
    assert callback(env, params, "dave").status_code == 303
    assert env.client.get("/v1/me").json()["github_login"] == "dave"
    assert (
        env.client.get("/v1/me", headers={"Authorization": "Bearer " + invite["token"]}).status_code
        == 401
    )
    env.client.cookies.clear()
    assert callback(env, begin(env), "dave").status_code == 303


def test_installation_approval_uses_human_owner_and_suspension_is_immediate(oauth):
    import hashlib
    import hmac
    import json

    env, _ = oauth
    source = env.hub.source("alice")
    with env.hub.db.write() as session:
        record = session.get(Source, source.id)
        record.github_token = "installation:99"
        record.github_id = 999  # Organization identity is not a human approver.
        # Re-home the fixture's installation onto an organization account.
        session.delete(session.get(GitHubInstallation, 1))
        session.flush()
        session.add(
            GitHubInstallation(id=99, account_id=999, account_login="org", source_id=source.id)
        )
    payload = {"source": "alice", "repository": "alice/widget", "issue_number": 1}
    # Approval authority is the GitHub label actor, never the hub caller: the organization
    # account labelling the issue is not a configured human approver.
    env.github.label("alice/widget", 1, actor=999)
    assert env.client.post("/v1/admin/approve", headers=env.admin, json=payload).status_code == 403
    start = env.client.post(
        "/auth/start", headers=env.admin, json={"kind": "admin_link", "provider": "app"}
    )
    params = parse_qs(urlsplit(start.json()["authorization_url"]).query)
    assert callback(env, params, "alice").status_code == 303
    csrf = env.client.get("/auth/status").json()["csrf"]
    env.github.label("alice/widget", 1, actor=1)
    assert (
        env.client.post(
            "/v1/admin/approve", headers={"X-CSRF-Token": csrf}, json=payload
        ).status_code
        == 200
    )
    claim = env.claim()
    assert claim.status_code == 200
    assert claim.json()["contract"]["approval"]["approver_id"] == 1
    body = json.dumps({"action": "suspend", "installation": {"id": 99}}).encode()
    signature = hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
    response = env.client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Delivery": "suspend-99",
            "X-GitHub-Event": "installation",
            "X-Hub-Signature-256": "sha256=" + signature,
        },
    )
    assert response.status_code == 202
    with pytest.raises(HubError, match="suspended"):
        env.hub.integrations.resolve("installation:99")
    assert env.action("bob", claim.json(), "heartbeat").status_code == 403


def test_removed_owner_session_is_rejected_but_bootstrap_session_remains(oauth):
    env, _ = oauth
    env.hub.integrations.save_config("admins", {"ids": [1]})
    owner = {"Authorization": "Bearer " + env.app.state.auth.session("admin", github_id=1)}
    bootstrap = {"Authorization": "Bearer " + env.app.state.auth.session("admin")}
    assert env.client.get("/v1/admin/tasks", headers=owner).status_code == 200
    env.hub.integrations.save_config("admins", {"ids": []})
    response = env.client.get("/v1/admin/tasks", headers=owner)
    assert response.status_code == 401
    assert response.json()["detail"] == "Owner authorization was removed"
    assert not env.client.get("/auth/status", headers=owner).json()["authenticated"]
    assert env.client.get("/v1/admin/tasks", headers=bootstrap).status_code == 200
