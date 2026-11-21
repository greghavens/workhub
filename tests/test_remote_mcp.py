import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

WORK = "http://127.0.0.1:8000/mcp"
PM = "http://127.0.0.1:8000/mcp/pm"


def registered(client, scope="work"):
    response = client.post(
        "/register",
        json={
            "client_name": "Test coding harness",
            "redirect_uris": ["http://127.0.0.1:9876/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": scope,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def authorize(env, client, client_id, scope="work", headers=None, resource=WORK):
    verifier = "a-very-long-valid-pkce-verifier-" + "x" * 40
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    response = client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": "http://127.0.0.1:9876/callback",
            "scope": scope,
            "state": "client-correlation",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        },
        follow_redirects=False,
    )
    assert response.status_code in {302, 303, 307}, response.text
    request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
    detail = client.get(f"/v1/mcp/consent/{request_id}", headers=headers or env.users["bob"])
    assert detail.json()["client_name"] == "Test coding harness"
    consent = client.post(
        f"/v1/mcp/consent/{request_id}", headers=headers or env.users["bob"], json={"allow": True}
    )
    assert consent.status_code == 200, consent.text
    params = parse_qs(urlsplit(consent.json()["redirect_url"]).query)
    assert params["state"] == ["client-correlation"]
    return {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": params["code"][0],
        "code_verifier": verifier,
        "redirect_uri": "http://127.0.0.1:9876/callback",
        "resource": resource,
    }


def test_remote_oauth_pkce_claim_refresh_revoke(env):
    env.github.now = int(time.time())
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        metadata = client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200, metadata.text
        assert "S256" in metadata.json()["code_challenge_methods_supported"]
        protected = client.get("/.well-known/oauth-protected-resource/mcp")
        assert protected.status_code == 200
        assert protected.json()["resource"] == "http://127.0.0.1:8000/mcp"
        client_id = registered(client)
        exchange = authorize(env, client, client_id)
        assert client.post("/token", data={**exchange, "code_verifier": "wrong"}).status_code == 400
        tokens = client.post("/token", data=exchange)
        assert tokens.status_code == 200, tokens.text
        assert client.post("/token", data=exchange).status_code == 400
        headers = {
            "Authorization": "Bearer " + tokens.json()["access_token"],
            "Accept": "application/json, text/event-stream",
        }
        initialized = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        )
        assert initialized.status_code == 200, initialized.text
        tools = client.post(
            "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        names = {t["name"] for t in tools.json()["result"]["tools"]}
        assert {"work_claim", "hub_identity", "github_connect_start"} <= names
        # The contributor endpoint never carries admin authority, so it lists no PM tools.
        assert not names & {"task_approve", "contributor_invite", "hub_login_start"}
        denied = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "task_approve",
                    "arguments": {
                        "source": "alice",
                        "repository": "alice/widget",
                        "issue_number": 1,
                    },
                },
            },
        )
        assert denied.json()["result"]["isError"]
        claimed = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "work_claim",
                    "arguments": {"idempotency_key": "remote-claim-key"},
                },
            },
        )
        assert claimed.status_code == 200, claimed.text
        assert not claimed.json()["result"].get("isError"), claimed.text
        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": tokens.json()["refresh_token"],
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert client.post("/mcp", headers=headers, json={}).status_code == 401
        assert (
            client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": tokens.json()["refresh_token"],
                },
            ).status_code
            == 400
        )
        response = client.post(
            "/revoke", data={"client_id": client_id, "token": refreshed.json()["access_token"]}
        )
        assert response.status_code == 200, response.text
        headers["Authorization"] = "Bearer " + refreshed.json()["access_token"]
        assert client.post("/mcp", headers=headers, json={}).status_code == 401


def test_remote_registration_resource_and_cookie_isolation(env):
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        assert (
            client.post(
                "/register", json={"redirect_uris": ["http://evil.example/callback"]}
            ).status_code
            == 400
        )
        client_id = registered(client)
        response = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://127.0.0.1:9876/callback",
                "code_challenge": "x" * 43,
                "code_challenge_method": "S256",
                "resource": "https://another.example/mcp",
            },
            follow_redirects=False,
        )
        # OAuth errors are returned to the registered client; no authorization ticket is created.
        assert response.status_code == 400 or "error=" in response.headers.get("location", "")
        assert client.post("/auth/session", json={"token": "A" * 40}).status_code == 200
        assert (
            client.post(
                "/mcp", headers={"Accept": "application/json, text/event-stream"}, json={}
            ).status_code
            == 401
        )


def test_consent_decision_clears_request_cookie(env):
    from test_oauth import IdentityProvider

    env.github.now = int(time.time())
    env.hub.integrations.provider = IdentityProvider(env)
    env.hub.integrations.save_config("oauth", {"client_id": "client", "client_secret": "secret"})
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        client_id = registered(client)
        for allow in [True, False]:
            response = client.get(
                "/authorize",
                params={
                    "client_id": client_id,
                    "response_type": "code",
                    "redirect_uri": "http://127.0.0.1:9876/callback",
                    "scope": "work",
                    "code_challenge": "x" * 43,
                    "code_challenge_method": "S256",
                },
                follow_redirects=False,
            )
            consent_url = urlsplit(response.headers["location"])
            request_id = parse_qs(consent_url.query)["request_id"][0]
            client.get(consent_url.path + "?" + consent_url.query, follow_redirects=False)
            assert client.cookies.get("workhub_mcp_request") == request_id
            decided = client.post(
                f"/v1/mcp/consent/{request_id}", headers=env.users["bob"], json={"allow": allow}
            )
            assert decided.status_code == 200
            assert "workhub_mcp_request" not in client.cookies
        # A later browser sign-in returns to the dashboard, not to a consumed request.
        start = client.post("/auth/start", json={"kind": "login", "provider": "oauth"})
        state = parse_qs(urlsplit(start.json()["authorization_url"]).query)["state"][0]
        signed_in = client.get(
            "/auth/github/callback", params={"state": state, "code": "bob"}, follow_redirects=False
        )
        assert signed_in.headers["location"] == "/"
