"""Role-specific remote MCP endpoints: contributors at /mcp, product managers at /mcp/pm."""

import asyncio
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from live_server import serve
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata
from test_remote_mcp import PM, WORK, authorize, registered

from workhub.models import RemoteAdminGrant, RemoteAuthorization

ACCEPT = "application/json, text/event-stream"
HARNESS = "http://127.0.0.1:9876/callback"


def owner_headers(env):
    env.hub.integrations.save_config("admins", {"ids": [1]})
    return {"Authorization": "Bearer " + env.app.state.auth.session("admin", github_id=1)}


def tokens(client, exchange):
    response = client.post("/token", data=exchange)
    assert response.status_code == 200, response.text
    return response.json()


def rpc(client, path, token, method, params=None):
    return client.post(
        path,
        headers={"Authorization": "Bearer " + token, "Accept": ACCEPT},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )


def test_endpoints_advertise_role_scopes(env):
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        work = client.get("/.well-known/oauth-protected-resource/mcp").json()
        pm = client.get("/.well-known/oauth-protected-resource/mcp/pm").json()
        assert (work["resource"], work["scopes_supported"]) == (WORK, ["work"])
        assert (pm["resource"], pm["scopes_supported"]) == (PM, ["work", "admin"])
        challenge = client.post("/mcp/pm", headers={"Accept": ACCEPT}, json={})
        assert challenge.status_code == 401
        assert (
            'resource_metadata="http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp/pm"'
            in challenge.headers["www-authenticate"]
        )


def test_scope_and_resource_must_match_the_role(env):
    owner = owner_headers(env)
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        client_id = registered(client, "work admin")

        def start(scope, resource=None):
            params = {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": HARNESS,
                "scope": scope,
                "state": "s",
                "code_challenge": "x" * 43,
                "code_challenge_method": "S256",
            }
            if resource:
                params["resource"] = resource
            return client.get("/authorize", params=params, follow_redirects=False)

        for scope, resource, message in [
            ("work admin", WORK, "Product-manager access uses"),
            ("work", PM, "requires scope work admin"),
        ]:
            location = start(scope, resource).headers["location"]
            assert location.startswith(HARNESS)
            query = parse_qs(urlsplit(location).query)
            assert query["error"] == ["invalid_scope"]
            assert message in query["error_description"][0]

        # Clients that omit the RFC 8707 resource are routed by their requested scope.
        for scope, resource in [("work admin", PM), ("work", WORK)]:
            location = start(scope).headers["location"]
            request_id = parse_qs(urlsplit(location).query)["request_id"][0]
            with env.hub.db.read() as session:
                assert session.get(RemoteAuthorization, request_id).params["resource"] == resource

        # An owner's contributor harness at /mcp never receives owner authority.
        with pytest.raises(AssertionError, match="Contributor identity is required"):
            authorize(env, client, registered(client), headers=owner)


def test_tokens_only_work_at_their_endpoint(env):
    env.github.now = int(time.time())
    owner = owner_headers(env)
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        pm_client = registered(client, "work admin")
        pm = tokens(
            client,
            authorize(env, client, pm_client, "work admin", headers=owner, resource=PM),
        )
        assert pm["scope"] == "work admin"
        work_client = registered(client)
        work = tokens(client, authorize(env, client, work_client))
        assert work["scope"] == "work"

        assert rpc(client, "/mcp", pm["access_token"], "tools/list").status_code == 401
        assert rpc(client, "/mcp/pm", work["access_token"], "tools/list").status_code == 401

        listed = rpc(client, "/mcp/pm", pm["access_token"], "tools/list")
        names = {t["name"] for t in listed.json()["result"]["tools"]}
        assert {"task_approve", "contributor_invite", "github_app_register", "work_claim"} <= names
        assert not names & {"hub_login_start", "hub_login_status"}
        identity = rpc(
            client, "/mcp/pm", pm["access_token"], "tools/call", {"name": "hub_identity"}
        ).json()["result"]
        assert json.loads(identity["content"][0]["text"])["role"] == "admin"

        # Refreshing at the PM endpoint cannot narrow the grant into a contributor token.
        narrowed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": pm_client,
                "refresh_token": pm["refresh_token"],
                "scope": "work",
            },
        )
        assert narrowed.status_code == 400

        # Owner grants issued for /mcp before the PM endpoint existed are no longer honoured.
        with env.hub.db.write() as session:
            for grant in session.query(RemoteAdminGrant):
                grant.resource = WORK
        assert rpc(client, "/mcp", pm["access_token"], "tools/list").status_code == 401
        assert rpc(client, "/mcp/pm", pm["access_token"], "tools/list").status_code == 401
        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": pm_client,
                "refresh_token": pm["refresh_token"],
            },
        )
        assert refreshed.status_code == 400


class MemoryStorage:
    def __init__(self):
        self.tokens = self.client_info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client_info

    async def set_client_info(self, client_info):
        self.client_info = client_info


def connect_with_sdk(origin, path, consent_headers):
    """Drive the official MCP SDK OAuth client; the human approves consent with their session."""
    requested, redirects = [], []

    def human(authorization_url):
        requested.append(parse_qs(urlsplit(authorization_url).query).get("scope", [None])[0])
        with httpx.Client(base_url=origin) as browser:
            consent = browser.get(authorization_url, follow_redirects=False)
            request_id = parse_qs(urlsplit(consent.headers["location"]).query)["request_id"][0]
            decided = browser.post(
                f"/v1/mcp/consent/{request_id}", headers=consent_headers, json={"allow": True}
            )
            assert decided.status_code == 200, decided.text
            return decided.json()["redirect_url"]

    async def redirect_handler(authorization_url):
        redirects.append(await asyncio.to_thread(human, authorization_url))

    async def callback_handler():
        query = parse_qs(urlsplit(redirects[-1]).query)
        return query["code"][0], query.get("state", [None])[0]

    storage = MemoryStorage()
    auth = OAuthClientProvider(
        server_url=origin + path,
        client_metadata=OAuthClientMetadata(
            client_name="SDK harness",
            redirect_uris=[HARNESS],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    async def session():
        async with httpx.AsyncClient(auth=auth, follow_redirects=True, timeout=30) as http:
            async with streamable_http_client(origin + path, http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as mcp:
                    await mcp.initialize()
                    names = {tool.name for tool in (await mcp.list_tools()).tools}
                    identity = await mcp.call_tool("hub_identity", {})
                    return names, json.loads(identity.content[0].text)

    names, identity = asyncio.run(session())
    return requested, storage.tokens, names, identity


def test_official_sdk_client_obtains_role_scopes_automatically(env):
    env.github.now = int(time.time())
    owner = owner_headers(env)
    with serve(env, clock=lambda: int(time.time())) as origin:
        requested, granted, names, identity = connect_with_sdk(origin, "/mcp/pm", owner)
        assert requested == ["work admin"] and granted.scope == "work admin"
        assert "task_approve" in names and identity["role"] == "admin"

        requested, granted, names, identity = connect_with_sdk(origin, "/mcp", env.users["bob"])
        assert requested == ["work"] and granted.scope == "work"
        assert "work_claim" in names and "task_approve" not in names
        assert identity["role"] == "contributor"
