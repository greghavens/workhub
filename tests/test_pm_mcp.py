import asyncio
import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError

from workhub.client import ClientError
from workhub.mcp_server import create_server


class LocalClient:
    def __init__(self, env, headers):
        self.env, self.headers = env, headers

    def call(self, method, path, **kwargs):
        response = self.env.client.request(method, path, headers=self.headers, **kwargs)
        if response.is_error:
            raise ClientError(response.json()["detail"], response.status_code)
        return response.json()


def test_pm_tool_lifecycle_and_scope_change_revokes_work(env):
    async def exercise():
        server, heartbeat = create_server(LocalClient(env, env.admin), auto_heartbeat=False)

        async def call(tool_name, **arguments):
            result = await server.call_tool(tool_name, arguments)
            # FastMCP may return (content, structuredContent) for typed tools.
            content = result[0] if isinstance(result, tuple) else result
            value = result[1] if isinstance(result, tuple) else json.loads(content[0].text)
            return (
                value["result"] if isinstance(value, dict) and set(value) == {"result"} else value
            )

        try:
            assert (await call("hub_identity"))["role"] == "admin"
            assert (await call("sources_list"))[0]["name"] == "alice"
            assert len(await call("repositories_list", source="alice")) == 2
            # The PM creates its issue directly in GitHub, outside the hub.
            with env.github("alice-token") as github:
                draft = github.create_issue(
                    "alice/widget",
                    {
                        "title": "Accessible navigation",
                        "body": "Acceptance: keyboard regression tests pass.",
                    },
                )
            assert not draft["labels"]
            assert any(
                i["number"] == draft["number"]
                for i in await call("issues_list", source="alice", repository="alice/widget")
            )
            # The PM approves in GitHub with its own GitHub tools; the hub verifies the label.
            env.github.label("alice/widget", draft["number"])
            approved = await call(
                "task_approve",
                source="alice",
                repository="alice/widget",
                issue_number=draft["number"],
            )
            task_id = approved["task_id"]
            await call("task_dependencies_set", task_id=task_id, dependencies=[])
            claim = env.claim(task_id=task_id).json()
            env.github.make_pr(claim)
            assert (
                await call("pr_inspect", source="alice", repository="alice/widget", pull_number=9)
            )["pull_request"]["state"] == "open"
            # External specification changes invalidate work at the next live check.
            with env.github("alice-token") as github:
                github.update_issue(
                    "alice/widget", draft["number"], {"body": "Revised acceptance criteria."}
                )
            assert env.action("bob", claim, "heartbeat").status_code == 409
            detail = await call("task_get", task_id=task_id)
            assert detail["approval_history"]
            invite = await call("contributor_invite", name="new-friend")
            assert any(c["id"] == invite["id"] for c in await call("contributors_list"))
            await call("contributor_revoke", contributor_id=invite["id"])
            assert await call("audit_list")
        finally:
            heartbeat.close()

    asyncio.run(exercise())


def test_remote_pm_oauth_admin_scope_and_revocation(env):
    from test_remote_mcp import PM, authorize, registered

    env.github.now = int(time.time())
    env.hub.integrations.save_config("admins", {"ids": [1]})
    owner_token = env.app.state.auth.session("admin", github_id=1)
    owner = {"Authorization": "Bearer " + owner_token}
    with TestClient(env.app, base_url="http://127.0.0.1:8000") as client:
        client_id = registered(client, "work admin")
        with pytest.raises(AssertionError, match="Only a linked owner"):
            authorize(env, client, client_id, scope="work admin", resource=PM)
        exchange = authorize(env, client, client_id, scope="work admin", headers=owner, resource=PM)
        response = client.post("/token", data=exchange)
        assert response.status_code == 200, response.text
        tokens = response.json()
        headers = {
            "Authorization": "Bearer " + tokens["access_token"],
            "Accept": "application/json, text/event-stream",
        }

        def call(name, arguments=None):
            response = client.post(
                "/mcp/pm",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments or {}},
                },
            )
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert not result.get("isError"), result
            return json.loads(result["content"][0]["text"])

        assert call("hub_identity")["role"] == "admin"
        assert call("hub_status")["authenticated"]
        with env.github("alice-token") as github:
            created = github.create_issue(
                "alice/widget",
                {"title": "PM-created work", "body": "Acceptance: regression tests pass"},
            )
        env.github.label("alice/widget", created["number"])
        approved = call(
            "task_approve",
            {"source": "alice", "repository": "alice/widget", "issue_number": created["number"]},
        )
        assert call("task_get", {"task_id": approved["task_id"]})["approval"]
        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": tokens["refresh_token"],
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        headers["Authorization"] = "Bearer " + refreshed.json()["access_token"]
        assert call("hub_identity")["role"] == "admin"
        env.hub.integrations.save_config("admins", {"ids": []})
        assert client.post("/mcp/pm", headers=headers, json={}).status_code == 401
        assert (
            client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refreshed.json()["refresh_token"],
                },
            ).status_code
            == 400
        )


def test_mcp_connections_are_browser_bound_and_monitorable(env):
    from test_oauth import IdentityProvider

    env.hub.integrations.provider = IdentityProvider(env)
    env.hub.integrations.save_config("oauth", {"client_id": "client", "client_secret": "secret"})

    async def exercise():
        server, _ = create_server(LocalClient(env, env.admin), auto_heartbeat=False)

        async def call(name, arguments):
            result = await server.call_tool(name, arguments)
            content = result[0] if isinstance(result, tuple) else result
            value = result[1] if isinstance(result, tuple) else json.loads(content[0].text)
            return (
                value["result"] if isinstance(value, dict) and set(value) == {"result"} else value
            )

        # Sign-in is identity only; repositories are connected through the read-only App.
        with pytest.raises(ToolError, match="read-only GitHub App"):
            await call("github_connect_start", {"kind": "source", "name": "agent-source"})
        app = await call("github_app_register", {"name": "Agent Work Hub"})
        first = env.client.get(
            urlsplit(app["authorization_url"]).path
            + "?"
            + urlsplit(app["authorization_url"]).query,
            follow_redirects=False,
        )
        assert first.status_code == 303
        assert (
            env.client.get(
                urlsplit(app["authorization_url"]).path
                + "?"
                + urlsplit(app["authorization_url"]).query
            ).status_code
            == 410
        )
        page = env.client.get(first.headers["location"])
        assert page.status_code == 200
        state = parse_qs(urlsplit(first.headers["location"]).query)["state"][0]
        assert (
            env.client.get(
                "/auth/github/app/manifest/callback",
                params={"state": state, "code": "manifest"},
                follow_redirects=False,
            ).status_code
            == 303
        )
        assert (await call("github_connect_status", {"request_id": app["id"]}))[
            "status"
        ] == "complete"
        assert (
            env.client.get(f"/v1/connections/{app['id']}", headers=env.users["bob"]).status_code
            == 404
        )
        installed = await call("github_app_install", {"name": "agent-app-source"})
        start = env.client.get(
            urlsplit(installed["authorization_url"]).path
            + "?"
            + urlsplit(installed["authorization_url"]).query,
            follow_redirects=False,
        )
        state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
        assert (
            env.client.get(
                "/auth/github/app/installed",
                params={"state": state, "installation_id": 99},
                follow_redirects=False,
            ).status_code
            == 303
        )
        assert (await call("github_connect_status", {"request_id": installed["id"]}))[
            "status"
        ] == "complete"

    asyncio.run(exercise())


def test_contributor_cannot_use_pm_operations_or_spoof_bridge(env):
    for method, path, body in [
        ("GET", "/v1/admin/issues?source=alice&repository=alice/widget", None),
        ("POST", "/v1/admin/contributors", {"name": "bad"}),
        (
            "POST",
            "/v1/admin/approve",
            {"source": "alice", "repository": "alice/widget", "issue_number": 1},
        ),
    ]:
        response = env.client.request(
            method, path, headers={**env.users["bob"], "workhub.principal": "admin"}, json=body
        )
        assert response.status_code == 403


async def tool(server, tool_name, /, **arguments):
    result = await server.call_tool(tool_name, arguments)
    content = result[0] if isinstance(result, tuple) else result
    value = result[1] if isinstance(result, tuple) else json.loads(content[0].text)
    text = "".join(getattr(part, "text", "") for part in content)
    value = value["result"] if isinstance(value, dict) and set(value) == {"result"} else value
    return value, text


def test_stdio_login_keeps_poll_and_session_secrets_in_adapter(env, tmp_path, monkeypatch):
    from test_oauth import IdentityProvider

    from workhub.client import Client
    from workhub.domain import token_hash
    from workhub.models import AuthFlow

    for name in ["WORKHUB_URL", "WORKHUB_TOKEN", "WORKHUB_ADMIN_TOKEN"]:
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "private" / "client.json"
    monkeypatch.setenv("WORKHUB_CLIENT_CONFIG", str(config))
    env.hub.integrations.provider = IdentityProvider(env)
    env.hub.integrations.save_config("oauth", {"client_id": "client", "client_secret": "secret"})
    env.github.identities["dave-token"] = {"id": 44, "login": "dave"}
    env.github.access["dave-token"] = {"alice/widget"}
    env.github.push["dave-token"] = set()
    invitation = env.client.post(
        "/v1/admin/contributors", headers=env.admin, json={"name": "dave"}
    ).json()

    origin = "http://127.0.0.1:8000"
    adapter = Client(url=origin, allow_anonymous=True)
    adapter.http.close()
    adapter.http = TestClient(env.app, base_url=origin)
    browser = TestClient(env.app, base_url=origin)

    async def exercise():
        server, heartbeat = create_server(adapter, auto_heartbeat=False)
        try:
            with pytest.raises(Exception, match="Sign in to Work Hub"):
                await tool(server, "hub_identity")
            started, text = await tool(server, "hub_login_start", invitation=invitation["token"])
            assert set(started) == {"id", "expires_in", "interval", "authorization_url"}
            with env.hub.db.read() as session:
                flow = session.get(AuthFlow, started["id"])
                poll_hash = flow.poll_hash
            # No substring of the tool output is the poll secret.
            assert not any(token_hash(word.strip('",{}:')) == poll_hash for word in text.split())
            pending, _ = await tool(server, "hub_login_status", request_id=started["id"])
            assert pending == {"status": "pending"}
            assert not config.exists()

            redirect = browser.get(
                urlsplit(started["authorization_url"]).path, follow_redirects=False
            )
            state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
            completed = browser.get(
                "/auth/github/callback", params={"state": state, "code": "dave"}
            )
            assert completed.status_code == 200
            assert "workhub_session" not in browser.cookies

            done, text = await tool(server, "hub_login_status", request_id=started["id"])
            assert done["status"] == "complete"
            assert done["role"] == "contributor" and done["github_login"] == "dave"
            assert "token" not in done
            saved = json.loads(config.read_text())
            assert saved["url"] == origin and saved["role"] == "contributor"
            assert saved["token"] not in text
            assert config.stat().st_mode & 0o777 == 0o600
            assert adapter.http.headers["Authorization"] == "Bearer " + saved["token"]

            identity, _ = await tool(server, "hub_identity")
            assert identity["role"] == "contributor"
            assert identity["contributor_id"] == invitation["id"]
            assert isinstance((await tool(server, "work_list"))[0], list)
            # The completed request is no longer owned by the adapter, and the invitation is spent.
            with pytest.raises(Exception, match="not owned by this adapter"):
                await tool(server, "hub_login_status", request_id=started["id"])
            with pytest.raises(Exception, match="not owned by this adapter"):
                await tool(server, "hub_login_status", request_id="someone-elses-request")
            with pytest.raises(Exception, match="Invalid or revoked contributor token"):
                await tool(server, "hub_login_start", invitation=invitation["token"])
        finally:
            heartbeat.close()

    asyncio.run(exercise())
    # A fresh stdio adapter starts from the privately saved session.
    restarted = Client(allow_anonymous=True)
    assert (
        restarted.http.headers["Authorization"]
        == "Bearer " + json.loads(config.read_text())["token"]
    )
    restarted.http.close()


def test_mcp_initiated_connections_leave_no_unretrievable_sessions(env):
    from sqlalchemy import func, select
    from test_oauth import IdentityProvider

    from workhub.models import AuthFlow, HubSession

    env.hub.integrations.provider = IdentityProvider(env)
    env.hub.integrations.save_config("oauth", {"client_id": "client", "client_secret": "secret"})

    def sessions():
        with env.hub.db.read() as session:
            return session.scalar(select(func.count()).select_from(HubSession))

    def complete(started, code):
        redirect = env.client.get(
            urlsplit(started["authorization_url"]).path, follow_redirects=False
        )
        state = parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]
        page = env.client.get("/auth/github/callback", params={"state": state, "code": code})
        assert page.status_code == 200 and "workhub_session" not in page.cookies
        with env.hub.db.read() as session:
            flow = session.get(AuthFlow, started["id"])
            assert flow.status == "complete" and flow.result is None

    async def exercise():
        before = sessions()
        owner, _ = create_server(LocalClient(env, env.admin), auto_heartbeat=False)
        started, _ = await tool(owner, "github_connect_start", kind="admin_link")
        complete(started, "alice")
        assert 1 in env.hub.integrations.config("admins")["ids"]
        assert (await tool(owner, "github_connect_status", request_id=started["id"]))[0][
            "status"
        ] == "complete"

        bob, _ = create_server(LocalClient(env, env.users["bob"]), auto_heartbeat=False)
        started, _ = await tool(bob, "github_connect_start", kind="contributor")
        complete(started, "bob")
        assert (await tool(bob, "github_connect_status", request_id=started["id"]))[0][
            "status"
        ] == "complete"
        assert sessions() == before

    asyncio.run(exercise())


def test_mcp_app_handoff_failures_are_reported_without_provider_detail(env):
    from test_oauth import IdentityProvider

    provider = IdentityProvider(env)
    env.hub.integrations.provider = provider

    def follow(handoff):
        url = urlsplit(handoff["authorization_url"])
        start = env.client.get(url.path + "?" + url.query, follow_redirects=False)
        return parse_qs(urlsplit(start.headers["location"]).query)["state"][0]

    async def exercise():
        server, _ = create_server(LocalClient(env, env.admin), auto_heartbeat=False)

        def broken_manifest(code):
            raise RuntimeError("upstream said client_secret=leaked-value")

        provider.convert_manifest = broken_manifest
        handoff, _ = await tool(server, "github_app_register", name="Broken Hub")
        state = follow(handoff)
        with pytest.raises(RuntimeError):
            env.client.get(
                "/auth/github/app/manifest/callback", params={"state": state, "code": "x"}
            )
        status, text = await tool(server, "github_connect_status", request_id=handoff["id"])
        assert status["status"] == "failed"
        assert status["error"] == "GitHub App registration failed; restart registration"
        assert "leaked-value" not in text
        # A failed flow cannot be replayed.
        replay = env.client.get(
            "/auth/github/app/manifest/callback", params={"state": state, "code": "x"}
        )
        assert replay.status_code == 400

        env.hub.integrations.save_config(
            "app", {"app_id": "123", "slug": "workhub-test", "private_key": "test-key"}
        )
        provider.installation = lambda config, installation_id: {
            "id": installation_id,
            "app_id": 999,
            "account": {"id": 1, "login": "alice", "type": "User"},
        }
        handoff, _ = await tool(server, "github_app_install", name="wrong-app")
        response = env.client.get(
            "/auth/github/app/installed",
            params={"state": follow(handoff), "installation_id": 77},
            follow_redirects=False,
        )
        assert response.status_code == 403
        status, _ = await tool(server, "github_connect_status", request_id=handoff["id"])
        assert status == {
            "id": handoff["id"],
            "kind": "installation",
            "status": "failed",
            "error": "Installation does not belong to this active GitHub App",
        }

    asyncio.run(exercise())
