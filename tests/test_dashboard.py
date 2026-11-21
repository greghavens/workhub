import os
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from live_server import serve
from playwright.sync_api import expect, sync_playwright

browser_test = pytest.mark.skipif(
    os.getenv("WORKHUB_BROWSER_TESTS") != "1",
    reason="Enable browser checks with WORKHUB_BROWSER_TESTS=1",
)


@browser_test
def test_dashboard_owner_oauth_contributor_and_mobile(env, tmp_path):
    with serve(env) as origin:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin)
            page.get_by_text("Owner setup or existing access token").click()
            page.get_by_label("Hub access token", exact=True).fill("A" * 40)
            page.get_by_role("button", name="Open workspace").click()
            expect(page.get_by_role("heading", name="Work queue", exact=True)).to_be_visible()
            expect(page.get_by_text("All work", exact=True)).to_be_visible()
            page.get_by_role("button", name="View", exact=True).first.click()
            expect(page.get_by_text("Prerequisite work", exact=True)).to_be_visible()
            page.get_by_label("Close dialog").click()
            page.locator('[data-view="people"]').click()
            page.get_by_role("button", name="Invite contributor").click()
            page.get_by_label("Contributor name").fill("browser-friend")
            page.get_by_role("button", name="Create invitation").click()
            expect(page.get_by_role("heading", name="Invite browser-friend")).to_be_visible()
            page.get_by_label("Close dialog").click()
            page.locator('[data-view="settings"]').click()
            # The App is registered and installed, so setup continues at step 3 of 5.
            steps = page.locator(".setup-steps li")
            expect(steps).to_have_count(5)
            expect(steps.nth(0)).to_contain_text("Register the read-only GitHub App")
            expect(steps.nth(0)).to_have_class("done")
            expect(steps.nth(1)).to_have_class("done")
            expect(steps.nth(2)).to_have_class("current")
            expect(steps.nth(2)).to_contain_text("Link your GitHub account as owner")
            expect(steps.nth(3)).to_contain_text("Set up contributor sign-in")
            expect(steps.nth(4)).to_contain_text("Invite contributors")
            page.get_by_role("button", name="Configure sign-in").click()
            page.get_by_label("Client ID", exact=True).fill("browser-client")
            page.get_by_label("Client secret", exact=True).fill("browser-secret")
            page.get_by_role("button", name="Save connection").click()
            expect(page.get_by_role("button", name="Update sign-in credentials")).to_be_visible()
            expect(steps.nth(3)).to_have_class("done")
            page.locator('[data-view="activity"]').click()
            expect(page.get_by_role("heading", name="Webhook deliveries")).to_be_visible()
            page.locator('[data-view="sources"]').click()
            expect(page.get_by_role("heading", name="Account sources")).to_be_visible()
            expect(page.get_by_role("button", name="Add repositories")).to_be_visible()
            page.locator('[data-view="queue"]').click()
            page.screenshot(path=str(tmp_path / "dashboard-desktop.png"), full_page=True)
            page.get_by_role("button", name="Sign out").click()
            expect(page.get_by_role("button", name="Continue with GitHub")).to_be_enabled()

            def github_login(route):
                state = parse_qs(urlsplit(route.request.url).query)["state"][0]
                route.fulfill(
                    status=302,
                    headers={"Location": origin + "/auth/github/callback?code=bob&state=" + state},
                )

            page.route("https://github.com/login/oauth/authorize?*", github_login)
            page.get_by_role("button", name="Continue with GitHub").click()
            expect(page.get_by_role("heading", name="Your work", exact=True)).to_be_visible()
            page.get_by_role("button", name="Claim approved work").click()
            page.get_by_role("button", name="Claim work", exact=True).click()
            expect(page.get_by_role("button", name="Download contract")).to_be_visible()
            page.get_by_role("button", name="Renew lease").click()
            expect(page.get_by_role("button", name="Renew lease")).to_be_enabled()
            # The hub never forks: the contributor gets the command to run themselves.
            page.get_by_role("button", name="Check push repository").click()
            expect(page.get_by_role("heading", name="Create your fork: bob/widget")).to_be_visible()
            expect(page.get_by_text("gh repo fork alice/widget")).to_be_visible()
            page.get_by_label("Close dialog").click()
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(tmp_path / "dashboard-mobile.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert errors == []
            browser.close()


@browser_test
def test_remote_pm_consent_in_browser(env):
    import base64
    import hashlib
    import json
    from urllib.parse import urlencode

    import httpx

    env.github.now = int(time.time())
    env.hub.integrations.save_config("admins", {"ids": [1]})
    env.hub.integrations.save_config("oauth", {"client_id": "client", "client_secret": "secret"})
    verifier = "browser-pm-verifier-" + "v" * 50
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    harness = "http://127.0.0.1:9876/callback"
    with (
        serve(env, clock=lambda: int(time.time())) as origin,
        httpx.Client(base_url=origin) as http,
        sync_playwright() as p,
    ):
        registration = http.post(
            "/register",
            json={
                "client_name": "PM harness",
                "redirect_uris": [harness],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "work admin",
            },
        )
        assert registration.status_code == 201, registration.text
        client_id = registration.json()["client_id"]

        def authorize_url(state):
            return (
                origin
                + "/authorize?"
                + urlencode(
                    {
                        "client_id": client_id,
                        "response_type": "code",
                        "redirect_uri": harness,
                        "scope": "work admin",
                        "state": state,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "resource": origin + "/mcp/pm",
                    }
                )
            )

        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors, returned, github_user = [], [], ["alice"]
        page.on("pageerror", lambda error: errors.append(str(error)))

        def github_login(route):
            state = parse_qs(urlsplit(route.request.url).query)["state"][0]
            route.fulfill(
                status=302,
                headers={
                    "Location": f"{origin}/auth/github/callback?code={github_user[0]}&state={state}"
                },
            )

        def harness_callback(route):
            returned.append(route.request.url)
            route.fulfill(status=200, body="harness received")

        page.route("https://github.com/login/oauth/authorize?*", github_login)
        page.route(harness + "*", harness_callback)
        consent_heading = page.get_by_role("heading", name="Connect your coding harness")

        # Owner without contributor membership signs in through GitHub and grants PM scope.
        page.goto(authorize_url("pm-approve"))
        page.get_by_role("button", name="Continue with GitHub").click()
        expect(consent_heading).to_be_visible()
        expect(
            page.get_by_text(
                "PM harness requests product-manager access: manage GitHub connections, approve "
                "existing issues, set dependencies, and invite or revoke contributors using your "
                "owner authority."
            )
        ).to_be_visible()
        expect(
            page.get_by_text("After authorization, you will return to 127.0.0.1:9876.")
        ).to_be_visible()
        page.get_by_role("button", name="Authorize harness").click()
        page.wait_for_url(harness + "*")
        params = parse_qs(urlsplit(returned[-1]).query)
        assert params["state"] == ["pm-approve"] and "code" in params
        assert "workhub_mcp_request" not in {c["name"] for c in page.context.cookies()}
        tokens = http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": params["code"][0],
                "code_verifier": verifier,
                "redirect_uri": harness,
                "resource": origin + "/mcp/pm",
            },
        )
        assert tokens.status_code == 200, tokens.text
        assert tokens.json()["scope"] == "work admin"

        def mcp(name):
            response = http.post(
                "/mcp/pm",
                headers={
                    "Authorization": "Bearer " + tokens.json()["access_token"],
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": {}},
                },
            )
            assert response.status_code == 200, response.text
            return response.json()["result"]

        identity = json.loads(mcp("hub_identity")["content"][0]["text"])
        assert identity["role"] == "admin" and identity["github_id"] == 1
        assert identity["contributor_id"] is None
        assert json.loads(mcp("tasks_list")["content"][0]["text"]) is not None
        denied = mcp("work_list")
        assert denied["isError"] and "contributor identity" in denied["content"][0]["text"]

        # A later sign-in returns to the dashboard instead of the consumed request.
        page.goto(origin)
        page.get_by_role("button", name="Sign out").click()
        page.get_by_role("button", name="Continue with GitHub").click()
        expect(page.get_by_role("heading", name="Work queue", exact=True)).to_be_visible()
        assert "mcp_request" not in page.url
        expect(consent_heading).to_be_hidden()
        expect(page.locator("#toast.error")).to_have_count(0)

        # Declining returns access_denied to the harness without a code.
        page.goto(authorize_url("pm-decline"))
        expect(consent_heading).to_be_visible()
        page.get_by_role("button", name="Decline").click()
        page.wait_for_url(harness + "*")
        params = parse_qs(urlsplit(returned[-1]).query)
        assert params == {"error": ["access_denied"], "state": ["pm-decline"]}

        # A contributor sees the request but cannot delegate owner authority.
        page.goto(origin)
        page.get_by_role("button", name="Sign out").click()
        github_user[0] = "bob"
        page.goto(authorize_url("pm-contributor"))
        page.get_by_role("button", name="Continue with GitHub").click()
        expect(consent_heading).to_be_visible()
        before = len(returned)
        page.get_by_role("button", name="Authorize harness").click()
        expect(page.locator("#toast.error")).to_have_text(
            "Only a linked owner may delegate product-manager admin scope"
        )
        assert len(returned) == before
        assert errors == []
        browser.close()
