import time
import webbrowser

from workhub.client import Client, ClientError


def browser_signin(client, data, *, no_browser=False, announce=print, sleep=time.sleep):
    status = client.call("GET", "/auth/status")
    if data.get("provider") == "auto":
        data = {**data, "provider": "oauth" if status["oauth_ready"] else "app"}
    pending = client.call("POST", "/auth/cli/start", json=data)
    url = pending["authorization_url"]
    # The authorization URL must belong to the configured hub, not to response-controlled origins.
    if not url.startswith(client.url + "/auth/cli/"):
        raise ClientError("Hub returned an unexpected sign-in URL")
    announce(f"Open this URL to connect GitHub:\n{url}")
    if not no_browser:
        webbrowser.open(url)
    poll = Client(url=client.url, token=pending["poll_token"])
    deadline = time.monotonic() + pending["expires_in"]
    while time.monotonic() < deadline:
        result = poll.call("GET", f"/auth/cli/{pending['id']}/result")
        if result["status"] == "complete":
            return result
        sleep(min(max(pending.get("interval", 2), 1), 10))
    raise ClientError("GitHub sign-in expired; run the command again")
