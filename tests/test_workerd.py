"""The Cloudflare build running in workerd (`wrangler dev`). Needs Node.js and network access to
install the Worker's packages, so it is opt-in: WORKHUB_WORKERD_TESTS=1."""

import json
import os
import shutil
import signal
import socket
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

from workhub.deploy import Cloudflare

pytestmark = pytest.mark.skipif(
    os.getenv("WORKHUB_WORKERD_TESTS") != "1",
    reason="Enable workerd checks with WORKHUB_WORKERD_TESTS=1",
)
ROOT = Path(__file__).parents[1]

CHECK_ENTRY = """
import uuid

from workers import DurableObject, Response

import adapter_check
from workhub.cloudflare_worker import Default as HubWorker, HubStore  # noqa: F401


class AdapterCheck(DurableObject):
    def __init__(self, ctx, env):
        self.ctx, self.env = ctx, env

    async def fetch(self, request):
        import json

        return Response(json.dumps(adapter_check.run(self.ctx.storage.sql)))


class Default(HubWorker):
    async def fetch(self, request):
        if request.url.endswith("/__adapter_check"):
            stub = self.env.CHECK.get(self.env.CHECK.idFromName(str(uuid.uuid4())))
            return await stub.fetch(request.js_object)
        return await super().fetch(request)
"""


@pytest.fixture(scope="module")
def worker():
    directory = ROOT / ".workhub" / "test-workerd"
    shutil.rmtree(directory / ".wrangler", ignore_errors=True)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    target = Cloudflare(directory, name="workhub-test")
    url = f"http://127.0.0.1:{port}"
    target.build(url)
    # Test-only additions: an extra Durable Object that runs the adapter scenarios in workerd.
    shutil.copy(ROOT / "tests" / "workerd_adapter_check.py", directory / "src" / "adapter_check.py")
    (directory / "src" / "entry.py").write_text(CHECK_ENTRY)
    config = json.loads((directory / "wrangler.jsonc").read_text().split("\n", 1)[1])
    config["durable_objects"]["bindings"].append({"name": "CHECK", "class_name": "AdapterCheck"})
    config["migrations"][0]["new_sqlite_classes"].append("AdapterCheck")
    (directory / "wrangler.jsonc").write_text(json.dumps(config, indent=2))
    secrets = target.secrets()
    (directory / ".dev.vars").write_text(
        "".join(f"{k}={json.dumps(v)}\n" for k, v in {**secrets, "WORKHUB_PUBLIC_URL": url}.items())
    )
    target.ensure_wrangler()
    log = open(directory / "dev.log", "w")
    process = subprocess.Popen(
        [
            "uvx",
            "--from",
            "workers-py",
            "pywrangler",
            "dev",
            "--ip",
            "127.0.0.1",
            "--port",
            str(port),
            "--test-scheduled",
        ],
        cwd=directory,
        env=target.tool_environment(),
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        for _ in range(300):
            try:
                if httpx.get(url + "/health", timeout=5).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if process.poll() is not None:
                raise AssertionError((directory / "dev.log").read_text()[-4000:])
            time.sleep(1)
        else:
            raise AssertionError("workerd did not become healthy")
        yield url, secrets["WORKHUB_ADMIN_TOKEN"], directory / "dev.log"
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=30)
        log.close()


def test_adapter_rolls_back_inside_a_real_durable_object(worker):
    url, _, _ = worker
    results = httpx.get(url + "/__adapter_check", timeout=60).json()
    assert results and all(value == "ok" for value in results.values()), results


def test_hub_serves_from_a_durable_object(worker):
    url, token, log = worker
    admin = {"Authorization": "Bearer " + token}
    with httpx.Client(base_url=url, timeout=30) as http:
        assert http.get("/health").json()["version"]
        assert http.get("/").status_code == 200
        assert http.get("/assets/app.js").status_code == 200
        name = "friend-" + uuid.uuid4().hex[:8]
        created = http.post("/v1/admin/contributors", headers=admin, json={"name": name})
        assert created.status_code == 200, created.text
        audit = len(http.get("/v1/admin/audit", headers=admin).json())
        duplicate = http.post("/v1/admin/contributors", headers=admin, json={"name": name})
        assert duplicate.status_code == 409
        assert len(http.get("/v1/admin/audit", headers=admin).json()) == audit
        assert {c["name"] for c in http.get("/v1/admin/contributors", headers=admin).json()} >= {
            name
        }
        pm = http.get("/.well-known/oauth-protected-resource/mcp/pm").json()
        assert pm["scopes_supported"] == ["work", "admin"]
        assert http.post("/mcp/pm", json={}).status_code == 401
        # GitHub receives the hub's User-Agent and answers a bad token with 401, not 403.
        friend = {"Authorization": "Bearer " + created.json()["token"]}
        rejected = http.post("/v1/me/github", headers=friend, json={"github_token": "invalid"})
        assert rejected.json().get("upstream_status") == 401, rejected.text
        assert http.get("/cdn-cgi/handler/scheduled", params={"cron": "*/2 * * * *"}).is_success
    for _ in range(20):
        if "workhub worker cycle complete" in log.read_text():
            break
        time.sleep(0.5)
    else:
        raise AssertionError("Cron trigger did not complete a worker cycle")
