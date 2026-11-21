"""Cloudflare Workers entry point. Imported only inside the Python Workers runtime.

One Durable Object instance owns the hub's SQLite database and serves every request, so hub
decisions are serialized exactly as the database lock serializes them elsewhere. The Worker
forwards HTTP requests to it and runs the periodic worker cycle from a Cron Trigger.
"""

import asyncio
import os
from contextlib import asynccontextmanager

# Import the application at startup: the Workers runtime applies its package compatibility
# patches (e.g. running anyio.to_thread work inline, as there are no threads) only to modules
# imported while the Worker initializes, not to modules first imported during a request.
import anyio.to_thread  # noqa: F401
import httpx
import js
from pyodide.ffi import JsException, run_sync, to_js
from workers import DurableObject, WorkerEntrypoint

import workhub.github
from workhub.api import create_app
from workhub.config import Settings
from workhub.db import Database
from workhub.durable import WorkersStorage

ENVIRONMENT = [
    "WORKHUB_ENCRYPTION_KEY",
    "WORKHUB_ADMIN_TOKEN",
    "WORKHUB_PUBLIC_URL",
    "WORKHUB_LEASE_SECONDS",
    "WORKHUB_MAX_WORK_MINUTES",
    "WORKHUB_SYNC_SECONDS",
    "WORKHUB_SESSION_SECONDS",
    "WORKHUB_ADMIN_GITHUB_IDS",
    "GITHUB_OAUTH_CLIENT_ID",
    "GITHUB_OAUTH_CLIENT_SECRET",
    "GITHUB_APP_ID",
    "GITHUB_APP_SLUG",
    "GITHUB_APP_CLIENT_ID",
    "GITHUB_APP_CLIENT_SECRET",
    "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_WEBHOOK_SECRET",
]
OBJECT_NAME = "hub"
# Request headers the fetch API computes itself.
FETCH_MANAGED = {"host", "content-length", "accept-encoding", "connection", "transfer-encoding"}


class FetchTransport(httpx.BaseTransport):
    """Synchronous httpx transport over the Workers fetch API that keeps every request header.

    The runtime's bundled transport drops User-Agent, a browser restriction that Workers do not
    have, and GitHub rejects API requests without one.
    """

    def handle_request(self, request):
        headers = js.Headers.new()
        for name, value in request.headers.multi_items():
            if name.lower() not in FETCH_MANAGED:
                headers.append(name, value)
        init = js.Object.new()
        init.method, init.headers, init.redirect = request.method, headers, "manual"
        body = request.read()
        if body:
            init.body = to_js(body)
        timeout = (request.extensions.get("timeout") or {}).get("read") or 30
        init.signal = js.AbortSignal.timeout(int(timeout * 1000))
        try:
            response = run_sync(js.fetch(str(request.url), init))
            content = run_sync(response.arrayBuffer()).to_bytes()
        except JsException as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc
        # fetch has already decoded the body; drop headers that describe the encoded form.
        received = [
            (str(pair[0]), str(pair[1]))
            for pair in response.headers.entries()
            if str(pair[0]).lower() not in {"content-encoding", "content-length"}
        ]
        return httpx.Response(response.status, headers=received, content=content, request=request)


@asynccontextmanager
async def started(_app):
    yield


class HubStore(DurableObject):
    def __init__(self, ctx, env):
        self.ctx, self.env = ctx, env
        self.app = None
        self.lifespan = None

    async def ready(self):
        if self.app is not None:
            return self.app
        for name in ENVIRONMENT:
            value = getattr(self.env, name, None)
            if isinstance(value, str) and value:
                os.environ[name] = value
        os.environ["WORKHUB_DATABASE_URL"] = "cloudflare-durable-object"
        workhub.github.TRANSPORT = FetchTransport()
        app = create_app(
            Settings.from_env(), database=Database(storage=WorkersStorage(self.ctx.storage.sql))
        )
        # The Workers ASGI adapter runs lifespan startup/shutdown around every request, but the
        # MCP session managers start once. Hold the real lifespan open for this instance.
        lifespan, opened = app.router.lifespan_context, asyncio.Event()

        async def hold():
            async with lifespan(app):
                opened.set()
                await asyncio.Event().wait()

        self.lifespan = asyncio.ensure_future(hold())
        await opened.wait()
        app.router.lifespan_context = started
        self.app = app
        return app

    async def fetch(self, request):
        import asgi

        return await asgi.fetch(await self.ready(), request.js_object, self.env)

    async def tick(self):
        """One `workhub worker --once` cycle: drain webhooks, then discover and reconcile."""
        hub = (await self.ready()).state.hub
        hub.webhooks.drain()
        result = hub.sync()
        return len(result.get("errors", []))


class Default(WorkerEntrypoint):
    def store(self):
        return self.env.HUB.get(self.env.HUB.idFromName(OBJECT_NAME))

    async def fetch(self, request):
        return await self.store().fetch(request.js_object)

    async def scheduled(self, controller, env, ctx):
        errors = await self.store().tick()
        print(f"workhub worker cycle complete: {errors} source error(s)")
