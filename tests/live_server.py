"""Run the hub on a real loopback socket for browser and MCP SDK client tests."""

import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import replace

import uvicorn

from workhub.api import create_app


@contextmanager
def serve(env, clock=None):
    from test_oauth import IdentityProvider

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    app = create_app(
        replace(env.hub.settings, public_url=origin),
        github_factory=env.github,
        clock=clock or (lambda: env.github.now),
        database=env.hub.db,
    )
    app.state.hub.integrations.provider = IdentityProvider(env)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        app.state.hub.db.engine.dispose()
