"""A real stdio MCP server backed by the real API and an in-memory GitHub fixture."""

import sys
import tempfile
from pathlib import Path

from conftest import Environment, FakeGitHub
from cryptography.fernet import Fernet

from workhub.api import create_app
from workhub.client import ClientError
from workhub.config import Settings
from workhub.mcp_server import create_server


def main():
    with tempfile.TemporaryDirectory() as directory:
        github = FakeGitHub()
        settings = Settings(
            f"sqlite:///{Path(directory) / 'hub.db'}", Fernet.generate_key().decode(), "A" * 40
        )
        environment = Environment(
            create_app(settings, github_factory=github, clock=lambda: github.now), github
        )
        environment.install_source()
        environment.invite("bob")
        environment.sync()

        class APIClient:
            def call(self, method, path, **kwargs):
                response = environment.client.request(
                    method,
                    path,
                    headers=environment.admin if "--pm" in sys.argv else environment.users["bob"],
                    **kwargs,
                )
                if response.is_error:
                    raise ClientError(response.json()["detail"], response.status_code)
                result = response.json()
                if path == "/v1/work/claim" and "contract" in result:
                    github.make_pr(result)
                return result

        server, heartbeat = create_server(APIClient())
        try:
            server.run(transport="stdio")
        finally:
            heartbeat.close()
            environment.client.close()


if __name__ == "__main__":
    main()
