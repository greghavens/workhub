"""`workhub deploy`: generated Cloudflare project, secrets, deployment flow, and local Compose."""

import json
from importlib.metadata import version

import httpx
import pytest

import workhub.deploy as deploy
import workhub.github
from workhub.client import ClientError
from workhub.deploy import Cloudflare, local


def config(directory):
    return json.loads((directory / "wrangler.jsonc").read_text().split("\n", 1)[1])


class Runner:
    def __init__(self, outputs=None):
        self.calls, self.outputs = [], outputs or {}

    def __call__(self, args, cwd=None, env=None, capture=True):
        self.calls.append(args)
        for key, value in self.outputs.items():
            if key in " ".join(args):
                return value.pop(0) if isinstance(value, list) else value
        return ""


def test_build_generates_worker_project(tmp_path):
    target = Cloudflare(tmp_path, name="team-hub", domain="hub.example.com", sync_seconds=300)
    target.build("https://hub.example.com")
    wrangler = config(tmp_path)
    assert wrangler["main"] == "src/entry.py"
    assert "python_workers" in wrangler["compatibility_flags"]
    assert wrangler["durable_objects"]["bindings"] == [{"name": "HUB", "class_name": "HubStore"}]
    assert wrangler["migrations"] == [{"tag": "v1", "new_sqlite_classes": ["HubStore"]}]
    assert wrangler["triggers"]["crons"] == ["*/5 * * * *"]
    assert wrangler["vars"]["WORKHUB_PUBLIC_URL"] == "https://hub.example.com"
    assert wrangler["routes"] == [{"pattern": "hub.example.com", "custom_domain": True}]
    assert "WORKHUB_ENCRYPTION_KEY" not in json.dumps(wrangler)
    package = json.loads((tmp_path / "package.json").read_text())
    assert package["devDependencies"] == {"wrangler": deploy.WRANGLER_VERSION}
    pyproject = (tmp_path / "pyproject.toml").read_text()
    for local_only in ("psycopg", "typer", "dotenv", "uvicorn"):
        assert local_only not in pyproject
    assert '"mcp<2,>=1.12"' in pyproject and "sqlalchemy" in pyproject
    source = tmp_path / "src"
    assert (
        "from workhub.cloudflare_worker import Default, HubStore"
        in (source / "entry.py").read_text()
    )
    assert (source / "workhub" / "durable.py").exists()
    assert (source / "workhub" / "static" / "app.js").exists()
    assert not list(source.rglob("__pycache__"))
    metadata = source / f"workhub-{version('workhub')}.dist-info" / "METADATA"
    assert f"Version: {version('workhub')}" in metadata.read_text()
    # Rebuilding replaces the package instead of merging stale files.
    (source / "workhub" / "stale.py").write_text("")
    target.build("https://hub.example.com")
    assert not (source / "workhub" / "stale.py").exists()


def test_secrets_are_generated_once_with_owner_only_permissions(tmp_path):
    target = Cloudflare(tmp_path / "cf")
    first = target.secrets()
    assert target.secrets_path.stat().st_mode & 0o777 == 0o600
    assert Cloudflare(tmp_path / "cf").secrets() == first
    assert len(first["WORKHUB_ADMIN_TOKEN"]) >= 32


def test_first_workers_dev_deploy_redeploys_with_the_real_url(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, "wait_healthy", lambda url: {"status": "ok", "version": "x"})
    monkeypatch.setattr(Cloudflare, "tool_environment", lambda self: {})
    runner = Runner(
        {
            "whoami": "You are logged in with an OAuth Token",
            "deploy": [
                "Uploaded workhub\n  https://workhub.team.workers.dev\nCurrent Version ID: 1",
                "Uploaded workhub\n  https://workhub.team.workers.dev\nCurrent Version ID: 2",
            ],
        }
    )
    target = Cloudflare(tmp_path, runner=runner)
    url, _ = target.deploy()
    assert url == "https://workhub.team.workers.dev"
    assert ["npm", "install", "--no-audit", "--no-fund"] in runner.calls
    deploys = [c for c in runner.calls if "deploy" in c]
    assert len(deploys) == 2
    assert all(str(target.secrets_path.resolve()) in c for c in deploys)
    assert config(tmp_path)["vars"]["WORKHUB_PUBLIC_URL"] == url
    assert json.loads(target.state_path.read_text())["url"] == url
    # Later deployments already know the URL and deploy once.
    runner.outputs["deploy"] = ["Uploaded workhub\n  https://workhub.team.workers.dev"]
    runner.calls.clear()
    target.deploy()
    assert len([c for c in runner.calls if "deploy" in c]) == 1


def test_custom_domain_deploys_once_and_login_is_required(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, "wait_healthy", lambda url: {"status": "ok", "version": "x"})
    monkeypatch.setattr(Cloudflare, "tool_environment", lambda self: {})
    runner = Runner({"whoami": "logged in", "deploy": "Uploaded"})
    url, _ = Cloudflare(tmp_path, domain="hub.example.com", runner=runner).deploy()
    assert url == "https://hub.example.com"
    assert len([c for c in runner.calls if "deploy" in c]) == 1
    signed_out = Runner({"whoami": "You are not authenticated. Please run `wrangler login`."})
    with pytest.raises(ClientError, match="wrangler login"):
        Cloudflare(tmp_path / "other", runner=signed_out).deploy()


def test_invalid_names_and_domains_are_rejected(tmp_path):
    with pytest.raises(ClientError):
        Cloudflare(tmp_path, name="Bad_Name")
    with pytest.raises(ClientError):
        Cloudflare(tmp_path, domain="https://hub.example.com/path")


def test_old_uv_uses_a_private_newer_uv(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy.shutil, "which", lambda name: "/usr/bin/" + name)
    runner = Runner({"uv --version": "uv 0.9.26", "find_uv_bin": "/private/uv/bin\n"})
    environment = Cloudflare(tmp_path, runner=runner).tool_environment()
    assert environment["PATH"].startswith("/private/uv/bin")
    current = Runner({"uv --version": "uv 0.14.0"})
    Cloudflare(tmp_path, runner=current).tool_environment()
    assert len(current.calls) == 1
    monkeypatch.setattr(deploy.shutil, "which", lambda name: None)
    with pytest.raises(ClientError, match="Node.js"):
        Cloudflare(tmp_path, runner=current).tool_environment()


def test_local_deploy_creates_private_env_and_starts_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, "wait_healthy", lambda url: {"status": "ok", "version": "x"})
    monkeypatch.setattr(deploy.shutil, "which", lambda name: "/usr/bin/" + name)
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n")
    env_file = tmp_path / ".env"
    runner = Runner()
    url, _ = local(env_file, compose, runner=runner)
    assert url == "http://127.0.0.1:8000"
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert "WORKHUB_POSTGRES_PASSWORD=" in env_file.read_text()
    up = runner.calls[-1]
    assert up[:2] == ["docker", "compose"] and up[-3:] == ["up", "-d", "--build"]
    assert str(env_file) in up

    # An installed docker CLI without a reachable engine falls back to podman.
    class NoDockerEngine(Runner):
        def __call__(self, args, cwd=None, env=None, capture=True):
            if args[:2] == ["docker", "info"]:
                raise ClientError("permission denied")
            return super().__call__(args, cwd, env, capture)

    fallback = NoDockerEngine()
    local(env_file, compose, runner=fallback)
    assert fallback.calls[-1][:2] == ["podman", "compose"]
    with pytest.raises(ClientError, match="missing.yaml not found"):
        local(env_file, tmp_path / "missing.yaml", runner=runner)


def test_every_github_client_sends_a_user_agent(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.headers.get("User-Agent"))
        return httpx.Response(200, json={"access_token": "x", "login": "a", "id": 1})

    monkeypatch.setattr(workhub.github, "TRANSPORT", httpx.MockTransport(handler))
    with workhub.github.GitHub("token") as github:
        github.client.get("/user")
    from workhub.integrations import GitHubIdentityProvider

    GitHubIdentityProvider().request("POST", "https://github.com/login/oauth/access_token")
    assert seen == ["workhub", "workhub"]


def test_first_upload_propagation_error_is_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, "wait_healthy", lambda url: {"status": "ok", "version": "x"})
    monkeypatch.setattr(Cloudflare, "tool_environment", lambda self: {})
    monkeypatch.setattr(deploy.time, "sleep", lambda _: None)

    class Propagating(Runner):
        failures = 1

        def __call__(self, args, cwd=None, env=None, capture=True):
            if "deploy" in args and self.failures:
                self.failures -= 1
                raise ClientError("Uploaded workhub ... This Worker does not exist [code: 10007]")
            return super().__call__(args, cwd, env, capture)

    runner = Propagating({"whoami": "logged in", "deploy": "Uploaded"})
    url, _ = Cloudflare(tmp_path, domain="hub.example.com", runner=runner).deploy()
    assert url == "https://hub.example.com"
    other = Propagating({"whoami": "logged in"})
    other.failures = 0

    def broken(args, cwd=None, env=None, capture=True):
        if "deploy" in args:
            raise ClientError("Authentication error [code: 10000]")
        return other(args, cwd, env, capture)

    with pytest.raises(ClientError, match="10000"):
        Cloudflare(tmp_path / "x", domain="hub.example.com", runner=broken).deploy()
