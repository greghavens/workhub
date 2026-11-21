import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path
from typing import Annotated

import typer
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from workhub.client import (
    Client,
    ClientError,
    Heartbeats,
    config_path,
    ensure_push_target,
    write_private,
)
from workhub.domain import HubError

app = typer.Typer(no_args_is_help=True, help="Approved work contracts for coding agents.")
admin = typer.Typer(no_args_is_help=True, help="Manage sources, approval, and contributors.")
work = typer.Typer(no_args_is_help=True, help="Claim and deliver approved work.")
deploy = typer.Typer(no_args_is_help=True, help="Deploy the hub locally or to Cloudflare.")
app.add_typer(admin, name="admin")
app.add_typer(work, name="work")
app.add_typer(deploy, name="deploy")


def output(value):
    typer.echo(json.dumps(value, indent=2))


def git_command(args, cwd=None, input_data=None):
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            input=input_data,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise ClientError(f"{args[0]} exceeded the 120-second command timeout") from exc
    if result.returncode:
        raise ClientError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def assignment(client, task_id):
    result = client.call("GET", f"/v1/work/{task_id}")
    lease = result["assignment"]
    return result, {"attempt_id": lease["attempt_id"], "generation": lease["generation"]}


@app.command()
def init(env_file: Path = Path(".env")):
    """Create owner-only server configuration. Never overwrites an existing file."""
    if env_file.exists():
        raise ClientError(f"{env_file} already exists")
    write_private(
        env_file,
        "\n".join(
            [
                "WORKHUB_DATABASE_URL=sqlite:///workhub.db",
                f"WORKHUB_ENCRYPTION_KEY={Fernet.generate_key().decode()}",
                f"WORKHUB_ADMIN_TOKEN={secrets.token_urlsafe(40)}",
                f"WORKHUB_POSTGRES_PASSWORD={secrets.token_urlsafe(32)}",
                "WORKHUB_URL=http://127.0.0.1:8000",
                "WORKHUB_PUBLIC_URL=http://127.0.0.1:8000",
                "",
            ]
        ),
    )
    typer.echo(f"Created {env_file}. Start with: workhub serve")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, env_file: Path = Path(".env")):
    """Run the HTTP API; run `workhub worker` separately for periodic discovery."""
    import uvicorn

    load_dotenv(env_file)
    uvicorn.run("workhub.api:create_app", factory=True, host=host, port=port, access_log=False)


@app.command()
def worker(once: bool = False, env_file: Path = Path(".env")):
    """Poll all accounts and reconcile leases and pull requests."""
    from workhub.config import Settings
    from workhub.db import Database
    from workhub.service import Hub

    load_dotenv(env_file)
    settings = Settings.from_env()
    hub = Hub(Database(settings.database_url), settings)
    from workhub.webhooks import Webhooks

    events = Webhooks(hub)
    next_sync = 0
    while True:
        events.drain()
        if time.monotonic() >= next_sync:
            output(hub.sync())
            next_sync = time.monotonic() + settings.sync_seconds
        if once:
            return
        time.sleep(2)


@app.command()
def login(
    url: str | None = None,
    invite: bool = False,
    provider: str = "auto",
    no_browser: bool = False,
    token: bool = False,
):
    """Sign in with GitHub in your browser; --invite accepts a first-time invitation."""
    from workhub.oauth_client import browser_signin

    if token:
        value = os.getenv("WORKHUB_TOKEN") or typer.prompt("Hub access token", hide_input=True)
        client = Client(url=url, token=value)
        user = client.call("GET", "/v1/me")
        write_private(config_path(), json.dumps({"url": client.url, "token": value}))
        output(user)
        return
    invitation = os.getenv("WORKHUB_INVITATION") or (
        typer.prompt("Invitation code", hide_input=True) if invite else None
    )
    client = Client(url=url, token="unused")
    del client.http.headers["Authorization"]
    result = browser_signin(
        client,
        {"kind": "login", "provider": provider, "invitation": invitation},
        no_browser=no_browser,
        announce=lambda text: typer.echo(text, err=True),
    )
    write_private(
        config_path(),
        json.dumps({"url": client.url, "token": result["token"], "role": result["role"]}),
    )
    output({"github_login": result["github_login"], "role": result["role"]})


@app.command()
def connect(provider: str = "auto", no_browser: bool = False, token: bool = False):
    """Connect or renew GitHub through browser OAuth."""
    from workhub.oauth_client import browser_signin

    if token:
        value = os.getenv("GH_TOKEN") or typer.prompt("GitHub token", hide_input=True)
        output(Client().call("POST", "/v1/me/github", json={"github_token": value}))
        return
    result = browser_signin(
        Client(),
        {"kind": "contributor", "provider": provider},
        no_browser=no_browser,
        announce=lambda text: typer.echo(text, err=True),
    )
    output({"github_login": result["github_login"], "connected": True})


@app.command()
def mcp():
    """Run the stdio MCP adapter (Codex, Claude Code, or another MCP client)."""
    from workhub.mcp_server import run

    run()


@app.command("run")
def run_agent(
    harness: str = "codex",
    source: str | None = None,
    repository: str | None = None,
    minutes: int = 60,
    max_tasks: int = 1,
    watch: bool = False,
    directory: Path | None = None,
    fork_name: str | None = None,
    resume: str | None = None,
    capability: Annotated[list[str] | None, typer.Option()] = None,
    harness_arg: Annotated[list[str] | None, typer.Option()] = None,
):
    """Run Codex or Claude unattended through claim, edit, validation, commit, push, and PR."""
    from workhub.runner import Runner

    if max_tasks < 1 or minutes < 1 or minutes > 240:
        raise ClientError("max-tasks must be positive and minutes must be between 1 and 240")
    runner = Runner(root=directory, harness=harness, extra_args=harness_arg)
    completed = 0
    while completed < max_tasks:
        result = runner.run_one(
            source=source,
            repository=repository,
            work_minutes=minutes,
            capabilities=capability,
            fork_name=fork_name,
            resume=resume,
        )
        output(result)
        resume = None
        if "contract" in result:
            completed += 1
        elif not watch:
            return
        else:
            time.sleep(min(result.get("retry_after_seconds", 60), 60))


@deploy.command("local")
def deploy_local(env_file: Path = Path(".env"), compose_file: Path = Path("compose.yaml")):
    """Run PostgreSQL, the API, and the worker on this machine with Compose."""
    from workhub.deploy import local, summary

    url, health = local(env_file, compose_file)
    typer.echo(
        summary(url)
        + f"\nVersion {health['version']}. Owner token: WORKHUB_ADMIN_TOKEN in {env_file}."
    )
    if not url.startswith("https://"):
        typer.echo(
            "This address is reachable only from this machine. Remote harnesses and GitHub "
            "webhooks need a public HTTPS URL; use `workhub deploy cloudflare` for that."
        )


@deploy.command("cloudflare")
def deploy_cloudflare(
    name: Annotated[str, typer.Option(help="Worker name")] = "workhub",
    domain: Annotated[
        str | None, typer.Option(help="Custom domain on your Cloudflare zone")
    ] = None,
    directory: Annotated[
        Path, typer.Option(help="Generated project, secrets, and deployment state")
    ] = Path(".workhub/cloudflare"),
    sync_seconds: int = 120,
    dev: Annotated[bool, typer.Option(help="Run the Worker locally in workerd instead")] = False,
    port: int = 8787,
):
    """Deploy to Cloudflare Workers: one Durable Object holds the hub's SQLite database."""
    from workhub.deploy import Cloudflare, summary

    target = Cloudflare(directory, name=name, domain=domain, sync_seconds=sync_seconds)
    if dev:
        target.dev(port)
        return
    url, health = target.deploy()
    typer.echo(
        summary(url)
        + f"\nVersion {health['version']}. Owner token: WORKHUB_ADMIN_TOKEN in "
        + f"{target.secrets_path} (keep this directory; it holds the encryption key)."
        + f"\nSign in with: workhub login --url {url}"
    )


@app.command("migrate")
def migrate(env_file: Path = Path(".env")):
    """Apply the versioned schema upgrade; preserves existing accounts and work."""
    from workhub.config import Settings
    from workhub.db import Database
    from workhub.migrations import CURRENT_VERSION

    load_dotenv(env_file)
    db = Database(Settings.from_env().database_url)
    db.engine.dispose()
    output({"schema_version": CURRENT_VERSION})


@admin.callback()
def admin_config(env_file: Path = Path(".env")):
    load_dotenv(env_file)


@admin.command("invite")
def invite(name: str):
    """Create an invitation. The returned token is shown only once."""
    output(Client(admin=True).call("POST", "/v1/admin/contributors", json={"name": name}))


@admin.command("revoke")
def revoke(contributor_id: str):
    output(Client(admin=True).call("DELETE", f"/v1/admin/contributors/{contributor_id}"))


@admin.command("sources")
def sources():
    output(Client(admin=True).call("GET", "/v1/admin/sources"))


@admin.command("sync")
def sync(source: str | None = None):
    output(
        Client(admin=True).call(
            "POST", "/v1/admin/sync", params={"source": source} if source else {}
        )
    )


@admin.command("approve")
def approve(source: str, repository: str, issue: int):
    """Confirm the agent:approved label an approver applied on GitHub; the hub never adds it."""
    output(
        Client(admin=True).call(
            "POST",
            "/v1/admin/approve",
            json={"source": source, "repository": repository, "issue_number": issue},
        )
    )


@admin.command("tasks")
def tasks():
    output(Client(admin=True).call("GET", "/v1/admin/tasks"))


@admin.command("audit")
def audit(after: int = 0):
    output(Client(admin=True).call("GET", "/v1/admin/audit", params={"after": after}))


@admin.command("retry")
def retry(task_id: str, reason: str):
    output(
        Client(admin=True).call("POST", f"/v1/admin/tasks/{task_id}/retry", json={"reason": reason})
    )


@work.command("list")
def list_work(source: str | None = None, repository: str | None = None):
    output(
        Client().call(
            "GET",
            "/v1/work",
            params={
                k: v
                for k, v in {"source": source, "repository": repository}.items()
                if v is not None
            },
        )
    )


@work.command("claim")
def claim(
    source: str | None = None,
    repository: str | None = None,
    capability: Annotated[list[str] | None, typer.Option()] = None,
    minutes: int = 60,
    key: str | None = None,
    task_id: str | None = None,
    out: Path | None = None,
    fork_name: str | None = None,
):
    key = key or str(uuid.uuid4())
    typer.echo(f"Claim idempotency key: {key}", err=True)
    result = Client().call(
        "POST",
        "/v1/work/claim",
        json={
            "source": source,
            "repository": repository,
            "capabilities": capability or [],
            "work_minutes": minutes,
            "idempotency_key": key,
            "task_id": task_id,
            "fork_name": fork_name,
        },
    )
    if out:
        write_private(out, json.dumps(result, indent=2))
    output(result)


@work.command("get")
def get(task_id: str):
    output(Client().call("GET", f"/v1/work/{task_id}"))


@work.command("heartbeat")
def heartbeat(task_id: str):
    client = Client()
    _, lease = assignment(client, task_id)
    output(client.call("POST", f"/v1/work/{task_id}/heartbeat", json=lease))


@work.command("provision")
def provision(task_id: str):
    """Create or verify the contributor's assigned fork using their GitHub connection."""
    client = Client()
    _, lease = assignment(client, task_id)
    output(client.call("POST", f"/v1/work/{task_id}/provision", json=lease))


@work.command("keepalive")
def keepalive(task_id: str):
    """Keep this process running while a non-MCP agent works; stops on lease loss."""
    client = Client()
    result, lease = assignment(client, task_id)
    result = client.call("POST", f"/v1/work/{task_id}/heartbeat", json=lease)
    heartbeat = Heartbeats(client)
    heartbeat.track(result)
    typer.echo("Maintaining lease until its deadline. Ctrl-C stops renewal.", err=True)
    try:
        while True:
            time.sleep(5)
            with heartbeat.lock:
                error = heartbeat.errors.get(task_id)
                active = task_id in heartbeat.assignments
            if error:
                typer.echo(error, err=True)
            if not active:
                raise ClientError("Lease renewal stopped; inspect the assignment before continuing")
    finally:
        heartbeat.close()


@work.command("release")
def release(task_id: str, note: str):
    client = Client()
    _, lease = assignment(client, task_id)
    output(client.call("POST", f"/v1/work/{task_id}/release", json={**lease, "note": note}))


@work.command("block")
def block(task_id: str, note: str):
    client = Client()
    _, lease = assignment(client, task_id)
    output(client.call("POST", f"/v1/work/{task_id}/block", json={**lease, "note": note}))


@work.command("resume")
def resume(task_id: str):
    client = Client()
    _, lease = assignment(client, task_id)
    output(client.call("POST", f"/v1/work/{task_id}/resume", json=lease))


@work.command("submit")
def submit(
    task_id: str,
    pr: Annotated[str, typer.Option()],
    sha: Annotated[str, typer.Option()],
    evidence_file: Annotated[Path, typer.Option()],
):
    client = Client()
    _, lease = assignment(client, task_id)
    output(
        client.call(
            "POST",
            f"/v1/work/{task_id}/submit",
            json={**lease, "pr_url": pr, "head_sha": sha, "evidence": evidence_file.read_text()},
        )
    )


@work.command("prepare")
def prepare(task_id: str, directory: Path):
    """Clone an isolated checkout; uses your own git/gh credentials. Does not run repo code."""
    client = Client()
    result, lease = assignment(client, task_id)
    client.call("POST", f"/v1/work/{task_id}/heartbeat", json=lease)
    if directory.exists():
        raise ClientError("Checkout directory must not exist")

    def provision():
        client.call("POST", f"/v1/work/{task_id}/heartbeat", json=lease)
        return client.call("POST", f"/v1/work/{task_id}/provision", json=lease)

    ensure_push_target(provision, lambda command: git_command(command))
    checkout = result["contract"]["checkout"]
    repo = result["contract"]["source"]["repository"]
    git_command(["git", "clone", "--", f"https://github.com/{repo}.git", str(directory.resolve())])
    git_command(["git", "checkout", "-b", checkout["branch"], checkout["base_sha"]], cwd=directory)
    git_command(["git", "remote", "rename", "origin", "upstream"], cwd=directory)
    git_command(
        ["git", "remote", "add", "origin", f"https://github.com/{checkout['push_repository']}.git"],
        cwd=directory,
    )
    output(
        {
            "directory": str(directory.resolve()),
            "checkout": checkout,
            "next": "Read the contract and repository instructions. "
            "Maintain the lease using MCP or workhub work keepalive.",
        }
    )


@work.command("publish")
def publish(
    task_id: str,
    body_file: Annotated[Path, typer.Option()],
    evidence_file: Annotated[Path, typer.Option()],
    title: Annotated[str, typer.Option()],
    directory: Path = Path("."),
):
    """Push committed work, open/reuse its PR, and submit it. Never commits or merges for you."""
    output(publish_work(Client(), task_id, body_file, evidence_file, title, directory))


def publish_work(client, task_id, body_file, evidence_file, title, directory, command=None):
    git_command = command or globals()["git_command"]
    result, lease = assignment(client, task_id)
    client.call("POST", f"/v1/work/{task_id}/heartbeat", json=lease)
    checkout = result["contract"]["checkout"]
    repo = result["contract"]["source"]["repository"]
    user = client.call("GET", "/v1/me")
    if git_command(["gh", "api", "user", "--jq", ".login"]).lower() != user["github_login"].lower():
        raise ClientError("gh must be authenticated as your connected GitHub account")
    if git_command(["git", "branch", "--show-current"], cwd=directory) != checkout["branch"]:
        raise ClientError("Current branch does not match the contract")
    if git_command(["git", "status", "--porcelain"], cwd=directory):
        raise ClientError("Commit your changes and leave the checkout clean before publishing")
    body = body_file.read_text()
    if task_id not in body:
        raise ClientError("PR body must include the contract ID")
    # A URL from the contract is constructed from server-verified GitHub repository names.
    target = f"https://github.com/{checkout['push_repository']}.git"
    git_command(["git", "push", target, f"HEAD:refs/heads/{checkout['branch']}"], cwd=directory)
    head = f"{checkout['push_repository'].split('/')[0]}:{checkout['branch']}"
    existing = json.loads(
        git_command(
            [
                "gh",
                "api",
                f"repos/{repo}/pulls",
                "--method",
                "GET",
                "-f",
                f"head={head}",
                "-f",
                "state=open",
            ]
        )
    )
    if existing:
        pr_url = existing[0]["html_url"]
    else:
        created = json.loads(
            git_command(
                ["gh", "api", f"repos/{repo}/pulls", "--method", "POST", "--input", "-"],
                input_data=json.dumps(
                    {"title": title, "body": body, "head": head, "base": checkout["base_branch"]}
                ),
            )
        )
        pr_url = created["html_url"]
    sha = git_command(["git", "rev-parse", "HEAD"], cwd=directory)
    # CI may still be running. Print the durable PR URL even if submission is not ready.
    output({"pr_url": pr_url, "head_sha": sha})
    return client.call(
        "POST",
        f"/v1/work/{task_id}/submit",
        json={
            **lease,
            "pr_url": pr_url,
            "head_sha": sha,
            "evidence": evidence_file.read_text(),
        },
    )


def main():
    try:
        app()
    except (ClientError, HubError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from None
