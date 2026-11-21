import os
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from workhub.cli import app
from workhub.client import Client, ClientError, write_private


def test_init_creates_private_config_and_worker_runs(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.output
    assert os.stat(".env").st_mode & 0o777 == 0o600
    result = subprocess.run(
        [sys.executable, "-c", "from workhub.cli import main; main()", "worker", "--once"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert '"repositories": 0' in result.stdout


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:8000",
        "http://127.0.0.1:8000@evil.test",
        "https://user:password@example.com",
        "file:///tmp/hub",
    ],
)
def test_client_rejects_unsafe_hub_urls(url, tmp_path, monkeypatch):
    monkeypatch.setenv("WORKHUB_CLIENT_CONFIG", str(tmp_path / "client.json"))
    with pytest.raises(ClientError):
        Client(url=url, token="test")


def test_client_secret_file_rejects_symlinks(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        write_private(link, "new")
    assert target.read_text() == "keep"


def test_real_git_prepare_publish_and_ci_retry(env, tmp_path, monkeypatch):
    """Exercise the shipping CLI against real git; only GitHub's network is simulated."""
    import json

    from workhub import cli
    from workhub.schemas import Policy

    def git(*args, cwd=None):
        return subprocess.check_output(
            ["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL
        ).strip()

    seed = tmp_path / "seed"
    seed.mkdir()
    git("init", "-b", "main", cwd=seed)
    (seed / "src").mkdir()
    (seed / "src" / "menu.py").write_text("value = 1\n")
    git("add", ".", cwd=seed)
    git(
        "-c",
        "user.name=Test Bob",
        "-c",
        "user.email=bob@example.test",
        "commit",
        "-m",
        "base",
        cwd=seed,
    )
    env.github.base = git("rev-parse", "HEAD", cwd=seed)
    upstream, fork = tmp_path / "upstream.git", tmp_path / "fork.git"
    git("clone", "--bare", str(seed), str(upstream))
    git("clone", "--bare", str(seed), str(fork))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    for index, (name, path) in enumerate([("alice", upstream), ("bob", fork)]):
        monkeypatch.setenv(f"GIT_CONFIG_KEY_{index}", f"url.{path.as_uri()}.insteadOf")
        monkeypatch.setenv(f"GIT_CONFIG_VALUE_{index}", f"https://github.com/{name}/widget.git")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")

    env.github.policies["alice/widget"] = Policy(required_checks=["unit"])
    env.github.label("alice/widget", 1)
    assert (
        env.client.post(
            "/v1/admin/approve",
            headers=env.admin,
            json={"source": "alice", "repository": "alice/widget", "issue_number": 1},
        ).status_code
        == 200
    )
    claim = env.claim().json()
    task_id = claim["contract"]["contract_id"]

    class LocalClient:
        def call(self, method, path, **kwargs):
            response = env.client.request(method, path, headers=env.users["bob"], **kwargs)
            if response.is_error:
                raise ClientError(response.json()["detail"], response.status_code)
            return response.json()

    monkeypatch.setattr(cli, "Client", LocalClient)
    original = cli.git_command
    forked = []

    def git_or_fake_fork(args, cwd=None, input_data=None):
        if args[0] == "git":
            return original(args, cwd=cwd, input_data=input_data)
        assert args[:4] == ["gh", "repo", "fork", "alice/widget"]
        forked.append(args)
        env.github.contributor_fork("alice/widget", "bob-token", "widget")
        return ""

    monkeypatch.setattr(cli, "git_command", git_or_fake_fork)
    runner = CliRunner()
    directory = tmp_path / "contribution"
    result = runner.invoke(app, ["work", "prepare", task_id, str(directory)])
    assert result.exit_code == 0, result.exception
    assert len(forked) == 1
    monkeypatch.setattr(cli, "git_command", original)
    assert git("rev-parse", "HEAD", cwd=directory) == env.github.base
    (directory / "src" / "menu.py").write_text("value = 2\n")
    git("add", ".", cwd=directory)
    git(
        "-c",
        "user.name=Test Bob",
        "-c",
        "user.email=bob@example.test",
        "commit",
        "-m",
        "fix",
        cwd=directory,
    )
    sha = git("rev-parse", "HEAD", cwd=directory)
    body = tmp_path / "body.txt"
    body.write_text(f"Contract: {task_id}\n\nLiteral `code` and $(not-a-shell-command).\n")
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("Unit tests passed locally")
    original = cli.git_command
    created = []

    def git_or_fake_gh(args, cwd=None, input_data=None):
        if args[0] == "git":
            return original(args, cwd=cwd, input_data=input_data)
        assert args[:2] == ["gh", "api"]
        if args[2] == "user":
            return "bob"
        assert args[2] == "repos/alice/widget/pulls"
        if "GET" in args:
            return json.dumps(list(env.github.pull_data.values()))
        assert "POST" in args
        request = json.loads(input_data)
        assert request["body"] == body.read_text()
        created.append(request)
        return json.dumps(env.github.make_pr(claim, sha=sha))

    monkeypatch.setattr(cli, "git_command", git_or_fake_gh)
    command = [
        "work",
        "publish",
        task_id,
        "--directory",
        str(directory),
        "--title",
        "Fix menu",
        "--body-file",
        str(body),
        "--evidence-file",
        str(evidence),
    ]
    pending = runner.invoke(app, command)
    assert pending.exit_code != 0
    assert "Required checks" in str(pending.exception)
    assert "https://github.com/alice/widget/pull/9" in pending.output
    branch = claim["contract"]["checkout"]["branch"]
    assert git("rev-parse", f"refs/heads/{branch}", cwd=fork) == sha
    env.github.check_data["alice/widget", sha] = {"unit": True}
    submitted = runner.invoke(app, command)
    assert submitted.exit_code == 0, submitted.exception
    assert '"state": "submitted"' in submitted.output
    assert len(created) == 1
