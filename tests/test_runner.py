import json
import os
import sys
import time

import pytest

from workhub import cli
from workhub.client import ClientError, Heartbeats
from workhub.models import Task
from workhub.runner import Runner, harness_command
from workhub.schemas import Policy


class LocalClient:
    def __init__(self, env):
        self.env = env
        self.claim = None

    def call(self, method, path, **kwargs):
        response = self.env.client.request(method, path, headers=self.env.users["bob"], **kwargs)
        if response.is_error:
            raise ClientError(response.json()["detail"], response.status_code)
        result = response.json()
        if path == "/v1/work/claim":
            self.claim = result
        return result


@pytest.mark.parametrize("harness", ["codex", "claude"])
def test_runner_edits_validates_commits_pushes_and_opens_pr(env, tmp_path, monkeypatch, harness):
    env.github.now = int(time.time())
    seed = tmp_path / "seed"
    seed.mkdir()

    def git(*args, cwd=seed):
        return cli.git_command(["git", *args], cwd=cwd)

    monkeypatch.setenv("GIT_AUTHOR_NAME", "Test Bob")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "bob@example.test")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Test Bob")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "bob@example.test")
    git("init", "-b", "main")
    (seed / "src").mkdir()
    (seed / "src/menu.py").write_text("value = 1\n")
    git("add", ".")
    git("commit", "-m", "base")
    env.github.base = git("rev-parse", "HEAD")
    upstream, fork = tmp_path / "upstream.git", tmp_path / "fork.git"
    git("clone", "--bare", str(seed), str(upstream))
    git("clone", "--bare", str(seed), str(fork))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    for index, (name, path) in enumerate([("alice", upstream), ("bob", fork)]):
        monkeypatch.setenv(f"GIT_CONFIG_KEY_{index}", f"url.{path.as_uri()}.insteadOf")
        monkeypatch.setenv(f"GIT_CONFIG_VALUE_{index}", f"https://github.com/{name}/widget.git")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    env.github.policies["alice/widget"] = Policy(
        validation=[
            [
                sys.executable,
                "-c",
                "from pathlib import Path; assert Path('src/menu.py').read_text() == 'value = 2\\n'",
            ]
        ]
    )
    env.github.label("alice/widget", 1)
    env.client.post(
        "/v1/admin/approve",
        headers=env.admin,
        json={
            "source": "alice",
            "repository": "alice/widget",
            "issue_number": 1,
        },
    ).raise_for_status()
    binary = tmp_path / "bin"
    binary.mkdir()
    script = binary / harness
    script.write_text(
        f"#!{sys.executable}\n"
        + """
import json, os, sys
from pathlib import Path
assert 'WORKHUB_TOKEN' not in os.environ
assert 'GH_TOKEN' not in os.environ
prompt = sys.stdin.read()
assert 'acceptance' in prompt.lower() and 'contract_id' in prompt
Path('src/menu.py').write_text('value = 2\\n')
if '--output-last-message' in sys.argv:
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text('Implemented and tested.')
else:
    print(json.dumps({'result': 'Implemented and tested.', 'is_error': False}))
"""
    )
    script.chmod(0o700)
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("WORKHUB_TOKEN", "secret-hub")
    monkeypatch.setenv("GH_TOKEN", "secret-github")
    client = LocalClient(env)
    runner = Runner(client, tmp_path / "runs", harness)
    original_git = runner.git
    original_cli = cli.git_command
    monkeypatch.setattr(
        cli,
        "git_command",
        lambda args, **kw: "bob" if args[0] == "gh" else original_cli(args, **kw),
    )
    created, forked = [], []

    def dispatch(args, cwd=None, input_data=None):
        if args[0] != "gh":
            return original_git(args, cwd=cwd, input_data=input_data)
        if args[1:3] == ["repo", "fork"]:
            forked.append(args)
            env.github.contributor_fork(args[3], "bob-token", args[args.index("--fork-name") + 1])
            return ""
        if args[2] == "user":
            return "bob"
        if "GET" in args:
            return json.dumps(list(env.github.pull_data.values()))
        created.append(json.loads(input_data))
        checkout = runner.root / client.claim["assignment"]["attempt_id"] / "repo"
        sha = git("rev-parse", "HEAD", cwd=checkout)
        return json.dumps(env.github.make_pr(client.claim, sha=sha))

    monkeypatch.setattr(runner, "git", dispatch)
    result = runner.run_one(repository="alice/widget")
    assert result["assignment"]["state"] == "submitted"
    assert len(created) == 1
    assert [a[:4] for a in forked] == [["gh", "repo", "fork", "alice/widget"]]
    assert result["contract"]["contract_id"] in created[0]["body"]
    assert "Closes #1" in created[0]["body"]
    branch = result["contract"]["checkout"]["branch"]
    assert git("rev-parse", f"refs/heads/{branch}", cwd=fork) == result["submission"]["head_sha"]
    directory = runner.root / result["assignment"]["attempt_id"]
    assert "PASS:" in (directory / "evidence.txt").read_text()
    assert (directory / "result.json").exists()


def test_supervisor_terminates_process_when_lease_is_lost(env, tmp_path, monkeypatch):
    env.github.now = int(time.time())
    client = LocalClient(env)
    runner = Runner(client, tmp_path)
    runner.current = client.call(
        "POST", "/v1/work/claim", json={"idempotency_key": "supervisor-test"}
    )
    runner.heartbeats = Heartbeats(client)
    runner.heartbeats.track(runner.current)
    original = runner.check
    checks = 0

    def check(renew=False):
        nonlocal checks
        checks += 1
        if checks > 1:
            raise ClientError("Lease lost")
        original(renew)

    monkeypatch.setattr(runner, "check", check)
    marker = tmp_path / "should-not-exist"
    started = time.monotonic()
    try:
        with pytest.raises(ClientError, match="Lease lost"):
            runner.execute(
                [
                    sys.executable,
                    "-c",
                    f"import time; from pathlib import Path; time.sleep(10); Path({str(marker)!r}).touch()",
                ],
                tmp_path,
                tmp_path / "child.log",
            )
        assert time.monotonic() - started < 5
        assert not marker.exists()
    finally:
        runner.heartbeats.close()


def test_failed_agent_blocks_and_never_publishes(env, tmp_path, monkeypatch):
    env.github.now = int(time.time())
    runner = Runner(LocalClient(env), tmp_path)

    def preflight():
        tmp_path.mkdir(exist_ok=True)

    monkeypatch.setattr(runner, "preflight", preflight)
    monkeypatch.setattr(
        runner, "git", lambda *a, **kw: (_ for _ in ()).throw(ClientError("checkout failed"))
    )
    with pytest.raises(ClientError, match="checkout failed"):
        runner.run_one()
    with env.hub.db.read() as session:
        task = session.get(Task, runner.current["contract"]["contract_id"])
        assert task.state == "blocked"
    assert not env.github.pull_data


def test_harness_flags_preserve_permission_controls():
    for harness in ["codex", "claude"]:
        command = harness_command(harness, "summary")
        assert not any("dangerously" in flag for flag in command)
    with pytest.raises(ClientError):
        harness_command("unknown", "summary")
