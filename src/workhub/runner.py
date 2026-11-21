"""Local, bounded harness execution; the owner explicitly starts each runner."""

import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path

from workhub.client import Client, ClientError, Heartbeats, ensure_push_target, write_private
from workhub.domain import validate_paths


def harness_command(harness, summary_path, extra_args=None):
    if harness == "codex":
        return [
            "codex",
            "exec",
            "--sandbox",
            "workspace-write",
            "-c",
            'approval_policy="never"',
            "--json",
            "--output-last-message",
            str(summary_path),
            *(extra_args or []),
            "-",
        ]
    if harness == "claude":
        return [
            "claude",
            "--print",
            "--output-format",
            "json",
            "--permission-mode",
            "acceptEdits",
            "--allowedTools",
            "Read,Edit,Write,Glob,Grep,Bash",
            "--no-session-persistence",
            *(extra_args or []),
        ]
    raise ClientError("Harness must be codex or claude")


class Runner:
    def __init__(self, client=None, root=None, harness="codex", extra_args=None):
        self.client = client or Client()
        self.root = Path(root or "~/.local/share/workhub/runs").expanduser().resolve()
        self.harness, self.extra_args = harness, extra_args or []
        self.heartbeats = None
        self.current = None

    def preflight(self):
        harness_command(self.harness, "summary.txt", self.extra_args)
        for command in ["git", "gh", self.harness]:
            if not shutil.which(command):
                raise ClientError(f"Install {command} before starting the runner")
        from workhub.cli import git_command

        identity = self.client.call("GET", "/v1/me")
        if (
            git_command(["gh", "api", "user", "--jq", ".login"]).lower()
            != (identity.get("github_login") or "").lower()
        ):
            raise ClientError("gh must use the same GitHub account connected to Work Hub")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def lease_payload(self):
        return {key: self.current["assignment"][key] for key in ("attempt_id", "generation")}

    def check(self, renew=False):
        task_id = self.current["contract"]["contract_id"]
        if renew:
            result = self.client.call(
                "POST", f"/v1/work/{task_id}/heartbeat", json=self.lease_payload()
            )
            self.current = result
            self.heartbeats.track(result)
        with self.heartbeats.lock:
            assignment = self.heartbeats.assignments.get(task_id)
        if (
            not assignment
            or assignment["expires_at"] <= time.time()
            or assignment["deadline"] <= time.time()
        ):
            raise ClientError("Lease lost or work deadline reached; runner stopped")

    def execute(self, args, cwd, log, input_text=None, scrub=True):
        if not args or not all(isinstance(arg, str) and arg for arg in args):
            raise ClientError("Invalid command in repository policy")
        self.check(renew=True)
        environment = (
            {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("WORKHUB_", "GITHUB_OAUTH_", "GITHUB_APP_"))
                and k not in {"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET"}
            }
            if scrub
            else os.environ.copy()
        )
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            process = subprocess.Popen(
                args,
                cwd=cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                try:
                    process.communicate(input=input_text, timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
                while process.poll() is None:
                    self.check()
                    try:
                        process.communicate(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                self.check()
                if process.returncode:
                    raise ClientError(
                        f"{args[0]} exited with status {process.returncode}; see {log}"
                    )
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate()
                raise

    def git(self, args, cwd=None, input_data=None):
        directory = self.root / self.current["assignment"]["attempt_id"]
        log = directory / "git-command.log"
        self.execute(args, cwd, log, input_text=input_data, scrub=False)
        return log.read_text().strip()

    def run_one(
        self,
        source=None,
        repository=None,
        work_minutes=60,
        capabilities=None,
        fork_name=None,
        resume=None,
    ):
        from workhub.cli import publish_work

        git_command = self.git

        self.preflight()
        if resume:
            previous = self.client.call("GET", f"/v1/work/{resume}")
            self.current = self.client.call(
                "POST",
                f"/v1/work/{resume}/resume",
                json={key: previous["assignment"][key] for key in ("attempt_id", "generation")},
            )
        else:
            pending = self.root / "pending-claim.json"
            if pending.exists():
                request = json.loads(pending.read_text())
            else:
                request = {
                    "source": source,
                    "repository": repository,
                    "work_minutes": work_minutes,
                    "fork_name": fork_name,
                    "capabilities": capabilities
                    or [
                        tool
                        for tool in [
                            "python",
                            "python3",
                            "uv",
                            "node",
                            "npm",
                            "pnpm",
                            "go",
                            "cargo",
                            "git",
                            "docker",
                        ]
                        if shutil.which(tool)
                    ],
                    "idempotency_key": str(uuid.uuid4()),
                }
                write_private(pending, json.dumps(request))
            self.current = self.client.call("POST", "/v1/work/claim", json=request)
            pending.unlink()
            if "contract" not in self.current:
                return self.current
        contract = self.current["contract"]
        task_id = contract["contract_id"]
        directory = self.root / self.current["assignment"]["attempt_id"]
        directory.mkdir(mode=0o700, exist_ok=True)
        write_private(directory / "contract.json", json.dumps(self.current, indent=2))
        self.heartbeats = Heartbeats(self.client)
        self.heartbeats.track(self.current)
        try:

            def provision():
                self.check(renew=True)
                return self.client.call(
                    "POST", f"/v1/work/{task_id}/provision", json=self.lease_payload()
                )

            ensure_push_target(provision, git_command)
            checkout = directory / "repo"
            branch = contract["checkout"]["branch"]
            if not checkout.exists():
                git_command(
                    [
                        "git",
                        "clone",
                        "--",
                        f"https://github.com/{contract['source']['repository']}.git",
                        str(checkout),
                    ]
                )
                if resume:
                    target = f"https://github.com/{contract['checkout']['push_repository']}.git"
                    git_command(["git", "fetch", target, f"refs/heads/{branch}"], cwd=checkout)
                    git_command(["git", "checkout", "-b", branch, "FETCH_HEAD"], cwd=checkout)
                else:
                    git_command(
                        ["git", "checkout", "-b", branch, contract["checkout"]["base_sha"]],
                        cwd=checkout,
                    )
            if git_command(["git", "branch", "--show-current"], cwd=checkout) != branch:
                raise ClientError("Existing checkout is on a different branch")
            summary = directory / "summary.txt"
            for index, command in enumerate(contract["policy"]["setup"]):
                self.execute(command, checkout, directory / f"setup-{index}.log")
            prompt = (
                "Implement this approved work contract in the current checkout. Read repository instructions. "
                "Stay within the approved scope; run relevant tests. Do not change the branch, commit, push, "
                "open a PR, merge, or claim more work: the supervising runner handles delivery after validation. "
                "If the task cannot be completed, explain the blocker. Your final response must summarize "
                "changes and validation, and clearly state whether the acceptance criteria are met.\n\n"
                + json.dumps(contract, indent=2)
            )
            self.execute(
                harness_command(self.harness, summary, self.extra_args),
                checkout,
                directory / "agent.log",
                input_text=prompt,
            )
            if self.harness == "claude":
                try:
                    result = json.loads((directory / "agent.log").read_text())
                    if result.get("is_error"):
                        raise ClientError("Claude reported an execution error")
                    write_private(summary, result.get("result", "Agent run completed"))
                except ValueError as exc:
                    raise ClientError("Claude did not return a valid execution result") from exc
            evidence = []
            for index, command in enumerate(contract["policy"]["validation"]):
                self.execute(command, checkout, directory / f"validation-{index}.log")
                evidence.append("PASS: " + " ".join(command))
            self.check(renew=True)
            git_command(["git", "add", "--all"], cwd=checkout)
            paths = git_command(
                ["git", "diff", "--cached", "--name-only", "--no-renames", "-z"], cwd=checkout
            )
            validate_paths(
                [{"filename": path} for path in paths.split("\0") if path], contract["policy"]
            )
            if paths:
                git_command(
                    ["git", "commit", "-m", f"{contract['specification']['title']} ({task_id})"],
                    cwd=checkout,
                )
            if (
                git_command(["git", "rev-parse", "HEAD"], cwd=checkout)
                == contract["checkout"]["base_sha"]
            ):
                raise ClientError("Agent produced no changes; inspect the run and clarify the task")
            changed = git_command(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    contract["checkout"]["base_sha"],
                    "HEAD",
                ],
                cwd=checkout,
            )
            validate_paths(
                [{"filename": path} for path in changed.split("\0") if path], contract["policy"]
            )
            report = (
                summary.read_text()
                if summary.exists()
                else "Implementation completed. See validation evidence."
            )
            body = directory / "pr-body.md"
            write_private(
                body,
                f"Contract: {task_id}\nCloses #{contract['source']['issue_number']}\n\n{report}\n",
            )
            evidence_file = directory / "evidence.txt"
            write_private(
                evidence_file,
                "\n".join(evidence)
                or "No repository validation commands configured; inspect agent.log for agent-reported checks.",
            )
            while True:
                self.check(renew=True)
                try:
                    result = publish_work(
                        self.client,
                        task_id,
                        body,
                        evidence_file,
                        contract["specification"]["title"],
                        checkout,
                        command=self.git,
                    )
                    write_private(directory / "result.json", json.dumps(result, indent=2))
                    return result
                except ClientError as exc:
                    if exc.status != 409 or "Required checks" not in str(exc):
                        raise
                    time.sleep(5)
        except BaseException as exc:
            try:
                self.client.call(
                    "POST",
                    f"/v1/work/{task_id}/block",
                    json={
                        **self.lease_payload(),
                        "note": f"Runner stopped: {str(exc) or type(exc).__name__}. Local run: {directory}"[
                            :10000
                        ],
                    },
                )
            except ClientError:
                pass  # A lost/revoked lease cannot be modified by this runner.
            raise
        finally:
            self.heartbeats.close()
