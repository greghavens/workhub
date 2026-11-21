import copy
import os
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from workhub.api import create_app
from workhub.config import Settings
from workhub.db import Database
from workhub.github import GitHubError
from workhub.models import Base, GitHubInstallation, Source
from workhub.schemas import Policy


class FakeGitHub:
    def __init__(self):
        self.now = 1795132800
        self.identities = {
            "alice-token": {"id": 1, "login": "alice"},
            "bob-token": {"id": 2, "login": "bob"},
            "carol-token": {"id": 3, "login": "carol"},
        }
        self.repos = {
            "alice/widget": {
                "id": 100,
                "full_name": "alice/widget",
                "private": False,
                "default_branch": "main",
                "allow_forking": True,
            },
            "org/secret": {
                "id": 200,
                "full_name": "org/secret",
                "private": True,
                "default_branch": "main",
                "allow_forking": False,
            },
        }
        self.access = {
            "alice-token": set(self.repos),
            "bob-token": {"alice/widget"},
            "carol-token": {"alice/widget"},
        }
        self.push = {"alice-token": set(self.repos), "bob-token": set(), "carol-token": set()}
        self.policies = {name: Policy() for name in self.repos}
        self.base = "a" * 40
        self.issue_data = {}
        self.event_data = {}
        self.pull_data = {}
        self.file_data = {}
        self.check_data = {}
        self.review_data = {}
        self.fork_data = {}
        self.comment_data = {}
        self.contains = True
        self.unavailable = False
        self.add_issue("alice/widget", 1)
        self.add_issue("org/secret", 1)

    def contributor_fork(self, name, owner_token, fork_name):
        """A contributor forking with their own GitHub tools, outside the hub."""
        identity = self.identities[owner_token]
        target = f"{identity['login']}/{fork_name}"
        fork = {
            "id": 10000 + len(self.repos),
            "full_name": target,
            "private": self.repos[name]["private"],
            "default_branch": "main",
            "fork": True,
            "owner": identity,
            "parent": self.repos[name],
            "source": self.repos[name],
        }
        self.repos[target] = fork
        self.access[owner_token].add(target)
        self.push[owner_token].add(target)
        self.fork_data.setdefault(name, []).append(fork)
        return copy.deepcopy(fork)

    def iso(self, offset=0):
        return datetime.fromtimestamp(self.now + offset, UTC).isoformat().replace("+00:00", "Z")

    def add_issue(self, repo, number, actor=1, approved=True):
        self.issue_data[repo, number] = {
            "number": number,
            "title": f"Fix widget {number}",
            "body": "Goal: fix keyboard navigation. Acceptance: regression tests pass.",
            "html_url": f"https://github.com/{repo}/issues/{number}",
            "state": "open",
            "updated_at": self.iso(),
            "labels": [{"name": "agent:approved"}] if approved else [],
        }
        self.event_data[repo, number] = (
            [
                {
                    "id": number,
                    "event": "labeled",
                    "actor": {"id": actor},
                    "label": {"name": "agent:approved"},
                    "created_at": self.iso(),
                }
            ]
            if approved
            else []
        )

    def label(self, repo, number, actor=1):
        """A maintainer (re)applying agent:approved in GitHub; each application is a new event."""
        self.now += 1
        issue = self.issue_data[repo, number]
        if {"name": "agent:approved"} not in issue["labels"]:
            issue["labels"].append({"name": "agent:approved"})
        issue["updated_at"] = self.iso()
        newest = max((e["id"] for events in self.event_data.values() for e in events), default=0)
        self.event_data[repo, number].append(
            {
                "id": newest + 1,
                "event": "labeled",
                "actor": {"id": actor},
                "label": {"name": "agent:approved"},
                "created_at": self.iso(),
            }
        )

    def make_pr(self, claim, *, number=9, author=2, sha=None):
        contract = claim["contract"]
        repo = contract["source"]["repository"]
        checkout = contract["checkout"]
        sha = sha or "b" * 40
        pull = {
            "number": number,
            "state": "open",
            "merged": False,
            "merged_at": None,
            "draft": False,
            "body": f"Implements {contract['contract_id']}",
            "html_url": f"https://github.com/{repo}/pull/{number}",
            "user": {"id": author},
            "base": {"ref": checkout["base_branch"], "repo": self.repos[repo]},
            "head": {
                "ref": checkout["branch"],
                "sha": sha,
                "repo": {"full_name": checkout["push_repository"]},
            },
            "changed_files": 1,
        }
        self.pull_data[repo, number] = pull
        self.file_data[repo, number] = [{"filename": "src/menu.py", "status": "modified"}]
        return pull

    def __call__(self, token):
        state = self

        class Client:
            def __enter__(self):
                if state.unavailable:
                    raise GitHubError(503)
                if token not in state.identities:
                    raise GitHubError(401)
                return self

            def __exit__(self, *_):
                pass

            def me(self):
                return copy.deepcopy(state.identities[token])

            def user(self, login):
                return copy.deepcopy(
                    next(i for i in state.identities.values() if i["login"] == login)
                )

            def repositories(self):
                return [self.repository(name) for name in sorted(state.access[token])]

            def repository(self, name):
                if name not in state.access[token]:
                    raise GitHubError(404)
                return {
                    **copy.deepcopy(state.repos[name]),
                    "permissions": {"push": name in state.push[token]},
                }

            def issue(self, name, number):
                return copy.deepcopy(state.issue_data[name, number])

            def backlog(self, name, status="open"):
                return [
                    copy.deepcopy(i)
                    for (repo, _), i in state.issue_data.items()
                    if repo == name and (status == "all" or i["state"] == status)
                ]

            def create_issue(self, name, data):
                number = max(n for repo, n in state.issue_data if repo == name) + 1
                state.add_issue(name, number, approved=False)
                return self.update_issue(name, number, data)

            def update_issue(self, name, number, data):
                issue = state.issue_data[name, number]
                for key, value in data.items():
                    issue[key] = [{"name": label} for label in value] if key == "labels" else value
                state.now += 1
                issue["updated_at"] = state.iso()
                return copy.deepcopy(issue)

            def comment(self, name, number, body):
                result = {"id": len(state.comment_data) + 1, "body": body}
                state.comment_data.setdefault((name, number), []).append(result)
                return result

            def comments(self, name, number):
                return copy.deepcopy(state.comment_data.get((name, number), []))

            def issues(self, name):
                return [
                    copy.deepcopy(i)
                    for (repo, _), i in state.issue_data.items()
                    if repo == name
                    and i["state"] == "open"
                    and {"name": "agent:approved"} in i["labels"]
                ]

            def events(self, name, number):
                return copy.deepcopy(state.event_data[name, number])

            def add_approval_label(self, name, number):
                issue = state.issue_data[name, number]
                if {"name": "agent:approved"} not in issue["labels"]:
                    issue["labels"].append({"name": "agent:approved"})
                    state.event_data[name, number].append(
                        {
                            "id": 1000 + len(state.event_data[name, number]),
                            "event": "labeled",
                            "actor": {"id": state.identities[token]["id"]},
                            "label": {"name": "agent:approved"},
                            "created_at": state.iso(),
                        }
                    )

            def policy(self, repo):
                return state.policies[repo["full_name"]].model_copy(deep=True), state.base

            def pull(self, name, number):
                return copy.deepcopy(state.pull_data[name, number])

            def pulls_for_branch(self, name, owner, branch):
                return [
                    copy.deepcopy(p)
                    for (repo, _), p in state.pull_data.items()
                    if repo == name
                    and p["head"]["ref"] == branch
                    and p["head"]["repo"]["full_name"].split("/")[0] == owner
                ]

            def files(self, name, number):
                return copy.deepcopy(state.file_data[name, number])

            def checks(self, name, sha):
                return state.check_data.get((name, sha), {})

            def reviews(self, name, number):
                return copy.deepcopy(state.review_data.get((name, number), []))

            def contains_base(self, name, base, head):
                return state.contains

            def forks(self, name):
                return copy.deepcopy(state.fork_data.get(name, []))

            def user_by_id(self, github_id):
                return copy.deepcopy(
                    next(i for i in state.identities.values() if i["id"] == github_id)
                )

            def permission(self, name, login):
                # Read with the source credential; derived from the target account's access.
                account = next(
                    (t for t, i in state.identities.items() if i["login"] == login), None
                )
                if not account or name not in state.access.get(account, set()):
                    return {"permission": "none", "user": None}
                return {
                    "permission": "write" if name in state.push.get(account, set()) else "read",
                    "user": copy.deepcopy(state.identities[account]),
                }

        return Client()


class FakeAppProvider:
    """The GitHub App side of the integration provider: mints installation tokens."""

    config = {
        "app_id": "123",
        "slug": "workhub-test",
        "private_key": "test-key",
        "client_id": "app-client",
        "client_secret": "app-secret",
        "webhook_secret": "webhook-secret",
    }

    def __init__(self, github):
        self.github, self.tokens = github, {}

    def installation_token(self, config, installation_id):
        return {"token": self.tokens[installation_id], "expires_at": self.github.iso(3600)}


class Environment:
    def __init__(self, app, github):
        self.app = app
        self.client = TestClient(app)
        self.github = github
        self.hub = app.state.hub
        self.admin = {"Authorization": "Bearer " + "A" * 40}
        self.users = {}

    def install_source(self, name="alice", token="alice-token", installation_id=1, approvers=None):
        """A source backed by a read-only GitHub App installation, as the install callback creates.

        The fake App provider mints installation tokens that the fake GitHub resolves to
        the installed account's repositories.
        """
        provider = self.hub.integrations.provider
        if not isinstance(provider, FakeAppProvider):
            provider = self.hub.integrations.provider = FakeAppProvider(self.github)
            self.hub.integrations.save_config("app", FakeAppProvider.config)
        provider.tokens[installation_id] = token
        account = self.github.identities[token]
        with self.hub.db.write() as session:
            source = Source(
                id=f"source_{installation_id}",
                name=name,
                github_id=account["id"],
                github_login=account["login"],
                github_token=f"installation:{installation_id}",
                approver_ids=approvers or [account["id"]],
                exclude=[],
            )
            session.add(source)
            session.flush()
            session.add(
                GitHubInstallation(
                    id=installation_id,
                    account_id=account["id"],
                    account_login=account["login"],
                    source_id=source.id,
                )
            )

    def invite(self, name):
        response = self.client.post(
            "/v1/admin/contributors", headers=self.admin, json={"name": name}
        )
        assert response.status_code == 200, response.text
        identity = response.json()
        headers = {"Authorization": f"Bearer {identity['token']}"}
        response = self.client.post(
            "/v1/me/github", headers=headers, json={"github_token": f"{name}-token"}
        )
        assert response.status_code == 200, response.text
        self.users[name] = headers
        return identity

    def sync(self):
        response = self.client.post("/v1/admin/sync", headers=self.admin)
        assert response.status_code == 200, response.text
        return response.json()

    def claim(self, name="bob", key="test-claim-1", **kwargs):
        return self.client.post(
            "/v1/work/claim", headers=self.users[name], json={"idempotency_key": key, **kwargs}
        )

    def lease(self, claim):
        return {key: claim["assignment"][key] for key in ["attempt_id", "generation"]}

    def action(self, name, claim, action, **kwargs):
        return self.client.post(
            f"/v1/work/{claim['contract']['contract_id']}/{action}",
            headers=self.users[name],
            json={**self.lease(claim), **kwargs},
        )

    def submit(self, claim, name="bob"):
        pull = self.github.pull_data["alice/widget", 9]
        return self.action(
            name,
            claim,
            "submit",
            pr_url=pull["html_url"],
            head_sha=pull["head"]["sha"],
            evidence="Regression tests passed",
        )


@pytest.fixture
def env(tmp_path):
    github = FakeGitHub()
    url = os.getenv("WORKHUB_TEST_DATABASE_URL", f"sqlite:///{tmp_path}/hub.db")
    database = None
    if url == "durable":
        # Cloudflare Durable Object SQLite, through the production adapter.
        from durable_fake import FakeDurableStorage

        database = Database(storage=FakeDurableStorage(str(tmp_path / "durable.sqlite")))
    elif os.getenv("WORKHUB_TEST_DATABASE_URL"):
        engine = create_engine(url)
        Base.metadata.drop_all(engine)
        engine.dispose()
    settings = Settings(url, Fernet.generate_key().decode(), "A" * 40, lease_seconds=60)
    app = create_app(settings, github_factory=github, clock=lambda: github.now, database=database)
    environment = Environment(app, github)
    environment.install_source()
    environment.invite("bob")
    environment.invite("carol")
    environment.sync()
    yield environment
    environment.client.close()
    app.state.hub.db.engine.dispose()
