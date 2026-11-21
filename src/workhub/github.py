import base64
from urllib.parse import quote

import httpx
import yaml

from workhub.schemas import Policy


class GitHubError(Exception):
    def __init__(self, status: int, message: str = "GitHub request failed"):
        self.status = status
        super().__init__(message)


# GitHub rejects API requests without a User-Agent. Set it explicitly: the Workers runtime's
# fetch-based httpx transport does not send httpx's default.
USER_AGENT = "workhub"
# Replaced inside Cloudflare Workers by a fetch transport that keeps the User-Agent header.
TRANSPORT = None


def http_client(**options):
    """The only way the hub reaches GitHub over HTTP."""
    return httpx.Client(transport=TRANSPORT, follow_redirects=False, **options)


class GitHub:
    """Fixed-origin GitHub API client; never follows URLs supplied by a task."""

    def __init__(self, token: str):
        self.client = http_client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
            timeout=20,
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.client.close()

    def request(self, method, path, **kwargs):
        if method != "GET":
            # The hub never writes to GitHub: approvals are labels applied by maintainers and
            # contributors push and fork with their own credentials.
            raise GitHubError(405, "Work Hub has read-only GitHub access")
        try:
            result = self.client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise GitHubError(503, "GitHub is unavailable; retry later") from exc
        if result.status_code >= 300:
            # Do not include response bodies or request headers (could contain secrets).
            raise GitHubError(result.status_code, f"GitHub returned HTTP {result.status_code}")
        return result.json() if result.content else None

    def pages(self, path, *, key=None, params=None, max_pages=1000):
        result = []
        for page in range(1, max_pages + 1):
            data = self.request(
                "GET", path, params={**(params or {}), "per_page": 100, "page": page}
            )
            items = data[key] if key else data
            result.extend(items)
            if len(items) < 100:
                return result
        raise GitHubError(422, "GitHub result exceeds supported pagination limit")

    def me(self):
        return self.request("GET", "/user")

    def user(self, login):
        return self.request("GET", f"/users/{quote(login, safe='')}")

    def repositories(self):
        if getattr(self, "installation", False):
            return self.pages("/installation/repositories", key="repositories")
        return self.pages(
            "/user/repos", params={"affiliation": "owner,collaborator,organization_member"}
        )

    def repository(self, name):
        return self.request("GET", f"/repos/{name}")

    def issue(self, name, number):
        return self.request("GET", f"/repos/{name}/issues/{number}")

    def backlog(self, name, state="open"):
        return [
            i
            for i in self.pages(f"/repos/{name}/issues", params={"state": state})
            if "pull_request" not in i
        ]

    def comments(self, name, number):
        return self.pages(f"/repos/{name}/issues/{number}/comments")

    def issues(self, name):
        return [
            i
            for i in self.pages(
                f"/repos/{name}/issues", params={"state": "open", "labels": "agent:approved"}
            )
            if "pull_request" not in i
        ]

    def events(self, name, number):
        return self.pages(f"/repos/{name}/issues/{number}/events")

    def policy(self, repo):
        name = repo["full_name"]
        branch = quote(repo["default_branch"], safe="")
        commit = self.request("GET", f"/repos/{name}/commits/{branch}")["sha"]
        try:
            data = self.request(
                "GET", f"/repos/{name}/contents/.workhub.yml", params={"ref": commit}
            )
        except GitHubError as exc:
            if exc.status == 404:
                return Policy(), commit
            raise
        if data.get("size", 0) > 100_000 or data.get("encoding") != "base64":
            raise GitHubError(422, "Repository policy is too large or unsupported")
        try:
            return Policy.model_validate(
                yaml.safe_load(base64.b64decode(data["content"])) or {}
            ), commit
        except (ValueError, yaml.YAMLError) as exc:
            raise GitHubError(422, "Invalid .workhub.yml policy") from exc

    def pull(self, name, number):
        return self.request("GET", f"/repos/{name}/pulls/{number}")

    def pulls_for_branch(self, name, owner, branch):
        return self.pages(
            f"/repos/{name}/pulls", params={"state": "all", "head": f"{owner}:{branch}"}
        )

    def files(self, name, number):
        return self.pages(f"/repos/{name}/pulls/{number}/files", max_pages=31)

    def reviews(self, name, number):
        return self.pages(f"/repos/{name}/pulls/{number}/reviews")

    def checks(self, name, sha):
        checks = self.pages(
            f"/repos/{name}/commits/{sha}/check-runs", key="check_runs", params={"filter": "latest"}
        )
        statuses = self.pages(f"/repos/{name}/commits/{sha}/statuses")
        result = {}
        for status in statuses:  # GitHub returns newest first.
            result.setdefault(status["context"], status["state"] == "success")
        grouped = {}
        for check in checks:
            grouped.setdefault(check["name"], []).append(
                check["status"] == "completed" and check["conclusion"] == "success"
            )
        for name, values in grouped.items():
            result[name] = all(values) and result.get(name, True)
        return result

    def contains_base(self, name, base, head):
        comparison = self.request("GET", f"/repos/{name}/compare/{base}...{head}")
        return comparison["status"] in {"ahead", "identical"}

    def forks(self, name):
        return self.pages(f"/repos/{name}/forks")

    def user_by_id(self, github_id):
        return self.request("GET", f"/user/{int(github_id)}")

    def permission(self, name, login):
        """A user's permission on a repository: admin, write, read, or none."""
        try:
            data = self.request(
                "GET", f"/repos/{name}/collaborators/{quote(login, safe='')}/permission"
            )
        except GitHubError as exc:
            if exc.status == 404:
                return {"permission": "none", "user": None}
            raise
        return data
