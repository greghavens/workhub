import httpx
import pytest

from workhub.github import GitHub, GitHubError


def fake_client(handler):
    github = GitHub("fake-token")
    github.client.close()
    github.client = httpx.Client(
        base_url="https://api.github.com", transport=httpx.MockTransport(handler)
    )
    return github


def test_repository_discovery_paginates_all_affiliations():
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.params["affiliation"] == "owner,collaborator,organization_member"
        page = int(request.url.params["page"])
        return httpx.Response(
            200, json=[{"id": i} for i in range(100)] if page == 1 else [{"id": 101}]
        )

    with fake_client(handler) as github:
        assert len(github.repositories()) == 101
    assert len(seen) == 2


def test_pagination_fails_instead_of_silently_truncating():
    with fake_client(lambda _: httpx.Response(200, json=[{}] * 100)) as github:
        with pytest.raises(GitHubError, match="pagination limit"):
            github.pages("/anything", max_pages=2)


def test_latest_checks_and_statuses():
    def handler(request):
        if request.url.path.endswith("check-runs"):
            return httpx.Response(
                200,
                json={
                    "check_runs": [
                        {"name": "unit", "status": "completed", "conclusion": "success"},
                        {"name": "lint", "status": "in_progress", "conclusion": None},
                    ]
                },
            )
        return httpx.Response(
            200,
            json=[
                {"context": "legacy", "state": "failure"},
                {"context": "legacy", "state": "success"},
            ],
        )

    with fake_client(handler) as github:
        assert github.checks("alice/widget", "a" * 40) == {
            "unit": True,
            "lint": False,
            "legacy": False,
        }


def test_github_error_does_not_echo_upstream_secrets():
    with fake_client(lambda _: httpx.Response(403, json={"message": "secret-token"})) as github:
        with pytest.raises(GitHubError) as caught:
            github.me()
        assert "secret-token" not in str(caught.value)


def test_policy_is_read_at_immutable_commit():
    import base64

    def handler(request):
        if "/commits/" in request.url.path:
            return httpx.Response(200, json={"sha": "a" * 40})
        assert request.url.params["ref"] == "a" * 40
        content = base64.b64encode(b"required_checks: [unit]\n").decode()
        return httpx.Response(200, json={"encoding": "base64", "size": 24, "content": content})

    with fake_client(handler) as github:
        policy, commit = github.policy({"full_name": "alice/widget", "default_branch": "main"})
        assert policy.required_checks == ["unit"]
        assert commit == "a" * 40
