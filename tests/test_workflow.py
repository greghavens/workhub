from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select

from workhub.models import Attempt, Contributor, Source, Task
from workhub.schemas import Policy


def test_account_discovery_filters_private_work(env):
    tasks = env.client.get("/v1/admin/tasks", headers=env.admin).json()
    assert len(tasks) == 2
    work = env.client.get("/v1/work", headers=env.users["bob"]).json()
    assert [t["repository"] for t in work] == ["alice/widget"]
    assert env.client.get("/v1/work").status_code == 401
    assert env.client.get("/v1/admin/tasks", headers=env.users["bob"]).status_code == 403


def test_full_claim_submit_merge(env):
    claim = env.claim().json()
    assert claim["assignment"]["state"] == "leased"
    assert claim["contract"]["checkout"]["push_repository"] == "bob/widget"
    assert claim["contract"]["delivery"]["merge_allowed"] is False
    pull = env.github.make_pr(claim)
    submitted = env.submit(claim)
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["assignment"]["state"] == "submitted"
    assert env.submit(claim).status_code == 200  # Safe retry after lost response.
    pull["state"], pull["merged"] = "closed", True
    env.sync()
    task_id = claim["contract"]["contract_id"]
    assert (
        env.client.get(f"/v1/work/{task_id}", headers=env.users["bob"]).json()["task_state"]
        == "merged"
    )


def test_simultaneous_claims_only_one_wins(env):
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(lambda name: env.claim(name=name, key=f"race-{name}"), ["bob", "carol"])
        )
    assert all(r.status_code == 200 for r in responses)
    assert sum("contract" in r.json() for r in responses) == 1


def test_idempotent_claim_and_key_conflict(env):
    claim = env.claim().json()
    again = env.claim().json()
    assert claim["assignment"]["attempt_id"] == again["assignment"]["attempt_id"]
    assert env.claim(work_minutes=30).status_code == 409


def test_concurrent_identical_claim_retries(env):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: env.claim().json(), range(2)))
    assert results[0]["assignment"]["attempt_id"] == results[1]["assignment"]["attempt_id"]


@pytest.mark.parametrize("change", ["body", "remove_label", "blocked", "policy", "close"])
def test_approval_changes_revoke_active_contract(env, change):
    claim = env.claim().json()
    issue = env.github.issue_data["alice/widget", 1]
    if change == "body":
        issue["body"] = "Replace authentication"
    elif change == "remove_label":
        issue["labels"] = []
    elif change == "blocked":
        issue["labels"].append({"name": "agent:blocked"})
    elif change == "close":
        issue["state"] = "closed"
    else:
        env.github.policies["alice/widget"] = Policy(required_checks=["unit"])
    response = env.action("bob", claim, "heartbeat")
    assert response.status_code == 409
    env.github.make_pr(claim)
    assert env.submit(claim).status_code == 409


def test_unauthorized_labeler_and_stale_label_require_approval(env):
    env.github.add_issue("alice/widget", 2, actor=2)
    env.github.add_issue("alice/widget", 3)
    env.github.issue_data["alice/widget", 3]["updated_at"] = env.github.iso(10)
    env.sync()
    work = env.client.get("/v1/work", headers=env.users["bob"]).json()
    assert [t["issue_number"] for t in work] == [1]
    payload = {"source": "alice", "repository": "alice/widget", "issue_number": 3}
    # The issue changed after it was labelled: the hub cannot vouch for it on its own.
    stale = env.client.post("/v1/admin/approve", headers=env.admin, json=payload)
    assert stale.status_code == 409 and "re-apply" in stale.json()["detail"]
    # Issue 2 was labelled by a non-approver.
    assert (
        env.client.post(
            "/v1/admin/approve", headers=env.admin, json={**payload, "issue_number": 2}
        ).status_code
        == 403
    )
    env.github.label("alice/widget", 3)
    response = env.client.post("/v1/admin/approve", headers=env.admin, json=payload)
    assert response.status_code == 200, response.text
    assert len(env.client.get("/v1/work", headers=env.users["bob"]).json()) == 2


def test_label_removed_and_readded_by_unapproved_actor_revokes(env):
    claim = env.claim().json()
    env.github.event_data["alice/widget", 1].append(
        {
            "id": 100,
            "event": "labeled",
            "actor": {"id": 2},
            "label": {"name": "agent:approved"},
            "created_at": env.github.iso(1),
        }
    )
    assert env.action("bob", claim, "heartbeat").status_code == 409


def test_lease_expiry_requeues_and_fences_stale_writer(env):
    first = env.claim().json()
    env.github.now += 61
    env.sync()
    second = env.claim("carol", key="carol-new").json()
    assert second["contract"]["contract_id"] == first["contract"]["contract_id"]
    assert second["assignment"]["generation"] > first["assignment"]["generation"]
    assert env.action("bob", first, "heartbeat").status_code == 409
    env.github.make_pr(first)
    assert env.submit(first).status_code == 409


def test_expired_assignment_with_existing_pr_is_not_reissued(env):
    claim = env.claim().json()
    env.github.make_pr(claim)
    env.github.now += 61
    env.sync()
    assert env.claim("carol", key="new-carol").json()["work"] is None
    resumed = env.action("bob", claim, "resume")
    assert resumed.status_code == 200, resumed.text
    assert env.submit(resumed.json()).status_code == 200


def test_total_deadline_limits_heartbeats(env):
    claim = env.claim(work_minutes=1).json()
    env.github.now += 30
    renewed = env.action("bob", claim, "heartbeat").json()
    assert renewed["assignment"]["expires_at"] == claim["assignment"]["deadline"]
    env.github.now += 31
    assert env.action("bob", claim, "heartbeat").status_code == 409


def test_private_access_revocation_blocks_get_and_heartbeat(env):
    claim = env.claim().json()
    env.github.access["bob-token"].clear()
    assert env.action("bob", claim, "heartbeat").status_code == 404
    task_id = claim["contract"]["contract_id"]
    assert env.client.get(f"/v1/work/{task_id}", headers=env.users["bob"]).status_code == 404


def test_capabilities_and_repository_scope(env):
    env.github.policies["alice/widget"] = Policy(required_tools=["node", "pnpm"])
    env.github.label("alice/widget", 1)
    env.client.post(
        "/v1/admin/approve",
        headers=env.admin,
        json={"source": "alice", "repository": "alice/widget", "issue_number": 1},
    )
    assert env.claim().json()["work"] is None
    assert "contract" in env.claim(key="with-tools", capabilities=["node", "pnpm"]).json()


@pytest.mark.parametrize(
    "fault",
    [
        "author",
        "branch",
        "base",
        "draft",
        "sha",
        "body",
        "files",
        "ancestry",
        "workflow",
        "rename",
        "dependency",
    ],
)
def test_submission_rejects_invalid_pr(env, fault):
    claim = env.claim().json()
    pull = env.github.make_pr(claim)
    if fault == "author":
        pull["user"]["id"] = 3
    elif fault == "branch":
        pull["head"]["ref"] = "different"
    elif fault == "base":
        pull["base"]["ref"] = "release"
    elif fault == "draft":
        pull["draft"] = True
    elif fault == "sha":
        response = env.action(
            "bob", claim, "submit", pr_url=pull["html_url"], head_sha="c" * 40, evidence="ok"
        )
        assert response.status_code == 409
        return
    elif fault == "body":
        pull["body"] = "No contract"
    elif fault == "files":
        pull["changed_files"] = 2
    elif fault == "ancestry":
        env.github.contains = False
    elif fault == "workflow":
        env.github.file_data["alice/widget", 9] = [{"filename": ".github/workflows/ci.yml"}]
    elif fault == "rename":
        env.github.file_data["alice/widget", 9] = [
            {"filename": "src/ci.yml", "previous_filename": ".github/workflows/ci.yml"}
        ]
    elif fault == "dependency":
        env.github.file_data["alice/widget", 9] = [{"filename": "package.json"}]
    assert env.submit(claim).status_code == 409


def test_required_checks_and_new_sha_invalidate_submission(env):
    env.github.policies["alice/widget"] = Policy(required_checks=["unit"])
    env.github.label("alice/widget", 1)
    env.client.post(
        "/v1/admin/approve",
        headers=env.admin,
        json={"source": "alice", "repository": "alice/widget", "issue_number": 1},
    )
    claim = env.claim().json()
    pull = env.github.make_pr(claim)
    assert env.submit(claim).status_code == 409
    env.github.check_data["alice/widget", "b" * 40] = {"unit": True}
    assert env.submit(claim).status_code == 200
    pull["head"]["sha"] = "c" * 40
    env.sync()
    resumed = env.action("bob", claim, "resume").json()
    assert env.submit(resumed).status_code == 409
    env.github.check_data["alice/widget", "c" * 40] = {"unit": True}
    assert env.submit(resumed).status_code == 200


def test_closed_pr_needs_explicit_retry(env):
    claim = env.claim().json()
    pull = env.github.make_pr(claim)
    assert env.submit(claim).status_code == 200
    pull["state"] = "closed"
    env.sync()
    assert env.claim("carol", key="new-carol").json()["work"] is None
    response = env.client.post(
        f"/v1/admin/tasks/{claim['contract']['contract_id']}/retry",
        headers=env.admin,
        json={"reason": "Try a different implementation"},
    )
    assert response.status_code == 200, response.text
    assert "contract" in env.claim("carol", key="new-carol-2").json()


def test_block_and_resume(env):
    claim = env.claim().json()
    assert env.action("bob", claim, "block", note="Need reproduction").status_code == 200
    assert env.claim("carol", key="carol-blocked").json()["work"] is None
    resumed = env.action("bob", claim, "resume")
    assert resumed.status_code == 200
    assert env.action("bob", claim, "heartbeat").status_code == 409


def test_secrets_encrypted_and_invites_hashed(env):
    with env.hub.db.read() as session:
        source = session.scalar(select(Source))
        user = session.scalar(select(Contributor).where(Contributor.name == "bob"))
        assert source.github_token != "alice-token"
        assert user.github_token != "bob-token"
        assert user.token_hash != env.users["bob"]["Authorization"].removeprefix("Bearer ")
    audit = env.client.get("/v1/admin/audit", headers=env.admin).text
    assert "alice-token" not in audit
    assert "bob-token" not in audit


def test_source_access_removed_stops_dispatch(env):
    env.github.access["alice-token"].remove("alice/widget")
    env.sync()
    assert env.claim().json()["work"] is None


def test_github_outage_fails_closed(env):
    claim = env.claim().json()
    env.github.unavailable = True
    assert env.action("bob", claim, "heartbeat").status_code == 503


def test_duplicate_sources_share_one_task(env):
    env.install_source("alice-alt", installation_id=2)
    env.sync()
    with env.hub.db.read() as session:
        assert len(list(session.scalars(select(Task)))) == 2
    first = env.claim(source="alice-alt").json()
    assert first["contract"]["source"]["repository"] == "alice/widget"
    assert env.claim("carol", key="another-source", source="alice").json()["work"] is None


def test_revoked_contributor_loses_token_and_lease(env):
    claim = env.claim().json()
    with env.hub.db.read() as session:
        user_id = session.scalar(select(Contributor.id).where(Contributor.name == "bob"))
    assert (
        env.client.delete(f"/v1/admin/contributors/{user_id}", headers=env.admin).status_code == 200
    )
    assert env.action("bob", claim, "heartbeat").status_code == 401
    with env.hub.db.read() as session:
        assert session.get(Attempt, claim["assignment"]["attempt_id"]).state == "revoked"


def test_merge_that_auto_closes_issue_is_observed(env):
    claim = env.claim().json()
    pull = env.github.make_pr(claim)
    assert env.submit(claim).status_code == 200
    pull["state"], pull["merged"] = "closed", True
    env.github.issue_data["alice/widget", 1]["state"] = "closed"
    env.sync()
    result = env.client.get(
        f"/v1/work/{claim['contract']['contract_id']}", headers=env.users["bob"]
    )
    assert result.json()["task_state"] == "merged"


def test_get_checks_live_approval_before_agent_publishes(env):
    claim = env.claim().json()
    env.github.issue_data["alice/widget", 1]["body"] = "Different scope"
    result = env.client.get(
        f"/v1/work/{claim['contract']['contract_id']}", headers=env.users["bob"]
    )
    assert result.status_code == 409


def test_submission_replay_rechecks_remote_sha(env):
    claim = env.claim().json()
    pull = env.github.make_pr(claim)
    assert env.submit(claim).status_code == 200
    pull["head"]["sha"] = "c" * 40
    response = env.action(
        "bob", claim, "submit", pr_url=pull["html_url"], head_sha="b" * 40, evidence="ok"
    )
    assert response.status_code == 409


def test_review_requests_resume_same_branch(env):
    claim = env.claim().json()
    env.github.make_pr(claim)
    assert env.submit(claim).status_code == 200
    env.github.review_data["alice/widget", 9] = [{"user": {"id": 1}, "state": "CHANGES_REQUESTED"}]
    env.sync()
    task_id = claim["contract"]["contract_id"]
    assert (
        env.client.get(f"/v1/work/{task_id}", headers=env.users["bob"]).json()["task_state"]
        == "changes_requested"
    )
    resumed = env.action("bob", claim, "resume").json()
    assert resumed["contract"]["checkout"] == claim["contract"]["checkout"]
    assert resumed["assignment"]["generation"] > claim["assignment"]["generation"]


def test_approval_history_preserves_previous_specifications(env):
    from workhub.models import Approval

    issue = env.github.issue_data["alice/widget", 1]
    old_body = issue["body"]
    issue["body"] = "Approved new goal"
    env.github.label("alice/widget", 1)
    response = env.client.post(
        "/v1/admin/approve",
        headers=env.admin,
        json={"source": "alice", "repository": "alice/widget", "issue_number": 1},
    )
    task_id = response.json()["task_id"]
    with env.hub.db.read() as session:
        assert session.get(Approval, (task_id, 1)).specification["body"] == old_body
        assert session.get(Approval, (task_id, 2)).specification["body"] == "Approved new goal"


def test_explicit_reapproval_after_reverting_revoked_issue(env):
    issue = env.github.issue_data["alice/widget", 1]
    old_body = issue["body"]
    issue["body"] = "Changed"
    env.sync()
    issue["body"] = old_body
    env.sync()
    assert env.client.get("/v1/work", headers=env.users["bob"]).json() == []
    env.github.label("alice/widget", 1)
    assert (
        env.client.post(
            "/v1/admin/approve",
            headers=env.admin,
            json={"source": "alice", "repository": "alice/widget", "issue_number": 1},
        ).status_code
        == 200
    )
    assert "contract" in env.claim().json()


def test_hub_never_stores_a_pasted_github_token(env):
    # Sources come only from read-only App installations; there is no way to hand the hub
    # a GitHub token it cannot verify is read-only.
    pasted = {"name": "pasted", "github_token": "alice-token"}
    created = env.client.post("/v1/admin/sources", headers=env.admin, json=pasted)
    assert created.status_code in {404, 405}
    rotate = env.client.put(
        "/v1/admin/sources/alice/github", headers=env.admin, json={"github_token": "alice-token"}
    )
    assert rotate.status_code in {404, 405}
    # A contributor's pasted token proves identity once and is then discarded.
    with env.hub.db.read() as session:
        users = list(session.scalars(select(Contributor)))
    assert users and all(u.github_id and u.github_token is None for u in users)


def test_health_and_openapi_report_package_version(env):
    import tomllib
    from pathlib import Path

    expected = tomllib.loads(Path(__file__).parents[1].joinpath("pyproject.toml").read_text())[
        "project"
    ]["version"]
    assert env.client.get("/health").json() == {"status": "ok", "version": expected}
    assert env.client.get("/openapi.json").json()["info"]["version"] == expected
