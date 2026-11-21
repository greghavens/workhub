import copy
import hashlib
import hmac
import json

from sqlalchemy import select

from workhub.models import Task, WebhookDelivery


def webhook(env, payload, event="issues", delivery="delivery-1", signature=None):
    env.hub.integrations.save_config("app", {"webhook_secret": "test-secret"})
    body = json.dumps(payload).encode()
    signature = signature or "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    return env.client.post(
        "/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Delivery": delivery,
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature,
        },
    )


def test_signed_snapshot_approval_and_replay(env):
    env.github.add_issue("alice/widget", 2)
    issue = env.github.issue_data["alice/widget", 2]
    issue["updated_at"] = env.github.iso(
        10
    )  # Polling alone cannot infer this old label's snapshot.
    payload = {
        "action": "labeled",
        "label": {"name": "agent:approved"},
        "sender": {"id": 1},
        "repository": env.github.repos["alice/widget"],
        "issue": copy.deepcopy(issue),
    }
    assert webhook(env, payload, signature="sha256=bad").status_code == 401
    response = webhook(env, payload)
    assert response.status_code == 202, response.text
    with env.hub.db.read() as session:
        task = session.scalar(select(Task).where(Task.repository_id == 100, Task.issue_number == 2))
        assert task.state == "ready"
        assert task.approval["method"] == "webhook_snapshot"
        assert session.get(WebhookDelivery, "delivery-1").state == "complete"
    assert webhook(env, payload).json()["duplicate"] is True
    assert webhook(env, {**payload, "action": "edited"}).status_code == 409


def test_stale_webhook_cannot_approve_changed_work(env):
    env.github.add_issue("alice/widget", 2)
    snapshot = copy.deepcopy(env.github.issue_data["alice/widget", 2])
    env.github.issue_data["alice/widget", 2]["body"] = "Changed after label"
    env.github.issue_data["alice/widget", 2]["updated_at"] = env.github.iso(10)
    payload = {
        "action": "labeled",
        "label": {"name": "agent:approved"},
        "sender": {"id": 1},
        "repository": env.github.repos["alice/widget"],
        "issue": snapshot,
    }
    assert webhook(env, payload).status_code == 202
    work = env.client.get("/v1/work", headers=env.users["bob"]).json()
    assert all(t["issue_number"] != 2 for t in work)


def test_webhook_retries_survive_temporary_outage(env):
    issue = copy.deepcopy(env.github.issue_data["alice/widget", 1])
    env.github.unavailable = True
    response = webhook(
        env, {"action": "edited", "repository": env.github.repos["alice/widget"], "issue": issue}
    )
    assert response.status_code == 202
    with env.hub.db.read() as session:
        delivery = session.get(WebhookDelivery, "delivery-1")
        assert delivery.state == "pending"
        assert "Goal: fix keyboard" not in delivery.encrypted_payload
    env.github.unavailable = False
    env.github.now += 5
    assert env.hub.webhooks.drain()["processed"] == 1


def test_declared_dependencies_block_until_merged(env):
    env.github.add_issue("alice/widget", 2)
    env.github.issue_data["alice/widget", 2]["body"] += '\n<!-- workhub: {"depends_on":["#1"]} -->'
    env.sync()
    work = env.client.get("/v1/work", headers=env.users["bob"]).json()
    assert [w["issue_number"] for w in work] == [1]
    first = env.claim().json()
    pull = env.github.make_pr(first)
    assert env.submit(first).status_code == 200
    pull["state"], pull["merged"] = "closed", True
    env.sync()
    second = env.claim("carol", key="dependency-ready").json()
    assert second["contract"]["source"]["issue_number"] == 2
    assert second["contract"]["dependencies"] == [first["contract"]["contract_id"]]


def test_admin_dependency_cycles_rejected_and_active_lease_revoked(env):
    env.github.add_issue("alice/widget", 2)
    env.sync()
    with env.hub.db.read() as session:
        tasks = {
            t.issue_number: t.id
            for t in session.scalars(select(Task).where(Task.repository_id == 100))
        }
    assert (
        env.client.put(
            f"/v1/admin/tasks/{tasks[2]}/dependencies",
            headers=env.admin,
            json={"dependencies": [tasks[1]]},
        ).status_code
        == 200
    )
    assert (
        env.client.put(
            f"/v1/admin/tasks/{tasks[1]}/dependencies",
            headers=env.admin,
            json={"dependencies": [tasks[2]]},
        ).status_code
        == 409
    )
    claim = env.claim().json()
    # Remove old edge, then changing the leased task's dependencies invalidates its lease.
    env.client.put(
        f"/v1/admin/tasks/{tasks[2]}/dependencies", headers=env.admin, json={"dependencies": []}
    )
    assert (
        env.client.put(
            f"/v1/admin/tasks/{tasks[1]}/dependencies",
            headers=env.admin,
            json={"dependencies": [tasks[2]]},
        ).status_code
        == 200
    )
    assert env.action("bob", claim, "heartbeat").status_code == 409


def test_custom_fork_provisioning_and_existing_fork_reuse(env):
    claim = env.claim(fork_name="my-contributions").json()
    assert claim["contract"]["checkout"]["push_repository"] == "bob/my-contributions"
    result = env.action("bob", claim, "provision")
    assert result.status_code == 200, result.text
    required = result.json()
    assert required["status"] == "fork_required"
    assert required["command"][:4] == ["gh", "repo", "fork", "alice/widget"]
    assert required["command"][required["command"].index("--fork-name") + 1] == "my-contributions"
    assert "alice/widget" not in env.github.fork_data  # The hub never creates the fork.
    env.github.contributor_fork("alice/widget", "bob-token", "my-contributions")
    assert env.action("bob", claim, "provision").json()["status"] == "ready"
    env.action("bob", claim, "release", note="Test another claim")
    env.sync()
    second = env.claim(key="reuse-custom-fork").json()
    assert second["contract"]["checkout"]["push_repository"] == "bob/my-contributions"
