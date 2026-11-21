import hashlib
import hmac
import json
import secrets

from sqlalchemy import select

from workhub.domain import HubError, digest, latest_approval_event, specification
from workhub.github import GitHubError
from workhub.models import (
    GitHubInstallation,
    Repository,
    Source,
    WebhookDelivery,
)


class Webhooks:
    def __init__(self, hub):
        self.hub = hub

    def accept(self, delivery_id, event, signature, body):
        secret = (
            self.hub.integrations.config("app").get("webhook_secret")
            or self.hub.settings.github_webhook_secret
        )
        if not secret:
            raise HubError(503, "GitHub webhook secret is not configured")
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not signature or not hmac.compare_digest(signature, expected):
            raise HubError(401, "Invalid GitHub webhook signature")
        if not delivery_id or len(delivery_id) > 200 or not event or len(event) > 100:
            raise HubError(400, "Missing or invalid webhook delivery headers")
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError()
        except ValueError as exc:
            raise HubError(400, "Invalid webhook JSON") from exc
        body_hash = hashlib.sha256(body).hexdigest()
        with self.hub.db.write() as session:
            prior = session.get(WebhookDelivery, delivery_id)
            if prior:
                if prior.payload_hash != body_hash or prior.event != event:
                    raise HubError(409, "Delivery ID was reused with a different payload")
                return {"accepted": True, "duplicate": True, "state": prior.state}
            session.add(
                WebhookDelivery(
                    id=delivery_id,
                    event=event,
                    encrypted_payload=self.hub.encrypt(body.decode()),
                    payload_hash=body_hash,
                    received_at=self.hub.now(),
                    available_at=self.hub.now(),
                )
            )
            if event == "installation" and payload.get("action") in {"suspend", "deleted"}:
                installation = session.get(
                    GitHubInstallation, payload.get("installation", {}).get("id", -1)
                )
                if installation:
                    installation.suspended = True
                    installation.encrypted_token = None
                    self.hub.audit(
                        session, "github", "installation.suspended", installation_id=installation.id
                    )
        return {"accepted": True, "duplicate": False, "state": "pending"}

    def drain(self, limit=50):
        processed = 0
        for _ in range(limit):
            owner = secrets.token_hex(16)
            with self.hub.db.write() as session:
                delivery = session.scalar(
                    select(WebhookDelivery)
                    .where(
                        WebhookDelivery.state.in_(["pending", "processing"]),
                        WebhookDelivery.available_at <= self.hub.now(),
                        WebhookDelivery.locked_until <= self.hub.now(),
                    )
                    .order_by(WebhookDelivery.received_at, WebhookDelivery.id)
                    .limit(1)
                )
                if not delivery:
                    break
                delivery.state, delivery.lock_owner = "processing", owner
                delivery.locked_until = self.hub.now() + 300
                delivery.attempts += 1
                payload = json.loads(self.hub.cipher.decrypt(delivery.encrypted_payload.encode()))
            try:
                self.process(delivery.event, payload)
            except Exception as exc:
                with self.hub.db.write() as session:
                    current = session.get(WebhookDelivery, delivery.id)
                    if current.lock_owner == owner:
                        current.state = "pending"
                        current.error = (
                            str(exc)
                            if isinstance(exc, (HubError, GitHubError))
                            else "Processing failed; delivery will be retried"
                        )
                        current.available_at = self.hub.now() + min(
                            3600, 2 ** min(current.attempts, 10)
                        )
                        current.locked_until, current.lock_owner = 0, None
                continue
            with self.hub.db.write() as session:
                current = session.get(WebhookDelivery, delivery.id)
                if current.lock_owner == owner:
                    current.state, current.error = "complete", None
                    current.locked_until, current.lock_owner = 0, None
            processed += 1
        return {"processed": processed}

    def process(self, event, payload):
        if event == "ping":
            return
        if event == "github_app_authorization":
            return  # The hub stores no user tokens, so there is nothing to revoke.
        if event in {"installation", "installation_repositories"}:
            installation_id = payload.get("installation", {}).get("id")
            with self.hub.db.read() as session:
                installation = (
                    session.get(GitHubInstallation, installation_id) if installation_id else None
                )
                source = session.get(Source, installation.source_id) if installation else None
            if not installation:
                return  # Only explicitly connected installations become queue sources.
            if payload.get("action") == "unsuspend":
                with self.hub.db.write() as session:
                    session.get(GitHubInstallation, installation_id).suspended = False
            if payload.get("action") not in {"suspend", "deleted"}:
                result = self.hub.sync(source.name)
                if result["errors"]:
                    raise HubError(503, "Installation synchronization will be retried")
            return
        repo_id = payload.get("repository", {}).get("id")
        with self.hub.db.read() as session:
            repo = session.get(Repository, repo_id) if repo_id else None
            source = session.get(Source, repo.authority_source_id) if repo else None
        if not repo or not source:
            return
        if event == "issues":
            snapshot = payload.get("issue", {})
            if not snapshot.get("number"):
                return
            with self.hub.github(source.github_token) as github:
                live_repo = github.repository(repo.full_name)
                issue = github.issue(repo.full_name, snapshot["number"])
                policy, commit = github.policy(live_repo)
                label_event = latest_approval_event(
                    github.events(repo.full_name, snapshot["number"])
                )
            approved_snapshot = (
                payload.get("action") == "labeled"
                and payload.get("label", {}).get("name") == "agent:approved"
                and payload.get("sender", {}).get("id") in source.approver_ids
                and digest(specification(snapshot)) == digest(specification(issue))
                and label_event
                and label_event["event"] == "labeled"
                and label_event.get("actor", {}).get("id") == payload["sender"]["id"]
            )
            self.hub.observe(
                source,
                live_repo,
                issue,
                policy,
                commit,
                label_event,
                webhook_actor=payload["sender"]["id"] if approved_snapshot else None,
            )
        elif event in {"pull_request", "pull_request_review", "check_run", "check_suite"}:
            errors = []
            self.hub.reconcile(errors)
            if errors:
                raise HubError(503, "PR reconciliation will be retried")
        elif event == "push":
            result = self.hub.sync(source.name)
            if result["errors"]:
                raise HubError(503, "Repository synchronization will be retried")

    def list(self):
        with self.hub.db.read() as session:
            return [
                {
                    "id": d.id,
                    "event": d.event,
                    "state": d.state,
                    "attempts": d.attempts,
                    "received_at": d.received_at,
                    "error": d.error,
                }
                for d in session.scalars(
                    select(WebhookDelivery).order_by(WebhookDelivery.received_at.desc()).limit(100)
                )
            ]
