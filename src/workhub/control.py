"""Product-manager operations shared by the HTTP API and both MCP transports."""

import secrets
from typing import Literal
from urllib.parse import quote

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from workhub.domain import HubError, token_hash
from workhub.models import AuthFlow, Contributor, Repository, SourceRepository
from workhub.schemas import AppStart, OAuthStart


def actor_key(current):
    if current.role == "admin":
        return f"owner:{current.github_id}" if current.github_id else "bootstrap-owner"
    return "contributor:" + current.contributor_id


def mount_control(app, hub, principal, admin):
    auth = app.state.auth

    @app.get("/v1/identity")
    def identity(current=Depends(principal)):
        return {
            "role": current.role,
            "github_id": current.github_id,
            "contributor_id": current.contributor_id,
            "mcp_scopes": ["work", "admin"] if current.role == "admin" else ["work"],
        }

    @app.get("/v1/admin/contributors", dependencies=[Depends(admin)])
    def contributors():
        with hub.db.read() as session:
            return [
                {"id": u.id, "name": u.name, "github_login": u.github_login, "active": u.active}
                for u in session.scalars(select(Contributor))
            ]

    def source_repository(source_name, name):
        source = hub.source(source_name)
        with hub.db.read() as session:
            repo = session.scalar(select(Repository).where(Repository.full_name == name))
            if not repo or not session.get(SourceRepository, (source.id, repo.id)):
                raise HubError(404, "Repository is not in this source; synchronize it first")
            if repo.authority_source_id != source.id:
                raise HubError(409, "Use the repository's authority source")
        return source, repo

    @app.get("/v1/admin/repositories", dependencies=[Depends(admin)])
    def repositories(source: str):
        connection = hub.source(source)
        with hub.db.read() as session:
            return [
                {
                    "repository": r.full_name,
                    "id": r.id,
                    "private": r.private,
                    "authority_source_id": r.authority_source_id,
                }
                for r in session.scalars(
                    select(Repository)
                    .join(SourceRepository)
                    .where(SourceRepository.source_id == connection.id)
                )
            ]

    @app.get("/v1/admin/issues", dependencies=[Depends(admin)])
    def backlog(source: str, repository: str, state: Literal["open", "closed", "all"] = "open"):
        connection, _ = source_repository(source, repository)
        with hub.github(connection.github_token) as github:
            return github.backlog(repository, state)

    @app.get("/v1/admin/issue", dependencies=[Depends(admin)])
    def issue(source: str, repository: str, issue_number: int):
        connection, _ = source_repository(source, repository)
        with hub.github(connection.github_token) as github:
            return {
                "issue": github.issue(repository, issue_number),
                "comments": github.comments(repository, issue_number),
            }

    @app.get("/v1/admin/pull-request", dependencies=[Depends(admin)])
    def inspect_pr(source: str, repository: str, pull_number: int):
        connection, _ = source_repository(source, repository)
        with hub.github(connection.github_token) as github:
            pull = github.pull(repository, pull_number)
            return {
                "pull_request": pull,
                "reviews": github.reviews(repository, pull_number),
                "checks": github.checks(repository, pull["head"]["sha"]),
                "files": github.files(repository, pull_number),
            }

    @app.post("/v1/connections/start")
    def connection_start(data: OAuthStart, current=Depends(principal)):
        if data.kind == "login" or data.invitation:
            raise HubError(422, "Use hub_login_start for initial sign-in")
        if data.kind == "source" and not data.name:
            raise HubError(422, "Source name is required")
        result = auth.begin(
            data.kind,
            data.provider,
            principal=current,
            cli=True,
            data={
                "name": data.name,
                "approvers": data.approvers,
                "exclude": data.exclude,
                "control_actor": actor_key(current),
            },
        )
        # The authenticated initiator monitors status; no polling/session secret enters agent context.
        return {key: value for key, value in result.items() if key != "poll_token"}

    @app.get("/v1/connections/{flow_id}")
    def connection_status(flow_id: str, current=Depends(principal)):
        with hub.db.read() as session:
            flow = session.get(AuthFlow, flow_id)
            if not flow or flow.data.get("control_actor") != actor_key(current):
                raise HubError(404, "Connection request not found")
            status = (
                "expired"
                if flow.expires_at <= hub.now() and flow.status != "complete"
                else flow.status
            )
            return {"id": flow.id, "kind": flow.kind, "status": status, "error": flow.error}

    def app_handoff(kind, data, current):
        if kind == "installation" and not hub.integrations.config("app").get("slug"):
            raise HubError(409, "Register the GitHub App first")
        flow = auth.special_flow(kind, {**data.model_dump(), "control_actor": actor_key(current)})
        ticket = secrets.token_urlsafe(40)
        with hub.db.write() as session:
            record = session.get(AuthFlow, flow["id"])
            record.data = {**record.data, "handoff_hash": token_hash(ticket)}
        return {
            "id": flow["id"],
            "authorization_url": hub.settings.public_url
            + f"/auth/agent/{flow['id']}?ticket={ticket}",
            "expires_in": 600,
        }

    @app.post("/v1/admin/integrations/app/agent-register")
    def register_app(data: AppStart, current=Depends(admin)):
        return app_handoff("manifest", data, current)

    @app.post("/v1/admin/integrations/app/agent-install")
    def install_app(data: AppStart, current=Depends(admin)):
        return app_handoff("installation", data, current)

    @app.get("/auth/agent/{flow_id}")
    def handoff(flow_id: str, ticket: str, request: Request):
        browser, state = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
        with hub.db.write() as session:
            flow = session.get(AuthFlow, flow_id)
            if (
                not flow
                or flow.kind not in {"manifest", "installation"}
                or flow.status != "waiting"
                or flow.expires_at <= hub.now()
                or not secrets.compare_digest(flow.data.get("handoff_hash", ""), token_hash(ticket))
            ):
                raise HubError(410, "App authorization link expired or already used")
            flow.data = {key: value for key, value in flow.data.items() if key != "handoff_hash"}
            flow.browser_hash, flow.state_hash = token_hash(browser), token_hash(state)
            kind = flow.kind
        if kind == "manifest":
            target = f"/auth/github/app/manifest/{flow_id}?state={state}"
        else:
            slug = hub.integrations.config("app")["slug"]
            target = (
                f"https://github.com/apps/{quote(slug, safe='')}/installations/new?state={state}"
            )
        response = RedirectResponse(target, status_code=303)
        response.set_cookie(
            "workhub_oauth",
            browser,
            max_age=600,
            httponly=True,
            secure=hub.settings.public_url.startswith("https://"),
            samesite="lax",
            path="/auth",
        )
        return response
