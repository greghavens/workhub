from pathlib import Path

from fastapi import Depends, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from workhub.domain import HubError
from workhub.models import (
    Approval,
    Attempt,
    Audit,
    Contributor,
    GitHubInstallation,
    Repository,
    Source,
    Task,
)
from workhub.scheduling import blockers, graph


def dashboard(app, hub, principal, admin, contributor):
    directory = Path(__file__).parent / "static"
    app.mount("/assets", StaticFiles(directory=directory), name="assets")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = (
            "no-store" if not request.url.path.startswith("/assets/") else "public, max-age=300"
        )
        if request.url.path == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        return response

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(directory / "index.html")

    @app.get("/v1/dashboard")
    def overview(current=Depends(principal)):
        if current.role != "admin":
            with hub.db.read() as session:
                user = session.get(Contributor, current.contributor_id)
                attempts = list(
                    session.scalars(
                        select(Attempt)
                        .where(Attempt.contributor_id == user.id)
                        .order_by(Attempt.deadline.desc())
                        .limit(100)
                    )
                )
            available = hub.work_list(user)
            own = []
            for attempt in attempts:
                try:
                    own.append(hub.work_get(user, attempt.task_id, attempt.id))
                except HubError:
                    continue
            return {
                "role": "contributor",
                "name": user.name,
                "github_login": user.github_login,
                "available": available,
                "assignments": own,
            }
        with hub.db.read() as session:
            repositories = {r.id: r for r in session.scalars(select(Repository))}
            sources = {s.id: s for s in session.scalars(select(Source))}
            tasks, edges, _ = graph(session)
            task_list = [
                {
                    "id": t.id,
                    "repository": repositories[t.repository_id].full_name,
                    "source": sources[repositories[t.repository_id].authority_source_id].name,
                    "issue_number": t.issue_number,
                    "title": t.spec.get("title", "Awaiting approval"),
                    "state": t.state,
                    "revision": t.revision,
                    "priority": t.priority,
                    "reason": t.reason,
                    "dependencies": sorted(edges[t.id]),
                    "blockers": blockers(session, t.id),
                }
                for t in tasks.values()
            ]
            contributors = [
                {"id": u.id, "name": u.name, "github_login": u.github_login, "active": u.active}
                for u in session.scalars(select(Contributor))
            ]
            installations = [
                {
                    "id": i.id,
                    "account": i.account_login,
                    "source_id": i.source_id,
                    "suspended": i.suspended,
                }
                for i in session.scalars(select(GitHubInstallation))
            ]
        return {
            "role": "admin",
            "tasks": task_list,
            "sources": hub.sources(),
            "contributors": contributors,
            "installations": installations,
        }

    @app.get("/v1/admin/tasks/{task_id}", dependencies=[Depends(admin)])
    def task_detail(task_id: str):
        with hub.db.read() as session:
            task = session.get(Task, task_id)
            if not task:
                raise HubError(404, "Task not found")
            attempts = list(session.scalars(select(Attempt).where(Attempt.task_id == task_id)))
            history = list(
                session.scalars(
                    select(Approval).where(Approval.task_id == task_id).order_by(Approval.revision)
                )
            )
            events = list(
                session.scalars(
                    select(Audit)
                    .where(Audit.task_id == task_id)
                    .order_by(Audit.id.desc())
                    .limit(100)
                )
            )
            return {
                "id": task.id,
                "specification": task.spec,
                "policy": task.policy,
                "approval": task.approval,
                "blockers": blockers(session, task_id),
                "attempts": [hub.attempt_view(a) for a in attempts],
                "approval_history": [
                    {"revision": a.revision, "specification": a.specification, "record": a.record}
                    for a in history
                ],
                "events": [
                    {
                        "action": a.action,
                        "actor": a.actor,
                        "timestamp": a.timestamp,
                        "detail": a.detail,
                    }
                    for a in events
                ],
            }
