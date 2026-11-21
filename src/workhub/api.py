from importlib.metadata import version

from fastapi import BackgroundTasks, Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from workhub.auth_routes import authentication
from workhub.config import Settings
from workhub.db import Database
from workhub.domain import HubError
from workhub.github import GitHub, GitHubError
from workhub.models import Audit
from workhub.schemas import (
    ApproveInput,
    ClaimInput,
    ConnectInput,
    ContributorInput,
    DependenciesInput,
    LeaseInput,
    NoteInput,
    RetryInput,
    SubmitInput,
)
from workhub.service import Hub

VERSION = version("workhub")


def create_app(
    settings=None, github_factory=GitHub, clock=None, identity_provider=None, database=None
):
    settings = settings or Settings.from_env()
    db = database or Database(settings.database_url)
    hub = Hub(db, settings, github_factory, **({"clock": clock} if clock else {}))
    if identity_provider:
        hub.integrations.provider = identity_provider
    app = FastAPI(title="Work Hub", version=VERSION, description="Approved GitHub work contracts")
    app.state.hub = hub

    @app.exception_handler(HubError)
    async def hub_error(_request: Request, exc: HubError):
        return JSONResponse(status_code=exc.status, content={"detail": exc.message})

    @app.exception_handler(GitHubError)
    async def github_error(_request: Request, exc: GitHubError):
        return JSONResponse(
            status_code=503, content={"detail": str(exc), "upstream_status": exc.status}
        )

    principal, admin, contributor = authentication(app, hub)
    from workhub.webhooks import Webhooks

    hub.webhooks = Webhooks(hub)

    @app.get("/health")
    def health():
        return {"status": "ok", "version": VERSION}

    @app.get("/v1/me")
    def me(user=Depends(contributor)):
        return {"id": user.id, "name": user.name, "github_login": user.github_login}

    @app.post("/v1/me/github")
    def connect(data: ConnectInput, user=Depends(contributor)):
        return hub.connect(user, data.github_token.get_secret_value())

    @app.post("/v1/admin/contributors", dependencies=[Depends(admin)])
    def create_contributor(data: ContributorInput):
        return hub.create_contributor(data.name)

    @app.delete("/v1/admin/contributors/{user_id}", dependencies=[Depends(admin)])
    def revoke_contributor(user_id: str):
        return hub.revoke_contributor(user_id)

    @app.get("/v1/admin/sources", dependencies=[Depends(admin)])
    def sources():
        return hub.sources()

    @app.post("/v1/admin/sync", dependencies=[Depends(admin)])
    def sync(source: str | None = None):
        hub.webhooks.drain()
        return hub.sync(source)

    @app.post("/webhooks/github", status_code=202)
    async def webhook(request: Request, background: BackgroundTasks):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                raise HubError(413, "Webhook payload too large")
        result = hub.webhooks.accept(
            request.headers.get("X-GitHub-Delivery"),
            request.headers.get("X-GitHub-Event"),
            request.headers.get("X-Hub-Signature-256"),
            bytes(body),
        )
        background.add_task(hub.webhooks.drain)
        return result

    @app.get("/v1/admin/webhooks", dependencies=[Depends(admin)])
    def deliveries():
        return hub.webhooks.list()

    @app.put("/v1/admin/tasks/{task_id}/dependencies", dependencies=[Depends(admin)])
    def dependencies(task_id: str, data: DependenciesInput):
        from workhub.scheduling import set_dependencies

        return set_dependencies(hub, task_id, data.dependencies)

    @app.post("/v1/admin/approve", dependencies=[Depends(admin)])
    def approve(data: ApproveInput):
        return hub.approve(data)

    @app.get("/v1/admin/tasks", dependencies=[Depends(admin)])
    def tasks():
        return hub.admin_tasks()

    @app.post("/v1/admin/tasks/{task_id}/retry", dependencies=[Depends(admin)])
    def retry(task_id: str, data: RetryInput):
        return hub.retry(task_id, data.reason)

    @app.get("/v1/admin/audit", dependencies=[Depends(admin)])
    def audit(after: int = 0):
        with db.read() as session:
            return [
                {
                    "id": a.id,
                    "timestamp": a.timestamp,
                    "actor": a.actor,
                    "action": a.action,
                    "task_id": a.task_id,
                    "detail": a.detail,
                }
                for a in session.scalars(
                    select(Audit).where(Audit.id > after).order_by(Audit.id).limit(200)
                )
            ]

    @app.get("/v1/work")
    def work_list(
        source: str | None = None, repository: str | None = None, user=Depends(contributor)
    ):
        return hub.work_list(user, source, repository)

    @app.post("/v1/work/claim")
    def claim(data: ClaimInput, user=Depends(contributor)):
        return hub.claim(user, data)

    @app.get("/v1/work/{task_id}")
    def get(task_id: str, attempt_id: str | None = None, user=Depends(contributor)):
        return hub.work_get(user, task_id, attempt_id)

    @app.post("/v1/work/{task_id}/heartbeat")
    def heartbeat(task_id: str, data: LeaseInput, user=Depends(contributor)):
        return hub.heartbeat(user, task_id, data)

    @app.post("/v1/work/{task_id}/release")
    def release(task_id: str, data: NoteInput, user=Depends(contributor)):
        return hub.stop(user, task_id, data, blocked=False)

    @app.post("/v1/work/{task_id}/block")
    def block(task_id: str, data: NoteInput, user=Depends(contributor)):
        return hub.stop(user, task_id, data, blocked=True)

    @app.post("/v1/work/{task_id}/resume")
    def resume(task_id: str, data: LeaseInput, user=Depends(contributor)):
        return hub.resume(user, task_id, data)

    @app.post("/v1/work/{task_id}/submit")
    def submit(task_id: str, data: SubmitInput, user=Depends(contributor)):
        return hub.submit(user, task_id, data)

    @app.post("/v1/work/{task_id}/provision")
    def provision(task_id: str, data: LeaseInput, user=Depends(contributor)):
        return hub.provision(user, task_id, data)

    from workhub.dashboard import dashboard

    dashboard(app, hub, principal, admin, contributor)
    from workhub.control import mount_control
    from workhub.remote_mcp import mount_remote_mcp

    mount_control(app, hub, principal, admin)
    mount_remote_mcp(app, hub, principal)

    return app
