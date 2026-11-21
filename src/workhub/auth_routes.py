import html
import json
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from workhub.auth import Auth, Principal
from workhub.domain import HubError, token_hash
from workhub.models import AuthFlow, Contributor
from workhub.schemas import AppStart, OAuthConfigInput, OAuthStart, SessionInput


def authentication(app, hub):
    auth = Auth(hub)
    app.state.auth = auth
    router = APIRouter()
    origin = hub.settings.public_url.rstrip("/")
    secure = origin.startswith("https://")

    def credential(request):
        header = request.headers.get("Authorization", "")
        return (
            header[7:] if header.startswith("Bearer ") else request.cookies.get("workhub_session")
        )

    def check_origin(request):
        if request.headers.get("Origin") and request.headers["Origin"].rstrip("/") != origin:
            raise HubError(403, "Cross-origin request rejected")

    def principal(request: Request):
        # Set only by the in-process MCP bridge, never from HTTP headers or request data.
        trusted = request.scope.get("workhub.principal")
        if isinstance(trusted, Principal):
            return trusted
        token = credential(request)
        if not token:
            raise HubError(401, "Sign in to Work Hub")
        result = auth.principal(token)
        if not request.headers.get("Authorization") and request.method not in {
            "GET",
            "HEAD",
            "OPTIONS",
        }:
            check_origin(request)
            if not result.csrf or not secrets.compare_digest(
                request.headers.get("X-CSRF-Token", ""), result.csrf
            ):
                raise HubError(403, "Missing or invalid CSRF token")
        return result

    def admin(current=Depends(principal)):
        if current.role != "admin":
            raise HubError(403, "Administrator access required")
        return current

    def contributor(request: Request, current=Depends(principal)):
        if not current.contributor_id:
            raise HubError(403, "Connect a contributor identity to request work")
        with hub.db.read() as session:
            user = session.get(Contributor, current.contributor_id)
            if not user or not user.active:
                raise HubError(401, "Contributor is unavailable")
            return user

    def browser_cookie(response, browser):
        response.set_cookie(
            "workhub_oauth",
            browser,
            max_age=600,
            httponly=True,
            secure=secure,
            samesite="lax",
            path="/auth",
        )

    def session_cookie(response, token):
        response.set_cookie(
            "workhub_session",
            token,
            max_age=hub.settings.session_seconds,
            httponly=True,
            secure=secure,
            samesite="lax",
            path="/",
        )

    @router.get("/auth/status")
    def status(request: Request):
        config = hub.integrations.config("oauth")
        app_config = hub.integrations.config("app")
        result = {
            "authenticated": False,
            "oauth_ready": bool(config.get("client_id") and config.get("client_secret")),
            "app_ready": bool(app_config.get("client_id") and app_config.get("client_secret")),
            "public_url": origin,
        }
        token = credential(request)
        if token or request.scope.get("workhub.principal"):
            try:
                current = principal(request)
                result.update(
                    authenticated=True,
                    role=current.role,
                    csrf=current.csrf,
                    contributor_id=current.contributor_id,
                    github_id=current.github_id,
                )
            except HubError:
                pass
        return result

    @router.post("/auth/session")
    def bootstrap(data: SessionInput, request: Request):
        check_origin(request)
        current = auth.principal(data.token.get_secret_value())
        token = auth.session(current.role, current.contributor_id, current.github_id)
        response = JSONResponse({"authenticated": True, "role": current.role})
        session_cookie(response, token)
        return response

    @router.post("/auth/logout")
    def logout(request: Request, _=Depends(principal)):
        auth.logout(credential(request))
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("workhub_session", path="/")
        return response

    def start(data, request, cli):
        check_origin(request)
        current = principal(request) if credential(request) else None
        if data.kind == "source" and not data.name:
            raise HubError(422, "A source name is required")
        result = auth.begin(
            data.kind,
            data.provider,
            principal=current,
            invitation=data.invitation.get_secret_value() if data.invitation else None,
            data={"name": data.name, "approvers": data.approvers, "exclude": data.exclude},
            cli=cli,
        )
        browser = result.pop("browser", None)
        response = JSONResponse(result)
        if browser:
            browser_cookie(response, browser)
        return response

    @router.post("/auth/start")
    def browser_start(data: OAuthStart, request: Request):
        return start(data, request, False)

    @router.post("/auth/cli/start")
    def cli_start(data: OAuthStart, request: Request):
        return start(data, request, True)

    @router.get("/auth/cli/{flow_id}")
    def cli_authorize(flow_id: str):
        result = auth.authorize(flow_id)
        response = RedirectResponse(result["authorization_url"], status_code=303)
        browser_cookie(response, result["browser"])
        return response

    @router.get("/auth/cli/{flow_id}/result")
    def cli_poll(flow_id: str, request: Request):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return auth.poll(flow_id, token)

    @router.get("/auth/github/callback")
    def callback(request: Request, state: str = "", code: str = "", error: str | None = None):
        result = auth.complete(state, request.cookies.get("workhub_oauth"), code, error)
        if result["cli"]:
            response = HTMLResponse(
                "<!doctype html><html lang=en><title>Signed in · Work Hub</title>"
                "<body><h1>GitHub connected</h1><p>Return to your terminal or coding agent. You can close this tab.</p></body></html>"
            )
        else:
            mcp_request = request.cookies.get("workhub_mcp_request")
            response = RedirectResponse(
                "/?mcp_request=" + quote(mcp_request, safe="") if mcp_request else "/",
                status_code=303,
            )
            if result["token"]:
                session_cookie(response, result["token"])
        response.delete_cookie("workhub_oauth", path="/auth")
        return response

    @router.put("/v1/admin/integrations/oauth", dependencies=[Depends(admin)])
    def configure_oauth(data: OAuthConfigInput):
        hub.integrations.save_config(
            "oauth",
            {"client_id": data.client_id, "client_secret": data.client_secret.get_secret_value()},
        )
        return {"configured": True, "callback_url": auth.callback_url}

    @router.get("/v1/admin/integrations", dependencies=[Depends(admin)])
    def integration_status():
        oauth, app_config = hub.integrations.config("oauth"), hub.integrations.config("app")
        return {
            "oauth": {
                "configured": bool(oauth.get("client_id") and oauth.get("client_secret")),
                "client_id": oauth.get("client_id"),
                "callback_url": auth.callback_url,
            },
            "app": {
                "configured": bool(app_config.get("app_id")),
                "slug": app_config.get("slug"),
                "app_id": app_config.get("app_id"),
                "webhook_url": origin + "/webhooks/github",
            },
            "admin_github_ids": hub.integrations.config("admins").get("ids", []),
        }

    @router.post("/v1/admin/integrations/app/register", dependencies=[Depends(admin)])
    def register_app(data: AppStart):
        flow = auth.special_flow("manifest", data.model_dump())
        response = JSONResponse(
            {"url": origin + f"/auth/github/app/manifest/{flow['id']}?state={flow['state']}"}
        )
        browser_cookie(response, flow["browser"])
        return response

    @router.get("/auth/github/app/manifest/{flow_id}")
    def manifest_page(flow_id: str, state: str, request: Request):
        with hub.db.read() as session:
            flow = session.get(AuthFlow, flow_id)
        if (
            not flow
            or flow.kind != "manifest"
            or flow.status != "waiting"
            or flow.expires_at <= hub.now()
            or flow.state_hash != token_hash(state)
            or flow.browser_hash != token_hash(request.cookies.get("workhub_oauth", ""))
        ):
            raise HubError(400, "Invalid GitHub App registration session")
        organization = flow.data.get("organization")
        action = (
            f"https://github.com/organizations/{quote(organization, safe='')}/settings/apps/new"
            if organization
            else "https://github.com/settings/apps/new"
        )
        manifest = html.escape(json.dumps(auth.manifest(flow.data["name"])), quote=True)
        return HTMLResponse(
            f'<!doctype html><html lang="en"><title>Register Work Hub</title><body>'
            f"<h1>Register your GitHub App</h1><p>GitHub will ask you to confirm the app permissions.</p>"
            f'<form method="post" action="{action}?state={html.escape(state)}">'
            f'<input type="hidden" name="manifest" value="{manifest}">'
            '<button type="submit">Continue to GitHub</button></form></body></html>'
        )

    @router.get("/auth/github/app/manifest/callback")
    def manifest_callback(request: Request, state: str = "", code: str = ""):
        auth.complete_manifest(state, request.cookies.get("workhub_oauth"), code)
        response = RedirectResponse("/?tab=settings", status_code=303)
        response.delete_cookie("workhub_oauth", path="/auth")
        return response

    @router.post("/v1/admin/integrations/app/install", dependencies=[Depends(admin)])
    def install_app(data: AppStart):
        config = hub.integrations.config("app")
        if not config.get("slug"):
            raise HubError(409, "Register a GitHub App first")
        flow = auth.special_flow(
            "installation",
            {**data.model_dump(), "name": None if data.name == "Work Hub" else data.name},
        )
        response = JSONResponse(
            {
                "url": f"https://github.com/apps/{quote(config['slug'], safe='')}/installations/new?state={flow['state']}"
            }
        )
        browser_cookie(response, flow["browser"])
        return response

    @router.get("/auth/github/app/installed")
    def installed(request: Request, installation_id: int, state: str = ""):
        auth.complete_installation(state, request.cookies.get("workhub_oauth"), installation_id)
        response = RedirectResponse("/?tab=sources", status_code=303)
        response.delete_cookie("workhub_oauth", path="/auth")
        return response

    # Keep literal callback routes before the dynamic manifest page.
    router.routes.sort(key=lambda route: "{flow_id}" in route.path)
    app.include_router(router)
    return principal, admin, contributor
