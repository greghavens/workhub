"""OAuth-protected Streamable HTTP MCP, using the MCP SDK's OAuth protocol handlers."""

import json
import secrets
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizeError,
    ProviderTokenVerifier,
    RefreshToken,
    RegistrationError,
)
from mcp.server.auth.provider import (
    TokenError as SDKTokenError,
)
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel
from sqlalchemy import select
from starlette.routing import get_route_path

from workhub.auth import Principal
from workhub.domain import HubError, token_hash
from workhub.models import (
    Contributor,
    RemoteAdminGrant,
    RemoteAuthorization,
    RemoteClient,
    RemoteGrant,
)


class TokenError(SDKTokenError):
    """SDK errors are frozen dataclasses; Python context managers must set traceback fields."""

    def __setattr__(self, name, value):
        if name in {
            "__traceback__",
            "__context__",
            "__cause__",
            "__suppress_context__",
            "__notes__",
        }:
            object.__setattr__(self, name, value)
        else:
            super().__setattr__(name, value)


WORK_SCOPES, PM_SCOPES = ["work"], ["work", "admin"]


class RemoteProvider:
    """One authorization server for two protected resources.

    Contributor harnesses use /mcp with scope "work". Product-manager harnesses use /mcp/pm
    with scope "work admin", consented by a linked owner. Every grant is bound to one resource.
    """

    def __init__(self, hub):
        self.hub = hub
        self.resource = hub.settings.public_url + "/mcp"
        self.pm_resource = hub.settings.public_url + "/mcp/pm"

    def consistent(self, subject, scopes, resource):
        owner = subject.startswith("owner:")
        if resource == self.pm_resource:
            return owner and set(scopes) == set(PM_SCOPES)
        return resource == self.resource and not owner and set(scopes) == set(WORK_SCOPES)

    async def get_client(self, client_id):
        with self.hub.db.read() as session:
            record = session.get(RemoteClient, client_id)
        return (
            OAuthClientInformationFull.model_validate_json(
                self.hub.cipher.decrypt(record.encrypted_metadata.encode())
            )
            if record
            else None
        )

    async def register_client(self, client_info):
        for uri in client_info.redirect_uris or []:
            parsed = urlsplit(str(uri))
            if (
                parsed.username
                or parsed.password
                or parsed.fragment
                or not parsed.hostname
                or (
                    parsed.scheme != "https"
                    and not (
                        parsed.scheme == "http"
                        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                    )
                )
            ):
                raise RegistrationError(
                    "invalid_redirect_uri", "Use HTTPS or an HTTP loopback callback"
                )
        with self.hub.db.write() as session:
            if session.get(RemoteClient, client_info.client_id):
                raise RegistrationError("invalid_client_metadata", "Client already registered")
            session.add(
                RemoteClient(
                    id=client_info.client_id,
                    encrypted_metadata=self.hub.encrypt(client_info.model_dump_json()),
                )
            )

    async def authorize(self, client, params):
        requested = params.resource.removesuffix("/") if params.resource else None
        resource = requested or (
            self.pm_resource if "admin" in (params.scopes or []) else self.resource
        )
        if resource == self.resource:
            scopes = params.scopes or WORK_SCOPES
            if set(scopes) != set(WORK_SCOPES):
                raise AuthorizeError(
                    "invalid_scope", f"Product-manager access uses {self.pm_resource}"
                )
        elif resource == self.pm_resource:
            scopes = params.scopes or PM_SCOPES
            if set(scopes) != set(PM_SCOPES):
                raise AuthorizeError(
                    "invalid_scope", "The product-manager endpoint requires scope work admin"
                )
        else:
            raise AuthorizeError("invalid_request", "Unknown resource")
        identifier = secrets.token_urlsafe(24)
        with self.hub.db.write() as session:
            session.add(
                RemoteAuthorization(
                    id=identifier,
                    client_id=client.client_id,
                    params={
                        **params.model_dump(mode="json"),
                        "resource": resource,
                        "scopes": scopes,
                    },
                    state="pending",
                    expires_at=self.hub.now() + 600,
                )
            )
        return self.hub.settings.public_url + f"/mcp/consent?request_id={identifier}"

    async def load_authorization_code(self, client, authorization_code):
        with self.hub.db.read() as session:
            request = session.scalar(
                select(RemoteAuthorization).where(
                    RemoteAuthorization.code_hash == token_hash(authorization_code),
                    RemoteAuthorization.client_id == client.client_id,
                    RemoteAuthorization.state == "approved",
                )
            )
            if not request or request.expires_at <= self.hub.now():
                return None
        return AuthorizationCode(
            code=authorization_code,
            client_id=client.client_id,
            expires_at=request.expires_at,
            subject=("owner:" + str(request.params["owner_github_id"]))
            if "owner_github_id" in request.params
            else request.contributor_id,
            **{
                key: request.params[key]
                for key in [
                    "scopes",
                    "code_challenge",
                    "redirect_uri",
                    "redirect_uri_provided_explicitly",
                    "resource",
                ]
            },
        )

    def find_grant(self, session, field, value):
        for model in (RemoteGrant, RemoteAdminGrant):
            grant = session.scalar(select(model).where(getattr(model, field) == token_hash(value)))
            if grant:
                return grant
        return None

    def subject(self, grant):
        return (
            "owner:" + str(grant.github_id)
            if isinstance(grant, RemoteAdminGrant)
            else grant.contributor_id
        )

    def valid_identity(self, session, subject):
        if subject.startswith("owner:"):
            return int(subject.split(":")[1]) in self.hub.integrations.config("admins").get(
                "ids", []
            )
        user = session.get(Contributor, subject)
        return bool(user and user.active)

    def issue(self, session, client_id, user_id, scopes, resource, grant=None):
        if not user_id or not self.valid_identity(session, user_id):
            raise TokenError(
                "invalid_grant", "Identity is unavailable or owner authorization was removed"
            )
        if not self.consistent(user_id, scopes, resource):
            raise TokenError(
                "invalid_scope",
                "Admin scope requires owner consent at the product-manager endpoint",
            )
        access, refresh = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
        if not grant:
            model = RemoteAdminGrant if user_id.startswith("owner:") else RemoteGrant
            identity = (
                {"github_id": int(user_id.split(":")[1])}
                if model is RemoteAdminGrant
                else {"contributor_id": user_id}
            )
            grant = model(
                id=secrets.token_hex(16),
                client_id=client_id,
                scopes=scopes,
                resource=resource,
                **identity,
            )
            session.add(grant)
        grant.access_hash, grant.refresh_hash = token_hash(access), token_hash(refresh)
        grant.scopes = scopes
        grant.access_expires_at = self.hub.now() + 3600
        grant.refresh_expires_at = self.hub.now() + 30 * 86400
        return OAuthToken(
            access_token=access, refresh_token=refresh, expires_in=3600, scope=" ".join(scopes)
        )

    async def exchange_authorization_code(self, client, authorization_code):
        with self.hub.db.write() as session:
            request = session.scalar(
                select(RemoteAuthorization).where(
                    RemoteAuthorization.code_hash == token_hash(authorization_code.code)
                )
            )
            if (
                not request
                or request.state != "approved"
                or request.expires_at <= self.hub.now()
                or request.client_id != client.client_id
            ):
                raise TokenError("invalid_grant", "Code expired or already used")
            request.state = "consumed"
            return self.issue(
                session,
                client.client_id,
                authorization_code.subject,
                request.params["scopes"],
                request.params["resource"],
            )

    async def load_refresh_token(self, client, refresh_token):
        with self.hub.db.read() as session:
            grant = self.find_grant(session, "refresh_hash", refresh_token)
            if (
                not grant
                or grant.revoked
                or grant.client_id != client.client_id
                or grant.refresh_expires_at <= self.hub.now()
                or not self.consistent(self.subject(grant), grant.scopes, grant.resource)
            ):
                return None
            return RefreshToken(
                token=refresh_token,
                client_id=grant.client_id,
                scopes=grant.scopes,
                expires_at=grant.refresh_expires_at,
                resource=grant.resource,
                subject=self.subject(grant),
            )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        with self.hub.db.write() as session:
            grant = self.find_grant(session, "refresh_hash", refresh_token.token)
            if (
                not grant
                or grant.revoked
                or grant.client_id != client.client_id
                or grant.refresh_expires_at <= self.hub.now()
                or not set(scopes) <= set(grant.scopes)
            ):
                raise TokenError("invalid_grant", "Refresh token expired or already rotated")
            return self.issue(
                session, grant.client_id, self.subject(grant), scopes, grant.resource, grant
            )

    async def load_access_token(self, token):
        with self.hub.db.read() as session:
            grant = self.find_grant(session, "access_hash", token)
            if not grant or grant.revoked or grant.access_expires_at <= self.hub.now():
                return None
            if not self.valid_identity(session, self.subject(grant)) or not self.consistent(
                self.subject(grant), grant.scopes, grant.resource
            ):
                # Also rejects owner grants issued for /mcp before the product-manager endpoint.
                return None
            return AccessToken(
                token=token,
                client_id=grant.client_id,
                scopes=grant.scopes,
                expires_at=grant.access_expires_at,
                resource=grant.resource,
                subject=self.subject(grant),
            )

    async def revoke_token(self, token):
        with self.hub.db.write() as session:
            grant = self.find_grant(session, "access_hash", token.token) or self.find_grant(
                session, "refresh_hash", token.token
            )
            if grant:
                grant.revoked = True


class WorkClient:
    """Dispatch MCP through the same validated API handlers, without an HTTP hop or reusable credentials."""

    def __init__(self, hub, app, resource):
        self.hub, self.app, self.resource = hub, app, resource
        self.product_manager = resource.endswith("/mcp/pm")

    async def call(self, method, path, **kwargs):
        token = get_access_token()
        if not token or not token.subject:
            raise HubError(401, "MCP authentication required")
        owner = token.subject.startswith("owner:")
        if (token.resource or "").removesuffix(
            "/"
        ) != self.resource or owner != self.product_manager:
            # The bearer backend already enforces the audience; keep the bridge independently safe.
            raise HubError(403, "This credential was issued for a different MCP endpoint")
        with self.hub.db.read() as session:
            if owner:
                github_id = int(token.subject.split(":")[1])
                if "admin" not in token.scopes or github_id not in self.hub.integrations.config(
                    "admins"
                ).get("ids", []):
                    raise HubError(403, "Owner authorization is unavailable")
                user = session.scalar(
                    select(Contributor).where(
                        Contributor.github_id == github_id, Contributor.active.is_(True)
                    )
                )
                current = Principal("admin", user.id if user else None, github_id)
            else:
                user = session.get(Contributor, token.subject)
                if not user or not user.active:
                    raise HubError(401, "Contributor is unavailable")
                current = Principal("contributor", user.id, user.github_id)
        if not (path.startswith("/v1/") or path == "/auth/status") or kwargs.get("headers"):
            raise HubError(403, "Use the MCP client's native OAuth flow for sign-in")

        async def dispatch(scope, receive, send):
            scope["workhub.principal"] = current
            await self.app(scope, receive, send)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dispatch), base_url=self.hub.settings.public_url
        ) as client:
            response = await client.request(method, path, **kwargs)
        if response.is_error:
            raise HubError(
                response.status_code, str(response.json().get("detail", "Hub request failed"))
            )
        return response.json()


class ConsentInput(BaseModel):
    allow: bool


def mount_remote_mcp(app, hub, principal):
    from workhub.mcp_server import create_server

    provider = RemoteProvider(hub)
    origin = hub.settings.public_url

    def endpoint(surface, resource, scopes, **options):
        return create_server(
            WorkClient(hub, app, resource),
            auto_heartbeat=False,
            surface=surface,
            stateless_http=True,
            json_response=True,
            streamable_http_path=urlsplit(resource).path,
            auth=AuthSettings(
                issuer_url=origin,
                resource_server_url=resource,
                validate_token_resource=True,
                required_scopes=scopes,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True, valid_scopes=PM_SCOPES, default_scopes=WORK_SCOPES
                ),
                revocation_options=RevocationOptions(enabled=True),
            ),
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[urlsplit(origin).netloc],
                allowed_origins=[origin],
            ),
            **options,
        )[0]

    # The contributor server also hosts the authorization server; the PM server only verifies.
    server = endpoint("contributor", provider.resource, WORK_SCOPES, auth_server_provider=provider)
    pm_server = endpoint(
        "pm", provider.pm_resource, PM_SCOPES, token_verifier=ProviderTokenVerifier(provider)
    )
    app.state.mcp_server, app.state.pm_mcp_server = server, pm_server
    app.state.remote_provider = provider

    @app.post("/revoke")
    async def revoke(request: Request):
        # SDK 1.x's revocation form incorrectly requires client_secret for public clients.
        # Retain its client authentication and implement RFC 7009's optional secret here.
        try:
            client = await ClientAuthenticator(provider).authenticate_request(request)
        except AuthenticationError as exc:
            return JSONResponse(
                {"error": "invalid_client", "error_description": exc.message}, status_code=401
            )
        form = await request.form()
        value = form.get("token")
        if not isinstance(value, str) or not value:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        with hub.db.write() as session:
            grant = provider.find_grant(session, "access_hash", value) or provider.find_grant(
                session, "refresh_hash", value
            )
            if grant and grant.client_id != client.client_id:
                grant = None
            if grant:
                grant.revoked = True
        return Response(
            status_code=200, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )

    @app.get("/mcp/consent")
    def consent_browser(request_id: str):
        with hub.db.read() as session:
            request = session.get(RemoteAuthorization, request_id)
            if not request or request.state != "pending" or request.expires_at <= hub.now():
                raise HubError(410, "MCP authorization expired")
        response = RedirectResponse("/?mcp_request=" + request_id, status_code=303)
        response.set_cookie(
            "workhub_mcp_request",
            request_id,
            max_age=600,
            httponly=True,
            secure=origin.startswith("https"),
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/v1/mcp/consent/{request_id}")
    def consent_detail(request_id: str, current=Depends(principal)):
        with hub.db.read() as session:
            request = session.get(RemoteAuthorization, request_id)
            if not request or request.state != "pending" or request.expires_at <= hub.now():
                raise HubError(410, "MCP authorization expired")
            client = session.get(RemoteClient, request.client_id)
        info = json.loads(hub.cipher.decrypt(client.encrypted_metadata.encode()))
        return {
            "client_name": info.get("client_name") or request.client_id,
            "redirect_origin": urlsplit(request.params["redirect_uri"]).netloc,
            "scopes": request.params["scopes"],
            "github_login": ("owner #" + str(current.github_id))
            if current.role == "admin"
            else "your connected GitHub account",
            "requires_admin": "admin" in request.params["scopes"],
        }

    @app.post("/v1/mcp/consent/{request_id}")
    def consent(request_id: str, data: ConsentInput, current=Depends(principal)):
        if not current.github_id:
            raise HubError(409, "Link your GitHub identity before authorizing an MCP client")
        code = secrets.token_urlsafe(40)
        with hub.db.write() as session:
            request = session.get(RemoteAuthorization, request_id)
            if not request or request.state != "pending" or request.expires_at <= hub.now():
                raise HubError(410, "MCP authorization expired or already approved")
            if "admin" in request.params["scopes"]:
                if current.role != "admin" or current.github_id not in hub.integrations.config(
                    "admins"
                ).get("ids", []):
                    raise HubError(
                        403, "Only a linked owner may delegate product-manager admin scope"
                    )
                request.params = {**request.params, "owner_github_id": current.github_id}
            else:
                user = (
                    session.get(Contributor, current.contributor_id)
                    if current.contributor_id
                    else None
                )
                if not user or not user.active or not user.github_id:
                    raise HubError(403, "Contributor identity is required for work-only scope")
                request.contributor_id = user.id
            request.state = "approved" if data.allow else "denied"
            request.code_hash = token_hash(code) if data.allow else None
            request.expires_at = hub.now() + 120
            uri = urlsplit(request.params["redirect_uri"])
            query = dict(parse_qsl(uri.query))
            query.update({"code": code} if data.allow else {"error": "access_denied"})
            if request.params.get("state"):
                query["state"] = request.params["state"]
            redirect = urlunsplit((uri.scheme, uri.netloc, uri.path, urlencode(query), ""))
            hub.audit(
                session,
                "owner:" + str(current.github_id)
                if current.role == "admin"
                else current.contributor_id,
                "mcp.authorized" if data.allow else "mcp.denied",
                client_id=request.client_id,
            )
        response = JSONResponse({"redirect_url": redirect})
        # The decision consumes the request; later GitHub sign-ins must not return to it.
        response.delete_cookie("workhub_mcp_request", path="/")
        return response

    @asynccontextmanager
    async def lifespan(_app):
        async with server.session_manager.run(), pm_server.session_manager.run():
            yield

    contributor_app, pm_app = server.streamable_http_app(), pm_server.streamable_http_app()
    pm_paths = {
        urlsplit(provider.pm_resource).path,
        urlsplit(str(build_resource_metadata_url(provider.pm_resource))).path,
    }

    async def endpoints(scope, receive, send):
        target = pm_app if get_route_path(scope) in pm_paths else contributor_app
        await target(scope, receive, send)

    app.router.lifespan_context = lifespan
    app.mount("/", endpoints)
