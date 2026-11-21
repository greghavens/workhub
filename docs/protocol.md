# Work Hub protocol v1

Work/admin API endpoints accept `Authorization: Bearer TOKEN`, or an HttpOnly browser session cookie. Cookie-authenticated mutations additionally require the session's `X-CSRF-Token` and a matching origin. Admin and contributor roles are separate. Health, static dashboard assets, OAuth discovery/entry/callback endpoints, and API documentation are public; webhooks require a valid GitHub signature. GitHub credentials are encrypted with Fernet at rest and never returned to workers. Assignments are identified by contributor ID, attempt ID, and monotonically increasing task generation. Contributors retain their bound GitHub identity across reconnects.

## HTTP operations

| Method and route | Credential | Behavior |
| --- | --- | --- |
| `GET /v1/me` | Contributor | Inspect connected identity |
| `POST /v1/me/github` | Contributor | Prove GitHub identity with a token; the token is discarded, not stored |
| `GET /v1/work?source=alice&repository=owner/repo` | Contributor | List eligible visible work |
| `POST /v1/work/claim` | Contributor | Atomically claim matching work |
| `GET /v1/work/{id}` | Contributor | Read own assignment, check active approval/access |
| `POST /v1/work/{id}/heartbeat` | Contributor | Renew active lease |
| `POST /v1/work/{id}/provision` | Contributor | Report the push repository: `ready`, or `fork_required` with a `gh repo fork` command to run |
| `POST /v1/work/{id}/block` | Contributor | Hold and record a blocker |
| `POST /v1/work/{id}/release` | Contributor | Release for reconciliation |
| `POST /v1/work/{id}/resume` | Contributor | Resume same contract and branch, increment generation |
| `POST /v1/work/{id}/submit` | Contributor | Verify PR and record submission |
| `POST /v1/admin/contributors` | Admin | Generate contributor token once |
| `DELETE /v1/admin/contributors/{id}` | Admin | Revoke hub token and lease |
| `GET /v1/admin/sources` | Admin | List sources (each is a read-only GitHub App installation) |
| `POST /v1/admin/sync?source=alice` | Admin | Discover and reconcile now |
| `POST /v1/admin/approve` | Admin | Confirm an `agent:approved` label applied on GitHub by a configured approver |
| `GET /v1/admin/tasks` | Admin | Inspect all task states |
| `GET /v1/admin/tasks/{id}` | Admin | Approval history, attempts, evidence, and events |
| `PUT /v1/admin/tasks/{id}/dependencies` | Admin | Replace administrative prerequisite task IDs |
| `POST /v1/admin/tasks/{id}/retry` | Admin | Requeue held work after checking for PRs |
| `GET /v1/admin/audit?after=123` | Admin | Read up to 200 ordered audit events |
| `GET /v1/dashboard` | Session | Owner overview or contributor's visible work |
| `GET /v1/admin/webhooks` | Admin | Delivery state, retries, sanitized failures |

Schemas are generated from the actual request models at `/openapi.json`.

## Claim example

```json
{
  "source": "alice",
  "repository": null,
  "capabilities": ["python", "uv"],
  "work_minutes": 60,
  "idempotency_key": "unique-stable-key-for-this-request"
}
```

`source`, `repository`, and `task_id` are optional filters. Without a source filter the hub considers the union of connected inventories. Repository access is checked with the source's read-only installation token (the contributor's live permission on the repository) before listing or returning contracts. The hub holds no repository credential for contributors. A public repository outside those inventories must first be accessible through a connected inventory; this is not a crawl of all public GitHub repositories.

An optional `fork_name` requests a contributor-owned custom fork. Fork targets must belong to the upstream repository network. The hub never creates forks. The provision operation returns `ready` once the assigned fork (or the upstream repository, for branch delivery) exists, or `fork_required` with the exact `gh repo fork` command for the contributor to run with their own GitHub CLI. The runner and checkout helper run that command once and re-check a bounded number of times.

A successful response contains `contract`, `assignment`, `submission`, and `note`. The contract is immutable per approval revision/attempt. The assignment contains mutable lease timestamps and a generation. No work returns `{"work": null, "reason": "No eligible approved work", "retry_after_seconds": 60}`. A repeated successful claim key returns the same attempt; changing the request under that key returns 409. No-work responses reserve nothing.

Lease operations require `attempt_id` and `generation`. Release/block additionally require `note`. Submit additionally requires an HTTPS github.com PR URL, 40-character `head_sha`, and textual `evidence`. Claims, heartbeats, and submissions recheck live approval. A claim does not override the contributor harness's own local permissions.

## States and invariants

```text
needs_approval -> ready -> leased -> submitted -> merged
                           |            |
                           |            +-> changes_requested -> leased
                           +-> blocked
                           +-> reconciling -> ready / changes_requested / closed
```

Approval changes can move unfinished work back to `needs_approval` and revoke active attempts. Expired/released attempts enter reconciliation; open PRs are never blindly requeued. A closed PR requires explicit retry. A known merged PR is tracked as merged even when its closing keyword closed the source issue. Merging is observed, not performed or endorsed by the hub.

One canonical task exists per stable GitHub repository ID and issue number. Overlapping accounts do not create duplicate tasks. The first source discovering a repository owns its approval policy. One task per repository and one attempt per contributor may be leased at a time; submitted PRs do not consume an active lease slot.

Database transactions serialize mutations using a database mutex row (`FOR UPDATE` on PostgreSQL, `BEGIN IMMEDIATE` on SQLite). Partial unique indexes independently enforce active-lease constraints. GitHub I/O happens outside these transactions. State/revision/generation comparisons reject races before committing decisions. There is no distributed transaction with GitHub: approval and head SHA are checked again near publication/submission, and periodic reconciliation observes later changes.

Approval history stores every specification and policy snapshot. The current task points to its latest revision. Attempts preserve exact contracts and use distinct branches. A stale attempt cannot renew or submit after expiration, reassignment, revocation, or resumption with a newer generation. Retry a failed submission after CI passes while the lease remains active, or resume the existing PR when held.

The scheduler is deterministic: priority label, then creation time and task ID, after source/repository/access/capability/dependency filtering. Approved issue bodies can include `<!-- workhub: {"depends_on":["owner/repo#12","#13"]} -->`; explicit administrative edges are additional prerequisites. Missing or unmerged prerequisites block work, cycles are rejected, and dependency edits revoke active assignments for reconciliation. Declared capabilities are a scheduling hint, not authentication. GitHub outages fail closed for live validation; worker retries recover connectivity.

## GitHub authorization and sessions

`POST /auth/start` accepts `kind` (`login`, `contributor`, `admin_link`; `source` is refused with 422 because sources come only from App installations), `provider` (`oauth`, `app`), and optional invitation/source settings. Source and owner-link operations require admin authentication. It returns GitHub's authorization URL (OAuth App sign-in requests no scopes) and sets a short-lived browser binding cookie. The callback exchanges a one-use state/code with PKCE, validates `/user`, and binds only an invited/existing contributor or explicitly linked owner. The initial invitation is consumed when first bound. Reconnection cannot replace an existing identity with a different GitHub account.

`POST /auth/cli/start` creates the same flow but returns a local browser URL and separate secret poll credential. Visit that URL to authorize; poll `GET /auth/cli/{id}/result` using the poll credential as bearer. The final hub session can be retrieved only once. Its token never appears in browser responses or redirect URLs. GitHub access/refresh credentials remain encrypted server-side; refresh is serialized per credential and rotates the stored pair.

`GET /auth/status` returns session role and CSRF token without provider secrets. `POST /auth/session` exchanges a bootstrap/legacy hub token for a browser session; `POST /auth/logout` revokes the session. Owner sessions bound to a GitHub ID stop working once that ID is removed from the owner list; bootstrap-token sessions are unaffected. Session lifetime defaults to 86400 seconds. `PUT /v1/admin/integrations/oauth` configures OAuth; `GET /v1/admin/integrations` returns only masked configuration metadata.

`POST /v1/admin/integrations/app/register` starts GitHub App manifest registration. The state/browser-bound callback converts the manifest code and encrypts the resulting credentials. `POST /v1/admin/integrations/app/install` starts installation; its callback validates the installation against the configured App and establishes a source. Installation credentials are the only GitHub credentials the hub keeps; sign-in tokens are used once to read `/user` and discarded. Installation tokens are automatically renewed and requested with read-only permissions only (metadata, contents, issues, pull requests, checks, statuses), matching the App manifest.

## Webhooks

`POST /webhooks/github` verifies `X-Hub-Signature-256` against the exact request bytes before accepting JSON. It requires `X-GitHub-Delivery` and `X-GitHub-Event`, limits bodies to 2 MB, and deduplicates delivery IDs with payload hashes. Reusing an ID with different data is rejected. Accepted payloads are encrypted in a durable queue. Processing leases recover after crashes; failures retry with bounded exponential backoff. The API starts processing after acknowledging; the separate worker drains pending deliveries and polls GitHub for recovery.

Label approval uses the signed snapshot only when its authorized sender, current issue, and current label event agree. Stale payloads cannot approve changed text. Installation suspension/removal blocks credentials immediately; authorization revocation disables the corresponding user credentials. PR/review/check events reconcile existing attempts.

## Remote MCP OAuth

Two stateless Streamable HTTP endpoints share one authorization server: `/mcp` for contributors (scope `work`) and `/mcp/pm` for the product manager (scope `work admin`). They accept only their own OAuth bearer tokens, not dashboard cookies or upstream GitHub tokens. Discovery uses `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp` (`scopes_supported: ["work"]`), and `/.well-known/oauth-protected-resource/mcp/pm` (`scopes_supported: ["work", "admin"]`); MCP clients select scopes from this metadata. `/authorize` accepts exactly `work` for the `/mcp` resource and exactly `work admin` for `/mcp/pm`; without an RFC 8707 `resource`, the requested scope selects the endpoint. `/register` supports dynamic clients with HTTPS or loopback redirect URIs. `/authorize` requires PKCE; contributors sign in and explicitly approve the client and `work` scope. `/token` exchanges one-use authorization codes or rotating refresh tokens. Tokens are bound to the client, identity, scope, and resource: contributor grants to `/mcp`, owner grants to `/mcp/pm`. A token is rejected at the other endpoint, and a refresh cannot narrow a PM grant into a contributor token. Owner grants issued for `/mcp` by earlier versions are rejected; re-authorize the PM harness at `/mcp/pm`. Access tokens expire after one hour; refresh tokens after 30 days. `/revoke` invalidates the grant. Contributor revocation is checked on every protected request.

The stdio adapter uses the locally configured/saved hub session and maintains heartbeat timers. It can also initiate and finish browser login through `hub_login_start`/`hub_login_status` without exposing session credentials to the model. Remote clients use native OAuth and call `work_heartbeat` themselves.

The stdio adapter and `/mcp/pm` expose work and PM/control operations (stdio additionally offers `hub_login_*`). `/mcp` exposes the `work_*` tools plus `hub_identity`, `hub_status`, and `github_connect_*`. Only a linked owner can consent to a `/mcp/pm` grant. Owner grants are independent of contributor membership and revalidate owner authority on access and refresh. `hub_identity` exposes the effective role. The `manage_product` and `contribute` prompts describe the two workflows. PM credentials must not be installed in contributor harnesses.

## Product-manager MCP operations

Issue authoring happens directly through the PM agent's GitHub tools. The hub exposes read-only issue/backlog inspection plus explicit approval; it does not create or edit issues.

| MCP tools | Shared HTTP routes |
| --- | --- |
| `hub_identity`, `hub_status` | `GET /v1/identity`, `GET /auth/status` |
| `sources_list`, `sources_sync`, `repositories_list` | `/v1/admin/sources`, `/v1/admin/sync`, `/v1/admin/repositories` |
| `issues_list`, `issue_get`, `pr_inspect` | Read-only `/v1/admin/issues`, `/v1/admin/issue`, `/v1/admin/pull-request` |
| `task_approve`, `tasks_list`, `task_get` | `/v1/admin/approve`, `/v1/admin/tasks`, `/v1/admin/tasks/{id}` |
| `task_dependencies_set`, `task_retry` | `/v1/admin/tasks/{id}/dependencies`, `/v1/admin/tasks/{id}/retry` |
| `contributors_list`, `contributor_invite`, `contributor_revoke` | `/v1/admin/contributors`, `/v1/admin/contributors/{id}` |
| `audit_list`, `webhooks_list` | `/v1/admin/audit`, `/v1/admin/webhooks` |
| `integrations_get`, `oauth_configure` | `/v1/admin/integrations`, `/v1/admin/integrations/oauth` |
| `github_connect_start`, `github_connect_status` | `POST /v1/connections/start`, `GET /v1/connections/{id}` |
| `github_app_register`, `github_app_install` | `/v1/admin/integrations/app/agent-register`, `/v1/admin/integrations/app/agent-install` |

Connection operations return a browser authorization URL and request ID. The initiating identity polls status (`waiting`, `processing`, `complete`, `failed` with a sanitized error, or `expired`) without receiving provider or session secrets. Agent-initiated connections mint no hub session: linking an owner or a contributor identity takes effect for the initiator's existing credentials. Completing or declining remote MCP consent clears the browser's pending-request cookie. App handoffs use one-use tickets to establish browser binding before GitHub registration/installation. Human browser consent remains necessary. Backend authorization applies equally to HTTP and MCP: remote calls dispatch to the same API handlers through an in-process ASGI bridge, with a server-created principal unavailable to HTTP header/body injection.

## Schema upgrades

The API and worker apply versioned additive schema upgrades before serving. `workhub migrate` applies the same upgrade independently. Version 2 adds OAuth, sessions, integrations, installations, webhook queue, dependencies, and contributor remote grants. Version 3 adds independent owner remote grants. Existing data is preserved. Startup refuses a newer unknown schema. Persist the database and encryption key together. On Cloudflare the same upgrade runs inside the Durable Object when it starts; the database is the object's SQLite storage, and write transactions roll back through a trigger-maintained undo log because Durable Object SQL forbids `BEGIN` and `SAVEPOINT`.

## Boundaries

PR verification checks author, target and push repository, branch, base ancestry, full changed-file count, both rename paths, common dependency files, and required GitHub check/status success at the submitted SHA. It rejects draft or closed PRs. It does not prove semantic correctness, independently rerun local tests, sandbox repository code, enforce path restrictions on git push, or merge.

Tokens are account credentials, not branch-scoped capabilities. Contributors retain responsibility for their local GitHub permissions. Keep mandatory reviews, CI, and branch protections on GitHub; use isolated workers for untrusted code. The hub is a small trusted collaboration service, not a hostile multi-tenant execution platform.
