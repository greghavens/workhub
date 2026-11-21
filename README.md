# Work Hub

A shared queue of approved GitHub work for your friends' coding agents. Install a read-only GitHub App on your repositories, approve issues with a GitHub label, and let contributors check in with Codex, Claude Code, another MCP client, or the CLI. Each claim receives an immutable contract and an exclusive, renewable lease. Work ends in a verified pull request for human review.

Includes a read-only GitHub App (registration, installation, renewable tokens), identity-only GitHub sign-in, signed durable webhooks, a dashboard, invitations, dependency scheduling, branch or contributor-created fork delivery, stdio and OAuth-protected remote MCP, unattended Codex/Claude runners, commit/push/PR delivery, recovery, audit history, and database upgrades.

## MCP is the primary interface

A separate **product-manager agent** manages the plan and GitHub issues using its own GitHub tools. The hub does not create or edit issues. The PM uses the hub's MCP tools to connect sources, inspect existing issues, approve work, manage prerequisites and contributor membership, and track delivery. Contributor agents use the same server to claim and execute approved contracts. CLI and dashboard are secondary interfaces.

| Agent | Authentication | Hub operations |
| --- | --- | --- |
| Product manager | Owner/admin identity; remote endpoint `/mcp/pm`, OAuth scopes `work admin` | Source connections, approvals, dependencies, invitations/revocation, task/PR inspection, audit |
| Contributor | Invited GitHub identity; remote endpoint `/mcp`, OAuth scope `work` | List, claim, check push repository, renew lease, report blocker, release/resume, submit PR |

Authorization is enforced on every operation. Naming an agent “PM” grants nothing. The remote contributor endpoint lists only contributor tools; the PM endpoint and stdio list all tools, and forbidden calls fail. `hub_identity` reports the caller's role. The PM currently receives delegated **admin** authority rather than a narrower bespoke PM role. Removing an owner's GitHub ID from the owner list disables that owner's remote grants and hub sessions; `contributor_revoke` disables contributor sessions/grants and active assignments. Hub membership is global; a contributor's own GitHub access further limits visible work. Request filters are not access-control lists.

For remote MCP, configure the PM harness with `https://your-hub.example.com/mcp/pm` and contributor harnesses with `https://your-hub.example.com/mcp`. Each endpoint advertises its own scopes, so spec-following MCP clients request `work admin` or `work` automatically. Tokens are bound to the endpoint that issued them. A linked GitHub owner must explicitly consent to `admin`; contributors cannot grant themselves that scope, and an owner's harness at `/mcp` receives only contributor authority. PM owner identities do not need contributor memberships. For stdio, configure `workhub mcp` with private `WORKHUB_URL` and `WORKHUB_TOKEN` environment values, or use the saved OAuth session. A bootstrap owner token can initialize integrations through MCP. Keep PM credentials separate from contributor harness configurations.

Without a saved stdio session, an agent can call `hub_login_start` with its invitation, present the authorization URL to its human, then call `hub_login_status`. The adapter saves the session privately without returning the access token to the agent. Remote MCP clients use their native OAuth login. No CLI login is required.

Typical PM tool sequence:

1. `hub_identity`, `integrations_get`; `github_app_register` once, then `github_app_install` to connect repositories through the read-only App. `oauth_configure` sets up identity-only contributor sign-in.
2. `github_connect_start(kind="admin_link")` links the owner identity. Present each returned URL to the human and monitor `github_connect_status`. Browser consent is required by GitHub, but the agent initiates and monitors the operation entirely through MCP.
3. `sources_sync`, `sources_list`, `repositories_list`, `issues_list`, `issue_get` inspect available repositories and existing backlog. Create/edit issues and priority/hold labels directly through GitHub tools.
4. Apply `agent:approved` on GitHub with the PM's own GitHub tools, then `task_approve` confirms it; `task_dependencies_set` and `contributor_invite` complete the queue. The hub never writes to GitHub.
5. `tasks_list`, `task_get`, `pr_inspect`, `audit_list` monitor contracts, PR reviews/checks, and blockers. `task_retry` requeues held work after reconciliation. `contributors_list`, `contributor_revoke`, and `webhooks_list` manage access and operations.

The MCP `manage_product` prompt describes this PM workflow; `contribute` describes the implementation-agent workflow. Source/App authorization handoffs are one-use, browser-bound, and monitorable only by the initiating identity. Upstream GitHub credentials are never returned to either agent.

## Start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run workhub init
uv run workhub serve
# Another terminal, same directory:
uv run workhub worker
```

Open **http://127.0.0.1:8000**. Expand **Owner setup or existing access token** and use the generated `WORKHUB_ADMIN_TOKEN` from your private `.env`. For remote access, set `WORKHUB_PUBLIC_URL=https://your-hub.example.com` before starting. The dashboard, callbacks, and MCP issuer share that origin.

## Connect GitHub

**Connections** shows a numbered checklist; do the steps in order:

1. **Register the read-only GitHub App.** One click starts GitHub's manifest registration with the hub's callbacks, webhook secret, and read-only permissions (metadata, contents, issues, pull requests, checks, statuses). The App cannot write to GitHub.
2. **Install it on your repositories.** Choose the repositories on GitHub; each installation becomes a source. Change the selection on GitHub at any time. Organization installations require named human approvers.
3. **Link your GitHub account as owner** (**Link my GitHub account**). You can then sign in with GitHub instead of the bootstrap token, and authorize a PM harness at `/mcp/pm`.
4. **Set up contributor sign-in.** Register a GitHub OAuth App at https://github.com/settings/applications/new with Homepage URL `https://your-hub.example.com` and Redirect URI `https://your-hub.example.com/auth/github/callback`, then enter its client ID and secret (**Configure sign-in**). Sign-in requests no scopes: it tells the hub who a contributor is and grants no repository access. Alternatively set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` in `.env`.
5. **Invite contributors** (below).

The hub holds no credential that can write to GitHub. App installation tokens are minted read-only and renew automatically. GitHub sign-in requests no scopes, and the hub uses the resulting token once to learn who signed in, then discards it; the same applies to a token presented to `workhub connect --token`. Upgrading to this version deletes GitHub tokens stored by earlier versions; sources connected with a pasted or OAuth token must be reinstalled through the App. Contributors see work only in installed repositories they can access on GitHub; the hub checks this with the App's read-only metadata permission. Dashboard configuration is encrypted in the database.

Signed deliveries at `/webhooks/github` update issues, approvals, PRs, reviews, checks, and pushes immediately. Deliveries are deduplicated, encrypted, and retried after failures or worker crashes. Suspension or deletion of an installation disables its access immediately. Periodic polling recovers updates when webhooks are unavailable. Existing App credentials can also be configured with the environment settings below.

## Approve and sequence work

Put requirements and acceptance criteria in a GitHub issue. A configured approver applies `agent:approved` on GitHub. Webhooks pick it up automatically; to confirm it explicitly through the dashboard, CLI, or `task_approve`:

```bash
uv run workhub admin approve alice owner/repository 42
```

Use `agent:blocked` to hold an issue and `agent:priority:high` to prioritize it. Approval binds title/body, policy, approver, and revision. Changes to the specification or policy, approval removal, or issue closure invalidate unfinished work. Comments do not silently change contracts.

Signed issue webhooks capture the approved snapshot. Approval is accepted only when the label was applied by a configured approver after the issue's latest edit; if the issue changed after labelling, review the current text and re-apply the label. The hub never adds or removes labels.

Optional prerequisites go in the issue before approval:

```html
<!-- workhub: {"depends_on":["owner/repository#12","#13"]} -->
```

Prerequisites must have merged PRs before dependent work can be claimed. Missing prerequisites block scheduling; cycles are rejected. Owners can also edit dependencies in the task dialog. Administrative dependency changes revoke active leases for reconciliation.

## Invite friends

Use **Contributors → Invite contributor**, or `uv run workhub admin invite bob`. Share the invitation privately. Your friend installs this checkout with `uv tool install .`, then signs in:

```bash
workhub login --url https://your-hub.example.com --invite
```

Subsequent `workhub login` calls need no invitation. `workhub connect` re-confirms which GitHub account you are. `--no-browser` prints a URL for headless machines. The owner-only CLI config is `~/.config/workhub/client.json`. Hub sessions expire after 24 hours by default; sign in again to renew.

Your friend authenticates local git and `gh` with **their own** GitHub account (`gh auth login`, `gh auth setup-git`). Source-owner credentials are never distributed to contributors.

## Unattended Codex and Claude runners

Install and authenticate git, `gh`, and the selected harness locally:

```bash
workhub run --harness codex --source alice --max-tasks 1
workhub run --harness claude --source alice --max-tasks 3 --watch
```

Omit `--source` for all connected inventories visible to your account. Optional filters: `--repository owner/repo`, `--capability python`, `--minutes 60`, `--fork-name my-contribution-fork`.

The runner claims work, creates its fork with your own `gh` when the contract asks for one, checks out the exact base commit, runs approved setup, launches the harness, validates changes and paths, commits, pushes, opens/reuses a PR, waits for required checks, and submits. It never merges. Lease loss terminates supervised process groups; failures hold the task with a handoff. Hub/GitHub environment tokens are stripped from setup, validation, and harness subprocesses. Git/gh delivery uses the contributor's local authentication.

Codex uses workspace-write sandboxing and noninteractive approval policy. Claude uses accept-edits permissions and an explicit tool allowlist. Permission-bypass flags are not enabled. Local harness restrictions can still block an operation; failures become task blockers.

Runs are saved in `~/.local/share/workhub/runs/<attempt-id>/`, including checkout, contract, logs, evidence, and results. Use `--directory` for another root, `--resume work_...` for revisions, and repeated `--harness-arg` for harness/model options. Persisted claim keys recover lost responses.

## Interactive agents and other harnesses

After `workhub login`, add stdio MCP:

```bash
codex mcp add workhub -- workhub mcp
claude mcp add --transport stdio workhub -- workhub mcp
```

Remote **Streamable HTTP MCP** is served at `https://your-hub.example.com/mcp` for contributors and `https://your-hub.example.com/mcp/pm` for the product manager. Configure the matching URL in an OAuth-capable MCP client. It supports OAuth discovery, dynamic registration, PKCE, explicit contributor consent, resource-bound tokens, rotating refresh, and revocation. Browser authorization signs into GitHub. Remote clients renew leases explicitly; the stdio adapter automatically renews tracked leases while running.

Tools: `work_list`, `work_claim`, `work_get`, `work_heartbeat`, `work_provision`, `work_block`, `work_release`, `work_resume`, `work_submit`. A `contribute` prompt describes the workflow. After reconnecting, `work_get` resumes tracking. Reuse the same idempotency key after a lost claim response.

Example instruction:

> Claim one approved task from source alice. Follow its contract and repository instructions. Check the push repository with work_provision and, if it asks, create the fork with your own gh. Implement and validate the change, commit, push, open a PR, and submit its URL, exact head SHA, and validation evidence. Keep the lease alive. Report blockers and stop if the lease is lost. Do not merge.

Any shell-capable harness can use the CLI:

```bash
workhub work list --source alice
workhub work claim --source alice --capability python --capability uv --out contract.json
workhub work prepare work_... ../contribution
workhub work keepalive work_...  # separate terminal while working
# After implementation, validation, and commit:
workhub work publish work_... --directory ../contribution \
  --title 'Fix keyboard navigation' \
  --body-file /path/to/pr-body.txt --evidence-file /path/to/tests.txt
```

The PR body must contain the contract ID. Keep body/evidence files outside the checkout. `prepare` provisions the fork. `publish` pushes committed work and opens/reuses a PR; pending CI may require a later `work submit` with `--pr`, `--sha`, and `--evidence-file`. The unattended runner handles this wait.

## Policy, review, and recovery

Copy [.workhub.example.yml](.workhub.example.yml) to `.workhub.yml` in a participating repository. Policy controls paths, dependency-file edits, setup/validation argument arrays, required tools/checks, delivery, and duration. Defaults allow ordinary source changes, forbid workflow/common dependency-manifest edits, and limit work to 60 minutes. Required CI checks must be configured explicitly.

The hub verifies PR author, repository, branch, exact SHA, base ancestry, complete diff, path/dependency restrictions, and required checks. Local test output is reported evidence; GitHub checks provide independent validation. Human review decides whether to merge.

Expired/released attempts are reconciled before reassignment; open PRs hold their tasks. `workhub work resume ID` renews the original contributor's assignment for revisions. `workhub work block ID 'reason'` records a blocker; `workhub work release ID 'handoff'` releases work. Closed unmerged PRs require `workhub admin retry ID 'reason'`. Changed specifications require fresh approval. Contributor revocation invalidates hub sessions, MCP grants, and active leases.

The dashboard displays approval history, assignments, PRs, dependencies, activity, and webhook retries. `workhub admin audit` exposes audit events. See [the HTTP protocol](docs/protocol.md).

## Deployment and upgrades

The same hub deploys to either target; choose one:

```bash
uv run workhub deploy cloudflare                         # https://workhub.<you>.workers.dev
uv run workhub deploy cloudflare --domain hub.example.com # custom domain on your Cloudflare zone
uv run workhub deploy local                              # Compose on this machine
```

Each prints the dashboard, both MCP endpoints, and the GitHub OAuth callback and webhook URLs to register.

### Cloudflare

`workhub deploy cloudflare` deploys a Python Worker. One Durable Object holds the hub's SQLite database and serves every request, so hub decisions stay serialized; a Cron Trigger runs the worker cycle every `--sync-seconds` (rounded to minutes). It needs Node.js (`npx`) and a Cloudflare login (`npx wrangler login`, or `CLOUDFLARE_API_TOKEN`). The command uses `pywrangler` and, if your uv is older than 0.13.4, a private newer uv.

The generated project, deployment state, and `secrets.json` (encryption key and owner token, owner-only permissions) live in `.workhub/cloudflare/`. **Keep that directory:** redeploys reuse the encryption key, and losing it makes stored GitHub credentials unreadable. The first workers.dev deployment deploys twice: once to learn the URL, then with it. `--dev` runs the same Worker locally in workerd with persistent local data; the Durable Object database then lives under `.workhub/cloudflare/.wrangler/`.

Durable Object SQL forbids `BEGIN`/`SAVEPOINT`, so the adapter (`workhub/durable.py`) gives hub write transactions rollback through an undo log maintained by triggers; write blocks perform no network I/O, which keeps them atomic within the object. Inside Workers, GitHub requests use a `fetch` transport that preserves the `User-Agent` header GitHub requires.

### Local (Compose)

`workhub deploy local` creates a private `.env` if missing (never overwrites one), then builds and starts Compose from the source checkout. Equivalent manual steps:

```bash
uv run workhub init  # once; never overwrites existing configuration
# Set WORKHUB_PUBLIC_URL in .env to the public HTTPS origin.
docker compose up --build -d
```

Compose runs PostgreSQL, the API/dashboard/MCP server, and the worker. Loopback port 8000 is published; put an HTTPS reverse proxy in front. Forward the original Host header and allow MCP streaming. Disable callback query-string logging in the proxy; built-in access logging is disabled. GitHub must reach callback and webhook URLs.

Schema upgrades run automatically, or explicitly with `workhub migrate`. The v1→v2 upgrade adds integrations; v3 adds independent owner MCP grants. Upgrades preserve accounts, credentials, work, and audit data. Unknown newer schemas are rejected. Back up the database and encryption key together before upgrades. Keep the encryption key stable.

| Setting | Purpose |
| --- | --- |
| `WORKHUB_PUBLIC_URL` | HTTPS origin; HTTP allowed only on loopback |
| `WORKHUB_DATABASE_URL` | SQLite locally or PostgreSQL in deployment |
| `WORKHUB_ENCRYPTION_KEY`, `WORKHUB_ADMIN_TOKEN` | Generated by init |
| `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` | Environment OAuth configuration |
| `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY` | Existing GitHub App; PEM supports escaped newlines |
| `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` | App user authorization |
| `GITHUB_WEBHOOK_SECRET` | Signature verification |
| `WORKHUB_ADMIN_GITHUB_IDS` | Comma-separated numeric owner identities |
| `WORKHUB_SESSION_SECONDS` | Hub session duration; default 86400 |
| `WORKHUB_SYNC_SECONDS`, `WORKHUB_LEASE_SECONDS` | Defaults 120 and 900 |
| `WORKHUB_MAX_WORK_MINUTES` | Maximum work duration; default 240 |

Dashboard-saved integration configuration overrides environment defaults. Client overrides: `WORKHUB_URL`, `WORKHUB_TOKEN`, `WORKHUB_CLIENT_CONFIG`. Explicit `--token` options preserve PAT-based connections for compatibility; OAuth is the default.

The service targets github.com. GitHub organization policies determine actual visibility and fork/push rights. Leases cannot revoke independently held GitHub credentials. Use branch protection/review rules and local isolation for unfamiliar repository code.

## Verification

```bash
uv sync --frozen --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run playwright install chromium
WORKHUB_BROWSER_TESTS=1 uv run pytest -q tests/test_dashboard.py
```

Set `WORKHUB_TEST_DATABASE_URL` to a **disposable** PostgreSQL database for the same suite there; tests recreate its tables. `WORKHUB_TEST_DATABASE_URL=durable` runs the suite through the Durable Object adapter against a stand-in with Durable Object SQL restrictions. `WORKHUB_WORKERD_TESTS=1 uv run pytest -q tests/test_workerd.py` builds the Cloudflare Worker, runs it in workerd, and checks rollback inside a real Durable Object (needs Node.js and network access). CI runs SQLite, PostgreSQL, and the Durable Object adapter with browser checks, plus the workerd job. Tests cover concurrent claims, OAuth/PKCE/replay/refresh/CSRF, real stdio/HTTP MCP, webhooks, dependencies, forks, migrations, real Git delivery, and supervised runs with deterministic Codex/Claude substitutes. GitHub boundaries are simulated; tests do not create live repositories or PRs.

