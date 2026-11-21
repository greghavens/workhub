"use strict";
let auth = {}, state = {}, view = new URLSearchParams(location.search).get("tab") || "queue";
const $ = (id) => document.getElementById(id);
const node = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };
const human = (value) => value.replaceAll("_", " ");
const pill = (value) => node("span", human(value), `pill ${value}`);
const date = (value) => new Date(value * 1000).toLocaleString();
function toast(text, error = false) { $("toast").textContent = text; $("toast").className = `toast${error ? " error" : ""}`; clearTimeout(toast.timer); toast.timer = setTimeout(() => $("toast").classList.add("hidden"), 7000); }
async function api(path, options = {}) {
  const headers = {"Content-Type": "application/json", ...(auth.csrf ? {"X-CSRF-Token": auth.csrf} : {}), ...options.headers};
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data));
  return data;
}
const post = (path, data = {}) => api(path, {method: "POST", body: JSON.stringify(data)});
function button(label, action, style = "secondary") {
  const b = node("button", label, style); b.type = "button";
  b.addEventListener("click", async () => { b.disabled = true; try { await action(); } catch (error) { toast(error.message, true); } finally { b.disabled = false; } });
  return b;
}
function dialog(title, content) { $("dialog-title").textContent = title; $("dialog-body").replaceChildren(content); if (!$("dialog").open) $("dialog").showModal(); }
$("close-dialog").onclick = () => $("dialog").close();
function form(title, fields, submitLabel, submit) {
  const f = node("form"), inputs = {};
  for (const field of fields) {
    const id = `field-${field.name}`;
    const label = node("label", field.label); label.htmlFor = id;
    const input = node(field.options ? "select" : field.type === "textarea" ? "textarea" : "input");
    input.id = id; input.name = field.name; input.required = !!field.required;
    if (field.options) { for (const [value, text] of field.options) { const o = node("option", text); o.value = value; input.append(o); } }
    else if (field.type !== "textarea") input.type = field.type || "text";
    if (field.value !== undefined) input.value = field.value;
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.type === "password") input.autocomplete = "off";
    if (field.help) { const help = node("p", field.help, "subtext"); help.id = `${id}-help`; input.setAttribute("aria-describedby", help.id); f.append(label, input, help); }
    else f.append(label, input);
    inputs[field.name] = input;
  }
  const errorBox = node("p", "", "notice error hidden"), b = node("button", submitLabel, "primary"); b.type = "submit"; f.append(errorBox, b);
  f.addEventListener("submit", async (event) => { event.preventDefault(); b.disabled = true; errorBox.classList.add("hidden");
    try { await submit(Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, input.value])), f); }
    catch (error) { errorBox.textContent = error.message; errorBox.classList.remove("hidden"); }
    finally { b.disabled = false; }
  });
  dialog(title, f);
}
function panel(title, body, action) { const p = node("section", undefined, "panel"), heading = node("div", undefined, "panel-heading"); heading.append(node("h2", title)); if (action) heading.append(action); p.append(heading, body); return p; }
function table(headers, rows) { const wrap = node("div", undefined, "table-wrap"), t = node("table"), head = node("thead"), hr = node("tr"); headers.forEach(text => hr.append(node("th", text))); head.append(hr); t.append(head); const body = node("tbody"); for (const cells of rows) { const row = node("tr"); for (const cell of cells) { const td = node("td"); td.append(cell instanceof Node ? cell : document.createTextNode(String(cell))); row.append(td); } body.append(row); } t.append(body); wrap.append(t); return wrap; }
function taskName(task) { const n = node("div"); n.append(node("span", task.title, "task-name"), node("span", `${task.repository} · #${task.issue_number}`, "subtext")); return n; }
function providerFields() { const options = []; if (auth.oauth_ready) options.push(["oauth", "GitHub sign-in (OAuth App)"]); if (auth.app_ready) options.push(["app", "GitHub App"]); return options; }
async function oauth(data) { const result = await post("/auth/start", data); location.assign(result.authorization_url); }
async function refresh() {
  auth = await api("/auth/status");
  $("login").classList.toggle("hidden", auth.authenticated);
  $("workspace-content").classList.toggle("hidden", !auth.authenticated);
  $("logout").classList.toggle("hidden", !auth.authenticated);
  document.querySelectorAll(".admin-only").forEach(e => e.classList.toggle("hidden", auth.role !== "admin"));
  $("setup-notice").classList.toggle("hidden", auth.oauth_ready || auth.app_ready);
  $("login-form").querySelector("button").disabled = !auth.oauth_ready && !auth.app_ready;
  $("login-provider").options[0].disabled = !auth.oauth_ready; $("login-provider").options[1].disabled = !auth.app_ready;
  if (!auth.oauth_ready && auth.app_ready) $("login-provider").value = "app";
  if (!auth.authenticated) { $("identity").textContent = "Not signed in"; return; }
  state = await api("/v1/dashboard");
  $("identity").textContent = state.github_login || state.name || "Workspace owner";
  if (auth.role !== "admin") view = "queue";
  await render();
  const mcpRequest = new URLSearchParams(location.search).get("mcp_request");
  if (mcpRequest && (auth.contributor_id || auth.role === "admin") && !$("dialog").open) {
    const consent = await api(`/v1/mcp/consent/${encodeURIComponent(mcpRequest)}`);
    const body = node("div"); body.append(node("p", consent.requires_admin ? `${consent.client_name} requests product-manager access: manage GitHub connections, approve existing issues, set dependencies, and invite or revoke contributors using your owner authority.` : `${consent.client_name} wants to claim and submit approved work as ${consent.github_login}.`), node("p", `After authorization, you will return to ${consent.redirect_origin}.`, "subtext"));
    const actions = node("div", undefined, "actions");
    for (const allow of [false, true]) actions.append(button(allow ? "Authorize harness" : "Decline", async () => { const result = await post(`/v1/mcp/consent/${encodeURIComponent(mcpRequest)}`, {allow}); location.assign(result.redirect_url); }, allow ? "primary" : "secondary"));
    body.append(actions); dialog("Connect your coding harness", body);
  }
}
$("login-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await oauth({kind: "login", provider: $("login-provider").value, invitation: $("invitation").value || null}); } catch (error) { toast(error.message, true); } });
$("bootstrap-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await post("/auth/session", {token: $("bootstrap-token").value}); $("bootstrap-token").value = ""; await refresh(); } catch (error) { toast(error.message, true); } });
$("logout").onclick = async () => { try { await post("/auth/logout"); await refresh(); } catch (error) { toast(error.message, true); } };
document.querySelectorAll("[data-view]").forEach(b => b.addEventListener("click", () => { view = b.dataset.view; render().catch(e => toast(e.message, true)); }));
async function render() {
  const titles = {queue: ["Work queue", "Clear assignments for the people and agents moving your projects forward."], sources: ["Repositories & sources", "One connection brings approved work from across your GitHub account."], people: ["Contributors", "Invite your people. They bring their preferred coding agents."], activity: ["Activity", "A traceable record from approval to pull request."], settings: ["Connections", "Connect GitHub once. Keep accounts and automation in sync."]};
  if (!titles[view]) view = "queue";
  $("view-title").textContent = titles[view][0]; $("crumb-name").textContent = titles[view][0]; $("view-description").textContent = titles[view][1];
  document.querySelectorAll("[data-view]").forEach(b => b.classList.toggle("selected", b.dataset.view === view));
  $("content").replaceChildren(); $("page-actions").replaceChildren(button("Refresh", refresh));
  if (view === "queue") renderQueue();
  if (view === "sources") renderSources();
  if (view === "people") renderPeople();
  if (view === "settings") await renderSettings();
  if (view === "activity") await renderActivity();
}
function renderQueue() {
  if (auth.role !== "admin") return renderContributor();
  setupStatus().then(status => {
    if (status.next < 0 || view !== "queue") return;
    const banner = node("div", undefined, "notice setup-banner"), step = status.steps[status.next];
    banner.append(node("span", `Finish setting up your hub — step ${status.next + 1} of ${status.steps.length}: ${step.title}.`), button("Continue setup", () => go("settings"), "primary"));
    $("content").prepend(banner);
  }).catch(error => toast(error.message, true));
  $("page-actions").prepend(button("Sync GitHub", async () => { const r = await post("/v1/admin/sync"); toast(`Synced ${r.repositories} repositories${r.errors.length ? `; ${r.errors.length} need attention` : ""}`); await refresh(); }, "primary"));
  const tasks = state.tasks || [], stats = node("div", undefined, "stats");
  for (const [label, states, note] of [["Ready to claim", ["ready"], "Approved and available"], ["In progress", ["leased"], "Active agent assignments"], ["In review", ["submitted", "changes_requested"], "Pull requests with people"], ["Needs attention", ["needs_approval", "blocked", "reconciling", "closed"], "Approval or follow-up needed"]]) {
    const card = node("div", undefined, "stat"); card.append(node("span", label, "stat-label"), node("strong", tasks.filter(t => states.includes(t.state)).length, "stat-value"), node("span", note, "stat-note")); stats.append(card);
  }
  $("content").append(stats);
  const body = node("div"), toolbar = node("div", undefined, "toolbar"), search = node("input"), filter = node("select"), rows = node("div");
  search.placeholder = "Search work or repository…"; search.setAttribute("aria-label", "Search work");
  for (const value of ["all", ...new Set(tasks.map(t => t.state))]) { const o = node("option", value === "all" ? "All statuses" : human(value)); o.value = value; filter.append(o); } filter.setAttribute("aria-label", "Filter by status");
  toolbar.append(search, filter); body.append(toolbar, rows);
  function updateRows() { const matching = tasks.filter(t => (filter.value === "all" || filter.value === t.state) && `${t.title} ${t.repository} ${t.issue_number}`.toLowerCase().includes(search.value.toLowerCase()));
    rows.replaceChildren(matching.length ? table(["Work", "Status", "Dependencies", "Approval", ""], matching.map(t => [taskName(t), pill(t.state), t.blockers.length ? `${t.blockers.length} waiting` : "Clear", t.revision ? `Revision ${t.revision}` : "Not approved", button("View", () => showTask(t), "quiet")])) : node("p", tasks.length ? "No work matches these filters." : "Your queue is empty. Connect a source, then approve a GitHub issue to get started.", "empty")); }
  search.oninput = updateRows; filter.onchange = updateRows; updateRows(); $("content").append(panel("All work", body));
}
async function showTask(task) {
  const detail = await api(`/v1/admin/tasks/${task.id}`), body = node("div");
  body.append(node("p", `${task.repository} #${task.issue_number} · ${task.id}`, "subtext"), pill(task.state), node("pre", detail.specification.body || "No approved specification yet."));
  const actions = node("div", undefined, "actions");
  actions.append(button("Approve current issue", async () => { await post("/v1/admin/approve", {source: task.source, repository: task.repository, issue_number: task.issue_number}); $("dialog").close(); toast("Current issue approved"); await refresh(); }, "primary"));
  actions.append(button("Retry held work", () => form("Retry this task", [{name: "reason", label: "Reason for retry", type: "textarea", required: true}], "Requeue work", async d => { await post(`/v1/admin/tasks/${task.id}/retry`, d); $("dialog").close(); await refresh(); })));
  body.append(actions);
  const deps = node("section", undefined, "detail-section"), label = node("label", "Prerequisite work"), select = node("select"); select.multiple = true; select.id = "task-dependencies"; label.htmlFor = select.id;
  state.tasks.filter(t => t.id !== task.id).forEach(t => { const o = node("option", `${t.repository} #${t.issue_number} · ${t.title}`); o.value = t.id; o.selected = task.dependencies.includes(t.id); select.append(o); });
  deps.append(label, node("p", "Selected work must be merged before this task can be claimed. Dependencies in the approved issue also apply.", "subtext"), select,
    button("Save prerequisites", async () => { await api(`/v1/admin/tasks/${task.id}/dependencies`, {method: "PUT", body: JSON.stringify({dependencies: [...select.selectedOptions].map(o => o.value)})}); $("dialog").close(); await refresh(); }));
  body.append(deps);
  const attempts = node("section", undefined, "detail-section"); attempts.append(node("h3", "Assignments & pull requests"));
  if (!detail.attempts.length) attempts.append(node("p", "No agent has claimed this task yet.", "subtext"));
  for (const a of detail.attempts) { const entry = node("div", undefined, "audit-event"); entry.append(pill(a.assignment.state), node("p", `${a.assignment.attempt_id} · lease generation ${a.assignment.generation}`, "subtext")); if (a.submission) { const link = node("a", a.submission.pr_url); link.href = a.submission.pr_url; link.target = "_blank"; link.rel = "noopener"; entry.append(link, node("pre", a.submission.evidence)); } attempts.append(entry); }
  body.append(attempts); const history = node("details"); history.append(node("summary", `${detail.approval_history.length} approval revisions`), node("pre", JSON.stringify(detail.approval_history, null, 2))); body.append(history); dialog(task.title, body);
}
function split(value) { return value.split(",").map(s => s.trim()).filter(Boolean); }
function renderSources() {
  $("page-actions").prepend(button("Add repositories", () => { if (!auth.app_ready) return go("settings"); installApp(); }, "primary"));
  const body = state.sources.length ? table(["Source", "GitHub account", "Excluded", ""], state.sources.map(s => [s.name, s.github_login, s.exclude.join(", ") || "None", button("Sync", async () => { const result = await post(`/v1/admin/sync?source=${encodeURIComponent(s.name)}`); if (result.errors.length) throw new Error(result.errors.map(e => e.error).join("; ")); toast("Source synchronized"); await refresh(); })])) : node("p", "Install the read-only GitHub App on repositories to add them here.", "empty");
  $("content").append(panel("Account sources", body));
  if (state.installations.length) $("content").append(panel("GitHub App installations", table(["Account", "Installation", "State"], state.installations.map(i => [i.account, i.id, pill(i.suspended ? "blocked" : "ready")]))));
}
function renderPeople() {
  $("page-actions").prepend(button("Invite contributor", () => form("Invite a contributor", [{name: "name", label: "Contributor name", required: true, placeholder: "bob"}], "Create invitation", async d => { const invite = await post("/v1/admin/contributors", d); const body = node("div"); body.append(node("p", "Share this invitation privately. Your friend uses it on their first GitHub sign-in."), node("pre", invite.token), button("Copy invitation", async () => { await navigator.clipboard.writeText(invite.token); toast("Invitation copied"); })); dialog(`Invite ${invite.name}`, body); state = await api("/v1/dashboard"); renderPeopleBehindDialog(); }), "primary"));
  renderPeopleBehindDialog();
}
function renderPeopleBehindDialog() { $("content").replaceChildren(panel("Your contributors", state.contributors.length ? table(["Name", "GitHub", "Access", ""], state.contributors.map(u => [u.name, u.github_login || "Invitation pending", pill(u.active ? "ready" : "revoked"), u.active ? button("Revoke", () => form(`Revoke ${u.name}`, [{name: "confirm", label: `Type ${u.name} to revoke access`, required: true}], "Revoke access", async d => { if (d.confirm !== u.name) throw new Error("Name does not match"); await api(`/v1/admin/contributors/${u.id}`, {method: "DELETE"}); $("dialog").close(); await refresh(); }), "danger") : ""])) : node("p", "Invite a friend to start contributing with their coding agent.", "empty"))); }
async function renderActivity() {
  const [events, deliveries] = await Promise.all([api("/v1/admin/audit"), api("/v1/admin/webhooks")]);
  const body = node("div", undefined, "panel-content");
  events.reverse().forEach(e => { const entry = node("div", undefined, "audit-event"); entry.append(node("strong", e.action), node("div", e.task_id || e.actor, "subtext"), node("time", date(e.timestamp))); body.append(entry); });
  if (!events.length) body.append(node("p", "Activity will appear as work moves through the hub.", "empty"));
  $("content").append(panel("Workspace events", body));
  $("content").append(panel("Webhook deliveries", deliveries.length ? table(["Event", "Status", "Attempts", "Received"], deliveries.map(d => [d.event, pill(d.state), d.attempts, date(d.received_at)])) : node("p", "GitHub App webhook deliveries will appear here.", "empty")));
}
async function setupStatus() {
  const config = await api("/v1/admin/integrations");
  const steps = [
    {title: "Register the read-only GitHub App", detail: "One click: GitHub creates an app that can only read issues, pull requests, and checks. The hub never gets write access.", done: config.app.configured, action: () => registerApp(), label: "Register GitHub App"},
    {title: "Install it on your repositories", detail: "Choose exactly which repositories the hub may read. Change the selection on GitHub at any time.", done: (state.sources || []).length > 0, action: installApp, label: "Choose repositories"},
    {title: "Link your GitHub account as owner", detail: "Sign in with GitHub instead of the bootstrap token, and authorize product-manager agents.", done: config.admin_github_ids.length > 0, action: linkOwner, label: "Link my GitHub account"},
    {title: "Set up contributor sign-in", detail: "Register an OAuth App so contributors can prove who they are. It requests no repository access.", done: config.oauth.configured, action: () => configureOAuth(config), label: "Configure sign-in"},
    {title: "Invite contributors", detail: "Send each friend a private, single-use invitation for their coding agent.", done: (state.contributors || []).length > 0, action: () => go("people"), label: "Go to Contributors"},
  ];
  return {config, steps, next: steps.findIndex(step => !step.done)};
}
function registerApp(replacing) {
  form(replacing ? "Register a replacement GitHub App" : "Register the read-only GitHub App", [{name: "name", label: "App name", required: true, value: "Work Hub"}, {name: "organization", label: "Owning organization", placeholder: "Optional; leave empty for your personal account"}], "Continue to GitHub", async d => { const result = await post("/v1/admin/integrations/app/register", {...d, organization: d.organization || null}); location.assign(result.url); });
}
function installApp() {
  form("Install the GitHub App", [{name: "name", label: "Source name", placeholder: "Optional; leave empty for an automatic name"}, {name: "approvers", label: "Approver GitHub usernames", required: false, help: "Required for organization installations. Separate usernames with commas."}], "Choose repositories on GitHub", async d => { const result = await post("/v1/admin/integrations/app/install", {name: d.name || "Work Hub", approvers: split(d.approvers)}); location.assign(result.url); });
}
function go(target) { view = target; render().catch(error => toast(error.message, true)); }
function configureOAuth(config) {
  form("Configure contributor sign-in", [{name: "client_id", label: "Client ID", required: true, value: config.oauth.client_id || ""}, {name: "client_secret", label: "Client secret", type: "password", required: true}], "Save connection", async d => { await api("/v1/admin/integrations/oauth", {method: "PUT", body: JSON.stringify(d)}); $("dialog").close(); await refresh(); });
}
function linkOwner() {
  if (!providerFields().length) throw new Error("Complete step 1 first: register the GitHub App.");
  form("Link owner identity", [{name: "provider", label: "GitHub connection", options: providerFields()}], "Continue with GitHub", d => oauth({kind: "admin_link", provider: d.provider}));
}
function setupChecklist({steps, next}) {
  const card = node("section", undefined, "card setup"), list = node("ol", undefined, "setup-steps");
  card.append(node("h2", next < 0 ? "Setup complete" : `Set up your hub · step ${next + 1} of ${steps.length}`));
  steps.forEach((step, index) => {
    const item = node("li", undefined, step.done ? "done" : index === next ? "current" : ""), text = node("div");
    text.append(node("strong", step.title), node("p", step.detail, "subtext"));
    item.append(node("span", step.done ? "✓" : String(index + 1), "step-number"), text, step.done ? pill("complete") : index === next ? button(step.label, step.action, "primary") : pill("pending"));
    list.append(item);
  });
  card.append(list);
  return card;
}
async function renderSettings() {
  const status = await setupStatus(), config = status.config;
  $("content").append(setupChecklist(status));
  const appCard = node("section", undefined, "card");
  appCard.append(node("h2", "1–2 · Read-only GitHub App"), pill(config.app.configured ? ((state.sources || []).length ? "ready" : "installing") : "pending"), node("p", "Reads issues, pull requests, reviews, and checks on the repositories you choose, and receives webhooks for immediate updates. It cannot write to GitHub."));
  appCard.append(node("p", config.app.slug ? `Connected app: ${config.app.slug}` : "Registration sets read-only permissions, callbacks, and the webhook secret for you.", "subtext"));
  const appActions = node("div", undefined, "actions");
  appActions.append(button(config.app.configured ? "Register replacement app" : "Register GitHub App", () => registerApp(config.app.configured), config.app.configured ? "secondary" : "primary"));
  if (config.app.configured) appActions.append(button("Install on repositories", installApp, "primary"));
  appCard.append(appActions, node("p", "Webhook endpoint", "subtext"), node("pre", config.app.webhook_url));
  $("content").append(appCard);
  const grid = node("div", undefined, "grid-two");
  const owner = node("section", undefined, "card"); owner.append(node("h2", "3 · Owner sign-in"), pill(config.admin_github_ids.length ? "ready" : "pending"), node("p", "Link your GitHub identity so you can return with GitHub instead of the bootstrap token, and authorize product-manager agents."));
  owner.append(providerFields().length ? button("Link my GitHub account", linkOwner, config.admin_github_ids.length ? "secondary" : "primary") : node("p", "Available after step 1.", "subtext"), node("p", `${config.admin_github_ids.length} owner identities linked`, "subtext"));
  grid.append(owner);
  const oauthCard = node("section", undefined, "card"); oauthCard.append(node("h2", "4 · Contributor sign-in"), pill(config.oauth.configured ? "ready" : "pending"), node("p", "A GitHub OAuth App that only confirms who a contributor is. It requests no scopes, so it grants no repository access."));
  const register = node("a", "Register an OAuth App on GitHub"); register.href = "https://github.com/settings/applications/new"; register.target = "_blank"; register.rel = "noopener";
  oauthCard.append(register, node("p", "Homepage URL", "subtext"), node("pre", auth.public_url), node("p", "Redirect URI (authorization callback URL)", "subtext"), node("pre", config.oauth.callback_url));
  oauthCard.append(button(config.oauth.configured ? "Update sign-in credentials" : "Configure sign-in", () => configureOAuth(config), config.oauth.configured ? "secondary" : "primary"));
  grid.append(oauthCard); $("content").append(grid);
}
function renderContributor() {
  $("view-title").textContent = "Your work";
  $("page-actions").prepend(button("Claim approved work", () => form("Claim your next task", [{name: "source", label: "Account source", placeholder: "Leave empty for all sources"}, {name: "capabilities", label: "Available tools", placeholder: "python, uv, node, npm"}, {name: "minutes", label: "Time available (minutes)", type: "number", value: "60", required: true}, {name: "fork_name", label: "Custom fork name", placeholder: "Optional"}], "Claim work", async d => { const result = await post("/v1/work/claim", {source: d.source || null, capabilities: split(d.capabilities), work_minutes: Number(d.minutes), fork_name: d.fork_name || null, idempotency_key: crypto.randomUUID()}); if (!result.contract) throw new Error(result.reason); $("dialog").close(); await refresh(); showAssignment(result); }), "primary"));
  const assignments = state.assignments || [], container = node("div");
  assignments.forEach(a => { const c = node("section", undefined, "card"); c.append(pill(a.task_state || a.assignment.state), node("h2", a.contract.specification.title), node("p", `${a.contract.source.repository} #${a.contract.source.issue_number}`, "subtext"), button("View contract", () => showAssignment(a))); if (a.submission) { const link = node("a", "Open pull request"); link.href = a.submission.pr_url; link.target = "_blank"; link.rel = "noopener"; c.append(link); } container.append(c); });
  if (!assignments.length) container.append(node("p", "You have no assignments yet. Claim one here or check in from your coding agent.", "empty"));
  $("content").append(panel("Your assignments", container));
  $("content").append(panel("Available approved work", state.available.length ? table(["Work", "Priority", "Tools"], state.available.map(t => [taskName(t), t.priority ? "High" : "Normal", t.required_tools.join(", ") || "Any"])) : node("p", "No eligible work is currently available to your GitHub account.", "empty")));
}
function showAssignment(a) {
  const body = node("div"), id = a.contract.contract_id, lease = {attempt_id: a.assignment.attempt_id, generation: a.assignment.generation};
  body.append(node("p", `Lease: ${human(a.assignment.state)} · expires ${date(a.assignment.expires_at)}`, "subtext"), node("pre", a.contract.specification.body), node("pre", `workhub work prepare ${id} ./contribution\nworkhub work keepalive ${id}`));
  const actions = node("div", undefined, "actions");
  actions.append(button("Download contract", () => { const url = URL.createObjectURL(new Blob([JSON.stringify(a, null, 2)], {type: "application/json"})); const link = node("a"); link.href = url; link.download = `${id}.json`; link.click(); URL.revokeObjectURL(url); }));
  if (a.assignment.state === "leased") {
    actions.append(button("Renew lease", async () => { const result = await post(`/v1/work/${id}/heartbeat`, lease); showAssignment(result); }), button("Check push repository", async () => { const r = await post(`/v1/work/${id}/provision`, lease); if (r.status === "ready") toast(`Push to ${r.repository}`); else { const b = node("div"); b.append(node("p", r.instructions), node("pre", r.command.join(" "))); dialog(`Create your fork: ${r.repository}`, b); } }));
    for (const action of ["block", "release"]) actions.append(button(action === "block" ? "Report blocker" : "Release work", () => form(action === "block" ? "Report a blocker" : "Leave a handoff", [{name: "note", label: "Notes", type: "textarea", required: true}], "Save", async d => { await post(`/v1/work/${id}/${action}`, {...lease, ...d}); $("dialog").close(); await refresh(); })));
    actions.append(button("Submit pull request", () => form("Submit your pull request", [{name: "pr_url", label: "PR URL", type: "url", required: true}, {name: "head_sha", label: "Full commit SHA", required: true}, {name: "evidence", label: "Validation results", type: "textarea", required: true}], "Verify submission", async d => { await post(`/v1/work/${id}/submit`, {...lease, ...d}); $("dialog").close(); await refresh(); }), "primary"));
  } else actions.append(button("Resume assignment", async () => { const result = await post(`/v1/work/${id}/resume`, lease); showAssignment(result); }));
  body.append(actions); const details = node("details"); details.append(node("summary", "Full contract"), node("pre", JSON.stringify(a, null, 2))); body.append(details); dialog(a.contract.specification.title, body);
}
refresh().catch(error => toast(error.message, true));
setInterval(() => { if (auth.authenticated && !$("dialog").open && document.visibilityState === "visible") refresh().catch(error => toast(error.message, true)); }, 30000);
