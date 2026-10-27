// PAN-OS Decrypt Bypass front end. Every value from the logs goes through
// textContent (never innerHTML): SNI, CN and error strings are attacker-controlled.

const $ = (id) => document.getElementById(id);
const REFRESH_MS = 30000;
let expanded = null;
let lastStatus = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  }
  return node;
}

function ago(epoch) {
  const s = Math.max(0, Date.now() / 1000 - epoch);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
const fullTime = (epoch) => new Date(epoch * 1000).toLocaleString();

function params() {
  return new URLSearchParams({
    hours: $("hours").value,
    failures_only: $("failuresOnly").checked,
    hide_bypassed: $("hideBypassed").checked,
    q: $("search").value,
  });
}

function signedOut(r) {
  if (r.status === 401) {
    location.replace("/login");
    return true;
  }
  return false;
}

async function getJSON(url, opts) {
  const r = await fetch(url, opts);
  if (signedOut(r)) throw new Error("Signed out");
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// --- Status ------------------------------------------------------------------

async function loadStatus() {
  const box = $("status");
  try {
    const s = await getJSON("/api/status");
    lastStatus = s;
    $("logout").hidden = !s.auth;
    $("version").textContent = `panos-decrypt-bypass ${s.version}`;
    $("setupHint").hidden = s.configured;
    $("setupHint").textContent = "Not configured yet: set folder (or snippet) in terraform.tfvars in the data directory before deploying. See docs/configuration.md.";
    const m = s.management;
    $("dlgHow").textContent = m.mode === "local"
      ? "Adds the hostnames to the no-decrypt URL category on the firewall, then commits."
      : "Adds the hostnames to the no-decrypt URL category, then applies it in SCM and pushes to the firewall.";
    const problem = s.problems.length ? s.problems.join(" ") : s.last_error;
    const dot = el("span", { class: `dot ${problem ? "err" : s.polling ? "busy" : ""}` });
    const parts = [dot, `Firewall ${s.firewall}`];
    if (s.last_success) parts.push(` · polled ${ago(s.last_success)}`);
    parts.push(` · ${s.events_stored.toLocaleString()} logs stored`);
    box.replaceChildren(...parts);
    if (problem) box.append(el("span", { class: "badge bad", title: problem }, problem.length > 90 ? problem.slice(0, 90) + "…" : problem));
  } catch (e) {
    box.replaceChildren(el("span", { class: "dot err" }), ` Can't reach the viewer API: ${e.message}`);
  }
}

// --- Issues table ----------------------------------------------------------

function problemBadge(advice) {
  if (!advice.kind && advice.summary === "No error") return el("span", { class: "badge ok" }, "OK");
  const cls = advice.kind === "exclusion" ? "bad" : advice.kind === "url" ? "warn" : "info";
  return el("span", { class: `badge ${cls}` }, advice.summary);
}

function bypassCell(issue) {
  if (issue.bypassed_by.length) {
    return issue.bypassed_by.map((b) => el("span", { class: "badge ok", title: `${b.kind} list` }, `✓ ${b.entry}`));
  }
  if (!issue.failures) return el("span", { class: "meta" }, "—");
  if (!issue.sni && !issue.cn) {
    return el("button", { type: "button", class: "secondary", disabled: true,
      title: "No hostname in the log, so there's nothing to add to the URL list. Add the IP from the CLI: main.py add destination <ip>" }, "Bypass…");
  }
  return el("button", { type: "button", class: "secondary", onclick: (ev) => { ev.stopPropagation(); openBypass(issue); } }, "Bypass…");
}

const IPS_SHOWN = 3;

function destinationIps(ips) {
  const shown = ips.slice(0, IPS_SHOWN).map((ip) => el("div", { class: "ips" }, ip));
  if (ips.length > IPS_SHOWN) shown.push(el("div", { class: "meta" }, `+${ips.length - IPS_SHOWN} more`));
  return shown;
}

function issueRow(issue) {
  const host = issue.sni || issue.cn || issue.dst;
  const row = el("tr", { class: "issue", tabindex: "0", "aria-expanded": expanded === issue.target ? "true" : "false" },
    el("td", { title: fullTime(issue.last_seen) }, ago(issue.last_seen)),
    el("td", {},
      el("div", { class: "host", title: issue.sni_truncated ? `The firewall's log cut this hostname short; it is ${issue.sni_truncated} characters long` : null },
        issue.sni_truncated ? `${host}…` : host),
      el("div", { class: "meta" }, `port ${issue.dport || "?"}${!issue.sni ? " · no SNI" : ""}`)),
    el("td", { title: issue.dst_ips.join("\n") }, destinationIps(issue.dst_ips)),
    el("td", {},
      problemBadge(issue.advice),
      issue.error ? el("div", { class: "err-text" }, issue.error) : null),
    el("td", { class: "num" }, issue.hits),
    el("td", { class: "num", title: issue.client_ips.join(", ") }, issue.clients),
    el("td", { class: "meta" }, issue.policy_name || "—"),
    el("td", {}, bypassCell(issue)),
  );
  const toggle = () => { expanded = expanded === issue.target ? null : issue.target; render(lastIssues); };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  return row;
}

// --- Copy to clipboard --------------------------------------------------------

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Blocked (plain HTTP, permissions policy, some embedded browsers): use the old way.
    }
  }
  const area = el("textarea", { class: "offscreen", readonly: true });
  area.value = text;
  document.body.append(area);
  area.select();
  try {
    if (!document.execCommand("copy")) throw new Error("copy refused");
  } finally {
    area.remove();
  }
}

// A value you can click (or press Enter on) to copy. `value` is what's copied,
// `shown` what's displayed, e.g. the IP alone for "203.0.113.5:443".
function copy(value, shown = value) {
  if (value === undefined || value === null || value === "") return "—";
  return el("span", { class: "copy", tabindex: "0", role: "button", title: "Click to copy", "aria-label": `Copy ${value}`, "data-copy": String(value) }, shown);
}

async function copyFrom(node) {
  if (window.getSelection()?.toString()) return; // selecting text, not clicking
  try {
    await copyText(node.dataset.copy);
    node.classList.add("copied");
  } catch {
    node.classList.add("copy-failed");
  }
  setTimeout(() => node.classList.remove("copied", "copy-failed"), 1200);
}

document.addEventListener("click", (e) => {
  const node = e.target.closest?.(".copy");
  if (node) copyFrom(node);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.classList?.contains("copy")) copyFrom(e.target);
});

// --- Detail row ------------------------------------------------------------------

const kv = (label, value) => el("div", {}, el("span", {}, label), copy(Array.isArray(value) ? value.join(", ") : value));
const lookups = new Map(); // target -> lookup result; survives the periodic re-render

function seenFrom(events) {
  const groups = new Map();
  for (const e of events) {
    const key = [e.src, e.src_host, e.srcuser, e.from_zone].join("|");
    const g = groups.get(key) || { ...e, n: 0 };
    g.n += 1;
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => b.n - a.n).map((g) => {
    const who = [g.src_host, g.srcuser].filter(Boolean).join(" · ");
    return el("div", { class: "seen" },
      copy(g.src),
      who ? " " : "",
      who ? copy(who) : "",
      el("span", { class: "meta" }, `${g.from_zone ? ` zone ${g.from_zone}` : ""} · ${g.n} event${g.n === 1 ? "" : "s"}`),
    );
  });
}

function lookupPart(title, data, rows) {
  const head = el("h4", {}, title);
  if (!data) return null;
  if (data.error) return el("div", { class: "about-part" }, head, el("p", { class: "meta" }, `Not available: ${data.error}`));
  if (data.skipped) return el("div", { class: "about-part" }, head, el("p", { class: "meta" }, data.skipped));
  const shown = rows.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length));
  return el("div", { class: "about-part" }, head,
    shown.length ? el("div", { class: "detail-grid" }, shown.map(([label, value]) => kv(label, value))) : el("p", { class: "meta" }, "Nothing found."));
}

function lookupView(r) {
  const c = r.certificate || {};
  const certNames = c.names ? c.names.join(", ") + (c.more_names ? ` (+${c.more_names} more)` : "") : "";
  const parts = r.kind === "ip"
    ? [
        lookupPart("Network", r.network, [["Network", r.network?.network], ["Range", r.network?.range], ["Owner", r.network?.owner], ["Country", r.network?.country]]),
        lookupPart("DNS", r.dns, [["Reverse DNS", r.dns?.reverse]]),
      ]
    : [
        lookupPart("Registration", r.registration, [
          ["Domain", r.registration?.domain], ["Registrant", r.registration?.registrant], ["Registrar", r.registration?.registrar],
          ["Registered", r.registration?.registered], ["Expires", r.registration?.expires], ["Name servers", r.registration?.nameservers],
        ]),
        lookupPart("DNS", r.dns, [["Canonical name", r.dns?.canonical !== r.target ? r.dns?.canonical : ""], ["Addresses", r.dns?.addresses]]),
      ];
  parts.push(lookupPart("Server certificate", c, [
    ["Subject", c.subject], ["Organization", [c.organization, c.country].filter(Boolean).join(", ")], ["Issuer", c.issuer],
    ["Also valid for", certNames], ["Expires", c.expires], ["Name check", c.matches === false ? `Doesn't cover ${r.target}` : ""],
  ]));
  const links = el("div", { class: "links" }, "Research: ",
    r.links.flatMap((l, i) => [i ? " · " : "", el("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.label)]));
  return [el("div", { class: "about-grid" }, parts), links, el("p", { class: "meta" }, `Looked up ${ago(r.looked_up)}.`)];
}

// --- Find the app on the client --------------------------------------------------
// Commands to run on the client that made the connection. Hostnames come from
// the TLS handshake and are attacker-controlled, so only names and IPs made of
// plainly safe characters ever reach a command; anything else gets none.

const SAFE_NAME = /^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))+$/;
const SAFE_IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const SAFE_IPV6 = /^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$/;
const OSES = [["mac", "macOS"], ["windows", "Windows"], ["linux", "Linux"]];
const findAppOpen = new Set(); // targets whose panel is open; kept across the periodic re-render

// PowerShell regex that also matches UTF-16 text (a NUL after each character),
// which is how many Windows programs store strings.
const utf16Pattern = (name) => [...name].map((c) => (c === "." ? "\\." : c) + "\\x00?").join("");

function clientCommands(os, name, ips) {
  const v4 = ips.filter((ip) => SAFE_IPV4.test(ip)).slice(0, 6);
  const v6 = ips.filter((ip) => SAFE_IPV6.test(ip)).slice(0, 4);
  const all = [...v4, ...v6];
  const cmds = [];
  if (os === "mac") {
    if (name) cmds.push(["Search installed apps for the name (a few minutes; skips files over 1 GB, such as VM disk images)",
      `find /Applications "$HOME/Library/Application Support" "/Library/Application Support" -type f -size -1024M -print0 2>/dev/null | xargs -0 -n 200 -P 8 grep -l --binary-files=text -F '${name}' 2>/dev/null`]);
    if (all.length) cmds.push(["Which process is connected to it right now",
      `sudo lsof -nP ${[...v4.map((ip) => `-i@${ip}`), ...v6.map((ip) => `'-i@[${ip}]'`)].join(" ")}`]);
  } else if (os === "windows") {
    if (name) cmds.push(["Search installed apps for the name (PowerShell; several minutes; skips files over 1 GB)",
      `Get-ChildItem $env:ProgramFiles, \${env:ProgramFiles(x86)}, $env:LOCALAPPDATA, $env:APPDATA -Recurse -File -ErrorAction SilentlyContinue | Where-Object Length -lt 1GB | Select-String -Pattern '${utf16Pattern(name)}' -List -ErrorAction SilentlyContinue | Select-Object -Unique Path`]);
    if (all.length) cmds.push(["Which process is connected to it right now (PowerShell)",
      `Get-NetTCPConnection -RemoteAddress ${all.map((ip) => `'${ip}'`).join(",")} -ErrorAction SilentlyContinue | ForEach-Object { Get-Process -Id $_.OwningProcess } | Select-Object -Unique Name, Path`]);
  } else {
    if (name) cmds.push(["Search installed apps for the name (a few minutes; skips files over 1 GB)",
      `find /opt /usr/share /usr/lib "$HOME/.local" "$HOME/.config" /snap /var/lib/flatpak -type f -size -1024M -print0 2>/dev/null | xargs -0 -n 200 -P 8 grep -l --binary-files=text -F '${name}' 2>/dev/null`]);
    if (all.length) cmds.push(["Which process is connected to it right now",
      `sudo ss -tnp '( ${[...v4.map((ip) => `dst ${ip}`), ...v6.map((ip) => `dst [${ip}]`)].join(" or ")} )'`]);
  }
  return cmds;
}

let findAppOs = (() => {
  try {
    return localStorage.getItem("findAppOs") || (navigator.userAgent.includes("Windows") ? "windows" : "mac");
  } catch {
    return "mac";
  }
})();

function findAppPanel(issue, events) {
  const looked = lookups.get(issue.target);
  const isIp = SAFE_IPV4.test(issue.target) || issue.target.includes(":");
  const candidate = (looked?.registration?.domain || (isIp ? "" : issue.target)).toLowerCase();
  const name = SAFE_NAME.test(candidate) ? candidate : "";
  const ips = (issue.dst_ips || []).map((ip) => ip.toLowerCase());
  const clients = [...new Set(events.map((e) => e.src).filter(Boolean))];
  const body = el("div", { class: "find-app-body" });
  const picker = el("div", { class: "os-picker", role: "group", "aria-label": "Client operating system" });

  const draw = () => {
    picker.replaceChildren(...OSES.map(([key, label]) => el("button", {
      type: "button", class: key === findAppOs ? "" : "secondary", "aria-pressed": key === findAppOs ? "true" : "false",
      onclick: () => {
        findAppOs = key;
        try { localStorage.setItem("findAppOs", key); } catch { /* not saved */ }
        draw();
      },
    }, label)));
    const cmds = clientCommands(findAppOs, name, ips);
    body.replaceChildren(...(cmds.length ? cmds.flatMap(([label, cmd]) => [
      el("p", { class: "meta" }, label),
      el("pre", { class: "cmd copy", tabindex: "0", role: "button", title: "Click to copy", "aria-label": `Copy command: ${label}`, "data-copy": cmd }, cmd),
    ]) : [el("p", { class: "meta" }, "No command for this destination: its name or address contains characters that aren't safe to put in a command.")]));
  };
  draw();

  const panel = el("details", { class: "find-app", open: findAppOpen.has(issue.target) },
    el("summary", {}, "Find the app on the client"),
    el("p", { class: "meta" },
      `Run these on ${clients.length ? clients.join(", ") : "the client"}${name ? `. The search looks for ${name} inside installed apps` : ""}. ` +
      "Apps that compress or encrypt their files won't match. Phones, TVs and other devices can't be searched: check which apps they run, or the vendor's support pages."),
    picker,
    body,
  );
  panel.addEventListener("toggle", () => (panel.open ? findAppOpen.add(issue.target) : findAppOpen.delete(issue.target)));
  return panel;
}

function aboutPanel(issue, events) {
  const lookupBox = el("div", { class: "lookup" });
  const show = (res) => lookupBox.replaceChildren(...lookupView(res));
  if (lookups.has(issue.target)) {
    show(lookups.get(issue.target));
  } else if (lastStatus?.lookup) {
    const button = el("button", { type: "button", class: "secondary" }, "Look up");
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Looking up…";
      try {
        const res = await postJSON("/api/lookup", { target: issue.target });
        lookups.set(issue.target, res);
        render(lastIssues); // the find-app commands can now use the registered domain
      } catch (e) {
        button.disabled = false;
        button.textContent = "Look up";
        lookupBox.append(el("p", { class: "meta" }, `Lookup failed: ${e.message}`));
      }
    });
    lookupBox.replaceChildren(button, el("span", { class: "meta" },
      " registration, DNS and server certificate. Sends the name to rdap.org and connects to the server on port 443."));
  }
  return el("section", { class: "about" },
    el("h3", {}, "About this destination"),
    events.length ? el("div", { class: "seen-from" }, el("span", { class: "meta" }, "Seen from"), seenFrom(events)) : null,
    lookupBox,
    findAppPanel(issue, events),
  );
}

async function detailRow(issue) {
  const cell = el("td", { colspan: "8" }, el("p", { class: "meta" }, "Loading events…"));
  const row = el("tr", { class: "detail" }, cell);
  const grid = el("div", { class: "detail-grid" },
    kv("Diagnosis", issue.advice.detail),
    kv("Cert subject / issuer", [issue.cn, issue.issuer_cn].filter(Boolean).join(" ← ")),
    kv("Chain / root status", [issue.chain_status, issue.root_status].filter(Boolean).join(" / ")),
    kv("TLS version · proxy", [issue.tls_version, issue.proxy_type].filter(Boolean).join(" · ")),
  );
  try {
    const events = await getJSON(`/api/events?${new URLSearchParams({ target: issue.target, hours: $("hours").value })}`);
    const table = el("table", { class: "events" },
      el("thead", {}, el("tr", {}, ["Time", "Client", "User / host", "Destination", "Error", "Proxy", "TLS"].map((h) => el("th", {}, h)))),
      el("tbody", {}, events.map((e) => el("tr", {},
        el("td", {}, copy(e.receive_time)),
        el("td", {}, copy(e.src)),
        el("td", {}, copy([e.srcuser, e.src_host].filter(Boolean).join(" · "))),
        el("td", { class: "ips" }, copy(e.dst, `${e.dst}:${e.dport || "?"}`)),
        el("td", {}, copy(e.error)),
        el("td", {}, copy(e.proxy_type)),
        el("td", {}, copy(e.tls_version)),
      ))),
    );
    cell.replaceChildren(grid, aboutPanel(issue, events), table);
  } catch (e) {
    cell.replaceChildren(grid, aboutPanel(issue, []), el("p", { class: "meta" }, `Couldn't load events: ${e.message}`));
  }
  return row;
}

let lastIssues = [];

async function render(issues) {
  lastIssues = issues;
  const body = $("issues").querySelector("tbody");
  const rows = [];
  for (const issue of issues) {
    rows.push(issueRow(issue));
    if (expanded === issue.target) rows.push(await detailRow(issue));
  }
  body.replaceChildren(...rows);
  const empty = $("empty");
  empty.hidden = issues.length > 0;
  if (!lastStatus?.last_success) {
    empty.textContent = "No logs pulled from the firewall yet. Check the status at the top right.";
  } else {
    empty.textContent = $("failuresOnly").checked
      ? "No decryption failures in this window. 🎉"
      : "No decryption logs in this window.";
  }
}

async function loadIssues() {
  try {
    await render(await getJSON(`/api/issues?${params()}`));
  } catch (e) {
    $("empty").hidden = false;
    $("empty").textContent = `Couldn't load issues: ${e.message}`;
  }
}

// --- Bypass dialog -----------------------------------------------------------

async function postJSON(url, body) {
  // X-Decrypt-Viewer is required by the server: it keeps other sites from posting here.
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Decrypt-Viewer": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (signedOut(r)) throw new Error("Signed out");
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : d ? d.map((x) => x.msg).join("; ") : `${r.status} ${r.statusText}`);
  }
  return data;
}

// Second-level labels used under two-letter country TLDs (bbc.co.uk, example.com.au),
// so "all of the domain" never becomes "all of co.uk".
const COUNTRY_SLDS = new Set(["co", "com", "net", "org", "gov", "edu", "ac", "ne", "or", "go", "gob", "nic", "mil"]);

function parentDomain(host) {
  const labels = host.replace(/^\*\./, "").split(".");
  const keep = labels.at(-1).length === 2 && COUNTRY_SLDS.has(labels.at(-2)) ? 3 : 2;
  return labels.length > keep ? labels.slice(-keep).join(".") : null;
}

// Mirrors bypass_lists.with_subdomains, for the preview only.
function withSubdomains(entries) {
  const out = [];
  for (const e of entries) {
    const base = e.replace(/^www\./, "");
    for (const v of base.startsWith("*.") ? [base] : [base, `*.${base}`]) if (!out.includes(v)) out.push(v);
  }
  return out;
}

const dialogEntries = () => $("dlgEntries").value.split(/[\s,]+/).filter(Boolean);
const dialogScope = () => document.querySelector("input[name=scope]:checked")?.value || "host";
const dialogSubdomains = () => dialogScope() !== "host";
let dialogHost = "";
let dialogParent = null;

function setScope(scope) {
  document.querySelectorAll("input[name=scope]").forEach((r) => { r.checked = r.value === scope; });
  $("dlgEntries").value = scope === "domain" ? dialogParent : dialogHost;
  updatePreview();
}

function updatePreview() {
  const entries = dialogSubdomains() ? withSubdomains(dialogEntries()) : dialogEntries();
  $("dlgPreview").textContent = entries.length ? `Will add: ${entries.join(", ")}` : "";
  $("dlgError").hidden = true;
}

function openBypass(issue) {
  const host = issue.sni || issue.cn;
  $("dlgTarget").textContent = host;
  $("dlgAdvice").textContent = `${issue.advice.summary}. ${issue.advice.detail}`
    + (issue.sni_truncated ? ` Note: the firewall's log cut this hostname short. It starts with ${issue.sni} and is ${issue.sni_truncated} characters long, so complete it below before adding.${issue.cn ? ` The server's certificate is for ${issue.cn}.` : ""}` : "");
  dialogHost = host;
  dialogParent = !issue.sni_truncated && parentDomain(host);
  $("scopeHost").textContent = host;
  document.querySelectorAll(".scope-host").forEach((n) => { n.textContent = host; });
  $("scopeDomain").textContent = dialogParent || "";
  $("scopeDomainRow").hidden = !dialogParent;
  $("dlgDesc").value = `Decrypt log: ${issue.advice.summary}`;
  $("dlgSubmit").disabled = false;
  setScope("host");
  $("bypassDialog").showModal();
}

$("bypassDialog").addEventListener("input", (ev) => {
  if (ev.target.name === "scope") setScope(ev.target.value);
  else updatePreview();
});
$("dlgClose").addEventListener("click", () => $("bypassDialog").close());
$("bypassForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("dlgSubmit").disabled = true;
  try {
    const res = await postJSON("/api/bypass", {
      entries: dialogEntries(),
      subdomains: dialogSubdomains(),
      description: $("dlgDesc").value,
    });
    if (!res.job) {
      throw new Error(`Already in the list: ${res.already.join(", ")}. If it hasn't reached the firewall yet, use Deploy….`);
    }
    $("bypassDialog").close();
    showDeploy(res.job);
  } catch (e) {
    $("dlgError").textContent = e.message;
    $("dlgError").hidden = false;
    $("dlgSubmit").disabled = false;
  }
});

// --- Deploy panel ------------------------------------------------------------

let deployJob = null;
let deployTimer = null;
const ACTIVE = ["planning", "applying", "pushing"];

// Wording for SCM (push) or a locally managed firewall (commit).
function words() {
  const local = lastStatus?.management?.mode === "local";
  return local
    ? { target: "the firewall", publish: "commit", step: "Commit", nochangeButton: "Commit now",
        publishing: "Committing on the firewall. This usually takes a minute or two; you can close this window and keep working.",
        done: "Done. The firewall has committed the new config.",
        nochange: "Nothing to apply: the firewall already matches the bypass lists. If an earlier commit failed, commit now.",
        failed: " The change is in the firewall's candidate config; only the commit failed." }
    : { target: "SCM", publish: "push", step: "Push to firewall", nochangeButton: "Push to firewall",
        publishing: "Pushing to the firewall. This usually takes a few minutes; you can close this window and keep working.",
        done: "Done. SCM is updated and the firewall has the new config.",
        nochange: "Nothing to apply: SCM already matches the bypass lists. If an earlier push failed, push now to send SCM's config to the firewall.",
        failed: " SCM has the change; only the push to the firewall failed." };
}

function steps(job) {
  const list = [["planning", "Plan"]];
  if (job.kind === "manual" || job.review_reason) list.push(["review", "Review"]);
  list.push(["applying", "Apply"], ["pushing", words().step]);
  const failedAt = { plan: "planning", apply: "applying", push: "pushing" }[job.failed_stage];
  const at = job.state === "failed" ? failedAt : job.state;
  const idx = list.findIndex(([k]) => k === at);
  const finished = ["done"].includes(job.state);
  return list.map(([k, label], i) => {
    let cls = "";
    if (finished || (idx >= 0 && i < idx)) cls = "done";
    else if (i === idx) cls = job.state === "failed" ? "bad" : "now";
    return el("li", { class: cls }, `${cls === "done" ? "✓" : cls === "bad" ? "✗" : cls === "now" ? "●" : "○"} ${label}`);
  });
}

function deployMessage(job) {
  const w = words();
  switch (job.state) {
    case "planning": return `Checking what will change in ${w.target}…`;
    case "review": return `${job.review_reason} Nothing has been changed yet.`;
    case "applying": return `Applying to ${w.target}…`;
    case "pushing": return w.publishing;
    case "done": return job.added.length ? `Done. ${job.added.join(", ")} ${job.added.length > 1 ? "are" : "is"} no longer decrypted.` : w.done;
    case "nochange": return w.nochange;
    case "cancelled": return "Cancelled. Nothing was changed" + (job.added.length ? `, and ${job.added.join(", ")} came back out of the list.` : ".");
    case "failed":
      return `Failed during ${job.failed_stage}: ${job.error}` +
        (job.failed_stage === "plan" && job.added.length ? " The new entries were taken back out of the list." : "") +
        (job.failed_stage === "push" ? w.failed : "");
  }
  return "";
}

function renderDeploy() {
  const job = deployJob;
  $("depTitle").textContent = job.kind === "bypass" ? `Bypass ${job.added.join(", ")}` : `Deploy pending changes (#${job.id})`;
  $("depSteps").replaceChildren(...(["nochange", "cancelled"].includes(job.state) ? [] : steps(job)));
  $("depMessage").textContent = deployMessage(job);
  $("depMessage").hidden = false;
  $("depMessage").className = `advice ${job.state === "failed" ? "bad" : ""}`;

  $("depChanges").replaceChildren(job.changes.length ? el("ul", { class: "changes" }, job.changes.map((c) =>
    el("li", {},
      el("div", { class: "what" }, `${c.actions.join("/")}: ${c.label}`),
      c.detail.map((d) => el("div", { class: "detail" }, d)),
    ))) : "");

  const log = $("depLog");
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 20;
  log.textContent = job.log.join("\n");
  if (atBottom) log.scrollTop = log.scrollHeight;

  const act = (label, fn, cls = "") => el("button", { type: "button", class: cls, onclick: fn }, label);
  const close = act(ACTIVE.includes(job.state) ? "Hide" : "Close", () => $("deployDialog").close(), "secondary");
  const buttons = [];
  if (job.state === "review") {
    buttons.push(
      act("Later", () => $("deployDialog").close(), "link"),
      act("Cancel", () => deployAction("cancel"), "secondary"),
      act(`Apply & ${words().publish}`, () => deployAction("confirm")),
    );
  } else if (job.state === "failed" && job.failed_stage === "push") {
    buttons.push(close, act(`Retry ${words().publish}`, () => deployAction("retry-push")));
  } else if (job.state === "nochange") {
    buttons.push(close, act(words().nochangeButton, () => deployAction("retry-push"), "secondary"));
  } else {
    buttons.push(close);
  }
  $("depActions").replaceChildren(...buttons);
  renderBanner();
}

function renderBanner() {
  const job = deployJob;
  const show = job && (ACTIVE.includes(job.state) || job.state === "review") && !$("deployDialog").open;
  $("deployBanner").hidden = !show;
  if (show) {
    $("deployBanner").replaceChildren(
      el("span", {}, job.state === "review" ? `Deploy #${job.id} is waiting for your review.` : `Deploy #${job.id}: ${job.state}…`),
      el("button", { type: "button", class: "link", onclick: () => showDeploy(job) }, "View"),
    );
  }
}

async function deployAction(action) {
  try {
    const res = await postJSON(`/api/deploy/${deployJob.id}/${action}`);
    showDeploy(res.job);
  } catch (e) {
    alert(e.message);
  }
}

function showDeploy(job) {
  deployJob = job;
  if (!$("deployDialog").open) $("deployDialog").showModal();
  renderDeploy();
  pollDeploy();
}

async function pollDeploy() {
  clearTimeout(deployTimer);
  if (!deployJob || !ACTIVE.includes(deployJob.state)) return;
  deployTimer = setTimeout(async () => {
    try {
      const { job } = await getJSON("/api/deploy");
      if (job) {
        const finished = ACTIVE.includes(deployJob.state) && !ACTIVE.includes(job.state);
        deployJob = job;
        renderDeploy();
        if (finished) loadIssues();
      }
    } catch { /* keep polling */ }
    pollDeploy();
  }, 2000);
}

$("deployDialog").addEventListener("close", renderBanner);
$("deployBtn").addEventListener("click", async () => {
  try {
    showDeploy((await postJSON("/api/deploy")).job);
  } catch (e) {
    const { job } = await getJSON("/api/deploy");
    if (job && (ACTIVE.includes(job.state) || job.state === "review")) showDeploy(job);
    else alert(e.message);
  }
});

// --- Wiring ------------------------------------------------------------------

let searchTimer;
$("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadIssues, 250); });
["hours", "failuresOnly", "hideBypassed"].forEach((id) => $(id).addEventListener("change", loadIssues));
$("pollNow").addEventListener("click", async () => {
  await postJSON("/api/poll");
  setTimeout(() => { loadStatus(); loadIssues(); }, 3000);
});

$("logout").addEventListener("click", async () => {
  await postJSON("/api/logout").catch(() => {});
  location.replace("/login");
});

async function refresh() { await loadStatus(); loadIssues(); }
refresh();
getJSON("/api/deploy").then(({ job }) => { if (job) { deployJob = job; renderBanner(); pollDeploy(); } }).catch(() => {});
setInterval(() => {
  if (!document.hidden && !$("bypassDialog").open && !$("deployDialog").open) refresh();
}, REFRESH_MS);
