/* Aegis EDR dashboard.
 *
 * Security notes:
 * - All server-supplied strings are rendered via textContent (never innerHTML),
 *   so alert fields cannot inject markup or scripts.
 * - The API token lives only in memory + sessionStorage (cleared when the tab
 *   closes); it is never written to localStorage or cookies.
 * - CSP (script-src 'self') blocks any inline script anyway — defense in depth.
 */
"use strict";

let token = sessionStorage.getItem("aegis_token") || "";

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (response.status === 401) {
    logout();
    throw new Error("unauthorized");
  }
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : detail;
    } catch (_) { /* non-JSON error body */ }
    throw new Error(detail);
  }
  if (response.status === 204) return null;
  return response.json();
}

function logout() {
  token = "";
  sessionStorage.removeItem("aegis_token");
  $("console-view").hidden = true;
  $("login-view").hidden = false;
}

function showConsole() {
  $("login-view").hidden = true;
  $("console-view").hidden = false;
  refreshAll();
}

/* ---- rendering ---- */

function renderStats(stats) {
  $("host-label").textContent = `host: ${stats.host}`;
  $("stat-total").textContent = stats.total_alerts;
  for (const sev of ["critical", "high", "medium", "low"]) {
    $(`stat-${sev}`).textContent = stats.by_severity[sev] || 0;
  }
}

function subjectOf(alert) {
  const e = alert.event || {};
  return e.cmdline || e.path ||
    `${e.process || "?"} -> ${e.remote_ip || "?"}${e.remote_port ? ":" + e.remote_port : ""}`;
}

function renderAlerts(data) {
  const body = $("alerts-body");
  body.replaceChildren();
  $("alerts-empty").hidden = data.alerts.length > 0;
  for (const alert of data.alerts) {
    const tr = document.createElement("tr");
    tr.appendChild(el("td", null, alert.timestamp));
    const sevTd = el("td");
    sevTd.appendChild(el("span", `badge badge-${alert.severity}`, alert.severity));
    tr.appendChild(sevTd);
    tr.appendChild(el("td", null, alert.rule_id));
    tr.appendChild(el("td", null, alert.name));
    tr.appendChild(el("td", null, subjectOf(alert)));
    const mitreTd = el("td");
    for (const tid of alert.mitre || []) mitreTd.appendChild(el("span", "mitre-tag", tid));
    tr.appendChild(mitreTd);
    body.appendChild(tr);
  }
}

function renderRules(data) {
  const body = $("rules-body");
  body.replaceChildren();
  for (const rule of data.rules) {
    const tr = document.createElement("tr");
    tr.appendChild(el("td", null, rule.id));
    tr.appendChild(el("td", null, rule.name));
    const sevTd = el("td");
    sevTd.appendChild(el("span", `badge badge-${rule.severity}`, rule.severity));
    tr.appendChild(sevTd);
    const mitreTd = el("td");
    for (const tid of rule.mitre || []) mitreTd.appendChild(el("span", "mitre-tag", tid));
    tr.appendChild(mitreTd);
    body.appendChild(tr);
  }
}

function renderIocs(iocs) {
  const wrap = $("ioc-list");
  wrap.replaceChildren();
  for (const [category, values] of Object.entries(iocs)) {
    if (!values.length) continue;
    const section = el("div", "ioc-cat");
    section.appendChild(el("h3", null, `${category} (${values.length})`));
    for (const value of values) {
      const item = el("span", "ioc-item", value);
      const btn = el("button", null, "✕");
      btn.type = "button";
      btn.title = "remove";
      btn.addEventListener("click", async () => {
        try {
          await api("/api/iocs", {
            method: "DELETE",
            body: JSON.stringify({ category, value }),
          });
          refreshIocs();
        } catch (err) {
          $("ioc-error").textContent = err.message;
          $("ioc-error").hidden = false;
        }
      });
      item.appendChild(btn);
      section.appendChild(item);
    }
    wrap.appendChild(section);
  }
}

/* ---- data loading ---- */

async function refreshStats() { renderStats(await api("/api/stats")); }
async function refreshAlerts() {
  const sev = $("severity-filter").value;
  renderAlerts(await api(`/api/alerts?limit=200${sev ? `&severity=${sev}` : ""}`));
}
async function refreshRules() { renderRules(await api("/api/rules")); }
async function refreshIocs() { renderIocs(await api("/api/iocs")); }

async function refreshAll() {
  try {
    await Promise.all([refreshStats(), refreshAlerts(), refreshRules(), refreshIocs()]);
  } catch (err) {
    if (err.message !== "unauthorized") console.error(err);
  }
}

/* ---- events ---- */

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  token = $("token-input").value.trim();
  try {
    await api("/api/auth/verify", { method: "POST" });
    sessionStorage.setItem("aegis_token", token);
    $("login-error").hidden = true;
    showConsole();
  } catch (err) {
    if (err.message === "unauthorized") {
      $("login-error").hidden = false;
    } else {
      $("login-error").textContent = err.message;
      $("login-error").hidden = false;
    }
  }
});

$("logout-btn").addEventListener("click", logout);

$("severity-filter").addEventListener("change", () => {
  refreshAlerts().catch(() => {});
});

$("scan-btn").addEventListener("click", async () => {
  const btn = $("scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    await api("/api/scan", { method: "POST" });
    await Promise.all([refreshStats(), refreshAlerts()]);
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run scan";
  }
});

$("ioc-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("ioc-error").hidden = true;
  try {
    await api("/api/iocs", {
      method: "POST",
      body: JSON.stringify({
        category: $("ioc-category").value,
        value: $("ioc-value").value.trim(),
      }),
    });
    $("ioc-value").value = "";
    refreshIocs();
  } catch (err) {
    $("ioc-error").textContent = err.message;
    $("ioc-error").hidden = false;
  }
});

/* ---- boot ---- */

if (token) {
  api("/api/auth/verify", { method: "POST" })
    .then(showConsole)
    .catch(() => logout());
}
