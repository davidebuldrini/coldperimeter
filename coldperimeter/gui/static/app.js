// ColdPerimeter interface. Plain JavaScript, no framework and no build step.
// Everything shown comes from the local API; nothing is loaded from the internet.
"use strict";

const STEPS = ["authorization", "scope", "scan", "checklist", "results"];
const STAGES = ["hosts", "ports", "identity", "exposure"];
const ANSWERS = ["yes", "no", "unknown"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const state = {
  token: new URLSearchParams(location.hash.slice(1)).get("token") || "",
  lang: "en",
  locale: null,
  meta: null,
  view: "authorization",
  reached: 0,        // furthest step index the operator has reached
  jobId: null,
  jobStatus: null,
  answers: {},
  result: null,
  pollTimer: null,
  vpnDir: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child != null) node.append(child);
  }
  return node;
}

function t(key) {
  const value = state.locale && state.locale.ui[key];
  return typeof value === "string" ? value : key;
}

// ---- API ------------------------------------------------------------------

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: { "X-ColdPerimeter-Token": state.token } };
  if (options.body !== undefined) {
    init.method = options.method || "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch (error) {
    throw new Error(t("error_engine"));
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : t("error_engine");
    throw new Error(detail);
  }
  return data;
}

function showError(message) {
  const box = $("error");
  box.textContent = message || "";
  box.hidden = !message;
  if (message) box.scrollIntoView({ block: "nearest" });
}

async function guarded(action) {
  showError("");
  try {
    await action();
  } catch (error) {
    showError(error.message);
  }
}

// ---- navigation -------------------------------------------------------------

function show(view) {
  state.view = view;
  const index = STEPS.indexOf(view);
  if (index > state.reached) state.reached = index;
  for (const section of document.querySelectorAll("section[data-view]")) {
    section.hidden = section.dataset.view !== view;
  }
  renderSteps();
  showError("");
  $("main").focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function renderSteps() {
  const list = $("steps");
  list.replaceChildren();
  const current = STEPS.indexOf(state.view === "vpn" ? "results" : state.view);
  STEPS.forEach((step, index) => {
    const item = el("li", { text: state.locale.ui.steps[step] });
    if (index === current) {
      item.className = "current";
      item.setAttribute("aria-current", "step");
    } else if (index < current) {
      item.className = "done";
    }
    list.append(item);
  });
  // The perimeter in the mark closes as the audit advances.
  const closed = state.result ? 100 : (current / (STEPS.length - 1)) * 100;
  $("mark-line").style.strokeDasharray = `${closed} 100`;
}

// ---- language -----------------------------------------------------------------

async function setLanguage(lang) {
  state.locale = await api(`/api/locale/${lang}`);
  state.lang = lang;
  document.documentElement.lang = lang;
  try { localStorage.setItem("coldperimeter.lang", lang); } catch (error) { /* optional */ }
  for (const node of document.querySelectorAll("[data-t]")) {
    const value = state.locale.ui[node.dataset.t];
    if (typeof value === "string") node.textContent = value;
  }
  $("network_hint").textContent = state.meta.network ? t("network_hint") : t("network_missing");
  const sends = $("sends");
  sends.replaceChildren(...state.locale.ui.sends.map((text) => el("li", { text })));
  updateEndpointLabel();
  renderSteps();
  renderChecklist();
  renderStages(state.lastSnapshot);
  if (state.jobId && state.jobStatus === "done") await loadResult();
}

// ---- step 1: authorization ------------------------------------------------------

function markInvalid(input, invalid) {
  if (invalid) input.setAttribute("aria-invalid", "true");
  else input.removeAttribute("aria-invalid");
  return invalid;
}

function submitAuthorization(event) {
  event.preventDefault();
  let firstBad = null;
  for (const id of ["site", "authorized_by", "operator"]) {
    if (markInvalid($(id), !$(id).value.trim()) && !firstBad) firstBad = $(id);
  }
  if (!$("confirmed").checked && !firstBad) firstBad = $("confirmed");
  if (firstBad) {
    firstBad.focus();
    return;
  }
  show("scope");
}

function openSavedScan(event) {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  guarded(async () => {
    let data;
    try {
      data = JSON.parse(await file.text());
    } catch (error) {
      throw new Error(t("error_file"));
    }
    const { id } = await api("/api/scans/import", { body: data });
    state.jobId = id;
    state.jobStatus = "done";
    state.reached = STEPS.length - 1;
    await loadResult();
    show("results");
  });
}

// ---- step 2: scope ----------------------------------------------------------------

function startScan(event) {
  event.preventDefault();
  guarded(async () => {
    const targets = $("targets").value.trim().split(/[\s,]+/).filter(Boolean);
    const body = {
      site_name: $("site").value.trim(),
      authorized_by: $("authorized_by").value.trim(),
      operator: $("operator").value.trim(),
      confirmed: $("confirmed").checked,
      network: $("network").value.trim() || null,
      targets,
      offline: $("offline").checked,
      probe_url: $("probe_url").value.trim() || null,
      xml_probe: $("xml_probe").checked,
      ports: $("ports").value.trim() || null,
      igd_url: $("igd_url").value.trim() || null,
    };
    const { id } = await api("/api/scans", { body });
    state.jobId = id;
    state.jobStatus = "running";
    state.result = null;
    state.answers = {};
    renderChecklist();
    $("scan-note").textContent = "";
    $("stop").disabled = false;
    show("scan");
    poll();
  });
}

// ---- step 3: scan -------------------------------------------------------------------

function renderStages(snapshot) {
  const list = $("stages");
  list.replaceChildren();
  for (const stage of STAGES) {
    const entry = (snapshot && snapshot.stages[stage]) || { status: "pending", done: 0, total: 0 };
    let label = t(`status_${entry.status}`);
    if (entry.status === "running" && entry.total > 1) label = `${entry.done} / ${entry.total}`;
    const percent = entry.status === "done" ? 100 : entry.total ? (entry.done / entry.total) * 100 : 0;
    const fill = el("span");
    fill.style.width = `${percent}%`;
    list.append(
      el("li", { class: entry.status },
        el("span", { class: "name", text: t(`stage_${stage}`) }),
        el("span", { class: "state", text: label }),
        el("div", { class: "bar" }, fill)),
    );
  }
}

async function poll() {
  clearTimeout(state.pollTimer);
  if (!state.jobId) return;
  let snapshot;
  try {
    snapshot = await api(`/api/scans/${state.jobId}`);
  } catch (error) {
    showError(error.message);
    return;
  }
  state.lastSnapshot = snapshot;
  state.jobStatus = snapshot.status;
  renderStages(snapshot);
  if (snapshot.status === "running") {
    state.pollTimer = setTimeout(poll, 700);
    return;
  }
  $("stop").disabled = true;
  if (snapshot.status === "done") {
    await guarded(loadResult);
    $("checklist-note").textContent = "";
    if (state.view === "scan") show("checklist");
    else if (state.wantResults) show("results");
  } else if (snapshot.status === "cancelled") {
    $("scan-note").textContent = t("stopped");
    if (state.view !== "scan") show("scan");
  } else {
    if (state.view !== "scan") show("scan");
    showError(`${t("failed")}: ${snapshot.error || ""}`);
  }
}

function stopScan() {
  guarded(async () => {
    $("stop").disabled = true;
    await api(`/api/scans/${state.jobId}/cancel`, { method: "POST" });
  });
}

// ---- step 4: checklist ------------------------------------------------------------------

function renderChecklist() {
  const form = $("checklist-form");
  if (!state.locale || !state.meta) return;
  form.replaceChildren();
  for (const question of state.meta.questions) {
    const current = state.answers[question] || "unknown";
    const choices = el("div", { class: "segmented" });
    for (const answer of ANSWERS) {
      const input = el("input", { type: "radio", name: question, value: answer });
      input.checked = answer === current;
      choices.append(el("label", {}, input, state.locale.labels[answer]));
    }
    form.append(
      el("fieldset", { class: "question" },
        el("legend", { text: state.locale.checklist[question] }), choices),
    );
  }
}

async function saveAnswers() {
  const data = new FormData($("checklist-form"));
  state.answers = Object.fromEntries(data.entries());
  await api(`/api/scans/${state.jobId}/checklist`, { body: { answers: state.answers } });
}

function seeResults() {
  guarded(async () => {
    await saveAnswers();
    if (state.jobStatus === "done") {
      await loadResult();
      show("results");
    } else if (state.jobStatus === "running") {
      state.wantResults = true;
      $("checklist-note").textContent = t("waiting_scan");
    } else {
      show("scan");
    }
  });
}

// ---- step 5: results ----------------------------------------------------------------------

async function loadResult() {
  state.result = await api(`/api/scans/${state.jobId}/result?lang=${state.lang}`);
  state.answers = { ...state.result.checklist };
  renderResults();
  renderSteps();
}

function severityBadge(severity, label) {
  return el("span", { class: `sev ${severity}`, text: label });
}

function renderResults() {
  const result = state.result;
  const labels = state.locale.labels;
  $("results-site").textContent = `${result.consent.site_name}, ${result.scope}`;
  $("saved-note").textContent = "";

  const summary = $("summary");
  summary.replaceChildren();
  const rows = [
    [labels.controllers_found, String(result.controllers.length)],
    [labels.hosts_seen, String(result.hosts_seen)],
    [labels.public_ip, result.public_ip || labels.unknown],
    [labels.external_check, result.external_checked ? labels.yes : labels.no],
  ];
  for (const [term, value] of rows) {
    summary.append(el("div", {}, el("dt", { text: term }), el("dd", { text: value })));
  }

  const body = $("results-body");
  body.replaceChildren();

  const counts = el("div", { class: "counts" });
  for (const severity of SEVERITIES) {
    const count = result.counts[severity];
    if (count) counts.append(severityBadge(severity, `${state.locale.severity[severity]}: ${count}`));
  }
  body.append(counts);

  body.append(el("h2", { text: labels.devices }));
  if (result.controllers.length) {
    const table = el("table", {},
      el("thead", {}, el("tr", {},
        el("th", { text: labels.address }), el("th", { text: labels.identified_as }),
        el("th", { text: labels.firmware }), el("th", { text: labels.confidence }),
        el("th", { text: labels.open_ports }))));
    const tbody = el("tbody");
    for (const device of result.controllers) {
      tbody.append(el("tr", {},
        el("td", { class: "mono", text: device.ip }),
        el("td", { text: device.name }),
        el("td", { text: device.firmware || labels.unknown }),
        el("td", { text: device.confidence }),
        el("td", { class: "mono", text: device.ports.map((p) => `${p.port} ${p.role}`).join(", ") })));
    }
    table.append(tbody);
    body.append(el("div", { class: "table-wrap" }, table));
  } else {
    body.append(el("p", { class: "hint", text: t("none_found") }));
  }

  body.append(el("h2", { text: labels.findings }));
  for (const finding of result.findings) {
    const head = el("div", { class: "finding-head" },
      severityBadge(finding.severity, finding.severity_label),
      el("h3", { text: finding.title }),
      finding.host ? el("span", { class: "host", text: finding.host }) : null);
    const card = el("article", { class: `finding ${finding.severity}` }, head, el("p", { text: finding.detail }));
    if (finding.evidence.length) {
      card.append(el("ul", {}, ...finding.evidence.map((text) => el("li", { text }))));
    }
    body.append(card);
  }

  body.append(el("h2", { text: labels.plan }));
  const plan = el("ol", { class: "plan" });
  for (const step of result.plan) {
    const tasks = el("ul");
    for (const text of step.always) tasks.append(el("li", { text }));
    for (const item of step.items) {
      tasks.append(el("li", { class: "task" },
        severityBadge(item.severity, item.severity_label), " ", item.action,
        item.host ? el("span", { class: "host", text: ` ${item.host}` }) : null));
    }
    const entry = el("li", {}, el("h3", { text: step.title }), el("p", { text: step.intro }), tasks);
    if (step.number === 2) {
      const button = el("button", { type: "button", class: "primary", text: t("setup_vpn") });
      button.addEventListener("click", openVpn);
      entry.append(el("div", { class: "actions" }, button));
    }
    plan.append(entry);
  }
  body.append(plan);

  body.append(el("h2", { text: labels.limits }));
  body.append(el("ul", { class: "hint" }, ...state.locale.limits.map((text) => el("li", { text }))));
}

function openExport(what) {
  guarded(async () => {
    const { dir } = await api(`/api/scans/${state.jobId}/open`, { body: { lang: state.lang, what } });
    $("saved-note").textContent = t("saved_to").replace("{dir}", dir);
  });
}

function newScan() {
  clearTimeout(state.pollTimer);
  Object.assign(state, { jobId: null, jobStatus: null, result: null, answers: {}, reached: 0, wantResults: false, lastSnapshot: null });
  $("confirmed").checked = false;
  renderStages(null);
  show("authorization");
}

// ---- VPN assistant ------------------------------------------------------------------------------

function updateEndpointLabel() {
  const topology = new FormData($("vpn-form")).get("topology");
  $("vpn_endpoint_label").textContent = t(topology === "hub" ? "vpn_endpoint_hub" : "vpn_endpoint_direct");
}

function openVpn() {
  const device = state.result && state.result.controllers[0];
  if (device && !$("vpn_controller").value) {
    $("vpn_controller").value = device.ip;
    const web = device.ports.filter((p) => p.role === "http" || p.role === "https").map((p) => p.port);
    if (web.length) $("vpn_ports").value = web.join(",");
  }
  $("vpn-output").hidden = true;
  show("vpn");
}

function generateVpn(event) {
  event.preventDefault();
  guarded(async () => {
    const form = new FormData($("vpn-form"));
    const body = {
      site_name: state.result ? state.result.consent.site_name : "site",
      lang: state.lang,
      topology: form.get("topology"),
      endpoint_host: $("vpn_endpoint").value.trim(),
      endpoint_port: Number($("vpn_port").value) || 51820,
      controller_ips: $("vpn_controller").value.trim().split(/[\s,]+/).filter(Boolean),
      controller_ports: $("vpn_ports").value.split(",").map((p) => Number(p.trim())).filter(Boolean),
      store_device: form.get("store_device"),
      store_number: Number($("vpn_store_number").value) || 1,
      server_public_key: $("vpn_existing_key").value.trim() || null,
    };
    if (markInvalid($("vpn_endpoint"), !body.endpoint_host)) { $("vpn_endpoint").focus(); return; }
    if (markInvalid($("vpn_controller"), !body.controller_ips.length)) { $("vpn_controller").focus(); return; }
    const plan = await api("/api/vpn/generate", { body });
    state.vpnDir = plan.dir;
    $("vpn-dir").textContent = plan.dir;
    $("vpn-files").replaceChildren(...plan.files.map((file) => el("li", { text: file.name })));
    $("vpn-instructions").textContent = plan.instructions;
    if (plan.access.length) {
      $("verify_address").value = plan.access[0].address;
      $("verify_port").value = plan.access[0].port;
    }
    $("verify-result").textContent = "";
    $("vpn-output").hidden = false;
    $("vpn-output").scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

function verifyVpn(event) {
  event.preventDefault();
  guarded(async () => {
    const verdict = $("verify-result");
    verdict.className = "verdict";
    verdict.textContent = "";
    const result = await api("/api/vpn/verify", {
      body: { address: $("verify_address").value.trim(), port: Number($("verify_port").value) || 80 },
    });
    verdict.classList.add(result.reachable ? "ok" : "bad");
    verdict.textContent = result.reachable
      ? `${t("vpn_reachable")}${result.title ? ` (${result.title})` : ""}`
      : t("vpn_unreachable");
  });
}

// ---- start --------------------------------------------------------------------------------------

async function init() {
  state.meta = await api("/api/meta");
  $("version").textContent = state.meta.version;
  $("network").value = state.meta.network || "";

  const select = $("lang");
  for (const lang of state.meta.languages) select.append(el("option", { value: lang, text: lang.toUpperCase() }));
  let preferred = null;
  try { preferred = localStorage.getItem("coldperimeter.lang"); } catch (error) { /* optional */ }
  preferred = preferred || (navigator.language || "en").slice(0, 2);
  const lang = state.meta.languages.includes(preferred) ? preferred : "en";
  select.value = lang;
  await setLanguage(lang);

  select.addEventListener("change", () => guarded(() => setLanguage(select.value)));
  $("auth-form").addEventListener("submit", submitAuthorization);
  $("open-saved").addEventListener("click", () => $("saved-file").click());
  $("saved-file").addEventListener("change", openSavedScan);
  $("scope-form").addEventListener("submit", startScan);
  $("stop").addEventListener("click", stopScan);
  $("see-results").addEventListener("click", seeResults);
  $("open-report").addEventListener("click", () => openExport("report"));
  $("open-folder").addEventListener("click", () => openExport("folder"));
  $("new-scan").addEventListener("click", newScan);
  $("vpn-form").addEventListener("submit", generateVpn);
  $("vpn-form").addEventListener("change", updateEndpointLabel);
  $("verify-form").addEventListener("submit", verifyVpn);
  $("vpn-open").addEventListener("click", () =>
    guarded(() => api("/api/vpn/open", { body: { dir: state.vpnDir } })));
  for (const button of document.querySelectorAll("[data-go]")) {
    button.addEventListener("click", () => show(button.dataset.go));
  }
  show("authorization");
}

init().catch((error) => {
  document.querySelector("section[data-view='authorization']").hidden = false;
  showError(error.message);
});
