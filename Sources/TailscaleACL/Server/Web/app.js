// Tailscale ACL — the read-only web interface.
// Plain JavaScript, no build step. Everything from the server (policy text,
// names, device data) goes into the page as text through h(); nothing is ever
// parsed as HTML. URLs are /s/<tailnet>/<view>?…, so every view can be linked.
"use strict";

const VIEWS = [
  { id: "map", label: "Access Map", icon: "map", group: "See" },
  { id: "builder", label: "Visual Builder", icon: "builder", group: "See" },
  { id: "simulate", label: "Simulator", icon: "play", group: "See" },
  { id: "ssh", label: "SSH", icon: "terminal", group: "See" },
  { id: "routes", label: "Routes", icon: "routes", group: "See" },
  { id: "problems", label: "Problems", icon: "warn", group: "Check" },
  { id: "tests", label: "Tests", icon: "check", group: "Check" },
  { id: "policy", label: "Policy", icon: "doc", group: "Tailnet" },
  { id: "devices", label: "Devices", icon: "device", group: "Tailnet" },
  { id: "review", label: "Review & export", icon: "export", group: "Draft", draftOnly: true },
];

// Stroke icons, 24×24.
const ICONS = {
  map: "M12 5a2 2 0 1 0 0 .01M5 12a2 2 0 1 0 0 .01M19 12a2 2 0 1 0 0 .01M12 19a2 2 0 1 0 0 .01M12 7v10M7 12h10",
  play: "M7 5l12 7-12 7z",
  warn: "M12 4l9 16H3zM12 10v4M12 17v.01",
  doc: "M7 3h7l4 4v14H7zM14 3v4h4M10 12h5M10 16h5",
  device: "M4 5h16v11H4zM9 20h6M12 16v4",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM5 20a7 7 0 0 1 14 0",
  group: "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM3 20a6 6 0 0 1 12 0M16 4.5a3.5 3.5 0 0 1 0 6.5M18 14a6 6 0 0 1 3 6",
  tag: "M3 12V4h8l9 9-8 8zM7.5 7.5v.01",
  host: "M4 4h16v6H4zM4 14h16v6H4zM8 7v.01M8 17v.01",
  set: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18",
  star: "M12 4v16M5 8l14 8M19 8L5 16",
  check: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM8.5 12l2.5 2.5 4.5-5",
  x: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM9 9l6 6M15 9l-6 6",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  arrowR: "M5 12h14M13 6l6 6-6 6",
  arrowL: "M19 12H5M11 6l-6 6 6 6",
  builder: "M6 6a2 2 0 1 0 0 .01M6 18a2 2 0 1 0 0 .01M18 12a2 2 0 1 0 0 .01M8 6c5 0 5 6 8 6M8 18c5 0 5-6 8-6",
  terminal: "M4 5h16v14H4zM8 10l3 2-3 2M13 15h3",
  routes: "M7 21V12a5 5 0 0 1 5-5h5M14 4l3 3-3 3M7 12V3",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  export: "M12 3v12M7 10l5 5 5-5M5 21h14",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
};

// MARK: - Helpers

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

/// replaceChildren with h()'s rules: nested lists flattened, null and false skipped.
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
}

function icon(name, cls) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  if (cls) svg.setAttribute("class", cls);
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", ICONS[name] || ICONS.star);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.8");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  svg.append(path);
  return svg;
}

/// The colour and icon the Mac app gives a policy name.
function entityStyle(name) {
  if (name === "*") return ["c-red", "star"];
  if (name.startsWith("node:")) return ["c-blue", "device"];
  if (name.startsWith("autogroup:")) return ["c-pink", "globe"];
  if (name.startsWith("group:")) return ["c-blue", "group"];
  if (name.startsWith("tag:")) return ["c-purple", "tag"];
  if (name.startsWith("ipset:")) return ["c-orange", "set"];
  if (name.includes("@")) return ["c-green", "user"];
  return ["c-orange", "host"];
}

function chip(name, extraClass) {
  const [cls] = entityStyle(name);
  return h("span", { class: `chip ${extraClass || cls}` }, name);
}

function plural(n, one, many) { return `${n} ${n === 1 ? one : many || one + "s"}`; }

function ago(date) {
  const seconds = (new Date(date) - Date.now()) / 1000;
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of [["day", 86400], ["hour", 3600], ["minute", 60]]) {
    if (Math.abs(seconds) >= size) return fmt.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

class SignedOut extends Error {}

async function api(path, options = {}) {
  const m = path.match(/^\/api\/sources\/([a-z0-9-]+)\/(?!draft)/);
  if (m && (options.method || "GET") === "GET" && inDraft(m[1])) path += (path.includes("?") ? "&" : "?") + "draft=1";
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: { Accept: "application/json", ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });
  if (response.status === 401) {
    location.assign("/login?return=" + encodeURIComponent(location.pathname + location.search));
    throw new SignedOut();
  }
  let body = null;
  if (response.status !== 204) { try { body = await response.json(); } catch { /* not JSON */ } }
  if (!response.ok) {
    const error = new Error((body && body.error && body.error.message) || `The server answered ${response.status}.`);
    error.status = response.status;
    throw error;
  }
  return body;
}

// MARK: - State and routing

const state = { me: null, sources: [], problemCount: {}, failingTests: {}, draft: {} };

/// Draft mode is remembered per tailnet in this browser, and only counts while a draft exists.
function inDraft(source) {
  let on = false;
  try { on = localStorage.getItem(`tsacl-draft:${source}`) === "1"; } catch { /* private window */ }
  return on && Boolean(state.draft[source] && state.draft[source].exists);
}
function setDraftMode(source, on) {
  try { localStorage.setItem(`tsacl-draft:${source}`, on ? "1" : "0"); } catch { /* private window */ }
}
/// Caches and badges are kept apart for the live policy and the draft.
function key(source) { return inDraft(source) ? `${source}:draft` : source; }
/// After the draft changed: forget what was worked out from it.
function draftChanged(source) {
  const k = `${source}:draft`;
  entityCache.delete(k);
  searchIndexes.delete(k);
  delete state.problemCount[k];
  delete state.failingTests[k];
}
let renderToken = 0;

function route() {
  const m = location.pathname.match(/^\/s\/([a-z0-9-]+)\/([a-z]+)\/?$/);
  const params = new URLSearchParams(location.search);
  if (!m) return { source: null, view: null, params };
  return { source: m[1], view: m[2], params };
}

function href(source, view, params) {
  const query = params ? new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== "")).toString() : "";
  return `/s/${encodeURIComponent(source)}/${view}` + (query ? "?" + query : "");
}

function go(url, replace) {
  if (replace) history.replaceState(null, "", url); else history.pushState(null, "", url);
  render();
}

// Same-origin links navigate without reloading.
document.addEventListener("click", (event) => {
  const a = event.target.closest("a[href^='/s/']");
  if (!a || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  go(a.getAttribute("href"));
});
window.addEventListener("popstate", render);

// MARK: - Shell

async function start() {
  try {
    [state.me, { sources: state.sources }] = await Promise.all([api("/api/me"), api("/api/sources")]);
  } catch (error) {
    if (!(error instanceof SignedOut)) showFatal(error);
    return;
  }
  document.getElementById("me").textContent = `${state.me.name} · ${state.me.roles.join(", ")}`;
  document.getElementById("me").title = state.me.login;
  const select = document.getElementById("source");
  select.replaceChildren(...state.sources.map((s) => h("option", { value: s.id }, s.name)));
  select.addEventListener("change", () => go(href(select.value, route().view || "map")));
  document.getElementById("search-button").addEventListener("click", openSearch);
  // ⌘K on a Mac, Ctrl+K elsewhere.
  document.querySelector("#search-button kbd").textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘K" : "Ctrl K";
  document.getElementById("search").addEventListener("click", (event) => { if (event.target.id === "search") event.target.close(); });
  if (state.sources.length < 2) select.closest("label").hidden = true;
  render();
}

function showFatal(error) {
  document.getElementById("main").replaceChildren(
    empty("x", "Couldn't load", error.message, "c-red"));
}

function renderNav(source, view) {
  const nav = document.getElementById("nav");
  const badge = (v) => {
    if (v.id === "problems") {
      const n = state.problemCount[key(source)];
      return n === undefined ? null : n === 0 ? h("span", { class: "badge c-green", title: "No problems" }, "✓")
        : h("span", { class: "badge c-orange" }, n);
    }
    if (v.id === "tests") {
      const t = state.failingTests[key(source)];
      return !t || !t.total ? null : t.failing === 0 ? h("span", { class: "badge c-green", title: `All ${t.total} tests pass` }, "✓")
        : h("span", { class: "badge c-red", title: `${t.failing} of ${t.total} tests fail` }, t.failing);
    }
    return null;
  };
  let group = null;
  nav.replaceChildren(...VIEWS.filter((v) => !v.draftOnly || (state.draft[source] && state.draft[source].exists)).flatMap((v) => {
    const out = [];
    if (v.group !== group) { group = v.group; out.push(h("div", { class: "nav-group" }, group)); }
    out.push(h("a", { href: href(source, v.id), "aria-current": v.id === view ? "page" : null }, icon(v.icon), v.label, badge(v)));
    return out;
  }));
}

async function render() {
  const token = ++renderToken;
  let { source, view, params } = route();
  if (!state.sources.length) {
    document.getElementById("main").replaceChildren(empty("globe", "No tailnets configured", "Add one under sources in the server's config."));
    return;
  }
  if (!state.sources.some((s) => s.id === source) || !VIEWS.some((v) => v.id === view)) {
    go(href(state.sources.some((s) => s.id === source) ? source : state.sources[0].id, "map"), true);
    return;
  }
  document.getElementById("source").value = source;
  if (state.draft[source] === undefined) {
    try { state.draft[source] = await api(`/api/sources/${source}/draft`); } catch (error) {
      if (error instanceof SignedOut) return;
      state.draft[source] = { exists: false };
    }
    if (token !== renderToken) return;
  }
  renderNav(source, view);
  const sourceName = state.sources.find((s) => s.id === source).name;
  document.title = `${VIEWS.find((v) => v.id === view).label} · ${sourceName} · Tailscale ACL`;

  const main = document.getElementById("main");
  const stillCurrent = () => token === renderToken;
  main.setAttribute("aria-busy", "true");
  try {
    const content = await VIEW_RENDERERS[view](source, params, stillCurrent);
    if (!stillCurrent()) return;
    main.replaceChildren(h("div", { class: "view" }, draftBar(source, view), content));
    main.focus({ preventScroll: true });
    afterRender.splice(0).forEach((fn) => fn());
  } catch (error) {
    if (error instanceof SignedOut || !stillCurrent()) return;
    main.replaceChildren(h("div", { class: "view" }, draftBar(source, view), errorState(error, source)));
  } finally {
    if (stillCurrent()) main.removeAttribute("aria-busy");
  }
  // The problem and failing-test counts in the sidebar, once per tailnet.
  if (state.problemCount[key(source)] === undefined) {
    api(`/api/sources/${source}/problems`).then((r) => {
      state.problemCount[key(source)] = r.problems.length;
      if (route().source === source) renderNav(source, route().view);
    }).catch(() => {});
  }
  if (state.failingTests[key(source)] === undefined) {
    api(`/api/sources/${source}/tests`).then((r) => {
      const all = [...r.tests, ...r.sshTests];
      state.failingTests[key(source)] = { total: all.length, failing: all.filter((t) => !t.passed).length };
      if (route().source === source) renderNav(source, route().view);
    }).catch(() => {});
  }
}

/// Work that needs the new content in the page (scrolling, measuring).
const afterRender = [];

function head(title, subtitle, ...actions) {
  actions = actions.filter(Boolean);
  return h("div", { class: "head" },
    h("div", {}, h("h1", {}, title), subtitle ? h("p", {}, subtitle) : null),
    actions.length ? h("div", { class: "actions" }, actions) : null);
}

function empty(iconName, title, message, cls, ...actions) {
  return h("div", { class: `empty ${cls || "c-muted"}` },
    h("div", { class: "icon" }, icon(iconName)),
    h("h2", {}, title),
    h("p", {}, message),
    actions.length ? h("div", {}, actions) : null);
}

function staleBanner(stale) {
  return stale ? h("div", { class: "banner warn" }, icon("clock"),
    h("div", { class: "text" }, "The tailnet's server couldn't be read just now, so this is the last copy that could. ",
      h("span", { class: "muted" }, stale))) : null;
}

function errorState(error, source) {
  if (error.status === 409) {
    return empty("warn", "The policy on the server has a syntax error", "Open the policy to see where.", "c-orange",
      h("a", { href: href(source, "policy") }, "Show the policy"));
  }
  return empty("x", "Couldn't load this", error.message, "c-red");
}

// MARK: - Problems

async function viewProblems(source) {
  const { problems, stale } = await api(`/api/sources/${source}/problems`);
  state.problemCount[key(source)] = problems.length;
  const errors = problems.filter((p) => p.severity === "error").length;
  const security = problems.filter((p) => p.security);
  const other = problems.filter((p) => !p.security);
  const card = (p) => h("div", { class: `card problem ${p.severity}` },
    icon(p.severity === "error" ? "x" : "warn", p.severity === "error" ? "c-red" : "c-orange"),
    h("div", { class: "title" }, p.title, p.line ? h("a", { href: href(source, "policy", { line: p.line }) }, `Line ${p.line}`) : null),
    h("div", { class: "detail" }, p.detail));
  return [
    head("Problems", "Undefined names, unused entities, shadowed, expiring and wide-open rules, and the security review."),
    staleBanner(stale),
    problems.length === 0
      ? empty("check", "No problems found", "The policy structure looks clean, and nothing in the security review stands out.", "c-green")
      : [
        h("div", { class: "chips" },
          errors ? h("span", { class: "chip c-red" }, plural(errors, "error")) : null,
          problems.length > errors ? h("span", { class: "chip c-orange" }, plural(problems.length - errors, "warning")) : null),
        security.length ? [h("h2", {}, "Security review"), h("div", { class: "stack" }, security.map(card))] : null,
        other.length ? [h("h2", {}, "Policy problems"), h("div", { class: "stack" }, other.map(card))] : null,
      ],
  ];
}

// MARK: - Policy

/// HuJSON into lines of [class, text] pieces, for colouring.
function highlight(text) {
  const lines = [[]];
  const push = (cls, s) => {
    const parts = s.split("\n");
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part) lines[lines.length - 1].push([cls, part]);
    });
  };
  const re = /(\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$))|("(?:[^"\\\n]|\\.)*"?)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([^"/\d\-tfn]+|[\s\S])/g;
  let m;
  while ((m = re.exec(text))) {
    if (m[1]) push("tk-comment", m[1]);
    else if (m[2]) {
      const rest = text.slice(re.lastIndex, re.lastIndex + 40);
      push(/^\s*:/.test(rest) ? "tk-key" : "tk-string", m[2]);
    } else if (m[3]) push("tk-number", m[3]);
    else if (m[4]) push("tk-literal", m[4]);
    else push("", m[5]);
  }
  return lines;
}

async function viewPolicy(source, params) {
  // In your draft: the editor.
  if (inDraft(source)) {
    const { editor, status } = policyEditor(source, state.draft[source], Number(params.get("line")) || 0);
    return [
      head("Policy — your draft", "Edits save as you type, and every view checks them while you're in your draft.", status,
        h("a", { class: "button", href: href(source, "review") }, "Review & export")),
      editor,
    ];
  }
  const [policy, problemsReply] = await Promise.all([
    api(`/api/sources/${source}/policy`),
    api(`/api/sources/${source}/problems`).catch(() => ({ problems: [] })),
  ]);
  const marks = new Map();
  for (const p of problemsReply.problems) {
    if (!p.line) continue;
    const prev = marks.get(p.line);
    marks.set(p.line, { error: (prev && prev.error) || p.severity === "error", titles: [...(prev ? prev.titles : []), p.title] });
  }
  if (policy.error) marks.set(policy.error.line, { error: true, titles: [policy.error.message] });
  const wanted = Number(params.get("line")) || (policy.error && policy.error.line) || 0;

  const lines = highlight(policy.text);
  const code = h("div", { class: "code", role: "region", "aria-label": "Policy" }, lines.map((pieces, i) => {
    const n = i + 1;
    const mark = marks.get(n);
    let dot = null;
    if (mark) {
      dot = h("span", { class: "mark", title: mark.titles.join("\n") });
      dot.style.background = mark.error ? "var(--red)" : "var(--orange)";
    }
    return h("div", { class: "ln" + (n === wanted ? " hl" : ""), id: `L${n}` },
      h("span", { class: "num" }, dot, n),
      h("span", { class: "src" }, pieces.map(([cls, s]) => cls ? h("span", { class: cls }, s) : s)));
  }));
  if (wanted) afterRender.push(() => document.getElementById(`L${wanted}`)?.scrollIntoView({ block: "center" }));

  const copy = h("button", {
    onclick: async () => {
      try { await navigator.clipboard.writeText(policy.text); copy.textContent = "Copied"; } catch { copy.textContent = "Couldn't copy"; }
      setTimeout(() => { copy.textContent = "Copy"; }, 1500);
    },
  }, "Copy");
  const download = h("button", {
    onclick: () => {
      const url = URL.createObjectURL(new Blob([policy.text], { type: "application/json" }));
      const a = h("a", { href: url, download: `${source}-policy.hujson` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
  }, "Download");

  const edit = h("button", { type: "button", class: "primary", onclick: async () => {
    try { await startDraft(source); go(href(source, "policy")); } catch (error) { if (!(error instanceof SignedOut)) alert(error.message); }
  } }, state.draft[source] && state.draft[source].exists ? "Open your draft" : "Edit in a draft");
  return [
    head("Policy", `As on the server, read ${ago(policy.fetched)}. To change it, edit a draft, then export it and import it into the tailnet.`, edit, copy, download),
    staleBanner(policy.stale),
    policy.error ? h("div", { class: "banner error" }, icon("x"),
      h("div", { class: "text" }, h("strong", {}, `Line ${policy.error.line}: `), policy.error.message)) : null,
    code,
  ];
}

// MARK: - Entities (for pickers)

const entityCache = new Map();

async function entities(source) {
  const k = key(source);
  if (!entityCache.has(k)) {
    entityCache.set(k, Promise.all([
      api(`/api/sources/${source}/entities`),
      api(`/api/sources/${source}/devices`).catch(() => ({ devices: [] })),
    ]).then(([e, d]) => ({ ...e, devices: d.devices })).catch((error) => { entityCache.delete(k); throw error; }));
  }
  return entityCache.get(k);
}

function deviceLabel(d) { return d.name + (d.user ? ` (${d.user})` : d.tags.length ? ` (${d.tags.join(", ")})` : ""); }

/// Everything a simulator source or destination can be, as datalist options.
/// Devices are offered by name; `fromField` turns the name back into node:<id>.
function datalist(id, e) {
  const options = [
    ...e.devices.map((d) => h("option", { value: d.name }, `device${d.user ? " · " + d.user : d.tags.length ? " · " + d.tags.join(", ") : ""}`)),
    ...e.users.map((u) => h("option", { value: u }, "user")),
    ...e.groups.map((g) => h("option", { value: g.name }, plural(g.detail.length, "member"))),
    ...e.tags.map((t) => h("option", { value: t.name }, "tag")),
    ...e.hosts.map((x) => h("option", { value: x.name }, x.detail.join(", "))),
    ...e.ipsets.map((x) => h("option", { value: x.name }, "IP set")),
    ...e.autogroups.map((a) => h("option", { value: a }, "autogroup")),
    h("option", { value: "*" }, "everyone / everything"),
  ];
  return h("datalist", { id }, options);
}

/// What the simulator sends for what was typed: a policy name as it is, a
/// device's name as node:<id>. Policy names win when both fit.
function fromField(value, e) {
  const v = value.trim();
  const isPolicyName = v.includes(":") || v.includes("@") || v === "*" || /^[\d.:/\[\]a-f]+$/i.test(v)
    || [e.users, e.hosts.map((x) => x.name)].some((list) => list.includes(v));
  if (isPolicyName) return v;
  const device = e.devices.find((d) => d.name.toLowerCase() === v.toLowerCase());
  return device ? `node:${device.id}` : v;
}

function nameOf(value, e) {
  if (value.startsWith("node:")) {
    const d = e.devices.find((x) => `node:${x.id}` === value);
    return d ? d.name : value;
  }
  return value;
}

// MARK: - Simulator

async function viewSimulate(source, params) {
  const e = await entities(source);
  const src = params.get("src") || "";
  const dst = params.get("dst") || "";
  const port = params.get("port") || "443";
  const proto = params.get("proto") || "";

  const srcInput = h("input", { type: "text", name: "src", list: "sim-names", value: nameOf(src, e), placeholder: "a device, user, group, tag…", required: true, autocomplete: "off" });
  const dstInput = h("input", { type: "text", name: "dst", list: "sim-names", value: nameOf(dst, e), placeholder: "a device, tag, host, address…", required: true, autocomplete: "off" });
  const portInput = h("input", { type: "number", name: "port", min: 0, max: 65535, value: port, required: true });
  const protoSelect = h("select", { name: "proto" },
    [["", "TCP or UDP"], ["tcp", "TCP"], ["udp", "UDP"]].map(([v, l]) => h("option", { value: v, selected: v === proto }, l)));
  const form = h("form", {
    class: "sim-form",
    onsubmit: (event) => {
      event.preventDefault();
      go(href(source, "simulate", { src: fromField(srcInput.value, e), dst: fromField(dstInput.value, e), port: portInput.value, proto: protoSelect.value }));
    },
  },
    h("label", {}, "Source", srcInput),
    h("label", {}, "Destination", dstInput),
    h("label", {}, "Port", portInput),
    h("label", {}, "Protocol", protoSelect),
    h("div", { class: "buttons" },
      h("button", { type: "submit", class: "primary" }, "Check"),
      h("button", { type: "button", title: "Swap source and destination", onclick: () => {
        [srcInput.value, dstInput.value] = [dstInput.value, srcInput.value];
      } }, "⇄")),
    datalist("sim-names", e));

  const out = [head("Simulator", "Can a source reach a destination on a port? The same engine as the Mac app."), form];
  if (!src || !dst) {
    out.push(h("p", { class: "muted" }, "Pick a device, user, group, or tag as the source, and what it should reach."));
    return out;
  }
  const result = await api(`/api/sources/${source}/simulate?` + new URLSearchParams({ src, dst, port, proto }));
  const what = `${nameOf(src, e)} → ${nameOf(dst, e)} on ${proto ? proto.toUpperCase() + " " : ""}port ${port}`;
  const kind = !result.allowed ? "denied" : result.conditional ? "conditional" : "allowed";
  out.push(staleBanner(result.stale));
  out.push(h("div", { class: `verdict ${kind}` },
    icon(kind === "denied" ? "x" : kind === "conditional" ? "clock" : "check"),
    h("div", {},
      kind === "denied" ? "Denied" : kind === "conditional" ? "Allowed only from devices that pass a posture check" : "Allowed",
      h("div", { class: "what" }, what))));
  if (!result.allowed) {
    out.push(h("p", { class: "muted rules" }, "No rule allows this: everything not allowed is denied. ",
      h("a", { href: href(source, "map", { focus: src }) }, "See what the source can reach")));
    return out;
  }
  // One rule can match through several of its destinations (a device with two tags): show it once.
  const rules = [];
  for (const r of result.rules) {
    const same = rules.find((x) => x.kind === r.kind && x.index === r.index);
    if (same) { if (!same.dst.split(", ").includes(r.dst)) same.dst += ", " + r.dst; } else rules.push({ ...r });
  }
  out.push(h("h2", {}, plural(rules.length, "matching rule")));
  out.push(h("div", { class: "stack rules" }, rules.map((r) => h("div", { class: "card rule" },
    h("div", { class: "rule-head" },
      h("span", { class: `chip ${r.kind === "grant" ? "c-green" : "c-blue"}` }, r.kind === "grant" ? `Grant #${r.index + 1}` : `ACL #${r.index + 1}`),
      h("span", { class: "mono muted" }, `${r.src} → ${r.dst}${r.ports ? " : " + r.ports : ""}`),
      r.line ? h("a", { href: href(source, "policy", { line: r.line }) }, `Line ${r.line}`) : null),
    r.explanation ? h("div", { class: "sentence" }, r.explanation) : null,
    r.posture.length || r.via.length ? h("div", { class: "chips" },
      r.posture.length ? h("span", { class: "chip c-orange" }, "if " + r.posture.join(" or ")) : null,
      r.via.length ? h("span", { class: "chip c-purple" }, "via " + r.via.join(", ")) : null) : null))));
  return out;
}

// MARK: - Access map

const KINDS = [
  { id: "device", label: "Device", icon: "device" },
  { id: "user", label: "User", icon: "user" },
  { id: "group", label: "Group", icon: "group" },
  { id: "tag", label: "Tag", icon: "tag" },
  { id: "host", label: "Host", icon: "host" },
  { id: "ipset", label: "IP set", icon: "set" },
];

function kindOf(focus, e) {
  if (focus.startsWith("node:")) return "device";
  if (focus.startsWith("group:")) return "group";
  if (focus.startsWith("tag:")) return "tag";
  if (focus.startsWith("ipset:")) return "ipset";
  if (e.hosts.some((x) => x.name === focus)) return "host";
  return "user";
}

function itemsOf(kind, e) {
  switch (kind) {
    case "device": return e.devices.map((d) => [`node:${d.id}`, deviceLabel(d)]);
    case "user": return e.users.map((u) => [u, u]);
    case "group": return e.groups.map((g) => [g.name, g.name]);
    case "tag": return e.tags.map((t) => [t.name, t.name]);
    case "host": return e.hosts.map((x) => [x.name, `${x.name} (${x.detail.join(", ")})`]);
    case "ipset": return e.ipsets.map((x) => [x.name, x.name]);
    default: return [];
  }
}

function node(name, label, subtitle, onclick) {
  const [cls, iconName] = entityStyle(name);
  return h(onclick ? "button" : "div", { class: "node", type: onclick ? "button" : null, onclick, "data-name": name, title: onclick ? `Focus on ${label}` : null },
    h("span", { class: `icon ${cls}` }, icon(iconName)),
    h("span", { class: "body" }, h("div", { class: "label" }, label), subtitle ? h("div", { class: "sub" }, subtitle) : null));
}

async function viewMap(source, params) {
  const e = await entities(source);
  const kinds = KINDS.filter((k) => itemsOf(k.id, e).length);
  let focus = params.get("focus") || "";
  const direction = params.get("direction") === "reachedBy" ? "reachedBy" : "reaches";
  let kind = focus ? kindOf(focus, e) : params.get("kind") || (kinds.some((k) => k.id === "group") ? "group" : kinds[0] && kinds[0].id);
  if (!kinds.some((k) => k.id === kind)) kind = kinds[0] && kinds[0].id;
  const items = kind ? itemsOf(kind, e) : [];
  if (!items.some(([v]) => v === focus)) focus = items.length ? items[0][0] : "";
  const link = (changes) => href(source, "map", { focus, direction, ...changes });

  const controls = h("div", { class: "toolbar" },
    h("div", { class: "pills", role: "group", "aria-label": "Direction" },
      [["reaches", "Reaches", "arrowR"], ["reachedBy", "Reached by", "arrowL"]].map(([id, label]) =>
        h("button", { type: "button", "aria-pressed": String(id === direction), onclick: () => go(link({ direction: id })) }, label))),
    h("div", { class: "pills", role: "group", "aria-label": "Kind" },
      kinds.map((k) => h("button", { type: "button", "aria-pressed": String(k.id === kind), onclick: () => go(href(source, "map", { kind: k.id, direction })) }, k.label))),
    items.length ? h("select", { "aria-label": "Focus", onchange: (event) => go(link({ focus: event.target.value })) },
      items.map(([v, l]) => h("option", { value: v, selected: v === focus }, l))) : null);

  const title = head("Access Map", direction === "reaches"
    ? "Pick a device, user, group, or tag to see every rule that applies to it and what it can reach."
    : "Pick a device, tag, host, or IP set to see everyone who can reach it, and through which rules.",
  focus ? h("a", { href: href(source, "simulate", { src: direction === "reaches" ? focus : "", dst: direction === "reaches" ? "" : focus }) }, "Simulate…") : null);

  if (!focus) return [title, controls, empty("map", "Nothing to map yet", "The policy defines no groups, tags, users, or hosts.")];
  const map = await api(`/api/sources/${source}/map?` + new URLSearchParams({ focus, direction }));
  const focusOn = (name) => () => go(href(source, "map", { focus: name, direction }));

  const out = [title, controls, staleBanner(map.stale)];
  if (map.routes && (map.routes.exitNode || map.routes.subnets.length)) {
    const r = map.routes;
    out.push(h("div", { class: "card routes" },
      h("div", {}, h("strong", {}, "Exit nodes "),
        r.exitNode
          ? [h("span", { class: "c-green" }, r.exitVia.length ? `allowed via ${r.exitVia.join(", ")}` : "allowed"), " ",
            r.exitNodes.length ? r.exitNodes.map((n) => h("span", { class: "chip c-pink" }, n)) : h("span", { class: "muted" }, "no exit node is approved")]
          : h("span", { class: "muted" }, "not allowed")),
      r.subnets.length ? h("div", {}, h("strong", {}, "Subnet routes "),
        r.subnets.map((s) => h("span", { class: "chip c-orange", title: s.routers.length ? `through ${s.routers.join(", ")}` : "no router carries it for this source" }, s.route))) : null));
  }
  if (!map.rules.length) {
    out.push(empty(direction === "reaches" ? "arrowR" : "arrowL",
      direction === "reaches" ? "No rule applies to this" : "No rule reaches this",
      direction === "reaches" ? "Everything not allowed is denied, so this reaches nothing." : "Nothing can reach it: everything not allowed is denied."));
    return out;
  }

  const colour = { acl: "var(--line-acl)", grant: "var(--line-grant)", ssh: "var(--line-ssh)" };
  const focusCol = h("div", { class: "col focus-col", "data-title": "Focus" },
    node(map.focus.name, map.focus.label, map.focus.subtitle));
  const ruleCol = h("div", { class: "col", "data-title": "Rules" }, h("div", { class: "col-title" }, "Rules"),
    map.rules.map((r) => {
      const dot = h("span", { class: "dot" });
      dot.style.background = colour[r.kind];
      return h("div", { class: "rule-card", "data-rule": r.id, title: r.explanation || r.name },
        h("div", { class: "top" }, dot, h("span", { class: "name" }, r.name), h("span", { class: "badge-text" }, r.badge)),
        r.explanation ? h("div", { class: "sentence" }, r.explanation) : null,
        r.notes.length || r.line ? h("div", { class: "chips notes" },
          r.notes.map((n) => h("span", { class: "chip c-orange" }, n)),
          r.line ? h("a", { class: "open", href: href(source, "policy", { line: r.line }) }, `Line ${r.line}`) : null) : null);
    }));
  const farTitle = direction === "reaches" ? "Reaches" : "Reached by";
  const farCol = h("div", { class: "col", "data-title": farTitle }, h("div", { class: "col-title" }, farTitle),
    map.endpoints.map((x) => node(x.name, x.label, x.subtitle, focusOn(x.name))));
  const wires = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  wires.setAttribute("class", "wires");
  wires.setAttribute("aria-hidden", "true");
  const grid = h("div", { class: "map" }, wires, focusCol, ruleCol, farCol);
  out.push(grid);

  // Dashed curves: focus → each rule → each thing it reaches. Redrawn when the layout changes.
  const draw = () => {
    if (!grid.isConnected) return;
    wires.replaceChildren();
    if (getComputedStyle(wires).display === "none") return;
    const base = grid.getBoundingClientRect();
    const anchor = (el, side) => {
      const r = el.getBoundingClientRect();
      return [side === "left" ? r.left - base.left : r.right - base.left, r.top - base.top + r.height / 2];
    };
    const curve = (a, b, stroke) => {
      const dx = Math.max(24, (b[0] - a[0]) / 2);
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", `M${a[0]},${a[1]} C${a[0] + dx},${a[1]} ${b[0] - dx},${b[1]} ${b[0]},${b[1]}`);
      path.setAttribute("stroke", stroke);
      wires.append(path);
    };
    const from = anchor(focusCol.querySelector(".node"), "right");
    const far = new Map([...farCol.querySelectorAll(".node")].map((el) => [el.dataset.name, el]));
    for (const r of map.rules) {
      const card = ruleCol.querySelector(`[data-rule="${CSS.escape(r.id)}"]`);
      curve(from, anchor(card, "left"), colour[r.kind]);
      for (const name of direction === "reaches" ? r.destinations : r.sources) {
        const target = far.get(name);
        if (target) curve(anchor(card, "right"), anchor(target, "left"), colour[r.kind]);
      }
    }
  };
  afterRender.push(() => {
    draw();
    const observer = new ResizeObserver(() => (grid.isConnected ? draw() : observer.disconnect()));
    observer.observe(grid);
  });
  return out;
}

// MARK: - Devices

async function viewDevices(source, params) {
  const { devices, stale } = await api(`/api/sources/${source}/devices`);
  if (!devices.length) {
    return [head("Devices"), staleBanner(stale), empty("device", "No devices", "The tailnet has no devices, or the credential can't list them.")];
  }
  const filter = h("input", { type: "search", class: "filter", placeholder: "Filter by name, user, tag, or address", value: params.get("q") || "", "aria-label": "Filter devices" });
  const rows = devices
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((d) => {
      const dot = h("span", { class: "status-dot" });
      dot.style.background = d.online ? "var(--green)" : "var(--muted)";
      const row = h("tr", {},
        h("td", {}, h("a", { href: href(source, "map", { focus: `node:${d.id}` }), title: "Show on the Access Map" }, d.name)),
        h("td", {}, d.user ? h("span", { class: "mono" }, d.user) : h("span", { class: "muted" }, "—")),
        h("td", {}, h("div", { class: "chips" }, d.tags.map((t) => chip(t)))),
        h("td", { class: "mono" }, d.addresses.join(", ")),
        h("td", {}, dot, d.online ? "online" : d.lastSeen ? `seen ${ago(d.lastSeen)}` : "offline"));
      row.dataset.search = [d.name, d.user, ...d.tags, ...d.addresses].join(" ").toLowerCase();
      return row;
    });
  const count = h("span", { class: "muted" });
  const apply = () => {
    const q = filter.value.trim().toLowerCase();
    let shown = 0;
    for (const row of rows) {
      row.hidden = q && !row.dataset.search.includes(q);
      if (!row.hidden) shown++;
    }
    count.textContent = q ? `${shown} of ${devices.length}` : plural(devices.length, "device");
    history.replaceState(null, "", href(source, "devices", { q }));
  };
  filter.addEventListener("input", apply);
  apply();
  return [
    head("Devices", "Devices on the tailnet. Pick one to see what it can reach."),
    staleBanner(stale),
    h("div", { class: "toolbar" }, filter, count),
    h("table", { class: "devices" },
      h("thead", {}, h("tr", {}, ["Device", "User", "Tags", "Addresses", "Status"].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows)),
  ];
}

// MARK: - SSH

async function viewSSH(source) {
  const { rules } = await api(`/api/sources/${source}/ssh`);
  const out = [head("SSH", "Tailscale SSH rules: who may connect where, and as which users.")];
  if (!rules.length) {
    out.push(empty("terminal", "No SSH rules", "Tailscale SSH is off until a rule allows it."));
    return out;
  }
  out.push(h("div", { class: "stack narrow" }, rules.map((r) => h("div", { class: "card rule" },
    h("div", { class: "rule-head" },
      h("span", { class: `chip ${r.action === "check" ? "c-orange" : "c-green"}`, title: r.action === "check" ? "People sign in again before connecting" : null }, r.action),
      h("span", { class: "name" }, r.name),
      r.line ? h("a", { href: href(source, "policy", { line: r.line }) }, `Line ${r.line}`) : null),
    h("div", { class: "chips flow" }, r.src.map((n) => chip(n)), h("span", { class: "muted" }, "→"), r.dst.map((n) => chip(n))),
    h("div", { class: "chips flow" }, h("span", { class: "muted" }, "as"), r.users.map((u) => h("span", { class: "chip c-pink" }, u)),
      r.expires ? h("span", { class: "chip c-orange" }, `expires ${r.expires}`) : null),
    r.explanation ? h("div", { class: "sentence" }, r.explanation) : null))));
  return out;
}

// MARK: - Tests

async function viewTests(source) {
  const { tests, sshTests } = await api(`/api/sources/${source}/tests`);
  const all = [...tests, ...sshTests];
  const failing = all.filter((t) => !t.passed).length;
  state.failingTests[key(source)] = { total: all.length, failing };
  const out = [head("Tests", all.length ? `${all.length - failing} of ${all.length} passing` : "The policy's tests, run against the policy as it is now.")];
  if (!all.length) {
    out.push(empty("check", "No tests in the policy", "Tests lock in the access you expect. They're written in the policy (\"tests\" and \"sshTests\"); the Mac app can generate them from current access."));
    return out;
  }
  out.push(failing
    ? h("div", { class: "banner error" }, icon("x"), h("div", { class: "text" }, `${plural(failing, "test")} failing.`))
    : h("div", { class: "banner ok" }, icon("check"), h("div", { class: "text" }, `All ${plural(all.length, "test")} pass.`)));
  const card = (t, ssh) => h("div", { class: `card test ${t.passed ? "" : "failed"}` },
    h("div", { class: "rule-head" },
      h("span", { class: `chip ${t.passed ? "c-green" : "c-red"}` }, t.passed ? "Pass" : "Fail"),
      h("span", { class: "name" }, `${ssh ? "SSH test" : "Test"} #${t.index + 1}`),
      chip(t.src),
      t.line ? h("a", { href: href(source, "policy", { line: t.line }) }, `Line ${t.line}`) : null),
    h("div", { class: "stack tight" }, t.assertions.map((a) => h("div", { class: "assertion" },
      icon(a.passed ? "check" : "x", a.passed ? "c-green" : "c-red"),
      h("div", {},
        h("span", { class: `chip ${a.kind === "deny" ? "c-orange" : "c-green"}` },
          ssh ? `${a.kind} ${a.dst} as ${a.login}` : `${a.kind === "accept" ? "allow" : "deny"} ${a.dst}`),
        !a.passed ? h("span", { class: "c-red fail-text" }, ssh ? ` — actually ${a.actual}` : a.kind === "accept" ? " expected to be allowed, but is denied" : " expected to be denied, but is allowed") : null,
        a.why ? h("div", { class: "muted why" }, a.why) : null)))));
  out.push(h("div", { class: "stack narrow" }, tests.map((t) => card(t, false))));
  if (sshTests.length) {
    out.push(h("h2", {}, "SSH tests"));
    out.push(h("div", { class: "stack narrow" }, sshTests.map((t) => card(t, true))));
  }
  return out;
}

// MARK: - Routes

async function viewRoutes(source) {
  const r = await api(`/api/sources/${source}/routes`);
  const panel = (title, detail, ...body) => h("section", { class: "card panel" }, h("h2", {}, title), h("p", { class: "muted" }, detail), body);
  const lineLink = (line) => line ? h("a", { class: "line-link", href: href(source, "policy", { line }) }, `Line ${line}`) : null;
  const STATES = {
    approved: ["c-green", "approved on the server"],
    autoApproved: ["c-orange", "not approved yet, but an auto-approver covers it"],
    manual: ["c-muted", "needs approving by hand"],
  };
  return [
    head("Routes", "Auto-approved subnet routes and exit nodes, routed grants, node attributes, and the routes your devices advertise."),
    h("div", { class: "stack narrow" },
      panel("Auto-approvers", "Routes and exit nodes advertised by these are approved without a manual step.",
        r.routeApprovers.map((a) => h("div", { class: "chips flow" }, h("span", { class: "chip c-orange" }, a.route), h("span", { class: "muted" }, "←"), a.approvers.map((n) => chip(n)))),
        h("div", { class: "chips flow" }, h("span", { class: "chip c-pink" }, "exit node"), h("span", { class: "muted" }, "←"),
          r.exitNodeApprovers.length ? r.exitNodeApprovers.map((n) => chip(n)) : h("span", { class: "muted" }, "no approvers"))),
      r.via.length ? panel("Routed through (via)", "Grants whose traffic must go through the routers or exit nodes carrying these tags.",
        r.via.map((v) => h("div", { class: "stack tight" },
          h("div", { class: "chips flow" }, v.src.map((n) => chip(n)), h("span", { class: "muted" }, "→"), v.dst.map((n) => chip(n)),
            h("span", { class: "muted" }, "via"), v.via.map((n) => chip(n)), lineLink(v.line)),
          h("div", { class: v.routers.length ? "muted small" : "c-orange small" },
            v.routers.length ? "Devices: " + v.routers.join(", ") : `No device carries ${v.via.join(" or ")}, so this traffic has no route.`)))) : null,
      panel("Node attributes", "Attributes (and app capabilities) given to the devices each entry targets.",
        r.nodeAttrs.length ? r.nodeAttrs.map((a) => h("div", { class: "chips flow" }, a.target.map((n) => chip(n)), h("span", { class: "muted" }, "→"),
          a.attr.map((x) => h("span", { class: "chip c-purple" }, x)), a.app ? h("span", { class: "chip c-pink" }, "app") : null, lineLink(a.line)))
          : h("p", { class: "muted" }, "No node attributes.")),
      panel("Devices advertising routes", "Green: approved on the server. Orange: not yet approved, but auto-approvers cover it. Grey: needs approving by hand.",
        r.devices.length ? r.devices.map((d) => h("div", { class: "card inner" },
          h("div", { class: "chips flow" }, h("a", { class: "mono strong", href: href(source, "map", { focus: `node:${d.id}` }) }, d.name), d.tags.map((t) => chip(t)),
            h("span", { class: "muted small" }, `${plural(d.routes.length, "route")} · ${d.routes.filter((x) => x.state === "approved").length} approved`)),
          h("div", { class: "chips flow" }, d.routes.map((x) => h("span", { class: `chip ${STATES[x.state][0]}`, title: STATES[x.state][1] }, x.route)))))
          : h("p", { class: "muted" }, "No device advertises routes."))),
  ];
}

// MARK: - Visual Builder (view only)

async function viewBuilder(source, params) {
  const editing = inDraft(source);
  const [data, ents] = await Promise.all([api(`/api/sources/${source}/connections`), editing ? entities(source) : null]);
  const rules = new Map(data.rules.map((r) => [r.id, r]));
  const kindOf = (c) => rules.get(c.rule).kind;
  const counts = { all: data.connections.length, grants: data.connections.filter((c) => kindOf(c) === "grant").length };
  counts.acls = counts.all - counts.grants;
  const ui = { q: params.get("q") || "", kind: params.get("kind") || "all", focus: params.get("focus") || "", unused: params.get("unused") === "1" };
  const save = () => history.replaceState(null, "", href(source, "builder", { q: ui.q, kind: ui.kind === "all" ? "" : ui.kind, focus: ui.focus, unused: ui.unused ? "1" : "" }));

  const filter = h("input", { type: "search", class: "filter", placeholder: "Show only… (name, group, tag, rule)", value: ui.q, "aria-label": "Filter" });
  const kinds = h("div", { class: "pills", role: "group", "aria-label": "Rule kind" });
  const legend = h("div", { class: "legend muted" });
  const detail = h("div", { class: "rule-detail", hidden: true });
  const canvas = h("div", { class: "map builder" });
  const colour = { acl: "var(--line-acl)", grant: "var(--line-grant)" };

  const paint = () => {
    save();
    kinds.replaceChildren(...[["all", "All"], ["grants", "Grants"], ["acls", "ACLs"]].map(([id, label]) =>
      h("button", { type: "button", "aria-pressed": String(ui.kind === id), onclick: () => { ui.kind = id; paint(); } }, `${label} (${counts[id]})`)));
    const q = ui.q.trim().toLowerCase();
    const [side, focusName] = ui.focus ? [ui.focus.slice(0, 2), ui.focus.slice(2)] : [null, null];
    const visible = data.connections.filter((c) => {
      if (ui.kind !== "all" && kindOf(c) !== (ui.kind === "grants" ? "grant" : "acl")) return false;
      if (side && (side === "S|" ? c.src !== focusName : c.dst !== focusName)) return false;
      return !q || [c.src, c.dst, rules.get(c.rule).name].some((x) => x.toLowerCase().includes(q));
    });
    const narrowed = Boolean(q || side || ui.kind !== "all");
    const used = { src: [...new Set(visible.map((c) => c.src))], dst: [...new Set(visible.map((c) => c.dst))] };
    const unusedSrc = narrowed ? [] : data.sourceOrder.filter((n) => !used.src.includes(n));
    const unusedDst = narrowed ? [] : data.destOrder.filter((n) => !used.dst.includes(n));
    let sources = [...used.src, ...(ui.unused ? unusedSrc : [])];
    let dests = [...used.dst, ...(ui.unused ? unusedDst : [])];
    if (side === "S|" && !sources.includes(focusName)) sources.unshift(focusName);
    if (side === "D|" && !dests.includes(focusName)) dests.unshift(focusName);
    // Like the Mac: sources by the policy position of what they reach, then
    // destinations by where their sources sit — few crossing lines.
    const destPos = new Map(data.destOrder.map((n, i) => [n, i]));
    const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : Infinity);
    const srcWeight = new Map(sources.map((n) => [n, avg(visible.filter((c) => c.src === n).map((c) => destPos.get(c.dst) ?? 0))]));
    sources = sources.map((n, i) => [n, i]).sort((a, b) => srcWeight.get(a[0]) - srcWeight.get(b[0]) || a[1] - b[1]).map(([n]) => n);
    const srcRow = new Map(sources.map((n, i) => [n, i]));
    const dstWeight = new Map(dests.map((n, i) => [n, avg(visible.filter((c) => c.dst === n).map((c) => srcRow.get(c.src)))]));
    dests = dests.map((n, i) => [n, i]).sort((a, b) => (dstWeight.get(a[0]) - dstWeight.get(b[0])) || a[1] - b[1]).map(([n]) => n);

    fill(legend, 
      h("span", { class: "swatch acl" }), " ACL ", h("span", { class: "swatch grant" }), " grant · ",
      plural(visible.length, "connection"), " · click a box to focus on it, a line to see its rule",
      !narrowed && unusedSrc.length + unusedDst.length
        ? [" · ", h("button", { type: "button", class: "link inline", onclick: () => { ui.unused = !ui.unused; paint(); } },
          ui.unused ? "hide unused boxes" : `show ${plural(unusedSrc.length + unusedDst.length, "unused box", "unused boxes")}`)] : null,
      ui.focus ? [" · ", h("button", { type: "button", class: "link inline", onclick: () => { ui.focus = ""; paint(); } }, `clear focus on ${focusName}`)] : null);

    if (!visible.length && !sources.length) {
      canvas.replaceChildren(empty("builder", "No connections match", ui.kind !== "all" && !counts[ui.kind]
        ? `The policy has no ${ui.kind === "grants" ? "grants" : "ACL rules"}.` : "Clear the filter or the focus to see everything."));
      return;
    }
    const box = (name, sideKey) => {
      const [cls, iconName] = entityStyle(name);
      const key = sideKey + name;
      const node = h("button", { type: "button", class: "node" + (ui.focus === key ? " focused" : ""), "data-key": key, "data-name": name,
        title: ui.focus === key ? "Show everything again" : `Show only ${name}'s connections`,
        onclick: () => { ui.focus = ui.focus === key ? "" : key; paint(); } },
        h("span", { class: `icon ${cls}` }, icon(iconName)), h("span", { class: "body" }, h("div", { class: "label" }, name)));
      if (!editing) return node;
      const defined = boxKind(name, ents);
      return h("div", { class: "box" }, node,
        defined ? h("button", { type: "button", class: "box-menu", title: `Change ${name}`, "aria-label": `Change ${name}`,
          onclick: () => boxMenu(source, name, defined, ents) }, "⋯") : null,
        sideKey === "S|" ? h("span", { class: "handle", title: `Drag to a destination to let ${name} reach it`, "data-name": name }) : null);
    };
    const left = h("div", { class: "col", "data-title": "Sources" }, h("div", { class: "col-title" }, "Sources"), sources.map((n) => box(n, "S|")));
    const right = h("div", { class: "col", "data-title": "Destinations" }, h("div", { class: "col-title" }, "Destinations"), dests.map((n) => box(n, "D|")));
    const wires = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    wires.setAttribute("class", "wires");
    canvas.replaceChildren(wires, left, h("div", { class: "gap" }), right);

    const draw = () => {
      if (!canvas.isConnected) return;
      wires.replaceChildren();
      if (getComputedStyle(wires).display === "none") return;
      const base = canvas.getBoundingClientRect();
      const at = (el, edge) => {
        const r = el.getBoundingClientRect();
        return [edge === "right" ? r.right - base.left : r.left - base.left, r.top - base.top + r.height / 2];
      };
      const boxes = { S: new Map([...left.querySelectorAll(".node")].map((el) => [el.dataset.name, el])),
        D: new Map([...right.querySelectorAll(".node")].map((el) => [el.dataset.name, el])) };
      const ns = "http://www.w3.org/2000/svg";
      for (const c of visible) {
        const a = boxes.S.get(c.src), b = boxes.D.get(c.dst);
        if (!a || !b) continue;
        const [x1, y1] = at(a, "right"), [x2, y2] = at(b, "left"), dx = Math.max(30, (x2 - x1) / 2);
        const d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
        const rule = rules.get(c.rule);
        const line = document.createElementNS(ns, "path");
        line.setAttribute("d", d);
        line.setAttribute("stroke", colour[rule.kind]);
        line.setAttribute("class", "line");
        line.dataset.src = c.src;
        line.dataset.dst = c.dst;
        const hit = document.createElementNS(ns, "path");
        hit.setAttribute("d", d);
        hit.setAttribute("class", "hit");
        const tip = document.createElementNS(ns, "title");
        tip.textContent = `${rule.name} · ${c.src} → ${c.dst}${c.ports ? " : " + c.ports : ""}`;
        hit.append(tip);
        hit.addEventListener("click", () => showRule(rule, c));
        hit.addEventListener("mouseenter", () => line.classList.add("hover"));
        hit.addEventListener("mouseleave", () => line.classList.remove("hover"));
        wires.append(line, hit);
      }
    };
    // Hovering a box dims what it doesn't touch.
    for (const el of canvas.querySelectorAll(".node")) {
      el.addEventListener("mouseenter", () => {
        const name = el.dataset.name, src = el.dataset.key.startsWith("S|");
        const touched = new Set();
        wires.querySelectorAll("path.line").forEach((p) => {
          const on = src ? p.dataset.src === name : p.dataset.dst === name;
          p.classList.toggle("dim", !on);
          if (on) { touched.add("S|" + p.dataset.src); touched.add("D|" + p.dataset.dst); }
        });
        canvas.querySelectorAll(".node").forEach((n) => n.classList.toggle("dim", !touched.has(n.dataset.key) && n !== el));
      });
      el.addEventListener("mouseleave", () => canvas.querySelectorAll(".dim").forEach((n) => n.classList.remove("dim")));
    }
    if (editing) {
      for (const handle of left.querySelectorAll(".handle")) {
        handle.addEventListener("pointerdown", (event) => {
          event.preventDefault();
          handle.setPointerCapture(event.pointerId);
          const base = canvas.getBoundingClientRect();
          const start = handle.getBoundingClientRect();
          const [x1, y1] = [start.left + start.width / 2 - base.left, start.top + start.height / 2 - base.top];
          const temp = document.createElementNS("http://www.w3.org/2000/svg", "path");
          temp.setAttribute("class", "line dragging");
          temp.setAttribute("stroke", "var(--line-grant)");
          wires.append(temp);
          const target = (e) => document.elementFromPoint(e.clientX, e.clientY)?.closest("[data-key^='D|']");
          const move = (e) => {
            const [x2, y2] = [e.clientX - base.left, e.clientY - base.top], dx = Math.max(30, (x2 - x1) / 2);
            temp.setAttribute("d", `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`);
            right.querySelectorAll(".drop").forEach((n) => n.classList.remove("drop"));
            target(e)?.classList.add("drop");
          };
          const up = (e) => {
            handle.removeEventListener("pointermove", move);
            temp.remove();
            right.querySelectorAll(".drop").forEach((n) => n.classList.remove("drop"));
            const dst = target(e);
            if (dst) askConnection(source, handle.dataset.name, dst.dataset.name);
          };
          handle.addEventListener("pointermove", move);
          handle.addEventListener("pointerup", up, { once: true });
        });
      }
    }
    requestAnimationFrame(draw);
    if (!canvas.observer) {
      canvas.observer = new ResizeObserver(() => (canvas.isConnected ? canvas.redraw() : canvas.observer.disconnect()));
      canvas.observer.observe(canvas);
    }
    canvas.redraw = draw;
  };

  const showRule = (rule, c) => {
    detail.hidden = false;
    fill(detail, 
      h("div", { class: "rule-head" },
        h("span", { class: `chip ${rule.kind === "grant" ? "c-green" : "c-blue"}` }, rule.kind === "grant" ? "grant" : "ACL"),
        h("span", { class: "name" }, rule.name), h("span", { class: "mono muted" }, rule.badge),
        rule.line ? h("a", { href: href(source, "policy", { line: rule.line }) }, `Line ${rule.line}`) : null,
        h("button", { type: "button", class: "link", "aria-label": "Close", onclick: () => { detail.hidden = true; } }, "✕")),
      rule.explanation ? h("div", { class: "sentence" }, rule.explanation) : null,
      h("div", { class: "muted small" }, `This line: ${c.src} → ${c.dst}${c.ports ? " on " + c.ports : ""}`),
      editing ? h("div", { class: "actions" },
        h("button", { type: "button", onclick: () => askPorts(source, rule, c) }, "Change ports…"),
        h("button", { type: "button", class: "danger", onclick: async () => {
          const others = data.connections.filter((x) => x.rule === c.rule && x.raw === c.raw && x.src !== c.src).map((x) => x.src);
          if (!confirm(`Remove ${c.dst} from this ${rule.kind === "grant" ? "grant" : "rule"}?` +
            (others.length ? ` It also stops ${others.join(", ")} reaching it through this rule.` : ""))) return;
          await draftEdit(source, { op: "disconnect", rule: c.rule, dst: c.raw });
        } }, "Remove")) : null);
  };

  let timer;
  filter.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { ui.q = filter.value; paint(); }, 150); });
  paint();
  return [
    head("Visual Builder", editing
      ? "Your draft: drag from a source's handle to a destination to connect them, use ⋯ to change a box, click a line to change it."
      : "Every rule as lines from sources to destinations. To change them, edit a draft.",
    editing ? h("button", { type: "button", onclick: () => askBox(source) }, "Add box") : null,
    editing ? h("button", { type: "button", onclick: () => askConnection(source, "", "", ents) }, "Add connection") : null,
    editing ? null : h("button", { type: "button", class: "primary", onclick: async () => {
      try { await startDraft(source); render(); } catch (error) { if (!(error instanceof SignedOut)) alert(error.message); }
    } }, state.draft[source] && state.draft[source].exists ? "Open your draft" : "Edit in a draft")),
    h("div", { class: "toolbar" }, filter, kinds),
    legend,
    detail,
    canvas,
  ];
}

// MARK: - Editing the draft (Visual Builder)

/// A small modal form; resolves to the field values, or null on Cancel/Escape.
/// fields: { name, label, value, type: "text" | "select" | "textarea", options: [[value, label]], placeholder, list }
/// `aside`: an extra button on the left (e.g. Delete); choosing it resolves to { aside: true }.
function askForm({ title, text, fields = [], submit = "Save", danger = false, aside = null }) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("form-dialog");
    const inputs = {};
    const rows = fields.map((f) => {
      let input;
      if (f.type === "select") {
        input = h("select", { name: f.name }, f.options.map(([v, l]) => h("option", { value: v, selected: v === f.value }, l)));
      } else if (f.type === "textarea") {
        input = h("textarea", { name: f.name, rows: 5, placeholder: f.placeholder || "", spellcheck: "false" });
        input.value = f.value || "";
      } else {
        input = h("input", { type: "text", name: f.name, value: f.value || "", placeholder: f.placeholder || "", list: f.list || null,
          autocomplete: "off", spellcheck: "false", required: f.required ? true : null });
      }
      inputs[f.name] = input;
      return h("label", {}, f.label, input, f.hint ? h("span", { class: "hint" }, f.hint) : null);
    });
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } if (dialog.open) dialog.close(); };
    const form = h("form", { class: "form-dialog" },
      h("h2", {}, title), text ? h("p", { class: "muted" }, text) : null, rows,
      h("div", { class: "actions" },
        aside ? h("button", { type: "button", class: "danger aside", onclick: () => finish({ aside: true }) }, aside) : null,
        h("button", { type: "button", onclick: () => finish(null) }, "Cancel"),
        h("button", { type: "submit", class: danger ? "danger solid" : "primary" }, submit)));
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      finish(Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value])));
    });
    dialog.addEventListener("close", () => finish(null), { once: true });
    fill(dialog, form);
    dialog.showModal();
    (form.querySelector("input:not([readonly]), select, textarea") || form.querySelector("button[type=submit]")).focus();
  });
}

/// One edit to the draft, then the view again from the saved draft.
async function draftEdit(source, op) {
  try {
    state.draft[source] = await api(`/api/sources/${source}/draft/edit`, { method: "POST", body: op });
    draftChanged(source);
    render();
  } catch (error) {
    if (!(error instanceof SignedOut)) alert(error.message);
  }
}

/// What a box is in the policy, if it's defined there (and so can be changed).
function boxKind(name, e) {
  if (e.groups.some((g) => g.name === name)) return "group";
  if (e.tags.some((t) => t.name === name)) return "tag";
  if (e.hosts.some((x) => x.name === name)) return "host";
  if (e.ipsets.some((x) => x.name === name)) return "ipset";
  return null;
}

const listOf = (text) => text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

async function askBox(source) {
  const v = await askForm({ title: "Add a box", submit: "Add", fields: [
    { name: "kind", label: "Kind", type: "select", value: "group",
      options: [["group", "Group of people"], ["tag", "Tag for devices"], ["host", "Host (a name for an address)"], ["ipset", "IP set"]] },
    { name: "name", label: "Name", placeholder: "e.g. eng, prod, nas", required: true, hint: "group: and tag: are added for you." },
    { name: "address", label: "Address (hosts and IP sets)", placeholder: "e.g. 10.0.0.5 or 192.168.1.0/24" },
  ] });
  if (!v) return;
  // Like the Mac: a new box has no lines yet, so show the unused boxes.
  const url = new URL(location.href);
  url.searchParams.set("unused", "1");
  history.replaceState(null, "", url.pathname + url.search);
  await draftEdit(source, { op: "addBox", kind: v.kind, name: v.name, address: v.address });
}

async function boxMenu(source, name, kind, e) {
  const fields = [{ name: "newName", label: "Name", value: name, required: true }];
  if (kind === "group") fields.push({ name: "values", label: "Members", type: "textarea", value: (e.groups.find((g) => g.name === name).detail || []).join("\n"), hint: "One per line: people, or other groups." });
  if (kind === "tag") fields.push({ name: "values", label: "Owners", type: "textarea", value: (e.tags.find((t) => t.name === name).detail || []).join("\n"), hint: "Who may give devices this tag." });
  if (kind === "host") fields.push({ name: "address", label: "Address", value: (e.hosts.find((x) => x.name === name).detail || [])[0] || "" });
  const v = await askForm({ title: name, fields, submit: "Save", aside: "Delete…" });
  if (!v) return;
  if (v.aside) {
    if (confirm(`Delete ${name}? Rules that only name ${name} are removed too.`)) await draftEdit(source, { op: "deleteBox", name });
    return;
  }
  // One edit at a time, so each lands on the draft the previous one saved.
  if ((kind === "group" || kind === "tag") && v.values !== undefined) {
    const before = ((kind === "group" ? e.groups : e.tags).find((x) => x.name === name).detail || []).join("\n");
    if (listOf(v.values).join("\n") !== listOf(before).join("\n")) await editQuietly(source, { op: "setMembers", name, values: listOf(v.values) });
  }
  if (kind === "host" && v.address && v.address !== (e.hosts.find((x) => x.name === name).detail || [])[0]) {
    await editQuietly(source, { op: "setAddress", name, address: v.address.trim() });
  }
  if (v.newName.trim() && v.newName.trim() !== name) await editQuietly(source, { op: "renameBox", name, newName: v.newName.trim() });
  draftChanged(source);
  render();
}

/// An edit whose view refresh comes later (several in a row).
async function editQuietly(source, op) {
  try { state.draft[source] = await api(`/api/sources/${source}/draft/edit`, { method: "POST", body: op }); }
  catch (error) { if (!(error instanceof SignedOut)) alert(error.message); }
}

const PORT_PRESETS = [["*", "any port"], ["443", "HTTPS"], ["22", "SSH"], ["80,443", "web"], ["3389", "RDP"], ["5432", "PostgreSQL"], ["3306", "MySQL"], ["53", "DNS"]];

function portsList() {
  return h("datalist", { id: "port-presets" }, PORT_PRESETS.map(([v, l]) => h("option", { value: v }, l)));
}

async function askConnection(source, src, dst, e) {
  e = e || await entities(source);
  const names = [...e.groups.map((g) => g.name), ...e.tags.map((t) => t.name), ...e.users, ...e.hosts.map((x) => x.name),
    ...e.ipsets.map((x) => x.name), ...e.autogroups, "*"];
  const list = h("datalist", { id: "connect-names" }, names.map((n) => h("option", { value: n })));
  document.body.append(list, portsList());
  const v = await askForm({
    title: "New connection", submit: "Connect",
    text: "Adds a rule to your draft: the source may reach the destination on these ports.",
    fields: [
      { name: "src", label: "Source", value: src, list: "connect-names", required: true },
      { name: "dst", label: "Destination", value: dst, list: "connect-names", required: true },
      { name: "ports", label: "Ports", value: "*", list: "port-presets", hint: "* for any, or e.g. 443, 22,443, 8000-8100." },
      { name: "proto", label: "Protocol", type: "select", value: "", options: [["", "TCP or UDP"], ["tcp", "TCP"], ["udp", "UDP"]] },
      { name: "as", label: "Write it as", type: "select", value: "grant", options: [["grant", "a grant (recommended)"], ["acl", "a legacy ACL rule"]] },
    ] });
  list.remove();
  document.getElementById("port-presets")?.remove();
  if (v) await draftEdit(source, { op: "connect", src: v.src.trim(), dst: v.dst.trim(), ports: v.ports.trim() || "*", proto: v.proto, asACL: v.as === "acl" });
}

/// A grant's "tcp:22, tcp:443" or an ACL's "22,443" as the form's ports and protocol.
function splitPorts(rule, c) {
  if (rule.kind !== "grant") return { ports: c.ports || "*", proto: "" };
  const entries = c.ports.split(",").map((x) => x.trim()).filter(Boolean);
  const protos = new Set(entries.map((x) => (x.includes(":") ? x.split(":")[0].toLowerCase() : "any")));
  const proto = protos.size === 1 && ["tcp", "udp"].includes([...protos][0]) ? [...protos][0] : "";
  return { ports: entries.map((x) => (x.includes(":") ? x.split(":").slice(1).join(":") : x)).join(","), proto };
}

async function askPorts(source, rule, c) {
  const now = splitPorts(rule, c);
  document.body.append(portsList());
  const v = await askForm({
    title: "Change ports", submit: "Save",
    text: rule.kind === "grant" ? "For every destination of this grant." : `For ${c.dst} in this rule.`,
    fields: [
      { name: "ports", label: "Ports", value: now.ports, list: "port-presets", hint: "* for any, or e.g. 443, 22,443, 8000-8100." },
      { name: "proto", label: "Protocol", type: "select", value: now.proto, options: [["", "TCP or UDP"], ["tcp", "TCP"], ["udp", "UDP"]] },
    ] });
  document.getElementById("port-presets")?.remove();
  if (v) await draftEdit(source, { op: "setPorts", rule: c.rule, dst: c.raw, ports: v.ports.trim() || "*", proto: v.proto });
}

// MARK: - Search (⌘K)

const searchIndexes = new Map();

function looksLikeAddress(q) { return /^[0-9a-f:.]+(\/\d{1,3})?$/i.test(q) && /\d/.test(q) && /[.:]/.test(q); }

async function openSearch() {
  const source = route().source;
  const dialog = document.getElementById("search");
  if (!source || !dialog || dialog.open) return;
  const input = dialog.querySelector("input");
  const list = dialog.querySelector("ul");
  input.value = "";
  list.replaceChildren(h("li", { class: "muted pad" }, "Loading…"));
  dialog.showModal();
  input.focus();
  const k = key(source);
  if (!searchIndexes.has(k)) {
    searchIndexes.set(k, api(`/api/sources/${source}/search-index`).then((r) => r.items).catch((e) => { searchIndexes.delete(k); throw e; }));
  }
  let items;
  try { items = await searchIndexes.get(k); } catch (error) {
    list.replaceChildren(h("li", { class: "c-red pad" }, error.message));
    return;
  }
  let results = [], selected = 0, ipHits = [], ipToken = 0, timer;
  const iconFor = (it) => it.kind === "device" ? "device" : it.kind === "rule" ? "doc" : it.kind === "ip" ? "search" : entityStyle(it.title)[1];
  const colorFor = (it) => it.kind === "entity" ? entityStyle(it.title)[0] : it.kind === "ip" ? "c-orange" : it.kind === "rule" ? "c-green" : "c-blue";
  const pick = (it) => {
    if (!it) return;
    dialog.close();
    if (it.focus) go(href(source, "map", { focus: it.focus }));
    else if (it.line) go(href(source, "policy", { line: it.line }));
  };
  const show = () => {
    const q = input.value.trim().toLowerCase();
    const matches = q ? items.filter((it) => it.title.toLowerCase().includes(q) || it.subtitle.toLowerCase().includes(q)) : items;
    results = [...ipHits, ...matches.filter((m) => !ipHits.some((x) => x.title === m.title))].slice(0, 60);
    selected = Math.min(selected, Math.max(results.length - 1, 0));
    list.replaceChildren(...(results.length ? results.map((it, i) => h("li", {
      role: "option", "aria-selected": String(i === selected), onclick: () => pick(it), onmousemove: () => { if (selected !== i) { selected = i; mark(); } },
    }, h("span", { class: `icon ${colorFor(it)}` }, icon(iconFor(it))),
    h("span", { class: "text" }, h("span", { class: "title" }, it.title), h("span", { class: "sub" }, it.subtitle))))
      : [h("li", { class: "muted pad" }, "No matches.")]));
  };
  const mark = () => {
    list.querySelectorAll("li[role=option]").forEach((li, i) => li.setAttribute("aria-selected", String(i === selected)));
    list.children[selected]?.scrollIntoView({ block: "nearest" });
  };
  input.oninput = () => {
    selected = 0;
    ipHits = [];
    show();
    clearTimeout(timer);
    const q = input.value.trim();
    if (!looksLikeAddress(q)) return;
    const token = ++ipToken;
    timer = setTimeout(async () => {
      try {
        const { hits } = await api(`/api/sources/${source}/ip-lookup?` + new URLSearchParams({ ip: q }));
        if (token !== ipToken) return;
        ipHits = hits.map((x) => ({ kind: "ip", title: x.title, subtitle: x.detail, focus: x.device ? `node:${x.device}` : null, line: x.line }));
        show();
      } catch { /* the plain matches stay */ }
    }, 200);
  };
  input.onkeydown = (event) => {
    if (event.key === "ArrowDown") { selected = Math.min(selected + 1, results.length - 1); mark(); event.preventDefault(); }
    else if (event.key === "ArrowUp") { selected = Math.max(selected - 1, 0); mark(); event.preventDefault(); }
    else if (event.key === "Enter") { pick(results[selected]); event.preventDefault(); }
  };
  show();
}

document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); openSearch(); }
});

// MARK: - Drafts

/// The strip above every view: which policy you're looking at, and the way to the other.
function draftBar(source, view) {
  const d = state.draft[source];
  if (!d || !d.exists) return null;
  if (!inDraft(source)) {
    return h("div", { class: "draft-bar live" }, icon("edit"),
      h("span", {}, "You have a draft of this policy."),
      h("button", { type: "button", class: "link inline", onclick: () => { setDraftMode(source, true); render(); } }, "Open your draft"));
  }
  return [
    h("div", { class: "draft-bar" }, icon("edit"),
      h("span", {}, h("strong", {}, "Your draft"), ` — the live policy is unchanged. ${d.changed ? `Edited ${ago(d.updated)}.` : "No changes yet."}`),
      h("span", { class: "spacer" }),
      view !== "review" ? h("a", { href: href(source, "review") }, "Review & export") : null,
      h("button", { type: "button", class: "link inline", onclick: () => { setDraftMode(source, false); render(); } }, "Back to live")),
    d.liveChanged ? h("div", { class: "banner warn" }, icon("warn"), h("div", { class: "text" },
      "Someone changed the live policy after your draft started. Importing the draft as it is would undo their change — ",
      h("a", { href: href(source, "review") }, "see what changed"), ".")) : null,
  ];
}

/// A link that opens a view on the draft.
function draftLink(source, view, content) {
  return h("a", { href: href(source, view), class: "plain", title: "Show it in your draft",
    onclick: () => setDraftMode(source, true) }, content);
}

async function startDraft(source) {
  state.draft[source] = await api(`/api/sources/${source}/draft`, { method: "POST" });
  setDraftMode(source, true);
  draftChanged(source);
}

/// The policy as an editable text box over its coloured copy, saved as you type.
function policyEditor(source, d, wanted) {
  const gutter = h("div", { class: "gutter", "aria-hidden": "true" });
  const paint = h("pre", { class: "paint", "aria-hidden": "true" });
  const box = h("textarea", { class: "source", spellcheck: "false", autocapitalize: "off", autocomplete: "off", wrap: "off",
    "aria-label": "Policy (your draft)" });
  box.value = d.text;
  const status = h("span", { class: "save-status muted" });
  let errorLine = d.valid ? 0 : (d.error && d.error.line) || 0;

  const repaint = () => {
    const lines = highlight(box.value);
    fill(paint, lines.map((pieces) => h("div", {}, pieces.length ? pieces.map(([cls, t]) => cls ? h("span", { class: cls }, t) : t) : "\u200b")));
    fill(gutter, lines.map((_, i) => h("div", { class: i + 1 === errorLine ? "err" : null }, i + 1)));
    box.style.height = "0px";
    box.style.height = box.scrollHeight + "px";
  };
  const showStatus = () => {
    const now = state.draft[source];
    fill(status, now.valid
      ? h("span", { class: "c-green" }, "Saved")
      : h("span", { class: "c-red" }, `Not valid — line ${now.error.line}: ${now.error.message}`));
  };
  let timer = null, saving = Promise.resolve();
  const save = () => {
    clearTimeout(timer);
    timer = null;
    saving = saving.then(async () => {
      try {
        state.draft[source] = await api(`/api/sources/${source}/draft`, { method: "PUT", body: { text: box.value, since: state.draft[source].updated } });
        errorLine = state.draft[source].valid ? 0 : state.draft[source].error.line;
        draftChanged(source);
        showStatus();
        repaint();
        renderNav(source, "policy");
      } catch (error) {
        if (!(error instanceof SignedOut)) fill(status, h("span", { class: "c-red" }, `Not saved: ${error.message}`));
      }
    });
  };
  box.addEventListener("input", () => {
    fill(status, h("span", { class: "muted" }, "Editing…"));
    requestAnimationFrame(repaint);
    clearTimeout(timer);
    timer = setTimeout(save, 700);
  });
  box.addEventListener("scroll", () => { paint.scrollLeft = box.scrollLeft; });
  box.addEventListener("keydown", (event) => {
    if (event.key === "Tab" && !event.shiftKey && !event.metaKey && !event.ctrlKey) {
      event.preventDefault();
      box.setRangeText("  ", box.selectionStart, box.selectionEnd, "end");
      box.dispatchEvent(new Event("input"));
    }
  });
  // Leaving the page with typing not yet saved: save it now. (Only then:
  // otherwise an old page could write its text over a newer draft.)
  window.addEventListener("pagehide", () => { if (timer !== null && box.isConnected) save(); }, { once: true });
  afterRender.push(() => {
    repaint();
    showStatus();
    if (wanted) {
      const top = box.getBoundingClientRect().top + window.scrollY + (wanted - 1) * parseFloat(getComputedStyle(box).lineHeight);
      window.scrollTo({ top: Math.max(top - window.innerHeight / 3, 0) });
    }
  });
  return { editor: h("div", { class: "editor code" }, gutter, h("div", { class: "layers" }, paint, box)), status };
}

async function viewReview(source) {
  const d = state.draft[source];
  if (!d || !d.exists) return [head("Review & export"), empty("export", "No draft", "Start one from the Policy view.")];
  const r = await api(`/api/sources/${source}/draft/review`);
  const diffView = (diff) => h("div", { class: "code diff" }, diff.map((l) => h("div", { class: `ln ${l.kind}` },
    h("span", { class: "num" }, l.kind === "added" ? "+" : l.kind === "removed" ? "−" : l.kind === "skipped" ? "…" : ""),
    h("span", { class: "src" }, l.kind === "skipped" ? `${l.text} unchanged lines` : l.text))));
  const changed = r.diff.some((l) => l.kind === "added" || l.kind === "removed");
  const out = [head("Review & export", "What importing your draft into the tailnet would change. The server never changes the tailnet itself.")];
  if (!r.valid) {
    out.push(h("div", { class: "banner error" }, icon("x"), h("div", { class: "text" },
      `The draft has a syntax error on line ${r.error.line}: ${r.error.message} `, h("a", { href: href(source, "policy", { line: r.error.line }) }, "Fix it"))));
  }
  if (r.liveDiff.length) {
    out.push(h("div", { class: "banner warn" }, icon("warn"), h("div", { class: "text" },
      h("strong", {}, "The live policy changed after your draft started. "),
      "Importing your draft replaces the whole policy, so these changes would be undone unless you add them to your draft:")));
    out.push(h("details", { class: "narrow" }, h("summary", {}, "Changes made to the live policy since your draft started"), diffView(r.liveDiff)));
  }
  if (!changed) {
    out.push(empty("check", "Your draft is the same as the live policy", "Edit it in the Policy view; every view checks the draft while you're in it.", "c-green"));
    return out;
  }
  // Summary
  const gained = r.access.filter((c) => c.gained.length || c.sshGained.length).length;
  const lost = r.access.filter((c) => c.lost.length || c.sshLost.length).length;
  out.push(h("div", { class: "chips summary" },
    r.devicesCompared ? h("span", { class: "chip c-green" }, `${gained} device pair${gained === 1 ? "" : "s"} gain access`) : null,
    r.devicesCompared ? h("span", { class: `chip ${lost ? "c-red" : "c-muted"}` }, `${lost} lose access`) : null,
    draftLink(source, "problems", h("span", { class: `chip ${r.newProblems.length ? "c-orange" : "c-muted"}` }, `${plural(r.newProblems.length, "new problem")}`)),
    r.fixedProblems ? h("span", { class: "chip c-green" }, `${r.fixedProblems} fixed`) : null,
    r.testsTotal ? draftLink(source, "tests", h("span", { class: `chip ${r.testsFailing ? "c-red" : "c-green"}` },
      r.testsFailing ? `${r.testsFailing} of ${r.testsTotal} tests fail` : `all ${r.testsTotal} tests pass`)) : null));

  const download = h("a", { class: "button primary", href: `/api/sources/${source}/draft/export`, download: "" }, "Download policy file");
  const copy = h("button", { type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(state.draft[source].text); copy.textContent = "Copied"; } catch { copy.textContent = "Couldn't copy"; }
    setTimeout(() => { copy.textContent = "Copy policy"; }, 1500);
  } }, "Copy policy");
  const discard = h("button", { type: "button", class: "danger", onclick: async () => {
    if (!confirm("Discard your draft? Your edits are deleted; the live policy is unchanged.")) return;
    await api(`/api/sources/${source}/draft`, { method: "DELETE" });
    state.draft[source] = { exists: false };
    setDraftMode(source, false);
    draftChanged(source);
    go(href(source, "policy"));
  } }, "Discard draft");
  out.push(h("div", { class: "card export narrow" },
    h("h2", {}, "Import it into your tailnet"),
    h("ol", {},
      h("li", {}, "Download or copy the policy file."),
      h("li", {}, "In the Tailscale admin console, open Access controls, switch to the JSON editor, select everything, and paste it over the old policy."),
      h("li", {}, "Save. Tailscale checks it and its tests before applying it.")),
    h("div", { class: "actions" }, r.valid ? [download, copy] : h("span", { class: "c-red" }, "Fix the syntax error to export."), discard)));

  if (r.access.length) {
    out.push(h("h2", {}, "Who gains or loses access"));
    out.push(h("div", { class: "stack narrow" }, r.access.map((c) => h("div", { class: "card access-change" },
      h("div", { class: "mono" }, `${c.src} → ${c.dst}`),
      h("div", { class: "chips flow" },
        c.gained.map((x) => h("span", { class: "chip c-green" }, `+ ${x}`)), c.sshGained.map((x) => h("span", { class: "chip c-green" }, `+ SSH as ${x}`)),
        c.lost.map((x) => h("span", { class: "chip c-red" }, `− ${x}`)), c.sshLost.map((x) => h("span", { class: "chip c-red" }, `− SSH as ${x}`)))))));
  } else if (r.devicesCompared) {
    out.push(h("p", { class: "muted" }, `No access changes between your ${r.devicesCompared} devices.`));
  }
  if (r.newProblems.length) {
    out.push(h("h2", {}, "New problems"));
    out.push(h("div", { class: "stack narrow" }, r.newProblems.map((p) => h("div", { class: `card problem ${p.severity}` },
      icon(p.severity === "error" ? "x" : "warn", p.severity === "error" ? "c-red" : "c-orange"),
      h("div", { class: "title" }, p.title, p.line ? h("a", { href: href(source, "policy", { line: p.line }) }, `Line ${p.line}`) : null),
      h("div", { class: "detail" }, p.detail)))));
  }
  out.push(h("h2", {}, "Changed lines"));
  out.push(h("p", { class: "muted small" }, "Both policies are laid out the same way before comparing, so only real changes show. Comments are kept; edits made in the Visual Builder lay the whole file out in this style."));
  out.push(diffView(r.diff));
  return out;
}

const VIEW_RENDERERS = {
  map: viewMap, builder: viewBuilder, simulate: viewSimulate, ssh: viewSSH, routes: viewRoutes,
  problems: viewProblems, tests: viewTests, policy: viewPolicy, devices: viewDevices, review: viewReview,
};

start();
