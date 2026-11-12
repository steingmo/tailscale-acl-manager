// Tailscale ACL — the read-only web interface.
// Plain JavaScript, no build step. Everything from the server (policy text,
// names, device data) goes into the page as text through h(); nothing is ever
// parsed as HTML. URLs are /s/<tailnet>/<view>?…, so every view can be linked.
"use strict";

const VIEWS = [
  { id: "map", label: "Access Map", icon: "map" },
  { id: "simulate", label: "Simulator", icon: "play" },
  { id: "problems", label: "Problems", icon: "warn" },
  { id: "policy", label: "Policy", icon: "doc" },
  { id: "devices", label: "Devices", icon: "device" },
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

async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" }, credentials: "same-origin" });
  if (response.status === 401) {
    location.assign("/login?return=" + encodeURIComponent(location.pathname + location.search));
    throw new SignedOut();
  }
  let body = null;
  try { body = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    const error = new Error((body && body.error && body.error.message) || `The server answered ${response.status}.`);
    error.status = response.status;
    throw error;
  }
  return body;
}

// MARK: - State and routing

const state = { me: null, sources: [], problemCount: {} };
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
  if (state.sources.length < 2) select.closest("label").hidden = true;
  render();
}

function showFatal(error) {
  document.getElementById("main").replaceChildren(
    empty("x", "Couldn't load", error.message, "c-red"));
}

function renderNav(source, view) {
  const nav = document.getElementById("nav");
  nav.replaceChildren(...VIEWS.map((v) => {
    const count = v.id === "problems" ? state.problemCount[source] : undefined;
    return h("a", { href: href(source, v.id), "aria-current": v.id === view ? "page" : null },
      icon(v.icon), v.label,
      count === undefined ? null
        : count === 0 ? h("span", { class: "badge c-green", title: "No problems" }, "✓")
        : h("span", { class: "badge c-orange" }, count));
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
  renderNav(source, view);
  const sourceName = state.sources.find((s) => s.id === source).name;
  document.title = `${VIEWS.find((v) => v.id === view).label} · ${sourceName} · Tailscale ACL`;

  const main = document.getElementById("main");
  const stillCurrent = () => token === renderToken;
  main.setAttribute("aria-busy", "true");
  try {
    const content = await VIEW_RENDERERS[view](source, params, stillCurrent);
    if (!stillCurrent()) return;
    main.replaceChildren(h("div", { class: "view" }, content));
    main.focus({ preventScroll: true });
    afterRender.splice(0).forEach((fn) => fn());
  } catch (error) {
    if (error instanceof SignedOut || !stillCurrent()) return;
    main.replaceChildren(errorState(error, source));
  } finally {
    if (stillCurrent()) main.removeAttribute("aria-busy");
  }
  // The problem count in the sidebar, once per tailnet.
  if (state.problemCount[source] === undefined) {
    api(`/api/sources/${source}/problems`).then((r) => {
      state.problemCount[source] = r.problems.length;
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
  state.problemCount[source] = problems.length;
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

  return [
    head("Policy", `As on the server, read ${ago(policy.fetched)}. Read-only — changes are made in the Mac app.`, copy, download),
    staleBanner(policy.stale),
    policy.error ? h("div", { class: "banner error" }, icon("x"),
      h("div", { class: "text" }, h("strong", {}, `Line ${policy.error.line}: `), policy.error.message)) : null,
    code,
  ];
}

// MARK: - Entities (for pickers)

const entityCache = new Map();

async function entities(source) {
  if (!entityCache.has(source)) {
    entityCache.set(source, Promise.all([
      api(`/api/sources/${source}/entities`),
      api(`/api/sources/${source}/devices`).catch(() => ({ devices: [] })),
    ]).then(([e, d]) => ({ ...e, devices: d.devices })).catch((error) => { entityCache.delete(source); throw error; }));
  }
  return entityCache.get(source);
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

const VIEW_RENDERERS = { map: viewMap, simulate: viewSimulate, problems: viewProblems, policy: viewPolicy, devices: viewDevices };

start();
