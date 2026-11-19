// Small helpers shared by the views: element building (text only, never HTML strings from data), number
// formatting, the hash route and its query, and the hover tooltip.

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "style") el.setAttribute("style", v);
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) append(el, k);
    else el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

const NF = new Intl.NumberFormat("en-US");
export const fmt = (n) => (n === null || n === undefined ? "—" : NF.format(n));
export function compact(n) {
  if (n === null || n === undefined) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(2).replace(/\.?0+$/, "") + " bn";
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + " M";
  if (n >= 1e4) return Math.round(n / 1e3) + " k";
  return NF.format(n);
}
export const capLabel = (g) => (g.startsWith("cap-") ? "CAP-" + g.slice(4) : g);
export const capRow = (n) => "cap-" + String(n).padStart(4, "0");
export const short = (s, n = 10) => (s && /^[0-9a-f]{20,}$/.test(s) ? s.slice(0, n) : s);

// Route: #/<view>/<rest>?<query>
export function route() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, qs] = raw.split("?");
  const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  return { view: parts[0] || "overview", rest: parts.slice(1).join("/"), q: new URLSearchParams(qs || "") };
}
export function href(view, rest, query) {
  let s = "#/" + view + (rest ? "/" + rest.split("/").map(encodeURIComponent).join("/") : "");
  if (query) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== "" && v !== null && v !== undefined && v !== false) p.set(k, v);
    const t = p.toString();
    if (t) s += "?" + t;
  }
  return s;
}
// Change the query of the current route without adding a history entry or re-rendering the view.
export function setQuery(query) {
  const r = route();
  const next = href(r.view, r.rest, query);
  if (next !== location.hash) history.replaceState(null, "", next);
}

export function table(head, rows, opts = {}) {
  return h("div", { class: "tbl-wrap" },
    h("table", opts.label ? { "aria-label": opts.label } : null,
      h("thead", null, h("tr", null, head.map((c) => (typeof c === "string"
        ? h("th", { scope: "col" }, c) : h("th", { scope: "col", class: c.cls }, c.t))))),
      h("tbody", null, rows.length ? rows : h("tr", null, h("td", { class: "empty", colspan: String(head.length) }, opts.empty || "Nothing matches these filters.")))));
}

export function select(label, name, options, value, onchange) {
  return h("label", null, label,
    h("select", { name, onchange: (e) => onchange(e.target.value) },
      options.map(([v, t]) => h("option", { value: v, selected: v === value }, t))));
}
export function search(label, value, oninput) {
  return h("label", null, label, h("input", { type: "search", value: value || "", placeholder: "filter…",
    oninput: (e) => oninput(e.target.value.trim()) }));
}
export function checkbox(label, checked, onchange) {
  return h("label", { class: "check" }, h("input", { type: "checkbox", checked, onchange: (e) => onchange(e.target.checked) }), label);
}

export const sevChip = (s) => h("span", { class: "chip sev-" + s }, s);
const STATE_TEXT = { filed: "filed by this kit", "duplicate-of": "known upstream", "not-a-defect": "not a defect" };
export const stateChip = (s) => h("span", { class: "chip st-" + s }, STATE_TEXT[s] || s);

export function notice(strong, text) {
  return h("p", { class: "notice" }, strong ? h("strong", null, strong + " ") : null, text);
}

// One tooltip element for the whole page; marks set data-tip.
export function initTips() {
  const tip = document.getElementById("tip");
  const show = (el, x, y) => {
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    const r = tip.getBoundingClientRect();
    tip.style.left = Math.max(8, Math.min(window.innerWidth - r.width - 8, x + 12)) + "px";
    tip.style.top = Math.max(8, y - r.height - 12) + "px";
  };
  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) show(el, e.clientX, e.clientY); else tip.hidden = true;
  });
  document.addEventListener("pointermove", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el && !tip.hidden) show(el, e.clientX, e.clientY);
  });
  document.addEventListener("focusin", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) { const r = el.getBoundingClientRect(); show(el, r.left, r.top); } else tip.hidden = true;
  });
  document.addEventListener("focusout", () => { tip.hidden = true; });
  window.addEventListener("scroll", () => { tip.hidden = true; }, { passive: true });
}

// Append children to a live element, skipping null, undefined and false (Node.append would print them).
export function put(el, ...kids) {
  for (const k of kids.flat(Infinity)) if (k !== null && k !== undefined && k !== false) el.append(k);
  return el;
}
