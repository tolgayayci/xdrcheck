// Dashboard entry point: loads the data files once, then renders the view the URL hash names.
import { h, route, initTips } from "./lib.js";

// Each view is its own module, loaded the first time it is shown.
const VIEWS = { overview: "overview", timeline: "timeline", caps: "caps", cap: "caps", entry: "caps",
  problems: "problems", sdk: "sdk", replay: "replay", siblings: "siblings", rarity: "rarity" };
const loaded = new Map();
async function viewModule(name) {
  if (!loaded.has(name)) loaded.set(name, import("./views/" + name + ".js").then((m) => m.default));
  return loaded.get(name);
}
const TAB_OF = { cap: "caps", entry: "caps" };
// The data files each view reads. Only these are fetched before the view draws; the large ones (the SDK matrix, the
// replay grid, the sibling matrix) only by the view that shows them.
const NEEDS = {
  overview: ["summary", "scan"], timeline: ["summary", "scan", "corpus"], caps: ["summary", "scan", "corpus", "findings"],
  problems: ["summary", "corpus", "findings"], sdk: ["summary", "corpus", "matrix"],
  replay: ["summary", "corpus", "findings", "replay"],
  rarity: ["summary", "scan", "corpus", "findings"], siblings: ["summary", "corpus", "findings", "siblings"],
};
const files = new Map();
const data = {};
function fetchFile(f) {
  if (!files.has(f)) {
    files.set(f, fetch("data/" + f + ".json").then((r) => {
      if (!r.ok) throw new Error("data/" + f + ".json: HTTP " + r.status);
      return r.json();
    }).then((j) => { data[f] = j; index(f); }).catch((e) => { files.delete(f); throw e; }));
  }
  return files.get(f);
}
function index(f) {
  const d = data;
  if (f === "corpus") {
    d.entryById = new Map(d.corpus.entries.map((e) => [e.id, e]));
    d.rowByGroup = new Map(d.corpus.rows.map((r) => [r.group, r]));
  } else if (f === "findings") {
    d.findingById = new Map(d.findings.findings.map((x) => [x.id, x]));
    d.ruleById = new Map(d.findings.lint_rules.map((r) => [r.id, r]));
  } else if (f === "scan") {
    d.bandByProtocol = new Map(d.scan.protocol_bands.map((b) => [b.protocol, b]));
  }
}
const load = (names) => Promise.all(names.map(fetchFile)).then(() => data);

function theme() {
  const btn = document.getElementById("theme");
  const root = document.documentElement;
  let saved = null;
  try { saved = localStorage.getItem("xdrcheck-theme"); } catch (e) { /* storage blocked */ }
  if (saved === "light" || saved === "dark") root.dataset.theme = saved;
  const current = () => root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const label = () => { btn.textContent = current() === "dark" ? "Light theme" : "Dark theme"; };
  label();
  btn.addEventListener("click", () => {
    root.dataset.theme = current() === "dark" ? "light" : "dark";
    try { localStorage.setItem("xdrcheck-theme", root.dataset.theme); } catch (e) { /* storage blocked */ }
    label();
  });
}

let lastView = null;

let seq = 0;
async function render() {
  const main = document.getElementById("main");
  const r = route();
  const mine = ++seq;
  let view = null;
  if (VIEWS[r.view]) {
    try { view = await viewModule(VIEWS[r.view]); } catch (e) {
      main.replaceChildren(h("h1", null, "This view could not be loaded"), h("p", { class: "notice" }, String(e.message || e)));
      return;
    }
  }
  if (mine !== seq) return;
  const tab = TAB_OF[r.view] || r.view;
  for (const a of document.querySelectorAll("#tabs a")) {
    if (a.dataset.view === tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  if (!view) {
    main.replaceChildren(h("h1", null, "Not found"), h("p", null, "There is no view called “" + r.view + "”. ",
      h("a", { href: "#/overview" }, "Go to the overview.")));
    document.title = "Not found · XDRCheck Dashboard";
    return;
  }
  const need = NEEDS[VIEWS[r.view]] || ["summary"];
  if (!need.every((f) => data[f])) {
    main.replaceChildren(h("p", { class: "loading" }, "Loading data…"));
    try { await load(need); } catch (e) { fail(e); return; }
    if (mine !== seq) return;
  }
  main.replaceChildren();
  const title = view(main, data, r) || "";
  document.title = (title ? title + " · " : "") + "XDRCheck Dashboard";
  const key = r.view + "/" + r.rest;
  if (key !== lastView) {
    window.scrollTo(0, 0);
    main.focus({ preventScroll: true });
    lastView = key;
  }
}

function fail(err) {
  const main = document.getElementById("main");
  main.replaceChildren(
    h("h1", null, "The data files could not be read"),
    h("p", { class: "notice" }, "This page reads JSON files from data/. Browsers do not allow that from a file:// URL. ",
      "Serve the folder instead: ", h("code", null, "python3 -m http.server -d apps/dashboard/site 8000"),
      ", then open http://localhost:8000/. (", String(err.message || err), ")"));
}

theme();
initTips();
load(["summary"]).then((d) => {
  const foot = document.getElementById("foot");
  const L = d.summary.links;
  foot.append(h("a", { href: L.landing }, "xdrcheck.dev"), h("a", { href: L.docs }, "Documentation"));
  window.addEventListener("hashchange", render);
  render();
}).catch(fail);
