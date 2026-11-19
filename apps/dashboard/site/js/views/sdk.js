// SDK matrix: corpus entries × SDK columns. From the conformance run's matrix when the repository has one; until
// then from the divergences each entry's manifest declares (which `make verify-conformance` checks on every run).
import { h, put, fmt, href, capLabel, setQuery, search, select, checkbox, notice } from "../lib.js";
import { FAMILY_TEXT, outcomeText } from "../verdicts.js";

const CLASS_MARK = { agrees: "✓", diverges: "✗", "not-run": "·" };
const CLASS_TEXT = { agrees: "agrees with the network", diverges: "diverges", pending: "awaiting finding review", "not-run": "not run" };
const DECL_FAMILIES = ["js", "go", "rust", "python", "java", "xdr-json", "soroban-spec"];

export default function sdk(root, d, r) {
  const M = d.matrix.conformance;
  const state = { q: r.q.get("q") || "", row: r.q.get("row") || "", shape: r.q.get("shape") || "",
    div: r.q.get("all") !== "1" && !r.q.get("shape") };
  const entries = d.corpus.entries;
  const shapes = d.corpus.risk_shapes;

  // column model
  let cols, cellOf;
  if (M) {
    const ids = (M.sets && M.sets.public) || Object.keys(M.columns || {});
    cols = ids.map((id) => ({ id, label: id, family: id.split("@")[0] }));
    cellOf = (e, c) => {
      const x = (M.entries[e.id] || {})[c.id];
      if (!x) return { cls: "c-none", mark: "", tip: "no cell" };
      return { cls: "c-" + x.class, mark: CLASS_MARK[x.class] || "?", diverges: x.class === "diverges",
        tip: e.id + " · " + c.id + ": " + (CLASS_TEXT[x.class] || x.class) + (x.findings && x.findings.length ? " (" + x.findings.join(", ") + ")" : "") };
    };
  } else {
    cols = DECL_FAMILIES.filter((f) => entries.some((e) => e.divergences.some((v) => v.family === f)))
      .map((f) => ({ id: f, label: FAMILY_TEXT[f] || f, family: f }));
    cellOf = (e, c) => {
      const ds = e.divergences.filter((v) => v.family === c.id);
      if (!ds.length) return { cls: "c-none", mark: "", tip: e.id + " · " + c.label + ": nothing declared" };
      const open = ds.some((v) => v.status === "open" || v.status === "wont_fix");
      return { cls: open ? "c-declared" : "c-declared-fixed", mark: open ? "✗" : "✓", diverges: true,
        tip: e.id + " · " + c.label + ": " + ds.map((v) => outcomeText(v.outcome) + " in " + (v.versions || "?") + " (" + (v.status || "").replace(/_/g, " ") +
          (v.fixed_in ? ", fixed in " + v.fixed_in : "") + ")" + (v.finding ? " " + v.finding : "")).join("; ") };
    };
  }

  const grid = h("div", { class: "grid-wrap" });
  const count = h("p", { class: "count", "aria-live": "polite" });
  const shapeBar = h("div", { class: "chips", role: "group", "aria-label": "Shapes behind known defects" });

  function draw() {
    const q = state.q.toLowerCase();
    const rows = entries.filter((e) => (!q || (e.id + " " + e.title).toLowerCase().includes(q))
      && (!state.row || e.rows.includes(state.row))
      && (!state.shape || e.risk_shapes.includes(state.shape))
      && (!state.div || cols.some((c) => cellOf(e, c).diverges)));
    shapeBar.replaceChildren(...shapes.map((s) => {
      const n = entries.filter((e) => e.risk_shapes.includes(s.key)).length;
      return h("button", { type: "button", class: "chip tag-risk shapebtn", "aria-pressed": state.shape === s.key ? "true" : "false",
        onclick: () => { state.shape = state.shape === s.key ? "" : s.key; if (state.shape) state.div = false; drawAll(); } }, s.label + " (" + n + ")");
    }));
    grid.replaceChildren(h("table", { class: "heat", "aria-label": "Entries by SDK column" },
      h("thead", null, h("tr", null, h("th", { class: "rowh", scope: "col" }, "Entry"), cols.map((c) => h("th", { class: "col", scope: "col", title: c.label }, c.label)))),
      h("tbody", null, rows.map((e) => h("tr", { class: e.risk_shapes.length ? "risk-row" : null },
        h("th", { class: "rowh", scope: "row", title: e.title }, h("a", { href: href("entry", e.id) }, e.id)),
        cols.map((c) => { const x = cellOf(e, c);
          return h("td", null, h("span", { class: "cell " + x.cls, "data-tip": x.tip, "aria-label": x.tip, role: "img" }, x.mark)); }))))));
    count.textContent = rows.length + " of " + entries.length + " entries";
    setQuery({ q: state.q, row: state.row, shape: state.shape, all: state.div || state.shape ? "" : "1" });
  }
  const controls = h("div", { class: "controls" });
  function drawControls() {
    controls.replaceChildren(
      search("Search entries", state.q, (v) => { state.q = v; draw(); }),
      select("CAP row", "row", [["", "every row"], ...d.corpus.rows.filter((x) => x.entries.length).map((x) => [x.group, capLabel(x.group) + " " + x.title.slice(0, 40)])],
        state.row, (v) => { state.row = v; draw(); }),
      checkbox(M ? "only entries with a divergence" : "only entries with a declared divergence", state.div, (v) => { state.div = v; draw(); }));
  }
  function drawAll() { drawControls(); draw(); }

  put(root, h("h1", null, "SDK matrix"),
    h("p", { class: "lede" }, "Each corpus entry through each SDK column: one SDK at one pinned version (and, for Rust, one decode profile). ",
      "A fix in one SDK becomes a regression test for the others when the same entry runs through all of them."));
  if (M) {
    put(root, h("div", { class: "legend" },
      Object.entries(CLASS_MARK).map(([k, m]) => h("span", null, h("span", { class: "cell c-" + k, "aria-hidden": "true" }, m), CLASS_TEXT[k]))),
    h("p", { class: "caption" }, "Source: ", h("code", null, d.matrix.source), ". Columns of the public set." +
      (M.pending_cells ? " " + M.pending_cells + " cells wait on finding review; they are left out of the grid and only counted here." : "")));
  } else {
    put(root, notice("Declared divergences.", "The conformance run's matrix is not in the repository yet, so this grid shows the divergences " +
      "each entry's manifest declares, per SDK family. A blank cell means nothing is declared, not that the SDK was checked and agrees. " +
      "make verify-conformance runs " + fmt(d.summary.sdk.columns_pr) + " columns on every pull request and fails on any divergence that is not declared."),
    h("div", { class: "legend" },
      h("span", null, h("span", { class: "cell c-declared", "aria-hidden": "true" }, "✗"), "declared, open in at least one version"),
      h("span", null, h("span", { class: "cell c-declared-fixed", "aria-hidden": "true" }, "✓"), "declared, fixed in a later version"),
      h("span", null, h("span", { class: "cell c-none", "aria-hidden": "true" }), "nothing declared")));
  }
  put(root, h("h2", null, "Shapes behind known defects"),
    h("p", null, "Shapes that have already tripped one SDK but not the others. Select one to list its entries; a marked row edge flags them in the grid."),
    shapeBar, controls, count, grid);
  drawAll();
  return "SDK matrix";
}
