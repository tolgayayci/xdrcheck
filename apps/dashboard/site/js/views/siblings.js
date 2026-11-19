// One fix, every SDK: each SDK defect class (from the public finding records) against each SDK family the kit knows,
// read from the executed conformance runs of the pr and public column sets (evidence/results/sibling-matrix.json).
import { h, put, fmt, href, setQuery, search, checkbox, notice, sevChip, stateChip } from "../lib.js";
import { commandBlock } from "../verdicts.js";

const STATE = {
  reproduces: { mark: "R", cls: "s-rep", text: "reproduces" },
  "not-a-defect": { mark: "nd", cls: "s-nd", text: "differs, not a defect" },
  "outside-runs": { mark: "rec", cls: "s-rec", text: "record only: a public record shows it by other means; the runs do not reach it" },
  "not-affected": { mark: "ok", cls: "s-ok", text: "not affected: its columns judged the cells and none failed" },
  "not-applicable": { mark: "n/a", cls: "s-none", text: "not applicable: the family has no counterpart API for this class" },
  "not-run": { mark: "–", cls: "s-none", text: "not run" },
};

function cellText(c) {
  if (c.state === "reproduces") {
    const v = c.versions || [];
    return (v.length > 2 ? v[0] + " … " + v[v.length - 1] : v.join(", ")) + (c.passes_from ? " → passes " + c.passes_from : " → no version run passes");
  }
  if (c.state === "not-affected") { const n = (c.versions || []).length; return n + (n === 1 ? " version" : " versions"); }
  return "";
}

function cellTip(S, cl, f, c) {
  const fam = S.families[f].label;
  let t = cl.id + " · " + fam + ": " + STATE[c.state].text;
  if (c.state === "reproduces") t += "; fails in " + (c.versions || []).join(", ") + (c.passes_from ? "; the first later version run that passes is " + c.passes_from : "; no later version run passes");
  if (c.state === "not-affected") t += " (" + (c.versions || []).join(", ") + ")";
  if (c.why) t += " (" + c.why + ")";
  if (c.records && c.records.length) t += "; records " + c.records.join(", ");
  return t;
}

export default function siblings(root, d, r) {
  const S = d.siblings.siblings;
  put(root, h("h1", null, "One fix, every SDK"),
    h("p", { class: "lede" }, "A defect found in one SDK is looked for in every other SDK the kit drives. Each row is one defect class from the public ",
      "finding records; each cell is read from the executed conformance runs on exactly that class's corpus entries, not from reading the SDK's code. ",
      "Once a class is in the corpus, every SDK's next release is checked against it."));
  if (!S) {
    put(root, notice("Not in the repository yet:", "the sibling matrix (evidence/results/sibling-matrix.json)."));
    return "One fix, every SDK";
  }
  const top = S.top;
  const reached = top.reached.map((f) => S.families[f].label);
  put(root, h("div", { class: "lead-box" },
    h("p", { class: "eyebrow" }, "The widest class"),
    h("p", { class: "big" }, top.title),
    h("p", null, "Reproduces ", h("strong", null, top.phrase), ": ",
      top.labels.join(", "), ". ", h("a", { href: href("siblings", "", { cls: top.id }) }, "Open the class"), "."),
    reached.length < S.family_order.length ? h("p", { class: "caption" }, "The other families have no driver in the public column sets or no column that applies: ",
      S.family_order.filter((f) => !top.reached.includes(f)).map((f) => S.families[f].label).join(", "), ".") : null),
  h("p", null, fmt(S.classes.length), " classes × ", fmt(S.family_order.length), " families: ",
    ["reproduces", "not-affected", "outside-runs", "not-a-defect", "not-applicable", "not-run"].map((k, i) => [i ? ", " : "", fmt(S.totals[k] || 0), " ", STATE[k].text.split(":")[0]]), ". ",
    S.family_order.length - S.families_with_driver.length ? [fmt(S.family_order.length - S.families_with_driver.length), " families (",
      S.family_order.filter((f) => !S.families_with_driver.includes(f)).map((f) => S.families[f].label).join(", "), ") have no driver in the public column sets; their cells come from records only. "] : null));

  const state = { q: r.q.get("q") || "", multi: r.q.get("multi") === "1", cls: r.q.get("cls") || "" };
  const grid = h("div", { class: "grid-wrap sib-wrap" });
  const detail = h("div", { id: "class-detail" });
  const count = h("p", { class: "count", "aria-live": "polite" });
  function draw() {
    const q = state.q.toLowerCase();
    const rows = S.classes.filter((c) => (!q || (c.id + " " + c.title + " " + c.records.join(" ") + " " + c.entries.join(" ")).toLowerCase().includes(q))
      && (!state.multi || S.family_order.filter((f) => c.cells[f].state === "reproduces").length > 1));
    grid.replaceChildren(h("table", { class: "heat sib", "aria-label": "Defect classes by SDK family" },
      h("thead", null, h("tr", null, h("th", { class: "rowh", scope: "col" }, "Defect class"),
        S.family_order.map((f) => h("th", { scope: "col", class: "fam" }, S.families[f].label)))),
      h("tbody", null, rows.map((c) => h("tr", { class: c.id === state.cls ? "on" : null },
        h("th", { class: "rowh", scope: "row" }, h("a", { href: href("siblings", "", { q: state.q, multi: state.multi ? "1" : "", cls: c.id }),
          onclick: (ev) => { ev.preventDefault(); state.cls = state.cls === c.id ? "" : c.id; draw(); document.getElementById("class-detail").scrollIntoView({ block: "nearest" }); } },
        h("span", { class: "mono" }, c.id)), h("span", { class: "t" }, c.title)),
        S.family_order.map((f) => {
          const x = c.cells[f];
          const st = STATE[x.state] || STATE["not-run"];
          const tip = cellTip(S, c, f, x);
          return h("td", null, h("span", { class: "scell " + st.cls, "data-tip": tip, "aria-label": tip, role: "img" },
            h("b", null, st.mark), cellText(x) ? h("small", null, cellText(x)) : null));
        }))))));
    count.textContent = rows.length + " of " + S.classes.length + " classes";
    drawDetail();
    setQuery({ q: state.q, multi: state.multi ? "1" : "", cls: state.cls });
  }
  function drawDetail() {
    const c = S.classes.find((x) => x.id === state.cls);
    if (!c) { detail.replaceChildren(); return; }
    const recs = c.records.map((id) => d.findingById.get(id)).filter(Boolean);
    detail.replaceChildren(h("div", { class: "card" },
      h("h3", null, h("span", { class: "mono" }, c.id), ": ", c.title),
      h("h4", null, "Finding records"),
      h("ul", { class: "flist" }, recs.map((f) => h("li", null, h("a", { href: href("problems", "", { q: f.id }) }, f.id), " ", f.project, " ", sevChip(f.severity), " ", stateChip(f.state),
        f.upstream && f.upstream.kind === "filed" ? [" ", h("a", { href: f.upstream.url, rel: "noopener" }, "our issue")] : null, h("div", { class: "caption" }, f.title)))),
      h("h4", null, "Per family"),
      h("ul", { class: "flist" }, S.family_order.map((f) => h("li", null, h("strong", null, S.families[f].label + ": "), cellTip(S, c, f, c.cells[f]).split(": ").slice(1).join(": ")))),
      h("h4", null, "Corpus entries"),
      h("div", null, c.entries.map((e) => h("div", { class: "mono small" }, d.entryById.has(e) ? h("a", { href: href("entry", e) }, e) : e))),
      h("h4", null, "Check it yourself"),
      commandBlock(d, [{ what: "look for this class's defect in every SDK family (read-only plan)", cmd: "xdrcheck conform siblings --finding " + (c.title_from || c.records[0]) + " --offline --plan" },
        { what: "run its entries through every column of the public set", cmd: "xdrcheck conform run --set public --entries " + c.entries.join(",") }])));
  }
  put(root, h("h2", null, "Defect classes by SDK family"),
    h("div", { class: "legend" }, Object.values(STATE).map((s) => h("span", null, h("span", { class: "scell " + s.cls, "aria-hidden": "true" }, h("b", null, s.mark)), s.text.split(":")[0]))),
    h("div", { class: "controls" }, search("Search classes, records, entries", state.q, (v) => { state.q = v; draw(); }),
      checkbox("only classes that reproduce in more than one family", state.multi, (v) => { state.multi = v; draw(); })),
    count, grid, detail,
    S.pending_notes ? h("p", { class: "caption" }, fmt(S.pending_notes) + " reproducing cells also have a failing cell that waits on finding review; nothing more is shown about it.") : null,
    h("p", { class: "caption" }, "Source: ", h("code", null, d.siblings.source), " (", h("code", null, "make results-siblings"), "), also rendered as ", h("code", null, "findings/SIBLINGS.md"), "."));
  draw();
  return "One fix, every SDK";
}
