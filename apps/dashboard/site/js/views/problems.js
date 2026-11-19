// Problems: what problem exists where. Findings by component and severity, then every public finding record with
// its state, affected versions, fix, CAP and corpus entries; and the linter's rules.
import { h, put, fmt, compact, href, capLabel, capRow, setQuery, search, select, sevChip, stateChip, notice, table } from "../lib.js";

const KIND_TEXT = { pipeline: "pipeline", sdk: "SDK", "xdr-library": "XDR library" };
const STATE_OPTS = [["", "any state"], ["filed", "filed by this kit"], ["duplicate-of", "known upstream"], ["not-a-defect", "not a defect"]];

export default function problems(root, d, r) {
  const F = d.findings;
  const sevs = F.severity_order;
  const state = {
    q: r.q.get("q") || "", project: r.q.get("project") || "", kind: r.q.get("kind") || "", sev: r.q.get("sev") || "",
    state: r.q.get("state") || "", cap: r.q.get("cap") || "", tab: r.q.get("tab") || "findings",
  };
  const projects = [...new Set(F.findings.map((f) => f.project))].sort((a, b) => {
    const k = (p) => (F.findings.find((f) => f.project === p).component === "pipeline" ? 0 : 1);
    return k(a) - k(b) || a.localeCompare(b);
  });
  const caps = [...new Set(F.findings.flatMap((f) => f.caps))].sort((a, b) => a - b);

  const matrixBox = h("div");
  const tableBox = h("div");
  const count = h("p", { class: "count", "aria-live": "polite" });
  const controls = h("div", { class: "controls" });

  const match = (f, ignore) => {
    const q = state.q.toLowerCase();
    return (!q || (f.id + " " + f.title + " " + f.project + " " + (f.versions_affected || "") + " " + f.entries.join(" ") + " " + f.rules.join(" ")).toLowerCase().includes(q))
      && (ignore || !state.project || f.project === state.project)
      && (!state.kind || f.component === state.kind)
      && (ignore || !state.sev || f.severity === state.sev)
      && (!state.state || f.state === state.state)
      && (!state.cap || (state.cap === "none" ? !f.caps.length : f.caps.includes(Number(state.cap.replace(/^cap-0*/, "")))));
  };

  const matchExcept = (f) => {
    const q = state.q.toLowerCase();
    return (!q || (f.id + " " + f.title + " " + f.project + " " + (f.versions_affected || "") + " " + f.entries.join(" ") + " " + f.rules.join(" ")).toLowerCase().includes(q))
      && (!state.kind || f.component === state.kind) && (!state.state || f.state === state.state);
  };

  function drawMatrix() {
    // counts ignore the component and severity filters (the grid sets those), and keep the others
    const fs = F.findings.filter((f) => match(f, true));
    const cell = (p, s) => fs.filter((f) => f.project === p && f.severity === s).length;
    const rows = projects.map((p) => {
      const kind = F.findings.find((f) => f.project === p).component;
      const tot = sevs.reduce((n, s) => n + cell(p, s), 0);
      return h("tr", null,
        h("th", { scope: "row" }, h("button", { class: "linkish", type: "button", "aria-pressed": state.project === p ? "true" : "false",
          onclick: () => { state.project = state.project === p ? "" : p; state.sev = ""; draw(); } }, p),
        h("span", { class: "muted" }, " " + KIND_TEXT[kind])),
        sevs.map((s) => {
          const n = cell(p, s);
          return h("td", { class: "num" }, n ? h("button", { type: "button", class: "cellbtn sevcell-" + s + (state.project === p && state.sev === s ? " on" : ""),
            "aria-label": n + " " + s + " findings in " + p,
            onclick: () => { const on = state.project === p && state.sev === s; state.project = on ? "" : p; state.sev = on ? "" : s; draw(); } }, String(n)) : h("span", { class: "muted" }, "·"));
        }),
        h("td", { class: "num" }, fmt(tot)));
    });
    matrixBox.replaceChildren(h("div", { class: "tbl-wrap" }, h("table", { "aria-label": "Findings by component and severity" },
      h("thead", null, h("tr", null, h("th", { scope: "col" }, "Component"), sevs.map((s) => h("th", { scope: "col", class: "num" }, s)), h("th", { scope: "col", class: "num" }, "all"))),
      h("tbody", null, rows))),
    h("p", { class: "caption" }, "Select a count to list those findings; select a component name to list all of its findings. The other filters apply to the counts."));
  }

  // component × CAP: how many findings each component has under each CAP (a finding counts under every CAP it has)
  const heatBox = h("div");
  function drawHeat() {
    const fs = F.findings.filter((f) => matchExcept(f));
    const cols = [...caps.map((c) => capRow(c)), "none"];
    const n = (p, g) => fs.filter((f) => f.project === p && (g === "none" ? !f.caps.length : f.caps.includes(Number(g.slice(4))))).length;
    const max = Math.max(1, ...projects.flatMap((p) => cols.map((g) => n(p, g))));
    heatBox.replaceChildren(h("div", { class: "grid-wrap heat-wrap" }, h("table", { class: "heat ccap", "aria-label": "Findings by component and CAP" },
      h("thead", null, h("tr", null, h("th", { class: "rowh", scope: "col" }, "Component"),
        cols.map((g) => h("th", { class: "col", scope: "col" }, g === "none" ? "no CAP" : capLabel(g))))),
      h("tbody", null, projects.map((p) => h("tr", null, h("th", { class: "rowh", scope: "row" }, p),
        cols.map((g) => {
          const k = n(p, g);
          if (!k) return h("td", null, h("span", { class: "cell c-none" }, ""));
          const on = state.project === p && state.cap === (g === "none" ? "none" : g);
          const lbl = k + " finding" + (k === 1 ? "" : "s") + " in " + p + (g === "none" ? " with no CAP" : " under " + capLabel(g));
          return h("td", null, h("button", { type: "button", class: "cell hcell" + (k / max > 0.45 ? " hi" : "") + (on ? " on" : ""), style: "--a:" + (0.18 + 0.82 * k / max).toFixed(2),
            "aria-label": lbl, "aria-pressed": on ? "true" : "false", "data-tip": lbl,
            onclick: () => { state.project = on ? "" : p; state.cap = on ? "" : (g === "none" ? "none" : g); state.sev = ""; draw(); } }, String(k)));
        })))))),
    h("p", { class: "caption" }, "Darker means more findings. Select a cell to list them. The search, kind and state filters apply to the counts."));
  }

  function drawTable() {
    const fs = F.findings.filter((f) => match(f)).sort((a, b) => sevs.indexOf(a.severity) - sevs.indexOf(b.severity) || (a.id < b.id ? -1 : 1));
    count.textContent = fs.length + " of " + F.findings.length + " findings";
    tableBox.replaceChildren(table(["Finding", "Title", "Component", "Severity", "State", "Affected", "Fixed in", "CAP", "Corpus entries and how rare their shape is on mainnet", "Upstream"],
      fs.map((f) => h("tr", { id: f.id },
        h("td", { class: "id" }, f.id),
        h("td", null, f.title, f.siblings.length ? h("div", { class: "caption" }, "Same defect elsewhere: ",
          f.siblings.map((s, i) => [i ? ", " : "", h("a", { href: href("problems", "", { q: s }) }, s)])) : null),
        h("td", null, f.project, h("div", { class: "muted" }, KIND_TEXT[f.component])),
        h("td", null, sevChip(f.severity)),
        h("td", null, stateChip(f.state)),
        h("td", { class: "vers", title: f.versions_affected || null }, shortHashes(f.versions_affected) || "—"),
        h("td", { class: "id", title: f.fixed_in || null }, shortHashes(f.fixed_in) || "—"),
        h("td", null, f.caps.length ? f.caps.map((c, i) => [i ? ", " : "", d.rowByGroup.has(capRow(c)) ? h("a", { href: href("cap", capRow(c)) }, String(c)) : String(c)]) : "—"),
        h("td", { class: "ents" }, f.entries.length ? f.entries.map((e) => entryCell(d, e)) : "—"),
        h("td", null, f.upstream && f.upstream.kind === "filed"
          ? h("a", { href: f.upstream.url, rel: "noopener" }, "our issue" + (f.upstream.state ? " (" + f.upstream.state + ")" : ""))
          : f.upstream ? "known upstream" : "—"))), { label: "Findings" }));
  }

  function drawControls() {
    controls.replaceChildren(
      search("Search", state.q, (v) => { state.q = v; drawBody(); }),
      select("Component", "project", [["", "any component"], ...projects.map((p) => [p, p])], state.project, (v) => { state.project = v; draw(); }),
      select("Kind", "kind", [["", "any kind"], ["pipeline", "pipelines"], ["sdk", "SDKs"], ["xdr-library", "XDR libraries"]], state.kind, (v) => { state.kind = v; draw(); }),
      select("Severity", "sev", [["", "any severity"], ...sevs.map((s) => [s, s])], state.sev, (v) => { state.sev = v; draw(); }),
      select("State", "state", STATE_OPTS, state.state, (v) => { state.state = v; draw(); }),
      select("CAP", "cap", [["", "any CAP"], ["none", "no CAP"], ...caps.map((c) => [capRow(c), capLabel(capRow(c))])], state.cap, (v) => { state.cap = v; draw(); }));
  }
  function drawBody() {
    drawHeat(); drawMatrix(); drawTable();
    setQuery({ q: state.q, project: state.project, kind: state.kind, sev: state.sev, state: state.state, cap: state.cap });
  }
  function draw() { drawControls(); drawBody(); }

  put(root, 
    h("h1", null, "Problems"),
    h("p", { class: "lede" }, "Every public finding record: a defect the corpus exposed in one component, with its severity, the ",
      "versions it affects, the fix, the CAP and the corpus entries that show it. ",
      "“Filed by this kit” links the issue this project opened; “known upstream” means the defect was already reported by someone else."),
    h("div", { class: "tabs", role: "tablist", style: "margin-bottom:8px" },
      h("a", { href: href("problems"), role: "tab", "aria-selected": state.tab !== "rules" ? "true" : "false", "aria-current": state.tab !== "rules" ? "page" : null }, "Findings"),
      h("a", { href: href("problems", "", { tab: "rules" }), role: "tab", "aria-selected": state.tab === "rules" ? "true" : "false", "aria-current": state.tab === "rules" ? "page" : null }, "Linter rules")));

  if (state.tab === "rules") {
    const used = new Map();
    for (const f of F.findings) for (const ru of f.rules) used.set(ru, (used.get(ru) || 0) + 1);
    put(root, 
      h("p", null, "xdrlint checks Go ingestion code for three common ingestion mistakes. The guide's checklist carries the same checks for other languages."),
      table(["Rule", "Mistake", "Reports", "Severity", "Default", "Guide section", "Checklist", { t: "Findings", cls: "num" }],
        F.lint_rules.map((ru) => h("tr", null, h("td", { class: "id" }, ru.id), h("td", null, ru.family), h("td", null, ru.reports),
          h("td", null, ru.severity), h("td", null, ru.default ? "yes" : "opt-in"), h("td", null, ru.guide_section), h("td", { class: "mono" }, ru.checklist || "—"),
          h("td", { class: "num" }, used.get(ru.id) ? h("a", { href: href("problems", "", { q: ru.id }) }, String(used.get(ru.id))) : "0"))), { label: "Linter rules" }),
      h("p", { class: "caption" }, "Source: ", h("code", null, "lint/docs/README.md"), ", generated from the rule registry."));
    return "Linter rules";
  }
  put(root, 
    F.totals.awaiting_review_total ? notice("Awaiting review:", fmt(F.totals.awaiting_review_total) + " entries of the repository's pending lists (" +
      Object.entries(F.totals.awaiting_review).filter(([, n]) => n).map(([k, n]) => n + " " + k).join(", ") +
      ") wait on finding review. Nothing about them is published until they are reviewed.") : null,
    controls, h("h2", null, "Where: component by CAP"), heatBox, h("h2", null, "How bad: component by severity"), matrixBox, h("h2", null, "Findings"), count, tableBox,
    h("p", { class: "caption" }, "Source: ", h("code", null, "findings/F-*/finding.json"), "."));
  draw();
  return "Problems";
}

// One corpus entry of a finding, with how common its shape is on mainnet. Worded as where the shape occurs, never as
// where a pipeline failed: the scan ran no pipeline.
function entryCell(d, id) {
  const e = d.entryById.get(id);
  const p = e && e.prevalence;
  let note;
  if (!e) note = null;
  else if (!p || !p.walked) note = h("span", { class: "muted" }, "no mainnet count (no ledger meta to walk)");
  else if (p.never_seen) note = h("span", { class: "rare" }, "never seen on mainnet in the scanned range");
  else note = h("span", { title: "Its rarest shape token occurs " + fmt(p.occurrences) + " times on mainnet between ledgers " + fmt(p.first_ledger) + " and " + fmt(p.last_ledger) +
    "; the whole shape occurs at most that often. This says where the shape occurs, not what any pipeline did with those ledgers." },
  "this shape occurs at most " + fmt(p.occurrences) + "× on mainnet, ledgers " + compact(p.first_ledger) + " to " + compact(p.last_ledger));
  return h("div", { class: "ent" }, h("div", { class: "id" }, e ? h("a", { href: href("entry", id) }, id) : id), note ? h("div", { class: "caption" }, note) : null);
}

// Commit hashes in version text, shortened to 10 characters (the full text is the cell's title).
const shortHashes = (t) => (t ? t.replace(/\b([0-9a-f]{10})[0-9a-f]{30}\b/g, "$1") : t);
