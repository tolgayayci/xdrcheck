// Replay: corpus entries served to unmodified indexers through inputs they already consume (the Galexie / SEP-54
// lake layout and a mock getLedgers endpoint). Leads with the three wallet-backend incidents before and after their
// fixes, then what the current pinned commit still fails, then every entry × pipeline version × input.
import { h, put, fmt, href, setQuery, search, select, checkbox, notice, table, stateChip, sevChip } from "../lib.js";
import { pipelineLabel, commandBlock, shq } from "../verdicts.js";

const CLASS_MARK = { pass: "✓", mishandled: "✗", dropped: "−", halt: "■", refused: "⊘", "not-run": "·", error: "!" };
const CLASS_TEXT = { pass: "pass", mishandled: "mishandled", dropped: "dropped", halt: "halted", refused: "refused",
  "not-run": "not run (planned out)", error: "harness error" };
const INPUT_TEXT = { "sep54-s3": "data lake in an object store (SEP-54)", "sep54-dir": "data lake in a directory (SEP-54)", rpc: "mock getLedgers" };
const INPUT_SHORT = { "sep54-s3": "lake S3", "sep54-dir": "lake dir", rpc: "getLedgers" };
const FAIL = ["error", "halt", "refused", "mishandled", "dropped"];

const classChip = (c) => h("span", { class: "chip cls cls-" + (c || "none") }, c ? CLASS_TEXT[c] || c : "no cell");

export default function replay(root, d, r) {
  const X = d.replay.replay;
  const P = d.replay.pipelines_pinned;
  put(root, h("h1", null, "Replay"),
    h("p", { class: "lede" }, "The replay harness serves corpus entries to an unmodified indexer through an input it already reads, ",
      "the Galexie data-lake layout (SEP-54) or a mock getLedgers endpoint, and compares what the indexer stored with the ",
      "values each entry's manifest expects."));
  if (!X) {
    put(root, notice("Not in the repository yet:", "the replay summary (evidence/results/replay-summary.json). make verify-replay runs the three wallet-backend pairs."));
    return "Replay";
  }
  const meta = X.pipelines;
  put(root, notice("Scope:", "the pipelines were replayed on corpus entries, not on mainnet history. wallet-backend ran the whole corpus at its pinned " +
    "current commit and the entries of each fix at the commits before and after it; stellar-etl " + P["stellar-etl"].tag +
    " ran the entries that declare a stellar-etl result; the kit's reference indexer ran the whole corpus. Horizon has a service rig " +
    "that reads lake ledgers, not corpus entries, so it has no column here."));

  // 1. the incidents, before and after
  const S = d.summary.replay;
  put(root, h("h2", null, "wallet-backend incidents, before and after their fixes"),
    h("p", null, S.pairs_reproduced === S.pairs
      ? ["On each pre-fix commit every entry of the incident fails, on its fixing commit every one passes, and at the current pinned commit they all pass, on both inputs wallet-backend reads (",
        S.inputs.map((i) => INPUT_TEXT[i] || i).join(" and "), "). ", h("code", null, "make verify-replay"), " runs all of them."]
      : [fmt(S.pairs_reproduced), " of ", fmt(S.pairs), " fixes show the failure before and the pass after in the committed run."]));
  const pairCards = X.pairs.map((p) => {
    const fs = p.findings.map((id) => d.findingById.get(id)).filter(Boolean);
    const first = p.rows[0];
    const cmds = first ? [p.prefix_key, p.fixed_key].map((k) => d.corpus.cli[k]).filter(Boolean)
      .map((t) => ({ what: t.what.replace("it", first.entry), cmd: t.cmd.replace("{id}", shq(first.entry)) })) : [];
    return h("div", { class: "card pair-card" + (p.reproduced ? "" : " warn") },
      h("h3", null, "Fix " + p.pair + ": ", fs.length ? fs[0].title : "declared divergence"),
      fs.length > 1 ? h("p", { class: "caption" }, "The same fix closed: ", fs.slice(1).map((f, i) => [i ? "; " : "", f.title])) : null,
      h("div", { class: "chips" }, fs.map((f) => [h("a", { class: "chip", href: href("problems", "", { q: f.id }) }, f.id), sevChip(f.severity), stateChip(f.state)])),
      h("ul", { class: "pair-rows" }, p.rows.map((x) => h("li", null,
        h("div", { class: "id" }, d.entryById.has(x.entry) ? h("a", { href: href("entry", x.entry) }, x.entry) : x.entry),
        h("div", { class: "flow" },
          h("span", null, h("b", null, "before ", h("code", null, p.prefix.slice(0, 8))), classChip(x.prefix)),
          h("span", { class: "arrow", "aria-hidden": "true" }, "→"),
          h("span", null, h("b", null, "after ", h("code", null, p.fixed.slice(0, 8))), classChip(x.fixed)),
          h("span", null, h("b", null, "current"), classChip(x.current)))))),
      cmds.length ? h("details", { class: "cmd-details" }, h("summary", null, "Replay it yourself"), commandBlock(d, cmds)) : null);
  });
  put(root, h("div", { class: "cards" }, pairCards));
  const known = d.summary.replay_defects || [];
  if (known.length) {
    put(root, h("p", { class: "caption" }, "The known upstream defects these pairs reproduce: ", known.map((s, i) => [i ? "; " : "", (s.topic || "").replace(/`/g, "")]), "."));
  }

  // 2. what the current commit still fails
  const cur = X.current_key;
  const byState = {};
  for (const x of X.current_failing) for (const id of x.findings) { const f = d.findingById.get(id); if (f) byState[f.state] = (byState[f.state] || 0) + 1; }
  const ST = { filed: "filed upstream by this kit", "duplicate-of": "known upstream", "not-a-defect": "reviewed and judged not a defect (wallet-backend's design)" };
  put(root, h("h2", null, "Where wallet-backend's pinned current commit differs"),
    h("p", null, fmt(d.summary.replay.current_entries), " entries ran at ", h("code", null, (meta[cur] || {}).commit ? meta[cur].commit.slice(0, 12) : cur),
      "; on ", fmt(X.current_failing.length), " of them the stored values differ from what the entry's manifest expects. Each names its public finding record: ",
      Object.entries(byState).map(([k, n], i) => [i ? ", " : "", fmt(n), " ", ST[k] || k]), "."));
  if (X.current_failing.length) {
    put(root, table(["Entry", "Result", "Finding", "Severity", "State"], X.current_failing.map((x) => {
      const fs = x.findings.map((id) => d.findingById.get(id)).filter(Boolean);
      return h("tr", null, h("td", { class: "id" }, d.entryById.has(x.entry) ? h("a", { href: href("entry", x.entry) }, x.entry) : x.entry),
        h("td", null, classChip(x.class)),
        h("td", null, fs.length ? fs.map((f) => h("div", null, h("a", { href: href("problems", "", { q: f.id }) }, f.id), " ", f.title)) : "—"),
        h("td", null, fs.map((f) => sevChip(f.severity))), h("td", null, fs.map((f) => stateChip(f.state))));
    }), { label: "Entries the current commit fails" }));
  }
  if (X.pending_cells) put(root, h("p", { class: "caption" }, fmt(X.pending_cells) + " further cells wait on finding review; only their number is shown."));

  drawGrid(root, d, r, X);
  return "Replay";
}

function drawGrid(root, d, r, X) {
  const meta = X.pipelines;
  const cols = X.columns.map((c) => ({ ...c, label: pipelineLabel(meta, c.key) + " · " + (INPUT_SHORT[c.input] || c.input) }));
  const pipes = [...new Set(cols.map((c) => c.pipeline))];
  const state = { q: r.q.get("q") || "", fail: r.q.get("all") !== "1", pipe: r.q.get("pipeline") || "" };
  const grid = h("div", { class: "grid-wrap" });
  const count = h("p", { class: "count", "aria-live": "polite" });
  const ids = Object.keys(X.entries).sort();
  function draw() {
    const q = state.q.toLowerCase();
    const cs = cols.filter((c) => !state.pipe || c.pipeline === state.pipe);
    const rows = ids.filter((id) => (!q || id.toLowerCase().includes(q))
      && (!state.fail || cs.some((c) => { const x = ((X.entries[id] || {})[c.key] || {})[c.input]; return x && FAIL.includes(x.class) && c.pipeline !== "baseline"; })));
    grid.replaceChildren(h("table", { class: "heat", "aria-label": "Entries by pipeline version and input" },
      h("thead", null, h("tr", null, h("th", { class: "rowh", scope: "col" }, "Entry"),
        cs.map((c) => h("th", { class: "col", scope: "col", title: c.label + ": " + (INPUT_TEXT[c.input] || c.input) }, c.label)))),
      h("tbody", null, rows.map((id) => h("tr", null,
        h("th", { class: "rowh", scope: "row" }, d.entryById.has(id) ? h("a", { href: href("entry", id) }, id) : id),
        cs.map((c) => {
          const x = ((X.entries[id] || {})[c.key] || {})[c.input];
          if (!x) {
            const why = c.scope === "known-divergences" ? "not in this run's scope (it ran only the entries that declare a result for it)" : "no cell";
            return h("td", null, h("span", { class: "cell c-none", "data-tip": id + " · " + c.label + ": " + why }));
          }
          const tip = id + " · " + c.label + ": " + (CLASS_TEXT[x.class] || x.class) + (x.findings && x.findings.length ? " (" + x.findings.join(", ") + ")" : "")
            + (c.pipeline === "baseline" && x.class === "refused" ? "; the reference indexer refuses this input by design" : "");
          return h("td", null, h("span", { class: "cell c-" + x.class, "data-tip": tip, "aria-label": tip, role: "img" }, CLASS_MARK[x.class] || "?"));
        }))))));
    count.textContent = rows.length + " of " + ids.length + " entries";
    setQuery({ q: state.q, all: state.fail ? "" : "1", pipeline: state.pipe });
  }
  put(root, h("h2", null, "Every entry by pipeline version and input"),
    h("p", null, "One column per pipeline version and input that ran. A blank cell under a version that ran only some entries means the entry was not in that run, not that it passed. ",
      "The kit's reference indexer refuses a few inputs by design; those refusals are its documented behaviour, not defects."),
    h("div", { class: "legend" }, Object.entries(CLASS_MARK).filter(([k]) => k !== "error").map(([k, m]) => h("span", null, h("span", { class: "cell c-" + k, "aria-hidden": "true" }, m), CLASS_TEXT[k]))),
    h("div", { class: "controls" }, search("Search entries", state.q, (v) => { state.q = v; draw(); }),
      select("Pipeline", "pipeline", [["", "every pipeline"], ...pipes.map((p) => [p, p === "baseline" ? "reference indexer" : p])], state.pipe, (v) => { state.pipe = v; draw(); }),
      checkbox("only entries a pipeline fails", state.fail, (v) => { state.fail = v; draw(); })),
    count, grid);
  draw();
  put(root, h("h3", null, "Totals per column"),
    table(["Pipeline version", "Input", ...X.classes.filter((c) => c !== "error").map((c) => ({ t: CLASS_TEXT[c] || c, cls: "num" }))],
      cols.map((c) => h("tr", null, h("td", null, pipelineLabel(meta, c.key)), h("td", null, INPUT_TEXT[c.input] || c.input),
        X.classes.filter((k) => k !== "error").map((k) => h("td", { class: "num" }, fmt(((X.totals[c.key] || {})[c.input] || {})[k] || 0))))), { label: "Totals per column" }),
    h("p", { class: "caption" }, "Source: ", h("code", null, d.replay.source), " (", h("code", null, "make results-replay"), ")."));
}
