// Rarity: every corpus entry ranked by how often the rarest shape token of its focus transaction (or ledger) occurs in
// the scanned pubnet range, from never seen to common. Rare but valid shapes are what the corpus is for.
import { h, put, fmt, compact, href, capLabel, capRow, setQuery, search, select } from "../lib.js";

const BUCKETS = [
  { k: "0", lo: 0, hi: 0, t: "never seen" }, { k: "1", lo: 1, hi: 9, t: "1–9" }, { k: "10", lo: 10, hi: 99, t: "10–99" },
  { k: "100", lo: 100, hi: 999, t: "100–999" }, { k: "1k", lo: 1e3, hi: 1e4 - 1, t: "1k–10k" }, { k: "10k", lo: 1e4, hi: 1e5 - 1, t: "10k–100k" },
  { k: "100k", lo: 1e5, hi: 1e6 - 1, t: "100k–1M" }, { k: "1m", lo: 1e6, hi: 1e7 - 1, t: "1M–10M" }, { k: "10m", lo: 1e7, hi: Infinity, t: "10M and more" },
];
const bucketOf = (n) => BUCKETS.find((b) => n >= b.lo && n <= b.hi);
const SRC = { "local-core": "local core", "core-golden": "core golden", history: "history", "history-archive": "archive",
  "contract-code": "contract code", synthetic: "synthetic" };

function srcBreak(es) {
  const n = {};
  for (const e of es) { const k = e.sources.map((s) => SRC[s] || s).join(" + ") || "no variant"; n[k] = (n[k] || 0) + 1; }
  return Object.entries(n).sort((a, b) => b[1] - a[1]).map(([k, v]) => fmt(v) + " " + k).join(", ");
}

export default function rarity(root, d, r) {
  const T = d.summary.entry_prevalence;
  const sc = d.corpus.entry_prevalence.scan;
  const lo = d.scan.first_ledger, hi = d.scan.last_ledger;
  const pct = (l) => ((l - lo) / (hi - lo)) * 100;
  const all = d.corpus.entries;
  const counted = all.filter((e) => e.prevalence && e.prevalence.walked);
  const noCount = all.filter((e) => !e.prevalence || !e.prevalence.walked);
  const seen = counted.filter((e) => !e.prevalence.never_seen);
  const never = counted.filter((e) => e.prevalence.never_seen);
  put(root, h("h1", null, "Rarity on mainnet"),
    h("p", { class: "lede" }, "Rare but valid shapes are what the corpus is for: shapes stellar-core accepts and emits, that a reader seldom or never meets on the live ",
      "network, so its code for them is the least exercised. Each entry is ranked by how often the rarest shape token of its focus transaction (or ledger) ",
      "occurs in pubnet ledgers ", fmt(sc.first_ledger), " to ", fmt(sc.last_ledger), "."),
    h("div", { class: "tiles" },
      h("a", { class: "tile", href: href("rarity", "", { group: "never" }) }, h("span", { class: "v" }, fmt(never.length)), h("span", { class: "k" }, "never seen on mainnet"),
        h("span", { class: "s" }, "in the scanned range: " + srcBreak(never))),
      h("a", { class: "tile", href: href("rarity", "", { b: "1" }) }, h("span", { class: "v" }, fmt(seen.filter((e) => e.prevalence.occurrences < 10).length)),
        h("span", { class: "k" }, "seen fewer than 10 times"), h("span", { class: "s" }, "their rarest token, over all of the scanned history")),
      h("a", { class: "tile", href: href("rarity", "", { group: "seen" }) }, h("span", { class: "v" }, fmt(seen.length)), h("span", { class: "k" }, "counted and seen"),
        h("span", { class: "s" }, "with a first and last ledger")),
      h("a", { class: "tile", href: href("rarity", "", { group: "none" }) }, h("span", { class: "v" }, fmt(noCount.length)), h("span", { class: "k" }, "no mainnet count"),
        h("span", { class: "s" }, "no ledger-close-meta variant to walk (SDK-level values, bucket files); not the same as never seen"))),
    h("p", { class: "caption" }, "The count is that of the entry's rarest token, so the entry's whole shape occurs at most that often; it is not a count of transactions with that whole shape. ",
      "A count says where a shape occurs; it says nothing about what any pipeline did with those ledgers. ", fmt(T.mainnet_variants_checked_against_the_scan),
      " variants taken from pubnet ledgers were checked token for token against the scan at their ledger."));

  const state = { q: r.q.get("q") || "", group: r.q.get("group") || "", b: r.q.get("b") || "", cap: r.q.get("cap") || "", src: r.q.get("src") || "" };
  const hist = h("div", { class: "hist", role: "group", "aria-label": "Entries by how often their rarest token occurs" });
  const box = h("div");
  const count = h("p", { class: "count", "aria-live": "polite" });
  const caps = [...new Set(all.flatMap((e) => e.caps))].sort((a, b) => a - b);
  const sources = [...new Set(all.flatMap((e) => e.sources))].sort();

  function base() {
    const q = state.q.toLowerCase();
    return all.filter((e) => (!q || (e.id + " " + e.title).toLowerCase().includes(q))
      && (!state.cap || e.caps.includes(Number(state.cap)))
      && (!state.src || e.sources.includes(state.src)));
  }
  function draw() {
    const xs0 = base();
    const ctd = xs0.filter((e) => e.prevalence && e.prevalence.walked);
    const max = Math.max(1, ...BUCKETS.map((b) => ctd.filter((e) => bucketOf(e.prevalence.occurrences) === b).length));
    hist.replaceChildren(...BUCKETS.map((b) => {
      const n = ctd.filter((e) => bucketOf(e.prevalence.occurrences) === b).length;
      return h("button", { type: "button", class: "hbar" + (state.b === b.k ? " on" : "") + (b.k === "0" ? " never" : ""), "aria-pressed": state.b === b.k ? "true" : "false",
        "aria-label": n + " entries: rarest token " + b.t, onclick: () => { state.b = state.b === b.k ? "" : b.k; state.group = ""; draw(); } },
      h("span", { class: "n" }, fmt(n)), h("span", { class: "bar", style: "height:" + Math.max(2, Math.round(110 * n / max)) + "px" }), h("span", { class: "t" }, b.t));
    }));
    let xs = xs0;
    if (state.group === "never") xs = xs.filter((e) => e.prevalence && e.prevalence.walked && e.prevalence.never_seen);
    else if (state.group === "seen") xs = xs.filter((e) => e.prevalence && e.prevalence.walked && !e.prevalence.never_seen);
    else if (state.group === "none") xs = xs.filter((e) => !e.prevalence || !e.prevalence.walked);
    if (state.b) xs = xs.filter((e) => e.prevalence && e.prevalence.walked && bucketOf(e.prevalence.occurrences).k === state.b);
    const key = (e) => (e.prevalence && e.prevalence.walked ? e.prevalence.occurrences : Infinity);
    xs = xs.slice().sort((a, b) => key(a) - key(b) || (a.id < b.id ? -1 : 1));
    const shown = xs.slice(0, 600);
    box.replaceChildren(h("div", { class: "tbl-wrap" }, h("table", { "aria-label": "Entries by rarity" },
      h("thead", null, h("tr", null, h("th", { scope: "col", class: "num" }, "#"), h("th", { scope: "col" }, "Entry"), h("th", { scope: "col" }, "CAP"),
        h("th", { scope: "col", class: "num" }, "Rarest token occurs"), h("th", { scope: "col" }, "Where in the scanned range"), h("th", { scope: "col" }, "Source"),
        h("th", { scope: "col", class: "num" }, "Findings"))),
      h("tbody", null, shown.length ? null : h("tr", null, h("td", { class: "empty", colspan: "7" }, "No entry matches these filters.")), shown.map((e, i) => {
        const p = e.prevalence;
        let occ, where;
        if (!p || !p.walked) { occ = h("span", { class: "muted" }, "no count"); where = h("span", { class: "muted" }, "no ledger-close-meta variant"); }
        else if (p.never_seen) { occ = h("span", { class: "chip tag-never" }, "never seen"); where = h("span", { class: "muted" }, "not in ledgers " + compact(sc.first_ledger) + " to " + compact(sc.last_ledger)); }
        else {
          occ = fmt(p.occurrences);
          const l = pct(p.first_ledger), w = Math.max(pct(p.last_ledger) - l, 0.4);
          where = h("div", { class: "mini", "data-tip": "first at ledger " + fmt(p.first_ledger) + ", last at " + fmt(p.last_ledger), tabindex: "0",
            "aria-label": "ledgers " + fmt(p.first_ledger) + " to " + fmt(p.last_ledger) },
          h("span", { class: "span", style: "left:" + l.toFixed(2) + "%;width:" + w.toFixed(2) + "%" }), h("span", { class: "lbl" }, compact(p.first_ledger) + " – " + compact(p.last_ledger)));
        }
        return h("tr", null, h("td", { class: "num muted" }, String(i + 1)),
          h("td", { class: "id" }, h("a", { href: href("entry", e.id) }, e.id), e.synthetic ? [" ", h("span", { class: "chip tag-syn" }, "synthetic")] : null,
            h("div", { class: "caption", style: "font-family:var(--sans);word-break:normal" }, e.title)),
          h("td", null, e.caps.map((c, j) => [j ? ", " : "", d.rowByGroup.has(capRow(c)) ? h("a", { href: href("cap", capRow(c)) }, String(c)) : String(c)])),
          h("td", { class: "num" }, occ), h("td", { style: "min-width:180px" }, where),
          h("td", null, e.sources.map((s) => SRC[s] || s).join(", ")),
          h("td", { class: "num" }, e.findings.length ? h("a", { href: href("problems", "", { q: e.id }) }, String(e.findings.length)) : "0"));
      })))));
    count.textContent = xs.length + " of " + all.length + " entries" + (xs.length > shown.length ? " (first " + shown.length + " shown)" : "");
    setQuery({ q: state.q, group: state.group, b: state.b, cap: state.cap, src: state.src });
  }
  const controls = h("div", { class: "controls" });
  function drawControls() {
    controls.replaceChildren(
      search("Search entries", state.q, (v) => { state.q = v; draw(); }),
      select("Group", "group", [["", "every entry"], ["never", "never seen on mainnet"], ["seen", "counted and seen"], ["none", "no mainnet count"]], state.group, (v) => { state.group = v; state.b = ""; drawAll(); }),
      select("CAP", "cap", [["", "any CAP"], ...caps.map((c) => [String(c), capLabel(capRow(c))])], state.cap, (v) => { state.cap = v; draw(); }),
      select("Source", "src", [["", "any source"], ...sources.map((s) => [s, SRC[s] || s])], state.src, (v) => { state.src = v; draw(); }));
  }
  function drawAll() { drawControls(); draw(); }
  put(root, h("h2", null, "From never seen to common"),
    h("p", null, "Entries by how often their rarest token occurs. Select a bar to list its entries."), hist, controls, count, box,
    h("p", { class: "caption" }, "Source: ", h("code", null, d.corpus.sources.entry_prevalence), " (", h("code", null, "make results-prevalence"),
      "). The scan's method is in ", h("code", null, "evidence/mainnet-scan/README.md"), ". Per CAP, the first and last mainnet ledger of each row's rare union arms: ",
      h("a", { href: href("timeline") }, "Ledger history"), "."));
  drawAll();
  return "Rarity on mainnet";
}
