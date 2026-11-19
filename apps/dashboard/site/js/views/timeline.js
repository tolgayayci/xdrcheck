// Ledger history: one horizontal axis over the scanned pubnet range, protocol bands from the census, and per CAP
// row the first and last ledger of the union arms joined to its entries, with how rare the rarest one is.
import { h, put, fmt, compact, href, capLabel, setQuery, search, select, checkbox, notice } from "../lib.js";

export default function timeline(root, d, r) {
  const scan = d.scan;
  const lo = scan.first_ledger, hi = scan.last_ledger;
  const pct = (l) => ((l - lo) / (hi - lo)) * 100;
  const state = { q: r.q.get("q") || "", sort: r.q.get("sort") || "protocol", seen: r.q.get("seen") === "1" };

  const bands = () => h("div", { class: "bands", "aria-hidden": "true" }, scan.protocol_bands.map((b) =>
    h("i", { style: "width:" + (pct(b.last_ledger + 1) - pct(b.first_ledger)).toFixed(4) + "%" })));

  const axis = h("div", { class: "tl-row axis-row" }, h("span", { class: "lab" }, "Protocol"),
    h("div", { class: "axis" },
      h("div", { class: "bands" }, scan.protocol_bands.map((b) => {
        const w = pct(b.last_ledger + 1) - pct(b.first_ledger);
        return h("i", { style: "width:" + w.toFixed(4) + "%", tabindex: "0",
          "data-tip": "Protocol " + b.protocol + ": ledgers " + fmt(b.first_ledger) + " to " + fmt(b.last_ledger) +
            ", " + fmt(b.ledgers) + " ledgers, " + fmt(b.transactions) + " transactions",
          "aria-label": "Protocol " + b.protocol + ", ledgers " + fmt(b.first_ledger) + " to " + fmt(b.last_ledger) },
          w > 2.6 ? String(b.protocol) : "");
      })),
      h("div", { class: "ticks", "aria-hidden": "true" }, [0, 10e6, 20e6, 30e6, 40e6, 50e6, 60e6, hi].map((l) =>
        h("span", { style: "left:" + pct(Math.max(l, lo)).toFixed(3) + "%" }, l === hi ? compact(hi) : l === 0 ? "ledger 2" : compact(l))))),
    h("span", { class: "val" }, "rarest arm"));

  const rows = d.corpus.rows.filter((x) => x.protocol !== null);
  const list = h("div", { role: "list" });
  const count = h("p", { class: "count", "aria-live": "polite" });

  function rowEl(x) {
    const p = x.prevalence;
    const track = h("div", { class: "track" }, bands());
    if (p.activation_ledger !== null) track.append(h("span", { class: "act", style: "left:" + pct(p.activation_ledger).toFixed(3) + "%",
      title: p.activation_protocol === x.protocol ? "protocol " + x.protocol + " from ledger " + fmt(p.activation_ledger)
        : "pubnet has no protocol " + x.protocol + " ledger; protocol " + p.activation_protocol + " from ledger " + fmt(p.activation_ledger) }));
    let val, tip;
    if (p.first_ledger !== null) {
      const l = pct(p.first_ledger), w = Math.max(pct(p.last_ledger) - l, 0.2);
      tip = capLabel(x.group) + ": first seen at ledger " + fmt(p.first_ledger) + ", last at " + fmt(p.last_ledger) +
        "; " + p.arms_seen + " of " + p.arms_joined + " joined union arms seen; the rarest occurs " + fmt(p.rarest_occurrences) + " times";
      track.append(h("span", { class: "span", style: "left:" + l.toFixed(3) + "%;width:" + w.toFixed(3) + "%" }),
        h("span", { class: "first", style: "left:" + l.toFixed(3) + "%" }));
      val = fmt(p.rarest_occurrences) + "×";
    } else if (x.after_scan) {
      tip = capLabel(x.group) + ": protocol " + x.protocol + " came after the scanned range (protocols " + scan.protocol_min + " to " + scan.protocol_max + ")";
      track.append(h("span", { class: "none" }, "after the scanned range (protocol " + x.protocol + ")"));
      val = "—";
    } else if (p.arms_seen_any) {
      tip = capLabel(x.group) + ": the " + p.arms_seen_any + " joined union arms its entries hold that occur on pubnet all occur before protocol " +
        x.protocol + " reached it, so none of them dates this row";
      track.append(h("span", { class: "none" }, "held arms predate protocol " + x.protocol));
      val = "—";
    } else if (p.arms_joined) {
      tip = capLabel(x.group) + ": " + p.arms_joined + " joined union arms, none seen in the scan";
      track.append(h("span", { class: "none" }, "joined arms not seen in the scan"));
      val = "0 seen";
    } else {
      tip = capLabel(x.group) + ": no union arm of its entries is joined to the scan, so there is no mainnet count";
      track.append(h("span", { class: "none" }, "no mainnet count"));
      val = "no count";
    }
    return h("div", { class: "tl-row", role: "listitem", tabindex: "0", "data-tip": tip, "aria-label": tip },
      h("span", { class: "lab" }, h("a", { href: href("cap", x.group) }, capLabel(x.group)), " ", h("span", { class: "muted" }, x.title)),
      track, h("span", { class: "val" }, val));
  }

  function draw() {
    const q = state.q.toLowerCase();
    let xs = rows.filter((x) => (!q || (x.group + " " + capLabel(x.group) + " " + x.title).toLowerCase().includes(q))
      && (!state.seen || x.prevalence.first_ledger !== null));
    const key = {
      protocol: (x) => [x.protocol, x.group],
      first: (x) => [x.prevalence.first_ledger ?? Infinity, x.group],
      rarest: (x) => [x.prevalence.rarest_occurrences ?? Infinity, x.group],
    }[state.sort];
    xs = xs.slice().sort((a, b) => { const A = key(a), B = key(b); return A[0] - B[0] || (A[1] < B[1] ? -1 : 1); });
    list.replaceChildren(...xs.map(rowEl));
    count.textContent = xs.length + " of " + rows.length + " rows";
    setQuery({ q: state.q, sort: state.sort === "protocol" ? "" : state.sort, seen: state.seen ? "1" : "" });
  }

  put(root, 
    h("h1", null, "Ledger history"),
    h("p", { class: "lede" }, "Pubnet ledgers ", fmt(lo), " to ", fmt(hi), ", banded by the protocol in each ledger header. ",
      "For each CAP row: the grey tick is the ledger where its protocol reached pubnet; the amber bar runs from the first to ",
      "the last ledger holding one of the rare union arms its entries carry, counting only arms that first occur at or after ",
      "that tick, and the dot marks the first. The figure on the right is how often the rarest of those arms occurs."),
    notice("How to read it:", "Mainnet counts exist only for the " + fmt(d.summary.prevalence.arms) + " union arms that at most three " +
      "corpus inputs hold and that join to the scan by exact name (" + fmt(d.summary.prevalence.arms_seen) + " of them occur). " +
      "A row with no joined arm has no count, which is not the same as zero. The pipelines were not replayed over these ledgers."),
    h("div", { class: "controls" },
      search("Search CAPs", state.q, (v) => { state.q = v; draw(); }),
      select("Sort", "sort", [["protocol", "by protocol"], ["first", "by first mainnet ledger"], ["rarest", "rarest first"]],
        state.sort, (v) => { state.sort = v; draw(); }),
      checkbox("only rows with a mainnet count", state.seen, (v) => { state.seen = v; draw(); })),
    count,
    h("div", { class: "tl" }, axis, list),
    h("p", { class: "caption" }, "Sources: ", h("code", null, "evidence/mainnet-scan/census-facts.tsv"), " (bands), ",
      h("code", null, "apps/docs/data/cap-prevalence.json"), " (arms). The same rows as a table: ", h("a", { href: href("caps") }, "CAPs"), "."));
  draw();
  return "Ledger history";
}
