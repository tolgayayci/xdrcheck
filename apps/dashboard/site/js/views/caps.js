// CAPs: the list of coverage rows (#/caps), one row's page (#/cap/<row>) and one entry's page (#/entry/<id>).
import { h, put, fmt, href, capLabel, capRow, short, table, setQuery, search, select, checkbox, notice, sevChip, stateChip } from "../lib.js";
import { entryChips, sourceNote, FAMILY_TEXT, outcomeText, entryCommands, commandBlock } from "../verdicts.js";

const SRC = { "local-core": "local core", "core-golden": "core golden", history: "history", "history-archive": "archive",
  "contract-code": "contract code", synthetic: "synthetic" };

export default function caps(root, d, r) {
  if (r.view === "cap") return capPage(root, d, r.rest);
  if (r.view === "entry") return entryPage(root, d, r.rest);
  return capList(root, d, r);
}

function sourcesText(bySource) {
  return Object.entries(bySource).filter(([, v]) => v).map(([k, v]) => v + " " + (SRC[k] || k)).join(", ") || "—";
}

function capList(root, d, r) {
  const state = { q: r.q.get("q") || "", kind: r.q.get("kind") || "", gaps: r.q.get("gaps") === "1" };
  const body = h("tbody");
  const count = h("p", { class: "count", "aria-live": "polite" });
  function draw() {
    const q = state.q.toLowerCase();
    const rows = d.corpus.rows.filter((x) => (!q || (x.group + " " + capLabel(x.group) + " " + x.title).toLowerCase().includes(q))
      && (!state.kind || (state.kind === "cap" ? x.group.startsWith("cap-") : !x.group.startsWith("cap-")))
      && (!state.gaps || x.gap_reason));
    body.replaceChildren(...rows.map((x) => {
      const p = x.prevalence;
      return h("tr", null,
        h("td", null, h("a", { href: href("cap", x.group) }, capLabel(x.group))),
        h("td", null, x.title),
        h("td", { class: "num" }, x.protocol ?? "—"),
        h("td", { class: "num" }, fmt(x.entries.length)),
        h("td", null, sourcesText(x.by_source)),
        h("td", { class: "num" }, fmt(x.twins)),
        h("td", { class: "num" }, p.first_ledger !== null ? fmt(p.first_ledger) : x.after_scan ? "after scan" : "—"),
        h("td", { class: "num" }, x.findings.length ? h("a", { href: href("problems", "", { cap: x.group }) }, fmt(x.findings.length)) : "0"),
        h("td", null, x.gap_reason ? x.gap_reason : ""));
    }));
    count.textContent = rows.length + " of " + d.corpus.rows.length + " rows";
    setQuery({ q: state.q, kind: state.kind, gaps: state.gaps ? "1" : "" });
  }
  put(root, 
    h("h1", null, "CAPs"),
    h("p", { class: "lede" }, "The per-CAP coverage manifest: one row per CAP that changes what a ledger reader sees, plus rows for ",
      "protocol upgrade ledgers and cross-cutting encoding rules. Open a row for its entries, mainnet prevalence, SDK and ",
      "pipeline results and findings."),
    h("div", { class: "controls" },
      search("Search", state.q, (v) => { state.q = v; draw(); }),
      select("Rows", "kind", [["", "all rows"], ["cap", "CAPs"], ["other", "protocol and encoding rows"]], state.kind, (v) => { state.kind = v; draw(); }),
      checkbox("only rows with a stated gap", state.gaps, (v) => { state.gaps = v; draw(); })),
    count,
    h("div", { class: "tbl-wrap" }, h("table", { "aria-label": "Coverage rows" },
      h("thead", null, h("tr", null, ["Row", "Title", { t: "Protocol", c: "num" }, { t: "Entries", c: "num" }, "Sources",
        { t: "Twins", c: "num" }, { t: "First on pubnet", c: "num" }, { t: "Findings", c: "num" }, "Gap"].map((c) =>
        typeof c === "string" ? h("th", { scope: "col" }, c) : h("th", { scope: "col", class: c.c }, c.t)))),
      body)),
    h("p", { class: "caption" }, "Source: ", h("code", null, "corpus/coverage.json"), ". Twins: entries with both a testnet and a pubnet variant. ",
      "First on pubnet: the earliest ledger of a joined union arm that first occurs at or after the row's protocol (see ",
      h("a", { href: href("timeline") }, "Ledger history"), ")."));
  const G = d.corpus.golden;
  put(root, h("h2", { id: "golden" }, "Stellar-core's goldens"),
    h("p", null, "stellar-core's own test suite records the ledgers it closes (its golden set, at ", h("code", null, G.core_tag), "). Of the ",
      fmt(G.local_core_entries), " entries a local stellar-core generated, ", h("strong", null, fmt(G.transaction_tier)), " match a golden transaction ",
      "(the same structural skeleton and reduced shape tokens): only these count as mapped. For ", h("strong", null, fmt(G.operation_tier)), " more, every operation has a golden operation of the same shape; ",
      "this operation tier is reported separately, is not agreement of the entry and says nothing about the envelope, fee processing or transaction-level meta. The other ", fmt(G.no_golden), " have neither."),
    h("h3", null, "Golden operation shapes the corpus holds"),
    h("p", null, "The reverse view: of the ", fmt(G.shapes), " reduced operation shapes in the golden set, ", fmt(G.shapes_core_emitted),
      " are held by an entry whose bytes stellar-core emitted outside its own tests (a local core or network history), ", fmt(G.shapes_goldens_only),
      " only by imported golden entries, and ", fmt(G.shapes_not_held), " by no entry. A golden shape is a pattern of stellar-core's tests, not necessarily one a reader has trouble with."),
    table(["Operation", { t: "Golden shapes", cls: "num" }, { t: "Held by core-emitted entries", cls: "num" }, { t: "Only by imported goldens", cls: "num" },
      { t: "Not held", cls: "num" }, ""], G.by_operation.map((o) => h("tr", null, h("td", { class: "mono" }, o.op), h("td", { class: "num" }, fmt(o.shapes)),
      h("td", { class: "num" }, fmt(o.core_emitted)), h("td", { class: "num" }, fmt(o.goldens_only)), h("td", { class: "num" }, fmt(o.not_held)),
      h("td", { style: "min-width:150px" }, h("span", { class: "stack", "aria-hidden": "true" },
        h("i", { class: "a", style: "width:" + (100 * o.core_emitted / o.shapes).toFixed(1) + "%" }),
        h("i", { class: "b", style: "width:" + (100 * o.goldens_only / o.shapes).toFixed(1) + "%" }))))), { label: "Golden operation shapes" }),
    h("p", { class: "caption" }, "Sources: ", h("code", null, "corpus/coverage.json"), ", ", h("code", null, "corpus/mirrors.json"), ", ",
      h("code", null, "corpus/COVERAGE.md"), " (section “Golden operation shapes”)."));
  draw();
  return "CAPs";
}

function capPage(root, d, group) {
  const x = d.rowByGroup.get(group);
  if (!x) {
    put(root, h("h1", null, "No such row"), h("p", null, "The corpus has no row “" + group + "”. ", h("a", { href: href("caps") }, "All rows.")));
    return "Not found";
  }
  const p = x.prevalence;
  const entries = x.entries.map((id) => d.entryById.get(id)).filter(Boolean);
  const findings = x.findings.map((id) => d.findingById.get(id)).filter(Boolean)
    .sort((a, b) => d.findings.severity_order.indexOf(a.severity) - d.findings.severity_order.indexOf(b.severity) || (a.id < b.id ? -1 : 1));
  put(root, 
    h("p", { class: "crumbs" }, h("a", { href: href("caps") }, "CAPs"), " / ", capLabel(group)),
    h("h1", null, capLabel(group), ": ", x.title),
    h("dl", { class: "kv" },
      h("dt", null, "Protocol"), h("dd", null, x.protocol ?? "—", x.after_scan ? " (after the scanned range)" : ""),
      h("dt", null, "Reader-visible"), h("dd", null, x.reader_visible ? "yes" : "no"),
      h("dt", null, "Entries"), h("dd", null, fmt(entries.length), " (", sourcesText(x.by_source), ")"),
      h("dt", null, "On both passphrases"), h("dd", null, fmt(x.twins), " entries"),
      x.mirrors ? [h("dt", null, "Golden skeleton mirrors"), h("dd", null, fmt(x.mirrors))] : null,
      x.gap_reason ? [h("dt", null, "Gap"), h("dd", null, x.gap_reason)] : null));

  put(root, h("h2", null, "Mainnet prevalence"));
  if (!p.arms_joined) {
    put(root, h("p", null, x.after_scan
      ? "Protocol " + x.protocol + " reached pubnet after the scanned range, so the scan holds none of its ledgers."
      : "No union arm held by this row's entries joins the scan by exact name, so there is no mainnet count for it. That is not a count of zero."));
  } else {
    put(root, h("p", null, p.activation_ledger !== null
      ? (p.activation_protocol === x.protocol ? ["Protocol ", x.protocol, " reached pubnet at ledger ", fmt(p.activation_ledger), ". "]
        : ["Pubnet has no protocol ", x.protocol, " ledger; protocol ", p.activation_protocol, ", the next it ran, reached it at ledger ", fmt(p.activation_ledger), ". "])
      : ["Protocol ", x.protocol, " came after the scanned range. "],
      "Rare union arms held by this row's entries, with how often the scan saw each. An arm first seen before the protocol ",
      "reached pubnet is held by an entry here but was not brought by this protocol."),
    table(["Union arm", { t: "Occurrences", cls: "num" }, { t: "Ledgers", cls: "num" }, { t: "First ledger", cls: "num" },
      { t: "Last ledger", cls: "num" }, "Note", "Entries"],
    p.arms.map((a) => h("tr", null, h("td", { class: "id" }, a.arm),
      h("td", { class: "num" }, a.seen ? fmt(a.occurrences) : "0"), h("td", { class: "num" }, a.seen ? fmt(a.ledgers) : "—"),
      h("td", { class: "num" }, a.seen ? fmt(a.first_ledger) : "—"), h("td", { class: "num" }, a.seen ? fmt(a.last_ledger) : "—"),
      h("td", null, !a.seen ? "not seen in the scan" : a.before_activation ? "first seen before this protocol" : ""),
      h("td", null, a.entries.map((id) => h("div", { class: "mono" }, d.entryById.has(id) ? h("a", { href: href("entry", id) }, id) : id))))),
    { label: "Union arms and their mainnet counts" }));
  }

  const gold = entries.filter((e) => e.golden);
  put(root, h("h2", null, "Replay this row yourself"), commandBlock(d, x.cli),
    h("p", { class: "caption" }, "Every entry page has the commands for that one entry, including the pipeline versions it ran on."));
  put(root, h("h2", null, "Entries"),
    h("p", { class: "caption" }, sourceNote(d), gold.length ? " Goldens: " + gold.filter((e) => e.golden === "transaction").length +
      " entries match a stellar-core golden transaction; for " + gold.filter((e) => e.golden === "operations").length + " more, every operation has a golden operation of the same shape (reported separately, not agreement of the entry)." : ""),
    table(["Entry", "Title", { t: "Protocol", cls: "num" }, "Source", "Networks", { t: "Rarest token on mainnet", cls: "num" }, "SDK and pipeline results"],
      entries.map((e) => h("tr", null,
        h("td", { class: "id" }, h("a", { href: href("entry", e.id) }, e.id)),
        h("td", null, e.title, " ", e.synthetic ? h("span", { class: "chip tag-syn" }, "synthetic") : null,
          e.risk_shapes.length ? h("span", { class: "chip tag-risk", title: "a rare shape behind a known upstream defect" }, "known-defect shape") : null),
        h("td", { class: "num" }, e.protocol ?? "—"),
        h("td", null, e.sources.map((s) => SRC[s] || s).join(", ") || "—"),
        h("td", null, e.networks.join(", "), e.twin ? h("span", { class: "chip", title: "testnet and pubnet variants" }, "twin") : null),
        h("td", { class: "num" }, rarityCell(e)),
        h("td", null, h("div", { class: "chips" }, entryChips(d, e)))))
      , { label: "Entries of " + capLabel(group) }));

  put(root, h("h2", null, "Findings tied to this row"));
  if (!findings.length) put(root, h("p", null, "None."));
  else put(root, findingTable(d, findings));
  const rules = x.rules.map((id) => d.ruleById.get(id)).filter(Boolean);
  if (rules.length) {
    put(root, h("h2", null, "Linter rules tied to these findings"),
      table(["Rule", "Reports", "Severity"], rules.map((ru) => h("tr", null, h("td", { class: "id" }, ru.id), h("td", null, ru.reports), h("td", null, ru.severity)))));
  }
  return capLabel(group);
}

export const GOLDEN_TEXT = {
  transaction: "its focus transaction matches a transaction of stellar-core's golden set: the same structural skeleton and the same reduced shape tokens",
  operations: "it matches no golden transaction; every operation of its focus transaction has a golden operation of the same reduced shape (the operation tier, reported separately and not agreement of the entry; it says nothing about the envelope, fee processing or transaction-level meta)",
};
function goldenText(d, e) {
  if (e.golden) return GOLDEN_TEXT[e.golden] + " (stellar-core " + d.corpus.golden.core_tag + ").";
  if (e.sources.includes("core-golden")) return "imported from stellar-core's golden set: the golden's own bytes.";
  if (e.sources.includes("local-core")) return "no golden transaction or operation of the same shape.";
  return "not compared (not generated by a local stellar-core).";
}

export function findingTable(d, findings) {
  return table(["Finding", "Title", "Component", "Severity", "State", "Upstream"], findings.map((f) => h("tr", null,
    h("td", { class: "id" }, h("a", { href: href("problems", "", { q: f.id }) }, f.id)),
    h("td", null, f.title),
    h("td", null, f.project),
    h("td", null, sevChip(f.severity)),
    h("td", null, stateChip(f.state)),
    h("td", null, f.upstream && f.upstream.kind === "filed" ? h("a", { href: f.upstream.url, rel: "noopener" }, "our issue")
      : f.upstream ? "known upstream" : "—"))), { label: "Findings" });
}

function entryPage(root, d, id) {
  const e = d.entryById.get(id);
  if (!e) {
    put(root, h("h1", null, "No such entry"), h("p", null, "The corpus has no entry “" + id + "”. ", h("a", { href: href("caps") }, "All rows.")));
    return "Not found";
  }
  const findings = e.findings.map((f) => d.findingById.get(f)).filter(Boolean);
  const shapeLabels = new Map(d.corpus.risk_shapes.map((s) => [s.key, s.label]));
  put(root, 
    h("p", { class: "crumbs" }, h("a", { href: href("caps") }, "CAPs"), " / ",
      e.rows.map((g, i) => [i ? ", " : "", h("a", { href: href("cap", g) }, capLabel(g))]), " / entry"),
    h("h1", { class: "mono", style: "font-size:clamp(18px,2.4vw,26px);word-break:break-all" }, e.id),
    h("p", { class: "lede" }, e.title),
    e.why ? h("p", null, e.why) : null,
    h("dl", { class: "kv" },
      h("dt", null, "CAPs"), h("dd", null, e.caps.length ? e.caps.map((c, i) => [i ? ", " : "", d.rowByGroup.has(capRow(c))
        ? h("a", { href: href("cap", capRow(c)) }, "CAP-" + String(c).padStart(4, "0")) : "CAP-" + String(c).padStart(4, "0")]) : "—"),
      h("dt", null, "Protocol introduced"), h("dd", null, e.protocol ?? "—"),
      h("dt", null, "Kind, validity"), h("dd", null, e.kind, ", ", e.validity, e.flags.length ? " (" + e.flags.join(", ") + ")" : ""),
      h("dt", null, "Synthetic"), h("dd", null, e.synthetic ? "yes: hand-made, not emitted by stellar-core" : "no"),
      h("dt", null, "Both passphrases"), h("dd", null, e.twin ? "yes: testnet and pubnet variants" : "no"),
      e.shapes.length ? [h("dt", null, "Shapes"), h("dd", null, h("div", { class: "chips" }, e.shapes.map((s) => h("span", { class: "chip" }, s))))] : null,
      e.risk_shapes.length ? [h("dt", null, "Shape behind a known defect"), h("dd", null, e.risk_shapes.map((k) => shapeLabels.get(k)).join("; "))] : null,
      h("dt", null, "stellar-core goldens"), h("dd", null, goldenText(d, e)),
      h("dt", null, "Manifest"), h("dd", { class: "mono" }, e.manifest)),
    entryPrevalence(d, e.id),
    h("h2", null, "Replay it yourself"),
    commandBlock(d, entryCommands(d, e)),
    h("h2", null, "Variants"),
    table(["Network", { t: "Protocol", cls: "num" }, { t: "Ledger", cls: "num" }, "Source", "XDR type", "Focus transaction"],
      e.variants.map((v) => h("tr", null, h("td", null, v.network), h("td", { class: "num" }, v.protocol), h("td", { class: "num" }, fmt(v.ledger_seq)),
        h("td", null, SRC[v.source] || v.source), h("td", { class: "mono" }, v.xdr_type), h("td", { class: "id" }, v.tx || "—"))), { label: "Variants" }),
    h("p", { class: "caption" }, "A variant from history carries the real ledger number on its network; a local-core variant's ledger is on a private standalone chain."),
    h("h2", null, "SDK and pipeline results"),
    h("p", { class: "caption" }, sourceNote(d)),
    h("div", { class: "chips" }, entryChips(d, e).length ? entryChips(d, e) : "Nothing declared for this entry."));
  if (e.divergences.length) {
    put(root, h("h3", null, "Declared divergences"),
      table(["Reader", "Level", "Outcome", "Versions", "Status", "Fixed in", "Finding"], e.divergences.map((v) => h("tr", null,
        h("td", null, FAMILY_TEXT[v.family] || v.family), h("td", null, v.level || "—"), h("td", null, outcomeText(v.outcome)),
        h("td", { class: "id" }, v.versions || "—"), h("td", null, (v.status || "").replace(/_/g, " ")),
        h("td", { class: "mono" }, short(v.fixed_in || "—", 12)),
        h("td", { class: "id" }, v.finding ? h("a", { href: href("problems", "", { q: v.finding }) }, v.finding) : "—"))), { label: "Declared divergences" }));
  }
  put(root, h("h2", null, "Findings"), findings.length ? findingTable(d, findings) : h("p", null, "None."));
  return e.id;
}


// Mainnet prevalence of the entry's rarest shape token (evidence/mainnet-scan/entry-prevalence.json).
export function prevalenceText(d, p) {
  if (!p) return "No mainnet count: the prevalence file has no row for this entry.";
  if (!p.walked) return "No mainnet count: the entry has no ledger-close-meta variant to walk (an SDK-level value or a bucket file), which is not the same as never seen.";
  const sc = d.corpus.entry_prevalence.scan;
  if (p.never_seen) return "Never seen on mainnet: its rarest shape token does not occur in pubnet ledgers " + fmt(sc.first_ledger) + " to " + fmt(sc.last_ledger) + ".";
  return "Its rarest shape token occurs " + fmt(p.occurrences) + (p.occurrences === 1 ? " time" : " times") + " on mainnet, between ledgers " + fmt(p.first_ledger) +
    " and " + fmt(p.last_ledger) + "; the entry's whole shape occurs at most that often.";
}

export function rarityCell(e) {
  const p = e.prevalence;
  if (!p || !p.walked) return h("span", { class: "muted" }, "no count");
  if (p.never_seen) return h("span", { class: "chip tag-never" }, "never seen");
  return h("span", { title: "ledgers " + fmt(p.first_ledger) + " to " + fmt(p.last_ledger) }, fmt(p.occurrences) + "×");
}

function entryPrevalence(d, id) {
  const e = d.entryById.get(id);
  const p = e.prevalence;
  return [h("h2", null, "How rare it is on mainnet"),
    h("p", null, prevalenceText(d, p)),
    p && p.walked ? h("dl", { class: "kv" },
      h("dt", null, "Rarest token"), h("dd", { class: "mono" }, p.token || "—"),
      p.rarest_tokens > 1 ? [h("dt", null, "Equally rare tokens"), h("dd", null, fmt(p.rarest_tokens))] : null,
      h("dt", null, "Tokens in its shape"), h("dd", null, fmt(p.tokens), p.tokens_unseen ? " (" + fmt(p.tokens_unseen) + " never seen on mainnet)" : ""),
      h("dt", null, "Counted in variant"), h("dd", { class: "mono" }, p.variant || "—")) : null,
    h("p", { class: "caption" }, "Source: ", h("code", null, d.corpus.sources.entry_prevalence || "—"),
      ". A count says where a shape occurs on mainnet; it says nothing about what any pipeline did with those ledgers. ",
      h("a", { href: href("rarity") }, "All entries by rarity"), ".")];
}
