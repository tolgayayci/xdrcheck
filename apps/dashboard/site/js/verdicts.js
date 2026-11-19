// What the dashboard can say about one entry in one SDK family or pipeline. Run results (the conformance matrix
// and the replay summary under evidence/results/, folded per entry into corpus.json by the builder) win; without them
// the manifest's declared divergences are shown, and the page says so. A missing result is never shown as agreement.
import { h } from "./lib.js";

export const FAMILY_TEXT = { js: "JavaScript", go: "Go", rust: "Rust", python: "Python", java: "Java", core: "stellar-core",
  "xdr-json": "XDR-JSON", "soroban-spec": "contract spec", "wallet-backend": "wallet-backend", "stellar-etl": "stellar-etl", other: "other" };
const OUTCOME_TEXT = { reject: "rejects", rejects_valid: "rejects valid", accepts_invalid: "accepts invalid",
  wrong_value: "wrong value", encode_mismatch: "encodes differently", halt: "halts", dropped: "drops", partial_drop: "drops part",
  silent_drop: "drops silently", resource_exhaustion: "exhausts resources" };
export const outcomeText = (o) => OUTCOME_TEXT[o] || (o || "").replace(/_/g, " ");
export const ROLE_TEXT = { current: "current", prefix: "before fix", fixed: "after fix", reference: "reference" };

// "wallet-backend@2a0a84ea1252" -> "wallet-backend before fix 1 (2a0a84ea)", from the replay summary's pipeline table
export function pipelineLabel(meta, key) {
  const m = meta && meta[key];
  if (!m) return key;
  if (m.pipeline === "baseline") return "reference indexer " + (m.version || "");
  const v = m.tag || (m.commit || "").slice(0, 8);
  if (m.role === "prefix" || m.role === "fixed") return m.pipeline + " " + ROLE_TEXT[m.role] + " " + m.pair + " (" + v + ")";
  return m.pipeline + " " + v;
}

// Chips for an entry: one per SDK family and pipeline that has anything to say.
export function entryChips(d, e) {
  const out = [];
  const fams = Object.entries(e.sdk || {});
  if (d.corpus.sources.conformance) {
    for (const [f, [agrees, diverges, notRun]] of fams) {
      const n = agrees + diverges + notRun;
      if (diverges) out.push(h("span", { class: "chip sev-high", title: diverges + " of " + n + " " + f + " columns diverge" },
        (FAMILY_TEXT[f] || f) + " " + diverges + "/" + n + " diverge"));
      else if (agrees) out.push(h("span", { class: "chip c-agrees" }, (FAMILY_TEXT[f] || f) + " agree"));
    }
  } else {
    for (const dv of e.divergences.filter((x) => !x.pipeline)) {
      out.push(h("span", { class: "chip " + (dv.status === "open" ? "sev-high" : "sev-medium"),
        title: "declared in the manifest: " + (dv.versions || "") + (dv.fixed_in ? "; fixed in " + dv.fixed_in : "") },
      (FAMILY_TEXT[dv.family] || dv.family) + ": " + outcomeText(dv.outcome) + (dv.status === "open" ? "" : " (" + dv.status.replace(/_/g, " ") + ")")));
    }
  }
  if (d.corpus.sources.replay) {
    for (const [pk, worst] of Object.entries(e.replay || {})) {
      if (!worst || worst === "not-run") continue;
      out.push(h("span", { class: "chip " + (worst === "pass" ? "c-agrees" : "sev-high") },
        pk.split("@")[0] + "@" + pk.split("@")[1].slice(0, 8) + ": " + worst));
    }
  } else {
    for (const dv of e.divergences.filter((x) => x.pipeline)) {
      out.push(h("span", { class: "chip " + (dv.status === "open" ? "sev-high" : "sev-medium"),
        title: "declared in the manifest: " + (dv.versions || "") + (dv.fixed_in ? "; fixed in " + dv.fixed_in : "") },
      dv.family + ": " + outcomeText(dv.outcome) + (dv.status === "open" ? "" : " (" + dv.status.replace(/_/g, " ") + ")")));
    }
  }
  return out;
}

export function sourceNote(d) {
  const s = d.corpus.sources;
  const parts = [];
  parts.push(s.conformance ? "SDK cells from " + s.conformance : "SDK results: the manifest's declared divergences (the run's matrix is not in the repository yet)");
  parts.push(s.replay ? "pipeline cells from " + s.replay : "pipeline results: the manifest's declared divergences (the replay summary is not in the repository yet)");
  return parts.join("; ") + ".";
}

// Shell-quote an entry ID the way the builder's templates expect (IDs are [a-z0-9./-] in practice).
export const shq = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : "'" + s + "'");

// The commands that replay one entry, filled from the builder's templates.
export function entryCommands(d, e) {
  const T = d.corpus.cli;
  return (e.cli || []).map((k) => T[k]).filter(Boolean).map((t) => ({ what: t.what, cmd: t.cmd.replace("{id}", shq(e.id)) }));
}

export function commandBlock(d, cmds) {
  return [h("p", { class: "caption" }, d.corpus.cli_preface),
    h("div", { class: "cmds" }, cmds.map((c) => h("div", { class: "cmd" },
      h("span", { class: "what" }, c.what),
      h("pre", null, h("code", null, c.cmd)))))];
}
