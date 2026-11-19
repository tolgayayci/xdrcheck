// Expected-failure lists and the all-read check (docs/use-in-sdk-ci.md §7), in the format `xdrcheck conform run
// --expected-failures` reads: one item per line, `<entry> <variant or -> <level or unread>`, `#` starts a
// comment, blank lines are ignored. The runner records what the SDK did with each variant in a Results; compare
// passes only when the failures are exactly the list: a failure the list does not name is NEW-FAILURE, a listed
// cell that now conforms is UNEXPECTED-PASS (remove its line), a listed item of a selected entry the run never saw
// is NOT-RUN, and with requireAllRead a variant the SDK never read that the list does not name is NEW-UNREAD.
import { readFileSync } from "node:fs";
import { ToolError } from "./archive.mjs";

export const UNREAD = "unread";

const key = (entry, variant, level) => `${entry}\0${variant}\0${level}`;
const dash = (s) => (s ? s : "-");
const show = (f) => `${f.entry} ${dash(f.variant)} ${f.level}`;

/** Parse a list; `name` is used in errors. A line that is not three fields, or an item listed twice, is an error. */
export function parseExpectedFailures(text, name = "list") {
  const out = [];
  const seen = new Map();
  String(text)
    .split("\n")
    .forEach((raw, i) => {
      const fields = raw.replace(/#.*/, "").trim().split(/\s+/).filter(Boolean);
      if (fields.length === 0) return;
      if (fields.length !== 3) throw new ToolError(`${name}:${i + 1}: want \`<entry> <variant or -> <level or unread>\`, got ${JSON.stringify(raw.trim())}`);
      const f = { entry: fields[0], variant: fields[1] === "-" ? "" : fields[1], level: fields[2], line: i + 1 };
      const k = key(f.entry, f.variant, f.level);
      if (seen.has(k)) throw new ToolError(`${name}:${i + 1}: ${show(f)} is already listed on line ${seen.get(k)}`);
      seen.set(k, i + 1);
      out.push(f);
    });
  return out;
}

export function readExpectedFailures(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new ToolError(`${path}: ${e.message}`);
  }
  return parseExpectedFailures(text, path);
}

/** What a run did with each variant. */
export class Results {
  cells = [];
  unreads = [];
  selected = new Set();
  select(entry) {
    this.selected.add(entry);
  }
  pass(entry, variant, level) {
    this.select(entry);
    this.cells.push({ entry, variant, level, failed: false, detail: "" });
  }
  fail(entry, variant, level, detail) {
    this.select(entry);
    this.cells.push({ entry, variant, level, failed: true, detail });
  }
  unread(entry, variant, reason) {
    this.select(entry);
    this.unreads.push({ entry, variant, reason });
  }

  /** Compare with a list: { matched, newFailures, nowPassing, nowRead, newUnread, notRun, passed }. */
  compare(list, requireAllRead) {
    const r = { matched: 0, newFailures: [], nowPassing: [], nowRead: [], newUnread: [], notRun: [] };
    const listed = new Set(list.map((f) => key(f.entry, f.variant, f.level)));
    const present = new Set();
    for (const c of this.cells) {
      const k = key(c.entry, c.variant, c.level);
      present.add(k);
      present.add(key(c.entry, c.variant, UNREAD));
      if (c.failed && listed.has(k)) r.matched++;
      else if (c.failed) r.newFailures.push(c);
      else if (listed.has(k)) r.nowPassing.push(c);
    }
    const unread = new Set();
    for (const u of this.unreads) {
      const k = key(u.entry, u.variant, UNREAD);
      unread.add(k);
      present.add(k);
      if (listed.has(k)) r.matched++;
      else if (requireAllRead) r.newUnread.push(u);
    }
    for (const f of list) {
      const k = key(f.entry, f.variant, f.level);
      if (!present.has(k)) {
        if (this.selected.has(f.entry)) r.notRun.push(f);
      } else if (f.level === UNREAD && !unread.has(k)) {
        r.nowRead.push(f);
      }
    }
    r.passed = !r.newFailures.length && !r.nowPassing.length && !r.nowRead.length && !r.newUnread.length && !r.notRun.length;
    return r;
  }

  /** The results as a list file: header comments, then one sorted line per failure and unread variant. */
  writeExpectedFailures(name, corpusVersion) {
    const lines = [
      ...this.cells.filter((c) => c.failed).map((c) => [key(c.entry, c.variant, c.level), `${c.entry} ${dash(c.variant)} ${c.level}  # ${oneLine(c.detail)}`]),
      ...this.unreads.map((u) => [key(u.entry, u.variant, UNREAD), `${u.entry} ${dash(u.variant)} ${UNREAD}  # never read: ${oneLine(u.reason)}`]),
    ].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    return [
      `# Expected corpus failures of ${name} against corpus ${corpusVersion}.`,
      "# The run passes only when its failures are exactly these lines: a new failure fails, and so does a listed",
      "# cell that passes (remove its line when a bug is fixed).",
      "# <entry> <variant or -> <level>  # what the SDK did",
      "# <entry> <variant or -> unread   # a variant the SDK never reads",
      ...lines.map((l) => l[1]),
      "",
    ].join("\n");
  }
}

/** The comparison as text, the same lines `xdrcheck conform run --expected-failures` prints. */
export function formatComparison(r, name, listPath) {
  const out = [];
  for (const c of r.newFailures) out.push(`NEW-FAILURE   ${c.entry} ${dash(c.variant)} ${c.level}: ${c.detail}`);
  for (const c of r.nowPassing) out.push(`UNEXPECTED-PASS ${c.entry} ${dash(c.variant)} ${c.level}: listed as failing but now conforms; remove the line from ${listPath}`);
  for (const f of r.nowRead) out.push(`UNEXPECTED-PASS ${show(f)}: listed as unread but the column now reads it; remove the line from ${listPath}`);
  for (const u of r.newUnread) out.push(`NEW-UNREAD    ${u.entry} ${dash(u.variant)}: never read (${u.reason})`);
  for (const f of r.notRun) out.push(`NOT-RUN       ${show(f)} (${listPath} line ${f.line}): the run has no such cell; remove the line or fix its spelling`);
  out.push(
    `expected failures ${name}: ${r.matched} still as listed, ${r.newFailures.length} new failures, ${r.newUnread.length} new unread, ` +
      `${r.nowPassing.length + r.nowRead.length} unexpected passes, ${r.notRun.length} listed but not run`,
  );
  return out.join("\n");
}

function oneLine(s) {
  const t = String(s ?? "").split(/\s+/).filter(Boolean).join(" ");
  return t.length > 300 ? `${t.slice(0, 300)}…` : t;
}
