// A minimal replay adapter in TypeScript: the same JSON protocol as go/adapters/minimal (`xcc.adapter/1`,
// docs/adapter-protocol.md), for an indexer written for Node. It reports receipts (the transaction count) and
// transactions (hash, index, successful, fee charged) — enough to catch an indexer that drops a ledger or a
// transaction, crashes, hangs or halts.
//
// The "indexer" here reads each ledger of the SEP-54 directory the harness serves with @stellar/stellar-sdk's
// XDR and keeps its facts in memory. Every place marked REPLACE is where your adapter calls your indexer
// instead. Node 24 runs this file as it is (type stripping); no build step.
//
//   node adapter.ts                                   speaks the protocol on stdin/stdout
//   xdrcheck replay --adapter "node examples/adapter-ts/adapter.ts" --selftest

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { zstdDecompressSync } from "node:zlib";
import { xdr } from "@stellar/stellar-sdk";

const PROTOCOL = "xcc.adapter/1";
const NAME = "ts-minimal"; // REPLACE: your adapter's name and version
const VERSION = "0.1.0";

type Range = { start: number; end: number };
type Transaction = { hash: string; index: number; successful: boolean; fee_charged: string };
type Ledger = { ledger_seq: number; ledger_hash: string; receipt?: { transactions: number }; transactions?: Transaction[] };
// REPLACE: your indexer's store (a database, a directory) and its own progress marker.
type Session = { ledgers: Map<number, Ledger>; cursor: number | null };

class ProtocolError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

const sessions = new Map<string, Session>();
const notModelled = { supported: false, reason: "the template maps receipts and transactions only" };

// describe: declare only what is true; every kind you do not model is not_applicable and costs nothing.
const DESCRIBE = {
  adapter: { name: NAME, version: VERSION },
  target: { name: "xdrcheck " + NAME + " indexer", version: VERSION, version_kind: "tag" },
  protocol_version: PROTOCOL,
  inputs: ["sep54-dir"], // REPLACE: the inputs your indexer reads (sep54-dir, sep54-s3, rpc)
  units: ["single", "chain", "stream"],
  envelope: {
    enforcement: "sdk_limit", max_protocol: 30, ledger_close_meta_versions: [0, 1, 2],
    basis: "@stellar/stellar-sdk 17.4.0 carries the XDR of protocol 30",
  },
  observations: {
    receipts: { supported: true, subkinds: ["transactions"] },
    transactions: { supported: true },
    participants: notModelled, state_changes: notModelled, movements: notModelled, addresses: notModelled,
  },
  requirements: { network: "none" },
};

function session(id: string): Session {
  const s = sessions.get(id);
  if (!s) throw new ProtocolError("unknown_session", `session ${id} was not prepared`);
  return s;
}

// The SEP-54 directory: every <partition>/<object>.xdr.zst holds a zstd-compressed LedgerCloseMetaBatch.
function readLake(dir: string): Map<number, xdr.LedgerCloseMeta> {
  const out = new Map<number, xdr.LedgerCloseMeta>();
  for (const entry of readdirSync(dir, { recursive: true, encoding: "utf8" })) {
    if (!entry.endsWith(".xdr.zst")) continue;
    const batch = xdr.LedgerCloseMetaBatch.fromXDR(zstdDecompressSync(readFileSync(join(dir, entry))));
    batch.ledgerCloseMetas.forEach((lcm, i) => out.set(batch.startSequence + i, lcm));
  }
  return out;
}

const hex = (h: { value: Uint8Array }) => Buffer.from(h.value).toString("hex");

// facts derives a ledger's receipt and transaction list from the ledger itself: the transaction results in
// apply order, each carrying its hash.
function facts(lcm: xdr.LedgerCloseMeta): Ledger {
  const v = lcm.value; // LedgerCloseMeta v0, v1 or v2: the fields read here are in all three
  const transactions: Transaction[] = v.txProcessing.map((meta, index) => {
    const pair = meta.result;
    const code = pair.result.result.type;
    return {
      hash: hex(pair.transactionHash), index,
      successful: code === "txSuccess" || code === "txFeeBumpInnerSuccess", // a fee bump: the inner transaction's outcome
      fee_charged: pair.result.feeCharged.toString(),
    };
  });
  return {
    ledger_seq: v.ledgerHeader.header.ledgerSeq, ledger_hash: hex(v.ledgerHeader.hash),
    receipt: { transactions: transactions.length }, transactions,
  };
}

// ingest: REPLACE with starting your indexer on the input and range, waiting for its progress marker to reach
// range.end (or for it to stop), and reporting the facts behind the status.
function ingest(p: any) {
  const s = session(p.session);
  const started = Date.now();
  const before = s.cursor;
  const range: Range = p.range;
  let failing: number | null = null;
  let error = "";
  try {
    const lake = readLake(p.input.path);
    for (let seq = range.start; seq <= range.end; seq++) {
      const lcm = lake.get(seq);
      if (!lcm) throw Object.assign(new Error(`ledger ${seq} is not in the lake`), { seq });
      failing = seq;
      s.ledgers.set(seq, facts(lcm));
      s.cursor = seq;
      failing = null;
    }
  } catch (e: any) {
    failing = failing ?? e.seq ?? range.start;
    error = String(e?.message ?? e);
  }
  const done = error === "";
  return {
    status: done ? "completed" : "halted",
    last_ledger: s.cursor,
    signals: {
      cursor_before: before, cursor_after: s.cursor, process_exited: false, wall_ms: Date.now() - started,
      failing_ledger: done ? null : failing, phase: done ? null : "process", runtime_panic: false,
      rows_for_failing_ledger: done ? null : 0, ...(done ? {} : { stderr_tail: error.slice(0, 3000) }),
    },
  };
}

// observe: REPLACE with one query per kind against your store, each stored record mapped to one fact; a ledger
// you hold nothing for is left out (that is how drops are seen).
function observe(p: any) {
  const s = session(p.session);
  const kinds: Record<string, unknown> = {};
  for (const [kind, cap] of Object.entries(DESCRIBE.observations)) {
    kinds[kind] = !p.kinds.includes(kind) ? { status: "not_applicable", reason: "not requested" }
      : cap.supported ? { status: "provided" } : { status: "not_applicable", reason: (cap as { reason: string }).reason };
  }
  const ledgers: Ledger[] = [];
  for (let seq = p.range.start; seq <= p.range.end; seq++) {
    const l = s.ledgers.get(seq);
    if (!l) continue;
    const out: Ledger = { ledger_seq: l.ledger_seq, ledger_hash: l.ledger_hash };
    if (p.kinds.includes("receipts")) out.receipt = l.receipt;
    if (p.kinds.includes("transactions")) out.transactions = l.transactions;
    ledgers.push(out);
  }
  return { schema: "xcc.observation/v1", range: p.range, kinds, ledgers };
}

function dispatch(method: string, p: any): unknown {
  switch (method) {
    case "describe":
      if (!p.protocol_versions?.includes(PROTOCOL)) throw new ProtocolError("unsupported_protocol_version", `this adapter speaks ${PROTOCOL} only`);
      return DESCRIBE;
    case "prepare": // REPLACE: create a fresh, empty store under p.workdir
      sessions.set(p.session, { ledgers: new Map(), cursor: null });
      return { ready: true, target_version: VERSION, state: "clean" };
    case "ingest":
      if (!DESCRIBE.inputs.includes(p.input.kind)) throw new ProtocolError("unsupported_input", `input kind ${p.input.kind} is not supported`);
      if (p.unit && !DESCRIBE.units.includes(p.unit)) throw new ProtocolError("unsupported_unit", `unit ${p.unit} is not supported`);
      return ingest(p);
    case "observe":
      return observe(p);
    case "teardown": // REPLACE: drop your store
      sessions.delete(p.session);
      return { ok: true };
  }
  throw new ProtocolError("unknown_method", `unknown method ${method}`);
}

// One JSON request per line on stdin, one response per line on stdout, logs on stderr.
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (!line.trim()) return;
  let req: { id: number; method: string; params: unknown };
  try {
    req = JSON.parse(line);
  } catch (e) {
    console.error("unreadable request:", e);
    return;
  }
  const head = { xdrcheck: PROTOCOL, id: req.id, method: req.method };
  let resp: object;
  try {
    resp = { ...head, result: dispatch(req.method, req.params ?? {}) };
  } catch (e: any) {
    const code = e instanceof ProtocolError ? e.code : "internal";
    resp = { ...head, error: { code, message: String(e?.message ?? e).slice(0, 4000), retryable: false } };
    if (code === "unsupported_protocol_version") {
      process.stdout.write(JSON.stringify(resp) + "\n");
      lines.close();
      return;
    }
  }
  process.stdout.write(JSON.stringify(resp) + "\n");
});
