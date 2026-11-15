// The v16 JavaScript driver's own tests, run against one built version directory:
//
//   node test/run.mjs --driver <version dir>/bin/xdrcheck-driver --version 16.3.0
//
// The same sections as the v17 driver's tests (drivers/js/test/run.mjs), through the driver protocol, as the
// orchestrator would send it. Expected values come from outside the SDK under test: the executed cross-SDK probe
// (evidence/sdk-matrix: hand-encoded vectors and the recorded results of this SDK version, which the driver must
// reproduce), the sdk-regression cases of the conformance runner with the v16 behaviour that probe recorded, and the corpus
// (oracle-decoded sidecars and hand-written pinpoints). Sections:
//
//   protocol   describe, shutdown and malformed requests
//   probe      every probe vector of evidence/sdk-matrix with a driver mapping, against results/js_<version>.jsonl
//              (from a local probe run, or the overlay's file when XDRCHECK_OVERLAY is set; skipped without either)
//   sdk-regression  the sdk-regression cases a1–a7, b1–b5, c1–c4 on this version: the issuer-order fix is in 16.3.1, the
//              offer/muxed ID, map-order and lossy-map fixes of 17.2.1 and 17.3.0 are in no 16.x release
//              (probe vectors 1a–1f, 2m5, 2o1, 2o4, 4a, 5a, 5b)
//   corpus     every vendored ledger: L0, L1, L2 (whole projection equal to the oracle sidecar, and the
//              manifest's pinpoints)
//   schema     every response line validated against corpus/schema/driver-protocol.schema.json
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { zstdDecompressSync } from "node:zlib";

// A decoded sidecar's JSON; sidecars are stored zstd-compressed (decoded/<aa>/<sha>.json.zst).
function readSidecar(path) {
  const raw = readFileSync(path);
  return JSON.parse((path.endsWith(".zst") ? zstdDecompressSync(raw) : raw).toString("utf8"));
}

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const arg = (n) => {
  const i = process.argv.indexOf(n);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const driverPath = resolve(arg("--driver"));
const version = arg("--version");
const TAG = "xcc.driver/1";
const TESTNET = "Test SDF Network ; September 2015";

// ---- harness -------------------------------------------------------------------------------------------------

let failures = 0;
let checks = 0;
const section = (name) => console.log(`-- ${name}`);
function check(cond, what, detail) {
  checks++;
  if (!cond) {
    failures++;
    console.log(`FAIL ${what}${detail !== undefined ? `: ${detail}` : ""}`);
  }
  return cond;
}

const lines = []; // every response line, for the schema section
const proc = spawn(driverPath, [], { stdio: ["pipe", "pipe", "inherit"], cwd: dirname(dirname(driverPath)) });
const reader = createInterface({ input: proc.stdout, crlfDelay: Infinity })[Symbol.asyncIterator]();
let nextId = 0;
async function raw(line) {
  proc.stdin.write(line + "\n");
  const r = await reader.next();
  if (r.done) throw new Error("the driver closed its output");
  lines.push(r.value);
  return JSON.parse(r.value);
}
const call = (req) => raw(JSON.stringify({ xcc: TAG, id: ++nextId, ...req }));
const run = (entry, level, input, extra = {}) => call({ op: "run", entry, level, input, ...extra });
const xdrIn = (type, hex, extra = {}) => ({ kind: "xdr", xdr_type: type, xdr_hex: hex, ...extra });
const apiIn = (op, args) => ({ kind: "api", api_op: op, args });
const accepted = (r) => r.outcome === "ok" || r.outcome === "diverge";
const short = (r) => `${r.outcome}${r.reason ? `/${r.reason.code} ${r.reason.message ?? ""}` : ""}`.slice(0, 200);

// ---- protocol ------------------------------------------------------------------------------------------------

section("protocol");
const d = await call({ op: "describe" });
check(d.op === "describe" && d.id === nextId, "describe echoes op and id");
check(d.sdk?.package === "@stellar/stellar-sdk" && d.sdk?.ecosystem === "npm", "describe names the npm package");
check(d.sdk?.version === version, "describe reads the installed version", `${d.sdk?.version} != ${version}`);
check(/^sha512-/.test(d.sdk?.integrity ?? ""), "describe reports the registry integrity");
check(d.driver?.adapter === "js-v16", "describe names the v16 adapter");
check(d.sdk?.dependencies?.some((x) => x.package === "@stellar/js-xdr" && x.version === "4.0.0" && /^sha512-/.test(x.integrity ?? "")), "describe reports js-xdr 4.0.0");
check(JSON.stringify(d.levels) === '["L0","L1","L2","L3","L4","spec"]', "all five levels and spec");
check(d.decode?.default_depth === 200 && d.decode?.checks_consumed_length === true && d.decode?.entry_point === "xdr.<Type>.fromXDR", "decode: js-xdr 4 default depth 200, strict length");
const p30 = d.xdr_schema?.probes?.sc_address_type_muxed_contract === true && d.xdr_schema?.probes?.stellar_value_signed_ms === true;
// The LTS line got the Protocol 30 XDR in 16.4.1 (probe vectors 6g5 and 10l5540314).
check(p30 === (version === "16.4.1"), "Protocol 30 probes", JSON.stringify(d.xdr_schema));
// The reported protocol is the highest one the driver can prove: 30 with every Protocol 30 probe, 29 without
// one, none when the SDK declares enum members above the Protocol 30 ceiling (src/reach.mjs).
check(d.xdr_schema?.protocol === (p30 ? 30 : 29), "xdr_schema.protocol is the proven protocol", JSON.stringify(d.xdr_schema));
{
  const reach = await import("../src/reach.mjs");
  const all = { a: true, b: true };
  check(reach.schemaProtocol(all, []) === 30 && reach.schemaProtocol({ a: true, b: false }, []) === 29, "protocol from the probes");
  check(reach.schemaProtocol(all, ["ContractCostType 95"]) === undefined, "no protocol for XDR newer than the driver knows");
  check(reach.beyondKnown((e) => (e === "ScValType" ? [0, 22, 23] : [0])).join() === "ScValType 23", "a member above the ceiling is found");
  // Every ceiling enum resolves in this SDK, and a Protocol 30 SDK declares each ceiling member itself, so the
  // ceiling is neither misspelt nor set too high to notice a newer SDK.
  const { loadSDK } = await import("../src/sdk.mjs");
  const { xdr } = (await loadSDK(dirname(dirname(driverPath)))).S;
  const values = (e) => { const m = xdr[e]?._byValue; return m instanceof Map ? [...m.keys()] : Object.keys(m ?? {}).map(Number); };
  check(reach.beyondKnown(values).length === 0, "the SDK's XDR is not newer than Protocol 30", reach.beyondKnown(values).join());
  for (const [e, max] of Object.entries(reach.CEILING)) {
    const vs = values(e);
    check(vs.length > 0, `ceiling enum ${e} exists in the SDK`);
    if (p30) check(vs.includes(max), `${e} ${max} is declared by a Protocol 30 SDK`);
  }
}
check(!d.api_ops.includes("xdrjson.decode") && d.api_ops.includes("strkey.encode"), "api ops");
{
  // js-xdr 4 messages name no path: the driver locates the failing construct (probe vectors 6a, 6b, 6e, 6f).
  const codes = [
    ["0000000000000002", "bool_range"],
    ["000000100000000200000000", "optional_flag_range"],
    ["00000002000000010000ffff", "enum_undeclared"],
    ["00000063", "union_arm_undeclared"],
    ["0000000e0000000161010203", "nonzero_padding"],
    ["0000000100000000", "trailing_bytes"],
    ["0000000dffffffff", "length_exceeds_input"],
  ];
  for (const [h, code] of codes) {
    const r = await run(`x/reason-${code}`, "L0", xdrIn("ScVal", h));
    check(r.outcome === "reject" && r.reason.code === code && r.reason.error_class === "XdrReaderError", `L0 reason ${code}`, short(r));
  }
  const ext = await run("x/int-union", "L0", xdrIn("TransactionExt", "00000007"));
  check(ext.outcome === "reject" && ext.reason.code === "union_arm_undeclared", "an undeclared integer discriminant", short(ext));
  const w = await run("x/w-strkey", "L4", apiIn("strkey.encode", { type: "muxed_contract", payload_hex: "00".repeat(40) }));
  check(w.outcome === "n_a" && w.reason.code === "type_not_generated" && /encodeMuxedContract/.test(w.reason.message), "no muxed-contract strkeys in v16", short(w));
  // A listed op never answers op_not_supported: an unusable argument is the request's fault.
  for (const [op, args] of [["liquidity_pool.id", { asset_a: "native" }], ["muxed_account.decode", { address: "MA7Q" }], ["strkey.encode", { type: "account", payload_hex: "zz" }], ["transaction.hash", { xdr_hex: "00" }]]) {
    const r = await run(`x/bad-args-${op}`, "L4", apiIn(op, args));
    check(r.op === "protocol_error" && r.id === nextId, `${op} with unusable arguments → protocol_error`, JSON.stringify(r).slice(0, 200));
  }
  const md = await run("x/muxed-decode", "L4", apiIn("muxed_account.decode", { text: "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAACCRFU" }));
  check(md.outcome === "ok" && md.actual.api.value.id === "16" && md.actual.api.value.account === "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ", "muxed_account.decode takes text", short(md));
  const cmp = await run("x/compare", "L4", apiIn("asset.compare", { asset_a: "native", asset_b: "native" }));
  check(cmp.outcome === "ok" && cmp.actual.api.value === 0, "asset.compare value is an integer", short(cmp));
  const tn = await run("x/to-native-map", "L4", apiIn("scval.to_native", { xdr_hex: "0000001100000001000000020000000300000001000000030000000a0000000f00000001310000000000000300000014" }));
  check(tn.outcome === "ok" && tn.actual.api.value.map_entries === 1, "scval.to_native of a map → {map_entries}", short(tn));
  // Typedefs js-xdr 4 resolves away still project by their own names: a PoolId is an L… strkey, a Hash hex.
  const pool = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a";
  const lk = await run("x/pool-key", "L2", xdrIn("LedgerKey", "00000005" + pool));
  check(lk.outcome === "ok" && lk.actual.projection?.liquidity_pool?.liquidity_pool_id === "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN", "PoolId projects as L…", JSON.stringify(lk.actual));
  const hh = await run("x/hash", "L2", xdrIn("Hash", pool));
  check(hh.outcome === "ok" && hh.actual.projection === pool, "Hash projects as hex", JSON.stringify(hh.actual));
}
{
  const e = await raw("this is not json");
  check(e.op === "protocol_error", "not JSON → protocol_error");
  const u = await call({ op: "frobnicate" });
  check(u.op === "protocol_error" && u.id === nextId, "unknown op → protocol_error with the id");
  const n = await run("x/unknown-op", "L4", apiIn("xdrjson.decode", {}));
  check(n.outcome === "n_a" && n.reason.code === "op_not_supported", "an op the driver lacks → n_a/op_not_supported");
  const v = await call({ op: "run", entry: "x/echo", variant: "none", profile: "p", level: "L0", input: xdrIn("ScVal", "00000001") });
  check(v.variant === "none" && v.profile === "p" && v.entry === "x/echo" && v.outcome === "ok", "run echoes entry, variant, profile", short(v));
  const t = await run("x/type", "L0", xdrIn("NoSuchType", "00"));
  check(t.outcome === "n_a" && t.reason.code === "type_not_generated", "unknown XDR type → n_a/type_not_generated");
  const rm = await run("x/framed", "L0", xdrIn("ScVal", "8000000400000001", { framing: "record-marked", frame_index: 0 }));
  check(rm.outcome === "ok" && rm.actual.consumed_bytes === 4, "record-marked framing", short(rm));
}

// ---- probe ---------------------------------------------------------------------------------------------------

section("probe (evidence/sdk-matrix)");
const probeDir = join(root, "evidence/sdk-matrix");
const vectors = JSON.parse(readFileSync(join(probeDir, "vectors/vectors.json"), "utf8"));
// The result files are not committed: a local probe run's file, and with XDRCHECK_OVERLAY set the overlay's file of the
// same name. With neither, the section is skipped.
const resultDirs = [join(probeDir, "results"), ...(process.env.XDRCHECK_OVERLAY ? [join(process.env.XDRCHECK_OVERLAY, "evidence/sdk-matrix/results")] : [])];
const results = new Map(
  resultDirs
    .map((d) => join(d, `js_${version}.jsonl`))
    .filter((f) => existsSync(f))
    .flatMap((f) => readFileSync(f, "utf8").split("\n"))
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .map((r) => [r.vector, r]),
);
const manifests = [];
(function walk(dir) {
  for (const f of readdirSync(dir).sort()) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith(".json")) manifests.push(JSON.parse(readFileSync(p, "utf8")));
  }
})(join(root, "corpus/manifest"));
const byLedger = new Map();
for (const e of manifests) for (const v of e.variants ?? []) if (v.ledger_seq) byLedger.set(v.ledger_seq, v);

const u64hex = (s) => BigInt(s).toString(16).padStart(16, "0");
const numberOrString = (p) => (p.kind === "number" ? { native: "number", value: p.value } : p.value);

// Each mapping returns [level, input, value(r) → the probe's "got", or undefined when not compared].
function mapVector(v) {
  const p = v.params ?? {};
  const g = v.group;
  if (g === 1 && v.id !== "1c") {
    return ["L4", apiIn("liquidity_pool.id", { asset_a: `${p.code}:${p.a}`, asset_b: `${p.code}:${p.b}` }), (r) => r.actual.api.value];
  }
  if (v.id === "1c") {
    return ["L1", xdrIn("TransactionEnvelope", v.hex, { passphrase: p.network, focus: { op_index: 2 } }),
      (r) => `hash=${r.actual.object.tx_hash} pool=${r.actual.object.derived.pool_id}`];
  }
  if (g === 2 && v.id.startsWith("2m")) {
    return ["L4", apiIn("muxed_account.encode", { account: p.g, id: numberOrString(p) }),
      (r) => BigInt("0x" + r.actual.api.xdr_hex.slice(8, 24)).toString()];
  }
  if (g === 2) {
    return ["L4", apiIn("offer.manage_sell", { offer_id: numberOrString(p), buying: `USD:${p.g}` }), (r) => r.actual.api.value];
  }
  if (g === 3) return ["L1", xdrIn("TransactionEnvelope", v.hex, { passphrase: p.network }), undefined];
  if (g === 4) return ["L3", xdrIn("ScVal", v.hex), (r) => `entries=${r.actual.native.map_entries}`];
  if (v.id === "5a") {
    return ["L4", apiIn("scval.from_native", { value: { 10: 1, 9: 2 }, type: { 10: ["u32", "u32"], 9: ["u32", "u32"] } }), (r) => r.actual.api.value.join(",")];
  }
  if (g === 5) return ["L4", apiIn("scval.sort_map", { keys: p.keys }), (r) => r.actual.api.value.join(",")];
  if (v.id === "6d2") return ["L1", xdrIn("TransactionEnvelope", v.hex, { passphrase: p.network }), undefined];
  if (g === 6 || g === 8) return ["L0", xdrIn(p.type, v.hex), undefined];
  if (v.id === "7a") return ["L4", apiIn("memo.text_roundtrip", { xdr_hex: v.hex }), (r) => r.actual.api.xdr_hex];
  if (v.id === "7b") return ["L4", apiIn("operation.object_roundtrip", { xdr_hex: v.hex }), (r) => r.actual.api.xdr_hex];
  if (v.id === "7c" || v.id === "7d") return ["L4", apiIn("scval.native_roundtrip", { xdr_hex: v.hex }), (r) => r.actual.api.xdr_hex];
  if (v.id === "9E1") return ["L4", apiIn("strkey.encode", { type: "muxed_contract", payload_hex: p.contract + u64hex(p.id) }), (r) => r.actual.api.value];
  if (v.id === "9E2") return ["L4", apiIn("address.from_sc_address", { xdr_hex: v.hex }), (r) => r.actual.api.value];
  if (v.id === "9E3") return ["L4", apiIn("strkey.encode", { type: "signed_payload", payload_hex: p.key + "00000000" }), (r) => r.actual.api.value];
  if (v.id === "9E4") return ["L4", apiIn("address.to_strkey", { xdr_hex: v.hex }), (r) => r.actual.api.value];
  if (g === 9) return ["L4", { kind: "strkey", text: p.s }, (r) => r.actual.api.value];
  if (g === 10) {
    const lv = byLedger.get(Number(v.id.slice(3)));
    if (!lv) return undefined;
    return ["L0", { kind: "xdr", xdr_type: lv.xdr_type, path: join(root, "corpus", lv.blob.path) }, undefined];
  }
  return undefined;
}

const probeClass = { ok: "accept", wrong: "accept", reject: "reject", "n/a": "n_a", crash: "crash" };
const driverClass = (r) => (accepted(r) ? "accept" : r.outcome);
let mapped = 0;
for (const v of vectors) {
  const want = results.get(v.id);
  const m = mapVector(v);
  if (!want || !m) continue;
  mapped++;
  const [level, input, got] = m;
  const r = await run(`probe/${v.id}`, level, input);
  if (r.outcome === "n_a" && r.reason?.code === "argument_type_not_accepted") {
    // The SDK's declaration of the parameter does not take the tag's kind (MuxedAccount's id is a string); the
    // probe passed it anyway and the SDK refused it at run time. The driver no longer passes it.
    check(want.outcome === "reject", `probe ${v.id} (${level}): argument_type_not_accepted only where the SDK refused the kind`, `probe ${want.outcome} ${want.detail ?? ""}`);
    continue;
  }
  const ok = check(driverClass(r) === probeClass[want.outcome], `probe ${v.id} (${level}) outcome`, `driver ${short(r)}, probe ${want.outcome} ${want.detail ?? ""}`);
  if (ok && got && accepted(r) && want.got !== undefined && !String(want.got).startsWith("decoded")) {
    let value;
    try {
      value = got(r);
    } catch (e) {
      value = `(${e.message})`;
    }
    check(String(value) === String(want.got), `probe ${v.id} value`, `driver ${value}, probe ${want.got}`);
  }
  if (ok && v.group === 3) check(r.outcome === "ok", `probe ${v.id}: object re-encode is byte-identical`, short(r));
  if (ok && v.group === 8 && r.outcome === "reject") check(r.reason.code === "depth", `probe ${v.id}: depth refusal`, short(r));
}
if (results.size === 0) {
  console.log(`   no probe results for ${version} (run evidence/sdk-matrix/run.sh, or set XDRCHECK_OVERLAY); skipped`);
} else {
  // Vectors with no row in the results read lower the bar by one each.
  check(mapped >= 100 - vectors.filter((v) => !results.has(v.id)).length, "probe vectors mapped", mapped);
  console.log(`   ${mapped} probe vectors`);
}

// ---- sdk-regression ------------------------------------------------------------------------------------------

section("sdk-regression");
// The issuer-order defect (sdk-regression/js-1766) is fixed in 16.3.1 (probe vectors 1a–1f); the map-order half of the same issue
// (5a, 5b), the unsafe offer/muxed IDs (sdk-regression/js-1785: 2o1, 2m5, 2o4) and the lossy map conversion (sdk-regression/js-1789: 4a) were
// fixed in 17.x only, so every 16.x release shows the pre-fix behaviour.
const preOrder = version === "16.3.0";
const sample = manifests.find((e) => e.id === "cap-0038/pool-issuers-order-by-bytes-not-strkey");
const sv = sample.variants[0];
const sampleIn = { kind: "xdr", xdr_type: sv.xdr_type, path: join(root, "corpus", sv.blob.path), passphrase: sv.passphrase, focus: { tx_index: sv.focus.tx_index, op_index: sv.focus.op_index } };
const FOCUS = "0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f";
const POOL = "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e";
{
  const r = await run(sample.id, "L1", sampleIn, { variant: "testnet" });
  const o = r.actual?.object ?? {};
  if (preOrder) {
    check(r.outcome === "reject" && r.reason.code === "ordering" && r.reason.entry_point === "TransactionBuilder.fromXDR", "a1 16.3.0 L1 reject/ordering", short(r));
    check(o.transactions === 19 && o.envelopes_parsed === 18, "a1 18 of 19 envelopes parse", JSON.stringify(o).slice(0, 200));
    check(o.envelopes_rejected?.length === 1 && o.envelopes_rejected[0].tx_hash === FOCUS && o.envelopes_rejected[0].tx_index === sv.focus.tx_index &&
      o.envelopes_rejected[0].message === "Assets are not in lexicographic order", "a1 exactly the focus transaction is rejected", JSON.stringify(o.envelopes_rejected));
  } else {
    check(r.outcome === "ok" && o.envelopes_parsed === 19 && o.transactions === 19, "a2 L1 ok, 19 envelopes", short(r));
    const f = o.focus ?? {};
    check(f.tx_hash === FOCUS && f.derived?.pool_id === POOL, "a2 focus hash and derived pool ID", JSON.stringify(f));
    check(JSON.stringify(o.tx_hashes) === JSON.stringify(sv.derived.tx_hashes), "a2 every envelope's hash, in apply order");
    check(f.operation_types?.[sv.focus.op_index] === "change_trust" && f.derived?.operation_type === "change_trust", "a2 operation types in XDR-JSON spelling", JSON.stringify(f.operation_types));
  }
  const r0 = await run(sample.id, "L0", sampleIn, { variant: "testnet" });
  check(r0.outcome === "ok" && r0.actual.consumed_bytes === sv.blob.bytes && r0.actual.reencoded_sha256 === sv.blob.sha256, "a3 L0 byte-identical re-encode", short(r0));
}
{
  const iss = ["GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL", "GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO"];
  const a4 = await run("cap-0038/api-liquidity-pool-issuer-ordering.network-order", "L4", apiIn("liquidity_pool.id", { asset_a: `USD:${iss[0]}`, asset_b: `USD:${iss[1]}` }));
  const a5 = await run("cap-0038/api-liquidity-pool-issuer-ordering.reversed-order", "L4", apiIn("liquidity_pool.id", { asset_a: `USD:${iss[1]}`, asset_b: `USD:${iss[0]}` }));
  if (preOrder) {
    check(a4.outcome === "reject" && a4.reason.code === "ordering", "a4 16.3.0 refuses the network order", short(a4));
    check(a5.outcome === "ok" && a5.actual.api.value === "c1324f878b3d11af9f923abb7d692fc74e0a7bcfd9a4edefd564efe5fdae9fdb", "a5 16.3.0 accepts the reversed order", short(a5));
  } else {
    check(a4.outcome === "ok" && a4.actual.api.value === POOL, "a4 network order → pool ID", short(a4));
    check(a5.outcome === "reject", "a5 reversed order refused", short(a5));
  }
  const a6 = await run("cap-0046/api-scval-map-sort-order.u32-keys", "L4", apiIn("scval.from_native", { value: { 10: 1, 9: 2 }, type: { 10: ["u32", "u32"], 9: ["u32", "u32"] } }));
  check(a6.outcome === "ok" && a6.actual.api.value.join(",") === "u32:10,u32:9", "a6 u32 key order (pre-fix on 16.x)", short(a6) + JSON.stringify(a6.actual?.api?.value));
  const a7 = await run("cap-0046/api-scval-map-sort-order.bytes-keys", "L4", apiIn("scval.sort_map", { keys: ["bytes:0a", "bytes:09"] }));
  check(a7.outcome === "ok" && a7.actual.api.value.join(",") === "bytes:0a,bytes:09", "a7 byte key order (pre-fix on 16.x)", JSON.stringify(a7.actual?.api?.value));
}
{
  const G = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
  const b1 = await run("classic/api-offer-id-encoding.id-2-pow-53-plus-1-number", "L4", apiIn("offer.manage_sell", { offer_id: { native: "number", value: "9007199254740993" } }));
  check(b1.outcome === "ok" && b1.actual.api.value === "9007199254740992", "b1 16.x accepts the unsafe number, encodes …992", short(b1));
  const b3 = await run("classic/api-offer-id-encoding.id-string-control", "L4", apiIn("offer.manage_sell", { offer_id: "9007199254740993" }));
  check(b3.outcome === "ok" && b3.actual.api.value === "9007199254740993", "b3 the decimal string is exact", short(b3));
  const b4 = await run("cap-0027/api-muxed-account-id-encoding.id-hex-string", "L4", apiIn("muxed_account.encode", { account: G, id: "0x10" }));
  check(b4.outcome === "ok" && b4.actual.api.value === "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAACCRFU", "b4 16.x encodes \"0x10\" as ID 16", short(b4));
  const b5 = await run("classic/api-offer-id-encoding.id-negative", "L4", apiIn("offer.manage_sell", { offer_id: { native: "number", value: "-5" } }));
  check(b5.outcome === "ok" && b5.actual.api.value === "-5", "b5 16.x encodes −5", short(b5));
}
{
  // The value of js-stellar-sdk#1789: an ScMap with keys U32(1) and Symbol("1").
  const c = "0000001100000001000000020000000300000001000000030000000a0000000f00000001310000000000000300000014";
  const c1 = await run("cap-0046/scval-map-keys-collide-u32-symbol", "L3", xdrIn("ScVal", c));
  check(c1.outcome === "ok" && c1.actual.native.map_entries === 1, "c1 16.x drops an entry", short(c1));
  const c3 = await run("cap-0046/scval-map-keys-collide-u32-symbol", "L0", xdrIn("ScVal", c));
  check(c3.outcome === "ok" && c3.actual.consumed_bytes === c.length / 2, "c3 L0 control", short(c3));
  const c4hex = "0000001100000001000000030000000300000001000000030000000a0000000e0000000131000000000000030000001e0000000f00000001310000000000000300000014";
  const c4 = await run("cap-0046/scval-map-keys-collide-three-types.u32-string-symbol", "L3", xdrIn("ScVal", c4hex));
  check(c4.outcome === "ok" && c4.actual.native.map_entries === 1, "c4 16.x keeps 1 entry of 3", short(c4));
}

// ---- custom union and argument types -------------------------------------------------------------------------

section("xdr.custom_union_encode, argument types");
{
  // js-xdr#162 with the js-xdr 4 bundled into the SDK: a float discriminant encodes, and its own decoder refuses it.
  const f = await run("xdr-strict/api-float-union-discriminant-custom-schema", "L4", apiIn("xdr.custom_union_encode",
    { switch_on: "float", cases: [{ discriminant: { native: "number", value: "0.1" }, arm: "void" }], discriminant: { native: "number", value: "0.1" } }));
  check(f.outcome === "diverge" && f.reason.code === "own_output_rejected" && f.actual.api.xdr_hex === "3dcccccd" && f.actual.api.self_decode === "rejected",
    "a float discriminant: encoded, then refused by its own decoder", JSON.stringify(f).slice(0, 200));
  const i = await run("types/int-union", "L4", apiIn("xdr.custom_union_encode", {
    switch_on: "int", cases: [{ discriminant: { native: "number", value: "1" }, arm: "void" }, { discriminant: { native: "number", value: "2" }, arm: "int" }],
    discriminant: { native: "number", value: "2" }, value: { native: "number", value: "5" } }));
  check(i.outcome === "ok" && i.actual.api.value === "2" && i.actual.api.xdr_hex === "0000000200000005", "an int union round-trips", JSON.stringify(i).slice(0, 200));
  const G = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
  for (const [op, args] of [["muxed_account.encode", { account: G, id: { native: "bigint", value: "16" } }], ["offer.manage_sell", { offer_id: { native: "bigint", value: "16" } }]]) {
    const r = await run(`types/${op}`, "L4", apiIn(op, args));
    check(r.outcome === "n_a" && r.reason.code === "argument_type_not_accepted", `${op} with a bigint ID → n_a/argument_type_not_accepted (declared string / number | string)`, JSON.stringify(r).slice(0, 200));
  }
}

// ---- corpus --------------------------------------------------------------------------------------------------

section("corpus (vendored ledgers)");
const canon = (x) => JSON.stringify(x, (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((kk) => [kk, v[kk]])) : v));
const subst = (s, derived) =>
  typeof s === "string"
    ? s.replace(/\$\{derived\.([^}]+)\}/g, (_, path) => path.split(".").reduce((o, k) => (o == null ? o : o[k]), derived))
    : s;
const substDeep = (v, derived) =>
  Array.isArray(v) ? v.map((x) => substDeep(x, derived)) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substDeep(x, derived)])) : subst(v, derived);
// What this column is expected to do where it does not decode: a ledger cell is held to a known divergence the
// manifest declares for this target and version at that level (outcome and declared reason), and a cell awaiting
// a finding is acknowledged without an asserted outcome: an item of the committed pending list
// (findings/pending/conformance.json) or a report row a finding record lists in evidence.report_rows (findings/,
// and the private overlay's findings/ when XDRCHECK_OVERLAY names one), as `xdrcheck conform check` reads them. As in the
// orchestrator, a declared or acknowledged refusal at L0 leaves nothing to check at L1 and L2. Everything else
// must decode.
const TARGET = "@stellar/stellar-sdk";
const COLUMN = `js@${version}`;
const pendingKey = (...k) => k.join("\u0000");
const pending = new Set(
  JSON.parse(readFileSync(join(root, "findings/pending/conformance.json"), "utf8")).pending.map((p) => pendingKey(p.entry, p.variant, p.column, p.level)),
);
// Report rows read conform:<entry>:<variant or ->:<column>:<level>; a Rust column ID holds a colon itself.
for (const dir of [join(root, "findings"), ...(process.env.XDRCHECK_OVERLAY ? [join(process.env.XDRCHECK_OVERLAY, "findings")] : [])]) {
  if (!existsSync(dir)) continue;
  for (const id of readdirSync(dir).sort()) {
    const p = join(dir, id, "finding.json");
    if (!existsSync(p)) continue;
    for (const row of JSON.parse(readFileSync(p, "utf8")).evidence?.report_rows ?? []) {
      const parts = row.split(":");
      if (parts.length < 5 || parts[0] !== "conform") continue;
      pending.add(pendingKey(parts[1], parts[2] === "-" ? "" : parts[2], parts.slice(3, -1).join(":"), parts.at(-1)));
    }
  }
}
function parseVer(s) {
  const [core, ...pre] = s.trim().replace(/^v/, "").split("+")[0].split("-");
  const nums = core.split(".").map(Number);
  while (nums.length < 3) nums.push(0);
  return { nums, pre: pre.length ? pre.join("-") : null };
}
function cmpVer(a, b) {
  const x = parseVer(a);
  const y = parseVer(b);
  for (let i = 0; i < 3; i++) if (x.nums[i] !== y.nums[i]) return x.nums[i] < y.nums[i] ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre < y.pre ? -1 : 1;
}
// docs/manifest.md: alternatives joined by ||, each *, a hyphen range A - B, or space-separated comparators.
function inRange(ver, rng) {
  return rng.split("||").some((alt) => {
    alt = alt.trim();
    if (alt === "*") return true;
    if (alt.includes(" - ")) {
      const [lo, hi] = alt.split(" - ");
      return cmpVer(ver, lo) >= 0 && cmpVer(ver, hi) <= 0;
    }
    return alt.split(/\s+/).every((c) => {
      const op = [">=", "<=", ">", "<", "="].find((o) => c.startsWith(o)) ?? "";
      const d = cmpVer(ver, c.slice(op.length));
      return { "": d === 0, "=": d === 0, "<": d < 0, "<=": d <= 0, ">": d > 0, ">=": d >= 0 }[op];
    });
  });
}
// The report's variant key: the network, with @protocol when the entry's variants differ in protocol.
const variantKey = (e, v) => (e.variants.some((o) => o.protocol !== v.protocol) ? `${v.network}@${v.protocol}` : v.network);
// The known divergence declared for this column at the level, "pending", or null.
function expectedDivergence(e, key, level) {
  for (const k of e.conformance?.known_divergences ?? []) {
    if (k.target === TARGET && (k.level ?? level) === level && !k.profile && inRange(version, k.versions)) return k;
  }
  return pending.has(pendingKey(e.id, key, COLUMN, level)) ? "pending" : null;
}
// Checks a cell against its expected divergence; true when the divergence accounts for the cell, so the usual
// checks are skipped: a declared one always, an acknowledged one at L1 and L2, and at L0 when the cell refuses.
function held(label, level, r, exp, wantHash) {
  if (!exp) return false;
  if (exp === "pending") return level !== "L0" || r.outcome !== "ok";
  const want = exp.match?.reason;
  // A wrong value at L1 on a ledger is judged by the orchestrator from a fact the driver reports with outcome ok:
  // the focus transaction's rebuild fact (docs/conformance-protocol.md), which must then hash to another
  // transaction than the network's.
  const rb = r.actual?.object?.focus?.rebuild;
  if (level === "L1" && exp.outcome === "wrong_value" && r.outcome === "ok" && wantHash !== undefined) {
    check(rb?.outcome === "rebuilt" && rb.tx_hash !== wantHash, `${label} L1: the declared wrong_value: the rebuilt transaction hashes to another one`, JSON.stringify(rb));
    return true;
  }
  check(r.outcome === exp.outcome && (want === undefined || r.reason?.code === want), `${label} ${level}: the declared ${exp.outcome}${want ? `/${want}` : ""}`, short(r));
  return true;
}
let ledgers = 0;
for (const e of manifests.sort((a, b) => a.id.localeCompare(b.id))) {
  if (e.kind !== "ledger") continue;
  for (const v of e.variants) {
    ledgers++;
    const label = `${e.id} (${v.network}, protocol ${v.protocol})`;
    const key = variantKey(e, v);
    const input = { kind: "xdr", xdr_type: v.xdr_type, path: join(root, "corpus", v.blob.path), passphrase: v.passphrase };
    if (v.focus) input.focus = Object.fromEntries(Object.entries(v.focus).filter(([k]) => k === "tx_index" || k === "op_index"));
    const r0 = await run(e.id, "L0", input, { variant: key });
    // Beyond this schema's reach (a Protocol 30 ledger, no Protocol 30 types) known divergences are not evaluated.
    const beyondReach = !p30 && v.protocol >= 30;
    if (!beyondReach && held(label, "L0", r0, expectedDivergence(e, key, "L0"))) continue;
    if (r0.outcome !== "ok") {
      // Only a schema older than the ledger may refuse it, and only cleanly.
      check(!p30 && r0.outcome === "reject" && ["union_arm_undeclared", "enum_undeclared"].includes(r0.reason.code), `${label} L0`, short(r0));
      const r1 = await run(e.id, "L1", input, { variant: key });
      check(r1.outcome === "reject" && r1.reason.code === r0.reason.code, `${label} L1 refuses as L0 does`, short(r1));
      continue;
    }
    check(r0.actual.reencoded_sha256 === v.blob.sha256 && r0.actual.consumed_bytes === v.blob.bytes, `${label} L0 byte-identical`);
    const r1 = await run(e.id, "L1", input, { variant: key });
    const expectReject = held(label, "L1", r1, expectedDivergence(e, key, "L1"), v.derived?.tx_hash);
    if (!expectReject) {
      check(r1.outcome === "ok", `${label} L1`, short(r1));
      if (r1.outcome === "ok" && v.derived?.tx_hashes) {
        check(canon(r1.actual.object.tx_hashes) === canon(v.derived.tx_hashes), `${label} L1 transaction hashes in apply order`);
      }
      if (r1.outcome === "ok" && v.derived?.tx_hash) check(r1.actual.object.focus?.tx_hash === v.derived.tx_hash, `${label} L1 focus hash`);
      // The rebuild fact: reported for every focus transaction; a rebuilt one is the network's transaction.
      if (r1.outcome === "ok" && v.derived?.tx_hash && input.focus?.tx_index !== undefined) {
        const rb = r1.actual.object.focus?.rebuild;
        check(rb !== undefined && (rb.outcome !== "rebuilt" || rb.tx_hash === v.derived.tx_hash) && rb.outcome !== "refused", `${label} L1 focus rebuild`, JSON.stringify(rb));
      }
      // Every derived fact the manifest states for the focus is reported, with the oracle's value.
      if (r1.outcome === "ok" && v.derived?.l1 && v.focus?.tx_index !== undefined) {
        const fd = r1.actual.object.focus?.derived;
        for (const [k, w] of Object.entries(v.derived.l1)) check(fd?.[k] === w, `${label} L1 focus.derived.${k}`, JSON.stringify(fd));
      }
    }
    const r2 = await run(e.id, "L2", input, { variant: key });
    if (held(label, "L2", r2, expectedDivergence(e, key, "L2"))) continue;
    const oracle = readSidecar(join(root, "corpus", v.decoded));
    check(r2.outcome === "ok" && canon(r2.actual.projection) === canon(oracle), `${label} L2 projection equals the oracle sidecar`);
    // Key-selected pinpoints (`select`) reach a driver only as plain pointers the orchestrator resolved.
    const values = [...(e.expect?.values ?? []), ...(v.expect?.values ?? [])].filter((x) => x.select === undefined);
    if (values.length) {
      const rp = await run(e.id, "L2", { ...input, pinpoints: values.map((x) => x.path) }, { variant: key });
      for (const [i, x] of values.entries()) {
        const pp = rp.actual?.pinpoints?.[i];
        check(pp?.found && canon(pp.value) === canon(substDeep(x.equals, v.derived ?? {})), `${label} L2 pinpoint ${x.path}`, JSON.stringify(pp).slice(0, 200));
      }
    }
  }
}
console.log(`   ${ledgers} ledger variants`);

// ---- shutdown and schema -------------------------------------------------------------------------------------

const bye = await call({ op: "shutdown" });
check(bye.op === "shutdown" && bye.ok === true, "shutdown");
await new Promise((res) => proc.on("exit", res));

section("schema");
{
  const py = [join(root, ".venv/bin/python"), "python3"].find((p) => p === "python3" || existsSync(p));
  const v = spawnSync(py, ["-I", join(here, "validate.py"), root], { input: lines.join("\n") + "\n", encoding: "utf8", maxBuffer: 1 << 30 });
  process.stdout.write(v.stdout ?? "");
  process.stderr.write(v.stderr ?? "");
  check(v.status === 0, `${lines.length} response lines validate against the driver protocol schema`, `exit ${v.status}`);
}

console.log(`js ${version}: ${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
