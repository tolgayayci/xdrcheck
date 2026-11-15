"""The Python driver's own tests, run against one built version directory:

    python -I test/run.py --driver <version dir>/bin/xdrcheck-driver --version 17.0.1 --root <repository root>

Everything goes through the driver protocol, as the orchestrator would send it. Expected values come from
outside the SDK under test: the executed cross-SDK probe (evidence/sdk-matrix: hand-encoded vectors and the
recorded results of this SDK version, which the driver must reproduce), and the corpus (oracle-decoded sidecars
and hand-written pinpoints). Sections:

  protocol   describe, shutdown and malformed requests
  probe      every probe vector of evidence/sdk-matrix with a driver mapping, against
             results/python_<version>.jsonl (from a local probe run, or the overlay's file when XDRCHECK_OVERLAY is set;
             skipped without either):
             outcome class, and the recorded value where the SDK accepted
  overlay    with XDRCHECK_OVERLAY set, the cases of <overlay>/drivers/python/selftest-cases.json
  types      argument types, and the issuer-order defect of 17.0.0 (rejects the network's pool) against its fix
             in 17.0.1
  api        every op in describe's api_ops answers (never n_a/op_not_supported); a missing argument is a
             protocol error
  corpus     every vendored ledger: L0, L1, L2 (whole projection equal to the oracle sidecar, and the
             manifest's pinpoints)
  schema     every response line validated against corpus/schema/driver-protocol.schema.json

Needs jsonschema and zstandard (scripts/py/requirements.txt), installed by `make test` into its own venv.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys

import jsonschema
import zstandard
from referencing import Registry, Resource

TAG = "xcc.driver/1"
TESTNET = "Test SDF Network ; September 2015"

ap = argparse.ArgumentParser()
ap.add_argument("--driver", required=True)
ap.add_argument("--version", required=True)
ap.add_argument("--root", required=True)
opts = ap.parse_args()
root = os.path.abspath(opts.root)
version = opts.version
driver = os.path.abspath(opts.driver)

failures = 0
checks = 0


def section(name):
    print(f"-- {name}", flush=True)


def check(cond, what, detail=None):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        print(f"FAIL {what}" + (f": {detail}" if detail is not None else ""), flush=True)
    return cond


lines = []  # every response line, for the schema section
proc = subprocess.Popen([driver], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=os.path.dirname(os.path.dirname(driver)))
next_id = 0


def raw(line):
    proc.stdin.write(line.encode() + b"\n")
    proc.stdin.flush()
    out = proc.stdout.readline()
    if not out:
        raise SystemExit("the driver closed its output")
    s = out.decode()
    lines.append(s.rstrip("\n"))
    return json.loads(s)


def call(req):
    global next_id
    next_id += 1
    return raw(json.dumps({"xcc": TAG, "id": next_id, **req}))


def run(entry, level, inp, **extra):
    r = call({"op": "run", "entry": entry, "level": level, "input": inp, **extra})
    return r


def xdr_in(typ, h, **extra):
    return {"kind": "xdr", "xdr_type": typ, "xdr_hex": h, **extra}


def api_in(op, args):
    return {"kind": "api", "api_op": op, "args": args}


def accepted(r):
    return r.get("outcome") in ("ok", "diverge")


def short(r):
    rs = r.get("reason") or {}
    return f"{r.get('outcome', r.get('op'))}/{rs.get('code', '')} {rs.get('message', r.get('error', ''))}"[:200]


def read_json(*p):
    with open(os.path.join(root, *p), encoding="utf-8") as f:
        return json.load(f)


def read_sidecar(path):
    with open(path, "rb") as f:
        data = f.read()
    if path.endswith(".zst"):
        data = zstandard.ZstdDecompressor().decompressobj().decompress(data)
    return json.loads(data)


# ---- protocol ------------------------------------------------------------------------------------------------

section("protocol")
d = call({"op": "describe"})
check(d.get("op") == "describe" and d.get("id") == next_id, "describe echoes op and id")
sdk = d.get("sdk", {})
check(sdk.get("package") == "stellar-sdk" and sdk.get("ecosystem") == "pypi", "describe names the PyPI package")
check(sdk.get("version") == version, "describe reads the installed version", f"{sdk.get('version')} != {version}")
want_wheel = None
with open(os.path.join(root, "drivers", "python", version, "requirements.txt")) as f:
    for ln in f:
        if ln.startswith(f"stellar-sdk=={version} "):
            want_wheel = "sha256:" + ln.split("--hash=sha256:")[1].split()[0]
check(sdk.get("integrity") == want_wheel, "describe reports the installed wheel's sha256", sdk.get("integrity"))
check(any(x.get("package") == "xdrlib3" and x.get("version") == "0.1.1" for x in sdk.get("dependencies", [])), "describe reports xdrlib3 0.1.1")
check(d.get("levels") == ["L0", "L1", "L2", "L3", "L4", "spec"], "all five levels and spec")
check(d.get("decode", {}).get("default_depth") == 512 and d["decode"].get("checks_consumed_length") is True,
      "decode: default depth 512, strict length")
probes = d.get("xdr_schema", {}).get("probes", {})
p30 = probes.get("sc_address_type_muxed_contract") is True and probes.get("stellar_value_signed_ms") is True
check(p30, "Protocol 30 probes", json.dumps(d.get("xdr_schema")))
# The reported protocol is the highest one the driver can prove: 30 with every Protocol 30 probe, 29 without
# one, none when the SDK declares enum members above the Protocol 30 ceiling (src/xdrcheck_driver/reach.py).
check(d.get("xdr_schema", {}).get("protocol") == (30 if p30 else 29), "xdr_schema.protocol is the proven protocol",
      json.dumps(d.get("xdr_schema")))
_spec = importlib.util.spec_from_file_location("reach", os.path.join(root, "drivers/python/src/xdrcheck_driver/reach.py"))
reach = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reach)
check(reach.schema_protocol({"a": True, "b": True}, []) == 30 and reach.schema_protocol({"a": True, "b": False}, []) == 29,
      "protocol from the probes")
check(reach.schema_protocol({"a": True}, ["ContractCostType 95"]) is None, "no protocol for XDR newer than the driver knows")
check(reach.beyond_known(lambda e: [0, 22, 23] if e == "SCValType" else [0]) == ["SCValType 23"],
      "a member above the ceiling is found")
API_OPS = d.get("api_ops", [])
e = raw("this is not json")
check(e.get("op") == "protocol_error", "not JSON -> protocol_error")
u = call({"op": "frobnicate"})
check(u.get("op") == "protocol_error" and u.get("id") == next_id, "unknown op -> protocol_error with the id")
n = run("x/unknown-op", "L4", api_in("price.encode", {}))
check(n.get("outcome") == "n_a" and n["reason"]["code"] == "op_not_supported", "an op the driver lacks -> n_a/op_not_supported")
v = call({"op": "run", "entry": "x/echo", "variant": "none", "profile": "p", "level": "L0", "input": xdr_in("ScVal", "00000001")})
check(v.get("variant") == "none" and v.get("profile") == "p" and v.get("entry") == "x/echo" and v.get("outcome") == "ok",
      "run echoes entry, variant, profile", short(v))
check(v.get("actual", {}).get("consumed_bytes") == 4 and len(v.get("actual", {}).get("reencoded_sha256", "")) == 64,
      "L0 ok carries consumed_bytes and reencoded_sha256")
t = run("x/type", "L0", xdr_in("NoSuchType", "00"))
check(t.get("outcome") == "n_a" and t["reason"]["code"] == "type_not_generated", "unknown XDR type -> n_a/type_not_generated")
rm = run("x/framed", "L0", xdr_in("ScVal", "8000000400000001", framing="record-marked", frame_index=0))
check(rm.get("outcome") == "ok" and rm["actual"]["consumed_bytes"] == 4, "record-marked framing", short(rm))
tr = run("x/trailing", "L0", xdr_in("ScVal", "0000000100000000"))
check(tr.get("outcome") == "reject" and tr["reason"]["code"] == "trailing_bytes" and
      tr.get("actual", {}).get("lenient_entry_points") == [{"entry_point": "xdr.SCVal.unpack", "accepted": True}],
      "trailing bytes: strict reject, lenient unpack listed", short(tr))

# ---- probe ---------------------------------------------------------------------------------------------------

section("probe (evidence/sdk-matrix)")
vectors = read_json("evidence", "sdk-matrix", "vectors", "vectors.json")
results = {}
OVERLAY = os.environ.get("XDRCHECK_OVERLAY") or None
for rdir in [os.path.join(root, "evidence", "sdk-matrix", "results")] + \
        ([os.path.join(OVERLAY, "evidence", "sdk-matrix", "results")] if OVERLAY else []):
    rpath = os.path.join(rdir, f"python_{version}.jsonl")
    if not os.path.exists(rpath):
        continue
    with open(rpath, encoding="utf-8") as f:
        for ln in f:
            if ln.strip():
                r = json.loads(ln)
                results[r["vector"]] = r

manifests = []
for dp, _, fs in os.walk(os.path.join(root, "corpus", "manifest")):
    for fn in sorted(fs):
        if fn.endswith(".json"):
            with open(os.path.join(dp, fn), encoding="utf-8") as f:
                manifests.append(json.load(f))
manifests.sort(key=lambda m: m["id"])
by_ledger = {}
for m in manifests:
    for vv in m.get("variants", []):
        if vv.get("ledger_seq"):
            by_ledger[vv["ledger_seq"]] = vv


def tagged_id(p):
    """The probe passed Python ints for numbers and decimal strings, and the text itself otherwise."""
    if p["kind"] == "number":
        return {"native": "number", "value": p["value"]}
    try:
        int(p["value"])
        return {"native": "bigint", "value": p["value"]}
    except ValueError:
        return p["value"]


def map_vector(vec):
    """[level, input, value(response) -> the probe's "got", or None when not compared]."""
    p = vec.get("params") or {}
    g, i, h = vec["group"], vec["id"], vec.get("hex")
    if g == 1 and i != "1c":
        return "L4", api_in("liquidity_pool.id", {"asset_a": f"{p['code']}:{p['a']}", "asset_b": f"{p['code']}:{p['b']}"}), \
            lambda r: r["actual"]["api"]["value"]
    if i == "1c":
        return "L1", xdr_in("TransactionEnvelope", h, passphrase=p["network"], focus={"op_index": 2}), \
            lambda r: f"hash={r['actual']['object']['tx_hash']} pool={r['actual']['object']['derived']['pool_id']}"
    if g == 2 and i.startswith("2m"):
        return "L4", api_in("muxed_account.encode", {"account": p["g"], "id": tagged_id(p)}), \
            lambda r: str(int(r["actual"]["api"]["xdr_hex"][8:24], 16))
    if g == 2:
        return "L4", api_in("offer.manage_sell", {"offer_id": tagged_id(p), "buying": f"USD:{p['g']}"}), \
            lambda r: r["actual"]["api"]["value"]
    if g == 3 or i == "6d2":
        return "L1", xdr_in("TransactionEnvelope", h, passphrase=p["network"]), None
    if g == 4:
        return "L3", xdr_in("ScVal", h), lambda r: f"entries={r['actual']['native']['map_entries']}"
    if g == 5:
        return "L4", api_in("scval.sort_map", {"keys": p["keys"]}), lambda r: ",".join(r["actual"]["api"]["value"])
    if g in (6, 8):
        return "L0", xdr_in(p["type"], h), (lambda r: r["actual"].get("reencoded_hex", h)) if g == 6 else None
    if i == "7a":
        return "L4", api_in("memo.text_roundtrip", {"xdr_hex": h}), lambda r: r["actual"]["api"]["xdr_hex"]
    if i == "7b":
        return "L4", api_in("operation.object_roundtrip", {"xdr_hex": h}), lambda r: r["actual"]["api"]["xdr_hex"]
    if i in ("7c", "7d"):
        return "L4", api_in("scval.native_roundtrip", {"xdr_hex": h}), lambda r: r["actual"]["api"]["xdr_hex"]
    if i == "9E1":
        payload = p["contract"] + int(p["id"]).to_bytes(8, "big").hex()
        return "L4", api_in("strkey.encode", {"type": "muxed_contract", "payload_hex": payload}), lambda r: r["actual"]["api"]["value"]
    if i == "9E2":
        return "L4", api_in("address.from_sc_address", {"xdr_hex": h}), lambda r: r["actual"]["api"]["value"]
    if i == "9E3":
        return "L4", api_in("strkey.encode", {"type": "signed_payload", "payload_hex": p["key"] + "00000000"}), \
            lambda r: r["actual"]["api"]["value"]
    if i == "9E4":
        return "L4", api_in("address.to_strkey", {"xdr_hex": h}), lambda r: r["actual"]["api"]["value"]
    if g == 9:
        return "L4", {"kind": "strkey", "text": p["s"]}, lambda r: r["actual"]["api"]["value"]
    if g == 10:
        lv = by_ledger.get(int(i[3:]))
        if lv is None:
            return None
        return "L0", {"kind": "xdr", "xdr_type": lv["xdr_type"], "path": os.path.join(root, "corpus", lv["blob"]["path"])}, None
    return None


PROBE_CLASS = {"ok": "accept", "wrong": "accept", "reject": "reject", "n/a": "n_a", "crash": "crash"}
mapped = 0
for vec in vectors:
    want = results.get(vec["id"])
    m = map_vector(vec)
    if want is None or m is None:
        continue
    mapped += 1
    level, inp, got = m
    r = run(f"probe/{vec['id']}", level, inp)
    cls = "accept" if accepted(r) else r.get("outcome", r.get("op"))
    ok = check(cls == PROBE_CLASS[want["outcome"]], f"probe {vec['id']} ({level}) outcome",
               f"driver {short(r)}, probe {want['outcome']} {want.get('detail', '')}")
    if ok and got is not None and accepted(r) and "got" in want and not str(want["got"]).startswith("decoded"):
        try:
            value = got(r)
        except Exception as ex:  # noqa: BLE001 - reported as a failed check
            value = f"({type(ex).__name__}: {ex})"
        check(str(value) == str(want["got"]), f"probe {vec['id']} value", f"driver {value}, probe {want['got']}")
    if ok and vec["group"] == 3:
        check(r.get("outcome") == "ok", f"probe {vec['id']}: object re-encode is byte-identical", short(r))
    if ok and vec["group"] == 8 and r.get("outcome") == "reject":
        check(r["reason"]["code"] == "depth", f"probe {vec['id']}: depth refusal", short(r))
if not results:
    print(f"   no probe results for {version} (run evidence/sdk-matrix/run.sh, or set XDRCHECK_OVERLAY); skipped")
else:
    # Vectors with no row in the results read lower the bar by one each.
    check(mapped >= 100 - sum(1 for v in vectors if v["id"] not in results), "probe vectors mapped", mapped)
    print(f"   {mapped} probe vectors")

# ---- overlay -------------------------------------------------------------------------------------------------

G = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"


def at_path(r, path):
    """The value at a dotted path of a response (list indices as numbers), or a marker when absent."""
    cur = r
    for k in path.split("."):
        if isinstance(cur, list) and k.isdigit() and int(k) < len(cur):
            cur = cur[int(k)]
        elif isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return "(absent)"
    return cur


if OVERLAY:
    section("overlay cases")
    cpath = os.path.join(OVERLAY, "drivers", "python", "selftest-cases.json")
    cases = read_json(cpath)["cases"] if os.path.exists(cpath) else []
    for c in cases:
        if c.get("versions") and version not in c["versions"]:
            continue
        extra = {"variant": c["variant"]} if c.get("variant") else {}
        r = run(c["entry"], c["level"], c["input"], **extra)
        want = c["expect"]
        ok = r.get("outcome") == want["outcome"] and ("code" not in want or (r.get("reason") or {}).get("code") == want["code"])
        for path, value in want.get("values", {}).items():
            ok = ok and at_path(r, path) == value
        check(ok, f"overlay: {c['name']}", short(r))
    print(f"   {len(cases)} overlay cases")

# The SDK annotates the muxed ID and the offer ID as int: a string-tagged ID cannot be passed at all
# (n_a/argument_type_not_accepted, decided from the annotation), while an integer of any size is passed.
section("argument types")
for op, args in (("muxed_account.encode", {"account": G, "id": {"native": "string", "value": "16"}}),
                 ("offer.manage_sell", {"offer_id": {"native": "string", "value": "9007199254740993"}})):
    r = run(f"types/{op}", "L4", api_in(op, args))
    check(r.get("outcome") == "n_a" and r["reason"]["code"] == "argument_type_not_accepted", f"{op} with a string ID -> n_a/argument_type_not_accepted", short(r))
r = run("types/offer-number", "L4", api_in("offer.manage_sell", {"offer_id": {"native": "number", "value": "9007199254740993"}}))
check(r.get("outcome") == "ok" and r["actual"]["api"]["value"] == "9007199254740993", "an integer offer ID is passed exactly", short(r))
r = run("types/offer-fraction", "L4", api_in("offer.manage_sell", {"offer_id": {"native": "number", "value": "0.5"}}))
check(r.get("outcome") == "n_a" and r["reason"]["code"] == "argument_type_not_accepted", "a fractional number (float) offer ID -> n_a", short(r))

# A struct field named after a Python keyword is generated with a trailing underscore (ClawbackOp.from_); the
# projection uses the XDR name. Operation: no source, CLAWBACK (19), asset CLW:GA7Q…, from GA7Q…, 25 XLM.
key = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"
op_hex = "00000000" + "00000013" + "00000001" + "434c5700" + "00000000" + key + "00000000" + key + "000000000ee6b280"
r = run("types/clawback-from", "L2", {**xdr_in("Operation", op_hex), "pinpoints": ["/body/clawback/from"]})
pin = (r.get("actual", {}).get("pinpoints") or [{}])[0]
check(r.get("outcome") == "ok" and pin.get("found") is True and pin.get("value") == G, "keyword-named field projected as `from`", short(r))
# Probe vectors 4a ({u32 1, symbol "1", ...}) and 4b ({bool true, u32 1, i32 1}): distinct host keys that
# Python's dict merges.
for vid, entries in (("4a", 2), ("4b", 1)):
    vec = next(x for x in vectors if x["id"] == vid)
    r = run(f"defect/map-keys-{vid}", "L3", xdr_in("ScVal", vec["hex"]))
    check(r.get("outcome") == "ok" and r["actual"]["native"]["map_entries"] == entries and r["actual"]["native"]["bytes_preserved"] is False,
          f"colliding map keys merged by scval.to_native ({vid}: {entries} of 3 entries)", short(r))
    r = run(f"defect/map-keys-{vid}", "L0", xdr_in("ScVal", vec["hex"]))
    check(r.get("outcome") == "ok", f"{vid} L0 control", short(r))

# A symbol whose byte is not UTF-8 (SCV_SYMBOL, length 1, 0xff, padding): the native conversion cannot turn it into
# a str without loss, and the refusal is reported as lossy_conversion_refused, not other.
r = run("native/symbol-not-utf8", "L3", xdr_in("ScVal", "0000000f00000001ff000000"))
check(r.get("outcome") == "reject" and r.get("reason", {}).get("code") == "lossy_conversion_refused",
      "a non-UTF-8 symbol at L3 is lossy_conversion_refused", short(r))

POOL = "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"
FOCUS = "0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f"
iss = ["GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL", "GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO"]
net = run("issuer-order/network", "L4", api_in("liquidity_pool.id", {"asset_a": f"USD:{iss[0]}", "asset_b": f"USD:{iss[1]}"}))
rev = run("issuer-order/reversed", "L4", api_in("liquidity_pool.id", {"asset_a": f"USD:{iss[1]}", "asset_b": f"USD:{iss[0]}"}))
sample = next(m for m in manifests if m["id"] == "cap-0038/pool-issuers-order-by-bytes-not-strkey")
sv = sample["variants"][0]
sample_in = {"kind": "xdr", "xdr_type": sv["xdr_type"], "path": os.path.join(root, "corpus", sv["blob"]["path"]),
             "passphrase": sv["passphrase"], "focus": {"tx_index": sv["focus"]["tx_index"], "op_index": sv["focus"]["op_index"]}}
l1 = run(sample["id"], "L1", sample_in, variant=sv["network"])
o = l1.get("actual", {}).get("object", {})
if version == "17.0.0":
    check(net.get("outcome") == "reject" and net["reason"]["code"] == "ordering", "17.0.0 refuses the network's issuer order", short(net))
    check(rev.get("outcome") == "ok" and rev["actual"]["api"]["value"] == "c1324f878b3d11af9f923abb7d692fc74e0a7bcfd9a4edefd564efe5fdae9fdb",
          "17.0.0 accepts the reversed order (a pool the network never creates)", short(rev))
    check(l1.get("outcome") == "reject" and l1["reason"]["code"] == "ordering" and l1["reason"]["entry_point"] == "TransactionBuilder.from_xdr",
          "17.0.0 L1 on the sample ledger: reject/ordering", short(l1))
    rej = o.get("envelopes_rejected", [])
    check(o.get("transactions") == 19 and o.get("envelopes_parsed") == 18 and len(rej) == 1 and rej[0].get("tx_hash") == FOCUS
          and rej[0].get("tx_index") == sv["focus"]["tx_index"], "17.0.0: exactly the focus transaction is rejected, at its apply index",
          json.dumps(o)[:300])
    check(FOCUS not in o.get("tx_hashes", []) and len(o.get("tx_hashes", [])) == 18, "17.0.0: the rejected hash is left out of tx_hashes")
else:
    check(net.get("outcome") == "ok" and net["actual"]["api"]["value"] == POOL, "network issuer order -> pool ID", short(net))
    check(rev.get("outcome") == "reject" and rev["reason"]["code"] == "ordering", "reversed order refused", short(rev))
    check(l1.get("outcome") == "ok" and o.get("transactions") == 19 and o.get("envelopes_parsed") == 19, "L1 on the sample ledger: 19 envelopes", short(l1))
    fo = o.get("focus", {})
    check(fo.get("tx_hash") == FOCUS and fo.get("derived", {}).get("pool_id") == POOL and fo["derived"].get("operation_type") == "change_trust",
          "focus hash, derived pool ID and operation type", json.dumps(fo))
r0 = run(sample["id"], "L0", sample_in, variant=sv["network"])
check(r0.get("outcome") == "ok" and r0["actual"]["reencoded_sha256"] == sv["blob"]["sha256"], "sample ledger L0 byte-identical", short(r0))

# ---- api -----------------------------------------------------------------------------------------------------

section("api")
X = {
    "scval_u32": "0000000300000005",
    "memo_text": "0000000100000002fffe0000",
    "muxed": "0000010001020304050607083f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a",
    "account": "000000003f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a",
    "signer": "000000003f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a",
    "asset": "0000000155534400000000003f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a",
}
# The probe envelope 3a (max muxed source ID and offer ID) parses on every version; 1c is the issuer-order case.
env_3a = next(x for x in vectors if x["id"] == "3a")["hex"]
op_7b = next(x for x in vectors if x["id"] == "7b")["hex"]
sc_9e2 = next(x for x in vectors if x["id"] == "9E2")["hex"]
CALLS = {
    "asset.compare": ({"asset_a": "native", "asset_b": f"USD:{G}"}, lambda v: v == -1),
    "liquidity_pool.id": ({"asset_a": "native", "asset_b": f"USD:{G}"}, lambda v: len(v) == 64),
    "liquidity_pool.asset": ({"asset_a": "native", "asset_b": f"USD:{G}"}, None),
    "muxed_account.encode": ({"account": G, "id": {"native": "number", "value": "5"}}, None),
    "muxed_account.decode": ({"text": "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAICAMCAKBQHBA7T4"},
                             lambda v: v == {"account": G, "id": str(0x0102030405060708)}),
    "offer.manage_sell": ({"offer_id": {"native": "number", "value": "7"}}, lambda v: v == "7"),
    "offer.manage_buy": ({"offer_id": {"native": "number", "value": "7"}}, lambda v: v == "7"),
    "scval.from_native": ({"value": {"10": 1, "9": 2}, "type": {"10": ["u32", "u32"], "9": ["u32", "u32"]}},
                          lambda v: v == ["u32:9", "u32:10"]),
    "scval.sort_map": ({"keys": ["symbol:a", "string:b"]}, lambda v: v == ["string:b", "symbol:a"]),
    "scval.to_native": ({"xdr_hex": X["scval_u32"]}, lambda v: v == 5),
    "scval.native_roundtrip": ({"xdr_hex": X["scval_u32"]}, lambda v: v is True),
    "strkey.encode": ({"type": "account", "payload_hex": "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"},
                      lambda v: v == "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"),
    "strkey.decode": ({"text": G}, lambda v: v == "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"),
    "transaction.parse": ({"xdr_hex": env_3a, "passphrase": TESTNET}, lambda v: len(v.get("tx_hash", "")) == 64 and v.get("operations") == 2),
    "transaction.hash": ({"xdr_hex": env_3a, "passphrase": TESTNET}, lambda v: len(v) == 64),
    "memo.text_roundtrip": ({"xdr_hex": X["memo_text"]}, lambda v: v == "fffe"),
    "address.to_strkey": ({"xdr_hex": X["muxed"]}, lambda v: v == "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAICAMCAKBQHBA7T4"),
    "address.from_sc_address": ({"xdr_hex": sc_9e2}, lambda v: v == "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAICAMCAKBQHBCARO"),
    "signer_key.to_strkey": ({"xdr_hex": X["signer"]}, lambda v: v == G),
    "operation.object_roundtrip": ({"xdr_hex": op_7b}, lambda v: v is True),
    "asset.from_operation": ({"xdr_hex": X["asset"]}, lambda v: v == {"type": "credit_alphanum4", "code": "USD", "issuer": G}),
    "xdrjson.decode": ({"xdr_type": "ScVal", "json": {"u32": 5}}, None),
}
for op in API_OPS:
    if op not in CALLS:
        check(False, f"api op {op} has a test call")
        continue
    args, pred = CALLS[op]
    r = run(f"api/{op}", "L4", api_in(op, args))
    check(r.get("outcome") == "ok", f"api {op} answers", short(r))
    if r.get("outcome") == "ok":
        a = r["actual"]["api"]
        if pred is not None:
            check(pred(a.get("value")), f"api {op} value", json.dumps(a.get("value"))[:200])
        if "xdr_hex" in a or (isinstance(a.get("value"), str) and a["value"][:1] in "GMWCPBLTXS" and len(a["value"]) > 50):
            check(a.get("self_decode") in ("accepted", "rejected"), f"api {op} reports self_decode", json.dumps(a)[:200])
    m = run(f"api/{op}/missing-args", "L4", api_in(op, {}))
    check(m.get("op") == "protocol_error", f"api {op} without arguments -> protocol_error", short(m))
x = run("api/xdrjson", "L4", api_in("xdrjson.decode", {"xdr_type": "ScVal", "json": {"u32": 5}}))
check(x.get("actual", {}).get("api", {}).get("xdr_hex") == X["scval_u32"], "xdrjson.decode -> the value's XDR", short(x))

# ---- corpus --------------------------------------------------------------------------------------------------

section("corpus (vendored ledgers)")


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


def subst(v, derived):
    if isinstance(v, str):
        import re

        def look(m):
            cur = derived
            for k in m.group(1).split("."):
                cur = cur.get(k) if isinstance(cur, dict) else None
            return str(cur)

        return re.sub(r"\$\{derived\.([^}]+)\}", look, v)
    if isinstance(v, list):
        return [subst(x, derived) for x in v]
    if isinstance(v, dict):
        return {k: subst(x, derived) for k, x in v.items()}
    return v


# What this column is expected to do where it does not decode: a ledger cell is held to a known divergence the
# manifest declares for this target and version at that level (outcome and declared reason), and a cell awaiting
# a finding is acknowledged without an asserted outcome: an item of the committed pending list
# (findings/pending/conformance.json) or a report row a finding record lists in evidence.report_rows (findings/,
# and the private overlay's findings/ when XDRCHECK_OVERLAY names one), as `xdrcheck conform check` reads them. As in the
# orchestrator, a declared or acknowledged refusal at L0 leaves nothing to check at L1 and L2. Everything else
# must decode.
TARGET = "stellar-sdk (PyPI)"
COLUMN = f"python@{version}"


def row_cell(row):
    """(entry, variant, column, level) of a report row conform:<entry>:<variant or ->:<column>:<level>."""
    parts = row.split(":")
    if len(parts) < 5 or parts[0] != "conform":
        return None
    return parts[1], "" if parts[2] == "-" else parts[2], ":".join(parts[3:-1]), parts[-1]


def finding_cells(d):
    out = set()
    for rid in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        p = os.path.join(d, rid, "finding.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                rec = json.load(f)
            out |= {c for c in map(row_cell, (rec.get("evidence") or {}).get("report_rows") or []) if c}
    return out


pending = {(p["entry"], p["variant"], p["column"], p["level"])
           for p in read_json("findings", "pending", "conformance.json")["pending"]}
pending |= finding_cells(os.path.join(root, "findings"))
if os.environ.get("XDRCHECK_OVERLAY"):
    pending |= finding_cells(os.path.join(os.environ["XDRCHECK_OVERLAY"], "findings"))


def _ver(s):
    s = s.strip().removeprefix("v").split("+")[0]
    core, _, pre = s.partition("-")
    nums = [int(x) for x in core.split(".")]
    return (nums + [0, 0, 0])[:3], (0, ()) if not pre else (-1, tuple(pre.split(".")))


def _cmp(a, b):
    (na, pa), (nb, pb) = _ver(a), _ver(b)
    return (na > nb) - (na < nb) if na != nb else (pa > pb) - (pa < pb)


def in_range(ver, rng):
    """docs/manifest.md: alternatives joined by ||, each *, a hyphen range A - B, or comparators."""
    for alt in rng.split("||"):
        alt = alt.strip()
        if alt == "*":
            return True
        if " - " in alt:
            lo, hi = alt.split(" - ")
            if _cmp(ver, lo) >= 0 and _cmp(ver, hi) <= 0:
                return True
            continue
        ok = True
        for c in alt.split():
            op = next((o for o in (">=", "<=", ">", "<", "=") if c.startswith(o)), "")
            d = _cmp(ver, c[len(op):])
            ok = ok and {"": d == 0, "=": d == 0, "<": d < 0, "<=": d <= 0, ">": d > 0, ">=": d >= 0}[op]
        if ok:
            return True
    return False


def variant_key(m, vv):
    """The report's variant key: the network, with @protocol when the entry's variants differ in protocol."""
    if any(o["protocol"] != vv["protocol"] for o in m["variants"]):
        return f"{vv['network']}@{vv['protocol']}"
    return vv["network"]


def expected_divergence(m, key, level):
    """The known divergence declared for this column at the level, "pending", or None."""
    for k in (m.get("conformance") or {}).get("known_divergences") or []:
        if (k["target"] == TARGET and k.get("level", level) == level and not k.get("profile")
                and in_range(version, k["versions"])):
            return k
    return "pending" if (m["id"], key, COLUMN, level) in pending else None


def held(label, level, r, exp):
    """Checks a cell against its expected divergence; True when the divergence accounts for the cell, so the
    usual checks are skipped: a declared one always, an acknowledged one at L1 and L2, and at L0 when the cell
    refuses."""
    if exp is None:
        return False
    if exp == "pending":
        return level != "L0" or r.get("outcome") != "ok"
    want = (exp.get("match") or {}).get("reason")
    check(r.get("outcome") == exp["outcome"] and (want is None or (r.get("reason") or {}).get("code") == want),
          f"{label} {level}: the declared {exp['outcome']}" + (f"/{want}" if want else ""), short(r))
    return True


ledgers = 0
for m in manifests:
    if m["kind"] != "ledger":
        continue
    for vv in m["variants"]:
        ledgers += 1
        label = f"{m['id']} ({vv['network']}, protocol {vv['protocol']})"
        key = variant_key(m, vv)
        inp = {"kind": "xdr", "xdr_type": vv["xdr_type"], "path": os.path.join(root, "corpus", vv["blob"]["path"])}
        if vv.get("passphrase") is not None and vv["network"] != "none":
            inp["passphrase"] = vv["passphrase"]
        if vv.get("focus"):
            f = {k: x for k, x in vv["focus"].items() if k in ("tx_index", "op_index")}
            if f:
                inp["focus"] = f
        r0 = run(m["id"], "L0", inp, variant=key)
        # Beyond this schema's reach (a Protocol 30 ledger, no Protocol 30 types) known divergences are not
        # evaluated.
        beyond_reach = not p30 and vv["protocol"] >= 30
        if not beyond_reach and held(label, "L0", r0, expected_divergence(m, key, "L0")):
            continue
        if not check(r0.get("outcome") == "ok", f"{label} L0", short(r0)):
            continue
        check(r0["actual"]["reencoded_sha256"] == vv["blob"]["sha256"] and r0["actual"]["consumed_bytes"] == vv["blob"]["bytes"],
              f"{label} L0 byte-identical")
        r1 = run(m["id"], "L1", inp, variant=key)
        if not held(label, "L1", r1, expected_divergence(m, key, "L1")):
            o = r1.get("actual", {}).get("object", {})
            check(r1.get("outcome") == "ok" and o.get("envelopes_parsed") == o.get("transactions"), f"{label} L1", short(r1))
            want = (vv.get("derived") or {}).get("tx_hashes")
            if r1.get("outcome") == "ok" and want is not None:
                check(o.get("tx_hashes") == want, f"{label} L1 transaction hashes in apply order",
                      f"{len(o.get('tx_hashes', []))} vs {len(want)}")
            if r1.get("outcome") == "ok" and (vv.get("derived") or {}).get("tx_hash") and "focus" in inp:
                check(o.get("focus", {}).get("tx_hash") == vv["derived"]["tx_hash"], f"{label} L1 focus hash")
            # Every derived fact the manifest states for the focus is reported, with the oracle's value.
            l1 = (vv.get("derived") or {}).get("l1") or {}
            if r1.get("outcome") == "ok" and l1 and (vv.get("focus") or {}).get("tx_index") is not None:
                fd = o.get("focus", {}).get("derived", {})
                for k, w in l1.items():
                    check(fd.get(k) == w, f"{label} L1 focus.derived.{k}", json.dumps(fd))
        r2 = run(m["id"], "L2", inp, variant=key)
        if held(label, "L2", r2, expected_divergence(m, key, "L2")):
            continue
        oracle = read_sidecar(os.path.join(root, "corpus", vv["decoded"]))
        same = r2.get("outcome") == "ok" and canon(r2["actual"]["projection"]) == canon(oracle)
        if not same and r2.get("outcome") == "ok":
            # name the first differing path, for the report
            def first_diff(a, b, p=""):
                if type(a) is not type(b):
                    return p or "/"
                if isinstance(a, dict):
                    for k in sorted(set(a) | set(b)):
                        if k not in a or k not in b:
                            return f"{p}/{k}"
                        q = first_diff(a[k], b[k], f"{p}/{k}")
                        if q:
                            return q
                    return None
                if isinstance(a, list):
                    if len(a) != len(b):
                        return p + " (length)"
                    for i, (x, y) in enumerate(zip(a, b)):
                        q = first_diff(x, y, f"{p}/{i}")
                        if q:
                            return q
                    return None
                return None if a == b else p
            detail = first_diff(r2["actual"]["projection"], oracle)
        else:
            detail = short(r2)
        check(same, f"{label} L2 projection equals the oracle sidecar", detail)
        # Key-selected pinpoints (`select`) reach a driver only as plain pointers the orchestrator resolved.
        values = [x for x in list((m.get("expect") or {}).get("values", [])) + list((vv.get("expect") or {}).get("values", []))
                  if "select" not in x]
        if values:
            rp = run(m["id"], "L2", {**inp, "pinpoints": [x["path"] for x in values]}, variant=key)
            pins = rp.get("actual", {}).get("pinpoints", [])
            for i, x in enumerate(values):
                pp = pins[i] if i < len(pins) else {}
                check(pp.get("found") and canon(pp.get("value")) == canon(subst(x["equals"], vv.get("derived") or {})),
                      f"{label} L2 pinpoint {x['path']}", json.dumps(pp)[:200])
check(ledgers > 0, "the corpus has ledger variants")
print(f"   {ledgers} ledger variants")

# ---- shutdown and schema -------------------------------------------------------------------------------------

bye = call({"op": "shutdown"})
check(bye.get("op") == "shutdown" and bye.get("ok") is True, "shutdown")
proc.stdin.close()
check(proc.wait(timeout=30) == 0, "the driver exits 0 after shutdown")

section("schema")
reg = Registry()
schemas = {}
for name in ("driver-protocol", "manifest-entry"):
    s = read_json("corpus", "schema", f"{name}.schema.json")
    schemas[name] = s
    reg = reg.with_resource(s["$id"], Resource.from_contents(s))
validator = jsonschema.Draft202012Validator(schemas["driver-protocol"], registry=reg)
bad = 0
for i, ln in enumerate(lines, 1):
    errs = list(validator.iter_errors(json.loads(ln)))
    if errs:
        bad += 1
        if bad <= 5:
            print(f"   line {i}: {ln[:200]}\n     {errs[0].message[:300]}")
check(bad == 0, f"{len(lines)} response lines validate against the driver protocol schema", f"{bad} invalid")

print(f"python {version}: {checks - failures}/{checks} checks passed")
sys.exit(1 if failures else 0)
