"""Builds vectors.json: every byte vector is hand-encoded here (no SDK), so the
expected values are independent of the SDKs under test.
Run: python3 -I gen_vectors.py  (writes vectors.json next to this file)
"""
import base64, hashlib, json, os, struct

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")

# ---------- minimal strkey (SEP-23) ----------
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
def crc16(b):
    c = 0
    for x in b:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c
def b32(b):
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return "".join(ALPH[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
def unb32(s):
    bits = "".join(f"{ALPH.index(c):05b}" for c in s)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
def sk_enc(ver, payload):
    raw = bytes([ver]) + payload
    return b32(raw + struct.pack("<H", crc16(raw)))
def sk_payload(s):
    raw = unb32(s)
    return raw[1:-2]

# ---------- XDR helpers ----------
u32 = lambda v: struct.pack(">I", v)
i32 = lambda v: struct.pack(">i", v)
u64 = lambda v: struct.pack(">Q", v)
i64 = lambda v: struct.pack(">q", v)
def opaque(b):
    return u32(len(b)) + b + b"\0" * (-len(b) % 4)
def acct(key):  # AccountID / PublicKey ed25519
    return u32(0) + key
def mux_g(key):
    return u32(0) + key
def mux_m(key, mid):  # KEY_TYPE_MUXED_ED25519 = 0x100: id first, then key (XDR order)
    return u32(0x100) + u64(mid) + key
def asset4(code, key):
    return u32(1) + code.encode().ljust(4, b"\0") + acct(key)
NATIVE = u32(0)

ISS_A = "GDRQL6EF772CANMYX55HXMU463OLAX46ZRCPCWS4KVL66ZS4BYA7OYDL"
ISS_B = "GD32JQHFWLIROCNQ564GLCB2M7T4GMQAP5UKHMVT64OQISWL2LHYK2HO"
GO_A = "GCXHWP6ILITHEZWVNCCTPJCT7ZIQ2JGKJH7XXR4VYI7PMAGOIHBMHHHM"
GO_B = "GC3BT2M7I2M5PJWE4VWYRVSOHSE6YBD2QKWVJH4TX7GSA3UHYCDH2YCD"
G1 = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
K1 = sk_payload
assert K1.hex() == "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"

def pool_id(a, b):
    params = u32(0) + asset4("USD", sk_payload(a)) + asset4("USD", sk_payload(b)) + i32(30)
    return hashlib.sha256(params).hexdigest()
assert pool_id(ISS_A, ISS_B) == "c2a730127d006897b021d6fcb279da68b4f65f9b6a408c74eb2cdd85ea862d5e"

V = []
def add(**kw):
    kw.setdefault("hex", None)
    kw.setdefault("params", {})
    V.append(kw)

# ---------- 1. issuer ordering ----------
CORE_LP = "stellar-core src/util/types.cpp:143 `cp.assetA < cp.assetB` (strict, xdrpp operator< on Asset: type, code bytes, issuer key bytes)"
add(id="1a", group=1, level="L3 builder", title="LP(A,B) network order -> pool id",
    params={"a": ISS_A, "b": ISS_B, "code": "USD"}, expect={"accept": True, "value": pool_id(ISS_A, ISS_B)},
    why=CORE_LP + "; key(A)=e305.. < key(B)=f7a4..; live testnet pool c2a73012..2d5e")
add(id="1b", group=1, level="L3 builder", title="LP(B,A) reversed -> must refuse",
    params={"a": ISS_B, "b": ISS_A, "code": "USD"}, expect={"accept": False}, why=CORE_LP)
env = open(os.path.join(DATA, "testnet-tx-0126748091.envelope.b64")).read().strip()
add(id="1c", group=1, level="L1 SDK parse", title="parse core-accepted testnet envelope 01267480..346f (op[2] LP ChangeTrust)",
    hex=base64.b64decode(env).hex(), params={"network": "Test SDF Network ; September 2015"},
    expect={"accept": True, "value": "hash=0126748091930959a3aefac9296e1773b947f964a9b73f37ce856c4df32d346f pool=" + pool_id(ISS_A, ISS_B)},
    why="tx is in testnet ledger 5521432 (successful); SDK object parse must accept it")
add(id="1d", group=1, level="L3 builder", title="Go test pair LP(A,B) (GCXHWP6I/GC3BT2M7)",
    params={"a": GO_A, "b": GO_B, "code": "USD"}, expect={"accept": True, "value": pool_id(GO_A, GO_B)},
    why=CORE_LP + "; go-stellar-sdk v0.8.0 xdr/asset_ordering_test.go pair")
add(id="1e", group=1, level="L3 builder", title="Go test pair LP(B,A) reversed -> refuse",
    params={"a": GO_B, "b": GO_A, "code": "USD"}, expect={"accept": False}, why=CORE_LP)
add(id="1f", group=1, level="L3 builder", title="LP(A,A) identical assets -> refuse",
    params={"a": ISS_A, "b": ISS_A, "code": "USD"}, expect={"accept": False}, why=CORE_LP + " (strict <, so equal is invalid)")

# ---------- 2. 64-bit ids through builders ----------
MUX_WHY = "MuxedAccount.med25519.id is uint64 (Stellar-transaction.x); a builder must encode exactly the given id or refuse"
OFF_WHY = "offerID is int64; core ManageOfferOpFrameBase.cpp:636-641 returns MALFORMED for offerID<0 (P>=15)"
cases = [("2^53+1", "number", 2**53 + 1), ("2^64-1", "string", 2**64 - 1), ("2^64", "string", 2**64),
         ("-1", "number", -1), ("0x10", "string", "0x10"), ("empty", "string", "")]
for i, (lab, kind, val) in enumerate(cases):
    if lab == "2^53+1":
        e = {"accept": "either", "value": str(2**53 + 1)}
    elif lab == "2^64-1":
        e = {"accept": True, "value": str(2**64 - 1)}
    else:
        e = {"accept": False}
    add(id=f"2m{i+1}", group=2, level="L3 builder", title=f"muxed id {lab} ({kind})",
        params={"g": G1, "kind": kind, "value": str(val)}, expect=e, why=MUX_WHY + ("; lossy-number input must be refused or kept exact" if lab == "2^53+1" else ""))
for i, (lab, kind, val) in enumerate(cases):
    if lab == "2^53+1":
        e = {"accept": "either", "value": str(2**53 + 1)}
    else:
        e = {"accept": False}  # 2^64-1 and 2^64 exceed int64; -1 malformed; strings non-canonical
    add(id=f"2o{i+1}", group=2, level="L3 builder", title=f"offer id {lab} ({kind})",
        params={"g": G1, "kind": kind, "value": str(val)}, expect=e, why=OFF_WHY)

# ---------- 3. decode->encode identity ----------
def tx_v1(src, ops, memo=u32(0), sigs=b""):
    tx = src + u32(100 * max(1, len(ops))) + i64(1) + u32(0) + memo + u32(len(ops)) + b"".join(ops) + u32(0)
    return u32(2) + tx + sigs
def op(body_type, body, src=None):
    return (u32(1) + src if src else u32(0)) + u32(body_type) + body
pay = op(1, mux_m(K1, 2**64 - 1) + NATIVE + i64(1))
mso = op(3, NATIVE + asset4("USD", K1) + i64(1) + i32(1) + i32(1) + i64(2**63 - 1))
env3 = tx_v1(mux_m(K1, 2**64 - 1), [pay, mso], sigs=u32(0))
add(id="3a", group=3, level="L0 codec + L1 SDK parse", title="tx: muxed source id 2^64-1, payment to M id 2^64-1, offerID 2^63-1; decode then re-encode",
    hex=env3.hex(), params={"network": "Test SDF Network ; September 2015"},
    expect={"accept": True, "value": f"roundtrip=true src_id={2**64-1} offer={2**63-1}"},
    why="XDR is canonical; any decoder must reproduce the bytes and the exact ids")

# ---------- 4. map key collisions after native conversion ----------
def scv(t, body=b""):
    return u32(t) + body
U32 = lambda v: scv(3, u32(v)); I32 = lambda v: scv(4, i32(v)); BOOL = lambda v: scv(0, u32(v))
STR = lambda s: scv(14, opaque(s)); SYM = lambda s: scv(15, opaque(s)); BYT = lambda s: scv(13, opaque(s))
def scmap(entries):
    return scv(17, u32(1) + u32(len(entries)) + b"".join(k + v for k, v in entries))
m4a = scmap([(U32(1), U32(10)), (STR(b"1"), U32(30)), (SYM(b"1"), U32(20))])  # host order: U32(3) < String(14) < Symbol(15)
m4b = scmap([(BOOL(1), U32(1)), (U32(1), U32(2)), (I32(1), U32(3))])
COLL = "keys are distinct ScVals in host order (soroban-env-host comparison.rs:298-438), so the map is valid on chain; native conversion must keep all 3 or refuse (js-stellar-sdk#1789 fix: throw)"
add(id="4a", group=4, level="L2 native", title="ScMap {U32 1, String \"1\", Symbol \"1\"} -> native", hex=m4a.hex(),
    expect={"accept": "either", "value": "entries=3"}, why=COLL)
add(id="4b", group=4, level="L2 native", title="ScMap {Bool true, U32 1, I32 1} -> native", hex=m4b.hex(),
    expect={"accept": "either", "value": "entries=3"}, why=COLL)

# ---------- 5. map key order on encode ----------
ORD = "Soroban host Compare<ScVal> (rs-soroban-env 0c99950e soroban-env-host/src/host/comparison.rs:298-438): discriminant first, then value; bytes/strings/symbols as byte slices"
add(id="5a", group=5, level="L3 builder", title="native map u32 keys {10, 9} -> ScMap order", params={"keys": ["u32:10", "u32:9"]},
    expect={"accept": True, "value": "u32:9,u32:10"}, why=ORD)
add(id="5b", group=5, level="L3 builder", title="bytes keys {0a, 09} -> ScMap order", params={"keys": ["bytes:0a", "bytes:09"]},
    expect={"accept": True, "value": "bytes:09,bytes:0a"}, why=ORD)
add(id="5c", group=5, level="L3 builder", title="symbol \"a\" vs string \"b\" -> ScMap order", params={"keys": ["symbol:a", "string:b"]},
    expect={"accept": True, "value": "string:b,symbol:a"}, why=ORD + "; SCV_STRING=14 < SCV_SYMBOL=15")

# ---------- 6. XDR strictness (negative) ----------
NEG = "RFC 4506 / stellar-xdr; xdrpp (core) behaviour in parentheses"
add(id="6a", group=6, level="L0 codec", title="ScVal Bool encoded as 2", hex=(u32(0) + u32(2)).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 4.4 bool is 0/1 (xdrpp ACCEPTS: types.h:305-306 `u != 0` -> true; core re-serialises canonically, so never core-emitted)")
add(id="6b", group=6, level="L0 codec", title="ScVal Vec optional flag = 2", hex=(u32(16) + u32(2) + u32(0)).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 4.19 optional is bool (xdrpp: same bool path, accepts)")
add(id="6c", group=6, level="L0 codec", title="ScVal String \"a\" with non-zero padding 010203", hex=(u32(14) + u32(1) + b"a\x01\x02\x03").hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 3 padding must be zero (xdrpp rejects: marshal.cc:51-55)")
add(id="6c2", group=6, level="L0 codec", title="ScVal Bytes 00 with non-zero padding ffffff", hex=(u32(13) + u32(1) + b"\x00\xff\xff\xff").hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 3 (xdrpp rejects)")
add(id="6d", group=6, level="L0 codec", title="ScVal Void + 4 trailing bytes", hex=(u32(1) + u32(0)).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="trailing bytes after a complete value (xdrpp rejects: marshal.h:214-217)")
add(id="6d2", group=6, level="L1 SDK parse", title="vector-3a envelope + 4 trailing zero bytes through high-level parser",
    hex=(env3 + u32(0)).hex(), params={"type": "TransactionEnvelope", "network": "Test SDF Network ; September 2015"},
    expect={"accept": False}, why="trailing bytes (xdrpp rejects)")
add(id="6e", group=6, level="L0 codec", title="ScVal Error{SCE_WASM_VM, code 0xffff} (ScErrorCode undeclared)", hex=(u32(2) + u32(1) + u32(0xFFFF)).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 4.3 enum must be declared (xdrpp: validated only where xdr_validate_enum is in scope)")
add(id="6f", group=6, level="L0 codec", title="ScVal discriminant 99 (undeclared union arm)", hex=u32(99).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 4.15 (xdrpp rejects: types.h:1105-1112)")
add(id="6g", group=6, level="L0 codec", title="ScVal Address with ScAddressType 6 (one past P30 max)", hex=(u32(18) + u32(6) + b"\0" * 40).hex(), params={"type": "ScVal"},
    expect={"accept": False}, why="RFC4506 4.15")
add(id="6g5", group=6, level="L0 codec", title="ScVal Address MuxedContract (type 5, P30-only arm): id 2^63, contract=K1",
    hex=(u32(18) + u32(5) + u64(2**63) + K1).hex(), params={"type": "ScVal"},
    expect={"accept": "p30"}, why="valid from Protocol 30 (CAP-0084); pre-P30 schema must reject cleanly (informational row)")
add(id="6h", group=6, level="L0 codec", title="ScVal Vec length FFFFFFFF, no body (memory)", hex=(u32(16) + u32(1) + u32(0xFFFFFFFF)).hex(), params={"type": "ScVal", "mem": True},
    expect={"accept": False}, why="length must not exceed remaining input; must not allocate (xdrpp: check before resize, marshal.h:193-200)")
add(id="6h2", group=6, level="L0 codec", title="ScVal Bytes length FFFFFFFF, no body (memory)", hex=(u32(13) + u32(0xFFFFFFFF)).hex(), params={"type": "ScVal", "mem": True},
    expect={"accept": False}, why="as 6h; rs BytesM pre-allocates vec![0;len] (header.rs 1445-1470)")
add(id="6h3", group=6, level="L0 codec", title="ScVal Bytes length 7FFFFFFF at end of input (go-xdr#34 shape)", hex=(u32(13) + u32(0x7FFFFFFF)).hex(), params={"type": "ScVal", "mem": True},
    expect={"accept": False}, why="go-xdr#34 (dc590f17): a prefix at the very end of the input dropped both bounds before make([]byte, n)")
add(id="6h4", group=6, level="L0 codec", title="ScVal Bytes length 40000000 (1 GiB) at end of input", hex=(u32(13) + u32(0x40000000)).hex(), params={"type": "ScVal", "mem": True},
    expect={"accept": False}, why="as 6h3, below maxInt32")
def sig():
    return b"\x01\x02\x03\x04" + opaque(b"\x55" * 64)
bump = op(11, i64(2))
env20 = tx_v1(mux_g(K1), [bump], sigs=u32(20) + sig() * 20)
env21 = tx_v1(mux_g(K1), [bump], sigs=u32(21) + sig() * 21)
env100 = tx_v1(mux_g(K1), [bump] * 100, sigs=u32(0))
env101 = tx_v1(mux_g(K1), [bump] * 101, sigs=u32(0))
add(id="6i20", group=6, level="L0 codec", title="TransactionEnvelope with 20 signatures (max, positive control)", hex=env20.hex(), params={"type": "TransactionEnvelope"},
    expect={"accept": True}, why="DecoratedSignature signatures<20>")
add(id="6i21", group=6, level="L0 codec", title="TransactionEnvelope with 21 signatures", hex=env21.hex(), params={"type": "TransactionEnvelope"},
    expect={"accept": False}, why="signatures<20> (xdrpp rejects: types.h:458-460 xvector overflow)")
add(id="6j100", group=6, level="L0 codec", title="Transaction with 100 operations (max, positive control)", hex=env100.hex(), params={"type": "TransactionEnvelope"},
    expect={"accept": True}, why="operations<MAX_OPS_PER_TX=100>")
add(id="6j101", group=6, level="L0 codec", title="Transaction with 101 operations", hex=env101.hex(), params={"type": "TransactionEnvelope"},
    expect={"accept": False}, why="operations<100> (xdrpp rejects)")
add(id="6k", group=6, level="L0 codec", title="Memo text with 29 bytes (string<28>)", hex=(u32(1) + opaque(b"a" * 29)).hex(), params={"type": "Memo"},
    expect={"accept": False}, why="string text<28> (xdrpp rejects)")

# ---------- 7. non-UTF-8 ----------
U8 = "stellar-core does not check MEMO_TEXT bytes (no validation in src/transactions; only TransactionUtils.cpp:2259 copies it into an SCV_STRING); XDR string is bytes; native round trip must preserve bytes"
add(id="7a", group=7, level="L2 native", title="MEMO_TEXT bytes fffe: decode -> native string -> re-encode", hex=(u32(1) + opaque(b"\xff\xfe")).hex(), params={"type": "Memo"},
    expect={"accept": "either", "value": (u32(1) + opaque(b"\xff\xfe")).hex()}, why=U8 + "; refusing to expose a native string is acceptable, mangling is wrong")
md = op(10, opaque(b"k") + u32(1) + opaque(b"\xff\xfe"))
add(id="7b", group=7, level="L2 native", title="ManageData value bytes fffe (opaque): decode op -> SDK op -> re-encode", hex=md.hex(), params={"type": "Operation"},
    expect={"accept": True, "value": md.hex()}, why="DataValue is opaque<64>, not text; must stay bytes")
add(id="7c", group=7, level="L2 native", title="ScVal String bytes fffe: decode -> native -> re-encode", hex=STR(b"\xff\xfe").hex(), params={"type": "ScVal"},
    expect={"accept": "either", "value": STR(b"\xff\xfe").hex()}, why="refusal acceptable, mangling wrong; SCString is string<> = bytes; host stores any bytes")
add(id="7d", group=7, level="L2 native", title="ScVal Symbol byte ff: decode -> native -> re-encode", hex=SYM(b"\xff").hex(), params={"type": "ScVal"},
    expect={"accept": "either", "value": SYM(b"\xff").hex()}, why="SCSymbol charset is [a-zA-Z0-9_] in the host, so rejecting is fine; mangling (U+FFFD -> efbfbd) is wrong")

# ---------- 8. depth ----------
def nested(n):
    return (u32(16) + u32(1) + u32(1)) * n + u32(1)
for n in [99, 100, 101, 199, 200, 201, 499, 500, 501, 749, 750, 751, 1499, 1500, 1501]:
    add(id=f"8n{n}", group=8, level="L0 codec", title=f"ScVal Vec nested {n} deep (innermost Void)", hex=nested(n).hex(), params={"type": "ScVal", "n": n},
        expect={"accept": "info"}, why="records the SDK default boundary; host Val depth limit is 100 (limits.rs:41), core xdrpp stack 1500 (main.cpp:425)")

# ---------- 9. strkey ----------
SEP = "SEP-0023 v1.4.0 Tests section (stellar-protocol ced008c3)"
valid = [
 ("V1", "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"),
 ("V2", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"),
 ("V3", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"),
 ("V4", "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM"),
 ("V5", "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU"),
 ("V6", "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA"),
 ("V7", "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN"),
 ("V8", "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU"),
 ("V9", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC"),
 ("V10", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY"),
]
invalid = [
 ("I1", "GAAAAAAAACGC6"), ("I2", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR"),
 ("I3", "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA"), ("I4", "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI"),
 ("I5", "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I"), ("I6", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA"),
 ("I7", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I"), ("I8", "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"),
 ("I9", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK==="), ("I10", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO"),
 ("I11", "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM"),
 ("I12", "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ"),
 ("I13", "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6"),
 ("I14", "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV"), ("I15", "BAAT6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGXACA"),
 ("I16", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD"), ("I17", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWCA"),
 ("I18", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI"), ("I19", "W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW"),
 ("I20", "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA"),
]
for lab, s in valid:
    add(id=f"9{lab}", group=9, level="strkey", title=f"SEP-23 valid {lab} ({s[0]})", params={"s": s},
        expect={"accept": "p30" if s[0] == "W" else True, "value": sk_payload(s).hex()}, why=SEP + (" (W = CAP-0084, Protocol 30)" if s[0] == "W" else ""))
for lab, s in invalid:
    add(id=f"9{lab}", group=9, level="strkey", title=f"SEP-23 invalid {lab} ({s[0]})", params={"s": s}, expect={"accept": False}, why=SEP)
# synthetic
pv = lambda n, pad=None: K1 + u32(n) + bytes(range(1, n + 1)) + (pad if pad is not None else b"\0" * (-n % 4))
P0 = sk_enc(15 << 3, K1 + u32(0))
P_pad = sk_enc(15 << 3, K1 + u32(1) + b"\x01\xff\xff\xff")
P65 = sk_enc(15 << 3, pv(65))
P1 = sk_enc(15 << 3, pv(1)); P64 = sk_enc(15 << 3, pv(64))
syn = [
 ("S1", "P n=0 (empty payload; go#5981)", P0, {"accept": False}, "rs-stellar-strkey #107 / go v0.7.2 reject n<1; core rejects empty payload (SetOptionsOpFrame.cpp:308-315); SEP silent"),
 ("S2", "P n=1 payload 01, padding ffffff", P_pad, {"accept": False}, "SEP-23: padding must be zero; re-encode rule"),
 ("S3", "P n=65 (> opaque<64>)", P65, {"accept": False}, "XDR opaque payload<64>"),
 ("S4", "P n=1 (69 chars) valid", P1, {"accept": True, "value": sk_payload(P1).hex()}, "SEP-23 + XDR"),
 ("S5", "P n=64 (165 chars) valid", P64, {"accept": True, "value": sk_payload(P64).hex()}, "SEP-23 + XDR"),
 ("S6", "M 56-char truncation (wallet-backend#716 output)", "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAPG", {"accept": False}, "M payload must be 40 bytes"),
 ("S7", "G lowercase", G1.lower(), {"accept": False}, "SEP-23 alphabet is uppercase RFC4648"),
 ("S8", "G with trailing '='", G1 + "=", {"accept": False}, "SEP-23: no padding"),
 ("S10", "M id 2^64-1", sk_enc(12 << 3, K1 + u64(2**64 - 1)), {"accept": True, "value": (K1 + u64(2**64 - 1)).hex()}, "SEP-23"),
 ("S11", "M id 2^53+1", sk_enc(12 << 3, K1 + u64(2**53 + 1)), {"accept": True, "value": (K1 + u64(2**53 + 1)).hex()}, "SEP-23"),
 ("S12", "S seed", "SA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWVG", {"accept": True, "value": K1.hex()}, "SEP-23"),
 ("S13", "T pre-auth", "TA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPUI", {"accept": True, "value": K1.hex()}, "SEP-23"),
 ("S14", "X hash-x", "XA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVLRR", {"accept": True, "value": K1.hex()}, "SEP-23"),
]
for lab, title, s, e, why in syn:
    add(id=f"9{lab}", group=9, level="strkey", title=title, params={"s": s}, expect=e, why=why)
# encode-side checks
W_ID = 0x0102030405060708
add(id="9E1", group=9, level="strkey encode", title="encode W from (contract=K1, id=2^63) -> must equal SEP V10",
    params={"contract": K1.hex(), "id": str(2**63)}, expect={"accept": "p30", "value": valid[9][1]}, why=SEP + " (strkey payload = contract || id)")
add(id="9E2", group=9, level="L0 codec + strkey", title="XDR ScAddress MuxedContract{id=0x0102030405060708, contract=K1} -> W strkey (field order XDR id-first vs strkey contract-first)",
    hex=(u32(5) + u64(W_ID) + K1).hex(), params={"type": "ScAddress"}, expect={"accept": "p30", "value": sk_enc(22 << 3, K1 + u64(W_ID))},
    why="Stellar-contract.x MuxedContract{uint64 id; ContractID contractId} vs SEP-23 W payload contract||id")
add(id="9E3", group=9, level="strkey encode", title="encode P with empty payload (go#5981) -> must refuse",
    params={"key": K1.hex(), "payload": ""}, expect={"accept": False}, why="decoders reject n=0, so an encoder must not emit it")
add(id="9E4", group=9, level="L0 codec + strkey", title="XDR MuxedAccount med25519{id=0x0102030405060708, key=K1} -> M strkey",
    hex=mux_m(K1, W_ID).hex(), params={"type": "MuxedAccount"}, expect={"accept": True, "value": sk_enc(12 << 3, K1 + u64(W_ID))},
    why="XDR id-first vs strkey key-first")

# ---------- 10. Protocol 30 LedgerCloseMeta ----------
for seq, sha in [(5540313, None), (5540314, None)]:
    raw = open(os.path.join(DATA, f"lcm-{seq}.xdr"), "rb").read()
    add(id=f"10l{seq}", group=10, level="L0 codec", title=f"testnet LedgerCloseMetaBatch ledger {seq} (Galexie object, core 30.0.0)",
        hex=None, params={"type": "LedgerCloseMetaBatch", "file": f"data/lcm-{seq}.xdr", "sha256": hashlib.sha256(raw).hexdigest()},
        expect={"accept": "p30" if seq == 5540314 else True}, why="core-emitted; P30 ledgers use StellarValue.ext SIGNED_MS (CAP-0088); pre-P30 schemas must fail with a clean error, not crash")

json.dump(V, open(os.path.join(HERE, "vectors.json"), "w"), indent=1)
print(len(V), "vectors")
