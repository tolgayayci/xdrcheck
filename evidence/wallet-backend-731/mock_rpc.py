#!/usr/bin/env python3
"""Throwaway: minimal stellar-rpc mock serving getHealth + getLedgers only.

Usage: mock_rpc.py <port> <lcm.xdr> [<lcm.xdr> ...]
Each file is one raw (uncompressed) LedgerCloseMeta. Field types follow
go-stellar-sdk protocols/rpc get_health.go / get_ledgers.go (see rpc-getledgers note):
getHealth close times are strings; getLedgers top-level close times are numbers,
ledgers[].ledgerCloseTime is a string. No 30 s latency check. Binds 127.0.0.1 only.
Every request is logged to stderr as one JSON line (method, params, result size, error).
"""
import base64, http.server, json, struct, sys, time


class R:
    def __init__(self, b, o=0):
        self.b, self.o = b, o
    def u32(self):
        v = struct.unpack_from(">I", self.b, self.o)[0]; self.o += 4; return v
    def u64(self):
        v = struct.unpack_from(">Q", self.b, self.o)[0]; self.o += 8; return v
    def fixed(self, n):
        v = self.b[self.o:self.o + n]; self.o += n; return v
    def var_opaque(self):
        n = self.u32(); v = self.fixed(n); self.o += (-n) % 4; return v


def parse_lcm(raw: bytes):
    r = R(raw)
    arm = r.u32()
    if arm in (1, 2):
        ext = r.u32()  # LedgerCloseMetaExt
        if ext == 1:   # LedgerCloseMetaExtV1 { ExtensionPoint ext; int64 sorobanFeeWrite1KB; }
            assert r.u32() == 0; r.u64()
        elif ext != 0:
            raise ValueError(f"unknown LedgerCloseMetaExt arm {ext}")
    elif arm != 0:
        raise ValueError(f"unknown LedgerCloseMeta arm {arm}")
    start = r.o                      # LedgerHeaderHistoryEntry begins here
    lhash = r.fixed(32)
    version = r.u32(); r.fixed(32)   # ledgerVersion, previousLedgerHash
    r.fixed(32); close_time = r.u64()  # scpValue.txSetHash, closeTime
    for _ in range(r.u32()):         # upgrades<6>
        r.var_opaque()
    sig = lambda: (r.u32(), r.fixed(32), r.var_opaque())  # LedgerCloseValueSignature
    sv = r.u32()                     # StellarValue.ext (StellarValueType)
    if sv == 1: sig()                                             # SIGNED
    elif sv == 2: r.fixed(64); r.u32(); sig()                     # EMPTY_TX_SET
    elif sv == 3: r.u64(); sig()                                  # SIGNED_MS (P30)
    elif sv == 4: r.u64(); r.fixed(64); r.u32(); sig()            # EMPTY_TX_SET_MS (P30)
    elif sv != 0: raise ValueError(f"unknown StellarValueType {sv}")
    r.fixed(32); r.fixed(32)         # txSetResultHash, bucketListHash
    seq = r.u32()
    r.fixed(8 + 8 + 4 + 8 + 4 + 4 + 4)  # totalCoins feePool inflationSeq idPool baseFee baseReserve maxTxSetSize
    r.fixed(4 * 32)                  # skipList
    if r.u32() == 1:                 # LedgerHeader.ext v1: flags + ext(0)
        r.u32(); assert r.u32() == 0
    assert r.u32() == 0              # LedgerHeaderHistoryEntry.ext
    return {"hash": lhash.hex(), "sequence": seq, "ledgerCloseTime": str(close_time),
            "headerXdr": base64.b64encode(raw[start:r.o]).decode(),
            "metadataXdr": base64.b64encode(raw).decode(), "_close": close_time, "_ver": version}


LEDGERS = {}


def log(**kw):
    print(json.dumps({"t": round(time.time(), 3), **kw}), file=sys.stderr, flush=True)


def handle(req):
    method, params, rid = req.get("method"), req.get("params") or {}, req.get("id")
    seqs = sorted(LEDGERS)
    lo, hi = LEDGERS[seqs[0]], LEDGERS[seqs[-1]]
    if method == "getHealth":
        res = {"status": "healthy", "latestLedger": hi["sequence"], "latestLedgerCloseTime": str(hi["_close"]),
               "oldestLedger": lo["sequence"], "oldestLedgerCloseTime": str(lo["_close"]),
               "ledgerRetentionWindow": len(seqs)}
    elif method == "getLedgers":
        if not isinstance(params, dict):
            return rid, None, {"code": -32602, "message": "invalid parameters"}
        start = int(params.get("startLedger") or 0)
        limit = int((params.get("pagination") or {}).get("limit") or 50)
        if limit > 200:
            return rid, None, {"code": -32600, "message": "limit must not exceed 200"}
        if not (lo["sequence"] <= start <= hi["sequence"]):
            return rid, None, {"code": -32600, "message": f"start ledger ({start}) must be between the oldest ledger: {lo['sequence']} and the latest ledger: {hi['sequence']} for this rpc instance"}
        out = [ {k: v for k, v in LEDGERS[s].items() if not k.startswith("_")}
                for s in seqs if s >= start][:limit]
        res = {"ledgers": out, "latestLedger": hi["sequence"], "latestLedgerCloseTime": hi["_close"],
               "oldestLedger": lo["sequence"], "oldestLedgerCloseTime": lo["_close"],
               "cursor": str(out[-1]["sequence"] if out else start - 1)}
    else:
        return rid, None, {"code": -32601, "message": f"method {method!r} not found"}
    return rid, res, None


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"null")
        reqs = body if isinstance(body, list) else [body]
        outs = []
        for rq in reqs:
            rid, res, err = handle(rq)
            log(method=rq.get("method"), params=rq.get("params"),
                n=(len(res["ledgers"]) if res and "ledgers" in res else None), error=err)
            o = {"jsonrpc": "2.0", "id": rid}
            o.update({"error": err} if err else {"result": res})
            outs.append(o)
        data = json.dumps(outs if isinstance(body, list) else outs[0]).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    for p in sys.argv[2:]:
        with open(p, "rb") as f:
            l = parse_lcm(f.read())
        LEDGERS[l["sequence"]] = l
        log(loaded=p, sequence=l["sequence"], hash=l["hash"], closeTime=l["_close"], protocol=l["_ver"])
    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
