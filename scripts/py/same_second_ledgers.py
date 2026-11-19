#!/usr/bin/env python3
"""Close several ledgers within one second on a local stellar-core 30 and stream their meta.

Manual close (the generator's mode) always advances the close time by at least one whole second,
so it cannot produce two ledgers in the same second (CAP-0088). This driver starts a standalone
node that closes ledgers by itself every `--close-ms` milliseconds
(ARTIFICIALLY_SET_CLOSE_TIME_FOR_TESTING, accepted by release builds), upgrades it to protocol 30,
and submits transactions whose outcome depends on whole-second time:

- payments in consecutive same-second ledgers;
- a payment whose maxTime is the current second (valid in every ledger of that second);
- a claimable balance with a 1-second relative predicate, claimed in the same second;
- a transaction with minSeqAge 1 right after its source's last transaction.

Close times follow the wall clock, so the ledgers (and their hashes) differ on every run.

    same_second_ledgers.py --core BIN --out DIR [--close-ms 200] [--passphrase P]

Writes DIR/meta.xdr (record-marked LedgerCloseMeta stream), DIR/steps.json (id, property,
tx_hash, submit) and DIR/core.cfg. Export with
`xdrcheck-corpus gen-lake --stream DIR/meta.xdr --steps DIR/steps.json --name … --passphrase …`.
Needs stellar-sdk (Python) 17.0.1 (pins.toml).
"""
import argparse
import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from stellar_sdk import (Account, Asset, Claimant, ClaimPredicate, Keypair, Network,
                         TransactionBuilder)
from stellar_sdk import xdr as sx


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    def __init__(self, core, out, passphrase, close_ms):
        self.core, self.out, self.passphrase = core, Path(out), passphrase
        self.http, self.query = free_port(), free_port()
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "buckets").mkdir(exist_ok=True)
        seed = hashlib.sha256(b"xdrcheck/same-second/node").digest()
        node = Keypair.from_raw_ed25519_seed(seed)
        cfg = f'''NETWORK_PASSPHRASE="{passphrase}"
RUN_STANDALONE=true
MANUAL_CLOSE=false
NODE_IS_VALIDATOR=true
NODE_SEED="{node.secret} self"
UNSAFE_QUORUM=true
FAILURE_SAFETY=0
KNOWN_PEERS=[]
PREFERRED_PEERS=[]
DATABASE="sqlite3://{self.out}/core.db"
BUCKET_DIR_PATH="{self.out}/buckets"
HTTP_PORT={self.http}
PUBLIC_HTTP_PORT=false
HTTP_QUERY_PORT={self.query}
METADATA_OUTPUT_STREAM="{self.out}/meta.xdr"
NTP_DRIFT_CHECK_SERVER=""
AUTOMATIC_SELF_CHECK_PERIOD=0
LOG_FILE_PATH="{self.out}/core.log"
ARTIFICIALLY_SET_CLOSE_TIME_FOR_TESTING={close_ms}
ENABLE_SOROBAN_DIAGNOSTIC_EVENTS=true
ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION=true
EMIT_SOROBAN_TRANSACTION_META_EXT_V1=true
EMIT_LEDGER_CLOSE_META_EXT_V1=true
EMIT_CLASSIC_EVENTS=true
BACKFILL_STELLAR_ASSET_EVENTS=true
BACKFILL_RESTORE_META=true
[QUORUM_SET]
THRESHOLD_PERCENT=100
VALIDATORS=["$self"]
'''
        (self.out / "core.cfg").write_text(cfg)
        subprocess.run([core, "new-db", "--conf", str(self.out / "core.cfg")], check=True,
                       cwd=self.out, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.proc = subprocess.Popen([core, "run", "--conf", str(self.out / "core.cfg")], cwd=self.out,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if "state" in self.cmd("info"):
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise SystemExit("stellar-core did not answer")

    def cmd(self, q):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.http}/{q}", timeout=10) as r:
            return r.read().decode()

    def info(self):
        return json.loads(self.cmd("info"))["info"]["ledger"]

    def submit(self, env_b64):
        r = json.loads(self.cmd("tx?blob=" + urllib.parse.quote(env_b64)))
        return r.get("status"), r

    def seq(self, account_id):
        key = sx.LedgerKey(sx.LedgerEntryType.ACCOUNT,
                           account=sx.LedgerKeyAccount(Keypair.from_public_key(account_id).xdr_account_id()))
        body = "key=" + urllib.parse.quote(key.to_xdr())
        req = urllib.request.Request(f"http://127.0.0.1:{self.query}/getledgerentryraw",
                                     data=body.encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=10) as r:
            v = json.loads(r.read().decode())
        for e in v.get("entries", []):
            le = sx.LedgerEntry.from_xdr(e["entry"])
            return le.data.account.seq_num.sequence_number.int64
        return None

    def wait_ledgers(self, n):
        start = self.info()["num"]
        while self.info()["num"] < start + n:
            time.sleep(0.02)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=20)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--close-ms", type=int, default=200)
    ap.add_argument("--passphrase", default=Network.TESTNET_NETWORK_PASSPHRASE)
    a = ap.parse_args()
    node = Node(a.core, a.out, a.passphrase, a.close_ms)
    steps = []

    def send(sid, prop, tx):
        env = tx.to_xdr()
        h = tx.hash_hex()
        status, raw = node.submit(env)
        submit = status if status != "ERROR" else "ERROR " + raw.get("error", "")
        steps.append({"id": sid, "property": prop, "tx_hash": h, "submit": submit})
        return status

    try:
        node.cmd("upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z&expirationminutes=100000000"
                 "&protocolversion=30&basereserve=5000000")
        while node.info()["version"] != 30:
            time.sleep(0.05)
        node.wait_ledgers(2)
        pp = a.passphrase
        root = Keypair.from_raw_ed25519_seed(hashlib.sha256(pp.encode()).digest())
        kp = {n: Keypair.from_raw_ed25519_seed(hashlib.sha256(f"xdrcheck/same-second/{n}".encode()).digest())
              for n in ("A", "B", "C")}

        def account(k):
            return Account(k.public_key, node.seq(k.public_key))

        def builder(src, fee=100, timeout=None):
            b = TransactionBuilder(src, pp, base_fee=fee)
            if timeout is None:
                b.add_time_bounds(0, 0)
            return b

        r = account(root)
        b = builder(r)
        for k in kp.values():
            b.append_create_account_op(k.public_key, "10000")
        t = b.build()
        t.sign(root)
        send("fund", "Root funds A, B and C.", t)
        node.wait_ledgers(2)

        # Burst: one payment per ledger from three sources, many ledgers inside one second.
        for i in range(12):
            src = kp["ABC"[i % 3]]
            acc = account(src)
            t = builder(acc, 100 + i).append_payment_op(kp["B" if src is not kp["B"] else "C"].public_key,
                                                         Asset.native(), str(1 + i)).build()
            t.sign(src)
            send(f"burst-payment-{i}",
                 "A payment in a ledger closed within the same second as its neighbours (closeTime equal, closeTimeMs different).",
                 t)
            node.wait_ledgers(1)

        # maxTime = the current whole second: valid in every ledger that closes in this second.
        now = node.info()["closeTime"]
        acc = account(kp["A"])
        b = TransactionBuilder(acc, pp, base_fee=150).add_time_bounds(0, now + 1)
        t = b.append_payment_op(kp["B"].public_key, Asset.native(), "1").build()
        t.sign(kp["A"])
        send("max-time-next-second",
             "Time bounds whose maxTime is the next whole second, applied in a same-second ledger.", t)
        node.wait_ledgers(1)

        # Claimable balance with a 1-second relative predicate, then claimed at once.
        acc = account(kp["A"])
        pred = ClaimPredicate.predicate_before_relative_time(1)
        t = builder(acc, 160).append_create_claimable_balance_op(
            Asset.native(), "5", [Claimant(kp["C"].public_key, pred)]).build()
        t.sign(kp["A"])
        send("claimable-relative-1s",
             "CreateClaimableBalance with before_relative_time 1: core stores closeTime+1 (whole seconds).", t)
        node.wait_ledgers(1)
        op_id = sx.HashIDPreimage(sx.EnvelopeType.ENVELOPE_TYPE_OP_ID, operation_id=sx.HashIDPreimageOperationID(
            source_account=kp["A"].xdr_account_id(), seq_num=sx.SequenceNumber(sx.Int64(acc.sequence)),
            op_num=sx.Uint32(0)))
        bid = hashlib.sha256(op_id.to_xdr_bytes()).hexdigest()
        acc_c = account(kp["C"])
        t = builder(acc_c, 170).append_claim_claimable_balance_op("00000000" + bid).build()
        t.sign(kp["C"])
        send("claim-within-same-second",
             "ClaimClaimableBalance submitted right after creation: claimable only while closeTime < creation closeTime + 1.", t)
        node.wait_ledgers(1)

        # minSeqAge 1 directly after the source's previous transaction.
        acc = account(kp["B"])
        t = builder(acc, 180).set_min_sequence_age(1).append_bump_sequence_op(0).build()
        t.sign(kp["B"])
        send("min-seq-age-1",
             "PRECOND_V2 minSeqAge 1 right after the source's last transaction (whole-second age; may wait for the next second).", t)
        node.wait_ledgers(10)
    finally:
        node.stop()
    (Path(a.out) / "steps.json").write_text(json.dumps(steps, indent=1) + "\n")
    print(f"{len(steps)} steps; meta in {a.out}/meta.xdr")


if __name__ == "__main__":
    sys.exit(main())
