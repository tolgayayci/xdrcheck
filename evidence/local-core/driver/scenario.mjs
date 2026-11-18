// Throwaway probe: drive a standalone stellar-core v30.0.0 through a fixed scenario.
// Usage: node scenario.mjs  (env: PASSPHRASE, HTTP, QHTTP, CORE_BIN, CORE_CONF, OUT, UPGRADE_DIR)
import * as S from '@stellar/stellar-sdk';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const { xdr, Keypair, StrKey, TransactionBuilder, Operation, Asset, Memo, Account, MuxedAccount } = S;
const PP = process.env.PASSPHRASE;
const HTTP = process.env.HTTP, QHTTP = process.env.QHTTP;
const OUT = process.env.OUT;
const T0 = 1700000000, DT = 1000000;
const sha = (b) => createHash('sha256').update(b).digest();

// ---- deterministic keys -------------------------------------------------
const root = Keypair.fromRawEd25519Seed(sha(PP));
const kp = (label) => Keypair.fromRawEd25519Seed(sha('g3-probe/' + label));
const A = kp('alice'), B = kp('bob'), C = kp('carol'), D = kp('dave');

// issuer pair whose order by strkey text differs from order by raw key bytes
function findIssuers() {
  for (let i = 0; i < 1000; i++) for (let j = i + 1; j < 1000; j++) {
    const x = kp('issuer-' + i), y = kp('issuer-' + j);
    const byStr = x.publicKey() < y.publicKey();
    const byRaw = Buffer.compare(x.rawPublicKey(), y.rawPublicKey()) < 0;
    if (byStr !== byRaw) return [i, j, x, y];
  }
  throw new Error('no pair');
}
const [ii, ij, I1, I2] = findIssuers();
const CODE = 'USDC';
const X1 = new Asset(CODE, I1.publicKey()), X2 = new Asset(CODE, I2.publicKey());

// ---- core HTTP ---------------------------------------------------------
const log = [];
// node's fetch misbehaves against core's HTTP/1.0 server (400s, apparent re-sends); use node:http, no retries
function hreq(port, path, method = 'GET', body = null) {
  return new Promise((res, rej) => {
    const headers = body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {};
    const req = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (r) => {
      let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(d)); });
    req.on('error', rej); req.end(body || undefined);
  });
}
const get = (path) => hreq(HTTP, '/' + path);
let k = 0; // close counter
async function close(note) {
  const ct = T0 + k * DT; k++;
  const r = await get(`manualclose?closeTime=${ct}`);
  const info = JSON.parse(await get('info')).info;
  const ent = { step: note, closeTime: ct, ledger: info.ledger.num, manualclose: r.trim().slice(0, 200) };
  if (!/Manually closed ledger|"status"\s*:\s*"OK"|closed/i.test(r) && !r.includes(String(info.ledger.num))) ent.warn = 'unexpected manualclose reply';
  log.push(ent);
  console.error(JSON.stringify(ent));
  return ent;
}
async function submit(name, env) {
  const b64 = typeof env === 'string' ? env : env.toEnvelope().toXDR('base64');
  const r = JSON.parse(await get('tx?blob=' + encodeURIComponent(b64)));
  const h = typeof env === 'string' ? null : Buffer.from(env.hash()).toString('hex');
  const ent = { submit: name, status: r.status, hash: h };
  if (r.error) ent.error = r.error;
  if (r.diagnostic_events) ent.diag = r.diagnostic_events;
  log.push(ent); console.error(JSON.stringify(ent));
  return r;
}
async function q(keys) {
  const body = keys.map((key) => 'key=' + encodeURIComponent(key.toXDR('base64'))).join('&');
  const j = JSON.parse(await hreq(QHTTP, '/getledgerentryraw', 'POST', body));
  return (j.entries || []).map((e) => xdr.LedgerEntry.fromXDR(e.entry || e.e, 'base64'));
}
const acctKey = (pk) => xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: S.Keypair.fromPublicKey(pk).xdrAccountId() }));
async function seqOf(pk) {
  const [e] = await q([acctKey(pk)]);
  if (!e) throw new Error('no account ' + pk);
  return e.data.account.seqNum.toString();
}
async function acct(k1) { return new Account(k1.publicKey(), await seqOf(k1.publicKey())); }

let feeCtr = 0; // distinct fee per tx
const fee = () => String(1000 + (feeCtr++));
function tb(src, extra = {}) {
  return new TransactionBuilder(src, { fee: extra.fee || fee(), networkPassphrase: PP, ...extra }).setTimeout(0);
}

// ---- protocol + settings upgrade ----------------------------------------
async function waitReady() {
  for (let i = 0; i < 200; i++) {
    try { const j = JSON.parse(await get('info')); if (j.info && j.info.state) return j.info; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('core not ready');
}
async function upgrade(params) {
  const r = await get(`upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z&expirationminutes=100000000&${params}`);
  log.push({ upgrade: params, reply: r.trim() }); console.error('upgrade', params, r.trim());
}

// core's get-settings-upgrade-txs picks a random contract salt (SettingsUpgradeUtils.cpp L129 @v30.0.0,
// autocheck::generator<Hash>), which makes the upgrade contract ID, and hence every later header hash,
// differ run to run. Replace salt + derived contract ID bytes with fixed values and re-sign with root.
function contractIdFor(addrScAddress, salt) {
  const pre = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({ networkId: sha(PP),
    contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(new xdr.ContractIdPreimageFromAddress({ address: addrScAddress, salt })) }));
  return sha(Buffer.from(pre.toXDR()));
}
function replaceAll(buf, from, to) {
  let n = 0, i;
  while ((i = buf.indexOf(from)) >= 0) { to.copy(buf, i); n++; }
  return n;
}
function fixSalt(out, file) {
  const j = JSON.parse(execFileSync(process.env.STELLAR_XDR, ['decode', '--type', 'TransactionEnvelope', '--input', 'single-base64', '--output', 'json'], { input: out[4] }).toString());
  const hf = j.tx.tx.operations[0].body.invoke_host_function.host_function;
  const cc = hf.create_contract_v2 || hf.create_contract;
  const oldSalt = Buffer.from(cc.contract_id_preimage.address.salt, 'hex');
  const addr = S.Address.fromString(cc.contract_id_preimage.address.address).toScAddress();
  const oldId = contractIdFor(addr, oldSalt);
  const newSalt = sha('g3-probe/settings-upgrade-salt/' + file.split('/').pop());
  const newId = contractIdFor(addr, newSalt);
  const counts = [];
  for (const i of [4, 6]) {
    const b = Buffer.from(out[i], 'base64');
    const c = replaceAll(b, oldSalt, newSalt) + replaceAll(b, oldId, newId);
    const tx = TransactionBuilder.fromXDR(b.toString('base64'), PP);
    tx.signatures.length = 0; tx.sign(root);
    out[i] = tx.toEnvelope().toXDR('base64'); out[i + 1] = Buffer.from(tx.hash()).toString('hex'); counts.push(c);
  }
  const kb = Buffer.from(out[8], 'base64'); counts.push(replaceAll(kb, oldId, newId)); out[8] = kb.toString('base64');
  log.push({ fixSalt: file.split('/').pop(), oldSalt: oldSalt.toString('hex'), newSalt: newSalt.toString('hex'), oldId: oldId.toString('hex'), newId: newId.toString('hex'), replacements: counts });
}
async function settingsUpgrade(file) {
  const seq = await seqOf(root.publicKey());
  const xdrB64 = readFileSync(file, 'utf8').trim();
  const out = execFileSync(process.env.CORE_BIN, ['get-settings-upgrade-txs', root.publicKey(), seq, PP, '--xdr', xdrB64, '--signtxs'],
    { input: root.secret() + '\n', env: process.env, stdio: ['pipe', 'pipe', 'ignore'] }).toString().trim().split('\n');
  if (out.length !== 9) throw new Error('unexpected settings tool output ' + out.length);
  if (process.env.RANDOM_SALT !== '1') fixSalt(out, file);
  const names = ['restore', 'upload', 'create', 'invoke'];
  for (let i = 0; i < 4; i++) {
    await submit('settings:' + names[i] + ':' + file.split('/').pop(), out[2 * i]);
    log.push({ settingsTxId: out[2 * i + 1] });
    await close('settings ' + names[i]);
  }
  await upgrade('configupgradesetkey=' + encodeURIComponent(out[8]));
  await close('arm settings ' + file.split('/').pop());
}

// ---- helpers for Soroban -----------------------------------------------
const scAcct = (k1) => xdr.ScAddress.scAddressTypeAccount(k1.xdrAccountId());
const scMuxed = (k1, id) => xdr.ScAddress.scAddressTypeMuxedAccount(new xdr.MuxedEd25519Account({ id: xdr.Uint64.fromString(id), ed25519: k1.rawPublicKey() }));
const sacId = X1.contractId(PP); // C... strkey
const sacAddr = S.Address.fromString(sacId).toScAddress();
const instanceKey = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: sacAddr, key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }));
const tlKey = (k1, asset) => xdr.LedgerKey.trustline(new xdr.LedgerKeyTrustLine({ accountId: k1.xdrAccountId(), asset: asset.toTrustLineXDRObject() }));
const i128 = (n) => S.nativeToScVal(BigInt(n), { type: 'i128' });
function invocation(fn, args, subs = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: sacAddr, functionName: fn, args })),
    subInvocations: subs,
  });
}
const srcAuth = (inv) => new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), rootInvocation: inv });
function sorobanData(ro, rw) {
  return new S.SorobanDataBuilder().setReadOnly(ro).setReadWrite(rw).setResources(50_000_000, 20_000, 20_000).setResourceFee('50000000').build();
}
async function invoke(name, srcKp, fn, args, auth, ro, rw) {
  const op = Operation.invokeHostFunction({
    func: xdr.HostFunction.hostFunctionTypeInvokeContract(new xdr.InvokeContractArgs({ contractAddress: sacAddr, functionName: fn, args })),
    auth,
  });
  const tx = tb(await acct(srcKp)).addOperation(op).setSorobanData(sorobanData(ro, rw)).build();
  tx.sign(srcKp);
  await submit(name, tx);
  await close(name);
  return tx;
}

// ---- scenario -------------------------------------------------------------
async function main() {
  const info = await waitReady();
  log.push({ startInfo: { ledger: info.ledger, state: info.state, network: info.network } });
  await upgrade('protocolversion=30&basereserve=5000000');
  await close('upgrade protocol 30');
  await settingsUpgrade(process.env.UPGRADE_DIR + '/enable.xdr');
  await settingsUpgrade(process.env.UPGRADE_DIR + '/p30-testnet.xdr');

  // (a) create + fund accounts from root
  {
    const t = tb(await acct(root));
    for (const k1 of [A, B, C, D, I1, I2]) t.addOperation(Operation.createAccount({ destination: k1.publicKey(), startingBalance: '10000' }));
    const tx = t.build(); tx.sign(root); await submit('a:create-accounts', tx); await close('a');
  }
  // (b) muxed source (id 2^64-1) -> muxed destination (id 2^53+1)
  {
    const mA = new MuxedAccount(await acct(A), '18446744073709551615');
    const mB = new MuxedAccount(new Account(B.publicKey(), '0'), '9007199254740993');
    const tx = tb(mA, { withMuxing: true }).addOperation(Operation.payment({ destination: mB.accountId(), asset: Asset.native(), amount: '10' })).build();
    tx.sign(A); await submit('b:muxed-payment', tx); await close('b');
  }
  // (c) signed-payload signers on A: D with 1-byte payload, C with 64-byte payload
  const sp1 = Buffer.from([0x2a]);
  const sp64 = Buffer.alloc(64).map((_, i) => i);
  const pStr = (k1, payload) => StrKey.encodeSignedPayload(new xdr.SignerKeyEd25519SignedPayload({ ed25519: k1.rawPublicKey(), payload }).toXDR());
  {
    const tx = tb(await acct(A))
      .addOperation(Operation.setOptions({ signer: { ed25519SignedPayload: pStr(D, sp1), weight: 1 } }))
      .addOperation(Operation.setOptions({ signer: { ed25519SignedPayload: pStr(C, sp64), weight: 1 } }))
      .build();
    tx.sign(A); await submit('c:add-signed-payload-signers', tx); await close('c1');
  }
  {
    // tx from A authorised only by D's signature over the 1-byte payload
    const tx = tb(await acct(A)).addOperation(Operation.payment({ destination: C.publicKey(), asset: Asset.native(), amount: '1' })).build();
    tx.signatures.push(D.signPayloadDecorated(sp1));
    await submit('c:authorised-by-signed-payload', tx); await close('c2');
  }
  {
    // PRECOND_V2 extraSigners: signed payload (D, 32 bytes) required in addition to B's own signature
    const xp = sha('g3-extra-signer-payload');
    const tx = tb(await acct(B)).setExtraSigners([pStr(D, xp)]).addOperation(Operation.payment({ destination: C.publicKey(), asset: Asset.native(), amount: '1' })).build();
    tx.sign(B); tx.signatures.push(D.signPayloadDecorated(xp));
    await submit('c:precond-v2-extra-signers', tx); await close('c3');
  }
  // (d) fee-bump with muxed fee source whose inner tx fails (payment to non-existent account)
  {
    const ghost = kp('ghost-never-created').publicKey();
    const inner = tb(await acct(C), { fee: '100' }).addOperation(Operation.payment({ destination: ghost, asset: Asset.native(), amount: '1' })).build();
    inner.sign(C);
    const mD = new MuxedAccount(new Account(D.publicKey(), '0'), '7');
    const fb = TransactionBuilder.buildFeeBumpTransaction(mD.accountId(), fee(), inner, PP);
    fb.sign(D); await submit('d:fee-bump-inner-fails', fb); await close('d');
  }
  // (e) trustlines, issuance, LP share trustline + deposit
  {
    const tx = tb(await acct(A)).addOperation(Operation.changeTrust({ asset: X1 })).addOperation(Operation.changeTrust({ asset: X2 })).build();
    tx.sign(A); await submit('e:A-trusts-X1-X2', tx); await close('e1');
  }
  {
    const tx = tb(await acct(C)).addOperation(Operation.changeTrust({ asset: X1 })).build();
    tx.sign(C); await submit('e:C-trusts-X1', tx); await close('e2');
  }
  {
    const tx = tb(await acct(I1)).addOperation(Operation.payment({ destination: A.publicKey(), asset: X1, amount: '1000' })).build();
    tx.sign(I1); await submit('e:I1-pays-A', tx); await close('e3');
  }
  {
    const tx = tb(await acct(I2)).addOperation(Operation.payment({ destination: A.publicKey(), asset: X2, amount: '1000' })).build();
    tx.sign(I2); await submit('e:I2-pays-A', tx); await close('e4');
  }
  // ordering: core wants assets sorted by XDR bytes (issuer raw bytes, same code)
  const rawLo = Buffer.compare(I1.rawPublicKey(), I2.rawPublicKey()) < 0;
  const [lo, hi] = rawLo ? [X1, X2] : [X2, X1];
  {
    // wrong (strkey-text) order: build the LiquidityPoolAsset by hand to bypass SDK checks
    const params = xdr.LiquidityPoolParameters.liquidityPoolConstantProduct(new xdr.LiquidityPoolConstantProductParameters({ assetA: hi.toXDRObject(), assetB: lo.toXDRObject(), fee: 30 }));
    const op = new xdr.Operation({ sourceAccount: null, body: xdr.OperationBody.changeTrust(new xdr.ChangeTrustOp({ line: xdr.ChangeTrustAsset.assetTypePoolShare(params), limit: xdr.Int64.fromString('9223372036854775807') })) });
    // the SDK refuses to build this, so patch the op into a built envelope and sign by hand
    const env = tb(await acct(A)).addOperation(Operation.bumpSequence({ bumpTo: '0' })).build().toEnvelope();
    env.v1.tx.operations = [op];
    const payload = new xdr.TransactionSignaturePayload({ networkId: sha(PP), taggedTransaction: xdr.TransactionSignaturePayloadTaggedTransaction.envelopeTypeTx(env.v1.tx) });
    const h = sha(Buffer.from(payload.toXDR()));
    env.v1.signatures = [new xdr.DecoratedSignature({ hint: A.signatureHint(), signature: A.sign(h) })];
    const r = await submit('e:pool-trust-WRONG-order(expect reject)', Buffer.from(env.toXDR()).toString('base64'));
    log.push({ wrongOrderHash: h.toString('hex') });
    log.push({ wrongOrderResult: r });
  }
  const pool = new S.LiquidityPoolAsset(lo, hi, 30);
  const poolId = Buffer.from(S.getLiquidityPoolId('constant_product', pool.getLiquidityPoolParameters())).toString('hex');
  {
    const tx = tb(await acct(A)).addOperation(Operation.changeTrust({ asset: pool })).build();
    tx.sign(A); await submit('e:pool-share-trustline', tx); await close('e5');
  }
  {
    const tx = tb(await acct(A)).addOperation(Operation.liquidityPoolDeposit({ liquidityPoolId: poolId, maxAmountA: '100', maxAmountB: '200', minPrice: '0.1', maxPrice: '10' })).build();
    tx.sign(A); await submit('e:pool-deposit', tx); await close('e6');
  }
  // (f) memos
  {
    const tx = tb(await acct(B), { memo: Memo.text('GBRPYHIL2CI3FNQ4BXLFMNDLFJUN') }).addOperation(Operation.payment({ destination: C.publicKey(), asset: Asset.native(), amount: '1' })).build();
    tx.sign(B); await submit('f:memo-text-address-like', tx); await close('f1');
  }
  {
    const raw = Buffer.from([0xff, 0xfe, 0x00, 0xc3, 0x28, 0xed, 0xa0, 0x80, 0x41]);
    const tx = tb(await acct(B), { memo: new Memo('text', raw) }).addOperation(Operation.payment({ destination: C.publicKey(), asset: Asset.native(), amount: '1' })).build();
    tx.sign(B); await submit('f:memo-text-non-utf8', tx); await close('f2');
  }
  // (g) Soroban: deploy SAC for X1
  {
    const op = Operation.createStellarAssetContract({ asset: X1 });
    const tx = tb(await acct(A)).addOperation(op).setSorobanData(sorobanData([acctKey(I1.publicKey())], [instanceKey])).build();
    tx.sign(A); await submit('g:deploy-SAC-X1', tx); await close('g1');
  }
  // CAP-0073 trust(B): B has no X1 trustline
  {
    const args = [xdr.ScVal.scvAddress(scAcct(B))];
    await invoke('g:SAC-trust(B)', B, 'trust', args, [srcAuth(invocation('trust', args))],
      [instanceKey, acctKey(I1.publicKey())], [tlKey(B, X1), acctKey(B.publicKey())]);
  }
  // SAC transfer A -> muxed(C, id 42)
  {
    const args = [xdr.ScVal.scvAddress(scAcct(A)), xdr.ScVal.scvAddress(scMuxed(C, '42')), i128(1234567)];
    await invoke('g:SAC-transfer-to-muxed', A, 'transfer', args, [srcAuth(invocation('transfer', args))],
      [instanceKey, acctKey(I1.publicKey())], [tlKey(A, X1), tlKey(C, X1)]);
  }
  // (h) extra unmatched address-credential auth entries (one flat, one nested 3 levels) with bogus signatures
  {
    const args = [xdr.ScVal.scvAddress(scAcct(A)), xdr.ScVal.scvAddress(scAcct(C)), i128(1000)];
    const bogusArgs = [xdr.ScVal.scvAddress(scAcct(D)), xdr.ScVal.scvAddress(scAcct(A)), i128(999999999)];
    const addrCred = (nonce) => xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: scAcct(D), nonce: xdr.Int64.fromString(String(nonce)), signatureExpirationLedger: 1, signature: xdr.ScVal.scvVoid() }));
    const nested = invocation('transfer', bogusArgs, [invocation('transfer', bogusArgs, [invocation('transfer', bogusArgs)]), invocation('approve', bogusArgs)]);
    const auth = [srcAuth(invocation('transfer', args)),
      new xdr.SorobanAuthorizationEntry({ credentials: addrCred(1), rootInvocation: invocation('transfer', bogusArgs) }),
      new xdr.SorobanAuthorizationEntry({ credentials: addrCred(2), rootInvocation: nested })];
    await invoke('h:SAC-transfer-with-unmatched-auth', A, 'transfer', args, auth,
      [instanceKey, acctKey(I1.publicKey())], [tlKey(A, X1), tlKey(C, X1)]);
  }
  await close('final empty');

  const summary = {
    passphrase: PP, networkId: sha(PP).toString('hex'), root: root.publicKey(),
    accounts: { A: A.publicKey(), B: B.publicKey(), C: C.publicKey(), D: D.publicKey(), I1: I1.publicKey(), I2: I2.publicKey() },
    issuerLabels: ['issuer-' + ii, 'issuer-' + ij],
    issuerOrder: { strkeyLess_I1_I2: I1.publicKey() < I2.publicKey(), rawLess_I1_I2: rawLo },
    driverMaxRssKB: process.resourceUsage().maxRSS,
    sac: sacId, poolId, signedPayloadSigners: { D1: pStr(D, sp1), C64: pStr(C, sp64) },
    log,
  };
  writeFileSync(OUT + '/driver.json', JSON.stringify(summary, null, 1));
}
main().catch((e) => { console.error('DRIVER FAILED', e); writeFileSync(OUT + '/driver.json', JSON.stringify({ error: String(e.stack), log }, null, 1)); process.exit(1); });
