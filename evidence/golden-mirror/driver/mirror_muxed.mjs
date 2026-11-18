// Throwaway: golden mirror of core test "Stellar asset contract transfer to muxed contract (CAP-0084)|custom asset|transfer"
// (golden test-lcm-current/InvokeHostFunctionTests/f9e9d669f79493b3.xdr, frame 11 = L13). Helpers copied from
// ../wallet-backend-731/core/driver/scenario731.mjs (itself from ../local-core/driver/scenario.mjs). Keys follow core's getAccount().
// Usage: node scenario731.mjs  (env: PASSPHRASE, HTTP, QHTTP, CORE_BIN, OUT, UPGRADE_DIR, STELLAR_XDR, PROTOCOL, SETTINGS)
import * as S from '@stellar/stellar-sdk';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const { xdr, Keypair, TransactionBuilder, Operation, Asset, Account } = S;
const PP = process.env.PASSPHRASE;
const HTTP = process.env.HTTP, QHTTP = process.env.QHTTP;
const OUT = process.env.OUT;
const PROTOCOL = Number(process.env.PROTOCOL || 28);
const SETTINGS = process.env.SETTINGS || 'p27-testnet.xdr';
const T0 = 1700000000, DT = 1000000;
const sha = (b) => createHash('sha256').update(b).digest();

// ---- deterministic keys -------------------------------------------------
const root = Keypair.fromRawEd25519Seed(sha(PP));
// core's TxTests.cpp getAccount(): seed = name padded with '.' to 32 bytes (so on the core test passphrase the keys equal the golden's)
const kp = (label) => Keypair.fromRawEd25519Seed(Buffer.from(label.padEnd(32, '.'), 'latin1'));
const A1 = kp('a1');
const USDC = new Asset('USDC', root.publicKey());   // golden: makeAsset(root, "USDC")

// ---- core HTTP (node:http, HTTP/1.0 server; undici fetch fails) ------------
const log = [];
function hreq(port, path, method = 'GET', body = null) {
  return new Promise((res, rej) => {
    const headers = body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {};
    const req = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (r) => {
      let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(d)); });
    req.on('error', rej); req.end(body || undefined);
  });
}
const get = (path) => hreq(HTTP, '/' + path);
let k = 0;
let curLedger = 1;
async function close(note) {
  const ct = T0 + k * DT; k++;
  const r = await get(`manualclose?closeTime=${ct}`);
  const info = JSON.parse(await get('info')).info;
  curLedger = info.ledger.num;
  const ent = { step: note, closeTime: ct, ledger: info.ledger.num, protocol: info.ledger.version, manualclose: r.trim().slice(0, 200) };
  log.push(ent); console.error(JSON.stringify(ent));
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
  if (r.status !== 'PENDING') throw new Error('submit ' + name + ' not PENDING: ' + JSON.stringify(r));
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
let feeCtr = 0;
const fee = () => String(1000 + (feeCtr++));
const tb = (src, extra = {}) => new TransactionBuilder(src, { fee: extra.fee || fee(), networkPassphrase: PP, ...extra }).setTimeout(0);

// ---- protocol + settings upgrade (fixed salt, as in local-core) --------------------
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
function contractIdFor(addrScAddress, salt) {
  const pre = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({ networkId: sha(PP),
    contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(new xdr.ContractIdPreimageFromAddress({ address: addrScAddress, salt })) }));
  return sha(Buffer.from(pre.toXDR()));
}
function replaceAll(buf, from, to) { let n = 0, i; while ((i = buf.indexOf(from)) >= 0) { to.copy(buf, i); n++; } return n; }
function fixSalt(out, file) {
  const j = JSON.parse(execFileSync(process.env.STELLAR_XDR, ['decode', '--type', 'TransactionEnvelope', '--input', 'single-base64', '--output', 'json'], { input: out[4] }).toString());
  const hf = j.tx.tx.operations[0].body.invoke_host_function.host_function;
  const cc = hf.create_contract_v2 || hf.create_contract;
  const oldSalt = Buffer.from(cc.contract_id_preimage.address.salt, 'hex');
  const addr = S.Address.fromString(cc.contract_id_preimage.address.address).toScAddress();
  const oldId = contractIdFor(addr, oldSalt);
  const newSalt = sha('g6-golden-mirror/settings-upgrade-salt/' + file.split('/').pop());
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
  fixSalt(out, file);
  const names = ['restore', 'upload', 'create', 'invoke'];
  for (let i = 0; i < 4; i++) {
    await submit('settings:' + names[i] + ':' + file.split('/').pop(), out[2 * i]);
    log.push({ settingsTxId: out[2 * i + 1] });
    await close('settings ' + names[i] + ' ' + file.split('/').pop());
  }
  await upgrade('configupgradesetkey=' + encodeURIComponent(out[8]));
  await close('arm settings ' + file.split('/').pop());
}

// ---- Soroban helpers -----------------------------------------------------
const scAcct = (k1) => xdr.ScAddress.scAddressTypeAccount(k1.xdrAccountId());
const sacOf = (asset) => { const id = asset.contractId(PP); return { id, addr: S.Address.fromString(id).toScAddress() }; };
const SUSDC = sacOf(USDC);
const instanceKey = (sac) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: sac.addr, key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }));
const tlKey = (k1, asset) => xdr.LedgerKey.trustline(new xdr.LedgerKeyTrustLine({ accountId: k1.xdrAccountId(), asset: asset.toTrustLineXDRObject() }));
const nonceKey = (k1, nonce) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: scAcct(k1), key: xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: xdr.Int64.fromString(String(nonce)) })), durability: xdr.ContractDataDurability.temporary }));
const i128 = (n) => S.nativeToScVal(BigInt(n), { type: 'i128' });
const invocation = (sac, fn, args) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: sac.addr, functionName: fn, args })),
  subInvocations: [] });
const srcAuth = (inv) => new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), rootInvocation: inv });
const sorobanData = (ro, rw, r = [50_000_000, 20_000, 20_000, '50000000']) => new S.SorobanDataBuilder().setReadOnly(ro).setReadWrite(rw).setResources(r[0], r[1], r[2]).setResourceFee(r[3]).build();
const GOLDEN_RES = [2_000_000, 2000, 2000, '2000000'];
async function invoke(name, srcKp, sac, fn, args, auth, ro, rw, res, inclFee) {
  const op = Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(new xdr.InvokeContractArgs({ contractAddress: sac.addr, functionName: fn, args })), auth });
  let tx = tb(await acct(srcKp), inclFee ? { fee: inclFee } : {}).addOperation(op).setSorobanData(sorobanData(ro, rw, res)).build();
  if (process.env.NO_TIMEBOUNDS !== '0') {
    // core's test txs carry PRECOND_NONE; the SDK always sets time bounds, so rewrite cond to none before signing
    const env = tx.toEnvelope(); env.v1.tx.cond = xdr.Preconditions.precondNone();   // js-xdr 5 property API
    tx = TransactionBuilder.fromXDR(env.toXDR('base64'), PP);
  }
  tx.sign(srcKp);
  await submit(name, tx);
  return { tx, close: await close(name) };
}
const steps = {};
const rec = (name, r) => { steps[name] = { ledger: r.close.ledger, hash: Buffer.from(r.tx.hash()).toString('hex') }; };
async function classic(name, srcKp, ops) {
  const t = tb(await acct(srcKp)); for (const o of ops) t.addOperation(o);
  const tx = t.build(); tx.sign(srcKp); await submit(name, tx);
  const c = await close(name); rec(name, { tx, close: c });
}

// ---- scenario -------------------------------------------------------------
// Golden sequence: root.create("a1", 1e9); a1.changeTrust(USDC:root, 1e9); root.pay(a1, USDC, 1e9); deploy SAC(USDC) [root];
// focus: a1 invokes SAC transfer(a1, W(destContract, 987654321987654321), 1e8), source-account auth,
// footprint RO [root acct, SAC instance], RW [a1 trustline, Balance(C dest)]. Golden dest is a deployed wasm contract; here the
// contract id is sha256("g6/dest-contract") with no contract deployed (the SAC does not read the destination's instance).
async function main() {
  const info = await waitReady();
  log.push({ startInfo: { ledger: info.ledger, state: info.state, network: info.network } });
  await upgrade(`protocolversion=${PROTOCOL}&basereserve=5000000`);
  await close('upgrade protocol ' + PROTOCOL);                                         // L2
  await settingsUpgrade(process.env.UPGRADE_DIR + '/enable.xdr');                       // L3-7
  await settingsUpgrade(process.env.UPGRADE_DIR + '/' + SETTINGS);                      // L8-12
  await classic('create-a1', root, [Operation.createAccount({ destination: A1.publicKey(), startingBalance: '100' })]);   // L13
  await classic('a1-changetrust', A1, [Operation.changeTrust({ asset: USDC, limit: '100' })]);                           // L14
  await classic('root-pay-a1', root, [Operation.payment({ destination: A1.publicKey(), asset: USDC, amount: '100' })]);   // L15
  {                                                                                      // L16 deploy SAC(USDC:root), source root
    const tx = tb(await acct(root)).addOperation(Operation.createStellarAssetContract({ asset: USDC }))
      .setSorobanData(sorobanData([], [instanceKey(SUSDC)])).build();
    tx.sign(root); await submit('deploy-sac-usdc', tx); rec('deploy-sac-usdc', { tx, close: await close('deploy-sac-usdc') });
  }
  const destId = new xdr.ContractId(sha('g6/dest-contract'));   // js-xdr 5: ContractId wrapper
  const MUX = 987654321987654321n;
  const dest = xdr.ScAddress.scAddressTypeMuxedContract(new xdr.MuxedContract({ id: MUX, contractId: destId }));
  const destC = xdr.ScAddress.scAddressTypeContract(destId);
  const balKey = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: SUSDC.addr,
    key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), xdr.ScVal.scvAddress(destC)]), durability: xdr.ContractDataDurability.persistent }));
  const args = [xdr.ScVal.scvAddress(scAcct), xdr.ScVal.scvAddress(dest), i128(100000000)];
  const RO = [acctKey(root.publicKey()), instanceKey(SUSDC)], RW = [tlKey(A1, USDC), balKey];
  rec('sac-transfer-muxed', await invoke('sac-transfer-muxed', A1, SUSDC, 'transfer', args, [srcAuth(invocation(SUSDC, 'transfer', args))], RO, RW, GOLDEN_RES, '100'));  // L17 (golden L13)
  await close('final empty');                                                            // L18
  writeFileSync(OUT + '/driver.json', JSON.stringify({
    passphrase: PP, networkId: sha(PP).toString('hex'), protocol: PROTOCOL, settings: SETTINGS, root: root.publicKey(),
    accounts: { a1: A1.publicKey() }, asset: USDC.toString(), sac: SUSDC.id, dest: S.Address.fromScAddress(dest).toString(), steps,
    focus: { 'sac-transfer-muxed': 'golden frame 11 (L13)' }, driverMaxRssKB: process.resourceUsage().maxRSS, log }, null, 1));
}
main().catch((e) => { console.error('DRIVER FAILED', e); writeFileSync(OUT + '/driver.json', JSON.stringify({ error: String(e.stack), log }, null, 1)); process.exit(1); });
