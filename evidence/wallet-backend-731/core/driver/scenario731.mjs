// Throwaway: minimal CAP-0073 (SAC `trust`) chain for wallet-backend#731, adapted from the local-core probe driver
// (../../local-core/driver/scenario.mjs). Differences: target protocol is $PROTOCOL (default 28), settings
// file is $SETTINGS (quickstart p<NN>/testnet.json), key labels are 'g5-731/…', and the scenario is minimal.
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
const kp = (label) => Keypair.fromRawEd25519Seed(sha('g5-731/' + label));
const I = kp('issuer'), J = kp('issuer-auth-required'), A = kp('deployer'), B = kp('trustor-sac'), C = kp('trustor-classic'), D = kp('trustor-sac-addr-cred');
const X = new Asset('USDC', I.publicKey());
const Y = new Asset('EURT', J.publicKey());

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
  const newSalt = sha('g5-731/settings-upgrade-salt/' + file.split('/').pop());
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
const SX = sacOf(X), SY = sacOf(Y);
const instanceKey = (sac) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: sac.addr, key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }));
const tlKey = (k1, asset) => xdr.LedgerKey.trustline(new xdr.LedgerKeyTrustLine({ accountId: k1.xdrAccountId(), asset: asset.toTrustLineXDRObject() }));
const nonceKey = (k1, nonce) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: scAcct(k1), key: xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: xdr.Int64.fromString(String(nonce)) })), durability: xdr.ContractDataDurability.temporary }));
const i128 = (n) => S.nativeToScVal(BigInt(n), { type: 'i128' });
const invocation = (sac, fn, args) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: sac.addr, functionName: fn, args })),
  subInvocations: [] });
const srcAuth = (inv) => new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), rootInvocation: inv });
const sorobanData = (ro, rw) => new S.SorobanDataBuilder().setReadOnly(ro).setReadWrite(rw).setResources(50_000_000, 20_000, 20_000).setResourceFee('50000000').build();
async function invoke(name, srcKp, sac, fn, args, auth, ro, rw) {
  const op = Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(new xdr.InvokeContractArgs({ contractAddress: sac.addr, functionName: fn, args })), auth });
  const tx = tb(await acct(srcKp)).addOperation(op).setSorobanData(sorobanData(ro, rw)).build();
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
async function main() {
  const info = await waitReady();
  log.push({ startInfo: { ledger: info.ledger, state: info.state, network: info.network } });
  await upgrade(`protocolversion=${PROTOCOL}&basereserve=5000000`);
  await close('upgrade protocol ' + PROTOCOL);                                         // L2
  await settingsUpgrade(process.env.UPGRADE_DIR + '/enable.xdr');                       // L3-7
  await settingsUpgrade(process.env.UPGRADE_DIR + '/' + SETTINGS);                      // L8-12
  await classic('fund', root, [I, J, A, B, C, D].map((k1) => Operation.createAccount({ destination: k1.publicKey(), startingBalance: '10000' })));  // L13
  {                                                                                      // L14 deploy SAC(USDC:I)
    const tx = tb(await acct(A)).addOperation(Operation.createStellarAssetContract({ asset: X }))
      .setSorobanData(sorobanData([acctKey(I.publicKey())], [instanceKey(SX)])).build();
    tx.sign(A); await submit('deploy-sac-usdc', tx); rec('deploy-sac-usdc', { tx, close: await close('deploy-sac-usdc') });
  }
  {                                                                                      // L15 TRIGGER: trust(B), B has no USDC:I trustline
    const args = [xdr.ScVal.scvAddress(scAcct(B))];
    rec('sac-trust-B', await invoke('sac-trust-B', B, SX, 'trust', args, [srcAuth(invocation(SX, 'trust', args))],
      [instanceKey(SX), acctKey(I.publicKey())], [tlKey(B, X), acctKey(B.publicKey())]));
  }
  {                                                                                      // L16 mint(B) on the contract-created trustline
    const args = [xdr.ScVal.scvAddress(scAcct(B)), i128(1234567)];
    rec('sac-mint-B', await invoke('sac-mint-B', I, SX, 'mint', args, [srcAuth(invocation(SX, 'mint', args))],
      [instanceKey(SX), acctKey(I.publicKey())], [tlKey(B, X)]));
  }
  await classic('control-changetrust-C', C, [Operation.changeTrust({ asset: X })]);    // L17 control
  await classic('control-payment-I-C', I, [Operation.payment({ destination: C.publicKey(), asset: X, amount: '0.1234567' })]);  // L18
  {                                                                                      // L19 SAC transfer B -> C
    const args = [xdr.ScVal.scvAddress(scAcct(B)), xdr.ScVal.scvAddress(scAcct(C)), i128(1000)];
    rec('sac-transfer-B-C', await invoke('sac-transfer-B-C', B, SX, 'transfer', args, [srcAuth(invocation(SX, 'transfer', args))],
      [instanceKey(SX), acctKey(I.publicKey())], [tlKey(B, X), tlKey(C, X)]));
  }
  {                                                                                      // L20 variant: trust(D) authorised by D's ADDRESS credentials, tx source A
    const NONCE = 731;
    const args = [xdr.ScVal.scvAddress(scAcct(D))];
    const unsigned = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
        address: scAcct(D), nonce: xdr.Int64.fromString(String(NONCE)), signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })),
      rootInvocation: invocation(SX, 'trust', args) });
    const signed = await S.authorizeEntry(unsigned, D, curLedger + 1000, PP);
    rec('sac-trust-D-addrcred', await invoke('sac-trust-D-addrcred', A, SX, 'trust', args, [signed],
      [instanceKey(SX), acctKey(I.publicKey())], [tlKey(D, X), acctKey(D.publicKey()), nonceKey(D, NONCE)]));
  }
  await classic('J-set-auth-required', J, [Operation.setOptions({ setFlags: S.AuthRequiredFlag | S.AuthRevocableFlag })]);  // L21
  {                                                                                      // L22 deploy SAC(EURT:J)
    const tx = tb(await acct(A)).addOperation(Operation.createStellarAssetContract({ asset: Y }))
      .setSorobanData(sorobanData([acctKey(J.publicKey())], [instanceKey(SY)])).build();
    tx.sign(A); await submit('deploy-sac-eurt', tx); rec('deploy-sac-eurt', { tx, close: await close('deploy-sac-eurt') });
  }
  {                                                                                      // L23 trust(B) on an AUTH_REQUIRED asset -> flags 0
    const args = [xdr.ScVal.scvAddress(scAcct(B))];
    rec('sac-trust-B-authreq', await invoke('sac-trust-B-authreq', B, SY, 'trust', args, [srcAuth(invocation(SY, 'trust', args))],
      [instanceKey(SY), acctKey(J.publicKey())], [tlKey(B, Y), acctKey(B.publicKey())]));
  }
  await close('final empty');                                                            // L24

  writeFileSync(OUT + '/driver.json', JSON.stringify({
    passphrase: PP, networkId: sha(PP).toString('hex'), protocol: PROTOCOL, settings: SETTINGS, root: root.publicKey(),
    accounts: { I: I.publicKey(), J: J.publicKey(), A: A.publicKey(), B: B.publicKey(), C: C.publicKey(), D: D.publicKey() },
    assets: { X: X.toString(), Y: Y.toString() }, sac: { X: SX.id, Y: SY.id }, steps,
    driverMaxRssKB: process.resourceUsage().maxRSS, log }, null, 1));
}
main().catch((e) => { console.error('DRIVER FAILED', e); writeFileSync(OUT + '/driver.json', JSON.stringify({ error: String(e.stack), log }, null, 1)); process.exit(1); });
