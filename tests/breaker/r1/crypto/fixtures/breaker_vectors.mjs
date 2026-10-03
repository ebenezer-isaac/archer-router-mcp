import './polyfill.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
const v = await import('./js/vendor-BrE4IMR2.js');
const us = await import('./js/update-store-DQkZxaRI.js');
const pinia = v.b0(); pinia.install({ provide(){}, config:{ globalProperties:{} } });
const dev = us.u();
dev.deviceConfig = { ...dev.deviceConfig, certification:['US FCC','SG CLS L1 STAGE2'] };
const ct=us.w, RSA=us.v, Enc=us.E, tok=us.d, Feat=us.x, Fen=us.y;

// fixed keypair for this run
const kp = crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
const jwk = kp.publicKey.export({format:'jwk'});
const nHex = Buffer.from(jwk.n,'base64url').toString('hex');
const eHex = Buffer.from(jwk.e,'base64url').toString('hex');
const privPem = kp.privateKey.export({format:'pem',type:'pkcs8'});

const KEY='1234567890123456', IV='6543210987654321';
const AES_FMT=`k=${KEY}&i=${IV}`;

tok.setToken('TESTSTOK0123456789abcdef');
Enc.init('deadbeef', 1000, nHex, eHex);
const enc = Enc.getEncryptor();
enc.setAESFormattedKey(AES_FMT);

function aesOnly(body){ return enc.aes.encrypt(body); }
function hmacSign(hash, s){
  // reproduce bundle post-login signature exactly via enc.encrypt by controlling state
  // but easier: call the public generateSignature indirectly through encrypt.
  return null;
}
// post-login request via the bundle's own encrypt()
function bundleRequest(body, seq){
  enc.setSequence(seq); enc.setHash('placeholder-will-be-overwritten-by-rolling');
  // encrypt() computes rolling hash itself when replace_hash & !withAesKey & token valid
  return enc.encrypt(body, false); // {sign,data} or {}
}
// login via bundle
function bundleLogin(body, seq, pwHash){
  enc.setSequence(seq); enc.setHash(pwHash);
  return enc.encrypt(body, true);
}

const out = { _about:'BREAKER new vectors: bundle-authoritative outputs for divergence hunt', inputs:{KEY,IV,rsa_public_n_hex:nHex,rsa_public_e_hex:eHex,test_rsa_private_pem_pkcs8:privPem}, cases:[] };

// ---- body length edges + seq edges ----
const bodies = {
  'len0':'',
  'len52':'a'.repeat(52),
  'len53':'a'.repeat(53),
  'len54':'a'.repeat(54),
  'len105':'a'.repeat(105),
  'len106':'a'.repeat(106),
  'len107':'a'.repeat(107),
};
for(const [name,body] of Object.entries(bodies)){
  const aes = aesOnly(body);
  const rolling = ct.SHA256(aes).toString();
  const r = bundleRequest(body, 1000);
  out.cases.push({kind:'request', name, body_len:body.length, seq:1000, aes_b64:aes, aes_b64_len:aes.length, rolling_hash:rolling, s:1000+aes.length, sign:r.sign??null, data:r.data??null, encrypt_returned_empty: !('sign' in r)});
}
// seq edges with a normal body
for(const seq of [0, 1, 2147483648]){
  const body='operation=read';
  const aes=aesOnly(body);
  const rolling=ct.SHA256(aes).toString();
  const r=bundleRequest(body, seq);
  out.cases.push({kind:'request_seq', name:`seq${seq}`, body, seq, aes_b64:aes, aes_b64_len:aes.length, rolling_hash:rolling, s:seq+aes.length, sign:r.sign??null, data:r.data??null, encrypt_returned_empty: !('sign' in r)});
}

// ---- key/iv leading zeros ----
{
  const K='0000000000000001', I='0000000000000002';
  enc.setAESFormattedKey(`k=${K}&i=${I}`);
  const body='operation=read';
  const aes=enc.aes.encrypt(body);
  const rolling=ct.SHA256(aes).toString();
  const r=bundleRequest(body,1000);
  out.cases.push({kind:'request_lzkey', name:'leadingzero_key_iv', key:K, iv:I, aes_fmt:`k=${K}&i=${I}`, body, aes_b64:aes, rolling_hash:rolling, s:1000+aes.length, sign:r.sign, data:r.data});
  enc.setAESFormattedKey(AES_FMT); // restore
}

// ---- unicode passwords: hash + RSA plaintext bytes ----
function decryptPkcs1(hexCt){
  const buf=Buffer.from(hexCt,'hex');
  const rec=crypto.privateDecrypt({key:kp.privateKey, padding:crypto.constants.RSA_PKCS1_PADDING}, buf);
  return rec.toString('hex');
}
for(const [name,pw] of Object.entries({ascii:'TestPass123', bmp:'café-Ñ-ü', astral:'pw🔑🎉', mixed:'aé🔑z'})){
  const pwHash=ct.SHA256('admin'+pw).toString();
  const pwRsa=RSA.encrypt(pw,nHex,eHex); // jsbn pkcs1 v1.5
  let recovered=null, recoverErr=null;
  try{ recovered=decryptPkcs1(pwRsa); }catch(e){ recoverErr=String(e); }
  out.cases.push({kind:'password', name, pw, pw_hash:pwHash, pw_rsa_hex:pwRsa, pw_rsa_hex_len:pwRsa.length, recovered_plaintext_hex:recovered, recover_error:recoverErr, utf8_hex:Buffer.from(pw,'utf8').toString('hex')});
}

// ---- 1 MB body ----
{
  const body='x'.repeat(1024*1024);
  const aes=enc.aes.encrypt(body);
  const rolling=ct.SHA256(aes).toString();
  out.cases.push({kind:'bigbody', name:'1MB', body_len:body.length, aes_b64_len:aes.length, aes_b64_has_newline: aes.includes('\n')||aes.includes('\r'), rolling_hash:rolling, s:1000+aes.length, aes_b64_sha256: ct.SHA256(aes).toString()});
}

// ---- empty-string sign plaintext chunking (bundle _getEncryptedSignature over "") ----
// The bundle loops for(n=0;n<len;n+=53); len=0 -> no iterations -> i stays "".
// Exercise via a request whose sign plaintext we can't force empty; instead document directly:
out.chunk_empty_note = 'bundle _getEncryptedSignature over empty string returns "" (loop body never runs)';

// ---- feature map: isSupport across ALL known flags for several certifications ----
const certs = {
  'SG':['US FCC','SG CLS L1 STAGE2'],
  'US_only':['US FCC'],
  'empty':[],
  'RG':['RG'],
  'CE_RED':['CE RED'],
};
const featByCert={};
for(const [cname,cval] of Object.entries(certs)){
  dev.deviceConfig={...dev.deviceConfig, certification:cval};
  featByCert[cname]=Object.fromEntries(Object.values(Fen).map(k=>[k,Feat.isSupport(k)]));
}
out.feature_map_all_flags = Object.values(Fen);
out.isSupport_by_cert = featByCert;
dev.deviceConfig={...dev.deviceConfig, certification:['US FCC','SG CLS L1 STAGE2']};

fs.writeFileSync('breaker_vectors.json', JSON.stringify(out,null,2));
console.log('WROTE breaker_vectors.json; cases:', out.cases.length);
for(const c of out.cases){
  if(c.kind==='password') console.log('PW', c.name, 'utf8=',c.utf8_hex,'recovered=',c.recovered_plaintext_hex, 'MATCH=', c.utf8_hex===c.recovered_plaintext_hex);
  if(c.kind==='request_seq') console.log('SEQ', c.seq, 'empty?', c.encrypt_returned_empty, 'sign?', !!c.sign);
  if(c.kind==='request') console.log('REQ', c.name, 'aeslen', c.aes_b64_len, 's', c.s, 'empty?', c.encrypt_returned_empty);
}
console.log('FEATURES', JSON.stringify(out.feature_map_all_flags));
console.log('isSupport SG', JSON.stringify(out.isSupport_by_cert.SG));
