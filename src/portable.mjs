import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createPublicKey} from 'node:crypto';
import {hash} from './crypto.mjs';
import {parseXProof} from './proof.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const nativeBinary=path.join(root,'vendor/tlsn-extension/servers/target/release/inbox-prover');
export const PROOF_FORMAT='tlsn-inbox-v1';
export const PROOF_AGE_MS=86400000;
export function trustedKeys(file=process.env.INBOX_TRUST_FILE) {
 if(!file)return [];
 const data=JSON.parse(fs.readFileSync(file,'utf8'));
 if(!Array.isArray(data.notaryKeys)||data.notaryKeys.length>16||!data.notaryKeys.every(k=>typeof k==='string'&&/^(02|03)[a-f0-9]{64}$/.test(k)))throw Error('Trust file must contain compressed secp256k1 notaryKeys');
 return [...new Set(data.notaryKeys)];
}
export function proofId(proof) {
 if(proof?.format!==PROOF_FORMAT||typeof proof.presentation!=='string'||proof.presentation.length>349528||!proof.presentation.length)throw Error('Portable TLSNotary presentation required');
 const bytes=Buffer.from(proof.presentation,'base64');
 if(bytes.length>262144||bytes.toString('base64')!==proof.presentation)throw Error('Invalid presentation encoding');
 return hash(bytes);
}
export function native(mode,input,{signal,timeout=150000}={}) {
 return new Promise((resolve,reject)=>{
  const child=spawn(nativeBinary,[mode],{stdio:['pipe','pipe','pipe'],signal});let chunks=[],size=0,done=false;
  const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);err?reject(err):resolve(value);};
  const timer=setTimeout(()=>{child.kill('SIGKILL');finish(Error('Native operation timed out'));},timeout);
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>524288){child.kill('SIGKILL');finish(Error('Native output limit'));}else chunks.push(chunk);});
  child.stderr.resume();child.stdin.on('error',()=>{});
  child.on('error',()=>finish(Error('Native TLSNotary unavailable; run npm run setup')));
  child.on('close',code=>{if(code!==0)return finish(Error('TLSNotary proof rejected'));try{finish(null,JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch{finish(Error('Invalid native result'));}});
  child.stdin.end(JSON.stringify(input));
 });
}
export function createProofVerifier({notaryKeys=[],verifyNative=native,now=Date.now}={}) {
 const cache=new Map();let active=0;
 return async proof=>{
  const id=proofId(proof),time=now();
  if(cache.has(id)){const c=cache.get(id);if(c.expiresAt<=time)throw Error('Proof expired; renew with human X login');return c;}
  if(!notaryKeys.length)throw Error('No trusted notary configured');
  if(active>=2)throw Object.assign(Error('Proof verifier busy'),{status:429});
  active++;
  try {
   const event=await verifyNative('verify',{presentation:proof.presentation,trustedNotaryKeys:notaryKeys},{timeout:10000});
   if(!notaryKeys.includes(event.notaryKey)||!Number.isSafeInteger(event.time)||event.time<=0)throw Error('Invalid notary or timestamp');
   const issuedAt=event.time*1000,expiresAt=issuedAt+PROOF_AGE_MS;
   if(issuedAt>time+60000||expiresAt<=time)throw Error('Proof expired or future dated');
   if(typeof event.subject!=='string'||event.subject.length>200||createPublicKey(event.subject).asymmetricKeyType!=='ed25519')throw Error('Invalid agent key');
   const identity=parseXProof(event,{referenceTime:issuedAt});
   const result={id,subject:event.subject,...identity,issuedAt,expiresAt,notaryKey:event.notaryKey,kind:PROOF_FORMAT};
   if(cache.size>=256)cache.delete(cache.keys().next().value);cache.set(id,result);return result;
  }finally{active--;}
 };
}
