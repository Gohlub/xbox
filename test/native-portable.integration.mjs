// Opt-in external-network check. Never uses an existing browser profile or cookies.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createECDH,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {native,nativeBinary,createProofVerifier} from '../src/portable.mjs';
import {keys} from '../src/crypto.mjs';
import {X_PATH} from '../src/x-endpoint.mjs';
test('real X session yields a portable cryptographic proof but unauthenticated response cannot enroll', {timeout:180000},async t=>{
 const key=createECDH('secp256k1');key.generateKeys();const publicKey=key.getPublicKey('hex','compressed'),token=randomBytes(32).toString('hex');
 const p=spawn(nativeBinary,['notary'],{stdio:['pipe','pipe','pipe']});p.stderr.resume();
 t.after(async()=>{if(p.exitCode===null){p.kill();await once(p,'exit');}});
 p.stdin.end(JSON.stringify({privateKey:key.getPrivateKey('hex'),token,port:14327}));
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Notary startup timeout')),10000);p.once('error',reject);p.once('exit',()=>{clearTimeout(timer);reject(Error('Notary startup failed'));});p.stdout.once('data',x=>{clearTimeout(timer);try{assert.equal(JSON.parse(x).ready,true);resolve();}catch(e){reject(e);}});});
 const agent=keys();
 const proof=await native('prove',{notaryUrl:'ws://127.0.0.1:14327/notarize',notaryKey:publicKey,notaryToken:token,publicKey:agent.publicKey,path:X_PATH,headers:{}});
 const verified=await native('verify',{presentation:proof.presentation,trustedNotaryKeys:[publicKey]});
 assert.equal(verified.server_name,'x.com');assert.equal(verified.subject,agent.publicKey);
 await assert.rejects(createProofVerifier({notaryKeys:[publicKey]})(proof));
 console.log('Real X TLS session notarized; offline verification passed; unauthenticated identity rejected.');
});
