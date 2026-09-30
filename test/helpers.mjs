import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createInbox} from '../src/server.mjs';
import {keys,signed} from '../src/crypto.mjs';
import {createProofVerifier,proofId} from '../src/portable.mjs';
import {X_HOST,X_PATH} from '../src/x-endpoint.mjs';
export const NOTARY='02'+'12'.repeat(32);
export function event(handle='alice',subject=keys().publicKey,time=Math.floor(Date.now()/1000),id='123'){
 const body=JSON.stringify({data:{viewer:{user_results:{result:{__typename:'User',rest_id:id,core:{screen_name:handle}}}}}});
 return {server_name:X_HOST,subject,notaryKey:NOTARY,time,transcript:{sent:`GET ${X_PATH} HTTP/1.1\r\n`,recv:`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: ${new Date(time*1000).toUTCString()}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`}};
}
// Only test processes can inject this verifier. The production entry point always invokes Rust.
export function fixtures(){const events=new Map();let serial=0;return {make(handle='alice',id='123',k=keys(),time=Math.floor(Date.now()/1000)){const proof={format:'tlsn-inbox-v1',presentation:Buffer.from('fixture-'+serial++).toString('base64')};events.set(proof.presentation,event(handle,k.publicKey,time,id));return {...k,proof};},verify:async(_mode,v)=>{if(!events.has(v.presentation))throw Error('Invalid cryptographic fixture');return structuredClone(events.get(v.presentation));},events};}
export async function app(t,fixture,port,extra={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'portable-inbox-'));
 const a=createInbox({dir,port,notaryKeys:[NOTARY],verifyProof:createProofVerifier({notaryKeys:[NOTARY],verifyNative:fixture.verify}),filter:async()=>({bucket:'low',provider:'fixture'}),...extra});
 await new Promise(r=>a.server.listen(port,'127.0.0.1',r));
 t.after(async()=>{a.server.closeAllConnections();await new Promise(r=>a.server.close(r));fs.rmSync(dir,{recursive:true,force:true});});
 const req=async(route,body,token,method=body?'POST':'GET')=>{const r=await fetch(a.origin+route,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});return {status:r.status,data:await r.json()};};
 return {...a,req,dir};
}
export function claim(k,origin,action='create-inbox'){const c={action,audience:origin,proofId:proofId(k.proof),timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};return {...c,proof:k.proof,signature:signed(c,k.privateKey)};}
export function envelope(k,origin,recipient='bob',body='Can you explain the proposal?'){
 const message={recipient,audience:origin,proofId:proofId(k.proof),body,timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};return {proof:k.proof,message,signature:signed(message,k.privateKey)};
}
