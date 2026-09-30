// Operator-invoked acceptance test using an already saved, human-approved proof.
// No login credentials are read; no external messages or classifier calls are sent.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createInbox} from '../src/server.mjs';
import {createProofVerifier,proofId,trustedKeys} from '../src/portable.mjs';
import {signed} from '../src/crypto.mjs';
const file=process.argv[2];if(!file)throw Error('Usage: npm run test:identity -- KEY_FILE (with INBOX_TRUST_FILE)');
const k=JSON.parse(fs.readFileSync(file,'utf8')),notaryKeys=trustedKeys();
const identity=await createProofVerifier({notaryKeys})(k.proof);assert.equal(identity.subject,k.publicKey);
const dirs=[],servers=[];
try{
 for(const port of [17049,17050]){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'inbox-identity-'));dirs.push(dir);
  const app=createInbox({dir,port,notaryKeys,filter:async()=>({bucket:'unscored',reason:'acceptance-test'})});servers.push(app.server);
  await new Promise((resolve,reject)=>{app.server.once('error',reject);app.server.listen(port,'127.0.0.1',resolve);});
  const req=async(route,body,token,method=body?'POST':'GET')=>{const r=await fetch(app.origin+route,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});return {status:r.status,data:await r.json()};};
  const claim={action:'create-inbox',audience:app.origin,proofId:proofId(k.proof),timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};
  const created=await req('/inboxes',{...claim,proof:k.proof,signature:signed(claim,k.privateKey)});assert.equal(created.status,201);const owner=created.data;
  const route='/inboxes/'+identity.handle;
  const message={recipient:identity.handle,audience:app.origin,proofId:proofId(k.proof),body:'Portable proof interoperability test.',timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};
  const envelope={proof:k.proof,message,signature:signed(message,k.privateKey)};
  assert.equal((await req(route+'/messages',envelope)).status,403);
  assert.equal((await req(route+'/policy',{allowIds:[identity.xUserId]},owner.ownerToken,'PUT')).status,200);
  const wrong={...message,audience:'https://wrong.example'};
  assert.equal((await req(route+'/messages',{proof:k.proof,message:wrong,signature:signed(wrong,k.privateKey)})).status,400);
  const sent=await req(route+'/messages',envelope);assert.equal(sent.status,202);assert.equal((await req(route+'/messages',envelope)).status,409);
  const metadata=await req(route+'/metadata',null,owner.readerToken);assert.equal(metadata.data.messages[0].senderId,identity.xUserId);assert.doesNotMatch(JSON.stringify(metadata.data),/interoperability|body/);
  assert.equal((await req(route+'/feed',null,owner.readerToken)).data.messages.length,0);
  assert.equal((await req(route+'/quarantine',null,owner.readerToken)).status,401);
  assert.equal((await req(route+'/messages/'+sent.data.id+'/release',{},owner.readerToken)).status,401);
  assert.equal((await req(route+'/messages/'+sent.data.id+'/release',{},owner.ownerToken)).status,200);
  assert.equal((await req(route+'/feed',null,owner.readerToken)).data.messages[0].body,message.body);
 }
 console.log(JSON.stringify({passed:true,independentInboxes:2,portableProof:true,offlineVerification:true,allowlist:true,replayProtection:true,metadataOnly:true,ownerOnlyRelease:true,proofExpiresAt:identity.expiresAt}));
}finally{
 await Promise.all(servers.map(server=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);})));for(const dir of dirs)fs.rmSync(dir,{recursive:true,force:true});
}
