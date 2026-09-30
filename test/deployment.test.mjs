import http from 'node:http';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createInbox} from '../src/server.mjs';
import {keys,signed} from '../src/crypto.mjs';
import {validateOrigin} from '../src/config.mjs';
test('public deployment rejects unsafe origins and missing invitation',()=>{
 for(const origin of ['http://example.com','https://example.com/','https://user:pass@example.com','https://example.com/path']) assert.throws(()=>validateOrigin(origin));
 assert.throws(()=>createInbox({publicOrigin:'https://inbox.example'}),/ENROLLMENT_TOKEN/);
});
test('public origin, private callback, enrollment gate, issuer persistence',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'inbox-public-')),port=14312,token='a'.repeat(64),origin='https://inbox.example';
 const app=createInbox({dir,port,publicOrigin:origin,enrollmentToken:token});
 await new Promise(r=>app.server.listen(port,'127.0.0.1',r));
 t.after(async()=>{await new Promise(r=>app.server.close(r));fs.rmSync(dir,{recursive:true,force:true});});
 async function request(route,{host='inbox.example',headers={},body}={}){return new Promise((resolve,reject)=>{const req=http.request({hostname:'127.0.0.1',port,path:route,method:body?'POST':'GET',headers:{Host:host,'Content-Type':'application/json',...headers}},res=>{let text='';res.on('data',chunk=>text+=chunk);res.on('end',()=>resolve({status:res.statusCode,json:async()=>JSON.parse(text)}));});req.on('error',reject);req.end(body?JSON.stringify(body):undefined);});}
 assert.equal((await request('/issuer',{host:'evil.example',headers:{'X-Forwarded-Host':'inbox.example'}})).status,403);
 assert.equal((await request('/issuer',{headers:{Origin:'https://evil.example'}})).status,403);
 assert.equal((await (await request('/issuer')).json()).issuer,origin);
 const k=keys(),body={publicKey:k.publicKey,signature:signed({action:'enroll',publicKey:k.publicKey},k.privateKey)};
 assert.equal((await request('/inboxes',{body})).status,401);
 const result=await request('/inboxes',{body,headers:{Authorization:'Bearer '+token}});assert.equal(result.status,401); // Missing portable proof, even with an invitation.
 assert.equal((await request('/internal/tlsn',{body:{}})).status,404);
 assert.equal((await request('/authentications',{body:{}})).status,404);
 assert.throws(()=>createInbox({dir,port,publicOrigin:'https://other.example',enrollmentToken:token}),/origin differs/);
});
