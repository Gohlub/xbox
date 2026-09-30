import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {app,fixtures,claim} from './helpers.mjs';
test('CLI sends one saved portable proof to multiple URL destinations and metadata contains no message',async t=>{
 const f=fixtures(),alice=f.make(),bob=f.make('bob','456'),carol=f.make('carol','789');const a=await app(t,f,14323),b=await app(t,f,14324);
 const owner=(await a.req('/inboxes',claim(bob,a.origin))).data,other=(await b.req('/inboxes',claim(carol,b.origin))).data;
 await a.req('/inboxes/bob/policy',{allowIds:['123']},owner.ownerToken,'PUT');await b.req('/inboxes/carol/policy',{allowIds:['123']},other.ownerToken,'PUT');
 const key=path.join(a.dir,'agent.json'),body=path.join(a.dir,'message.txt');fs.writeFileSync(key,JSON.stringify(alice));fs.writeFileSync(body,'private message');
 const cli=(args,env={})=>new Promise(resolve=>{const p=spawn(process.execPath,['src/cli.mjs',...args],{env:{...process.env,INBOX_URL:a.origin,...env}});let stdout='',stderr='';p.stdout.on('data',x=>stdout+=x);p.stderr.on('data',x=>stderr+=x);p.on('close',code=>resolve({code,stdout,stderr}));});
 for(const url of [a.origin+'/inboxes/bob',b.origin+'/inboxes/carol']){const r=await cli(['send',key,url,body]);assert.equal(r.code,0,r.stderr);assert.equal(JSON.parse(r.stdout).status,'quarantined');}
 const meta=await cli(['metadata','bob'],{INBOX_READER_TOKEN:owner.readerToken});assert.equal(meta.code,0);assert.match(meta.stdout,/alice/);assert.doesNotMatch(meta.stdout,/private message/);
 const output=await cli(['envelope',key,'bob',body]);assert.equal(output.code,0);assert.deepEqual(JSON.parse(output.stdout).proof,alice.proof);
 assert.equal((await cli(['send',key,'https://example.com/inboxes/bob?bad',body])).code,1);
});
