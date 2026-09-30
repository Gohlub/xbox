import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createGateway,publicRoute} from '../src/funnel-gateway.mjs';
test('Funnel default-deny routing keeps owner and verifier operations private',()=>{
 for(const url of ['/internal/tlsn','/authentications','/enrollments','/session','/verifier','/proxy','/inboxes/bob/quarantine','/inboxes/bob/policy','/inboxes/bob/messages/id/release','/inboxes/bob/credentials/revoke','/inboxes/bob/../quarantine','/inboxes/bob/messages?x=1','//internal/tlsn','/%69nternal/tlsn'])for(const method of ['GET','POST','PUT'])assert.equal(publicRoute(method,url),false,url);
 assert.equal(publicRoute('GET','/inboxes/bob'),true);
 assert.equal(publicRoute('POST','/inboxes/bob/messages'),true);
 assert.equal(publicRoute('GET','/inboxes/bob/feed'),true);
 assert.equal(publicRoute('POST','/inboxes'),true);
});
test('Funnel preserves credentials and origin, rejects wrong host, never forwards private routes',async t=>{
 let seen=[];
 const api=http.createServer((req,res)=>{seen.push({url:req.url,headers:req.headers});res.setHeader('Content-Type','application/json');res.end('{}');});
 await new Promise(r=>api.listen(0,'127.0.0.1',r));
 const gateway=createGateway({origin:'https://test.ts.net',apiPort:api.address().port});
 await new Promise(r=>gateway.listen(0,'127.0.0.1',r));
 t.after(async()=>{await Promise.all([new Promise(r=>gateway.close(r)),new Promise(r=>api.close(r))]);});
 const base='http://127.0.0.1:'+gateway.address().port;
 const request=(url,options={})=>new Promise((resolve,reject)=>{const req=http.request(url,options,res=>{res.resume();res.on('end',()=>resolve({status:res.statusCode}));});req.on('error',reject);req.end();});
 const headers={Host:'test.ts.net',Authorization:'Bearer test','X-Forwarded-For':'fake'};
 assert.equal((await request(base+'/inboxes/bob/feed',{headers})).status,200);
 assert.equal(seen[0].headers.host,'test.ts.net');assert.equal(seen[0].headers.authorization,'Bearer test');assert.equal(seen[0].headers['x-forwarded-for'],undefined);
 assert.equal((await request(base+'/internal/tlsn',{headers,method:'POST'})).status,404);
 assert.equal((await request(base+'/inboxes/bob/quarantine',{headers})).status,404);
 assert.equal((await request(base+'/')).status,403);assert.equal(seen.length,1);
});
