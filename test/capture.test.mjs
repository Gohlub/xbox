import {test} from 'node:test';
import assert from 'node:assert/strict';
import {captureHeaders,createReview} from '../src/capture.mjs';
test('capture only accepts authenticated X settings traffic and drops unrelated headers',()=>{
 const h={cookie:'auth_token=test; ct0=csrf',authorization:'Bearer test','x-csrf-token':'csrf',unrelated:'private'};
 assert.equal(captureHeaders('https://evil.example/1.1/account/settings.json',h),null);
 assert.equal(captureHeaders('https://api.x.com/1.1/users/show.json',h),null);
 assert.equal(captureHeaders('https://api.x.com/1.1/account/settings.json',{...h,cookie:'guest=1'}),null);
 assert.equal(captureHeaders('https://api.x.com/1.1/account/settings.json',{...h,authorization:'bad\r\nheader'}),null);
 assert.deepEqual(Object.keys(captureHeaders('https://api.x.com/1.1/account/settings.json',h)),['cookie','authorization','x-csrf-token']);
});
test('browser approval is capability-bound, same-origin, one-use, and hides owner setup until verified',async t=>{
 let approved=0,finished=0;
 const review=await createReview({fingerprint:'key',issuer:'https://inbox.example',isReady:()=>true,onApprove:async()=>{approved++;return {ownerToken:'owner-secret'};},onFinish:()=>finished++});
 t.after(()=>review.close());const url=new URL(review.url),base=url.origin,auth={Authorization:'Bearer '+url.hash.slice(1)};
 assert.equal((await fetch(base+'/status')).status,401);
 assert.equal((await fetch(base+'/approve',{method:'POST',headers:auth})).status,403);
 assert.equal((await fetch(base+'/approve',{method:'POST',headers:{...auth,Origin:'https://x.com'}})).status,403);
 assert.equal(approved,0);
 const before=await (await fetch(base+'/status',{headers:auth})).json();assert.equal(before.owner,null);
 assert.equal((await fetch(base+'/approve',{method:'POST',headers:{...auth,Origin:base}})).status,202);
 const after=await (await fetch(base+'/status',{headers:auth})).json();assert.equal(after.phase,'complete');assert.equal(after.owner.ownerToken,'owner-secret');
 assert.equal((await fetch(base+'/approve',{method:'POST',headers:{...auth,Origin:base}})).status,409);
 assert.equal(approved,1);
 assert.equal((await fetch(base+'/finish',{method:'POST',headers:{...auth,Origin:base}})).status,200);
 assert.equal(finished,1);
});

test('portable approval explains reuse and finishes without owner bootstrap',async t=>{
 const review=await createReview({fingerprint:'key',issuer:'https://bob.example',portable:true,isReady:()=>true,onApprove:async()=>({handle:'alice',recipient:'bob'}),onFinish:()=>{}});
 t.after(()=>review.close());const url=new URL(review.url),headers={Authorization:'Bearer '+url.hash.slice(1),Origin:url.origin};
 const html=await (await fetch(url.origin)).text();assert.match(html,/notary does not receive/);assert.match(html,/Finish login/);assert.doesNotMatch(html,/I saved my owner credentials/);
 const script=await (await fetch(url.origin+'/review.js')).text();const {Script}=await import('node:vm');assert.doesNotThrow(()=>new Script(script));
 await fetch(url.origin+'/approve',{method:'POST',headers});
 const status=await (await fetch(url.origin+'/status',{headers})).json();assert.equal(status.phase,'complete');assert.equal(status.owner.ownerToken,undefined);assert.equal(status.owner.recipient,'bob');
});
