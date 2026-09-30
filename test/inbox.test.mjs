import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createInbox} from '../src/server.mjs';
import {keys,signed} from '../src/crypto.mjs';
import {X_HOST,X_PATH} from '../src/x-endpoint.mjs';
import {parseXProof} from '../src/proof.mjs';
function event(handle,enrollment){const body=JSON.stringify({data:{viewer:{user_results:{result:{__typename:'User',rest_id:handle==='alice'?'123':'456',core:{screen_name:handle}}}}}});return {server_name:X_HOST,session:{enrollment,id:'test'},transcript:{sent:`GET ${X_PATH} HTTP/1.1\r\n\0`,recv:`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: ${new Date().toUTCString()}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`}};}
test('proof parser rejects wrong origin, endpoint, redaction, stale data and non-200',()=>{
 const good=event('alice','test');assert.equal(parseXProof(good).handle,'alice');
 for(const bad of [{...good,server_name:'evil.test'},{...good,transcript:{...good.transcript,sent:'GET /users/alice HTTP/1.1\r\n'}},{...good,transcript:{...good.transcript,recv:good.transcript.recv+'\0'}},{...good,transcript:{...good.transcript,recv:good.transcript.recv.replace('200 OK','401 Unauthorized')}},{...good,transcript:{...good.transcript,recv:good.transcript.recv.replace(/Date:.*\r\n/,'Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n')}}])assert.throws(()=>parseXProof(bad));
});
test('Viewer proof requires ID and exact self query; unicode response is supported',()=>{
 const good=event('alice','test');
 for(const changed of [good.transcript.recv.replace('"123"','123'),good.transcript.recv.replace('"rest_id"','"other_id"')]) {
  const recv=changed.replace(/Content-Length: [0-9]+/,`Content-Length: ${Buffer.byteLength(changed.split('\r\n\r\n')[1])}`);
  assert.throws(()=>parseXProof({...good,transcript:{...good.transcript,recv}}),/account ID/);
 }
 assert.throws(()=>parseXProof({...good,transcript:{...good.transcript,sent:good.transcript.sent.replace('Viewer?','UserByScreenName?')}}),/endpoint/);
 const body=JSON.stringify({data:{viewer:{user_results:{result:{__typename:'User',rest_id:'9007199254740993',core:{screen_name:'alice',name:'你好'}}}}}});
 const recv=`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: ${new Date().toUTCString()}\r\nTransfer-Encoding: chunked\r\n\r\n${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\n\r\n`;
 assert.equal(parseXProof({...good,transcript:{...good.transcript,recv}}).xUserId,'9007199254740993');
});
test('repeat cookies are allowed but duplicate identity framing headers are rejected',()=>{
 const good=event('alice','test');
 const recv=good.transcript.recv.replace('Content-Type:','Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type:');
 assert.equal(parseXProof({...good,transcript:{...good.transcript,recv}}).xUserId,'123');
 assert.throws(()=>parseXProof({...good,transcript:{...good.transcript,recv:recv.replace('Content-Type:','Content-Type: application/json\r\nContent-Type:')}}),/Duplicate/);
});
