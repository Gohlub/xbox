import {X_HOST,X_PATH,X_URL} from './x-endpoint.mjs';
// Only call this on cryptographically verified TLSNotary output.
// Never accept a client-supplied "verified: true" flag or handler result as identity.
export function parseXProof(event,{referenceTime=Date.now()}={}) {
  if (event.server_name !== X_HOST) throw Error('Wrong TLS server');
  const { sent, recv } = event.transcript ?? {};
  if (typeof sent !== 'string' || !sent.startsWith(`GET ${X_PATH} HTTP/1.1\r\n`)) throw Error('Wrong authenticated endpoint');
  if (typeof recv !== 'string' || recv.includes('\0')) throw Error('Full authenticated response required');
  const split = recv.indexOf('\r\n\r\n');
  if (split < 0) throw Error('Missing response headers');
  const lines = recv.slice(0,split).split('\r\n');
  if (!/^HTTP\/1\.[01] 200(?: |$)/.test(lines.shift())) throw Error('X did not return success');
  const headers = new Map();
  for (const line of lines) {
    const i = line.indexOf(':'); if(i < 1) throw Error('Malformed header');
    const name = line.slice(0,i).toLowerCase();
    if(headers.has(name)){if(name==='set-cookie')continue;throw Error('Duplicate header');}
    headers.set(name,line.slice(i+1).trim());
  }
  if (!headers.get('content-type')?.toLowerCase().includes('application/json')) throw Error('Expected JSON');
  if (headers.has('content-encoding') && headers.get('content-encoding') !== 'identity') throw Error('Compressed response unsupported');
  let body = recv.slice(split+4);
  if(headers.get('transfer-encoding') === 'chunked') {
    if(headers.has('content-length')) throw Error('Ambiguous response framing');
    let bytes=Buffer.from(body),chunks=[];
    for (;;) {
      const end=bytes.indexOf('\r\n'),sizeText=bytes.subarray(0,end).toString('ascii');
      if(end<0 || !/^[0-9a-f]+$/i.test(sizeText)) throw Error('Invalid chunk');
      const size=parseInt(sizeText,16);bytes=bytes.subarray(end+2);
      if(!Number.isSafeInteger(size)) throw Error('Invalid chunk size');
      if(size===0){if(!bytes.equals(Buffer.from('\r\n')))throw Error('Unexpected trailers');break;}
      if(bytes.length<size+2||bytes.subarray(size,size+2).toString()!=='\r\n')throw Error('Invalid chunk size');
      chunks.push(bytes.subarray(0,size));bytes=bytes.subarray(size+2);
    }
    body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
  } else {
    if(headers.has('transfer-encoding')) throw Error('Unsupported transfer encoding');
    if(headers.has('content-length') && Number(headers.get('content-length'))!==Buffer.byteLength(body)) throw Error('Truncated response');
  }
  const date=Date.parse(headers.get('date'));
  if(!Number.isFinite(date) || Math.abs(referenceTime-date)>300000) throw Error('Stale X response');
  const data=JSON.parse(body);
  if(data.errors?.length) throw Error('X returned GraphQL errors');
  const user=data.data?.viewer?.user_results?.result;
  if(user?.__typename!=='User' || typeof user.rest_id!=='string' || !/^[1-9][0-9]{0,19}$/.test(user.rest_id)) throw Error('Missing authenticated X account ID');
  const handle=user.core?.screen_name;
  if(typeof handle!=='string' || !/^[a-zA-Z0-9_]{1,15}$/.test(handle)) throw Error('Missing X handle');
  return {xUserId:user.rest_id,handle:handle.toLowerCase(),source:X_URL,observedAt:new Date(date).toISOString()};
}
