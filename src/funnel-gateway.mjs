import http from 'node:http';
import {validateOrigin} from './config.mjs';
// Owner operations are accessible only on the private loopback API.
export function publicRoute(method,url){
 if(method==='GET'&&['/','/signup','/signup.js','/issuer'].includes(url))return true;
 if(method==='POST'&&['/inboxes','/identities'].includes(url))return true;
 if(method==='GET'&&/^\/inboxes\/[a-z0-9_]{1,15}(\/(feed|metadata))?$/.test(url))return true;
 return method==='POST'&&/^\/inboxes\/[a-z0-9_]{1,15}\/messages$/.test(url);
}
export function createGateway({origin,apiPort=4310}){
 const expected=validateOrigin(origin);if(expected.protocol!=='https:')throw Error('Funnel requires a public HTTPS origin');
 const server=http.createServer((req,res)=>{
  const fail=(status,message)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:message}));};
  if(req.headers.host!==expected.host)return fail(403,'Invalid Host');
  if(!publicRoute(req.method,req.url))return fail(404,'Not found');
  const headers={...req.headers,host:expected.host};for(const key of Object.keys(headers))if(key.startsWith('x-forwarded-')||key.startsWith('tailscale-')||key==='forwarded')delete headers[key];
  const upstream=http.request({hostname:'127.0.0.1',port:apiPort,path:req.url,method:req.method,headers},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
  upstream.setTimeout(15000,()=>upstream.destroy());upstream.on('error',()=>{if(!res.headersSent)fail(502,'Inbox unavailable');else res.destroy();});req.on('aborted',()=>upstream.destroy());res.on('close',()=>upstream.destroy());req.pipe(upstream);
 });
 server.requestTimeout=15000;server.headersTimeout=10000;server.timeout=20000;server.maxConnections=100;
 server.on('upgrade',(_req,socket)=>socket.destroy());return server;
}
