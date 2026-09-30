import {captureHeaders} from './capture-headers.mjs';
import {parseCapturedCurl} from './curl-capture.mjs';
import {spawn} from 'node:child_process';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {native,createProofVerifier} from './portable.mjs';
import {X_PATH} from './x-endpoint.mjs';
import {hash} from './crypto.mjs';
const htmlEscape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export {captureHeaders} from './capture-headers.mjs';
export async function createReview({fingerprint,issuer,onApprove,onFinish,isReady,portable=false,creating=false,onCapture}) {
 const capability=randomBytes(32).toString('hex');let phase='waiting',owner=null,error=null,origin;
 const server=http.createServer(async(req,res)=>{
  const send=(status,value,type='application/json')=>{res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"});res.end(type==='application/json'?JSON.stringify(value):value);};
  if(req.headers.host!==new URL(origin).host)return send(403,{error:'Invalid Host'});
  const url=new URL(req.url,origin);
  if(req.method==='GET'&&url.pathname==='/')return send(200,`<!doctype html><html lang="en"><meta charset="utf-8"><title>Connect X · xbox</title><style>body{font:17px system-ui;max-width:700px;margin:60px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}button{padding:12px}</style><h1>${creating?"Create your inbox":"Connect your agent to X"}</h1><p>${creating?"Approve creating your inbox. Owner credentials will appear only in this window.":onCapture?"Use your already signed-in X tab. No new login is needed.":"Sign in on the X tab, then return here."}</p><p>${portable?"Notary service":"Inbox service"}: <strong>${htmlEscape(issuer)}</strong></p><p>Approve only a key you control:</p><pre>${htmlEscape(fingerprint)}</pre><p>${portable?"This proves your X account ID and handle. Your reusable proof shares the full X Viewer response with recipient inboxes, including profile and account metadata. The notary does not receive that plaintext. Request cookies and authorization headers stay hidden.":"Your existing proof is sent to this inbox service. Keep owner credentials outside your agent environment."}</p>${onCapture?`<section><ol><li>In your signed-in X tab, open Developer Tools → Network.</li><li>Filter for <code>settings.json</code> and reload the X tab. Select the request to <code>api.x.com/1.1/account/settings.json</code>.</li><li>Right-click that request → Copy → Copy as cURL (bash).</li><li>Paste below, then click Capture. Do not paste it in a terminal, chat, or file.</li></ol><p>The copied request contains session credentials. It is parsed locally as data, never executed. Clear your clipboard after pasting. Only the proof is saved.</p><textarea id="capture" rows="6" cols="65" autocomplete="off" spellcheck="false" placeholder="Paste the copied request here"></textarea><p><button id="capture-submit">Capture request locally</button></p><p id="capture-status"></p></section>`:''}<button id="approve" disabled>${creating?"Create inbox with this key":"Authorize this key and generate proof"}</button><p id="status">${creating?"Ready to create inbox":"Waiting for X login…"}</p><pre id="owner"></pre><button id="finish" hidden>${portable?'Finish login':'I saved my owner credentials — close setup'}</button><script src="/review.js"></script></html>`,'text/html');
  if(req.method==='GET'&&url.pathname==='/review.js')return send(200,`const token=location.hash.slice(1);history.replaceState(null,'','/');const status=document.querySelector('#status'),approve=document.querySelector('#approve'),finish=document.querySelector('#finish');async function call(path,method='GET',body){const r=await fetch(path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const v=await r.json();if(!r.ok)throw Error(v.error);return v;}async function poll(){try{const s=await call('/status');status.textContent=s.error||({waiting:s.ready?${JSON.stringify(creating?'Proof ready. Approve inbox creation to continue.':onCapture?'Request captured. Approve the key to continue.':'X session detected. Approve the key to continue.')}:'Waiting for X login…',proving:${JSON.stringify(creating?'Creating inbox…':'Generating TLSNotary proof…')},complete:${JSON.stringify(portable?'Portable proof saved. You can use it across compatible inboxes until expiry.':'Verified. Save owner credentials somewhere your agent cannot access.')}}[s.phase]);approve.disabled=!s.ready||s.phase!=='waiting';if(s.owner){document.querySelector('#owner').textContent=JSON.stringify(s.owner,null,2);finish.hidden=false;}if(s.phase!=='complete')setTimeout(poll,1000);}catch(e){status.textContent=e.message;}}approve.onclick=async()=>{approve.disabled=true;try{await call('/approve','POST');}catch(e){status.textContent=e.message;}};const capture=document.querySelector('#capture');if(capture){document.querySelector('#capture-submit').onclick=async()=>{const input=capture.value;capture.value='';try{await call('/capture','POST',{curl:input});document.querySelector('#capture-status').textContent='Request captured in memory. Clear your clipboard, then approve your key.';}catch(e){document.querySelector('#capture-status').textContent=e.message;}};}finish.onclick=async()=>{await call('/finish','POST');window.close();};poll();`,'text/javascript');
  if(req.headers.authorization!==`Bearer ${capability}`)return send(401,{error:'Private browser session required'});
  if(req.method==='POST'&&req.headers.origin!==origin)return send(403,{error:'Same-origin approval required'});
  if(req.method==='GET'&&url.pathname==='/status')return send(200,{phase,ready:isReady(),error,owner});
  if(req.method==='POST'&&url.pathname==='/capture'&&onCapture){
   if(phase!=='waiting')return send(409,{error:'Capture is closed'});
   try{let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>131072)return send(413,{error:'Request too large'});chunks.push(chunk);}const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));onCapture(parseCapturedCurl(data.curl));return send(200,{captured:true});}
   catch{return send(400,{error:'Paste one authenticated settings.json request using Copy as cURL (bash).'});}
  }
  if(req.method==='POST'&&url.pathname==='/approve'){
   if(phase!=='waiting'||!isReady())return send(409,{error:'Login not ready or proof already started'});
   phase='proving';send(202,{started:true});
   try{owner=await onApprove();phase='complete';}catch(e){phase='failed';error='Request failed. Close this window and retry the CLI command.';}return;
  }
  if(req.method==='POST'&&url.pathname==='/finish'&&phase==='complete'){send(200,{done:true});setImmediate(onFinish);return;}
  send(404,{error:'Not found'});
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 origin='http://127.0.0.1:'+server.address().port;
 server.requestTimeout=10000;server.headersTimeout=5000;server.maxConnections=20;
 return {url:origin+'/#'+capability,close:()=>new Promise(r=>{server.closeAllConnections();server.close(r);})};
}
export async function loginBrowser({key,notary,saveProof}) {
 const {chromium}=await import('playwright');
 const browser=await chromium.launch({headless:false});
 const context=await browser.newContext({acceptDownloads:false});
 let captured=null,review,verified=false,finished=false,resolveDone,rejectDone;
 const done=new Promise((resolve,reject)=>{resolveDone=resolve;rejectDone=reject;});done.catch(()=>{});
 const abort=new AbortController();const cancel=()=>{abort.abort();rejectDone(Error('Login cancelled'));};
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
 const timer=setTimeout(()=>{abort.abort();rejectDone(Error('Login timed out; start again'));},600000);
 browser.on('disconnected',()=>{if(!finished)rejectDone(Error(verified?'Proof saved; browser closed before confirmation':'Login browser closed'));});
 context.on('response',async response=>{
  if(response.status()!==200||!response.url().startsWith('https://api.x.com/1.1/account/settings.json'))return;
  try{const candidate=captureHeaders(response.url(),await response.request().allHeaders());if(candidate)captured=candidate;}catch{}
 });
 try{
  review=await createReview({fingerprint:hash(key.publicKey),issuer:notary.url,portable:true,isReady:()=>!!captured,onFinish:()=>{finished=true;resolveDone();},onApprove:async()=>{
   const headers=captured;captured=null;
   const proof=await native('prove',{headers,path:X_PATH,publicKey:key.publicKey,notaryUrl:notary.url,notaryKey:notary.publicKey,notaryToken:notary.token},{signal:abort.signal});
   const identity=await createProofVerifier({notaryKeys:[notary.publicKey]})(proof);
   if(identity.subject!==key.publicKey)throw Error('Agent key mismatch');
   await saveProof(proof,identity);verified=true;
   return {handle:identity.handle,xUserId:identity.xUserId,expiresAt:identity.expiresAt};
  }});
  const approval=await context.newPage();await approval.goto(review.url);
  const x=await context.newPage();await x.goto('https://x.com/i/flow/login');
  console.error('Sign in to X, then return to the Connect X tab to approve your agent key.');await done;
 }finally{clearTimeout(timer);abort.abort();captured=null;process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);await context.close().catch(()=>{});await browser.close().catch(()=>{});if(review)await review.close();}
}
export async function createInboxBrowser({key,issuer,onCreate}) {
 const {chromium}=await import('playwright');const browser=await chromium.launch({headless:false});let review,finished=false,resolveDone,rejectDone;
 const done=new Promise((resolve,reject)=>{resolveDone=resolve;rejectDone=reject;});done.catch(()=>{});
 const timer=setTimeout(()=>rejectDone(Error('Owner setup timed out')),600000);
 browser.on('disconnected',()=>{if(!finished)rejectDone(Error('Owner setup browser closed'));});
 try{
  review=await createReview({fingerprint:hash(key.publicKey),issuer,creating:true,isReady:()=>true,onApprove:onCreate,onFinish:()=>{finished=true;resolveDone();}});
  const page=await browser.newPage();await page.goto(review.url);console.error('Approve inbox creation in the browser and save the owner token outside your agent workspace.');await done;
 }finally{clearTimeout(timer);await browser.close().catch(()=>{});if(review)await review.close();}
}

export function openLocalReview(url){
 const parsed=new URL(url);if(parsed.protocol!=='http:'||parsed.hostname!=='127.0.0.1')throw Error('Local review URL required');
 const command=process.platform==='darwin'?'open':process.platform==='win32'?'rundll32':'xdg-open';
 const args=process.platform==='win32'?['url.dll,FileProtocolHandler',url]:[url];
 return new Promise((resolve,reject)=>{const child=spawn(command,args,{stdio:'ignore'});child.once('error',()=>reject(Error('Could not open the local capture page')));child.once('exit',code=>code===0?resolve():reject(Error('Could not open the local capture page')));});
}
export async function loginExistingSession({key,notary,saveProof}){
 let captured=null,review,resolveDone,rejectDone;
 const done=new Promise((resolve,reject)=>{resolveDone=resolve;rejectDone=reject;});done.catch(()=>{});
 const abort=new AbortController();const cancel=()=>{abort.abort();rejectDone(Error('Capture cancelled'));};
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
 const timer=setTimeout(()=>{abort.abort();rejectDone(Error('Capture timed out; start again'));},600000);
 try{
  review=await createReview({fingerprint:hash(key.publicKey),issuer:notary.url,portable:true,onCapture:headers=>{captured=headers;},isReady:()=>!!captured,onFinish:resolveDone,onApprove:async()=>{
   const headers=captured;captured=null;
   const proof=await native('prove',{headers,path:X_PATH,publicKey:key.publicKey,notaryUrl:notary.url,notaryKey:notary.publicKey,notaryToken:notary.token},{signal:abort.signal});
   const identity=await createProofVerifier({notaryKeys:[notary.publicKey]})(proof);
   if(identity.subject!==key.publicKey)throw Error('Agent key mismatch');
   await saveProof(proof,identity);
   return {handle:identity.handle,xUserId:identity.xUserId,expiresAt:identity.expiresAt};
  }});
  await openLocalReview(review.url);
  console.error('The local capture page is open in your browser. Follow its steps using your already signed-in X tab, then approve your agent key.');
  await done;
 }finally{clearTimeout(timer);abort.abort();captured=null;process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);if(review)await review.close();}
}
