import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {validateOrigin} from './config.mjs';
import {keys,signed} from './crypto.mjs';
import {proofId,createProofVerifier,trustedKeys} from './portable.mjs';
const [command,...args]=process.argv.slice(2);let base=process.env.INBOX_URL||'http://localhost:4310';
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const write=(p,x,flag='w')=>{fs.writeFileSync(p,JSON.stringify(x,null,2),{mode:0o600,flag});fs.chmodSync(p,0o600);};
async function request(route,body,method=body?'POST':'GET',token){const r=await fetch(base+route,{method,redirect:'error',signal:AbortSignal.timeout(30000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});const x=await r.json();if(!r.ok)throw Error(`${r.status}: ${x.error}`);return x;}
function destination(to){
 if(to?.startsWith('https://')||to?.startsWith('http://')){const u=new URL(to);validateOrigin(u.origin);const m=/^\/inboxes\/([a-z0-9_]{1,15})$/.exec(u.pathname);if(!m||u.search||u.hash||u.username||u.password)throw Error('Expected inbox URL: https://host/inboxes/handle');base=u.origin;return m[1];}
 const handle=to?.replace(/^@/,'').toLowerCase();if(!handle||!/^[a-z0-9_]{1,15}$/.test(handle))throw Error('Inbox handle or URL required');return handle;
}
function claim(k,action){const c={action,audience:base,proofId:proofId(k.proof),timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};return {...c,proof:k.proof,signature:signed(c,k.privateKey)};}
try{
 validateOrigin(base);let out;
 if(command==='login'||command==='renew'||command==='capture'){
  const file=args[0];if(!file)throw Error('login KEY_FILE');
  if(!process.env.INBOX_NOTARY_CONFIG)throw Error('Set INBOX_NOTARY_CONFIG to the operator-provided notary client JSON');
  const notary=read(process.env.INBOX_NOTARY_CONFIG);
  if(typeof notary.url!=='string'||typeof notary.publicKey!=='string'||!/^(02|03)[a-f0-9]{64}$/.test(notary.publicKey))throw Error('Invalid notary configuration');
  const k=fs.existsSync(file)?read(file):keys();if(!fs.existsSync(file))write(file,k,'wx');
  const {loginBrowser,loginExistingSession}=await import('./capture.mjs');
  const login=command==='capture'?loginExistingSession:loginBrowser;
  await login({key:k,notary,saveProof:(proof,identity)=>{k.proof=proof;k.identity=identity;write(file,k);}});
  out={authenticated:true,handle:k.identity.handle,xUserId:k.identity.xUserId,expiresAt:k.identity.expiresAt,keyFile:file};
 }else if(command==='create'){
  const file=args[0],k=read(file);proofId(k.proof);
  const {createInboxBrowser}=await import('./capture.mjs');
  await createInboxBrowser({key:k,issuer:base,onCreate:async()=>{const owner=await request('/inboxes',claim(k,'create-inbox'),'POST',process.env.INBOX_ENROLLMENT_TOKEN);k.inboxes={...k.inboxes,[owner.url]:{readerToken:owner.readerToken}};write(file,k);out={created:true,url:owner.url,handle:owner.handle};return owner;}});
 }else if(command==='introduce'){const k=read(args[0]);out=await request('/identities',claim(k,'introduce'));}
 else if(command==='inspect'){const k=read(args[0]);out=await createProofVerifier({notaryKeys:trustedKeys()})(k.proof);}
 else if(command==='send'||command==='envelope'){
  const [file,to,bodyFile]=args,k=read(file),recipient=destination(to);
  const message={recipient,audience:base,proofId:proofId(k.proof),body:fs.readFileSync(bodyFile,'utf8'),timestamp:Date.now(),nonce:randomBytes(16).toString('hex')};
  const envelope={proof:k.proof,message,signature:signed(message,k.privateKey)};
  out=command==='envelope'?envelope:await request('/inboxes/'+recipient+'/messages',envelope);
 }else if(command==='feed'||command==='metadata'){const handle=destination(args[0]);out=await request('/inboxes/'+handle+'/'+command,null,'GET',process.env.INBOX_READER_TOKEN);}
 else if(command==='doctor'){const{checkSetup}=await import('./doctor.mjs');out=await checkSetup(base);if(!out.ready)process.exitCode=1;}
 else {console.log('Commands:\n  capture KEY_FILE  # reuse X session via local browser request capture\n  login KEY_FILE  # human X login; portable proof, no recipient required\n  renew KEY_FILE  # repeat login using the same agent key\n  create KEY_FILE  # create inbox; owner token appears only in browser\n  introduce KEY_FILE  # share verified identity for handle allowlisting\n  inspect KEY_FILE  # verify proof locally using INBOX_TRUST_FILE\n  send KEY_FILE HANDLE_OR_INBOX_URL BODY_FILE\n  envelope KEY_FILE HANDLE_OR_INBOX_URL BODY_FILE  # JSON for curl\n  metadata HANDLE_OR_INBOX_URL  # sender info only; INBOX_READER_TOKEN\n  feed HANDLE_OR_INBOX_URL  # owner-released messages only\n  doctor\nINBOX_URL defaults to http://localhost:4310. Login needs INBOX_NOTARY_CONFIG.');process.exit(0);}
 console.log(JSON.stringify(out,null,2));
}catch(e){console.error(e.message);process.exitCode=1;}
