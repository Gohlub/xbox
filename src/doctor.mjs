import fs from 'node:fs';
import {chromium} from 'playwright';
import {nativeBinary,trustedKeys} from './portable.mjs';
export async function checkSetup(base){
 const checks=[];const add=(name,ok,detail)=>checks.push({name,ok,detail});
 const executable=p=>{try{fs.accessSync(p,fs.constants.X_OK);return true;}catch{return false;}};
 add('native-tlsnotary',executable(nativeBinary),'Run npm run setup if missing.');
 add('login-browser',executable(chromium.executablePath()),'Human login requires an interactive desktop.');
 try{add('trusted-notaries',trustedKeys().length>0,'Set INBOX_TRUST_FILE to the operator-provided public trust file.');}catch{add('trusted-notaries',false,'Invalid trust configuration.');}
 add('notary-client-config',!!process.env.INBOX_NOTARY_CONFIG&&fs.existsSync(process.env.INBOX_NOTARY_CONFIG),'Needed for login only; set INBOX_NOTARY_CONFIG.');
 try{const r=await fetch(base+'/issuer',{redirect:'error',signal:AbortSignal.timeout(3000)});const info=await r.json();add('inbox-api',r.ok&&info.issuer===base&&info.protocol==='tlsn-inbox-v1','Needed for receiving or sending; login is independent.');}catch{add('inbox-api',false,'Start npm start or set INBOX_URL.');}
 return {ready:checks.every(c=>c.ok),checks,liveEnrollmentVerified:false};
}
