import fs from 'node:fs';
import path from 'node:path';
import {createECDH,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {nativeBinary} from '../src/portable.mjs';
const command=process.argv[2],dir=path.resolve(process.env.NOTARY_DATA_DIR||'.local/notary');
if(command==='init'){
 const url=process.argv[3]||'ws://127.0.0.1:7048/notarize';const u=new URL(url);
 if(u.pathname!=='/notarize'||u.search||u.hash||u.username||u.password||!(u.protocol==='wss:'||(u.protocol==='ws:'&&['localhost','127.0.0.1'].includes(u.hostname))))throw Error('Use wss://host/notarize or ws://127.0.0.1:7048/notarize');
 fs.mkdirSync(dir,{recursive:true,mode:0o700});const key=createECDH('secp256k1');key.generateKeys();const publicKey=key.getPublicKey('hex','compressed'),token=randomBytes(32).toString('hex');
 const write=(name,data)=>fs.writeFileSync(path.join(dir,name),JSON.stringify(data,null,2)+'\n',{mode:0o600,flag:'wx'});
 write('private.json',{privateKey:key.getPrivateKey('hex'),token,port:7048});write('client.json',{url,publicKey,token});write('trust.json',{notaryKeys:[publicKey]});
 console.log(`Notary configuration created in ${dir}. Distribute trust.json publicly and client.json privately to pilot users. Keep private.json on the notary host.`);
}else if(command==='start'){
 const config=JSON.parse(fs.readFileSync(path.join(dir,'private.json'),'utf8'));if(process.env.NOTARY_PORT)config.port=Number(process.env.NOTARY_PORT);
 const child=spawn(nativeBinary,['notary'],{stdio:['pipe','inherit','inherit']});child.stdin.end(JSON.stringify(config));child.on('error',()=>{console.error('Build native TLSNotary with npm run setup');process.exitCode=1;});child.on('exit',c=>process.exitCode=c??1);for(const s of ['SIGINT','SIGTERM'])process.on(s,()=>child.kill(s));
}else throw Error('Usage: node scripts/notary.mjs init [wss://host/notarize] | start');
