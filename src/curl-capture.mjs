// Parse Chrome's “Copy as cURL (bash)” as data. Never invoke a shell or curl.
import {captureHeaders} from './capture-headers.mjs';
export function parseCapturedCurl(text){
 const fail=()=>{throw Error('Paste one authenticated settings.json request using Copy as cURL (bash).');};
 if(typeof text!=='string'||Buffer.byteLength(text)>65536||text.includes('\0'))return fail();
 const tokens=[];let token='',quote=null,started=false;
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(quote==="'"){if(c==="'")quote=null;else token+=c;continue;}
  if(quote==='"'){
   if(c==='"'){quote=null;continue;}
   if(c==='$'||c==='`')return fail();
   if(c==='\\'){const next=text[++i];if(next===undefined)return fail();if(next==='\n')continue;token+=next;continue;}
   token+=c;continue;
  }
  if(c==="'"||c==='"'){quote=c;started=true;continue;}
  if(c==='\\'){const next=text[++i];if(next===undefined)return fail();if(next==='\n')continue;if(next==='\r'&&text[i+1]==='\n'){i++;continue;}token+=next;started=true;continue;}
  if(/\s/.test(c)){if(started){tokens.push(token);token='';started=false;}continue;}
  if(/[;|&<>`$()]/.test(c))return fail();
  token+=c;started=true;
 }
 if(quote)return fail();if(started)tokens.push(token);
 if(tokens.shift()!=='curl')return fail();
 let url=null,method='GET';const headers=Object.create(null);
 const add=(name,value)=>{name=name.toLowerCase();if(!/^[a-z0-9-]+$/.test(name)||/[\r\n\0]/.test(value)||Object.hasOwn(headers,name))return fail();headers[name]=value;};
 for(let i=0;i<tokens.length;i++){
  const arg=tokens[i];
  if(['-H','--header','-b','--cookie','-X','--request','--url'].includes(arg)){
   const value=tokens[++i];if(value===undefined)return fail();
   if(arg==='-H'||arg==='--header'){const index=value.indexOf(':');if(index<1)return fail();add(value.slice(0,index),value.slice(index+1).trim());}
   else if(arg==='-b'||arg==='--cookie'){if(!value.includes('='))return fail();add('cookie',value);}
   else if(arg==='-X'||arg==='--request')method=value;
   else {if(url!==null)return fail();url=value;}
  }else if(['--compressed','--http1.1','--http2','--globoff'].includes(arg))continue;
  else if(arg.startsWith('https://')&&url===null)url=arg;
  else return fail();
 }
 if(method!=='GET'||!url)return fail();
 let parsed;try{parsed=new URL(url);}catch{return fail();}
 if(parsed.username||parsed.password||parsed.hash)return fail();
 const picked=captureHeaders(url,headers);if(!picked)return fail();return picked;
}
