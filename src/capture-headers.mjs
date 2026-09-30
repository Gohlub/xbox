export function captureHeaders(url,headers) {
 const parsed=new URL(url);
 if(parsed.origin!=='https://api.x.com'||parsed.pathname!=='/1.1/account/settings.json')return null;
 const picked=Object.fromEntries(['cookie','authorization','x-csrf-token','x-client-transaction-id'].filter(k=>headers[k]).map(k=>[k,headers[k]]));
 if(!picked.cookie?.split(';').some(c=>c.trim().startsWith('auth_token='))||!picked.authorization||!picked['x-csrf-token'])return null;
 if(Object.values(picked).some(v=>typeof v!=='string'||/[\r\n]/.test(v)))return null;
 return picked;
}
