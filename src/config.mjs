import {trustedKeys} from './portable.mjs';
import path from 'node:path';
export function validateOrigin(value) {
  const url=new URL(value);
  if(url.origin!==value || (url.protocol!=='https:' && !(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))) throw Error('Origin must be HTTPS, or HTTP on loopback, without a path or trailing slash');
  return url;
}
export function environmentConfig(env=process.env) {
  const port=Number(env.PORT||4310);
  if(!Number.isInteger(port)||port<1||port>65535) throw Error('Invalid PORT');
  return {notaryKeys:trustedKeys(env.INBOX_TRUST_FILE),port,publicOrigin:env.PUBLIC_ORIGIN||`http://localhost:${port}`,enrollmentToken:env.ENROLLMENT_TOKEN, ...(env.DATA_DIR?{dir:path.resolve(env.DATA_DIR)}:{})};
}
