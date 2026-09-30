import { createHash, generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
export const hash = value => createHash('sha256').update(value).digest('hex');
export function canonical(x) {
  if (Array.isArray(x)) return `[${x.map(canonical).join(',')}]`;
  if (x && typeof x === 'object') return `{${Object.keys(x).sort().map(k => JSON.stringify(k)+':'+canonical(x[k])).join(',')}}`;
  return JSON.stringify(x);
}
export function keys() { return generateKeyPairSync('ed25519', { publicKeyEncoding:{type:'spki',format:'pem'}, privateKeyEncoding:{type:'pkcs8',format:'pem'} }); }
export const signed = (value, key) => sign(null, Buffer.from(canonical(value)), key).toString('base64');
export function valid(value, signature, key) { try { return createPublicKey(key).asymmetricKeyType === 'ed25519' && verify(null, Buffer.from(canonical(value)), key, Buffer.from(signature,'base64')); } catch { return false; } }
