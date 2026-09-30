import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
execFileSync('cargo',['build','--locked','--release','--manifest-path','native/Cargo.toml'],{cwd:root,stdio:'inherit',env:{...process.env,CARGO_TARGET_DIR:path.join(root,'vendor/tlsn-extension/servers/target')}});
if(!process.argv.includes('--server-only'))execFileSync(process.execPath,['node_modules/playwright/cli.js','install','chromium'],{cwd:root,stdio:'inherit'});
console.log('Native portable prover, notary, and offline verifier built. Configure trust before login or receiving messages.');
