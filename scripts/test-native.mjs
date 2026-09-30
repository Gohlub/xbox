import {execFileSync} from 'node:child_process';
import path from 'node:path';
execFileSync('cargo',['test','--release','--locked','--manifest-path','native/Cargo.toml','--','--nocapture'],{stdio:'inherit',env:{...process.env,CARGO_TARGET_DIR:path.resolve('vendor/tlsn-extension/servers/target')}});
