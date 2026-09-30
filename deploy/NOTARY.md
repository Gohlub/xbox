# Operate the shared notary

This service is separate from recipient inboxes. It signs portable MPC-TLS
attestations; clients connect directly to X, and the notary does not receive hidden
request cookies or plaintext responses. It signs one application extension binding
the selected agent public key. Recipients decide what the authenticated X response
means and verify the exact endpoint themselves.

## Pilot setup

On a separate operator-controlled host:

```sh
npm ci
npm run setup -- --server-only
npm run notary:init -- wss://NOTARY-DEVICE.TAILNET.ts.net/notarize
npm run notary:start
```

`NOTARY_DATA_DIR` overrides `.local/notary`. Initialization refuses to overwrite
files. It produces:

- `private.json`: signing private key, pilot access token and loopback port. Never distribute.
- `client.json`: notary URL, pinned public key and pilot access token. Share privately with pilot senders.
- `trust.json`: accepted public signing key. Distribute publicly through an authenticated release channel to inbox operators.

The Rust listener binds only to 127.0.0.1:7048. On that **notary host**, after manually
connecting its Tailscale account and inspecting existing mappings, you can expose it:

```sh
tailscale funnel --bg http://127.0.0.1:7048
```

Use a separate device/hostname from the inbox mapping; do not replace an existing
inbox Funnel route. Funnel terminates public TLS and forwards WebSocket traffic.
Native clients require WSS except on loopback and pin the attestation signing key.
The only accepted upgrade is `/notarize`, with the pilot bearer token and no browser
Origin header. There is no generic TCP proxy or public callback endpoint.

## Limits and key management

Two simultaneous sessions, ten connection attempts per minute globally, 150 seconds
per session, 1 MiB WebSocket frame/message limits, and fixed maximum transcript sizes
of 4 KiB sent and 16 KiB received. The pilot token limits casual access; it is not a
public billing/quota system. Global budgets can be exhausted by another pilot user.
Use operator monitoring and stronger admission controls before a broad launch.
No session content is logged. Only startup readiness and generic process errors
reach stdout/stderr. Never enable upstream trace logs on real user sessions.

A notary-key compromise allows forged inbox identities. Keep signing keys separate
from inbox/agent hosts, encrypt backups and restrict service access. Rotation is a
coordinated trust-file release: distribute a file accepting old and new keys before
switching issuance, keep the old key accepted only through the remaining proof
lifetime, then remove it and restart inboxes. For compromise, remove the affected
key immediately; proofs under it stop working. A URL change with the same trusted
signing key does not invalidate existing proofs.

Proof verification does not call this service. An outage stops signup and renewal,
but existing unexpired proofs remain usable. A future revocation feed or multiple
independent notaries would change that model and is not implemented.

The shared pilot invitation, no durable job queue and no cloud service supervisor
make this a deployment scaffold, not an already operating hosted service. Benchmark
CPU, peak memory, bandwidth and concurrent login capacity on the intended host
before estimating production costs. Do not use tiny fixture timings as a capacity estimate.
