# Self-host an inbox with Tailscale Funnel

The receiver runs **only the inbox API and its public gateway**. Offline verification
uses the native binary on this machine. It does not run the online notary.

1. Install with `npm ci` and `npm run setup -- --server-only`.
2. Obtain the shared notary's public `trust.json` through a trusted channel.
3. Configure the project with your device's HTTPS hostname:

```sh
export INBOX_TRUST_FILE=/absolute/path/to/trust.json
npm run funnel:configure -- https://YOUR-DEVICE.YOUR-TAILNET.ts.net
npm run funnel:service -- api       # terminal 1
npm run funnel:service -- gateway   # terminal 2
```

Configuration is saved privately to `.local/funnel/environment.json`. It includes
an enrollment invitation and trust-file path, never the notary private key. Existing
configuration is not overwritten. If upgrading an existing configuration, add
`INBOX_TRUST_FILE` with an absolute path and stop the old verifier process.
Services load this file without printing secrets.

The project does not join a tailnet or expose this device automatically. Connect
Tailscale to your intended account yourself. Inspect `tailscale funnel status` before
changing any mapping. On macOS, the app's CLI can be
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`; a Homebrew binary may target
a different daemon. The hostname is `Self.DNSName` from `tailscale status --json`
without its trailing dot.

```sh
# Publish the dedicated gateway, not the private API.
tailscale funnel --bg http://127.0.0.1:4311
```

Funnel may require account-side enablement. Keep this machine awake. The API is on
127.0.0.1:4310 and gateway on 127.0.0.1:4311. Do not rewrite the public Host header.
Do not overwrite other Serve/Funnel mappings. To stop this mapping, when port 443
belongs to the inbox, use `tailscale funnel --https=443 off`. This does not stop Node.
For unattended hosting, arrange a process supervisor for both Node services.

## Create and share the inbox

On your human desktop, configure the notary client, perform `login`, then set
`INBOX_URL` to the Funnel origin and `INBOX_ENROLLMENT_TOKEN` to the private invitation.
Run `npm run cli -- create agent.json`. Keep the owner credentials outside agent access.
Share the resulting `https://DEVICE.TAILNET.ts.net/inboxes/HANDLE` URL.

A sender performs one human login against the shared notary and can then use:

```sh
npm run cli -- send agent.json https://DEVICE.TAILNET.ts.net/inboxes/HANDLE message.txt
```

The same proof works at every inbox accepting its notary key until its 24-hour
expiry. The recipient must allow the sender's stable X account ID. No recipient
challenge, online verifier, WebSocket session or per-recipient login is involved.

## Private owner operations

Use the loopback API with the public Host header. These routes are blocked by the
public gateway, even when a valid owner token is supplied there:

```sh
export PUBLIC_ORIGIN=https://YOUR-DEVICE.YOUR-TAILNET.ts.net
curl http://127.0.0.1:4310/inboxes/HANDLE/quarantine \
  -H "Host: ${PUBLIC_ORIGIN#https://}" \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN"
```

Use the same headers for policy, revocation, blocked keys, release and reject. A
remote owner needs private access such as an SSH tunnel; never expose port 4310.

Public routes: landing/signup, protocol/trust information, invitation-protected inbox
creation, signed identity introduction, inbox descriptor, signed messages, authenticated
metadata and released feed. All WebSocket upgrades and old `/authentications`,
`/enrollments`, `/internal/tlsn`, `/session`, `/verifier`, `/proxy` routes are blocked.

## Check and operate

```sh
curl "$PUBLIC_ORIGIN/"
curl "$PUBLIC_ORIGIN/issuer"
curl -i "$PUBLIC_ORIGIN/internal/tlsn"              # 404
curl -i "$PUBLIC_ORIGIN/inboxes/HANDLE/quarantine"  # 404
```

Set `TYPESAFE_API_KEY` in the API's operator environment if you want Jev filtering;
that shares admitted message text with TypeSafe. Errors leave messages quarantined
and unscored. Low-risk results still require explicit owner release.

Protect the data directory and human browser from the agent OS identity. Token
permissions alone cannot protect files that an agent can read directly. State holds
plaintext messages and token hashes; use encrypted disk/backups. Run one process per
data directory, stop it for backups, and monitor storage/limits. Origin is pinned;
changing it needs a fresh data directory or deliberate migration. Old locally issued
credentials no longer authenticate; existing inbox tokens/messages are retained and
owners must re-prove identity for sending. Legacy handle-only allowlists stay denied
until replaced with stable IDs. No automatic migration of account identity occurs.

This is the supported self-hosting scaffold. No Tailscale account is joined by these
scripts; public Funnel deployment and fresh authenticated X login need live testing.

Reference: [Tailscale Funnel CLI](https://tailscale.com/docs/reference/tailscale-cli/funnel).
