# Proof Inbox

An extension-free CLI for proving access to an X account and sending signed messages
to compatible inboxes. A shared TLSNotary service notarizes login once; recipients
verify the reusable presentation locally. Tailscale Funnel exposes a self-hosted
inbox. No blockchain, recipient participation in login, or automatic agent callbacks.

```text
Human login: CLI ↔ notary, CLI ↔ X → portable proof saved locally
Message:     CLI → recipient Funnel → offline proof + signature checks
                                     → stable-ID allowlist → Jev review buckets
                                     → quarantine → explicit owner release → agent feed
```

## Install

Prerequisites: Node 20+, npm, Rust/Cargo, native build tools. X login requires a
human desktop; servers can be headless. Linux Chromium may require Playwright's
system dependencies (`npx playwright install-deps chromium`).

```sh
npm ci
npm run setup                     # native prover/notary/verifier + Chromium
# Headless inbox or notary host: npm run setup -- --server-only
```

TLSN is pinned to `v0.1.0-alpha.15` with `native/Cargo.lock`. The native program uses
the Rust TLSNotary library directly; it does not install a browser extension or
clone/build the TLSNotary extension server. This is a source install, not a packaged
single executable yet. The native build output retains its historical location
under `vendor/tlsn-extension/servers/target/release/inbox-prover`.

## Configure the shared notary

No hosted notary has been deployed or silently selected. An operator supplies two
files: a **public trust file** containing `notaryKeys`, and a **private client file**
containing `url`, `publicKey`, and the pilot access `token`. Obtain these from the
operator through a trusted channel; do not accept a sender-supplied trust key.

For a local development notary:

```sh
npm run notary:init                 # creates .local/notary/{private,client,trust}.json
npm run notary:start                # separate terminal; loopback port 7048
export INBOX_NOTARY_CONFIG="$PWD/.local/notary/client.json"
export INBOX_TRUST_FILE="$PWD/.local/notary/trust.json"
```

For the hosted service, see [notary operations](deploy/NOTARY.md). Receivers need
only the public trust file and the native verifier. They do not run a notary or
contact it during message verification. Alternative notaries work only when their
public keys are explicitly accepted by a recipient. Restart services after changing
trust; removing a notary key rejects its proofs, including previously cached ones.

## Sender: login once, send to compatible inboxes

```sh
export INBOX_NOTARY_CONFIG=/absolute/path/to/client.json
npm run cli -- login .local/agent.json
npm run cli -- send .local/agent.json https://BOB.TAILNET.ts.net/inboxes/bob message.txt
npm run cli -- send .local/agent.json https://CAROL.TAILNET.ts.net/inboxes/carol message.txt
```

The person signs into X in an isolated Chromium window, returns to the approval tab,
and approves the displayed agent-key fingerprint. The CLI captures session headers
in memory and submits them only to its local native subprocess over stdin. The prover
connects to X directly using MPC-TLS with the notary. The notary signs transcript
commitments and an extension binding the Ed25519 agent key. The CLI verifies the
result locally before saving it. Nothing is posted to the X account.

Only the portable presentation and identity metadata are saved with the agent key.
Raw transcript secrets and request credentials are not intentionally written to disk.
The presentation reveals the full X Viewer response to recipients, including profile
and account metadata; it is not an account-ID-only disclosure yet. Request cookies,
CSRF and authorization headers stay hidden. The client checks for sensitive session
cookies in the response before exporting it. No screenshots, HARs, traces or existing
browser profiles are captured. OS swap, crash dumps and processes sharing the same
OS identity remain outside this application boundary.

Proofs expire **24 hours after the attested connection time**. Run `renew KEY_FILE`
(or `login` again) for another human login using the same agent key. Renewal does not
instantly revoke older portable proofs everywhere: they expire naturally, and each
recipient can revoke a proof or block a key locally. X logout, password changes,
suspension and handle changes do not proactively invalidate already-issued proofs.

`INBOX_URL=https://host` plus a handle is also supported. `envelope` produces the
signed JSON for curl. URLs are supplied explicitly; a directory and handle-to-URL
discovery are not implemented.

```sh
export INBOX_URL=https://BOB.TAILNET.ts.net
npm run cli -- envelope .local/agent.json bob message.txt > .local/envelope.json
curl "$INBOX_URL/inboxes/bob/messages" -H 'Content-Type: application/json' \
  --data-binary @.local/envelope.json
```

## Receiver: create an inbox

For local development, start `npm start` with `INBOX_TRUST_FILE` configured. For
public hosting, follow the [Funnel guide](deploy/README.md). The server refuses
identity operations without an accepted notary; missing trust never enables mocks.

After local X login, run:

```sh
export INBOX_URL=http://localhost:4310
npm run cli -- create .local/agent.json
```

For a public host, creation additionally requires `INBOX_ENROLLMENT_TOKEN`, supplied
by its operator. `create` opens a local approval window. The owner token is shown
only there; the reader token is saved under the inbox URL in the agent file. Save
the owner token in a human-controlled secret store before closing. If setup is
interrupted after creation, token recovery requires local operator intervention.
Never give an agent the owner token or access to the server data directory.

## Allowlist, inspect, release

Default deny. Policies pin **stable X account IDs**, not mutable handles:

```sh
# Human-controlled terminal; local development API shown here.
curl -X PUT http://localhost:4310/inboxes/bob/policy \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"allowIds":["123456789"],"tolerance":0.5}'
curl http://localhost:4310/inboxes/bob/quarantine \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN"
curl -X POST http://localhost:4310/inboxes/bob/messages/MESSAGE_ID/release \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN" -H 'Content-Type: application/json' -d '{}'
```

`reject` discards instead of releasing. For handle convenience, the sender can run
`introduce KEY_FILE` against this host first, then the owner can set
`{"allow":["alice"]}`. Introduction verifies identity but delivers no message.
Ambiguous or stale handle mappings are rejected. The policy stores the resolved ID.
Handles in URLs do not automatically rename when an X handle changes.

Revoke a proof with owner-authenticated `POST /inboxes/bob/authentications/revoke`
and `{"proofId":"SHA256_OF_PRESENTATION"}`. To block an agent key across renewals,
use `PUT /inboxes/bob/blocked-keys` with `{"fingerprints":["SHA256_OF_PUBLIC_KEY_PEM"]}`.
Removing an ID from the allowlist blocks all that account's keys. These are local
recipient decisions; there is no centralized live revocation lookup.

```sh
export INBOX_READER_TOKEN='READER_TOKEN'
npm run cli -- metadata bob       # authenticated sender metadata, never content/buckets
npm run cli -- feed bob           # only explicitly owner-released messages
```

The feed cannot invoke an agent, webhook, model, shell or tool. Even released text
is labeled untrusted external data. The owner must inspect content in a separate
human-controlled context; an agent with server filesystem or owner-browser access
can bypass API isolation. Use separate OS/container identities to enforce separation.

## Jev filtering

Set `TYPESAFE_API_KEY` on the receiver to enable the TypeSafe adapter. This explicitly
sends **admitted message text** to TypeSafe's hosted API; it sends no X proof, session
credentials or owner token. Without a key, messages remain quarantined and unscored.
`TYPESAFE_MODEL` defaults to `jev-latest`.

Three independent Noul judgments assess instruction override, secret disclosure
requests and requests for external actions. Raw probabilities are retained for
owner inspection and routed to `low`, `medium`, or `high` review buckets. Invalid
responses, timeouts and provider failures yield `unscored`. The owner may set
`tolerance` from 0 (tighter flagging) to 1 (looser flagging); it recomputes buckets
without rerunning inference. These thresholds are provisional, not calibrated safety
guarantees. A probability near 0.5 is uncertainty, not medium severity.

**Every bucket remains quarantined.** No filter result, low-risk score, timeout or
setting can release content. Only the owner release endpoint can. `createInbox`
accepts a replaceable filter function for custom integrations. The built-in adapter
uses the current [TypeSafe HTTP API](https://docs.typesafe.ai/api) and the
[guardrails workflow](https://docs.typesafe.ai/cookbooks/llm_guardrails).

## Trust and limits

- Recipients trust the configured notary to attest honestly. A dishonest or compromised
  notary can forge inbox identities; local signature verification cannot detect that.
  MPC-TLS protects hidden X credentials from the notary, subject to correct implementation.
  Users separately trust the CLI, which handles session cookies locally.
- Verification checks the accepted notary key, X certificate/server identity, authenticated
  exact Viewer request, full response, HTTP success, stable account ID, handle, date,
  signed agent-key extension, and a fresh message signature binding proof, audience,
  recipient, body and nonce. An identity proves account access at that time, not legal
  ownership, current access or benign intent.
- X can change its pinned internal Viewer query or block browser login. Fresh human X
  login was blocked again during the portable-flow acceptance test with “We’ve temporarily
  limited your login.” It occurs before notarization; its exact cause is not established.
  There is no extension or OAuth fallback. OAuth stays in the separate private local fork.
- TLSNotary remains alpha software. This prototype is not independently audited.
  Notary signing-key compromise affects all inboxes accepting that key.
- One API process per data directory. State is an atomic JSON snapshot, plaintext on
  disk, with private file modes. Back up only with the service stopped. No clustering,
  retention jobs or automated owner recovery. `.local/` is gitignored.
- Limits: 384 KiB request, 256 KiB binary presentation, 16,000 message characters,
  two native proof verifications at once, eight pending message requests, 600 requests/min,
  ten admitted messages per sender/min, 100 quarantined messages/inbox, 10,000 messages
  total, and 1,000 inboxes. These are bounds, not DDoS protection.

## Tests

```sh
npm test                 # API, CLI, parsing, filtering, quarantine and Funnel policy
npm run test:native      # actual MPC + signed presentation with a local TLS fixture
npm run test:x           # opt-in network test against X, without login credentials
# After a successful human login, with INBOX_TRUST_FILE set:
npm run test:identity -- .local/agent.json  # same real proof at two temporary local inboxes
```

Application tests inject cryptographic-boundary fixtures only in test processes.
The native test performs real MPC/notarization and checks offline verification,
agent-key tampering, unknown trust keys, trailing bytes and hidden-cookie disclosure.
Its test CA is compiled only into tests and is rejected by the production verifier.
The real X test verifies a portable presentation cryptographically and ensures an
unauthenticated response cannot become an identity. Neither test substitutes for
fresh human-authenticated X login, a deployed hosted notary, live Jev evaluation,
or a public Funnel test.

Current validation: all 14 application tests, the real local MPC/attestation fixture,
and the unauthenticated real-X portable-proof test passed. Fresh human login remains
blocked by X; no hosted notary or public Funnel has been deployed. Jev was tested
with API fixtures, not a live TypeSafe API key. No retries are scheduled.

For X's temporary-lock guidance, see [X Help](https://help.x.com/en/managing-your-account/locked-out-after-too-many-login-attempts).
Wait before retrying; the generic message does not establish whether automation,
browser state, account state or network reputation caused this particular rejection.
