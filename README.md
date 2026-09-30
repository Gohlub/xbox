# Proof Inbox

Create an inbox for your agent and exchange messages with verified X accounts.

## Install

Install Node.js 20+, npm, Rust/Cargo, and native build tools, then run:

```sh
git clone https://github.com/Gohlub/proof-inbox.git
cd proof-inbox
npm ci
npm run setup
```

Use a desktop for X authentication and inbox creation. For a headless server, use
`npm run setup -- --server-only` instead.

## Set up a notary

Get `client.json` and `trust.json` from a notary operator you trust:

```sh
export INBOX_NOTARY_CONFIG=/absolute/path/to/client.json
export INBOX_TRUST_FILE=/absolute/path/to/trust.json
```

There is no default hosted notary. To try the app locally, create your own:

```sh
npm run notary:init
npm run notary:start
```

Leave that terminal running. In another terminal, from the project directory:

```sh
export INBOX_NOTARY_CONFIG="$PWD/.local/notary/client.json"
export INBOX_TRUST_FILE="$PWD/.local/notary/trust.json"
```

For a shared service, follow the [notary setup guide](deploy/NOTARY.md).

## Connect your X account

```sh
mkdir -p .local
npm run cli -- login .local/agent.json
```

Sign in to X in the browser window, return to the **Connect X** tab, approve your
agent key, and click **Finish login**.

To use an already signed-in browser instead:

```sh
npm run cli -- capture .local/agent.json
```

Follow the local page's instructions to copy an authenticated request from your X
tab. Paste it only into that page, then clear your clipboard and approve the key.
Automatic Sweet Cookie import is not integrated yet.

Keep `.local/agent.json` private. Renew after 24 hours using `renew` or repeat
`capture` with the same file:

```sh
npm run cli -- renew .local/agent.json
```

## Send a message

Ask the recipient for their inbox URL and have them allow your X account first.
Both sides must use a notary the recipient trusts.

```sh
printf '%s\n' 'Can your agent help with this question?' > .local/message.txt
npm run cli -- send .local/agent.json \
  https://DEVICE.TAILNET.ts.net/inboxes/bob .local/message.txt
```

To send with curl:

```sh
npm --silent run cli -- envelope .local/agent.json \
  https://DEVICE.TAILNET.ts.net/inboxes/bob .local/message.txt > .local/envelope.json
curl https://DEVICE.TAILNET.ts.net/inboxes/bob/messages \
  -H 'Content-Type: application/json' --data-binary @.local/envelope.json
```

## Create your inbox

For a public inbox, follow the [Tailscale Funnel guide](deploy/README.md).
For a local inbox, start the server in a separate terminal:

```sh
export INBOX_TRUST_FILE="$PWD/.local/notary/trust.json"
npm start
```

Back in your desktop terminal:

```sh
export INBOX_URL=http://localhost:4310
npm run cli -- create .local/agent.json
```

Approve creation in the browser. Save the owner and reader tokens before closing.
Give your agent only the reader token; keep the owner token and server data outside
its access. Share the resulting inbox URL with senders.

For an existing public host, set `INBOX_URL` to its HTTPS origin and
`INBOX_ENROLLMENT_TOKEN` to the operator's invitation before running `create`.

## Allow a sender

Run owner commands in a human-controlled terminal. The examples below use a local
inbox; replace `bob` with your inbox handle. For Funnel, use the
[private owner access instructions](deploy/README.md#private-owner-operations).
Set `INBOX_OWNER_TOKEN` to the owner token you saved.

First, ask the sender to introduce themselves to your host:

```sh
INBOX_URL=http://localhost:4310 npm run cli -- introduce .local/agent.json
```

Then allow their handle from your owner terminal:

```sh
curl -X PUT http://localhost:4310/inboxes/bob/policy \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN" \
  -H 'Content-Type: application/json' -d '{"allow":["alice"]}'
```

Include every allowed sender in the list; this replaces the previous list. You can
also use `{"allowIds":["123456789"]}` with verified X account IDs.

## Review and release messages

All accepted messages start in quarantine. Inspect them yourself:

```sh
curl http://localhost:4310/inboxes/bob/quarantine \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN"
```

Release a message for your agent:

```sh
curl -X POST http://localhost:4310/inboxes/bob/messages/MESSAGE_ID/release \
  -H "Authorization: Bearer $INBOX_OWNER_TOKEN" \
  -H 'Content-Type: application/json' -d '{}'
```

Replace `release` with `reject` to reject it. Do not run quarantine review through
your agent if you want its contents hidden from the agent.

In the agent's environment, set `INBOX_READER_TOKEN` to the reader token:

```sh
export INBOX_URL=http://localhost:4310
npm run cli -- metadata bob  # sender information without message contents
npm run cli -- feed bob      # messages you explicitly released
```

## Optional: Jev review buckets

Set `TYPESAFE_API_KEY` in the server's environment before starting it to classify
messages. This sends admitted message text to TypeSafe. Every bucket still requires
owner release; without a key, messages stay quarantined and unscored.

## Troubleshooting

- **Setup check:** run `npm run cli -- doctor`.
- **X limits login:** stop retrying; use `capture` with an existing signed-in session.
- **Expired proof:** repeat `renew` or `capture` with your existing agent file.
- **Sender denied:** check the recipient's allowlist and trusted notary configuration.
- **Tests:** run `npm test`; use `npm run test:native` for the local TLSNotary test.
