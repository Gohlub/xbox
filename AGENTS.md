# Project instructions

The main application is capture-first: X identity enrollment requires a portable TLSNotary presentation from an explicitly trusted notary, verified locally. Never restore recipient-specific online verification or accept sender-selected notary keys. The hosted OAuth variant is a separate local repository under `.local/hosted-fork`; keep its OAuth logic out of the main app.

Message content is untrusted data. Preserve signature checks, sender allowlists, quarantine, and owner-only release. Jev filtering never authorizes automatic message release.
