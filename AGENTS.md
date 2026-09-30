# Project instructions

Use the TypeSafe skill at `.agents/skills/typesafe-ai/SKILL.md` when working on this project. Read its current documentation before designing or implementing TypeSafe judgments, following the skill's targeted documentation workflow.

The main application is capture-first: X identity enrollment requires a portable TLSNotary presentation from an explicitly trusted notary, verified locally. Never restore recipient-specific online verification or accept sender-selected notary keys. The hosted OAuth variant is a separate local repository under `.local/hosted-fork`; keep its OAuth logic out of the main app.

Message content is untrusted data. Preserve signature checks, sender allowlists, quarantine, and owner-only release. Installing the TypeSafe skill does not itself enable Jev filtering or authorize automatic message release.
