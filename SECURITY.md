# Security

This add-in is an advisory static-analysis tool, not a mail gateway, sandbox or guarantee of safety. A clean result must not be used to decide that links or attachments are safe to open.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → Report a vulnerability) rather than a public issue. Do not post real corporate emails, personal data or credentials in public issues; use a redacted or synthetic sample.

Detection bypasses (a phishing email that scores clean) are welcome as normal issues if the sample is synthetic. Please include the minimal HTML/headers that reproduce it so it can become a regression test.

## Design notes

- No runtime network calls, telemetry or message storage by default; CI blocks `fetch(`, `XMLHttpRequest`, `WebSocket` and `sendBeacon` in `src/` except the opt-in `src/outlook/rdap.ts`, which sends only link domain names and only when built with `VITE_RDAP_ORIGIN`.
- Attachment content is read in memory for static inspection and is never saved, opened, executed or transmitted.
- The task pane must be served over HTTPS and needs network access to load.
- Message HTML is parsed, never rendered, and no resource it references is fetched.
- `Authentication-Results` passes are not trusted; only failures are surfaced.
- The Vite/esbuild dev-server advisories apply to developer machines only; the dev server binds to 127.0.0.1 and build tooling is a dev dependency. Do not expose the dev server.
