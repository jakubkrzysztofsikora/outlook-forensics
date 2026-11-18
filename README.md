# Outlook Forensics

A local-only, deterministic **analyst helper** for Outlook. It runs in the task pane, reads the selected message through Office.js, and lists static phishing/scam indicators with evidence. No AI, no telemetry, no reputation lookups, nothing leaves the pane.

> **What this is not.** It is not a mail gateway, not a sandbox, and not a guarantee. It only runs when a person opens it on a message, so it cannot protect anyone who never clicks. For organisation-wide protection use a server-side control (Microsoft Defender for Office 365 with Safe Links / Safe Attachments, Conditional Access, attack simulation) and treat this add-in as a second opinion for reporters and the security team. A clean result never means "safe".

## Verdicts

| Verdict | Meaning |
|---|---|
| `likely-phishing` | At least one **high** indicator (e.g. displayed-vs-real link mismatch, look-alike sender, credential form, dangerous attachment type, ClickFix / device-code lure). An indicator, not proof. |
| `review` | At least one **medium** indicator or two **low** ones. |
| `insufficient-evidence` | Nothing found, but some inputs were unavailable (headers, attachment bytes). This is the normal "clean" outcome today. |
| `no-known-indicators` | Nothing found **and** every check had full evidence. Practically unreachable while attachment bytes are not read. |

## What it checks

- **Links** (HTML parsed with parse5, same tree a browser builds): displayed vs real destination, Safe Links / URL Defense unwrapping, userinfo, IP and punycode hosts (mixed-script homographs flagged, plain Polish/Latin IDNs not), shorteners, form/user-content hosting, brand look-alike hosts, dangerous and unusual schemes (`javascript:`, `data:`, `ms-msdt:`, `search-ms:`, UNC/`file:`), `<base>`, meta refresh, image-map areas, OAuth consent and device-code links. Plain-text URLs and bare domains too.
- **Sender identity**: From / Reply-To / Sender / Return-Path consistency, multiple `From` headers, display name containing another address, built-in brand list plus your protected names (zero-width and Cyrillic/Greek confusables folded), leet look-alike domains (`micr0soft`), executive title from a free-mail domain.
- **Headers**: `Authentication-Results` and Defender verdict headers. **Passes are never trusted** (the header is sender-forgeable). A reported *failure* is surfaced, because an attacker gains nothing by forging one.
- **Body language**: credential-lockout lures with an external link, BEC phrasing, bank-detail change with IBAN, callback phishing, ClickFix paste-and-run commands, device-code sign-in lures, QR lures (image not decoded).
- **Attachments, by name**: dangerous/active formats incl. `.rdp`, `.msix`, `.appinstaller`, `.library-ms`, macro-capable Office files, bidi/double extensions, trailing dot/space tricks, nested `.eml`/`.msg`, MFA/QR-named images, payment-themed documents from senders that are not internal or trusted.
- **Attachments, by content** (read in memory via `getAttachmentContentAsync`, up to 10 files / 2 MB each / 10 MB total; nothing is saved or opened): executable signature under a false name; ZIP member names (executables, path traversal, encrypted archives, VBA projects, embedded OLE/ActiveX); PDF `/URI` links and active-content markers; HTML/SVG attachments (login forms, links, HTML-smuggling `atob`/`Blob`); links inside attached `.eml`; cloud-attachment URLs.

## Known limits (read before relying on it)

- **Attachment content is inspected shallowly.** Nothing is decompressed, so macros and external relationships inside compressed OOXML parts, links inside compressed PDF object streams, nested archive members, scanned images and QR payloads are not seen. Files over 2 MB, beyond the 10th attachment, or that Outlook refuses to hand over are judged by name only. No sandbox.
- **Domain age is off by default** (see below). Without it, a freshly registered clean-looking phishing domain with no other tell will pass. There is no reputation feed and no SPF/DKIM/DMARC cryptographic verification.
- Medium rules such as "payment-themed PDF from a non-internal sender" and "form-platform link" fire on some legitimate mail by design. Put regular vendors in `trustedDomains` to silence the payment, archive, HTML-attachment and nested-message nuisance rules for them. This never silences executable, macro, form or link-mismatch findings.
- English and Polish lure wording only. Other languages rely on structural rules.
- Outlook support differs by client; the add-in is user-pulled, so there are no silent background scans. `item.replyTo` does not exist in read mode, so Reply-To comes from raw headers.
- Detection quality is measured only against the bundled corpora (123 tests, including 67 hand-written attack and false-positive cases). That is regression protection, not a detection rate.

## Configure your organisation

The shipped policy is empty on purpose, so impersonation of *your* people is **not** checked until you configure it. Copy `src/policy.example.ts` to `src/policy.local.ts` (gitignored, never committed) and fill in:

- `internalDomains`: your mail domains.
- `trustedDomains`: vendors you routinely get invoices, archives or HTML reports from.
- `protectedNames`: executives, finance, HR, brands. Matching ignores case, accents, zero-width characters and Cyrillic/Greek look-alikes. `domains` lists the only legitimate sender domains for that name.

For CI releases store the same file contents in the repository secret `POLICY_TS`; the release workflow writes it to `src/policy.local.ts` before building and warns loudly if it is missing.

## Optional: newly-registered-domain check

Off by default to keep the local-only guarantee. To enable it, build with `VITE_RDAP_ORIGIN=https://rdap.org` (or your own RDAP service; in CI set the repository variable `RDAP_ORIGIN`). The CSP is widened to that one origin at build time. Only the registrable **domain names** found in links are sent (max 8 per message, no cookies, no referrer); never message content, sender, subject or recipients. Links to domains registered under 7 days are **high**, under 30 days **medium**. The pane header and verdict card show `DOMAIN LOOKUP ON` when it is enabled. The lookup itself is the only code allowed to use a network API (`src/outlook/rdap.ts`); CI enforces that.

## Develop

```
npm ci
npm run typecheck && npm test && npm run build
```

Dev server (developer machines only): create a locally trusted certificate for `localhost` (for example with mkcert; **never** run `mkcert -install` on end-user machines or distribute its CA), then

```
LOCAL_HTTPS_KEY=./localhost-key.pem LOCAL_HTTPS_CERT=./localhost.pem npm run dev
```

and sideload `manifest.xml` via Outlook **Get Add-ins → My add-ins → Add a custom add-in**. Icons are in `public/icon-*.png` (16, 32, 64, 80, 128); swap in your own branding if you like.

## Deploy

Localhost hosting is for development. For real use host the built `dist/` on an HTTPS origin you control, replace every `https://localhost:3000` in `manifest.xml`, and deploy the manifest centrally from the Microsoft 365 admin center (this is also how it reaches the new Outlook on Windows and Mac). The release workflow automates this packaging, see [docs/RELEASING.md](docs/RELEASING.md). The page must be reachable over the network; this is not an offline extension.

## Privacy

Analysis runs in the browser pane. By default the CSP restricts the app's own connections to `self` (`connect-src 'self'`); Outlook itself and Microsoft's Office.js CDN are outside the app's control. Nothing is stored. CI fails if `fetch(`, `XMLHttpRequest`, `WebSocket` or `sendBeacon` appears in `src/` outside the opt-in `src/outlook/rdap.ts`. Attachment content is read in memory only, never saved, opened or transmitted.

## Security

See [SECURITY.md](SECURITY.md). MIT licensed.
