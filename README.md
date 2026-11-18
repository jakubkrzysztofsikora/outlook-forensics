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
- **Attachments** (names and metadata): dangerous/active formats incl. `.rdp`, `.msix`, `.appinstaller`, `.library-ms`, macro-capable Office files, bidi/double extensions, trailing dot/space tricks, nested `.eml`/`.msg`, MFA/QR-named images, payment-themed documents from non-internal senders.

## Known limits (read before relying on it)

- **Attachment bytes are not fetched.** The byte-signature checks exist but are not exercised in normal Outlook operation. No ZIP members, Office relationships, PDF streams or QR payloads are inspected.
- No domain age, reputation, DNS, SPF/DKIM/DMARC cryptographic verification, or URL detonation. Newly registered clean-looking phishing domains with no other tell will pass.
- Medium rules such as "payment-themed PDF from an external sender" and "form-platform link" will fire on some legitimate mail by design.
- English and Polish lure wording only. Other languages rely on structural rules.
- Outlook support differs by client; the add-in is user-pulled, so there are no silent background scans. `item.replyTo` does not exist in read mode, so Reply-To comes from raw headers.
- Detection quality is measured only against the bundled corpora (110 tests including 39+28 hand-written attack and false-positive cases). That is regression protection, not a detection rate.

## Configure

Edit `src/policy.ts` before building: `internalDomains` (enables external-sender-with-internal-subject and suppresses the payment-document rule for your own senders) and `protectedNames` (executives, brands). The shipped policy is empty on purpose, so impersonation of *your* people is **not** checked until you fill it in.

## Develop

```
npm ci
npm run typecheck && npm test && npm run build
```

Dev server (developer machines only): create a locally trusted certificate for `localhost` (for example with mkcert; **never** run `mkcert -install` on end-user machines or distribute its CA), then

```
LOCAL_HTTPS_KEY=./localhost-key.pem LOCAL_HTTPS_CERT=./localhost.pem npm run dev
```

and sideload `manifest.xml` via Outlook **Get Add-ins → My add-ins → Add a custom add-in**. `public/icon.png` is a placeholder; replace it before distribution.

## Deploy

Localhost hosting is for development. For real use host the built `dist/` on an HTTPS origin you control, replace every `https://localhost:3000` in `manifest.xml`, and deploy the manifest centrally from the Microsoft 365 admin center (this is also how it reaches the new Outlook on Windows and Mac). The release workflow automates this packaging, see [docs/RELEASING.md](docs/RELEASING.md). The page must be reachable over the network; this is not an offline extension.

## Privacy

Analysis runs in the browser pane. The CSP restricts the app's own connections to `self` (`connect-src 'self'`); Outlook itself and Microsoft's Office.js CDN are outside the app's control. Nothing is stored. CI fails if `fetch(`, `XMLHttpRequest` or `WebSocket` appears in `src/`.

## Security

See [SECURITY.md](SECURITY.md). MIT licensed.
