import type { Message, Finding, Result, Severity, Policy, Attachment } from './types';
import { parseInternetHeaders, headerAddresses } from './headers';
import { inspectHtml } from './html';
import { checkUrl, type Emit } from './url';
import { BRANDS, FREEMAIL } from './brands';
import { clean, domainOf, fold, hostMatches, leet, regDomain, sameSite } from './util';

export const RULE_VERSION = '3.0.0';
const MAX_HTML = 1024 * 1024, MAX_TEXT = 1024 * 1024, MAX_HEADERS = 256 * 1024;
const MAX_LINKS = 2000, MAX_ATTACHMENTS = 100, MAX_BYTES = 2 * 1024 * 1024, MAX_FINDINGS_SHOWN = 200, MAX_FINDINGS_INTERNAL = 5000;
const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const dangerous = new Set(['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'wsc', 'sct', 'hta', 'ps1', 'psm1', 'bat', 'cmd', 'com', 'msi', 'msp', 'mst', 'lnk', 'iso', 'img', 'vhd', 'vhdx', 'jar', 'jnlp', 'one', 'onepkg', 'xll', 'iqy', 'slk', 'url', 'application', 'appref-ms', 'appinstaller', 'appx', 'appxbundle', 'msix', 'msixbundle', 'chm', 'reg', 'inf', 'cpl', 'scf', 'pif', 'gadget', 'rdp', 'library-ms', 'searchconnector-ms', 'search-ms', 'dll', 'sys', 'msc', 'diagcab', 'settingcontent-ms']);
const macroExt = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'xlsb', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm']);
const htmlLike = new Set(['html', 'htm', 'xhtml', 'shtml', 'svg', 'mht', 'mhtml']);
const archives = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'arj', 'z', 'lzh']);
const nestedMail = new Set(['eml', 'msg']);

const CRED_LURE = /(?:password\s+(?:will\s+)?(?:expire|expir)|keep\s+my\s+password|verify\s+your\s+(?:account|identity|mailbox|email)|account\s+(?:will\s+be\s+|has\s+been\s+)?(?:suspended|locked|deactivated|limited)|unusual\s+(?:sign|log)[- ]?in|re-?enable\s+(?:mfa|2fa)|reset\s+your\s+(?:mfa|password)|confirm\s+your\s+(?:identity|password)|mailbox\s+(?:is\s+)?(?:full|almost\s+full)|hasło\s+wygasa|zweryfikuj\s+(?:swoje\s+)?konto)/i;
const BEC_PHRASES: RegExp[] = [/are\s+you\s+(?:at\s+your\s+desk|available|free\s+now)/i, /(?:need|want)\s+(?:you\s+)?(?:to\s+)?(?:process|handle|do)\s+(?:a|an|the)?\s*(?:wire|payment|transfer|favou?r)/i, /\b(?:wire|gift\s*cards?|itunes\s+cards?|bitcoin)\b/i, /keep\s+(?:this\s+)?(?:strictly\s+)?confidential/i, /(?:urgent|quick)\s+(?:favou?r|task|request)/i, /don'?t\s+(?:call|tell|discuss)|reply\s+only\s+(?:by\s+)?email/i, /czy\s+jeste[sś]\s+przy\s+biurku|poufn[ey]|pilny\s+przelew/i];
const CLICKFIX = /(?:win(?:dows)?\s*\+\s*r\b|press\s+win\b|run\s+dialog|ctrl\s*\+\s*v\s+(?:then|and)\s+enter)|powershell(?:\.exe)?\s+(?:-\w+\s+)*(?:-w(?:indowstyle)?\s+hidden|-e(?:nc(?:odedcommand)?)?\b|-c(?:ommand)?\b)|\|\s*iex\b|\biwr\s+\S+|\bmshta\b|certutil\s+-urlcache|\bbitsadmin\b/i;
const DEVICE_CODE = /(?:microsoft\.com\/devicelogin|login\.microsoftonline\.com\/common\/oauth2\/deviceauth|microsoft\.com\/link\b|login\.microsoft\.com\/device)/i;
const ENTER_CODE = /(?:enter\s+(?:the\s+)?code|device\s+code|code\s*[:\-]?\s*[A-Z0-9]{4}-[A-Z0-9]{4})/i;
const PAYMENT_CHANGE = /(?:(?:new|updated?|changed?|different)\s+(?:bank\s+details|iban|bank\s+account|account\s+(?:number|details)|payment\s+details)|bank\s+(?:details|account)\s+(?:have\s+|has\s+)?changed|nowy\s+numer\s+(?:konta|rachunku)|zmian[aey]\s+(?:numeru\s+)?(?:konta|rachunku))/i;
const IBAN = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b/;
const CALLBACK_PHONE = /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/;
const CALLBACK_ACTION = /\b(?:call|dial|phone|contact\s+(?:our\s+)?(?:support|billing))\b/i;
const CALLBACK_BILLING = /(?:charged|invoice|subscription|renewed|dispute|refund|auto-?renew|your\s+order|billing)/i;
const INTERNAL_CLAIM = /\b(?:internal|confidential|payroll|salary|bonus|it\s+support|helpdesk|hr)\b|poufn|wynagrodze|premi[ae]|lista\s+p[lł]ac|dział\s+it|kadry|vertraulich|gehalt/i;
const EXEC_TITLE = /\b(?:ceo|cfo|coo|cto|president|chairman|managing\s+director|prezes|dyrektor)\b/i;
const QR_HINT = /(?:^|[^a-z])qr(?:[^a-z]|$|code)|scan/i;
const MFA_IMG_NAME = /(?:mfa|2fa|qr|scan|authenticator|verify|verification)/i;
const PAYMENT_DOC = /(?:invoice|faktur|payment|remittance|statement|purchase[\s_-]?order|receipt|wire|przelew)/i;

const normName = (name: string) => name.replace(/[\u0000-\u0020\u00a0\u200b-\u200f.]+$/g, '').replace(/^[\u0000-\u0020]+/, '');
const extOf = (name: string) => (normName(name).toLowerCase().split('.').pop() || '');

function bytesCheck(a: Attachment, i: number, emit: Emit): boolean {
  const b = a.bytes; if (!b) return false;
  const name = normName(a.name).toLowerCase();
  const prefix = new TextDecoder('latin1').decode(b.slice(0, Math.min(b.length, MAX_BYTES)));
  if (/^%PDF-/.test(prefix)) {
    if (/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/Launch\b|\/EmbeddedFile\b/i.test(prefix)) emit(`attachment-${i}-pdf-action`, 'high', 'PDF contains active-content indicators', clean(a.name));
  }
  if (/^MZ/.test(prefix) && !['exe', 'dll', 'scr'].includes(extOf(name))) emit(`attachment-${i}-magic`, 'high', 'Executable signature inconsistent with filename', clean(a.name));
  if (/^PK\x03\x04/.test(prefix) && /externalLink|attachedTemplate|TargetMode="External"|vbaProject\.bin/i.test(prefix)) emit(`attachment-${i}-office-external`, 'high', 'Office archive contains external relationship or macro indicator', clean(a.name));
  return true;
}

export function analyze(m: Message, policy: Policy = {}): Result {
  const all: Finding[] = [], checks: Result['checks'] = [];
  let truncated = false;
  const emit: Emit = (id, severity, title, evidence) => {
    if (all.length >= MAX_FINDINGS_INTERNAL) { truncated = true; return; }
    all.push({ id, severity, title, evidence: clean(evidence) });
  };

  const parsed = m.headers !== undefined ? parseInternetHeaders(m.headers.slice(0, MAX_HEADERS)) : [];
  const senderHost = domainOf(m.from);
  const internal = (policy.internalDomains ?? []).map(d => d.toLowerCase());
  const senderInternal = !!senderHost && internal.some(d => hostMatches(senderHost, d));

  // Body text sources
  let html: ReturnType<typeof inspectHtml> | undefined;
  let htmlError = false;
  if (m.bodyHtml !== undefined) {
    const src = m.bodyHtml.slice(0, MAX_HTML);
    if (src.length < m.bodyHtml.length) { truncated = true; emit('html-limit', 'medium', 'HTML analysis limit reached', String(m.bodyHtml.length)); }
    try { html = inspectHtml(src, MAX_LINKS); } catch { htmlError = true; emit('html-parse-error', 'medium', 'HTML could not be parsed', 'parser error'); }
  }
  let text = '';
  if (m.bodyText !== undefined) {
    text = m.bodyText.slice(0, MAX_TEXT);
    if (text.length < m.bodyText.length) { truncated = true; emit('text-limit', 'medium', 'Text analysis limit reached', String(m.bodyText.length)); }
  }
  const visible = [m.subject, html?.text ?? '', text].join('\n').slice(0, 400000);

  // ---- Sender identity -------------------------------------------------------------------
  if (!senderHost) emit('missing-from', 'medium', 'Missing or invalid sender address', m.from);
  const display = m.displayName || '';
  const embedded = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/.exec(display);
  if (embedded && senderHost && !sameSite(embedded[1].toLowerCase(), senderHost)) emit('display-name-address', 'high', 'Display name shows a different email address than the real sender', `${display} / ${senderHost}`);

  const fromHeaders = [...(m.headerFrom ?? []), ...headerAddresses(parsed, 'from')];
  const fromHeaderCount = Math.max(parsed.filter(h => h.name === 'from').length, m.headerFrom?.length ?? 0);
  if (fromHeaderCount > 1) emit('multiple-from', 'high', 'Multiple From headers (parser-differential spoofing)', fromHeaders.join(' | '));

  const replyTos = [...new Set([m.replyTo, ...(m.headerReplyTo ?? []), ...headerAddresses(parsed, 'reply-to')].filter((x): x is string => !!x))];
  for (const r of replyTos) { const rd = domainOf(r); if (senderHost && rd && !sameSite(senderHost, rd)) emit('reply-to', 'medium', 'Reply-To domain differs', `${senderHost} -> ${rd}`); }

  const senderHdr = m.headerSender || headerAddresses(parsed, 'sender')[0] || m.sender;
  if (senderHdr && senderHost) { const sd = domainOf(senderHdr); if (sd && !sameSite(sd, senderHost)) emit('sender-header', 'medium', 'Sender header domain differs from From', `${senderHost} -> ${sd}`); }
  const rp = m.returnPath || headerAddresses(parsed, 'return-path')[0];
  if (rp && senderHost) { const rd = domainOf(rp); if (rd && !sameSite(rd, senderHost)) emit('return-path', 'low', 'Return-Path domain differs', `${senderHost} -> ${rd}`); }

  const foldedName = fold(display);
  (policy.protectedNames ?? []).forEach((p, i) => {
    if (foldedName.includes(fold(p.name)) && senderHost && !p.domains.some(d => hostMatches(senderHost, d.toLowerCase()))) emit('brand-' + i, 'high', 'Protected identity display-name impersonation', `${p.name} / ${senderHost}`);
  });
  for (const b of BRANDS) {
    if (new RegExp(`(?:^|[^a-z])${b.name}(?:[^a-z]|$)`).test(foldedName) && senderHost && !b.domains.some(d => hostMatches(senderHost, d))) emit('brand-builtin-' + b.name, 'high', `Display name claims ${b.name} but sender domain is not a ${b.name} domain`, `${display} / ${senderHost}`);
  }
  if (senderHost) {
    const rawFold = fold(senderHost), leeted = leet(senderHost);
    const words = new Set(foldedName.split(/[^a-z0-9]+/).filter(w => w.length >= 5 && /^[a-z]+$/.test(w)));
    for (const w of leet(display).split(/[^a-z0-9]+/).filter(w => w.length >= 5)) words.add(w);
    for (const w of words) if (leeted.includes(w) && !rawFold.includes(w)) { emit('lookalike-sender', 'high', 'Sender domain is a character-substitution look-alike of the display name', `${w} ~ ${senderHost}`); break; }
  }
  if (internal.length && senderHost && !senderInternal && INTERNAL_CLAIM.test(m.subject)) emit('external-internal-claim', 'medium', 'External sender with internal-themed subject', m.subject);
  if (senderHost && EXEC_TITLE.test(display) && FREEMAIL.has(regDomain(senderHost).split('.')[0])) emit('exec-freemail', 'medium', 'Executive title in display name sent from a free-mail domain', `${display} / ${senderHost}`);
  checks.push({ name: 'Sender consistency', state: 'evaluated', detail: 'Address, Reply-To, Sender, Return-Path, display-name look-alikes, built-in brands and configured names; domain ownership is not verified' });

  // ---- Headers -----------------------------------------------------------------------------
  if (m.headers !== undefined) {
    if (m.headers.length > MAX_HEADERS) { truncated = true; emit('headers-limit', 'medium', 'Headers exceed analysis limit', String(m.headers.length)); }
    const auth = parsed.filter(h => h.name === 'authentication-results').map(h => h.value);
    if (auth.length) emit('untrusted-auth', 'info', 'Authentication-Results are untrusted without receiver boundary', auth[0]);
    // A *failure* is safe to act on even from an untrusted header: an attacker gains nothing by forging one. A "pass" is never trusted.
    const joined = auth.join(' ; ');
    if (/\b(?:dmarc|compauth)=fail\b/i.test(joined)) emit('auth-fail', 'high', 'Authentication-Results report a DMARC / composite-authentication failure', joined.slice(0, 200));
    else if (/\b(?:spf|dkim)=(?:fail|softfail|permerror)\b/i.test(joined)) emit('auth-fail', 'medium', 'Authentication-Results report an SPF or DKIM failure', joined.slice(0, 200));
    const ffr = parsed.filter(h => h.name === 'x-forefront-antispam-report').map(h => h.value).join(' ');
    const cat = /CAT:([A-Z]+)/i.exec(ffr)?.[1]?.toUpperCase();
    if (cat && /^(?:PHSH|HPHSH|HPHISH|MALW)$/.test(cat)) emit('defender-verdict', 'high', `Microsoft filtering already classified this message (${cat})`, clean(ffr));
    else if ((cat && /^(?:SPOOF|DIMP|UIMP|IMP)$/.test(cat)) || /SFTY:9\./i.test(ffr)) emit('defender-verdict', 'medium', 'Microsoft filtering flagged spoofing or impersonation', clean(ffr));
    checks.push({ name: 'SPF / DKIM / DMARC', state: 'unavailable', detail: 'Passes are never trusted (header is sender-forgeable). Failures reported in Authentication-Results and Defender verdict headers are surfaced as indicators' });
    const received = parsed.filter(h => h.name === 'received');
    checks.push({ name: 'Transport headers', state: 'partial', detail: `${received.length} Received field(s) counted, authenticity and routing unverified` });
  } else {
    checks.push({ name: 'SPF / DKIM / DMARC', state: 'unavailable', detail: 'Internet headers unavailable' });
    checks.push({ name: 'Transport headers', state: 'unavailable', detail: 'Internet headers unavailable' });
  }

  // ---- HTML body ---------------------------------------------------------------------------
  let linkIndex = 0, linkCount = 0;
  const ctx = { senderHost, base: html?.base };
  if (html) {
    if (html.forms || html.passwordInputs) emit('html-form', 'high', 'HTML form or credential input', `${html.forms} form(s), ${html.passwordInputs} password field(s)`);
    for (const a of html.formActions) checkUrl(a, '', 'form-action-' + linkIndex++, ctx, emit);
    if (html.active.length) emit('active-html', 'medium', 'Active or complex HTML markup', `${[...new Set(html.active)].join(', ')}; static detection only`);
    if (html.metaRefresh.length) emit('meta-refresh', 'high', 'Meta refresh redirect', clean(html.metaRefresh[0]));
    if (html.base) { emit('base-tag', 'medium', 'Base tag rewrites relative links', clean(html.base)); checkUrl(html.base, '', 'base', ctx, emit); }
    const remote = html.imgs.filter(i => /^(?:https?:)?\/\//i.test(i.src.trim()));
    if (remote.length) emit('remote-image', 'info', 'Remote image / tracking pixel possibility', `${remote.length} remote image(s); no image fetched by scanner`);
    const fileImg = html.imgs.filter(i => /^(?:file:|\\\\)/i.test(i.src.trim()));
    if (fileImg.length) emit('file-image', 'high', 'Image loads from a file/UNC path (NTLM credential leak risk)', clean(fileImg[0].src));
    const qr = html.imgs.filter(i => QR_HINT.test(i.alt + ' ' + i.src.replace(/^data:[^,]*,.*/i, 'data:')) || (/^data:image/i.test(i.src.trim()) && QR_HINT.test(visible)));
    if (qr.length) emit('qr', 'medium', 'Possible QR-code lure (image not decoded)', `${qr.length} candidate image(s)`);
    html.links.forEach(l => { linkCount++; checkUrl(l.href, l.label, l.kind === 'area' ? `url-${linkIndex++}-imagemap` : 'url-' + linkIndex++, ctx, emit); });
    for (const l of html.links) if (l.kind === 'area') emit(`url-area-${linkIndex++}`, 'medium', 'Image-map click area (invisible clickable region)', clean(l.href));
    if (html.truncatedLinks) { truncated = true; emit('link-limit', 'medium', 'HTML link count exceeded limit', String(MAX_LINKS)); }
    checks.push({ name: 'HTML links and forms', state: html.truncatedLinks ? 'partial' : 'evaluated', detail: `${linkCount} links inspected (spec-compliant parser, Safe Links/URL Defense unwrapped); no remote resources fetched` });
  } else checks.push({ name: 'HTML links and forms', state: htmlError ? 'partial' : 'unavailable', detail: htmlError ? 'HTML parse failed' : 'HTML body unavailable' });

  // ---- Plain-text URLs and bare domains --------------------------------------------------
  if (m.bodyText !== undefined) {
    const stripTail = (s: string) => s.replace(/[)\]}.,;:!?'">]+$/g, '');
    const urls = (text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || []).map(stripTail);
    const rest = text.replace(/(?:https?:\/\/|www\.)[^\s<>"']+/gi, ' ');
    const bare = (rest.match(/(?<![@\w./-])(?:[a-z0-9-]+\.)+[a-z]{2,}\/[^\s<>"']*/gi) || []).map(stripTail);
    let n = 0;
    for (const u of urls.slice(0, MAX_LINKS)) checkUrl(u.startsWith('www.') ? 'https://' + u : u, '', 'text-url-' + n++, ctx, emit);
    for (const u of bare.slice(0, MAX_LINKS)) checkUrl('https://' + u, '', 'text-url-' + n++, ctx, (id, sev, title, ev) => { if (!id.endsWith('-http')) emit(id, sev, title, ev); });
    if (urls.length + bare.length > MAX_LINKS) { truncated = true; emit('text-url-limit', 'medium', 'Plain-text URL limit reached', String(urls.length + bare.length)); }
    checks.push({ name: 'Plain-text URLs', state: urls.length + bare.length > MAX_LINKS ? 'partial' : 'evaluated', detail: `${Math.min(urls.length + bare.length, MAX_LINKS)} URLs / bare domains inspected` });
  } else checks.push({ name: 'Plain-text URLs', state: 'unavailable', detail: 'Plain-text body unavailable' });

  // ---- Language-level lures (HTML + text + subject) --------------------------------------
  if (CRED_LURE.test(visible)) {
    const external = (html?.links ?? []).some(l => { try { const h = new URL(l.href.replace(/[\s\u0000-\u001f]/g, ''), ctx.base).hostname; return !!h && !sameSite(h, senderHost); } catch { return false; } }) || /(?:https?:\/\/|www\.)\S+/i.test(text);
    if (external) emit('credential-lure', 'medium', 'Credential / account-lockout language combined with an external link', clean((CRED_LURE.exec(visible) || [''])[0]));
  }
  const becHits = BEC_PHRASES.filter(r => r.test(visible)).length;
  if (becHits >= 2) emit('bec-language', 'medium', 'Business-email-compromise phrasing (urgency, secrecy, payment or gift-card request)', `${becHits} indicator phrase(s)`);
  if (CLICKFIX.test(visible)) emit('clickfix', 'high', 'Paste-and-run command instructions (ClickFix)', clean((CLICKFIX.exec(visible) || [''])[0]));
  if (DEVICE_CODE.test(visible) && ENTER_CODE.test(visible)) emit('device-code', 'high', 'Device-code sign-in lure (OAuth device-code phishing)', clean((DEVICE_CODE.exec(visible) || [''])[0]));
  if (PAYMENT_CHANGE.test(visible)) emit('payment-redirect', IBAN.test(visible) ? 'high' : 'medium', 'Request to change bank / payment details', IBAN.test(visible) ? 'bank-change wording with an IBAN' : 'bank-change wording');
  if (CALLBACK_PHONE.test(visible) && CALLBACK_ACTION.test(visible) && CALLBACK_BILLING.test(visible)) emit('callback-phishing', 'medium', 'Billing notice that asks the reader to phone a number (callback phishing)', 'phone number + billing wording');

  // ---- Attachments ------------------------------------------------------------------------
  if (m.attachments !== undefined) {
    let allBytes = true;
    for (const [i, a] of m.attachments.slice(0, MAX_ATTACHMENTS).entries()) {
      const nm = normName(a.name), n = nm.toLowerCase(), e = extOf(a.name);
      if (dangerous.has(e)) emit(`attachment-${i}-dangerous`, 'high', 'Dangerous or active attachment format', a.name);
      if (macroExt.has(e)) emit(`attachment-${i}-macro`, 'high', 'Macro-capable Office file', a.name);
      if (htmlLike.has(e)) emit(`attachment-${i}-dangerous-html`, 'low', 'HTML/SVG attachment (HTML-smuggling carrier; opens locally)', a.name);
      if (archives.has(e)) emit(`attachment-${i}-archive`, 'low', 'Archive contents not inspected', a.name);
      if (nestedMail.has(e)) emit(`attachment-${i}-nested-message`, 'medium', 'Attached message; its content and links are not inspected', a.name);
      if (/[\u202a-\u202e\u2066-\u2069]/.test(a.name)) emit(`attachment-${i}-bidi`, 'high', 'Bidirectional Unicode filename spoofing', a.name);
      if (n.split('.').length > 2 && dangerous.has(e)) emit(`attachment-${i}-double`, 'medium', 'Multiple-extension active file', a.name);
      if (/^image\//i.test(a.contentType || '') && MFA_IMG_NAME.test(n)) emit(`attachment-${i}-qr-image`, 'medium', 'Image attachment named like an MFA / QR / verification lure', a.name);
      if (PAYMENT_DOC.test(n) && ['pdf', 'doc', 'docx', 'xls', 'xlsx'].includes(e) && !senderInternal) emit(`attachment-${i}-payment-doc`, 'medium', 'Payment-themed document from a non-internal sender; contents are not inspected', a.name);
      if (a.size !== undefined && a.size > MAX_BYTES) emit(`attachment-${i}-size`, 'low', 'Attachment exceeds optional static byte limit', a.name);
      if (!bytesCheck(a, i, emit)) allBytes = false;
    }
    if (m.attachments.length > MAX_ATTACHMENTS) { truncated = true; emit('attachment-limit', 'medium', 'Attachment count exceeded limit', String(m.attachments.length)); }
    checks.push({ name: 'Attachment metadata', state: m.attachments.length > MAX_ATTACHMENTS ? 'partial' : 'evaluated', detail: `${Math.min(m.attachments.length, MAX_ATTACHMENTS)} filenames inspected` });
    checks.push({ name: 'Attachment payloads', state: m.attachments.length === 0 ? 'evaluated' : allBytes ? 'partial' : 'unavailable', detail: m.attachments.length === 0 ? 'No attachments' : allBytes ? 'Only bounded signatures; no full parser or sandbox' : 'Payload bytes not fetched; content not inspected' });
  } else {
    checks.push({ name: 'Attachment metadata', state: 'unavailable', detail: 'Attachment list unavailable' });
    checks.push({ name: 'Attachment payloads', state: 'unavailable', detail: 'Attachment payloads unavailable' });
  }
  if (truncated) checks.push({ name: 'Resource limits', state: 'partial', detail: 'One or more inputs were truncated or capped' });

  // ---- Verdict ---------------------------------------------------------------------------
  const seen = new Set<string>();
  const unique = all.filter(f => { const k = `${f.severity}|${f.title}|${f.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; });
  unique.sort((a, b) => rank[b.severity] - rank[a.severity] || a.id.localeCompare(b.id));
  if (unique.length > MAX_FINDINGS_SHOWN) truncated = true;
  const shown = unique.slice(0, MAX_FINDINGS_SHOWN);
  const count = (s: Severity) => unique.filter(f => f.severity === s).length;
  const unavailable = checks.filter(c => c.state !== 'evaluated').map(c => c.name);
  const verdict: Result['verdict'] =
    count('high') + count('critical') > 0 ? 'likely-phishing'
    : count('medium') > 0 || count('low') >= 2 ? 'review'
    : unavailable.length ? 'insufficient-evidence' : 'no-known-indicators';
  return { verdict, findings: shown, checks, ruleVersion: RULE_VERSION, coverage: { complete: unavailable.length === 0, unavailable }, truncated };
}
