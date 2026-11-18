import type { Severity } from './types';
import { BRANDS, USER_CONTENT_HOSTS, URL_SHORTENERS, isOfficialHost } from './brands';
import { clean, hostMatches, idnRisk, leet, regDomain, sameSite } from './util';
export type Emit = (id: string, severity: Severity, title: string, evidence: string) => void;
export interface UrlCtx { senderHost: string; base?: string; internalOnly?: boolean }

const SAFE_SCHEMES = new Set(['http', 'https', 'mailto', 'tel', 'sms', 'cid', 'callto']);
const DANGEROUS_SCHEMES = new Set(['javascript', 'data', 'vbscript', 'file', 'ms-msdt', 'search-ms', 'search', 'ms-excel', 'ms-word', 'ms-powerpoint', 'ms-access', 'ms-officecmd', 'ms-appinstaller', 'ms-infopath', 'ms-its', 'mhtml', 'shell', 'ms-cxh', 'ms-cxh-full', 'ms-vsto', 'ms-visio', 'ms-project', 'ms-publisher', 'ms-spd', 'ms-windows-store', 'ms-settings', 'ie', 'microsoft-edge']);
const SENSITIVE_SCOPE = /(?:offline_access|\.readwrite|mail\.|files\.|full_access|directory\.|user\.read\.all|https:\/\/mail\.google\.com|gmail|drive)/i;
const HOST_TOKENS = new Set(['login', 'signin', 'sign', 'secure', 'verify', 'verification', 'account', 'auth', 'sso', 'webmail', 'm365', 'o365', 'office365', 'owa', 'helpdesk', 'support', 'update', 'password', 'mfa']);

/** Remove the wrappers added by Microsoft Safe Links and Proofpoint URL Defense v3 so the real destination is judged. */
export function unwrap(u: URL): { url: URL; wrapped: boolean } {
  try {
    const h = u.hostname.toLowerCase();
    if (h.endsWith('safelinks.protection.outlook.com')) { const t = u.searchParams.get('url'); if (t) return { url: new URL(t), wrapped: true }; }
    if (h === 'urldefense.com' || h === 'urldefense.proofpoint.com') {
      const m = /\/v3\/__(.+?)__;/.exec(u.pathname + u.search + u.hash);
      if (m) return { url: new URL(m[1].replace(/\*/g, '')), wrapped: true };
    }
  } catch { /* fall through: judge the wrapper itself */ }
  return { url: u, wrapped: false };
}

function labelHost(label: string): string {
  const t = label.trim();
  const withScheme = /https?:\/\/([^\s/?#:]+)/i.exec(t);
  if (withScheme) return withScheme[1].toLowerCase();
  const bare = /^(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?$/i.exec(t);
  return bare ? bare[1].toLowerCase() : '';
}

/** Judge one URL. `raw` is the href exactly as the sender wrote it. */
export function checkUrl(raw: string, label: string, id: string, ctx: UrlCtx, emit: Emit): void {
  const compact = raw.replace(/[\u0000-\u0020\u007f-\u009f\u200b-\u200f\u2028-\u202f\u2060\ufeff]/g, '');
  if (!compact) return;
  if (/^\\\\/.test(compact) || /^\/\/\/?[^/]*\\/.test(compact)) { emit(id + '-unc', 'high', 'UNC / network-share link (NTLM credential leak risk)', clean(raw)); return; }
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(compact)?.[1].toLowerCase();
  if (scheme && !SAFE_SCHEMES.has(scheme)) {
    if (DANGEROUS_SCHEMES.has(scheme)) emit(id + '-scheme', 'high', 'Dangerous URL scheme', clean(compact));
    else emit(id + '-scheme', 'medium', 'Unusual URL scheme', clean(compact));
    return;
  }
  if (scheme && !/^https?$/.test(scheme)) return;
  let value = compact;
  if (value.startsWith('//')) { emit(id + '-relative', 'medium', 'Protocol-relative external URL', clean(value)); value = 'https:' + value; }
  let u: URL;
  try { u = new URL(value, scheme || value.startsWith('https:') ? undefined : ctx.base); }
  catch { return; }
  if (!/^https?:$/.test(u.protocol)) return;
  const { url, wrapped } = unwrap(u);
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return;
  const unsubscribe = /unsubscribe|opt[-_ ]?out|preferences?|wypisz/i.test(label + ' ' + url.pathname);

  if (url.protocol === 'http:') emit(id + '-http', unsubscribe ? 'low' : 'medium', 'Unencrypted HTTP URL', clean(url.href));
  if (url.username || url.password) emit(id + '-userinfo', 'high', 'Misleading URL userinfo', clean(url.href));
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) emit(id + '-ip', 'medium', 'IP-address destination', clean(host));
  const idn = idnRisk(host);
  if (idn === 'mixed-script') emit(id + '-idn', 'high', 'Mixed-script hostname (homograph)', clean(host));
  else if (idn) emit(id + '-idn', 'medium', 'Look-alike or unparseable internationalized hostname', clean(host));
  if (['zip', 'mov', 'top', 'click', 'xyz', 'icu', 'cfd', 'sbs', 'rest', 'country'].includes(host.split('.').pop() || '')) emit(id + '-tld', 'low', 'Unusual TLD', clean(host));
  if (URL_SHORTENERS.has(regDomain(host))) emit(id + '-shortener', 'medium', 'URL shortener hides the destination', clean(host));
  if (USER_CONTENT_HOSTS.some(h => hostMatches(host, h))) emit(id + '-usercontent', 'medium', 'Link to a form / user-content hosting platform (content is attacker-controllable)', clean(host));

  // OAuth consent and device-code abuse
  if ((host === 'login.microsoftonline.com' && /\/oauth2\/(?:v2\.0\/)?authorize/i.test(url.pathname)) || (host === 'accounts.google.com' && /\/o\/oauth2\//i.test(url.pathname))) {
    const scope = url.searchParams.get('scope') ?? '';
    emit(id + '-oauth', SENSITIVE_SCOPE.test(scope) ? 'high' : 'medium', 'OAuth consent link (illicit consent grant risk)', clean(`${host} scope=${scope}`));
  }
  if (/\/common\/oauth2\/deviceauth|\/devicelogin/i.test(url.pathname) && /microsoft/i.test(host)) emit(id + '-devicecode', 'medium', 'Device-code login page', clean(url.href));

  // Brand look-alike hosts and credential-themed host names (only for hosts that are NOT the real brand)
  if (!isOfficialHost(host)) {
    const tokens = host.split('.').slice(0, -1).flatMap(l => l.split('-'));
    const brand = BRANDS.find(b => tokens.some(t => leet(t) === b.name));
    if (brand) emit(id + '-brand', 'high', `Host imitates ${brand.name} but is not a ${brand.name} domain`, clean(host));
    else if (!sameSite(host, ctx.senderHost) && new Set(tokens.filter(t => HOST_TOKENS.has(t))).size >= 2) emit(id + '-hostwords', 'medium', 'Credential-themed host name on an unrelated domain', clean(host));
  }

  // Displayed destination vs real destination
  const shown = labelHost(label);
  if (shown && !sameSite(shown, host)) emit(id + '-mismatch', 'high', 'Displayed link destination mismatch', `${clean(shown)} -> ${clean(host)}`);
  void wrapped;
}
