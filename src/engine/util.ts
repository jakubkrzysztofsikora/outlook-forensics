/** Shared, dependency-free helpers: address/domain parsing, confusable folding, punycode. */
export const clean = (s: string, n = 240) => s.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

export function addressOf(s: string): string {
  const all = [...s.matchAll(/<([^<>]+)>/g)];
  const inner = all.length ? all[all.length - 1][1] : s;
  return inner.trim().toLowerCase();
}
export const domainOf = (s: string): string => (addressOf(s).split('@')[1] || '').replace(/[>\s]+$/g, '');

const MULTI_SUFFIX = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl', 'com.au', 'co.jp', 'com.br', 'com.tr', 'co.nz', 'co.za', 'com.mx', 'co.in']);
export function regDomain(host: string): string {
  const l = host.toLowerCase().replace(/\.$/, '').split('.');
  if (l.length <= 2) return l.join('.');
  const two = l.slice(-2).join('.');
  return MULTI_SUFFIX.has(two) ? l.slice(-3).join('.') : two;
}
export const hostMatches = (host: string, base: string) => host === base || host.endsWith('.' + base);
/** True when both hosts belong to the same registrable domain (sub-domains count as the same site). */
export const sameSite = (a: string, b: string) => !!a && !!b && (a === b || regDomain(a) === regDomain(b));

const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'в': 'b', 'ӏ': 'l',
  // Greek
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ε': 'e', 'η': 'n', 'β': 'b',
  // Latin look-alikes
  'ɡ': 'g', 'ı': 'i', 'ł': 'l', 'ǀ': 'l', 'ⅼ': 'l',
};
/** NFKD, strip marks / zero-width / format characters, map common confusables, lowercase. */
export function fold(s: string): string {
  const stripped = s.normalize('NFKD').replace(/[\p{M}\p{Cf}]/gu, '').toLowerCase();
  let out = '';
  for (const ch of stripped) out += CONFUSABLES[ch] ?? ch;
  return out;
}
/** fold() plus digit/symbol substitutions typical for look-alike domains (micr0soft, paypa1). */
export function leet(s: string): string {
  return fold(s).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[01345$@7]/g, c => ({ '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '$': 's', '@': 'a', '7': 't' } as Record<string, string>)[c]);
}

function decodePuny(input: string): string {
  try {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    let n = 128, i = 0, bias = 72;
    const out: number[] = [];
    const b = Math.max(input.lastIndexOf('-'), 0);
    for (let j = 0; j < b; j++) out.push(input.charCodeAt(j));
    const adapt = (delta: number, num: number, first: boolean) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / num);
      let k = 0;
      while (delta > (((base - tMin) * tMax) >> 1)) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
    };
    for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) return input;
        const c = input.charCodeAt(idx++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
        if (digit >= base) return input;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  } catch { return input; }
}
export const unicodeHost = (host: string) => host.split('.').map(l => (l.startsWith('xn--') ? decodePuny(l.slice(4)) : l)).join('.');

/** Latin letters with diacritics (e.g. Polish) are fine; mixed scripts or whole-label look-alikes are not. */
export function idnRisk(host: string): 'mixed-script' | 'lookalike-script' | 'unparseable-punycode' | null {
  for (const label of unicodeHost(host).split('.')) {
    if (/^[\x00-\x7f]*$/.test(label)) continue;
    const latin = /\p{Script=Latin}/u.test(label), cyr = /\p{Script=Cyrillic}/u.test(label), grk = /\p{Script=Greek}/u.test(label);
    if ([latin, cyr, grk].filter(Boolean).length > 1) return 'mixed-script';
    if ((cyr || grk) && /^[a-z0-9-]+$/.test(fold(label))) return 'lookalike-script';
  }
  return host.split('.').some(l => l.startsWith('xn--') && unicodeHost(l) === l) ? 'unparseable-punycode' : null;
}
