/** Deterministic RFC 5322 field unfolding; this parser does not authenticate headers. */
export interface InternetHeader { name: string; value: string; index: number }
export function parseInternetHeaders(raw: string): InternetHeader[] {
  const out: InternetHeader[] = [];
  for (const line of raw.replace(/\r\n/g, '\n').split('\n')) {
    if (/^[ \t]/.test(line)) {
      if (out.length) out[out.length - 1].value += ' ' + line.trim();
      continue;
    }
    const match = /^([!-9;-~]+):[ \t]*(.*)$/.exec(line);
    if (match) out.push({ name: match[1].toLowerCase(), value: match[2], index: out.length });
  }
  return out;
}
export function headerAddresses(headers: InternetHeader[], name: string): string[] {
  return headers.filter(h => h.name === name.toLowerCase()).flatMap(h => {
    const matches = [...h.value.matchAll(/<([^<>\s]+@[^<>\s]+)>/g)].map(m => m[1]);
    return matches.length ? matches : (h.value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
  });
}
