/**
 * OPT-IN domain-age lookup. Disabled unless VITE_RDAP_ORIGIN is set at build time (for example https://rdap.org).
 * When enabled, ONLY registrable domain names found in links are sent to that RDAP service. No message
 * content, subject, sender or recipient leaves the pane. This is the single file allowed to use network APIs.
 */
const ORIGIN = ((import.meta.env.VITE_RDAP_ORIGIN as string | undefined) ?? '').replace(/\/+$/, '');
export const rdapEnabled = /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(ORIGIN);
const cache = new Map<string, string | null>();

async function one(domain: string): Promise<string | null> {
  if (cache.has(domain)) return cache.get(domain)!;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 4000);
  try {
    const res = await fetch(`${ORIGIN}/domain/${encodeURIComponent(domain)}`, { signal: ctl.signal, credentials: 'omit', referrerPolicy: 'no-referrer', headers: { accept: 'application/rdap+json, application/json' } });
    if (!res.ok) { cache.set(domain, null); return null; }
    const json = (await res.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
    const reg = json.events?.find(e => e.eventAction === 'registration')?.eventDate ?? null;
    cache.set(domain, reg && Number.isFinite(Date.parse(reg)) ? reg : null);
    return cache.get(domain)!;
  } catch { return null; } finally { clearTimeout(timer); }
}

/** Returns registration dates for the domains that could be resolved. Failures are silently omitted. */
export async function lookupDomainAges(domains: string[]): Promise<Record<string, string>> {
  if (!rdapEnabled) return {};
  const out: Record<string, string> = {};
  const list = domains.filter(d => /^[a-z0-9.-]{3,253}$/.test(d)).slice(0, 8);
  const results = await Promise.all(list.map(one));
  list.forEach((d, i) => { const r = results[i]; if (r) out[d] = r; });
  return out;
}
