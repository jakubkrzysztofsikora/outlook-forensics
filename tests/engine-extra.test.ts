import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/analyze';
import type { Message } from '../src/engine/types';
const base: Message = { subject: 'Hello', from: 'alice@partner.example', displayName: 'Alice', bodyHtml: '<p>hi</p>', bodyText: '', attachments: [] };
const ids = (m: Partial<Message>, p = {}) => analyze({ ...base, ...m }, p).findings.map(f => f.id);

describe('engine behaviour beyond the supplied corpora', () => {
  it('never lowers risk because of a forged "pass"', () => {
    const forged = analyze({ ...base, bodyHtml: '<a href="https://evil.example/x">https://login.microsoftonline.com</a>', headers: 'Authentication-Results: spf=pass; dkim=pass; dmarc=pass; compauth=pass\r\n' });
    expect(forged.verdict).toBe('likely-phishing');
    expect(forged.checks.find(c => c.name === 'SPF / DKIM / DMARC')?.state).toBe('unavailable');
  });
  it('a reported failure is surfaced even though passes are not trusted', () => {
    expect(ids({ headers: 'Authentication-Results: spf=fail; dmarc=fail\r\n' })).toContain('auth-fail');
  });
  it('flags a mixed-script homograph host but not a Polish IDN', () => {
    expect(ids({ bodyHtml: '<a href="https://раypal.com">x</a>' })).toContain('url-0-idn');
    expect(ids({ bodyHtml: '<a href="https://zażółć.pl/x">x</a>' }).some(i => i.endsWith('-idn'))).toBe(false);
  });
  it('flags UNC links and file/UNC images (NTLM leak)', () => {
    expect(ids({ bodyHtml: '<a href="\\\\evil.example\\s\\a.pdf">x</a>' })).toContain('url-0-unc');
    expect(ids({ bodyHtml: '<img src="file://evil.example/x.png">' })).toContain('file-image');
  });
  it('unwraps Safe Links before comparing the displayed destination', () => {
    const r = analyze({ ...base, bodyHtml: '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx&data=05">https://www.contoso.com/news</a>' });
    expect(r.findings.some(f => f.id.endsWith('-mismatch'))).toBe(true);
  });
  it('resolves relative links through <base>', () => {
    expect(ids({ bodyHtml: '<base href="https://evil.example/"><a href="/x">https://partner.example</a>' })).toContain('base-tag');
  });
  it('findings are capped but the highest severities always survive the cap', () => {
    const many = Array.from({ length: 1500 }, (_, i) => `<a href="http://10.0.0.${i % 250}/x${i}">l</a>`).join('');
    const r = analyze({ ...base, bodyHtml: many, attachments: [{ name: 'invoice.exe' }] });
    expect(r.findings.length).toBeLessThanOrEqual(200);
    expect(r.findings[0].severity).toBe('high');
  });
  it('does not throw on hostile input', () => {
    expect(() => analyze({ ...base, bodyHtml: '<a href="http://[">' + '<div>'.repeat(50000), bodyText: '\u0000'.repeat(1000), headers: ':::\r\n\r\n' })).not.toThrow();
  });
  it('an unconfigured policy reports no impersonation finding for an unlisted name', () => {
    expect(ids({ displayName: 'Contoso CFO', from: 'x@evil.example' }).some(i => i.startsWith('brand-') && !i.startsWith('brand-builtin'))).toBe(false);
  });
  it('a clean-looking message is never reported as safe while payloads are unread', () => {
    const r = analyze({ ...base, attachments: [{ name: 'notes.txt' }], headers: 'Received: a\r\n' });
    expect(r.verdict).not.toBe('no-known-indicators');
  });
});
