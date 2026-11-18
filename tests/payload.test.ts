import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/analyze';
import { zipEntries } from '../src/engine/payload';
import type { Message } from '../src/engine/types';

const enc = (s: string) => new TextEncoder().encode(s);
/** Minimal ZIP writer (stored, no compression) so the central-directory reader is tested on real bytes. */
function zip(entries: Array<{ name: string; encrypted?: boolean }>): Uint8Array {
  const parts: number[] = [], central: number[] = [];
  const u16 = (n: number) => [n & 255, (n >> 8) & 255], u32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
  for (const e of entries) {
    const name = [...enc(e.name)], flags = e.encrypted ? 1 : 0, off = parts.length;
    parts.push(...u32(0x04034b50), ...u16(20), ...u16(flags), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(0), ...u32(0), ...u16(name.length), ...u16(0), ...name);
    central.push(...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(flags), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(0), ...u32(0), ...u16(name.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(off), ...name);
  }
  const cdOff = parts.length;
  const end = [...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(entries.length), ...u16(entries.length), ...u32(central.length), ...u32(cdOff), ...u16(0)];
  return new Uint8Array([...parts, ...central, ...end]);
}
const base: Message = { subject: 'Hello', from: 'alice@partner.example', displayName: 'Alice', bodyHtml: '<p>hi</p>', bodyText: '', attachments: [] };
const ids = (name: string, bytes: Uint8Array, extra: Partial<Message> = {}) => analyze({ ...base, ...extra, attachments: [{ name, bytes, byteStatus: 'read' }] }).findings.map(f => f.id);

describe('attachment payload inspection', () => {
  it('reads ZIP member names from the central directory', () => {
    expect(zipEntries(zip([{ name: 'a.txt' }, { name: 'b/c.exe' }]))?.map(e => e.name)).toEqual(['a.txt', 'b/c.exe']);
    expect(zipEntries(enc('not a zip'))).toBeUndefined();
  });
  it('flags an executable inside a harmless-looking archive', () => expect(ids('docs.zip', zip([{ name: 'invoice.pdf.exe' }]))).toContain('attachment-0-zip-dangerous'));
  it('flags encrypted archives', () => expect(ids('docs.zip', zip([{ name: 'a.txt', encrypted: true }]))).toContain('attachment-0-zip-encrypted'));
  it('flags path traversal members', () => expect(ids('docs.zip', zip([{ name: '../../evil.txt' }]))).toContain('attachment-0-zip-traversal'));
  it('flags a macro project inside an OOXML file even when the extension is innocent', () => expect(ids('report.xlsx', zip([{ name: 'xl/vbaProject.bin' }]))).toContain('attachment-0-office-macro'));
  it('does not flag a plain Office document', () => expect(ids('report.docx', zip([{ name: 'word/document.xml' }, { name: '[Content_Types].xml' }])).filter(i => i.startsWith('attachment-0-') && !i.includes('payment'))).toEqual([]));
  it('judges URI annotations inside a PDF like any other link', () => {
    expect(ids('doc.pdf', enc('%PDF-1.7\n1 0 obj << /Type /Annot /A << /S /URI /URI (http://185.10.10.10/login) >> >> endobj'))).toEqual(expect.arrayContaining(['attachment-0-pdf-url-0-ip']));
  });
  it('flags HTML smuggling and local credential forms in an HTML attachment', () => {
    expect(ids('invoice.html', enc('<script>const b=new Blob([atob("AAAA")]);</script>'))).toContain('attachment-0-html-smuggling');
    expect(ids('invoice.html', enc('<form><input type=password></form>'))).toContain('attachment-0-html-form');
  });
  it('checks links inside an attached .eml', () => expect(ids('fwd.eml', enc('From: a@b.example\r\nSubject: x\r\n\r\nhttp://evil.example/x'))).toContain('attachment-0-eml-url-0-http'));
  it('judges a cloud-attachment URL', () => {
    const r = analyze({ ...base, attachments: [{ name: 'shared.docx', url: 'https://bit.ly/abc', byteStatus: 'read' }] });
    expect(r.findings.some(f => f.id === 'attachment-0-cloud-url-shortener')).toBe(true);
  });
  it('still reports payload coverage as partial, never complete', () => {
    const r = analyze({ ...base, attachments: [{ name: 'a.txt', bytes: enc('hello'), byteStatus: 'read' }] });
    expect(r.checks.find(c => c.name === 'Attachment payloads')?.state).toBe('partial');
  });
  it('trustedDomains silences the payment/archive nuisance rules but never the executable rules', () => {
    const m: Message = { ...base, from: 'ap@vendor.example', attachments: [{ name: 'Invoice-1.pdf' }, { name: 'a.zip' }, { name: 'x.exe' }] };
    const f = analyze(m, { trustedDomains: ['vendor.example'] }).findings.map(x => x.id);
    expect(f).not.toContain('attachment-0-payment-doc');
    expect(f).not.toContain('attachment-1-archive');
    expect(f).toContain('attachment-2-dangerous');
  });
  it('newly registered linked domains are scored only when ages are supplied, deterministically', () => {
    const m: Message = { ...base, bodyHtml: '<a href="https://fresh-site.example/x">go</a>' };
    const now = Date.parse('2026-11-18T00:00:00Z');
    expect(analyze(m).findings.some(f => f.id.startsWith('domain-age'))).toBe(false);
    const r = analyze(m, {}, { domainAges: { 'fresh-site.example': '2026-11-15T00:00:00Z' }, now });
    expect(r.findings.find(f => f.id === 'domain-age-fresh-site.example')?.severity).toBe('high');
    expect(r.hosts).toContain('fresh-site.example');
    expect(analyze(m, {}, { domainAges: { 'fresh-site.example': '2020-01-01T00:00:00Z' }, now }).findings.some(f => f.id.startsWith('domain-age'))).toBe(false);
  });
});
