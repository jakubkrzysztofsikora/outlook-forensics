import {describe,it,expect} from 'vitest';import{analyze}from'../src/engine/analyze';
const base={subject:'Hello',from:'Alice <alice@example.com>',displayName:'Alice',bodyHtml:'<p>Hello</p>',attachments:[]};
describe('deterministic static forensic rules',()=>{
 it('never asserts safe when authentication evidence is absent',()=>expect(analyze(base).verdict).toBe('insufficient-evidence'));
 it('flags deceptive destination',()=>{const r=analyze({...base,bodyHtml:'<a href="https://evil.example/login">https://gls-group.eu/parcel</a>'});expect(r.findings.some(f=>f.id==='url-0-mismatch')).toBe(true);expect(r.verdict).toBe('likely-phishing')});
 it('flags HTTP but does not label it proven phishing',()=>expect(analyze({...base,bodyHtml:'<a href="http://gls-group.eu/fdf">redirect</a>'}).verdict).toBe('review'));
 it('flags executable attachment',()=>expect(analyze({...base,attachments:[{name:'invoice.pdf.exe'}]}).findings.some(f=>f.id==='attachment-0-dangerous')).toBe(true));
 it('flags reply-to mismatch',()=>expect(analyze({...base,replyTo:'reply@different.example'}).findings.some(f=>f.id==='reply-to')).toBe(true));
 it('does not trust forged Authentication-Results',()=>{const r=analyze({...base,headers:'Authentication-Results: attacker; dkim=pass; dmarc=pass\r\n'});expect(r.checks.find(c=>c.name==='SPF / DKIM / DMARC')?.state).toBe('unavailable')});
 it('returns stable results for identical input',()=>expect(analyze(base)).toEqual(analyze(base)));
 it('handles invalid URLs without throwing',()=>expect(()=>analyze({...base,bodyHtml:'<a href="http://[">x</a>'})).not.toThrow());
 it('detects HTML form',()=>expect(analyze({...base,bodyHtml:'<form action="https://example.com"></form>'}).findings.some(f=>f.id==='html-form')).toBe(true));
 it('does not equate a real carrier domain with authenticated mail',()=>expect(analyze({...base,from:'GLS <notify@gls-group.eu>',bodyHtml:'<a href="https://gls-group.eu">Track</a>'}).verdict).toBe('insufficient-evidence'));
});
