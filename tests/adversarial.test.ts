import {describe,it,expect} from 'vitest';
import {analyze} from '../src/engine/analyze';
import type {Message} from '../src/engine/types';
const base:Message={subject:'Invoice',from:'cfo@corp.example',displayName:'CFO',bodyHtml:'<p>hi</p>',bodyText:'',attachments:[]};
const cases:[string,Partial<Message>,string][]=[
 ['Unquoted HTML URL',{bodyHtml:'<a href=https://evil.example/login>https://safe.example</a>'},'url-0-mismatch'],
 ['Plain-text HTTP',{bodyHtml:undefined,bodyText:'Visit http://evil.example'},'text-url-0-http'],
 ['Remote pixel',{bodyHtml:'<img src="https://evil.example/t">'},'remote-image'],
 ['SVG',{bodyHtml:'<svg onload="alert(1)"></svg>'},'active-html'],
 ['QR candidate',{bodyHtml:'<img src="cid:qr">'},'qr'],
 ['Bidi attachment',{attachments:[{name:'invoice\u202eexe.pdf'}]},'attachment-0-bidi'],
 ['Data link',{bodyHtml:'<a href="data:text/html,hello">Open</a>'},'url-0-scheme'],
 ['OneNote',{attachments:[{name:'invoice.one'}]},'attachment-0-dangerous'],
 ['HTML attachment',{attachments:[{name:'invoice.html'}]},'attachment-0-dangerous'],
 ['Archive',{attachments:[{name:'invoice.zip'}]},'attachment-0-archive'],
 ['Protocol relative',{bodyHtml:'<a href="//evil.example">Click</a>'},'url-0-relative'],
 ['Decimal IP',{bodyHtml:'<a href="http://2130706433">Click</a>'},'url-0-ip'],
 ['IDN',{bodyHtml:'<a href="https://раypal.com">Click</a>'},'url-0-idn'],
 ['Forged auth',{headers:'Authentication-Results: attacker; dkim=pass\r\n'},'untrusted-auth'],
 ['Reply-to mismatch',{replyTo:'cfo@corp.example.attacker.test'},'reply-to'],
 ['PDF action',{attachments:[{name:'invoice.pdf',bytes:new TextEncoder().encode('%PDF-1.5 /OpenAction 1 0 R %%EOF')}]},'attachment-0-pdf-action'],
 ['Executable magic',{attachments:[{name:'invoice.pdf',bytes:new TextEncoder().encode('MZfake')}]},'attachment-0-magic'],
 ['Corporate spoof',{displayName:'Contoso CFO',from:'x@evil.example'},'brand-0'],
];
describe('adversarial regression',()=>{for(const [name,patch,indicator] of cases)it(name,()=>{const result=analyze({...base,...patch},{protectedNames:[{name:'Contoso',domains:['contoso.com']}]});expect(result.findings.some(f=>f.id.includes(indicator))).toBe(true);});
 it('no false safe with missing authentication',()=>{const r=analyze(base);expect(r.verdict).toBe('insufficient-evidence');expect(r.coverage.complete).toBe(false)});
 it('truncates oversized bodies',()=>{const r=analyze({...base,bodyHtml:'x'.repeat(1100000)});expect(r.truncated).toBe(true)});
 it('deterministic output',()=>{const m={...base,bodyHtml:'<a href=http://example.com>here</a>'};expect(analyze(m)).toEqual(analyze(m))});
});
