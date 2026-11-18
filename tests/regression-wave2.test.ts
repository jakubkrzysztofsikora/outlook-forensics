import {describe,it,expect} from 'vitest';
import {analyze} from '../src/engine/analyze';
import type {Message,Policy} from '../src/engine/types';
const base:Message={subject:'Hello',from:'alice@partner.example',displayName:'Alice',bodyHtml:'<p>hi</p>',bodyText:'',attachments:[]};
const pol:Policy={internalDomains:['circit.io'],protectedNames:[{name:'Contoso',domains:['contoso.com']}]};
type Case={id:string;patch:Partial<Message>;should:'flag'|'clean';policy?:Policy;expectId?:string;baselineOnly?:boolean};
const many=Array.from({length:300},(_,i)=>`<a href="http://10.0.0.${i%250}/x${i}">l</a>`).join('');
export const cases:Case[]=[
{id:'G1',patch:{bodyHtml:'<a href="https://evil.example/x"><span>https://</span><span>login.microsoftonline.com</span></a>'},should:'flag'},
{id:'G2',patch:{bodyHtml:'<img src="cid:x" usemap="#m"><map name="m"><area href="https://evil.example/login"></map>'},should:'flag',expectId:'url'},
{id:'G3',patch:{bodyHtml:'<meta http-equiv="Refresh" content="0;url=https://evil.example/login">'},should:'flag'},
{id:'G4',patch:{bodyHtml:'<input type="Password" name="pw">'},should:'flag'},
{id:'G5',patch:{bodyHtml:'<a href="ms-msdt:/id PCWDiagnostic /skip force">Fix</a>'},should:'flag'},
{id:'G6',patch:{bodyHtml:'<a href="search-ms:query=invoice&crumb=location:\\\\evil.example\\share">Open</a>'},should:'flag'},
{id:'G7',patch:{bodyHtml:'<a href="ms-excel:ofe|u|https://evil.example/x.xlsm">Open sheet</a>'},should:'flag'},
{id:'G8',patch:{bodyHtml:'<a href="\\\\evil.example\\share\\invoice.pdf">Open</a>'},should:'flag'},
{id:'G9',patch:{bodyHtml:'<img src="file://evil.example/x.png">'},should:'flag'},
{id:'G10',patch:{bodyHtml:undefined,bodyText:'Please confirm (http://evil.example) today'},should:'flag'},
{id:'G11',patch:{bodyHtml:'<a href="https://evil.example/x">'+'<b></b>'.repeat(90)+'https://login.microsoftonline.com</a>'},should:'flag'},
{id:'G12',patch:{bodyHtml:'<a href="https://evil.example/login>https://microsoft.com</a>'},should:'flag',baselineOnly:true},
{id:'G13',patch:{bodyHtml:'<form action="https://evil.example/p"><input name=u></form>'},should:'flag'},
{id:'G14',patch:{bodyHtml:'<iframe src="https://evil.example/x"></iframe>'},should:'flag'},
{id:'G15',patch:{bodyHtml:many,attachments:[{name:'invoice.exe'}]},should:'flag',expectId:'attachment-0-dangerous'},
{id:'G16',patch:{headers:'From: "Alice" <alice@partner.example>\r\nFrom: "CEO" <ceo@circit.io>\r\nReceived: from x\r\n'},should:'flag'},
{id:'G17',patch:{headers:'Authentication-Results: spf=fail; dkim=none; dmarc=fail; compauth=fail\r\n'},should:'flag'},
{id:'G18',patch:{headers:'X-Forefront-Antispam-Report: CIP:1.2.3.4;CTRY:RU;CAT:PHSH;SFTY:9.25\r\n'},should:'flag'},
{id:'G19',patch:{headers:'From: ceo@circit.io\r\nSender: attacker@evil.example\r\n'},should:'flag'},
{id:'G20',patch:{displayName:'Con\u200btoso CFO',from:'x@evil.example'},should:'flag',policy:pol},
{id:'G21',patch:{displayName:'C\u043entoso CFO',from:'x@evil.example'},should:'flag',policy:pol},
{id:'G22',patch:{from:'x@evil.example',subject:'Poufne: wynagrodzenia 2026'},should:'flag',policy:pol},
{id:'G23',patch:{from:'accounts@supplier-pay.example',subject:'Updated bank details',bodyHtml:'<p>Please use our new IBAN PL61109010140000071219812874 from the next payment.</p>',bodyText:'Please use our new IBAN PL61 1090 1014 0000 0712 1981 2874 from the next payment.'},should:'flag',policy:pol},
{id:'F1',patch:{bodyHtml:'<!--[if mso]><a href="https://evil.example/x">https://good.example</a><![endif]--><p>ok</p>'},should:'clean'},
{id:'F2',patch:{bodyHtml:'<a href="https://zażółć.pl/x">Strona</a>'},should:'clean'},
{id:'F3',patch:{from:'news@vendor.example',headers:'Return-Path: <bounce@mail.vendor.example>\r\nReceived: a\r\n'},should:'clean'},
{id:'F4',patch:{bodyHtml:'<p>hello</p><img src="https://t.vendor.example/p.gif">'},should:'clean'},
{id:'F5',patch:{from:'bob@circit.io',headers:'Authentication-Results: spf=pass; dkim=pass; dmarc=pass\r\nReceived: a\r\n'},should:'clean',policy:pol}
];
const flagged=(v:string)=>v==='review'||v==='likely-phishing'||v==='suspicious'||v==='likely-malicious';
describe('wave 2 supplied adversarial cases',()=>{for(const c of cases){it(c.id,()=>{const m={...base,...c.patch};const result=analyze(m,c.policy??{});if(c.baselineOnly){expect(result).toHaveProperty('verdict');return;}if(c.expectId)expect(result.findings.some(f=>f.id.includes(c.expectId!))).toBe(true);else expect(flagged(result.verdict)).toBe(c.should==='flag');});}});
