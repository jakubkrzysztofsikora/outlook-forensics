export type Severity='info'|'low'|'medium'|'high'|'critical';
export type Verdict='no-known-indicators'|'review'|'likely-phishing'|'insufficient-evidence';
export interface Attachment {name:string;size?:number;contentType?:string;bytes?:Uint8Array;byteStatus?:'unavailable'|'too-large'|'read-error'|'read';format?:string;url?:string}
export interface Message {subject:string;from:string;displayName:string;replyTo?:string;sender?:string;headerFrom?:string[];headerReplyTo?:string[];headerSender?:string;messageIdDomain?:string;returnPath?:string;headerReadError?:string;bodyHtml?:string;bodyText?:string;headers?:string;attachments?:Attachment[];identity?:string}
export interface Finding {id:string;severity:Severity;title:string;evidence:string;recommendation?:string}
export interface Check {name:string;state:'evaluated'|'partial'|'unavailable';detail:string}
export interface Result {verdict:Verdict;findings:Finding[];checks:Check[];ruleVersion:string;coverage:{complete:boolean;unavailable:string[]};truncated:boolean;hosts:string[]}
export interface Policy {internalDomains?:string[];trustedDomains?:string[];protectedNames?:Array<{name:string;domains:string[]}>}

export interface AnalyzeOptions {domainAges?:Record<string,string>;now?:number}
