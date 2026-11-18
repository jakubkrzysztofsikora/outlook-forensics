import type { Message, Attachment } from '../engine/types';
import { parseInternetHeaders, headerAddresses } from '../engine/headers';

type ReadResult =
  | { status: 'ok'; message: Message }
  | { status: 'no-item' }
  | { status: 'read-error'; reason: string };

function asyncValue<T>(invoke: (cb: (r: Office.AsyncResult<T>) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    try {
      invoke(r => r.status === Office.AsyncResultStatus.Succeeded
        ? resolve(r.value)
        : reject(new Error(r.error?.message || 'Office.js read failed')));
    } catch (error) { reject(error); }
  });
}

const MAX_READ_BYTES = 2 * 1024 * 1024, MAX_READ_TOTAL = 10 * 1024 * 1024, MAX_READ_COUNT = 10;

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Reads attachment content in memory (Mailbox 1.8 getAttachmentContentAsync). Nothing is saved, opened or executed. */
async function readAttachments(item: Office.MessageRead, stable: () => boolean): Promise<Attachment[]> {
  const list = item.attachments || [];
  const canRead = Office.context.requirements.isSetSupported('Mailbox', '1.8') && typeof item.getAttachmentContentAsync === 'function';
  let total = 0, reads = 0;
  const out: Attachment[] = [];
  for (const a of list) {
    const base: Attachment = { name: a.name, size: a.size, contentType: a.contentType, byteStatus: 'unavailable' };
    if (!canRead || !stable()) { out.push(base); continue; }
    if (a.size > MAX_READ_BYTES || total + a.size > MAX_READ_TOTAL || reads >= MAX_READ_COUNT) { out.push({ ...base, byteStatus: 'too-large' }); continue; }
    reads++;
    try {
      const r = await asyncValue<Office.AttachmentContent>(cb => item.getAttachmentContentAsync(a.id, cb));
      total += a.size;
      if (r.format === Office.MailboxEnums.AttachmentContentFormat.Url) out.push({ ...base, url: r.content, format: 'url', byteStatus: 'read' });
      else if (r.format === Office.MailboxEnums.AttachmentContentFormat.Base64) out.push({ ...base, bytes: fromBase64(r.content), format: 'base64', byteStatus: 'read' });
      else out.push({ ...base, bytes: new TextEncoder().encode(r.content), format: String(r.format), byteStatus: 'read' });
    } catch { out.push({ ...base, byteStatus: 'read-error' }); }
  }
  return out;
}

export function selectedIdentity(): string | undefined {
  try { return Office.context?.mailbox?.item?.itemId || undefined; }
  catch { return undefined; }
}

export async function readCurrentMessage(): Promise<ReadResult> {
  if (typeof Office === 'undefined' || !Office.context?.mailbox?.item) return { status: 'no-item' };
  const item = Office.context.mailbox.item;
  const identity = item.itemId;
  const stable = () => Office.context?.mailbox?.item === item && Office.context?.mailbox?.item?.itemId === identity;
  try {
    const bodyHtml = await asyncValue<string>(cb => item.body.getAsync(Office.CoercionType.Html, cb));
    if (!stable()) return { status: 'read-error', reason: 'Selected message changed during scan' };
    const bodyText = await asyncValue<string>(cb => item.body.getAsync(Office.CoercionType.Text, cb));
    if (!stable()) return { status: 'read-error', reason: 'Selected message changed during scan' };
    let headers: string | undefined;
    let headerReadError: string | undefined;
    if (Office.context.requirements.isSetSupported('Mailbox', '1.8') && typeof item.getAllInternetHeadersAsync === 'function') {
      try { headers = await asyncValue<string>(cb => item.getAllInternetHeadersAsync(cb)); }
      catch (error) { headerReadError = error instanceof Error ? error.message : 'Header read failed'; }
    }
    if (!stable()) return { status: 'read-error', reason: 'Selected message changed during scan' };
    const attachments = await readAttachments(item, stable);
    if (!stable()) return { status: 'read-error', reason: 'Selected message changed during scan' };
    const parsed = headers ? parseInternetHeaders(headers) : [];
    const first = (name: string) => headerAddresses(parsed, name)[0];
    const from = item.from;
    const sender = item.sender;
    const messageId = parsed.find(h => h.name === 'message-id')?.value || '';
    const messageIdDomain = /@([^>\s]+)>?/.exec(messageId)?.[1]?.toLowerCase();
    return { status: 'ok', message: {
      identity, subject: item.subject || '', from: from?.emailAddress || '', displayName: from?.displayName || '',
      sender: sender?.emailAddress, headerFrom: headerAddresses(parsed, 'from'),
      headerReplyTo: headerAddresses(parsed, 'reply-to'), headerSender: first('sender'),
      replyTo: first('reply-to'), returnPath: first('return-path'), messageIdDomain,
      bodyHtml, bodyText, headers, headerReadError,
      attachments
    } };
  } catch (error) {
    return { status: 'read-error', reason: error instanceof Error ? error.message : 'Unknown Office.js error' };
  }
}
