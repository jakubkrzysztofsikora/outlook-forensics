import type { Message } from '../engine/types';
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
      attachments: (item.attachments || []).map(a => ({ name: a.name, size: a.size, contentType: a.contentType, byteStatus: 'unavailable' }))
    } };
  } catch (error) {
    return { status: 'read-error', reason: error instanceof Error ? error.message : 'Unknown Office.js error' };
  }
}
