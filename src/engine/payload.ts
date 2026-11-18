import { inspectHtml } from './html';
import { checkUrl, type Emit, type UrlCtx } from './url';
import { clean } from './util';

/** Static, bounded inspection of attachment bytes. Nothing is decompressed, executed or rendered. */
const DANGEROUS_MEMBER = /\.(?:exe|scr|js|jse|vbs|vbe|wsf|hta|ps1|bat|cmd|com|msi|lnk|iso|img|jar|dll|rdp|appinstaller|msix|one|chm|reg|cpl|scf|library-ms|search-ms|xll|iqy)$/i;
const NESTED_ARCHIVE = /\.(?:zip|rar|7z|cab|gz|tar|iso|img|vhd|vhdx)$/i;
const MAX_ZIP_ENTRIES = 5000;
const latin1 = (b: Uint8Array) => new TextDecoder('latin1').decode(b);

export interface ZipEntry { name: string; encrypted: boolean }
/** Reads names from the ZIP central directory. Returns undefined if the bytes are not a readable ZIP. */
export function zipEntries(b: Uint8Array): ZipEntry[] | undefined {
  if (b.length < 22 || b[0] !== 0x50 || b[1] !== 0x4b) return undefined;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return undefined;
  const count = Math.min(dv.getUint16(eocd + 10, true), MAX_ZIP_ENTRIES);
  let p = dv.getUint32(eocd + 16, true);
  const out: ZipEntry[] = [];
  for (let k = 0; k < count; k++) {
    if (p + 46 > b.length || dv.getUint32(p, true) !== 0x02014b50) break;
    const flags = dv.getUint16(p + 8, true), nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
    if (p + 46 + nameLen > b.length) break;
    out.push({ name: new TextDecoder('utf-8').decode(b.subarray(p + 46, p + 46 + nameLen)), encrypted: (flags & 1) === 1 });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

export function inspectPayload(name: string, b: Uint8Array, i: number, ctx: UrlCtx, emit: Emit, maxBytes: number): boolean {
  const view = b.length > maxBytes ? b.subarray(0, maxBytes) : b;
  const head = latin1(view.subarray(0, 8));
  const id = (s: string) => `attachment-${i}-${s}`;
  const lower = name.toLowerCase().replace(/[\s.]+$/g, '');
  const ext = lower.split('.').pop() || '';

  if (head.startsWith('MZ') && !['exe', 'dll', 'scr', 'sys'].includes(ext)) emit(id('magic'), 'high', 'Executable signature inconsistent with filename', clean(name));

  if (head.startsWith('PK')) {
    const entries = zipEntries(view);
    if (entries) {
      const names = entries.map(e => e.name);
      const bad = names.find(n => DANGEROUS_MEMBER.test(n));
      if (bad) emit(id('zip-dangerous'), 'high', 'Archive contains an executable or script member', clean(bad));
      if (names.some(n => /(?:^|\/)\.\.(?:\/|$)|^\/|^[a-z]:/i.test(n))) emit(id('zip-traversal'), 'high', 'Archive member path escapes its folder', clean(names.find(n => /\.\.|^\//.test(n)) || ''));
      if (entries.some(e => e.encrypted)) emit(id('zip-encrypted'), 'medium', 'Encrypted archive (cannot be scanned by gateways; password usually in the mail body)', clean(name));
      if (names.some(n => /vbaProject\.bin$/i.test(n))) emit(id('office-macro'), 'high', 'Office file contains a VBA macro project', clean(name));
      if (names.some(n => /(?:^|\/)(?:embeddings|activeX)\//i.test(n))) emit(id('office-embedded'), 'medium', 'Office file embeds OLE/ActiveX objects', clean(name));
      if (names.some(n => NESTED_ARCHIVE.test(n))) emit(id('zip-nested'), 'low', 'Archive contains another archive or disk image', clean(name));
      if (names.length >= MAX_ZIP_ENTRIES) emit(id('zip-limit'), 'low', 'Archive entry list truncated', String(names.length));
    } else emit(id('zip-unreadable'), 'low', 'ZIP signature but central directory unreadable', clean(name));
  }

  if (head.startsWith('%PDF')) {
    const t = latin1(view);
    if (/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/Launch\b|\/EmbeddedFile\b/i.test(t)) emit(id('pdf-action'), 'high', 'PDF contains active-content indicators', clean(name));
    let k = 0;
    for (const m of t.matchAll(/\/URI\s*\(([^)\\]{1,500})\)/g)) { if (k >= 20) break; checkUrl(m[1], '', id(`pdf-url-${k++}`), ctx, emit); }
    if (!/\/URI\s*\(/.test(t) && /\/FlateDecode/.test(t) && !/\/Type\s*\/Page\b/.test(t)) emit(id('pdf-streams'), 'info', 'PDF objects are compressed; links inside them were not inspected', clean(name));
  }

  if (['html', 'htm', 'xhtml', 'shtml', 'svg', 'mht', 'mhtml'].includes(ext) || /^\s*<(?:!doctype|html|svg)/i.test(latin1(view.subarray(0, 64)))) {
    const t = new TextDecoder('utf-8').decode(view.subarray(0, Math.min(view.length, 1024 * 1024)));
    try {
      const f = inspectHtml(t, 200);
      if (f.forms || f.passwordInputs) emit(id('html-form'), 'high', 'HTML attachment contains a login form (local credential-harvesting page)', clean(name));
      f.links.forEach((l, k) => checkUrl(l.href, l.label, id(`html-url-${k}`), ctx, emit));
      if (f.metaRefresh.length) emit(id('html-refresh'), 'high', 'HTML attachment redirects on open', clean(f.metaRefresh[0]));
    } catch { /* unparseable */ }
    if (/\batob\s*\(|new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL|\bdownload\s*=|unescape\s*\(\s*['"]%/i.test(t)) emit(id('html-smuggling'), 'high', 'HTML attachment assembles a file in the browser (HTML smuggling)', clean(name));
  }

  if (ext === 'eml' || /^(?:received|from|return-path|mime-version|message-id|date|subject):/im.test(latin1(view.subarray(0, 512)))) {
    const t = latin1(view).slice(0, 500000);
    let k = 0;
    for (const m of t.matchAll(/https?:\/\/[^\s<>"')]+/gi)) { if (k >= 30) break; checkUrl(m[0], '', id(`eml-url-${k++}`), ctx, emit); }
  }
  return true;
}
