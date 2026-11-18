import { parse } from 'parse5';
/** Spec-compliant HTML parsing (parse5). Message HTML is never rendered and no resource is fetched. */
interface N { nodeName: string; attrs?: Array<{ name: string; value: string }>; childNodes?: N[]; content?: N; value?: string }
export interface LinkRef { href: string; label: string; kind: 'a' | 'area' }
export interface ImgRef { src: string; alt: string }
export interface HtmlFacts {
  links: LinkRef[]; imgs: ImgRef[]; text: string;
  forms: number; passwordInputs: number; formActions: string[];
  active: string[]; metaRefresh: string[]; base?: string; truncatedLinks: boolean;
}
const SKIP_TEXT = new Set(['script', 'style', 'head', 'title']);
const kids = (n: N): N[] => (n.nodeName === 'template' && n.content ? n.content.childNodes ?? [] : n.childNodes ?? []);
const attrMap = (n: N): Record<string, string> => { const o: Record<string, string> = {}; for (const a of n.attrs ?? []) if (!(a.name in o)) o[a.name] = a.value; return o; };

function textOf(root: N, limit: number): string {
  let out = '', budget = 20000;
  const stack: N[] = [root];
  while (stack.length && out.length < limit && budget-- > 0) {
    const n = stack.pop()!;
    if (n.nodeName === '#text') out += n.value ?? '';
    else if (n.nodeName !== '#comment' && !SKIP_TEXT.has(n.nodeName)) { const c = kids(n); for (let i = c.length - 1; i >= 0; i--) stack.push(c[i]); }
  }
  return out.replace(/\s+/g, ' ').trim().slice(0, limit);
}

export function inspectHtml(html: string, maxLinks: number): HtmlFacts {
  const f: HtmlFacts = { links: [], imgs: [], text: '', forms: 0, passwordInputs: 0, formActions: [], active: [], metaRefresh: [], truncatedLinks: false };
  const doc = parse(html) as unknown as N;
  const seen = new Set<string>();
  const stack: N[] = [doc];
  while (stack.length) {
    const n = stack.pop()!;
    const tag = n.nodeName;
    if (tag.startsWith('#')) { const c = kids(n); for (let i = c.length - 1; i >= 0; i--) stack.push(c[i]); continue; }
    const a = attrMap(n);
    if ((tag === 'a' || tag === 'area') && a.href !== undefined) {
      const label = tag === 'a' ? textOf(n, 240) : '';
      const key = a.href + '\u0000' + label;
      if (!seen.has(key)) {
        if (f.links.length >= maxLinks) f.truncatedLinks = true;
        else { seen.add(key); f.links.push({ href: a.href, label, kind: tag }); }
      }
    }
    if (tag === 'img') f.imgs.push({ src: a.src ?? '', alt: a.alt ?? '' });
    if (tag === 'form') { f.forms++; if (a.action) f.formActions.push(a.action); }
    if (tag === 'input' && (a.type ?? '').trim().toLowerCase() === 'password') f.passwordInputs++;
    if (tag === 'base' && a.href && !f.base) f.base = a.href;
    if (tag === 'meta' && (a['http-equiv'] ?? '').trim().toLowerCase() === 'refresh') f.metaRefresh.push(a.content ?? '');
    if (['script', 'object', 'embed', 'iframe', 'frame'].includes(tag)) f.active.push(tag);
    if (Object.keys(a).some(k => /^on[a-z]+$/.test(k))) f.active.push(`${tag}[event-handler]`);
    const c = kids(n); for (let i = c.length - 1; i >= 0; i--) stack.push(c[i]);
  }
  f.text = textOf(doc, 200000);
  return f;
}
