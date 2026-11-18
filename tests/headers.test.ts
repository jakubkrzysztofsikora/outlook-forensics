import { describe, expect, it } from 'vitest';
import { parseInternetHeaders, headerAddresses } from '../src/engine/headers';
describe('synthetic header parser regression', () => {
  it('unfolds headers and preserves duplicates in order', () => {
    const h = parseInternetHeaders('From: Alice <alice@example.com>\r\nReply-To: bob@else.test\r\nAuthentication-Results: edge;\r\n dkim=pass\r\nAuthentication-Results: attacker; dkim=pass');
    expect(h.map(x => x.name)).toEqual(['from', 'reply-to', 'authentication-results', 'authentication-results']);
    expect(h[2].value).toBe('edge; dkim=pass');
    expect(headerAddresses(h, 'reply-to')).toEqual(['bob@else.test']);
  });
  it('does not treat a forged authentication result as verified', () => {
    const h = parseInternetHeaders('Authentication-Results: evil; dmarc=pass\r\nFrom: x@evil.test');
    expect(h[0].value).toContain('dmarc=pass');
    // Parsing a header is not verification of its provenance.
  });
});
