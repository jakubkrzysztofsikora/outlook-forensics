import { it, expect } from 'vitest';
import { CORPORATE_POLICY } from '../src/policy';
it('ships an empty policy when no local file exists (never silently trusts a domain)', () => {
  expect(CORPORATE_POLICY.trustedDomains ?? []).toEqual([]);
});
