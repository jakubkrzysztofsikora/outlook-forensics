import type { Policy } from './engine/types';
// Organisation policy lives in src/policy.local.ts (gitignored, never committed). Copy src/policy.example.ts to create it.
// With no local file the policy is empty, which means impersonation of YOUR people is NOT checked.
const local = import.meta.glob<{ default: Policy }>('./policy.local.ts', { eager: true });
export const CORPORATE_POLICY: Policy = Object.values(local)[0]?.default ?? { internalDomains: [], trustedDomains: [], protectedNames: [] };
