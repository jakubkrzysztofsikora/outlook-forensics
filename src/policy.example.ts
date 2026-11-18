import type { Policy } from './engine/types';
/** Copy to src/policy.local.ts and edit. That file is gitignored. */
const policy: Policy = {
  // Your own mail domains. Senders here are "internal": enables external-sender-with-internal-subject
  // and silences the payment-document rule for them.
  internalDomains: ['circit.io'],
  // Known vendors / partners you accept payment documents, archives and HTML reports from.
  // This never silences executable, macro, form or link-mismatch findings.
  trustedDomains: [],
  // Names that attackers will use as a display name. Matching is case-, accent-, zero-width- and
  // Cyrillic/Greek-confusable-insensitive. `domains` are the ONLY legitimate sender domains for that name.
  protectedNames: [
    { name: 'Circit', domains: ['circit.io'] },
    // { name: 'Firstname Lastname', domains: ['circit.io'] },   // CEO, CTO, CFO, finance, HR payroll ...
  ],
};
export default policy;
