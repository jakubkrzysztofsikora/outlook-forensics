# Release process

0. Add repository secret `POLICY_TS` (contents of your `src/policy.local.ts`). Without it the release builds with an **empty** policy and the workflow prints a warning. Optionally set variable `RDAP_ORIGIN` to enable the domain-age lookup (see README).
1. Set the repository Actions **variable** `ADDIN_ORIGIN` to the real HTTPS origin that will host the built site (no trailing slash, not localhost).
2. Make sure CI is green on `main` (`npm ci`, typecheck, tests, build, production dependency audit, no-network-API check).
3. Push a tag matching `package.json`, e.g. `git tag v0.1.0 && git push origin v0.1.0`.
4. The Release workflow re-runs all gates, runs `scripts/package.mjs` (copies `dist/` to `site/` and rewrites every `https://localhost:3000` in `manifest.xml` to `ADDIN_ORIGIN`) and attaches `outlook-forensics-v<version>.zip` to a GitHub release. It fails if `ADDIN_ORIGIN` is missing or invalid.
5. Upload `site/` to the origin first, then deploy `manifest.xml` through Microsoft 365 admin center → Integrated apps.

Before the first real rollout: fill in the policy secret, validate the manifest with Microsoft's validator, and test in the Outlook clients you actually use (new Outlook on Windows/Mac, web). The ZIP is a deployment package, not an offline extension.
