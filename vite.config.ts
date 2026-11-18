import { loadEnv } from 'vite';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';

export default defineConfig(({ mode }) => {
  const rdap = (loadEnv(mode, process.cwd(), 'VITE_').VITE_RDAP_ORIGIN ?? '').replace(/\/+$/, '');
  return {
    plugins: [
      react(),
      // The CSP only allows a second connect-src origin when the opt-in RDAP lookup is configured at build time.
      { name: 'csp-rdap', transformIndexHtml: (html: string) => (rdap && /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(rdap) ? html.replace("connect-src 'self'", `connect-src 'self' ${rdap}`) : html) },
    ],
    server: { host: '127.0.0.1', port: 3000, strictPort: true, https: process.env.LOCAL_HTTPS_KEY && process.env.LOCAL_HTTPS_CERT ? { key: fs.readFileSync(process.env.LOCAL_HTTPS_KEY), cert: fs.readFileSync(process.env.LOCAL_HTTPS_CERT) } : undefined },
    build: { outDir: 'dist' },
    test: { environment: 'node' },
  };
});
