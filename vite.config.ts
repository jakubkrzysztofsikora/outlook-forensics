import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
export default defineConfig({plugins:[react()],server:{host:'127.0.0.1',port:3000,strictPort:true,https:process.env.LOCAL_HTTPS_KEY && process.env.LOCAL_HTTPS_CERT ? {key:fs.readFileSync(process.env.LOCAL_HTTPS_KEY),cert:fs.readFileSync(process.env.LOCAL_HTTPS_CERT)} : undefined},build:{outDir:'dist'},test:{environment:'node'}});
