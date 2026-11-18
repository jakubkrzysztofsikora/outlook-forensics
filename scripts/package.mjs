import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const origin = process.env.ADDIN_ORIGIN;
if (!origin || !/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(origin) || origin.includes('localhost')) {
  throw new Error('Set ADDIN_ORIGIN to the real HTTPS origin hosting dist/ before packaging a release');
}
if (!fs.existsSync('dist/index.html')) throw new Error('Missing dist/index.html; run npm run build');
const version = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
const out = path.resolve('release'); fs.mkdirSync(out, {recursive:true});
const stage = path.join(out, 'stage'); fs.rmSync(stage,{recursive:true,force:true});fs.mkdirSync(stage);
fs.cpSync('dist',path.join(stage,'site'),{recursive:true});
const manifest = fs.readFileSync('manifest.xml','utf8').replaceAll('https://localhost:3000',origin);
fs.writeFileSync(path.join(stage,'manifest.xml'),manifest);
fs.writeFileSync(path.join(stage,'DEPLOY.txt'),`Deploy site/ to ${origin}/ with HTTPS, then deploy manifest.xml through Microsoft 365 admin center.\nDo not install manifest before site is deployed.\n`);
const zip=path.join(out,`outlook-forensics-v${version}.zip`);
fs.rmSync(zip,{force:true});execFileSync('zip',['-qr',zip,'.'],{cwd:stage});
fs.rmSync(stage,{recursive:true,force:true});console.log(zip);
