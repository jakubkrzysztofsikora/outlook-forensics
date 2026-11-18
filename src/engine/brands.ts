import { hostMatches } from './util';
/** Built-in impersonation targets. Official domains only; user-content sub-domains (e.g. *.onmicrosoft.com) are deliberately excluded. */
export const BRANDS: Array<{ name: string; domains: string[] }> = [
  { name: 'microsoft', domains: ['microsoft.com', 'microsoftonline.com', 'microsoft365.com', 'office.com', 'office365.com', 'office.net', 'outlook.com', 'live.com', 'sharepoint.com', 'windows.com', 'azure.com', 'msn.com', 'bing.com', 'skype.com', 'xbox.com', 'aka.ms'] },
  { name: 'paypal', domains: ['paypal.com', 'paypal.me', 'paypal-communication.com'] },
  { name: 'google', domains: ['google.com', 'gmail.com', 'googlemail.com', 'googleusercontent.com', 'gstatic.com', 'goo.gl', 'youtube.com', 'withgoogle.com'] },
  { name: 'apple', domains: ['apple.com', 'icloud.com', 'me.com'] },
  { name: 'amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.pl', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazonses.com', 'amazonaws.com', 'amazon.ie'] },
  { name: 'docusign', domains: ['docusign.com', 'docusign.net'] },
  { name: 'dropbox', domains: ['dropbox.com', 'dropboxmail.com'] },
  { name: 'linkedin', domains: ['linkedin.com', 'licdn.com'] },
  { name: 'dhl', domains: ['dhl.com', 'dhl.de', 'dhl.pl'] },
  { name: 'fedex', domains: ['fedex.com'] },
  { name: 'netflix', domains: ['netflix.com'] },
  { name: 'facebook', domains: ['facebook.com', 'facebookmail.com', 'fb.com'] },
  { name: 'adobe', domains: ['adobe.com', 'adobesign.com'] },
  { name: 'zoom', domains: ['zoom.us', 'zoom.com'] },
  { name: 'okta', domains: ['okta.com'] },
];
export const isOfficialHost = (host: string): boolean => BRANDS.some(b => b.domains.some(d => hostMatches(host, d)));
export const FREEMAIL = new Set(['gmail', 'googlemail', 'yahoo', 'hotmail', 'outlook', 'live', 'msn', 'proton', 'protonmail', 'icloud', 'aol', 'gmx', 'mail', 'wp', 'o2', 'interia', 'onet', 'poczta']);
export const URL_SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rebrand.ly', 'buff.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly', 'v.gd', 'qr.ae', 'bl.ink']);
/** Platforms where anybody can host a page or form; the sender's own link is rarely the point, the content is. */
export const USER_CONTENT_HOSTS = ['forms.office.com', 'forms.microsoft.com', 'forms.gle', 'typeform.com', 'jotform.com', 'sites.google.com', 'notion.site', 'canva.com', 'weebly.com', 'wixsite.com', 'webflow.io', 'blob.core.windows.net', 'web.core.windows.net', 'firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'github.io', 'netlify.app', 'vercel.app', 'glitch.me', 'ipfs.io', 'storage.googleapis.com', 'r2.dev', 'herokuapp.com'];
