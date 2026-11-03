// Post-build guard: the emitted app must satisfy the CSP without exceptions.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const fail = (m) => {
  console.error(`check-dist: ${m}`);
  process.exit(1);
};

if (!/<meta http-equiv="Content-Security-Policy" content="[^"]*script-src 'self';/.test(html)) fail('CSP meta tag missing');
if (/unsafe-|wasm-unsafe-eval/.test(html)) fail('CSP contains unsafe keyword');
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
  if (!/\bsrc=/.test(m[1]) || m[2].trim() !== '') fail('inline <script> found');
  if (/src="(https?:)?\/\//.test(m[1])) fail('external script found');
}
if (/\son[a-z]+=/i.test(html)) fail('inline event handler attribute found');
if (/<link[^>]+href="(https?:)?\/\//.test(html)) fail('external stylesheet/link found');
// _headers: the full CSP incl. frame-ancestors (header-only directive) must ship.
let headers;
try {
  headers = readFileSync(join(dist, '_headers'), 'utf8');
} catch {
  fail('_headers missing');
}
const cspLine = headers.split('\n').find((l) => /^\s*Content-Security-Policy:/.test(l));
if (!cspLine) fail('_headers has no Content-Security-Policy');
if (!/frame-ancestors 'none'/.test(cspLine)) fail("_headers CSP lacks frame-ancestors 'none'");
if (!/script-src 'self'(;|$)/.test(cspLine) || !/default-src 'none'/.test(cspLine)) fail('_headers CSP is not the strict policy');
if (/unsafe-|wasm-unsafe-eval/.test(headers)) fail('_headers contains unsafe keyword');

let all = '';
for (const f of readdirSync(join(dist, 'assets'))) {
  if (!f.endsWith('.js')) continue;
  const js = readFileSync(join(dist, 'assets', f), 'utf8');
  if (/\bnew Function\s*\(|[^\w.]eval\s*\(/.test(js)) fail(`${f} uses eval/new Function`);
  all += js;
}
// Trust policy wiring (names are minified, so string markers are checked):
// the test-only pass-through hook must be tree-shaken out, and the
// signature hook + lock assertion + encrypt guard must be present.
if (all.includes('pass-through (UNVERIFIED)') || all.includes('recipient-signatures-not-verified')) fail('passThroughTrustHook is in the bundle');
if (!all.includes('gpg-id signatures v1')) fail('signatureTrustHook is missing from the bundle');
if (!all.includes('g00pass: trust policy is not locked')) fail('lockTrustHook() start-up assertion (src/main.ts) is missing from the bundle');
if (!all.includes('OpenPGP encryption outside encryptToVerified() is blocked')) fail('installEncryptGuard is missing from the bundle');
console.log('check-dist: OK (CSP meta + _headers with frame-ancestors, no inline/external scripts, no eval, trust hook locked, no pass-through hook)');
