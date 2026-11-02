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
for (const f of readdirSync(join(dist, 'assets'))) {
  if (!f.endsWith('.js')) continue;
  const js = readFileSync(join(dist, 'assets', f), 'utf8');
  if (/\bnew Function\s*\(|[^\w.]eval\s*\(/.test(js)) fail(`${f} uses eval/new Function`);
}
console.log('check-dist: OK (CSP meta present, no inline/external scripts, no eval)');
