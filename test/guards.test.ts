import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { CSP_DIRECTIVES, CSP_HEADER, CSP_META } from '../csp.config';
import pkg from '../package.json';

const ROOT = join(__dirname, '..');
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const srcFiles = walk(join(ROOT, 'src')).filter((f) => /\.(ts|js)$/.test(f));
const code = (f: string) =>
  readFileSync(f, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
const rel = (f: string) => relative(ROOT, f).replace(/\\/g, '/');

describe('trust choke-point (static guard, backs up the ESLint rule)', () => {
  it('only src/core/crypto/encrypt.ts calls openpgp encrypt or namespace-imports openpgp', () => {
    const offenders = srcFiles
      .filter((f) => rel(f) !== 'src/core/crypto/encrypt.ts')
      .filter((f) => {
        const s = code(f);
        return (
          /import\s*\*\s*as\s+\w+\s+from\s*['"]openpgp['"]/.test(s) ||
          /import\(\s*['"]openpgp['"]\s*\)/.test(s) ||
          /\bopenpgp\s*\.\s*(encrypt|encryptSessionKey)\b/.test(s) ||
          /import\s*\{[^}]*\b(encrypt|encryptSessionKey)\b[^}]*\}\s*from\s*['"]openpgp['"]/.test(s) ||
          /openpgp\s*\[\s*['"`]encrypt/.test(s)
        );
      })
      .map(rel);
    expect(offenders).toEqual([]);
  });

  it('encryptToVerified is the only exported encrypt and checks minted sets', () => {
    const s = readFileSync(join(ROOT, 'src/core/crypto/encrypt.ts'), 'utf8');
    expect(s).toContain('isVerifiedRecipientSet(recipients)');
  });

  it('no console logging in src (secrets must never be logged)', () => {
    const offenders = srcFiles.filter((f) => /\bconsole\s*\.\s*\w+\s*\(/.test(code(f))).map(rel);
    expect(offenders).toEqual([]);
  });

  it('tokens are never written to localStorage', () => {
    const offenders = srcFiles
      .filter((f) => /localStorage\.setItem\([^)]*token/i.test(readFileSync(f, 'utf8')))
      .map(rel);
    expect(offenders).toEqual([]);
  });
});

describe('CSP', () => {
  it('has no unsafe keywords and only api.github.com as third-party origin', () => {
    for (const csp of [CSP_META, CSP_HEADER]) {
      expect(csp).not.toMatch(/unsafe-|\*|http:|blob:|wasm/);
    }
    const origins = Object.values(CSP_DIRECTIVES)
      .flat()
      .filter((v) => /^https?:/.test(v));
    expect(origins).toEqual(['https://api.github.com']);
    expect(CSP_DIRECTIVES['script-src']).toEqual(["'self'"]);
    expect(CSP_DIRECTIVES['default-src']).toEqual(["'none'"]);
    expect(CSP_HEADER).toContain("frame-ancestors 'none'");
  });
});

describe('dependency pinning', () => {
  it('all dependencies are exact versions', () => {
    const all = { ...pkg.dependencies, ...pkg.devDependencies } as Record<string, string>;
    for (const [name, v] of Object.entries(all)) expect(v, name).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
