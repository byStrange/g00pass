import { defineConfig, type Plugin } from 'vite';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { CSP_HEADER, CSP_META } from './csp.config.ts';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

function gitCommit(): string {
  if (process.env.G00PASS_COMMIT) return process.env.G00PASS_COMMIT;
  try {
    const sha = execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim() !== '';
    return dirty ? `${sha}-dirty` : sha;
  } catch {
    return 'unknown';
  }
}

/**
 * Build-only: inject the CSP meta tag, emit _headers, and emit a service
 * worker whose precache list is the exact set of emitted assets.
 * (CSP is not applied in dev because Vite's dev server injects inline styles.)
 */
function securityAndPwa(): Plugin {
  return {
    name: 'g00pass-security-pwa',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        const tag = `<meta http-equiv="Content-Security-Policy" content="${CSP_META}">`;
        if (!html.includes('<meta charset="utf-8">')) throw new Error('index.html must declare <meta charset="utf-8">');
        return html.replace('<meta charset="utf-8">', `<meta charset="utf-8">\n    ${tag}`);
      },
    },
    generateBundle(_opts, bundle) {
      const assets = Object.keys(bundle).filter((f) => !f.endsWith('.map'));
      const files = ['./', ...assets.map((f) => `./${f}`), './manifest.webmanifest', './icon.svg'];
      const version = createHash('sha256').update(files.join('\n')).digest('hex').slice(0, 16);
      const sw = readFileSync(new URL('./src/sw-template.js', import.meta.url), 'utf8')
        .replace('__PRECACHE__', JSON.stringify(files))
        .replace('__CACHE_VERSION__', version);
      this.emitFile({ type: 'asset', fileName: 'sw.js', source: sw });
      this.emitFile({
        type: 'asset',
        fileName: '_headers',
        source: [
          '/*',
          `  Content-Security-Policy: ${CSP_HEADER}`,
          '  X-Content-Type-Options: nosniff',
          '  Referrer-Policy: no-referrer',
          '  Permissions-Policy: camera=(), microphone=(), geolocation=()',
          '  Cross-Origin-Opener-Policy: same-origin',
          '',
        ].join('\n'),
      });
    },
  };
}

export default defineConfig({
  base: './',
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __APP_COMMIT__: JSON.stringify(gitCommit()),
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
  plugins: [securityAndPwa()],
});
