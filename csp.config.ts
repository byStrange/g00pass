/**
 * Single source of truth for the Content-Security-Policy.
 *
 * Rules (see DESIGN.md "Security of the web app itself"):
 *  - no inline scripts, no eval, no 'unsafe-*' keywords
 *  - the only third-party origin is https://api.github.com
 *
 * The policy is injected into index.html at build time (meta tag) and written
 * to dist/_headers for hosts that support header files. `frame-ancestors`
 * only works as an HTTP header, so it is only in _headers.
 */
export const CSP_DIRECTIVES: Record<string, string[]> = {
  'default-src': ["'none'"],
  'script-src': ["'self'"],
  'style-src': ["'self'"],
  'img-src': ["'self'", 'data:'],
  'font-src': ["'self'"],
  'connect-src': ["'self'", 'https://api.github.com'],
  'manifest-src': ["'self'"],
  'worker-src': ["'self'"],
  'base-uri': ["'none'"],
  'form-action': ["'none'"],
  'object-src': ["'none'"],
};

export const HEADER_ONLY_DIRECTIVES: Record<string, string[]> = {
  'frame-ancestors': ["'none'"],
};

export function serializeCsp(d: Record<string, string[]>): string {
  return Object.entries(d)
    .map(([k, v]) => `${k} ${v.join(' ')}`)
    .join('; ');
}

export const CSP_META = serializeCsp(CSP_DIRECTIVES);
export const CSP_HEADER = serializeCsp({ ...CSP_DIRECTIVES, ...HEADER_ONLY_DIRECTIVES });
