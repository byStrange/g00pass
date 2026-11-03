/**
 * Canonical JSON and digests for signed g00pass documents
 * (docs/specs/store-layout.md §Shared formats).
 */

/** Recursively sort object keys (UTF-16 code unit order); arrays keep their order. */
export function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  if (value === undefined) throw new Error('canonical JSON: undefined is not allowed (use null)');
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('canonical JSON: non-finite number');
  return value;
}

/** `JSON.stringify(sortKeysDeep(value), null, 2) + '\n'`. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value), null, 2) + '\n';
}

/**
 * Parse signed JSON bytes and require that they are exactly the canonical
 * serialization of what they parse to (no BOM, no extra whitespace, sorted
 * keys). Throws on anything else.
 */
export function parseCanonicalJson(bytes: Uint8Array): unknown {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const value: unknown = JSON.parse(text);
  if (canonicalJson(value) !== text) throw new Error('not canonical JSON');
  return value;
}

/** `"sha256:" + lower-case hex(sha256(bytes))` (WebCrypto). */
export async function sha256Digest(bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return 'sha256:' + [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** RFC 3339 UTC, `Z`, no fractional seconds. */
export function rfc3339(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
