/**
 * Shared-origin risk (store-layout.md §Trust anchors, README §Deploy).
 *
 * The device key (passphrase-protected) and the pinned trust anchors live in
 * `localStorage`, which is shared by EVERY page on the same origin. On
 * `<user>.github.io` all of that user's project pages share one origin, and
 * any page served from the same origin but outside this app's path can read
 * and rewrite the key and the anchors. g00pass must therefore run at the
 * root of a dedicated origin; otherwise a blocking warning is shown until the
 * user explicitly accepts the risk for this exact origin + path.
 */

export const ORIGIN_ACK_KEY = 'g00pass.shared-origin-ack.v1';

export interface OriginRisk {
  readonly risky: boolean;
  readonly reasons: readonly string[];
  /** What the acknowledgement is bound to: origin + app path. */
  readonly scope: string;
}

/** App base path: the directory part of the page path ("/" at the origin root). */
export function appBasePath(pathname: string): string {
  const i = pathname.lastIndexOf('/');
  return i <= 0 ? '/' : pathname.slice(0, i + 1);
}

export function assessOrigin(loc: { hostname: string; origin: string; pathname: string }): OriginRisk {
  const reasons: string[] = [];
  const host = loc.hostname.toLowerCase();
  if (host === 'github.io' || host.endsWith('.github.io')) {
    reasons.push(`${host} is GitHub Pages: every repository page of this account shares this origin and its storage, and custom security headers (frame-ancestors) are not supported.`);
  }
  const base = appBasePath(loc.pathname);
  if (base !== '/') {
    reasons.push(`The app is served from ${base}, not from the root of its origin: other pages on ${loc.origin} share its storage.`);
  }
  return { risky: reasons.length > 0, reasons, scope: `${loc.origin}${base}` };
}

export function isOriginRiskAcknowledged(storage: Pick<Storage, 'getItem'>, risk: OriginRisk): boolean {
  try {
    return storage.getItem(ORIGIN_ACK_KEY) === risk.scope;
  } catch {
    return false;
  }
}

export function acknowledgeOriginRisk(storage: Pick<Storage, 'setItem'>, risk: OriginRisk): void {
  storage.setItem(ORIGIN_ACK_KEY, risk.scope);
}
