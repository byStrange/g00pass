import { escrowRecipientIds, idMatchesFingerprint, normalizeKeyId, parsePublicKey, readRecipientLines, sanitizeDisplayText, type StoreSnapshot } from '../core';
import { h } from './dom';

/**
 * People, by name. Names come from the user id inside each person's public
 * key: they are labels the key's owner typed and prove nothing. The
 * fingerprint is the real identity, so it stays visible (small) next to
 * the name, and the app asks for it whenever identity matters.
 */

export interface Person {
  readonly fingerprint: string;
  /** "Alice Example", or a short fingerprint when the key has no name. */
  readonly name: string;
  readonly email: string | null;
  readonly escrow: boolean;
}

const cache = new WeakMap<StoreSnapshot, Map<string, Promise<Person>>>();

export function shortFpr(fpr: string): string {
  return (fpr.slice(-16).match(/.{4}/g) ?? []).join(' ');
}

export function splitUserId(uid: string): { name: string; email: string | null } {
  const m = /^(.*?)\s*<([^<>]*)>\s*$/.exec(uid);
  return m ? { name: m[1]!.trim(), email: m[2]!.trim() || null } : { name: uid.trim(), email: null };
}

export function person(snapshot: StoreSnapshot, fingerprint: string, escrow = false): Promise<Person> {
  const fpr = fingerprint.toUpperCase();
  let m = cache.get(snapshot);
  if (!m) cache.set(snapshot, (m = new Map()));
  const ck = `${fpr}|${escrow}`;
  let p = m.get(ck);
  if (!p) {
    p = (async () => {
      let uid: string;
      try {
        const data = await snapshot.readFile(`.public-keys/${fpr}`);
        const keys = data ? await parsePublicKey(data, fpr) : [];
        uid = keys.length === 1 ? sanitizeDisplayText(keys[0]!.getUserIDs()[0] ?? '', 200) : '';
      } catch {
        uid = '';
      }
      const { name, email } = splitUserId(uid);
      return { fingerprint: fpr, name: escrow ? 'Recovery key' : name || `Key ${shortFpr(fpr)}`, email, escrow };
    })();
    m.set(ck, p);
  }
  return p;
}

/** Members of `folder` (its own `.gpg-id`), people first, recovery key last. */
export async function members(snapshot: StoreSnapshot, folder: string): Promise<Person[]> {
  const lines = (await readRecipientLines(snapshot, folder)) ?? [];
  const escrow = await escrowRecipientIds(snapshot);
  const out: Person[] = [];
  for (const l of lines) {
    const fpr = normalizeKeyId(l.id);
    const isEscrow = l.flags.includes('g00pass:escrow') || escrow.some((e) => idMatchesFingerprint(e, fpr));
    out.push(await person(snapshot, fpr, isEscrow));
  }
  return out.sort((a, b) => Number(a.escrow) - Number(b.escrow) || a.name.localeCompare(b.name));
}

/** "Alice, Bob and you (+ recovery key)" */
export function namesSentence(people: readonly Person[], me: string | null): string {
  const real = people.filter((p) => !p.escrow).map((p) => (p.fingerprint === me ? 'you' : p.name));
  const list = real.length <= 1 ? real.join('') : `${real.slice(0, -1).join(', ')} and ${real[real.length - 1]}`;
  return `${list || 'nobody'}${people.some((p) => p.escrow) ? ' (+ the recovery key)' : ''}`;
}

/** Name in bold, e-mail and short fingerprint below. */
export function personBlock(p: Person, opts: { me?: string | null } = {}): HTMLElement {
  return h('div', { class: 'person-row' }, avatar(p), personText(p, opts));
}

function personText(p: Person, opts: { me?: string | null }): HTMLElement {
  return h(
    'div',
    { class: 'person' },
    h('div', {}, h('b', { class: 'uid', dir: 'auto' }, p.name), p.fingerprint === opts.me ? h('span', { class: 'badge' }, 'you') : '', p.escrow ? h('span', { class: 'badge' }, 'recovery') : ''),
    h('div', { class: 'hint' }, p.email ? h('span', { class: 'uid', dir: 'auto' }, `${p.email} · `) : '', h('span', { class: 'mono', title: p.fingerprint }, `key …${shortFpr(p.fingerprint)}`)),
  );
}

/** Stable color index (0-7) for a fingerprint or name. */
function hue(seed: string): number {
  let x = 0;
  for (const c of seed) x = (x * 31 + c.charCodeAt(0)) >>> 0;
  return x % 8;
}

export function initials(name: string): string {
  const parts = name.replace(/[^\p{L}\p{N}\s]/gu, ' ').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return ((parts[0]![0] ?? '') + (parts.length > 1 ? parts[parts.length - 1]![0] ?? '' : '')).toUpperCase();
}

/** Round avatar with initials; the color comes from the key, so it is the same everywhere. */
export function avatar(p: Pick<Person, 'name' | 'fingerprint' | 'escrow'>, size: 'sm' | 'md' | 'lg' = 'md'): HTMLElement {
  return h('span', { class: `avatar ${size} av-${p.escrow ? 'escrow' : hue(p.fingerprint)}`, 'aria-hidden': 'true' }, p.escrow ? '⛑' : initials(p.name));
}

/** Overlapping avatars, "+N" after `max`. */
export function avatarStack(people: readonly Person[], max = 4): HTMLElement {
  const shown = people.slice(0, max);
  return h('span', { class: 'avatar-stack', title: people.map((p) => p.name).join(', ') }, ...shown.map((p) => avatar(p, 'sm')), people.length > max ? h('span', { class: 'avatar sm more' }, `+${people.length - max}`) : '');
}

/** Tile for a folder or secret: first letter on a color from its name. */
export function tile(name: string, size: 'sm' | 'md' | 'lg' = 'md'): HTMLElement {
  const base = name.split('/').filter(Boolean).pop() ?? name;
  return h('span', { class: `tile ${size} av-${hue(name)}`, 'aria-hidden': 'true' }, (base[0] ?? '?').toUpperCase());
}
