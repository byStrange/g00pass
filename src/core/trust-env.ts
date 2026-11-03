import { TrustError } from './errors';
import { GitHubSnapshot } from './github/snapshot';
import type { FileHistory } from './github/history';
import type { GitHubRepo } from './github/client';
import { normalizePath } from './paths';
import type { StoreSnapshot } from './store';
import { isTrustHookLocked } from './trust';

/**
 * Device-local inputs of the trust policy. Production uses the defaults
 * (localStorage, GitHubSnapshot identity + history, wall clock). Tests inject
 * their own via setTrustEnvironment(); this is frozen by lockTrustHook().
 *
 * Nothing here is secret, but all of it is INTEGRITY-sensitive: it is the
 * part of the trust decision the repository cannot influence.
 */
export interface TrustStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface TrustEnvironment {
  readonly storage: TrustStorage;
  /** Stable identity of the store a snapshot belongs to, or null (unknown store: nothing is trusted). */
  storeId(snapshot: StoreSnapshot): string | null;
  /** History reachable from the snapshot's commit, if available. */
  history(snapshot: StoreSnapshot): FileHistory | null;
  now(): Date;
}

export class MemoryTrustStorage implements TrustStorage {
  readonly map = new Map<string, string>();
  getItem(k: string) {
    return this.map.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.map.set(k, v);
  }
  removeItem(k: string) {
    this.map.delete(k);
  }
}

/** `owner/repo|storeRoot`, owner/repo lower-cased (GitHub names are case-insensitive). */
export function storeIdOf(repo: Pick<GitHubRepo, 'owner' | 'repo' | 'storeRoot'>): string {
  return `${repo.owner.toLowerCase()}/${repo.repo.toLowerCase()}|${normalizePath(repo.storeRoot ?? '')}`;
}

function browserStorage(): TrustStorage {
  try {
    if (typeof localStorage !== 'undefined') return localStorage;
  } catch {
    /* storage disabled */
  }
  return new MemoryTrustStorage();
}

function defaults(): TrustEnvironment {
  return {
    storage: browserStorage(),
    storeId: (s) => (s instanceof GitHubSnapshot ? storeIdOf(s.repo) : null),
    history: (s) => (s instanceof GitHubSnapshot ? s.fileHistory() : null),
    now: () => new Date(),
  };
}

let env: TrustEnvironment | null = null;

/** Current environment. Once the trust hook is locked it is frozen (its fields cannot be swapped). */
export function trustEnvironment(): TrustEnvironment {
  const e = (env ??= defaults());
  if (isTrustHookLocked() && !Object.isFrozen(e)) Object.freeze(e);
  return e;
}

/** Override parts of the environment (tests). Throws once the trust hook is locked. */
export function setTrustEnvironment(partial: Partial<TrustEnvironment>): TrustEnvironment {
  if (isTrustHookLocked()) throw new TrustError('', 'trust environment is locked; it can only be set at start-up');
  env = { ...trustEnvironment(), ...partial };
  return env;
}

/** Back to defaults (tests). Throws once locked. */
export function resetTrustEnvironment(): void {
  if (isTrustHookLocked()) throw new TrustError('', 'trust environment is locked');
  env = null;
}

// ---- small JSON maps in storage (fail closed: unreadable => empty) ----

export function readMap<T>(key: string, valid: (v: unknown) => v is T): Record<string, T> {
  let raw: string | null;
  try {
    raw = trustEnvironment().storage.getItem(key);
  } catch {
    return {};
  }
  if (!raw) return {};
  try {
    const o = JSON.parse(raw) as unknown;
    if (!o || typeof o !== 'object' || Array.isArray(o)) return {};
    const out: Record<string, T> = Object.create(null) as Record<string, T>;
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) if (valid(v)) out[k] = v;
    return out;
  } catch {
    return {};
  }
}

export function writeMap<T>(key: string, map: Record<string, T>): void {
  trustEnvironment().storage.setItem(key, JSON.stringify(map));
}

export function updateMap<T>(key: string, valid: (v: unknown) => v is T, fn: (m: Record<string, T>) => void): void {
  const m = readMap(key, valid);
  fn(m);
  writeMap(key, m);
}
