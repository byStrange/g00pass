import type { PrivateKey } from 'openpgp';
import {
  MemoryStore,
  MemoryTrustStorage,
  setTrustEnvironment,
  signAdminsFile,
  signGpgId,
  type FileHistory,
  type StoreSnapshot,
} from '../../src/core';

export const STORE_ID = 'acme/secrets|';

/** History of a file as a list of whole-store states, newest first. */
export class FakeHistory implements FileHistory {
  reads = 0;
  constructor(public states: StoreSnapshot[]) {}
  async *versions(path: string, companions: readonly string[], opts: { limit: number }) {
    let n = 0;
    for (const s of this.states) {
      if (n++ >= opts.limit) return;
      this.reads++;
      const files = await Promise.all([path, ...companions].map((p) => s.readFile(p)));
      yield { commitSha: s.commitSha, files };
    }
  }
}

export interface EnvHandle {
  storage: MemoryTrustStorage;
  history: FakeHistory | null;
  now: Date | null;
}

/** Fresh device-local trust environment (empty storage) for every test. */
export function freshEnv(): EnvHandle {
  const h: EnvHandle = { storage: new MemoryTrustStorage(), history: null, now: null };
  setTrustEnvironment({
    storage: h.storage,
    storeId: () => STORE_ID,
    history: () => h.history,
    now: () => h.now ?? new Date(),
  });
  return h;
}

let shaN = 0;
/** Immutable-by-convention copy of a store with changes applied (new commitSha). */
export async function derive(base: StoreSnapshot, changes: Record<string, Uint8Array | string | null>): Promise<MemoryStore> {
  const files: Record<string, Uint8Array> = {};
  for (const p of base.listFiles()) files[p] = (await base.readFile(p))!;
  const s = new MemoryStore(files, `c${++shaN}`);
  for (const [p, c] of Object.entries(changes)) {
    if (c === null) s.delete(p);
    else s.set(p, c);
  }
  return s;
}

/** `.gpg-id` text + folder-bound signature by `signer`. */
export async function signedGpgId(folder: string, text: string, signer: PrivateKey, date?: Date) {
  const prefix = folder ? `${folder}/` : '';
  return {
    [`${prefix}.gpg-id`]: text,
    [`${prefix}.gpg-id.sig`]: await signGpgId(text, folder, signer, { date }),
  };
}

export async function adminsFiles(base: StoreSnapshot, folder: string, admins: string[], signer: PrivateKey, date?: Date) {
  const f = await signAdminsFile({ snapshot: base, folder, admins, signingKey: signer, date });
  return { [f.path]: f.content, [f.sigPath]: f.signature };
}
