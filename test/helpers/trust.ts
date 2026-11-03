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
  /** Merge commits in any range (tests model a merge by listing it plus its parents' states in `hidden`). */
  mergeList: { sha: string; parents: string[] }[] = [];
  /** States not listed by versions() (pruned by history simplification), by commitSha. */
  hidden: StoreSnapshot[] = [];
  /** null simulates a range too large to check. */
  mergesResult: 'ok' | null = 'ok';
  constructor(public states: StoreSnapshot[]) {}
  async merges() {
    return this.mergesResult === null ? null : this.mergeList;
  }
  async readAt(commit: string, path: string) {
    const s = [...this.states, ...this.hidden].find((x) => x.commitSha === commit);
    if (!s) throw new Error(`unknown commit ${commit}`);
    return s.readFile(path);
  }
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

/**
 * `.gpg-id` text + folder-bound signature by `signer`, declaring the given
 * direct child boundaries (`child@g00pass`). 4th argument: a date (legacy) or options.
 */
export async function signedGpgId(
  folder: string,
  text: string,
  signer: PrivateKey,
  dateOrOpts?: Date | { date?: Date; children?: string[] },
) {
  const o = dateOrOpts instanceof Date ? { date: dateOrOpts } : (dateOrOpts ?? {});
  const prefix = folder ? `${folder}/` : '';
  return {
    [`${prefix}.gpg-id`]: text,
    [`${prefix}.gpg-id.sig`]: await signGpgId(text, folder, signer, { date: o.date, children: o.children }),
  };
}

/** Snapshot wrapper counting reads (e.g. to bound how many key files are parsed). */
export function countingSnapshot(s: StoreSnapshot): StoreSnapshot & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    get commitSha() {
      return s.commitSha;
    },
    listFiles: () => s.listFiles(),
    hasFile: (p: string) => s.hasFile(p),
    readFile: async (p: string) => {
      reads.push(p);
      return s.readFile(p);
    },
  };
}

export async function adminsFiles(base: StoreSnapshot, folder: string, admins: string[], signer: PrivateKey, date?: Date) {
  const f = await signAdminsFile({ snapshot: base, folder, admins, signingKey: signer, date });
  return { [f.path]: f.content, [f.sigPath]: f.signature };
}
