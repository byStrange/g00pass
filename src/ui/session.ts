import type { PrivateKey } from 'openpgp';

/** Best-effort zeroing of the unlocked secret key material (openpgp.js `clearPrivateParams`, not in its typings). */
export function wipePrivateKey(key: PrivateKey | null): void {
  if (!key) return;
  try {
    (key as unknown as { clearPrivateParams?: () => void }).clearPrivateParams?.();
  } catch {
    /* already cleared / not decrypted */
  }
}

/**
 * Holds the unlocked key in memory and locks after inactivity. Locking (idle
 * timeout, "Lock now", pagehide) drops the reference AND wipes the decrypted
 * private parameters, so an operation still holding the key fails instead of
 * keeping secret material alive.
 */
export class Session {
  private key: PrivateKey | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  constructor(
    private readonly idleMs: number,
    private readonly onLock: () => void,
  ) {}
  unlock(key: PrivateKey): void {
    if (this.key && this.key !== key) wipePrivateKey(this.key);
    this.key = key;
    this.touch();
  }
  get unlockedKey(): PrivateKey | null {
    return this.key;
  }
  touch(): void {
    if (!this.key) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.lock(), this.idleMs);
  }
  lock(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const key = this.key;
    this.key = null;
    wipePrivateKey(key);
    if (key) this.onLock();
  }
}

export interface ClipboardLike {
  writeText(text: string): Promise<void>;
  readText?(): Promise<string>;
}

/**
 * Copy text and clear the clipboard after `ms` (best effort). The clipboard is
 * only cleared if it still holds what we copied, when the browser lets us read
 * it; if reading is not permitted, it is cleared anyway (the secret must not
 * linger).
 */
export async function copyWithAutoClear(
  text: string,
  ms: number,
  onCleared?: () => void,
  clipboard: ClipboardLike = navigator.clipboard,
): Promise<void> {
  await clipboard.writeText(text);
  setTimeout(() => {
    void (async () => {
      let current: string | null;
      try {
        current = clipboard.readText ? await clipboard.readText() : null;
      } catch {
        current = null; // not permitted: clear unconditionally
      }
      if (current !== null && current !== text) return; // user copied something else since
      await clipboard.writeText('').catch(() => undefined);
      onCleared?.();
    })();
  }, ms);
}
