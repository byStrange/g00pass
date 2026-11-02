import type { PrivateKey } from 'openpgp';

/** Holds the unlocked key in memory and locks after inactivity. */
export class Session {
  private key: PrivateKey | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  constructor(
    private readonly idleMs: number,
    private readonly onLock: () => void,
  ) {}
  unlock(key: PrivateKey): void {
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
    const wasUnlocked = this.key !== null;
    this.key = null;
    if (wasUnlocked) this.onLock();
  }
}

/** Copy text and clear the clipboard after `ms` (best effort). */
export async function copyWithAutoClear(text: string, ms: number, onCleared?: () => void): Promise<void> {
  await navigator.clipboard.writeText(text);
  setTimeout(() => {
    navigator.clipboard.writeText('').then(onCleared, onCleared);
  }, ms);
}
