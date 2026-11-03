/**
 * GitHub token holder. Tokens live in memory, or (opt-in) in sessionStorage
 * so they survive a reload of the same tab. Never localStorage, never logged.
 */
export type TokenPersistence = 'memory' | 'session';

const SESSION_KEY = 'g00pass.gh-session';

export class TokenStore {
  private value: string | null = null;
  constructor(
    private persistence: TokenPersistence = 'memory',
    private readonly session: Storage | null = typeof sessionStorage === 'undefined' ? null : sessionStorage,
  ) {
    if (persistence === 'session') this.value = this.session?.getItem(SESSION_KEY) ?? null;
  }
  get = (): string | null => this.value;
  set(token: string, persistence: TokenPersistence = this.persistence): void {
    const t = token.trim();
    if (!t) throw new Error('Empty token');
    this.clear();
    this.persistence = persistence;
    this.value = t;
    if (persistence === 'session') this.session?.setItem(SESSION_KEY, t);
  }
  clear(): void {
    this.value = null;
    this.session?.removeItem(SESSION_KEY);
  }
  get hasToken(): boolean {
    return this.value !== null;
  }
  /** Prevent accidental serialization (JSON.stringify / structured logging). */
  toJSON(): string {
    return '[TokenStore]';
  }
}
