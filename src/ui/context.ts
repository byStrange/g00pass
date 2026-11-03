import type { GitHubClient, GitHubRepo, GitHubSnapshot, RootTrust, TokenStore } from '../core';
import type { Session } from './session';

/** What every screen gets from the app shell. */
export interface AppCtx {
  readonly client: GitHubClient;
  readonly tokens: TokenStore;
  readonly session: Session;
  config(): GitHubRepo;
  saveConfig(c: GitHubRepo): void;
  snapshot(): GitHubSnapshot | null;
  root(): RootTrust | null;
  /** Status line (aria-live). */
  toast(text: string, isError?: boolean): void;
  /** Reload the store, then re-render; `note` (the result of an action) stays visible. */
  reload(note?: string, isError?: boolean): Promise<void>;
  /** Re-render the current screen from state. */
  rerender(): void;
}

export const CONFIG_KEY = 'g00pass.repo-config.v1';

export function loadConfig(): GitHubRepo {
  try {
    const c = JSON.parse(localStorage.getItem(CONFIG_KEY) ?? '{}') as Partial<GitHubRepo>;
    return { owner: c.owner ?? '', repo: c.repo ?? '', branch: c.branch ?? 'main', storeRoot: c.storeRoot ?? '', requestsRepo: c.requestsRepo ?? '' };
  } catch {
    return { owner: '', repo: '', branch: 'main', storeRoot: '', requestsRepo: '' };
  }
}

export const storeLabel = (c: GitHubRepo) => `${c.owner}/${c.repo}${c.storeRoot ? `/${c.storeRoot}` : ''}`;
export const folderLabel = (f: string) => (f ? `${f}/` : '/ (everything)');
