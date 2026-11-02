import {
  G00passError,
  GitHubClient,
  TokenStore,
  buildAccessRequest,
  checkPassphrase,
  createAccessRequestIssue,
  describeSubmitError,
  generateEnrollmentKey,
  groupFingerprint,
  inspectImportedKey,
  requestsRepoWarning,
  resolveRequestsRepo,
  unlockPrivateKey,
  REQUEST_ROLES,
  type GitHubRepo,
  type RequestRole,
} from '../core';
import type { PrivateKey } from 'openpgp';
import { clear, h } from './dom';
import { deviceKeyInfo, loadDeviceKeyArmored, saveDeviceKey } from './keystore';

const PENDING_KEY = 'g00pass.pending-request.v1';

/** Everything an invite (Phase 2) can prefill. All optional. */
export interface EnrollPrefill {
  folder?: string;
  role?: RequestRole;
  inviteId?: string;
  requestsRepo?: string;
  /** Requester token; kept in memory only. */
  token?: string;
}

export interface EnrollDeps {
  getConfig: () => GitHubRepo;
  /** Currently unlocked session key, if any. */
  getUnlockedKey: () => PrivateKey | null;
  mainToken: () => string | null;
  setStatus: (t: string, isError?: boolean) => void;
  /** Called after the device key was created/imported. */
  onKeyChanged: () => void;
}

interface PendingRequest {
  requestsRepo: string;
  issueNumber: number;
  url: string;
  fingerprint: string;
  folder: string;
  role: string;
}

function loadPending(): PendingRequest | null {
  try {
    const p = JSON.parse(localStorage.getItem(PENDING_KEY) ?? 'null') as PendingRequest | null;
    return p && typeof p.issueNumber === 'number' ? p : null;
  } catch {
    return null;
  }
}

function nameFromUserId(uid: string | undefined): string {
  return (uid ?? '').replace(/\s*<[^>]*>\s*$/, '').trim();
}

export interface Enrollment {
  el: HTMLElement;
  render: () => Promise<void>;
  /** Single entry point for an invite link (Phase 2) to prefill the flow. */
  applyPrefill: (p: EnrollPrefill) => void;
}

export function createEnrollment(deps: EnrollDeps): Enrollment {
  const el = h('section', { class: 'card' });
  // Requester token: memory only, never sessionStorage.
  const requestTokens = new TokenStore('memory', null);
  let prefill: EnrollPrefill = {};

  const pw = () => h('input', { type: 'password', autocomplete: 'new-password' });

  function keyCreationForms(): Node[] {
    const name = h('input', { autocomplete: 'off', required: true });
    const email = h('input', { type: 'email', autocomplete: 'off', required: true });
    const p1 = pw();
    const p2 = pw();
    const gen = h(
      'form',
      {
        class: 'card inner',
        onsubmit: async (e: Event) => {
          e.preventDefault();
          if (p1.value !== p2.value) return deps.setStatus('Passphrases do not match.', true);
          const weak = checkPassphrase(p1.value);
          if (weak) return deps.setStatus(weak, true);
          deps.setStatus('Generating key…');
          try {
            const k = await generateEnrollmentKey({ name: name.value, email: email.value, passphrase: p1.value });
            await saveDeviceKey(k.privateKeyArmored);
            deps.setStatus('Key created and stored (passphrase-protected) in this browser.');
            deps.onKeyChanged();
          } catch (err) {
            deps.setStatus(err instanceof G00passError ? err.message : 'Key generation failed.', true);
          } finally {
            p1.value = '';
            p2.value = '';
          }
        },
      },
      h('h3', {}, 'Create a new key'),
      h('label', {}, 'Name', name),
      h('label', {}, 'E-mail', email),
      h('label', {}, 'Passphrase (min 12 characters; never leaves this browser)', p1),
      h('label', {}, 'Confirm passphrase', p2),
      h('p', { class: 'hint' }, 'If you lose the passphrase the key cannot be recovered. The key is generated locally.'),
      h('button', { type: 'submit' }, 'Generate key'),
    );
    const ta = h('textarea', { rows: '5', spellcheck: 'false', placeholder: '-----BEGIN PGP PRIVATE KEY BLOCK-----' });
    const imp = h(
      'form',
      {
        class: 'card inner',
        onsubmit: async (e: Event) => {
          e.preventDefault();
          try {
            await inspectImportedKey(ta.value);
            await saveDeviceKey(ta.value);
            deps.setStatus('Key imported.');
            deps.onKeyChanged();
          } catch (err) {
            deps.setStatus(err instanceof G00passError ? err.message : 'Import failed.', true);
          } finally {
            ta.value = '';
          }
        },
      },
      h('h3', {}, 'Or import an existing key'),
      h('p', { class: 'hint' }, 'Armored private key, v4, Ed25519 or RSA ≥ 3072, passphrase-protected (iterated S2K; Argon2 keys cannot unlock here).'),
      ta,
      h('button', { type: 'submit' }, 'Import key'),
    );
    return [gen, imp];
  }

  function requestForm(info: { fingerprint: string; userIds: string[] }): Node[] {
    const cfg = deps.getConfig();
    const storeRepo = `${cfg.owner}/${cfg.repo}`;
    const target = resolveRequestsRepo(storeRepo, prefill.requestsRepo ?? cfg.requestsRepo);
    const warning = requestsRepoWarning(target.fallback);
    const folder = h('input', { autocomplete: 'off', required: true, placeholder: 'e.g. infra' });
    folder.value = prefill.folder ?? '';
    const role = h('select', {}, ...REQUEST_ROLES.map((r) => h('option', { value: r }, r)));
    if (prefill.role) role.value = prefill.role;
    const note = h('textarea', { rows: '2', maxlength: '500', placeholder: 'Optional note for the approver' });
    const pass = h('input', { type: 'password', autocomplete: 'current-password' });
    const token = h('input', { type: 'password', autocomplete: 'off', placeholder: 'fine-grained, Issues: read and write' });
    const result = h('div', { class: 'result' });

    const needToken = !requestTokens.hasToken && !deps.mainToken();
    const form = h(
      'form',
      {
        class: 'card inner',
        onsubmit: async (e: Event) => {
          e.preventDefault();
          if (!cfg.owner || !cfg.repo) return deps.setStatus('Configure the store repository first.', true);
          try {
            if (token.value) requestTokens.set(token.value, 'memory');
            token.value = '';
            const tokenFn = () => requestTokens.get() ?? deps.mainToken();
            if (!tokenFn()) return deps.setStatus('A GitHub token with Issues access to the requests repo is required.', true);
            const armored = loadDeviceKeyArmored();
            if (!armored) return deps.setStatus('No device key.', true);
            let key = deps.getUnlockedKey();
            if (!key || key.getFingerprint().toUpperCase() !== info.fingerprint) key = await unlockPrivateKey(armored, pass.value);
            pass.value = '';
            const built = await buildAccessRequest(
              {
                repo: storeRepo,
                storeRoot: cfg.storeRoot ?? '',
                folder: folder.value,
                role: role.value as RequestRole,
                name: nameFromUserId(info.userIds[0]) || 'unknown',
                note: note.value,
                inviteId: prefill.inviteId ?? null,
                publicKey: key.toPublic().armor(),
                fingerprint: info.fingerprint,
              },
              key,
            );
            deps.setStatus('Submitting request…');
            const client = new GitHubClient({ token: tokenFn });
            const res = await createAccessRequestIssue(client, target.repo, built);
            const pending: PendingRequest = {
              requestsRepo: res.requestsRepo,
              issueNumber: res.issueNumber,
              url: res.url,
              fingerprint: info.fingerprint,
              folder: folder.value.trim(),
              role: role.value,
            };
            localStorage.setItem(PENDING_KEY, JSON.stringify(pending));
            deps.setStatus('Request submitted.');
            void render();
          } catch (err) {
            deps.setStatus(describeSubmitError(err), true);
          } finally {
            pass.value = '';
          }
        },
      },
      h('h3', {}, 'Request access'),
      h('p', { class: 'hint' }, `Requests are posted as an issue in ${target.repo}.`),
      warning ? h('p', { class: 'warn' }, warning) : null,
      h('label', {}, 'Folder', folder),
      h('label', {}, 'Role', role),
      h('label', {}, 'Note (optional)', note),
      deps.getUnlockedKey() ? null : h('label', {}, 'Key passphrase (to sign the request)', pass),
      needToken ? h('label', {}, 'GitHub token (memory only, not stored)', token) : h('label', {}, 'Replace token (optional)', token),
      result,
      h('button', { type: 'submit' }, 'Sign & submit request'),
    );
    return [form];
  }

  async function render(): Promise<void> {
    clear(el);
    el.append(h('h2', {}, 'Get access'));
    const info = await deviceKeyInfo().catch(() => null);
    if (!info) {
      el.append(h('p', { class: 'hint' }, 'No key on this device yet.'), ...keyCreationForms());
      return;
    }
    el.append(
      h('p', {}, 'Your key fingerprint:'),
      h('p', { class: 'mono fpr' }, groupFingerprint(info.fingerprint)),
      h('p', { class: 'hint' }, 'Share this fingerprint with your admin out of band (in person, phone, trusted chat). They must confirm it before approving you.'),
    );
    const pending = loadPending();
    if (pending && pending.fingerprint === info.fingerprint) {
      const a = h('a', { href: pending.url, target: '_blank', rel: 'noopener noreferrer' }, `${pending.requestsRepo}#${pending.issueNumber}`);
      el.append(
        h('p', { class: 'pending' }, 'Request pending approval for ', h('code', {}, pending.folder), ` (${pending.role}): `, a),
        h('button', { onclick: () => { localStorage.removeItem(PENDING_KEY); void render(); } }, 'Submit another request'),
      );
      return;
    }
    el.append(...requestForm(info));
  }

  function applyPrefill(p: EnrollPrefill): void {
    prefill = { ...p, token: undefined };
    if (p.token) requestTokens.set(p.token, 'memory');
    void render();
  }

  return { el, render, applyPrefill };
}
