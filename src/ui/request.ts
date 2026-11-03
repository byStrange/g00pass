import {
  GitHubClient,
  LABEL_APPROVED,
  LABEL_REJECTED,
  REQUEST_ROLES,
  buildAccessRequest,
  createAccessRequestIssue,
  describeSubmitError,
  getIssueStatus,
  parseOwnerRepo,
  unlockPrivateKey,
  type GitHubRepo,
  type RequestRole,
} from '../core';
import type { PrivateKey } from 'openpgp';
import { actionButton, field, fingerprintTail, form, input, link, notice } from './components';
import { h } from './dom';
import { deviceKeyInfo, loadDeviceKeyArmored } from './keystore';

/** Access requests from the requester's side: submit, remember, wait. */

const PENDING_KEY = 'g00pass.pending-request.v1';

export interface PendingRequest {
  requestsRepo: string;
  issueNumber: number;
  url: string;
  fingerprint: string;
  folder: string;
  role: string;
}

export function loadPending(): PendingRequest | null {
  try {
    const p = JSON.parse(localStorage.getItem(PENDING_KEY) ?? 'null') as PendingRequest | null;
    return p && typeof p.issueNumber === 'number' && typeof p.fingerprint === 'string' ? p : null;
  } catch {
    return null;
  }
}
export function clearPending(): void {
  localStorage.removeItem(PENDING_KEY);
}

const nameFromUserId = (uid: string | undefined) => (uid ?? '').replace(/\s*<[^>]*>\s*$/, '').trim();

export interface RequestFormOpts {
  config: GitHubRepo;
  /** Fixed folder (invite) or a list to choose from. */
  folder: string | readonly string[];
  role?: RequestRole;
  lockRole?: boolean;
  inviteId?: string | null;
  requestsRepo: string;
  /** Token with Issues: Read and write on the requests repo (null: ask for one). */
  token: () => string | null;
  unlockedKey: () => PrivateKey | null;
  onSubmitted: (p: PendingRequest) => void;
  onError: (m: string) => void;
}

export function requestForm(o: RequestFormOpts): HTMLElement {
  const folder = typeof o.folder === 'string'
    ? input({ value: o.folder, readonly: true })
    : h('select', { required: true }, ...o.folder.map((f) => h('option', { value: f }, f + '/')));
  const role = h('select', { disabled: !!o.lockRole }, ...REQUEST_ROLES.map((r) => h('option', { value: r }, r === 'reader' ? 'Reader (can read secrets)' : 'Folder admin (can also manage people)')));
  if (o.role) role.value = o.role;
  const note = h('textarea', { rows: '2', maxlength: '500', placeholder: 'Optional: a short note for the admin' });
  const pass = input({ type: 'password', autocomplete: 'current-password' });
  const tokenIn = input({ type: 'password', placeholder: 'github_pat_…' });
  let ownToken: string | null = null;
  const needToken = !o.token();
  const needPass = !o.unlockedKey();
  return form(
    async () => {
      if (tokenIn.value.trim()) ownToken = tokenIn.value.trim();
      tokenIn.value = '';
      const token = ownToken ?? o.token();
      if (!token) return o.onError('A token that can create issues in the requests repo is needed.');
      const info = await deviceKeyInfo();
      const armored = loadDeviceKeyArmored();
      if (!info || !armored) return o.onError('No key on this device.');
      let key = o.unlockedKey();
      try {
        if (!key || key.getFingerprint().toUpperCase() !== info.fingerprint) key = await unlockPrivateKey(armored, pass.value);
      } finally {
        pass.value = '';
      }
      const built = await buildAccessRequest(
        {
          repo: `${o.config.owner}/${o.config.repo}`,
          storeRoot: o.config.storeRoot ?? '',
          folder: folder.value,
          role: role.value as RequestRole,
          name: nameFromUserId(info.userIds[0]) || 'unknown',
          note: note.value,
          inviteId: o.inviteId ?? null,
          publicKey: key.toPublic().armor(),
          fingerprint: info.fingerprint,
        },
        key,
      );
      try {
        const res = await createAccessRequestIssue(new GitHubClient({ token: () => token }), o.requestsRepo, built);
        const pending: PendingRequest = { requestsRepo: res.requestsRepo, issueNumber: res.issueNumber, url: res.url, fingerprint: info.fingerprint, folder: folder.value, role: role.value };
        localStorage.setItem(PENDING_KEY, JSON.stringify(pending));
        o.onSubmitted(pending);
      } catch (e) {
        o.onError(describeSubmitError(e));
      }
    },
    o.onError,
    'Send request',
    'Signing and sending…',
    field('Folder', folder),
    field('Access', role),
    field('Note (optional)', note),
    needPass ? field('Your key passphrase', pass, 'Signs the request, proving it comes from your key.') : null,
    needToken ? field('Requests token', tokenIn, `Fine-grained token with Issues: Read and write on ${o.requestsRepo} (your admin can give you one).`) : null,
  );
}

/**
 * "Waiting for approval": what to tell the admin, and the request status.
 * Polls at most once a minute while visible and a token is available.
 */
export function waitingView(o: {
  pending: PendingRequest;
  token: () => string | null;
  onApproved: () => void;
  onCancel: () => void;
  onError: (m: string) => void;
}): HTMLElement {
  const p = o.pending;
  const state = h('p', { class: 'state', role: 'status', 'aria-live': 'polite' }, 'Waiting for an admin to approve…');
  let timer: ReturnType<typeof setTimeout> | null = null;
  const check = async (manual: boolean) => {
    const token = o.token();
    if (!token) {
      if (manual) state.textContent = 'Status cannot be checked from here (no requests token in this tab). Open the request link, or continue once your admin tells you it is approved.';
      return;
    }
    try {
      const r = parseOwnerRepo(p.requestsRepo);
      const st = await getIssueStatus(new GitHubClient({ token: () => token }), r, p.issueNumber);
      if (st.labels.includes(LABEL_APPROVED)) {
        state.textContent = 'Approved!';
        return o.onApproved();
      }
      if (st.state === 'closed') {
        state.textContent = st.labels.includes(LABEL_REJECTED) ? 'Your request was declined. Open the request to see why.' : 'Your request was closed without approval.';
        return;
      }
      state.textContent = `Still waiting (checked ${new Date().toLocaleTimeString()}).`;
    } catch {
      state.textContent = 'Could not check the status right now.';
    }
    if (el.isConnected) timer = setTimeout(() => void check(false), 60_000);
  };
  const el = h(
    'div',
    { class: 'waiting' },
    h('p', {}, 'Your request for ', h('b', {}, p.folder + '/'), ` (${p.role}) was sent: `, link(p.url, `${p.requestsRepo}#${p.issueNumber}`), '.'),
    notice('info', h('b', {}, 'Tell your admin these 16 characters'), ' (in person, by phone or chat — not in the request):', h('div', { class: 'tail-box' }, fingerprintTail(p.fingerprint)), 'They type them to confirm the request really is yours.'),
    state,
    h('div', { class: 'actions' },
      actionButton('Check now', () => check(true), { onError: o.onError }),
      h('button', { type: 'button', class: 'ghost', onclick: () => o.onApproved() }, 'My admin says it is approved'),
      h('button', { type: 'button', class: 'ghost', onclick: () => { if (timer) clearTimeout(timer); clearPending(); o.onCancel(); } }, 'Start over')),
  );
  queueMicrotask(() => void check(false));
  return el;
}
