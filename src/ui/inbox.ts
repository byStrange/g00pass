import {
  G00passError,
  GitHubSnapshot,
  GitHubWriter,
  approveAccessRequest,
  buildInbox,
  denyAccessRequest,
  finalizeApprovedIssue,
  formatFingerprint,
  listIssues,
  type GitHubClient,
  type GitHubRepo,
  type InboxItem,
  type IssueRepo,
  type ReencryptProgress,
} from '../core';
import { clear, h } from './dom';
import type { Session } from './session';

export interface InboxDeps {
  client: GitHubClient;
  getConfig: () => GitHubRepo;
  /** Fingerprint of the stored device key (no unlock needed to list). */
  deviceFingerprint: () => Promise<string | null>;
  session: Session;
  setStatus: (text: string, isError?: boolean) => void;
  /** Called after a successful approval so the app can reload the store. */
  onApproved: () => void;
}

const PHASES: Record<ReencryptProgress['phase'], string> = {
  verifying: 'Verifying recipients',
  reencrypting: 'Re-encrypting',
  committing: 'Committing',
  done: 'Done',
};

function requestsRepoOf(cfg: GitHubRepo): IssueRepo | null {
  const raw = cfg.requestsRepo?.trim();
  if (!raw) return cfg.owner && cfg.repo ? { owner: cfg.owner, repo: cfg.repo } : null;
  const m = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(raw);
  return m ? { owner: m[1]!, repo: m[2]! } : null;
}

const errMsg = (e: unknown) => (e instanceof G00passError ? e.message : 'Unexpected error');

/**
 * Admin inbox. SECURITY: everything from an issue (name, note, user ids,
 * reasons) is attacker-controlled and is only ever put into the DOM through
 * text nodes (`h()` never uses innerHTML). Approval is gated twice: the UI
 * needs the ticked checkboxes, and the core refuses without the confirmation.
 */
export function mountInbox(deps: InboxDeps): { el: HTMLElement; refresh: () => Promise<void>; clear: () => void } {
  const body = h('div', { class: 'inbox-list' });
  const summary = h('p', { class: 'hint' }, 'Access requests are read from the requests repository when you load them.');
  const loadBtn = h('button', { type: 'button', onclick: () => void refresh() }, 'Load access requests');
  const el = h('section', { class: 'card inbox' }, h('h2', {}, 'Access requests'), summary, h('div', { class: 'row' }, loadBtn), body);
  let busy = false;

  function reset() {
    clear(body);
    summary.textContent = 'Access requests are read from the requests repository when you load them.';
  }

  async function refresh() {
    if (busy) return;
    const cfg = deps.getConfig();
    const issueRepo = requestsRepoOf(cfg);
    if (!issueRepo || !cfg.owner || !cfg.repo) {
      deps.setStatus('Set the repository (and a valid requests repo, if any) first.', true);
      return;
    }
    busy = true;
    loadBtn.disabled = true;
    try {
      const fp = await deps.deviceFingerprint();
      if (!fp) {
        deps.setStatus('Store your device key first.', true);
        return;
      }
      deps.setStatus('Loading access requests…');
      const [issues, snapshot] = await Promise.all([
        listIssues(deps.client, issueRepo),
        GitHubSnapshot.load(deps.client, cfg),
      ]);
      const inbox = await buildInbox({
        issues,
        snapshot,
        store: { repo: `${cfg.owner}/${cfg.repo}`, storeRoot: cfg.storeRoot ?? '' },
        operatorFingerprint: fp,
      });
      clear(body);
      summary.textContent =
        `${inbox.actionable.length} request(s) you can act on` +
        (inbox.hidden ? `; ${inbox.hidden} for folders where you are not an admin recipient (hidden)` : '') +
        '.';
      for (const item of inbox.actionable) body.append(renderItem(item, issueRepo));
      if (inbox.invalid.length) {
        const list = h('ul', { class: 'invalid' });
        for (const i of inbox.invalid.slice(0, 20)) list.append(h('li', {}, `#${i.issue.number}: ${i.message}`));
        body.append(h('details', {}, h('summary', {}, `${inbox.invalid.length} invalid request(s) (not approvable)`), list));
      }
      deps.setStatus('Access requests loaded.');
    } catch (e) {
      deps.setStatus(errMsg(e), true);
    } finally {
      busy = false;
      loadBtn.disabled = false;
    }
  }

  function renderItem({ issue, request: r }: InboxItem, issueRepo: IssueRepo): HTMLElement {
    const confirm = h('input', { type: 'checkbox' });
    const ack = h('input', { type: 'checkbox' });
    const approveBtn = h('button', { type: 'button', class: 'primary', disabled: true }, 'Approve');
    const cancelBtn = h('button', { type: 'button', hidden: true }, 'Cancel');
    const denyBtn = h('button', { type: 'button', class: 'danger' }, 'Deny');
    const reason = h('input', { placeholder: 'Reason for denying (optional)', maxlength: '500', autocomplete: 'off' });
    const progress = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
    const sync = () => {
      approveBtn.disabled = !(confirm.checked && ack.checked);
    };
    confirm.addEventListener('change', sync);
    ack.addEventListener('change', sync);
    let abort: AbortController | null = null;
    const setBusy = (b: boolean) => {
      for (const x of [approveBtn, denyBtn, confirm, ack, reason]) x.disabled = b || (x === approveBtn && !(confirm.checked && ack.checked));
      cancelBtn.hidden = !b;
    };

    approveBtn.addEventListener('click', async () => {
      const key = deps.session.unlockedKey;
      if (!key) return deps.setStatus('Unlock your device key to approve.', true);
      const cfg = deps.getConfig();
      abort = new AbortController();
      setBusy(true);
      try {
        const res = await approveAccessRequest(r, {
          loadSnapshot: (signal) => GitHubSnapshot.load(deps.client, cfg, { signal }),
          writer: new GitHubWriter(deps.client, cfg),
          operatorKey: key,
          confirmation: {
            confirmedFingerprint: confirm.checked ? r.fingerprint : '',
            acknowledgeUninvited: ack.checked,
          },
          requestRef: `${issueRepo.owner}/${issueRepo.repo}#${issue.number}`,
          onProgress: (p) => {
            progress.textContent = `${PHASES[p.phase]}: ${p.done}/${p.total}`;
          },
          onConflict: () => {
            progress.textContent = 'Store changed; retrying with a fresh snapshot…';
          },
          signal: abort.signal,
        });
        const failed = await finalizeApprovedIssue(deps.client, issueRepo, issue.number, res);
        deps.setStatus(
          `Approved in ${res.commitSha.slice(0, 7)}.` +
            (failed.length ? ` Could not update the issue (${failed.join(', ')}); close it manually.` : '') +
            (r.inviteId ? ' Now revoke the invite token on GitHub.' : ''),
          failed.length > 0,
        );
        card.remove();
        deps.onApproved();
      } catch (e) {
        const aborted = e instanceof Error && e.name === 'AbortError';
        deps.setStatus(aborted ? 'Approval cancelled; nothing was committed.' : errMsg(e), true);
        progress.textContent = '';
        setBusy(false);
      } finally {
        abort = null;
      }
    });
    cancelBtn.addEventListener('click', () => abort?.abort());
    denyBtn.addEventListener('click', async () => {
      setBusy(true);
      try {
        const failed = await denyAccessRequest(deps.client, issueRepo, issue.number, reason.value);
        deps.setStatus(failed.length ? `Denied, but could not update the issue (${failed.join(', ')}).` : 'Request denied and closed.', failed.length > 0);
        card.remove();
      } catch (e) {
        deps.setStatus(errMsg(e), true);
        setBusy(false);
      }
    });

    const card = h(
      'article',
      { class: 'request' },
      h('h3', {}, `${r.name} `, h('span', { class: 'badge' }, `#${issue.number}`)),
      h('p', { class: 'hint' }, r.userIds.length ? `Key user id: ${r.userIds.join(', ')}` : 'Key has no user id'),
      r.email ? h('p', {}, `E-mail on key: ${r.email}`) : null,
      h('p', { class: 'fpr mono', 'aria-label': 'Full fingerprint' }, formatFingerprint(r.fingerprint)),
      h('p', {}, `Folder: ${r.folder}  ·  Role: ${r.role}`),
      h('p', {}, h('span', { class: 'badge ok' }, 'Signature valid'), ' ', h('span', { class: 'hint' }, 'proves the requester holds this key, not who they are')),
      h('p', {}, h('span', { class: 'badge warn' }, r.inviteId ? 'Invite not verified' : 'Uninvited')),
      r.note ? h('pre', { class: 'details' }, r.note) : null,
      h('label', { class: 'inline' }, confirm, `I confirmed this fingerprint with ${r.name} through another channel (not this issue).`),
      h('label', { class: 'inline' }, ack, 'I understand this request has no verified invite.'),
      h('div', { class: 'row' }, approveBtn, cancelBtn),
      progress,
      h('div', { class: 'row' }, reason, denyBtn),
    );
    return card;
  }

  return { el, refresh, clear: reset };
}
