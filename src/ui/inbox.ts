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
  FINGERPRINT_SUFFIX_LENGTH,
  type GitHubClient,
  type GitHubRepo,
  type InboxItem,
  type IssueRepo,
  type ReencryptProgress,
} from '../core';
import { clear, h } from './dom';
import { renderPlan } from './plan';
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
 * reasons) is attacker-controlled, sanitized by the parser (bidi / zero-width
 * characters replaced) and only ever put into the DOM through text nodes
 * (`h()` never uses innerHTML), isolated with `dir`. Approval is gated twice:
 * the UI needs the typed fingerprint suffix and the reviewed before → after
 * plan, and the core re-checks both (suffix, plan digest on the commit base).
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
        (inbox.blocked.length ? `; ${inbox.blocked.length} blocked` : '') +
        (inbox.hidden ? `; ${inbox.hidden} for folders where you are not a verified admin recipient (see reasons)` : '') +
        '.';
      for (const item of inbox.actionable) body.append(renderItem(item, issueRepo));
      if (inbox.blocked.length) {
        const list = h('ul', { class: 'invalid' });
        for (const b of inbox.blocked.slice(0, 20)) list.append(h('li', {}, `#${b.issue.number} (${b.request.folder}): NOT approvable. ${b.reason}`));
        body.append(h('p', { class: 'banner danger', role: 'alert' }, `${inbox.blocked.length} request(s) cannot be approved because the folder's current recipient list is not verified or cannot be re-signed. Do not work around this: someone may have edited it without authority.`), list);
      }
      if (inbox.hiddenReasons.length) {
        const list = h('ul', { class: 'invalid' });
        for (const i of inbox.hiddenReasons.slice(0, 20)) list.append(h('li', {}, `#${i.issue.number} (${i.folder}): ${i.reason}`));
        body.append(h('details', {}, h('summary', {}, `${inbox.hiddenReasons.length} request(s) you cannot approve`), list));
      }
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

  function renderItem({ issue, request: r, plan, invite }: InboxItem, issueRepo: IssueRepo): HTMLElement {
    const invited = invite?.valid === true;
    const suffix = h('input', {
      autocomplete: 'off',
      spellcheck: 'false',
      maxlength: '24',
      inputmode: 'text',
      placeholder: `last ${FINGERPRINT_SUFFIX_LENGTH} characters`,
      'aria-label': `Last ${FINGERPRINT_SUFFIX_LENGTH} characters of the fingerprint, as the requester told you`,
    });
    const reviewed = h('input', { type: 'checkbox' });
    const ack = h('input', { type: 'checkbox' });
    const approveBtn = h('button', { type: 'button', class: 'primary', disabled: true }, 'Approve');
    const cancelBtn = h('button', { type: 'button', hidden: true }, 'Cancel');
    const denyBtn = h('button', { type: 'button', class: 'danger' }, 'Deny');
    const reason = h('input', { placeholder: 'Reason for denying (optional)', maxlength: '500', autocomplete: 'off' });
    const progress = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
    const ready = () => suffix.value.replace(/\s+/g, '').length === FINGERPRINT_SUFFIX_LENGTH && reviewed.checked && (invited || ack.checked);
    const sync = () => {
      approveBtn.disabled = !ready();
    };
    suffix.addEventListener('input', sync);
    reviewed.addEventListener('change', sync);
    ack.addEventListener('change', sync);
    let abort: AbortController | null = null;
    const setBusy = (b: boolean) => {
      for (const x of [approveBtn, denyBtn, suffix, reviewed, ack, reason]) x.disabled = b || (x === approveBtn && !ready());
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
          // Core re-checks both: the typed suffix against the request, and the
          // reviewed plan digest against the plan recomputed on the commit base.
          confirmation: {
            fingerprintSuffix: suffix.value,
            acknowledgeUninvited: ack.checked,
            approvedPlan: reviewed.checked ? plan.digest : '',
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
            (res.inviteConsumed ? ' The invite was used up. Now revoke the invite token on GitHub.' : r.inviteId ? ' Revoke the invite token on GitHub.' : ''),
          failed.length > 0,
        );
        card.remove();
        deps.onApproved();
      } catch (e) {
        const aborted = e instanceof Error && e.name === 'AbortError';
        const changed = e instanceof G00passError && (e as { code?: string }).code === 'plan-changed';
        deps.setStatus(aborted ? 'Approval cancelled; nothing was committed.' : changed ? `${errMsg(e)} Reload the access requests.` : errMsg(e), true);
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
      h('h3', { dir: 'auto' }, `${r.name} `, h('span', { class: 'badge' }, `#${issue.number}`)),
      h('p', { class: 'hint uid', dir: 'auto' }, r.userIds.length ? `Key user id: ${r.userIds.join(', ')}` : 'Key has no user id'),
      r.email ? h('p', { dir: 'auto' }, `E-mail on key: ${r.email}`) : null,
      h('p', { class: 'fpr mono', dir: 'ltr', 'aria-label': 'Full fingerprint' }, formatFingerprint(r.fingerprint)),
      h('p', {}, `Folder: ${r.folder}  ·  Role: ${r.role}`),
      h('p', {}, h('span', { class: 'badge ok' }, 'Signature valid'), ' ', h('span', { class: 'hint' }, 'proves the requester holds this key, not who they are')),
      h('p', {}, invited
        ? h('span', { class: 'badge ok' }, `Invited (${invite.record.role}, by ${invite.record.issuedBy.slice(-16)}, expires ${invite.record.expiresAt})`)
        : h('span', { class: 'badge warn' }, r.inviteId ? `Invite not valid: ${invite && !invite.valid ? invite.reason : 'unknown'}` : 'Uninvited')),
      r.note ? h('pre', { class: 'details', dir: 'auto' }, r.note) : null,
      renderPlan(plan),
      h('label', {}, `Ask ${r.name} for their fingerprint through another channel (not this issue) and type its LAST ${FINGERPRINT_SUFFIX_LENGTH} characters:`, suffix),
      h('label', { class: 'inline' }, reviewed, 'I reviewed the recipient change above (before → after) and approve exactly that.'),
      invited ? '' : h('label', { class: 'inline' }, ack, 'I understand this request has no verified invite.'),
      h('div', { class: 'row' }, approveBtn, cancelBtn),
      progress,
      h('div', { class: 'row' }, reason, denyBtn),
    );
    return card;
  }

  return { el, refresh, clear: reset };
}
