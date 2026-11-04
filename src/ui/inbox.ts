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
import { avatar } from './people';
import { icon } from './icons';
import type { Session } from './session';

export interface InboxDeps {
  client: GitHubClient;
  getConfig: () => GitHubRepo;
  /** Fingerprint of the stored device key (no unlock needed to list). */
  deviceFingerprint: () => Promise<string | null>;
  session: Session;
  setStatus: (text: string, isError?: boolean) => void;
  /** Called after a successful approval so the app can reload the store; `note` is the result to keep showing. */
  onApproved: (note: string, isError: boolean) => void;
  /** Number of requests the operator can act on (tab badge). */
  onCount?: (n: number) => void;
}

const PHASES: Record<ReencryptProgress['phase'], string> = {
  verifying: 'Checking the member list',
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
  const summary = h('p', { class: 'hint' }, 'Loading requests…');
  const loadBtn = h('button', { type: 'button', class: 'ghost small', onclick: () => void refresh() }, 'Refresh');
  const el = h('section', { class: 'panel inbox' }, h('div', { class: 'panel-head' }, h('h3', {}, 'Access requests'), loadBtn), summary, body);
  let busy = false;

  function reset() {
    clear(body);
    summary.textContent = '';
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
        summary.textContent = 'Set up your key first.';
        return;
      }
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
      deps.onCount?.(inbox.actionable.length);
      summary.textContent =
        (inbox.actionable.length ? `${inbox.actionable.length} waiting for you` : 'No requests waiting for you.') +
        (inbox.blocked.length ? ` ${inbox.blocked.length} blocked.` : '') +
        (inbox.hidden ? ` ${inbox.hidden} for folders you don't manage.` : '');
      for (const item of inbox.actionable) body.append(renderItem(item, issueRepo));
      if (inbox.blocked.length) {
        const list = h('ul', { class: 'invalid' });
        for (const b of inbox.blocked.slice(0, 20)) list.append(h('li', {}, `#${b.issue.number} (${b.request.folder}): NOT approvable. ${b.reason}`));
        body.append(h('p', { class: 'banner danger', role: 'alert' }, `${inbox.blocked.length} request(s) cannot be approved because the folder's current member list is not verified or cannot be re-signed. Do not work around this: someone may have edited it without authority.`), list);
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
    } catch (e) {
      const st = (e as { status?: number }).status;
      summary.textContent = st === 403 || st === 404 || st === 401
        ? `Your token cannot read issues in ${issueRepo.owner}/${issueRepo.repo}. To manage requests it needs Issues: Read and write there.`
        : `Could not load requests: ${errMsg(e)}`;
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
      class: 'code-input',
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
        deps.onApproved(
          `Approved in ${res.commitSha.slice(0, 7)}.` +
            (failed.length ? ` Could not update the issue (${failed.join(', ')}); close it manually.` : '') +
            (res.inviteConsumed ? ' The invite was used up. Now revoke the invite token on GitHub.' : r.inviteId ? ' Revoke the invite token on GitHub.' : ''),
          failed.length > 0,
        );
        card.remove();
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

    const who = { name: r.name, fingerprint: r.fingerprint, escrow: false };
    const step = (n: number, title: string, ...body: (Node | string | null)[]) =>
      h('section', { class: 'req-step' }, h('div', { class: 'req-step-num' }, String(n)), h('div', { class: 'req-step-body' }, h('h4', {}, title), ...body));
    const card = h(
      'article',
      { class: 'request' },
      h('header', { class: 'req-head' },
        avatar(who, 'lg'),
        h('div', { class: 'req-who' },
          h('h3', { dir: 'auto', class: 'uid' }, r.name),
          h('div', { class: 'hint uid', dir: 'auto' }, r.email ?? (r.userIds[0] ?? 'no e-mail on key')),
          h('div', { class: 'chips' },
            h('span', { class: 'chip' }, icon('folder', { size: 14 }), `${r.role === 'reader' ? 'Reader' : 'Folder admin'} · ${r.folder}/`),
            invited
              ? h('span', { class: 'chip ok' }, icon('check', { size: 14 }), `Invited by …${invite.record.issuedBy.slice(-8)}`)
              : h('span', { class: 'chip warn' }, icon('alert', { size: 14 }), r.inviteId ? `Invite not valid: ${invite && !invite.valid ? invite.reason : 'unknown'}` : 'No invite'),
            h('span', { class: 'chip' }, `#${issue.number}`))),
      ),
      r.note ? h('blockquote', { class: 'req-note', dir: 'auto' }, r.note) : null,
      step(1, `Confirm it is really ${r.name}`,
        h('p', { class: 'hint' }, `Call or message ${r.name} (not through this request) and ask for the ${FINGERPRINT_SUFFIX_LENGTH}-character code on their screen. Type it here:`),
        suffix,
        h('details', { class: 'fpr-details' }, h('summary', {}, 'Show their full key fingerprint'), h('p', { class: 'fpr mono', dir: 'ltr', 'aria-label': 'Full fingerprint' }, formatFingerprint(r.fingerprint)), h('p', { class: 'hint' }, 'The request is signed by this key: that proves they hold it, not who they are.'))),
      step(2, 'Check who will have access', renderPlan(plan), h('label', { class: 'check' }, reviewed, 'I reviewed the member change above (before → after) and approve exactly that.')),
      step(3, 'Approve',
        invited ? '' : h('label', { class: 'check' }, ack, 'I understand this request has no verified invite.'),
        h('div', { class: 'actions' }, approveBtn, cancelBtn),
        progress,
        h('details', { class: 'deny' }, h('summary', {}, 'Decline instead'), h('div', { class: 'row' }, reason, denyBtn))),
    );
    return card;
  }

  return { el, refresh, clear: reset };
}
