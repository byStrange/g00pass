import { getPinnedAnchors, pinAnchors, type Invite } from '../core';
import { actionButton, field, fingerprint, form, help, input, notice, screen, tokenSteps } from './components';
import { type AppCtx, folderLabel } from './context';
import { h } from './dom';
import { deviceKeyInfo, forgetDeviceKey } from './keystore';
import { keyChooser } from './keyforms';
import { type PendingRequest, clearPending, loadPending, requestForm, waitingView } from './request';

/**
 * Newcomer flows.
 *
 * With an invite link: Check admins → Your key → Request → Approval → Connect.
 * Without (a request is pending, no store token yet): Approval → Connect.
 * The invite token lives in this closure only (memory, this tab).
 */

const JOIN_STEPS = ['Check admins', 'Your key', 'Request', 'Approval', 'Connect'] as const;

export function joinFlow(ctx: AppCtx, inv: Invite, onDone: () => void): HTMLElement {
  const root = h('div', { class: 'flow' });
  const [owner, repo] = inv.repo.split('/') as [string, string];
  const store = { owner, repo, storeRoot: inv.storeRoot };
  const err = (m: string) => ctx.toast(m, true);

  const show = (el: HTMLElement) => {
    root.replaceChildren(el);
    window.scrollTo?.(0, 0);
  };

  function stepAdmins() {
    const pinned = getPinnedAnchors(store);
    const same = !!pinned && pinned.anchors.length === inv.anchors.length && pinned.anchors.every((a) => inv.anchors.includes(a));
    const differs = !!pinned && !same;
    const useInvite = () => ctx.saveConfig({ owner, repo, branch: inv.branch, storeRoot: inv.storeRoot, requestsRepo: inv.requestsRepo });
    if (same) {
      useInvite();
      return void stepKey();
    }
    const ok = h('input', { type: 'checkbox' });
    show(
      screen(
        { steps: JOIN_STEPS, step: 0, title: `You're invited to ${inv.repo}`, icon: 'mail', lead: `You were invited to ${folderLabel(inv.folder)} as ${inv.role === 'reader' ? 'a reader' : 'a folder admin'}. This invite expires ${new Date(inv.expiresAt).toLocaleString()}.` },
        h('p', {}, 'First, make sure this invite really comes from your team. It names these admins:'),
        h('ul', { class: 'admin-list' }, ...inv.anchors.map((a) => h('li', {}, fingerprint(a, true)))),
        differs
          ? notice('danger', h('b', {}, 'This browser already trusts different admins for this store. '), 'An invite cannot change that (a forged invite could make you trust an attacker). If your admin confirms the change in person, reset the trusted admins in Settings and open the invite link again.')
          : notice('warn', h('b', {}, 'Ask your admin to read you their fingerprint'), ' (in person, on a call, or a chat you trust) and compare. If it does not match, close this page.'),
        differs ? null : h('label', { class: 'check' }, ok, 'The fingerprint matches what my admin told me.'),
        differs
          ? null
          : h('div', { class: 'actions' }, actionButton('Continue', async () => {
              if (!ok.checked) return err('Compare the fingerprint and tick the box first.');
              pinAnchors(store, inv.anchors, 'invite');
              useInvite();
              stepKey();
            }, { variant: 'primary', onError: err })),
      ),
    );
  }

  async function stepKey() {
    const info = await deviceKeyInfo().catch(() => null);
    if (info) {
      const pending = loadPending();
      if (pending && pending.fingerprint === info.fingerprint && pending.folder === inv.folder) return stepWait(pending);
      return show(
        screen(
          { steps: JOIN_STEPS, step: 1, title: 'Your key', icon: 'key', lead: 'This browser already has a key. Use it for this request?' },
          h('p', {}, fingerprint(info.fingerprint), ' ', h('span', { class: 'hint' }, info.userIds.join(', '))),
          h('div', { class: 'actions' },
            h('button', { type: 'button', class: 'primary', onclick: () => stepRequest() }, 'Use this key'),
            h('button', { type: 'button', class: 'ghost', onclick: () => { if (confirm('Remove the existing key from this browser and create a new one?')) { forgetDeviceKey(); void stepKey(); } } }, 'Create a new key instead')),
        ),
      );
    }
    show(
      screen(
        { steps: JOIN_STEPS, step: 1, title: 'Create your key', icon: 'key', lead: 'Your key lets you read the secrets you are given access to. It is created and kept in this browser, protected by your passphrase.' },
        keyChooser(() => stepRequest(), err, { preferCreate: true }),
      ),
    );
  }

  function stepRequest() {
    show(
      screen(
        { steps: JOIN_STEPS, step: 2, title: 'Ask for access', icon: 'inbox', lead: `This sends a signed request to ${inv.requestsRepo}. Your admin approves it.` },
        requestForm({
          config: ctx.config(),
          folder: inv.folder,
          role: inv.role,
          lockRole: true,
          inviteId: inv.id,
          requestsRepo: inv.requestsRepo,
          token: () => inv.token,
          unlockedKey: () => ctx.session.unlockedKey,
          onSubmitted: (p) => {
            ctx.toast('Request sent.');
            stepWait(p);
          },
          onError: err,
        }),
      ),
    );
  }

  function stepWait(p: PendingRequest) {
    show(screen({ steps: JOIN_STEPS, step: 3, title: 'Waiting for approval', icon: 'clock' }, waitingView({ pending: p, token: () => inv.token, onApproved: () => stepConnect(), onCancel: () => void stepKey(), onError: err })));
  }

  function stepConnect() {
    show(screen({ steps: JOIN_STEPS, step: 4, title: 'You are approved', icon: 'check', lead: 'One last thing: a token so this app can read the store.' }, connectReader(ctx, onDone)));
  }

  stepAdmins();
  return root;
}

/** Reader-token form after approval. */
function connectReader(ctx: AppCtx, onDone: () => void): HTMLElement {
  const c = ctx.config();
  const token = input({ type: 'password', placeholder: 'github_pat_…', required: true });
  return form(
    async () => {
      ctx.tokens.set(token.value.trim(), 'session');
      token.value = '';
      clearPending();
      onDone();
      await ctx.reload('Connected. Welcome!');
    },
    (m) => ctx.toast(m, true),
    'Connect',
    'Connecting…',
    field('Read token for the store', token),
    help('How do I get it?', h('p', {}, 'Your admin may send you one. Or, if you are a collaborator on the repository, create it yourself:'), tokenSteps(`${c.owner}/${c.repo}`, 'Contents: Read-only', 'up to 90 days')),
  );
}

/** A request is pending and there is no store token yet (e.g. after a reload). */
export function pendingFlow(ctx: AppCtx, p: PendingRequest, onDone: () => void): HTMLElement {
  const root = h('div', { class: 'flow' });
  const wait = () =>
    root.replaceChildren(
      screen({ steps: ['Approval', 'Connect'], step: 0, title: 'Waiting for approval', icon: 'clock' }, waitingView({ pending: p, token: () => null, onApproved: connect, onCancel: () => onDone(), onError: (m) => ctx.toast(m, true) })),
    );
  const connect = () => root.replaceChildren(screen({ steps: ['Approval', 'Connect'], step: 1, title: 'You are approved', icon: 'check', lead: 'Paste the read token for the store.' }, connectReader(ctx, onDone)));
  wait();
  return root;
}
