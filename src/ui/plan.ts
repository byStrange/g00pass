import { formatFingerprint, type PlannedRecipient, type RecipientChangePlan } from '../core';
import { h } from './dom';

/** Shared rendering of an exact before → after recipient change (approve / remove). */
export function recipientList(title: string, list: readonly PlannedRecipient[], mark: (fpr: string) => string | null): HTMLElement {
  return h(
    'div',
    { class: 'plan-side' },
    h('h4', {}, title),
    h(
      'ul',
      { class: 'fprs' },
      ...list.map((p) => {
        const m = mark(p.fingerprint);
        return h(
          'li',
          { class: m ?? '' },
          h('span', { class: 'mono', dir: 'ltr' }, formatFingerprint(p.fingerprint)),
          ' ',
          h('span', { class: 'hint uid', dir: 'auto' }, p.userIds.length ? p.userIds.join(', ') : '(no user id)'),
          p.escrow ? h('span', { class: 'badge' }, 'escrow') : null,
          m ? h('span', { class: `badge ${m}` }, m) : null,
        );
      }),
    ),
  );
}

export function fprList(title: string, fprs: readonly string[] | null, cls = ''): HTMLElement {
  return h('div', { class: 'plan-side' }, h('h4', {}, title), fprs && fprs.length ? h('ul', { class: 'fprs' }, ...fprs.map((f) => h('li', { class: cls }, h('span', { class: 'mono', dir: 'ltr' }, formatFingerprint(f))))) : h('p', { class: 'hint' }, '(none)'));
}

export function renderPlan(plan: RecipientChangePlan): HTMLElement {
  return h(
    'div',
    { class: 'plan' },
    h('p', {}, `Recipients of ${plan.folder}/ will change exactly as follows. Everyone in “after” will be able to decrypt every entry in this folder.`),
    recipientList('Before', plan.before, (f) => (plan.removed.includes(f) ? 'removed' : null)),
    recipientList('After', plan.after, (f) => (plan.added.includes(f) ? 'added' : null)),
    plan.admins
      ? h('div', { class: 'plan-admins' },
          h('p', {}, `Folder admins of ${plan.folder}/ (signed admins file) also change:`),
          fprList('Admins before', plan.admins.before),
          fprList('Admins after', plan.admins.after))
      : null,
    plan.resign.length
      ? h('p', { class: 'hint' }, `Re-signed by you because their signer loses admin rights: ${plan.resign.map((r) => `${r.folder}/ (${[r.gpgId ? '.gpg-id' : '', r.adminsFile ? 'admins file' : ''].filter(Boolean).join(' + ')})`).join(', ')}`)
      : null,
    plan.droppedEscrow.length ? h('p', { class: 'hint' }, `Retired escrow key(s) dropped: ${plan.droppedEscrow.map(formatFingerprint).join(', ')}`) : null,
    plan.childBoundaries.length ? h('p', { class: 'hint' }, `Sub-folders that keep their own recipients (declared in the signature): ${plan.childBoundaries.map((c) => c + '/').join(', ')}`) : null,
    plan.warnings.includes('escrow-missing') ? h('p', { class: 'hint' }, 'This also restores the missing escrow recipient.') : null,
  );
}
